/**
 * Secret scanner — `before_provider_request` handler.
 *
 * Provider-agnostic: recursively walks the entire payload for string values,
 * runs regex matching, and replaces secrets with `***REDACTED:{pattern-name}***`.
 * No parsing of provider-specific message structures (ADR-0002).
 *
 * Only scans the request — not the response. Input-side redaction prevents
 * secrets from reaching the model, so they cannot appear in responses.
 *
 * Scan bounds (ADR-0013): the total string bytes of the payload are
 * measured before scanning; above `scanBudgetBytes` (machine-only,
 * `security-policy.json`, default 2 MiB) the line-by-line scan is
 * SKIPPED with a `secret.skipped` audit entry + notification — never a
 * silent skip. PEM private-key redaction still runs on over-budget
 * payloads: it precedes line-splitting by design and the budget must
 * not bypass it.
 */
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import type { Config } from "./config.js";
import { auditLog } from "./audit.js";

// ── Secret patterns ───────────────────────────────────────────────────

interface SecretPattern {
	name: string;
	pattern: RegExp;
}

const SECRET_PATTERNS: SecretPattern[] = [
	// Cloud provider keys
	{ name: "aws-access-key", pattern: /AKIA[0-9A-Z]{16}/g },
	{
		name: "aws-secret-key",
		pattern: /(?<=aws_secret_access_key\s*=\s*|AWS_SECRET_ACCESS_KEY\s*=\s*)[A-Za-z0-9/+=]{40}/g,
	},

	// LLM provider keys
	{ name: "anthropic-key", pattern: /sk-ant-api[a-zA-Z0-9_-]{20,}/g },
	{ name: "openai-key", pattern: /sk-[a-zA-Z0-9]{20,}/g },
	{ name: "gemini-key", pattern: /AIza[a-zA-Z0-9_-]{35}/g },

	// Generic secrets
	{
		name: "private-key",
		pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
	},
	{
		name: "api-key-generic",
		pattern: /(?:api[_-]?key|apikey)\s*[:=]\s*["']?[A-Za-z0-9_-]{20,}/gi,
	},
	{
		name: "bearer-token",
		pattern: /(?:bearer|authorization)\s*[:=]\s*["']?[A-Za-z0-9_.-]{20,}/gi,
	},
	{
		name: "password",
		pattern: /(?:password|passwd|pwd)\s*[:=]\s*["']?[A-Za-z0-9+/=_!@#$%^&*()\-]{8,}["']?/gi,
	},

	// Database connection strings
	{
		name: "db-connection",
		pattern: /(?:mongodb|postgres|mysql|redis|amqp):\/\/[^\s"']+/gi,
	},

	// GitHub tokens
	{ name: "github-token", pattern: /gh[ps]_[a-zA-Z0-9]{36}/g },

	// Slack, Discord, etc.
	{ name: "slack-token", pattern: /xox[baprs]-[0-9a-zA-Z-]{10,}/g },
	{
		name: "discord-token",
		pattern: /[\w-]{24}\.[\w-]{6}\.[\w-]{27}/g,
	},

	// High entropy detection (fallback)
	{
		name: "high-entropy",
		pattern: /(?:key|token|secret|password|credential)["']?\s*[:=]\s*["']?([A-Za-z0-9+/=_-]{32,})["']?/gi,
	},
];

// ── False-positive mitigation ─────────────────────────────────────────

const PLACEHOLDER_PATTERNS = [
	/^YOUR_/i,
	/^<.+>$/,
	/^x{3,}$/i,
	/^\*{3,}$/,
	/^REPLACE_/i,
	/^INSERT_/i,
	/^CHANGE_ME/i,
	/^CHANGEME/i,
	/^TODO/i,
	/^example/i,
	/^placeholder/i,
	/^sample/i,
	/^dummy/i,
	/^fake/i,
	/^test/i,
	/^foobar/i,
	/^bar$/i,
	/^baz$/i,
];

/**
 * Check if a matched value is clearly a placeholder and should be skipped.
 */
export function isPlaceholder(value: string): boolean {
	for (const p of PLACEHOLDER_PATTERNS) {
		if (p.test(value)) return true;
	}
	return false;
}

/**
 * Check if the string is inside a comment line (starts with #, //, --).
 * We receive full strings from the payload, so we check if the entire
 * surrounding line is a comment by looking for comment prefixes.
 */
export function isCommentLine(text: string): boolean {
	const trimmed = text.trim();
	if (trimmed.startsWith("#")) return true;
	if (trimmed.startsWith("//")) return true;
	if (trimmed.startsWith("/*")) return true;
	// SQL-style -- comment: must be followed by space or end-of-line
	// to avoid false positives on PEM headers (-----BEGIN ...)
	if (/^--(?:\s|$)/.test(trimmed)) return true;
	return false;
}

// ── Redaction logic ───────────────────────────────────────────────────

export interface Redaction {
	patternName: string;
	original: string;
}

export interface RedactOptions {
	skipCommentLines?: boolean;
}

/**
 * Regex that matches an entire PEM private key block, from BEGIN to END.
 * Captures the full block including body and END line.
 */
const PEM_BLOCK_REGEX = /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g;

/**
 * Redact PEM private key blocks from a string before line-by-line processing.
 * PEM keys span multiple lines and must be replaced as a single unit.
 */
function redactPEMBlocks(value: string): { result: string; redactions: Redaction[] } {
	const redactions: Redaction[] = [];
	const result = value.replace(PEM_BLOCK_REGEX, (match) => {
		redactions.push({ patternName: "private-key", original: match });
		return "***REDACTED:private-key***";
	});
	return { result, redactions };
}

/**
 * Scan and redact secrets from a single line (no comment check).
 * Used internally by redactString for per-line processing.
 *
 * Each pattern is applied in a single linear `String.replace` pass:
 * the previous implementation rebuilt the line after every real match
 * (`slice + concat`), which made a line with K real matches cost
 * O(K × lineLength) — 6000 matches on a 138 KB line measured ~1 s, a
 * per-turn DoS vector on attacker-controlled tool output (found by the
 * fuzz harness). `replace` processes all matches in one pass and
 * records redactions via the callback, preserving the exact semantics:
 * placeholder matches are kept verbatim, real matches are replaced with
 * `***REDACTED:{name}***`, and scanning continues after each
 * replacement.
 */
function redactLineContent(line: string): { result: string; redactions: Redaction[] } {
	let result = line;
	const redactions: Redaction[] = [];

	for (const { name, pattern } of SECRET_PATTERNS) {
		const regex = new RegExp(pattern.source, pattern.flags);
		result = result.replace(regex, (matched: string) => {
			if (isPlaceholder(matched)) return matched;
			redactions.push({ patternName: name, original: matched });
			return `***REDACTED:${name}***`;
		});
	}

	return { result, redactions };
}

/**
 * Detect (without redacting) which secret patterns match inside a string.
 * Reuses the same `SECRET_PATTERNS` table as `redactString` so detection
 * stays consistent with redaction. Comment lines are not skipped here —
 * callers scanning command strings want every match.
 *
 * Returns one entry per pattern that matched at least once (deduplicated
 * by pattern name). Use this from the bash gate to detect secret-bearing
 * commands without duplicating the pattern list.
 */
export function findSecrets(text: string): { patternName: string }[] {
	const found = new Set<string>();

	// PEM blocks first (treat the whole block as a single private-key hit)
	const pemRegex = new RegExp(PEM_BLOCK_REGEX.source, PEM_BLOCK_REGEX.flags);
	if (pemRegex.test(text)) {
		found.add("private-key");
	}

	for (const { name, pattern } of SECRET_PATTERNS) {
		// Skip the multi-line private-key pattern — handled above via PEM_BLOCK_REGEX
		if (name === "private-key") continue;

		const regex = new RegExp(pattern.source, pattern.flags);
		let match: RegExpExecArray | null;
		while ((match = regex.exec(text)) !== null) {
			const matched = match[0];
			if (!isPlaceholder(matched)) {
				found.add(name);
				// One hit per pattern is enough for detection purposes
				break;
			}
			if (match.index === regex.lastIndex) regex.lastIndex++;
		}
	}

	return Array.from(found).map((patternName) => ({ patternName }));
}

/**
 * Scan and redact secrets from a string value.
 * First redacts multi-line PEM private key blocks as a whole,
 * then processes remaining content line-by-line.
 *
 * Comment lines are scanned by default (M1): commented-out credentials
 * (`# API_KEY=sk-ant-...`, `// password=hunter2`) are common in config
 * files the agent reads and must not reach the LLM in plaintext. Pass
 * `{ skipCommentLines: true }` to restore the legacy display-only skip
 * (used by callers that want to preserve comment content verbatim).
 * Returns the redacted string and a list of redactions performed.
 */
export function redactString(value: string, options: RedactOptions = {}): { result: string; redactions: Redaction[] } {
	const skipComments = options.skipCommentLines === true;

	// Step 1: Redact multi-line PEM blocks before line-by-line processing
	const { result: pemRedacted, redactions: pemRedactions } = redactPEMBlocks(value);
	const allRedactions: Redaction[] = [...pemRedactions];

	// Step 2: Line-by-line processing for remaining secrets
	const lines = pemRedacted.split("\n");
	const resultLines: string[] = [];

	for (const line of lines) {
		if (skipComments && isCommentLine(line)) {
			resultLines.push(line);
		} else {
			const { result, redactions } = redactLineContent(line);
			resultLines.push(result);
			allRedactions.push(...redactions);
		}
	}

	return { result: resultLines.join("\n"), redactions: allRedactions };
}

/**
 * Recursively walk a payload object, finding and redacting secrets in all
 * string values. Mutates the object in place and returns it.
 */
export function walkAndRedact(
	obj: unknown,
	redactions: Redaction[],
	depth = 0,
): unknown {
	if (depth > 50) return obj; // safety limit

	if (typeof obj === "string") {
		const { result, redactions: found } = redactString(obj);
		redactions.push(...found);
		return result;
	}

	if (Array.isArray(obj)) {
		for (let i = 0; i < obj.length; i++) {
			obj[i] = walkAndRedact(obj[i], redactions, depth + 1);
		}
		return obj;
	}

	if (obj !== null && typeof obj === "object") {
		const record = obj as Record<string, unknown>;
		for (const key of Object.keys(record)) {
			record[key] = walkAndRedact(record[key], redactions, depth + 1);
		}
		return obj;
	}

	return obj;
}

// ── Scan budget ───────────────────────────────────────────────────────

/**
 * Shipped default total scan budget per provider request: 2 MiB of
 * payload string content. The secret scan is linear at roughly 95 ms
 * per MiB and re-scans the whole transcript every turn, so unbounded
 * payloads translate directly into unbounded per-turn latency. The
 * budget is machine-only via `security-policy.json` (`scanBudgetBytes`,
 * resolved through `loadSecurityPolicy` — the project layer is ignored
 * wholesale, ADR-0009). Mirrored into `DEFAULT_SECURITY_POLICY` in
 * config.ts and `defaults/security-policy.json` — keep the three in
 * sync. A missing, zero, or negative value falls back to this default
 * (the budget cannot be silently disabled).
 */
export const DEFAULT_SCAN_BUDGET_BYTES = 2 * 1024 * 1024;

/**
 * Resolve the active scan budget from the runtime config. Follows the
 * `resolveMetricsThresholds` convention: only a positive number in
 * `config.securityPolicy.scanBudgetBytes` overrides the default.
 */
export function resolveScanBudget(config: Config): number {
	const value = config.securityPolicy?.scanBudgetBytes;
	return typeof value === "number" && value > 0 ? value : DEFAULT_SCAN_BUDGET_BYTES;
}

/**
 * Recursively sum the UTF-8 byte length of every string value in a
 * payload (depth-capped at 50, parity with the redaction walks). This
 * measurement pass is linear with a small constant — cheap next to the
 * ~95 ms/MiB scan it is gating.
 */
export function sumStringBytes(obj: unknown, depth = 0): number {
	if (depth > 50) return 0;
	if (typeof obj === "string") return Buffer.byteLength(obj, "utf8");
	if (Array.isArray(obj)) {
		let sum = 0;
		for (const item of obj) sum += sumStringBytes(item, depth + 1);
		return sum;
	}
	if (obj !== null && typeof obj === "object") {
		const record = obj as Record<string, unknown>;
		let sum = 0;
		for (const key of Object.keys(record)) {
			sum += sumStringBytes(record[key], depth + 1);
		}
		return sum;
	}
	return 0;
}

/**
 * Recursively walk a payload object redacting ONLY multi-line PEM
 * private-key blocks in string values (depth-capped at 50). Used on
 * over-budget payloads: PEM redaction is a single linear pass and
 * private keys are the highest-value secret class, so the budget skips
 * the line-by-line scan but must not bypass PEM redaction
 * (`redactPEMBlocks` runs before line-splitting by design).
 */
export function walkAndRedactPEMOnly(
	obj: unknown,
	redactions: Redaction[],
	depth = 0,
): unknown {
	if (depth > 50) return obj; // safety limit

	if (typeof obj === "string") {
		const { result, redactions: found } = redactPEMBlocks(obj);
		redactions.push(...found);
		return result;
	}

	if (Array.isArray(obj)) {
		for (let i = 0; i < obj.length; i++) {
			obj[i] = walkAndRedactPEMOnly(obj[i], redactions, depth + 1);
		}
		return obj;
	}

	if (obj !== null && typeof obj === "object") {
		const record = obj as Record<string, unknown>;
		for (const key of Object.keys(record)) {
			record[key] = walkAndRedactPEMOnly(record[key], redactions, depth + 1);
		}
		return obj;
	}

	return obj;
}

// ── Scanner registration ──────────────────────────────────────────────

/**
 * Turn-scoped redaction count for the after_provider_response notification.
 */
let _pendingRedactionCount = 0;

/**
 * Turn-scoped count of provider requests whose payload exceeded the scan
 * budget (for the after_provider_response notification — one per turn).
 */
let _pendingSkipCount = 0;

/**
 * Register the secret scanner on the pi extension API.
 *
 * Uses `before_provider_request` to scan and redact secrets (ADR-0002).
 * Uses `after_provider_response` to notify the user.
 *
 * Scan budget (ADR-0013): payloads whose total string content exceeds
 * `scanBudgetBytes` skip the line-by-line scan, emit ONE `secret.skipped`
 * audit entry + notification, and still run PEM private-key redaction —
 * the budget never bypasses PEM redaction and never skips silently.
 */
export function registerSecretScanner(
	pi: ExtensionAPI,
	getConfig: () => Config,
): void {
	pi.on("before_provider_request", (event, _ctx) => {
		const redactions: Redaction[] = [];
		const payload = event.payload as Record<string, unknown>;

		// Budget gate: measure first (cheap linear pass), then decide.
		const budget = resolveScanBudget(getConfig());
		const bytes = sumStringBytes(payload);
		if (bytes > budget) {
			// Over budget — skip the line-by-line scan, but NEVER bypass
			// PEM redaction: it runs before line-splitting by design and
			// stays in front of the budget.
			walkAndRedactPEMOnly(payload, redactions);
			for (const r of redactions) {
				auditLog("secret.redacted", "warning", {
					patternName: r.patternName,
					originalLength: r.original.length,
				});
			}
			_pendingRedactionCount += redactions.length;
			_pendingSkipCount += 1;

			// Exactly one skip event per over-budget request — never a
			// silent skip.
			auditLog("secret.skipped", "warning", {
				bytes,
				budget,
			});

			return redactions.length > 0 ? payload : undefined;
		}

		// Walk and redact in place
		walkAndRedact(payload, redactions);

		if (redactions.length > 0) {
			_pendingRedactionCount += redactions.length;

			// Log each redaction to audit
			for (const r of redactions) {
				auditLog("secret.redacted", "warning", {
					patternName: r.patternName,
					originalLength: r.original.length,
				});
			}

			// Return modified payload
			return payload;
		}

		// No redactions — return undefined to keep payload unchanged
		return undefined;
	});

	pi.on("after_provider_response", (_event, ctx) => {
		if (_pendingSkipCount > 0) {
			const skipped = _pendingSkipCount;
			_pendingSkipCount = 0;

			if (ctx.hasUI) {
				ctx.ui.notify(
					`⚠️ secret scan skipped on ${skipped} request(s) this turn — payload exceeded scanBudgetBytes; PEM private keys were still redacted`,
					"warning",
				);
			}
		}
		if (_pendingRedactionCount > 0) {
			const count = _pendingRedactionCount;
			_pendingRedactionCount = 0;

			if (ctx.hasUI) {
				ctx.ui.notify(
					`⚠️ ${count} secret(s) redacted from context this turn`,
					"warning",
				);
			}
		}
	});

	// Reset counters at turn start to scope counts per turn
	pi.on("turn_start", () => {
		_pendingRedactionCount = 0;
		_pendingSkipCount = 0;
	});
}
