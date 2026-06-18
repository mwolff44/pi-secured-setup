/**
 * Secret scanner — `before_provider_request` handler.
 *
 * Provider-agnostic: recursively walks the entire payload for string values,
 * runs regex matching, and replaces secrets with `***REDACTED:{pattern-name}***`.
 * No parsing of provider-specific message structures (ADR-0002).
 *
 * Only scans the request — not the response. Input-side redaction prevents
 * secrets from reaching the model, so they cannot appear in responses.
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
 */
function redactLineContent(line: string): { result: string; redactions: Redaction[] } {
	let result = line;
	const redactions: Redaction[] = [];

	for (const { name, pattern } of SECRET_PATTERNS) {
		const regex = new RegExp(pattern.source, pattern.flags);

		let match: RegExpExecArray | null;
		while ((match = regex.exec(result)) !== null) {
			const matched = match[0];

			if (isPlaceholder(matched)) continue;

			const replacement = `***REDACTED:${name}***`;
			redactions.push({ patternName: name, original: matched });

			result =
				result.slice(0, match.index) +
				replacement +
				result.slice(match.index + matched.length);

			regex.lastIndex = match.index + replacement.length;
		}
	}

	return { result, redactions };
}

/**
 * Scan and redact secrets from a string value.
 * First redacts multi-line PEM private key blocks as a whole,
 * then processes remaining content line-by-line.
 * Only individual comment lines are skipped; non-comment lines
 * have secrets redacted normally.
 * Returns the redacted string and a list of redactions performed.
 */
export function redactString(value: string, options: RedactOptions = {}): { result: string; redactions: Redaction[] } {
	const skipComments = options.skipCommentLines !== false;

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

// ── Scanner registration ──────────────────────────────────────────────

/**
 * Turn-scoped redaction count for the after_provider_response notification.
 */
let _pendingRedactionCount = 0;

/**
 * Register the secret scanner on the pi extension API.
 *
 * Uses `before_provider_request` to scan and redact secrets (ADR-0002).
 * Uses `after_provider_response` to notify the user.
 */
export function registerSecretScanner(
	pi: ExtensionAPI,
	_getConfig: () => Config,
): void {
	pi.on("before_provider_request", (event, _ctx) => {
		const redactions: Redaction[] = [];
		const payload = event.payload as Record<string, unknown>;

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

	// Reset counter at turn start to scope redaction counts per turn
	pi.on("turn_start", () => {
		_pendingRedactionCount = 0;
	});
}
