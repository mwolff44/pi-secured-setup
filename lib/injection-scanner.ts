/**
 * Injection scanner — `before_provider_request` handler.
 *
 * Heuristic prompt-injection detection. Provider-agnostic: recursively walks
 * the entire payload for string values, runs regex heuristics, and wraps
 * suspicious segments in `[UNTRUSTED CONTENT]…[/UNTRUSTED CONTENT]` markers.
 * No parsing of provider-specific message structures (ADR-0002).
 *
 * This is a SCANNER: it detects, marks, and notifies but NEVER blocks the
 * provider request (ADR-0006; CONTEXT.md — "a Scanner ... never prevent(s)
 * a tool from running"). The request always proceeds; only its payload text
 * may be annotated. Only the request is scanned — not the response.
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import type { Config, InjectionRule } from "./config.js";
import { auditLog } from "./audit.js";
import { isCommentLine } from "./secret-scanner.js";
import { DEFAULTS_DIR } from "./utils.js";

// ── Types ─────────────────────────────────────────────────────────────

export interface InjectionFinding {
	patternName: string;
}

interface CompiledPattern {
	name: string;
	pattern: RegExp;
}

interface InjectionRulesFile {
	patterns: InjectionRule[];
	threshold: number;
}

const DEFAULT_THRESHOLD = 3;

// ── Pattern compilation ───────────────────────────────────────────────

/**
 * Compile raw pattern strings into RegExp instances (case-insensitive).
 * Invalid patterns are skipped during compilation — parity with the
 * bash-gate's `classifySegment`, which silently drops unparseable regexes.
 */
function compileRules(rules: InjectionRule[]): CompiledPattern[] {
	const compiled: CompiledPattern[] = [];
	for (const rule of rules) {
		try {
			compiled.push({ name: rule.name, pattern: new RegExp(rule.pattern, "i") });
		} catch {
			// Skip invalid regex patterns.
		}
	}
	return compiled;
}

/**
 * Minimal built-in fallback used only if `defaults/injection-rules.json`
 * cannot be read at module load. The JSON file is the source of truth for
 * the shipped defaults; this constant merely guarantees the scanner has at
 * least one pattern if the file is missing or unreadable.
 */
const FALLBACK_RULES: InjectionRule[] = [
	{
		name: "ignore-previous-instructions",
		pattern: "ignore (?:all |the |everything |any |your )?(?:previous|prior|above|earlier) (?:instructions|rules|prompts?)",
	},
];

// ── Module-level runtime state ────────────────────────────────────────

let _patterns: CompiledPattern[] = compileRules(FALLBACK_RULES);
let _threshold: number = DEFAULT_THRESHOLD;

/**
 * Load the default patterns from `defaults/injection-rules.json` at module
 * init so `detectInjection(text)` works standalone with the shipped
 * defaults. `registerInjectionScanner` later overrides this with the
 * machine-merged config on each request.
 */
function loadDefaultRules(): void {
	try {
		const raw = readFileSync(resolve(DEFAULTS_DIR, "injection-rules.json"), "utf-8");
		const parsed = JSON.parse(raw) as InjectionRulesFile;
		if (parsed.patterns && parsed.patterns.length > 0) {
			_patterns = compileRules(parsed.patterns);
		}
		if (typeof parsed.threshold === "number" && parsed.threshold > 0) {
			_threshold = parsed.threshold;
		}
	} catch {
		// Keep the hardcoded fallback.
	}
}
loadDefaultRules();

/**
 * Replace the active injection patterns at runtime (called by the
 * registration with the machine-merged config). Invalid patterns are
 * skipped during compilation. Empty rule lists leave the existing patterns
 * in place so callers cannot accidentally disarm detection by passing `[]`.
 */
export function setInjectionRules(rules: InjectionRule[], threshold: number): void {
	if (Array.isArray(rules) && rules.length > 0) {
		_patterns = compileRules(rules);
	}
	if (typeof threshold === "number" && threshold > 0) {
		_threshold = threshold;
	}
}

// ── Detection ─────────────────────────────────────────────────────────

/**
 * Detect prompt-injection indicators in a string. Processes the text
 * line-by-line, skipping comment lines (`#`, `//`, `/*`, `--`) for parity
 * with the secret scanner's `isCommentLine`. Returns one entry per
 * distinct pattern that matched at least once (deduplicated by name).
 */
export function detectInjection(text: string): InjectionFinding[] {
	const found = new Set<string>();
	for (const line of text.split("\n")) {
		if (isCommentLine(line)) continue;
		for (const { name, pattern } of _patterns) {
			if (pattern.test(line)) {
				found.add(name);
			}
		}
	}
	return Array.from(found).map((patternName) => ({ patternName }));
}

/**
 * Wrap a string in `[UNTRUSTED CONTENT]…[/UNTRUSTED CONTENT]` markers when
 * injection indicators are found. Multi-line strings are wrapped once as a
 * whole (not per line). Returns the string unchanged when nothing matched.
 */
export function markUntrusted(text: string): string {
	if (detectInjection(text).length === 0) return text;
	return `[UNTRUSTED CONTENT]\n${text}\n[/UNTRUSTED CONTENT]`;
}

// ── Payload walk ──────────────────────────────────────────────────────

/**
 * Scan + mark a single string, accumulating findings into `findings`.
 * Avoids running detection twice by computing it once and reusing the
 * result to decide whether to wrap.
 */
function scanString(text: string, findings: InjectionFinding[]): string {
	const detected = detectInjection(text);
	if (detected.length === 0) return text;
	findings.push(...detected);
	return `[UNTRUSTED CONTENT]\n${text}\n[/UNTRUSTED CONTENT]`;
}

/**
 * Recursively walk a payload object, detecting and marking injection
 * payloads in all string values. Mutates the object in place and returns
 * it together with the aggregated findings. Depth is capped at 50.
 * Does NOT parse provider message structure (ADR-0002) — this is the
 * symmetric counterpart of the secret scanner's `walkAndRedact`.
 */
export function walkAndMark(payload: unknown): {
	findings: InjectionFinding[];
	payload: unknown;
} {
	const findings: InjectionFinding[] = [];
	const result = walkNode(payload, findings, 0);
	return { findings, payload: result };
}

function walkNode(obj: unknown, findings: InjectionFinding[], depth: number): unknown {
	if (depth > 50) return obj; // safety limit

	if (typeof obj === "string") {
		return scanString(obj, findings);
	}

	if (Array.isArray(obj)) {
		for (let i = 0; i < obj.length; i++) {
			obj[i] = walkNode(obj[i], findings, depth + 1);
		}
		return obj;
	}

	if (obj !== null && typeof obj === "object") {
		const record = obj as Record<string, unknown>;
		for (const key of Object.keys(record)) {
			record[key] = walkNode(record[key], findings, depth + 1);
		}
		return obj;
	}

	return obj;
}

// ── Scanner registration ─────────────────────────────────────────────

/**
 * Turn-scoped injection count for the after_provider_response notification.
 */
let _pendingInjectionCount = 0;

/**
 * Register the injection scanner on the pi extension API.
 *
 * SCANNER CONTRACT (ADR-0006; CONTEXT.md): this handler mutates the
 * provider payload to mark detected injection segments and notifies the
 * user, but it NEVER blocks the provider request. It returns the (possibly
 * annotated) payload — never a block verdict. Detection always runs; the
 * request always proceeds.
 */
export function registerInjectionScanner(
	pi: ExtensionAPI,
	getConfig: () => Config,
): void {
	pi.on("before_provider_request", (event, _ctx) => {
		// Refresh patterns from the current (machine-merged) config on each
		// request so config reloads are picked up. getConfig() returns an
		// already-merged in-memory object — no per-turn file I/O.
		const cfg = getConfig();
		setInjectionRules(cfg.injection.patterns, cfg.injection.threshold);

		const payload = event.payload as Record<string, unknown>;
		const { findings } = walkAndMark(payload);

		if (findings.length === 0) {
			// No findings — keep payload unchanged.
			return undefined;
		}

		_pendingInjectionCount += findings.length;

		// Aggregate pattern names + counts only. Do NOT log verbatim matched
		// text — that would amplify the very payload we are defending against
		// and write attacker-controlled content into the tamper-evident log.
		const counts: Record<string, number> = {};
		for (const { patternName } of findings) {
			counts[patternName] = (counts[patternName] ?? 0) + 1;
		}
		auditLog("injection.detected", "warning", {
			count: findings.length,
			patterns: counts,
		});

		// Scanner contract: return the marked payload, never a block verdict.
		return payload;
	});

	pi.on("after_provider_response", (_event, ctx) => {
		if (_pendingInjectionCount > 0) {
			const count = _pendingInjectionCount;
			_pendingInjectionCount = 0;

			if (ctx.hasUI) {
				// Escalate severity when the per-turn count exceeds the
				// configured threshold (multiple indicators suggest a
				// concerted injection attempt rather than a stray match).
				const severity = count > _threshold ? "error" : "warning";
				ctx.ui.notify(
					`⚠️ ${count} potential prompt-injection segment(s) detected and marked as untrusted this turn`,
					severity,
				);
			}
		}
	});

	// Reset counter at turn start to scope counts per turn.
	pi.on("turn_start", () => {
		_pendingInjectionCount = 0;
	});
}
