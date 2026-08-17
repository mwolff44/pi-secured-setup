/**
 * Metrics scanner — token / cost tracking + anomaly detection (P2-5).
 *
 * Estimates tokens per turn, accumulates per-session counters in memory,
 * and emits a `turn.metrics` audit event on every `after_provider_response`.
 * Anomaly thresholds (read from `config.securityPolicy` via the
 * `SecurityLimits` type P2-3 added to Config) trigger an additional
 * `anomaly` audit event + UI notification. This is a SCANNER: it
 * observes and reports — it NEVER blocks the provider request (ADR-0006;
 * CONTEXT.md — "a Scanner ... never prevent(s) a tool from running").
 *
 * Provider-agnostic token estimation (ADR-0002):
 *   1. Prefer a `usage` / `usage_metadata` block found anywhere in the
 *      `after_provider_response` event payload (recursive walk, same
 *      shape as the secret scanner's `walkAndRedact`).
 *   2. Fall back to the chars/4 heuristic over string values in the
 *      request payload captured at `before_provider_request`.
 *
 * Safety: only token counts (and optionally the model name) are written
 * to the audit log — never request/response text. By the time the
 * metrics scanner runs, the secret scanner has already redacted secrets
 * from the request payload, so the heuristic inputs are also safe.
 */
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import type { Config } from "./config.js";
import { auditLog } from "./audit.js";

// ── Default thresholds ────────────────────────────────────────────────

/**
 * Shipped default anomaly thresholds. Generous defaults that avoid false
 * positives on legitimate heavy workflows — including modern
 * large-context models (150k+ tokens) and tool-bearing turns whose
 * definitions alone routinely consume 10–20k tokens — while still
 * alerting on runaway loops and denial-of-wallet patterns. Mirrored
 * into `defaults/security-policy.json` and `DEFAULT_SECURITY_POLICY` so
 * all three locations stay in sync; this constant is the final fallback
 * when neither the config layer nor `DEFAULT_SECURITY_POLICY` supplies a
 * value. Operators can tune all three thresholds via the machine-layer
 * `~/.pi/agent/security/security-policy.json` (the project layer cannot
 * raise them — see ADR-0009).
 */
export const DEFAULT_METRICS_THRESHOLDS = {
	tokensPerTurnWarn: 32000,
	toolCallsPerMinuteWarn: 60,
	tokensSessionWarn: 200000,
} as const;

/** Sliding-window duration for the tool-calls-per-minute estimate. */
const TOOL_CALL_WINDOW_MS = 60_000;

/** Depth cap for the recursive payload walks (parity with secret scanner). */
const MAX_WALK_DEPTH = 50;

// ── Token estimation: payload walks ───────────────────────────────────

/**
 * Recursively walk a payload summing the lengths of all string values.
 * Provider-agnostic (ADR-0002): no parsing of message structure.
 * Used by the chars/4 fallback heuristic.
 */
export function sumStringChars(obj: unknown, depth = 0): number {
	if (depth > MAX_WALK_DEPTH) return 0;
	if (typeof obj === "string") return obj.length;
	if (Array.isArray(obj)) {
		let sum = 0;
		for (const item of obj) sum += sumStringChars(item, depth + 1);
		return sum;
	}
	if (obj !== null && typeof obj === "object") {
		let sum = 0;
		const record = obj as Record<string, unknown>;
		for (const key of Object.keys(record)) {
			sum += sumStringChars(record[key], depth + 1);
		}
		return sum;
	}
	return 0;
}

/**
 * Extract a numeric token count from an OpenAI-style `usage` block.
 * Accepts any of: `total_tokens`, `prompt_tokens`+`completion_tokens`,
 * `input_tokens`+`output_tokens`. Returns null when no numeric field
 * is present.
 */
function tokensFromUsage(u: Record<string, unknown>): number | null {
	const total = u.total_tokens;
	if (typeof total === "number" && total >= 0) return total;
	const prompt = u.prompt_tokens ?? u.input_tokens;
	const completion = u.completion_tokens ?? u.output_tokens;
	if (typeof prompt === "number" && typeof completion === "number") {
		return prompt + completion;
	}
	if (typeof prompt === "number") return prompt;
	if (typeof completion === "number") return completion;
	return null;
}

/**
 * Extract a numeric token count from a Google-style `usage_metadata`
 * block. Accepts any of: `total_token_count`,
 * `prompt_token_count`+`candidates_token_count`.
 */
function tokensFromUsageMetadata(u: Record<string, unknown>): number | null {
	const total = u.total_token_count;
	if (typeof total === "number" && total >= 0) return total;
	const prompt = u.prompt_token_count;
	const completion = u.candidates_token_count;
	if (typeof prompt === "number" && typeof completion === "number") {
		return prompt + completion;
	}
	if (typeof prompt === "number") return prompt;
	if (typeof completion === "number") return completion;
	return null;
}

/**
 * Recursively walk a payload looking for the first `usage` or
 * `usage_metadata` object that yields a numeric token count. Returns the
 * total token count when found, else null. Stops at the first hit so
 * nested duplicates do not double-count.
 */
export function findUsageTokens(obj: unknown, depth = 0): number | null {
	if (depth > MAX_WALK_DEPTH) return null;
	if (obj === null || typeof obj !== "object") return null;
	const record = obj as Record<string, unknown>;

	// Direct hit on this object — check both known key shapes.
	const usage = record.usage;
	if (usage && typeof usage === "object") {
		const t = tokensFromUsage(usage as Record<string, unknown>);
		if (t !== null) return t;
	}
	const usageMetadata = record.usage_metadata;
	if (usageMetadata && typeof usageMetadata === "object") {
		const t = tokensFromUsageMetadata(usageMetadata as Record<string, unknown>);
		if (t !== null) return t;
	}

	// Recurse into children (arrays and object values).
	if (Array.isArray(obj)) {
		for (const item of obj) {
			const t = findUsageTokens(item, depth + 1);
			if (t !== null) return t;
		}
	} else {
		for (const key of Object.keys(record)) {
			const t = findUsageTokens(record[key], depth + 1);
			if (t !== null) return t;
		}
	}
	return null;
}

/**
 * Estimate tokens for a turn. Prefer the provider-reported `usage` /
 * `usage_metadata` field found by walking the response event; fall back
 * to the chars/4 heuristic over the request payload string lengths.
 *
 * @param responseEvent  The `after_provider_response` event (or any value
 *                       to search for usage info).
 * @param requestCharsFallback  Total chars summed across the request
 *                              payload's string values (captured on
 *                              `before_provider_request`).
 */
export function estimateTokens(responseEvent: unknown, requestCharsFallback: number): number {
	const fromUsage = findUsageTokens(responseEvent);
	if (fromUsage !== null && fromUsage >= 0) return fromUsage;
	return Math.ceil(requestCharsFallback / 4);
}

/**
 * Best-effort extraction of a model identifier from a provider event.
 * Looks on the event itself and under common nested keys
 * (`response`, `request`, `body`). Returns undefined when not found —
 * callers must handle the missing case gracefully.
 */
function extractModel(event: unknown): string | undefined {
	if (typeof event !== "object" || event === null) return undefined;
	const r = event as Record<string, unknown>;
	if (typeof r.model === "string") return r.model;
	for (const k of ["response", "request", "body", "payload"]) {
		const child = r[k];
		if (child && typeof child === "object") {
			const m = (child as Record<string, unknown>).model;
			if (typeof m === "string") return m;
		}
	}
	return undefined;
}

// ── Module-level runtime state ────────────────────────────────────────

let _tokensThisTurn = 0;
let _tokensSessionTotal = 0;
/** Timestamps (ms) of recent provider round-trips within the sliding window. */
const _toolCallTimestamps: number[] = [];
/**
 * Total chars across string values in the request payload captured on
 * `before_provider_request`. Consumed as the fallback heuristic input
 * on `after_provider_response`. Reset on every request and on turn_start.
 */
let _pendingRequestChars = 0;

/** Per-turn state reset (called on `turn_start`). */
function resetTurn(): void {
	_tokensThisTurn = 0;
	_pendingRequestChars = 0;
}

/** Per-session state reset (called on `session_start`). */
function resetSession(): void {
	_tokensThisTurn = 0;
	_tokensSessionTotal = 0;
	_toolCallTimestamps.length = 0;
	_pendingRequestChars = 0;
}

/**
 * Drop timestamps aged out of the sliding 1-minute window and return the
 * number of remaining (in-window) entries.
 */
function countRecentToolCalls(now: number): number {
	const cutoff = now - TOOL_CALL_WINDOW_MS;
	while (_toolCallTimestamps.length > 0 && _toolCallTimestamps[0] <= cutoff) {
		_toolCallTimestamps.shift();
	}
	return _toolCallTimestamps.length;
}

// ── Threshold resolution ──────────────────────────────────────────────

export interface MetricsThresholds {
	tokensPerTurnWarn: number;
	toolCallsPerMinuteWarn: number;
	tokensSessionWarn: number;
}

/**
 * Resolve the active anomaly thresholds from the runtime config.
 *
 * `securityPolicy` is optional on `Config` (P2-3): when absent, or when a
 * specific field is missing, we fall back to the shipped defaults from
 * `DEFAULT_METRICS_THRESHOLDS`. A field present but `<= 0` is treated as
 * "unset" so operators can explicitly disable a threshold by setting it
 * to 0 (matching the rate limiter's validation convention).
 */
export function resolveMetricsThresholds(config: Config): MetricsThresholds {
	const sp = config.securityPolicy;
	const pick = (value: number | undefined, fallback: number): number =>
		typeof value === "number" && value > 0 ? value : fallback;
	return {
		tokensPerTurnWarn: pick(sp?.tokensPerTurnWarn, DEFAULT_METRICS_THRESHOLDS.tokensPerTurnWarn),
		toolCallsPerMinuteWarn: pick(sp?.toolCallsPerMinuteWarn, DEFAULT_METRICS_THRESHOLDS.toolCallsPerMinuteWarn),
		tokensSessionWarn: pick(sp?.tokensSessionWarn, DEFAULT_METRICS_THRESHOLDS.tokensSessionWarn),
	};
}

// ── Test hooks ────────────────────────────────────────────────────────

/**
 * Reset ALL module-scoped state. Intended for tests to isolate module
 * state between cases.
 */
export function _resetAllForTest(): void {
	resetSession();
}

/**
 * Read-only snapshot of current counters. Intended for tests / debugging.
 */
export function _snapshotForTest(): {
	tokensThisTurn: number;
	tokensSessionTotal: number;
	toolCallsInWindow: number;
	pendingRequestChars: number;
} {
	return {
		tokensThisTurn: _tokensThisTurn,
		tokensSessionTotal: _tokensSessionTotal,
		toolCallsInWindow: _toolCallTimestamps.length,
		pendingRequestChars: _pendingRequestChars,
	};
}

// ── Scanner registration ──────────────────────────────────────────────

/**
 * Register the metrics scanner on the pi extension API.
 *
 * SCANNER CONTRACT (ADR-0006; CONTEXT.md): this handler observes traffic
 * and emits metrics + anomaly events to the audit log; it NEVER blocks
 * the provider request. The `before_provider_request` handler returns
 * `undefined` always — it only captures the request char count as
 * fallback input. Anomaly detection does NOT prevent the request from
 * proceeding.
 *
 * Event flow:
 *   - `before_provider_request`: capture sum of request string chars.
 *   - `after_provider_response`: estimate tokens (usage or fallback),
 *     accumulate session + turn counters, emit `turn.metrics`, slide
 *     the tool-call window, evaluate thresholds, emit `anomaly` events.
 *   - `turn_start`: reset per-turn counters.
 *   - `session_start`: reset all session counters.
 */
export function registerMetricsScanner(
	pi: ExtensionAPI,
	getConfig: () => Config,
): void {
	pi.on("before_provider_request", (event, _ctx) => {
		_pendingRequestChars = sumStringChars(event.payload);
		// Scanner contract: return undefined — never block, never mutate.
		return undefined;
	});

	pi.on("after_provider_response", (event, ctx) => {
		const tokens = estimateTokens(event, _pendingRequestChars);

		_tokensThisTurn = tokens;
		_tokensSessionTotal += tokens;

		const model = extractModel(event);

		// Emit metrics. Only the count + (optional) model name are written.
		// The request payload was already redacted by the secret scanner
		// by this point; we additionally avoid logging any text — only
		// token counts reach the audit log.
		auditLog("turn.metrics", "info", {
			tokensTurn: tokens,
			tokensSession: _tokensSessionTotal,
			...(model ? { model } : {}),
		});

		// Approximate "tool calls / minute" using provider round-trips
		// within the sliding window. Each turn corresponds to one
		// provider request; this is the closest signal available to a
		// scanner that observes provider traffic.
		const now = Date.now();
		_toolCallTimestamps.push(now);
		const toolCallsInWindow = countRecentToolCalls(now);

		// Anomaly detection — observer only, never blocks.
		const thresholds = resolveMetricsThresholds(getConfig());
		const anomalies: Array<{
			kind: "tokens-per-turn" | "tool-calls-per-minute" | "session-tokens";
			value: number;
			threshold: number;
			message: string;
		}> = [];

		if (tokens > thresholds.tokensPerTurnWarn) {
			anomalies.push({
				kind: "tokens-per-turn",
				value: tokens,
				threshold: thresholds.tokensPerTurnWarn,
				message: `Token spike: ${tokens} tokens this turn (threshold ${thresholds.tokensPerTurnWarn})`,
			});
		}
		if (toolCallsInWindow > thresholds.toolCallsPerMinuteWarn) {
			anomalies.push({
				kind: "tool-calls-per-minute",
				value: toolCallsInWindow,
				threshold: thresholds.toolCallsPerMinuteWarn,
				message: `High tool-call rate: ${toolCallsInWindow}/min (threshold ${thresholds.toolCallsPerMinuteWarn}/min)`,
			});
		}
		if (_tokensSessionTotal > thresholds.tokensSessionWarn) {
			anomalies.push({
				kind: "session-tokens",
				value: _tokensSessionTotal,
				threshold: thresholds.tokensSessionWarn,
				message: `Session token budget exceeded: ${_tokensSessionTotal} tokens (threshold ${thresholds.tokensSessionWarn})`,
			});
		}

		for (const a of anomalies) {
			auditLog("anomaly", "warning", {
				kind: a.kind,
				value: a.value,
				threshold: a.threshold,
			});
			if (ctx.hasUI) {
				ctx.ui.notify(`⚠️ ${a.message}`, "warning");
			}
		}
	});

	pi.on("turn_start", () => {
		resetTurn();
	});

	pi.on("session_start", () => {
		resetSession();
	});
}
