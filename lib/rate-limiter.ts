/**
 * In-memory rate limiter for tool calls and confirmations.
 *
 * Two scopes with independent lifecycles:
 *   - `tool_calls`    — per turn, reset by `resetTurn()` on `turn_start`
 *   - `confirmations` — per session, cumulative, reset by `resetSession()`
 *
 * Monotonic counters; no external state. Fail-closed: when a limit is
 * exceeded, `checkLimit` returns `{ allowed: false }` and the caller is
 * expected to block the action (see the guard-pipeline integration).
 *
 * Audit log writes are intentionally NOT a rate-limit scope: silently
 * dropping forensic entries when over budget would let an attacker
 * suppress evidence of their actions by flooding the log. Disk usage
 * is bounded by rotation; write rate is indirectly bounded by the
 * `tool_calls` per-turn cap. See ADR-0010.
 *
 * The limits object is supplied by the caller. Runtime config loads it
 * machine-only from `security-policy.json` via `loadSecurityPolicy` in
 * config.ts; the shape is shared as `SecurityPolicy` (an alias of
 * `SecurityLimits` defined here so this module stays a pure leaf).
 */

/**
 * The limits shape consumed by the rate limiter. Aliased as
 * `SecurityPolicy` in config.ts. Kept here (rather than imported from
 * config.ts) so this module has no inbound lib dependencies and is
 * independently unit-testable.
 *
 * The `tokensPerTurnWarn` / `toolCallsPerMinuteWarn` / `tokensSessionWarn`
 * fields are anomaly-detection thresholds consumed by the metrics scanner
 * (P2-5). They are optional on the interface so existing test fixtures
 * that build a `SecurityLimits` literal keep compiling; runtime config
 * from `loadConfig` always populates them via `DEFAULT_SECURITY_POLICY`.
 * Consumers must fall back to the shipped defaults when the fields are
 * absent (see `resolveMetricsThresholds` in `metrics-scanner.ts`).
 */
export interface SecurityLimits {
	/** Max tool calls within a single turn (reset on turn_start). */
	toolCallsPerTurn: number;
	/** Max confirmation dialogs within a single session (cumulative). */
	confirmationsPerSession: number;
	/** Per-turn token-count anomaly threshold (metrics scanner). */
	tokensPerTurnWarn?: number;
	/** Sliding 1-minute tool-call-count anomaly threshold (metrics scanner). */
	toolCallsPerMinuteWarn?: number;
	/** Cumulative session token-count anomaly threshold (metrics scanner). */
	tokensSessionWarn?: number;
}

export type RateLimitScope = "tool_calls" | "confirmations";

export interface RateLimitResult {
	allowed: boolean;
	/** Current count after this call's increment / window evaluation. */
	count: number;
	/** The limit value evaluated against. */
	limit: number;
	/** Human-readable reason when not allowed. */
	reason?: string;
}

// ── Counters (module-scoped, monotonic) ────────────────────────────────

let _toolCallCount = 0;
let _confirmationCount = 0;

/**
 * Check whether an action under `scope` is allowed given `limits`.
 *
 * Side effect: increments the relevant counter (`tool_calls` /
 * `confirmations`). The increment happens unconditionally so the
 * returned `count` reflects the current attempt including this call.
 *
 * Semantics: the first `limit` calls within the scope's lifecycle are
 * allowed; call `limit + 1` is blocked, as is every subsequent call
 * until the counter is reset.
 */
export function checkLimit(
	scope: RateLimitScope,
	limits: SecurityLimits,
): RateLimitResult {
	switch (scope) {
		case "tool_calls": {
			_toolCallCount += 1;
			const limit = limits.toolCallsPerTurn;
			if (_toolCallCount > limit) {
				return {
					allowed: false,
					count: _toolCallCount,
					limit,
					reason: `tool_calls rate limit exceeded (${_toolCallCount}/${limit} per turn)`,
				};
			}
			return { allowed: true, count: _toolCallCount, limit };
		}
		case "confirmations": {
			_confirmationCount += 1;
			const limit = limits.confirmationsPerSession;
			if (_confirmationCount > limit) {
				return {
					allowed: false,
					count: _confirmationCount,
					limit,
					reason: `confirmations rate limit exceeded (${_confirmationCount}/${limit} per session)`,
				};
			}
			return { allowed: true, count: _confirmationCount, limit };
		}
	}
}

/**
 * Reset the per-turn counter (`tool_calls`). Called on `turn_start`.
 */
export function resetTurn(): void {
	_toolCallCount = 0;
}

/**
 * Reset the per-session counter (`confirmations`). Called on
 * `session_start`.
 */
export function resetSession(): void {
	_confirmationCount = 0;
}

/**
 * Reset ALL counters. Intended for tests to isolate module state
 * between cases.
 */
export function _resetAllForTest(): void {
	_toolCallCount = 0;
	_confirmationCount = 0;
}

/**
 * Read-only snapshot of current counts. Intended for tests / debugging.
 */
export function _snapshotForTest(): {
	toolCalls: number;
	confirmations: number;
} {
	return {
		toolCalls: _toolCallCount,
		confirmations: _confirmationCount,
	};
}
