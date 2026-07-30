/**
 * Unit tests for lib/metrics-scanner.ts (P2-5)
 *
 * Covers:
 *   AC#1 — Dashboard surfaces tokens/session + tool_calls/min
 *          (aggregateSessionMetrics reads turn.metrics events).
 *   AC#2 — tokensPerTurnWarn exceeded → anomaly audit event + notify.
 *   AC#3 — Metrics scanner NEVER blocks (returns undefined /
 *          the payload, never a block verdict).
 *   AC#4 — turn.metrics details contain no secret-like values
 *          (only token counts).
 *   AC#5 — Thresholds read from config.securityPolicy with fallback
 *          to shipped defaults when absent.
 *   Plus: usage-block discovery (OpenAI / Google shapes), chars/4
 *   fallback, sliding-window tool-call counting, turn_start /
 *   session_start resets.
 */
import { describe, it, beforeEach, afterEach, mock } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, rmSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { tmpdir } from "node:os";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import type { Config } from "../lib/config.js";
import {
	registerMetricsScanner,
	sumStringChars,
	findUsageTokens,
	estimateTokens,
	resolveMetricsThresholds,
	DEFAULT_METRICS_THRESHOLDS,
	_resetAllForTest,
	_snapshotForTest,
} from "../lib/metrics-scanner.js";
import {
	initAuditLog,
	_setAuditFileForTest,
	aggregateSessionMetrics,
	getSessionId,
} from "../lib/audit.js";
import type { AuditEntry } from "../lib/audit.js";

// ── Helpers ───────────────────────────────────────────────────────────

function makeConfig(overrides: Partial<Config> = {}): Config {
	return {
		cwd: "/home/user/project",
		protectedPaths: { patterns: [], writeAction: "block", readAction: "confirm" },
		commandRules: { safe: [], moderate: [], dangerous: [], external: [] },
		allowedExternal: { paths: [] },
		audit: { maxFileSize: 10_000_000, maxFiles: 3 },
		injection: { patterns: [], threshold: 3 },
		...overrides,
	};
}

function configWithPolicy(policy: NonNullable<Config["securityPolicy"]>): Config {
	return makeConfig({ securityPolicy: policy });
}

/**
 * Capture pi event handlers so tests can dispatch them directly.
 */
function createMockPi(): {
	pi: ExtensionAPI;
	handlers: Record<string, Array<(event: any, ctx: any) => unknown>>;
} {
	const handlers: Record<string, Array<(event: any, ctx: any) => unknown>> = {};
	const pi = {
		on(event: string, handler: (event: any, ctx: any) => unknown) {
			(handlers[event] ??= []).push(handler);
		},
		registerCommand() {},
	} as unknown as ExtensionAPI;
	return { pi, handlers };
}

function readAuditEntries(file: string): AuditEntry[] {
	if (!existsSync(file)) return [];
	const content = readFileSync(file, "utf-8").trim();
	if (!content) return [];
	const entries: AuditEntry[] = [];
	for (const line of content.split("\n")) {
		try {
			entries.push(JSON.parse(line) as AuditEntry);
		} catch {
			// skip malformed
		}
	}
	return entries;
}

function dispatchBeforeProviderRequest(
	handlers: Record<string, Array<(event: any, ctx: any) => unknown>>,
	payload: unknown,
	ctx: any = { hasUI: false, ui: { notify: () => {} } },
): unknown {
	return handlers["before_provider_request"][0]({ type: "before_provider_request", payload }, ctx);
}

function dispatchAfterProviderResponse(
	handlers: Record<string, Array<(event: any, ctx: any) => unknown>>,
	responseEvent: any = { type: "after_provider_response", status: 200, headers: {} },
	ctx: any = { hasUI: false, ui: { notify: () => {} } },
): void {
	handlers["after_provider_response"][0](responseEvent, ctx);
}

// ── sumStringChars ────────────────────────────────────────────────────

describe("sumStringChars", () => {
	it("sums lengths of flat string values", () => {
		assert.equal(sumStringChars({ a: "hello", b: "world" }), 10);
	});

	it("walks nested objects and arrays", () => {
		const payload = {
			messages: [
				{ role: "user", content: "abc" },
				{ role: "assistant", content: "wxyz" },
			],
		};
		// "user" + "abc" + "assistant" + "wxyz" = 4 + 3 + 9 + 4 = 20
		assert.equal(sumStringChars(payload), 20);
	});

	it("ignores non-string primitives", () => {
		assert.equal(sumStringChars({ num: 42, bool: true, nil: null }), 0);
	});

	it("respects the depth cap", () => {
		let deep: any = "leaf";
		for (let i = 0; i < 60; i++) deep = { nested: deep };
		// Deep enough that the leaf is beyond MAX_WALK_DEPTH — must not throw.
		assert.doesNotThrow(() => sumStringChars(deep));
		assert.ok(typeof sumStringChars(deep) === "number");
	});
});

// ── findUsageTokens ───────────────────────────────────────────────────

describe("findUsageTokens", () => {
	it("extracts total_tokens from an OpenAI-style usage block", () => {
		const event = { response: { usage: { prompt_tokens: 100, completion_tokens: 50, total_tokens: 150 } } };
		assert.equal(findUsageTokens(event), 150);
	});

	it("sums prompt+completion when total_tokens is absent", () => {
		const event = { usage: { prompt_tokens: 80, completion_tokens: 20 } };
		assert.equal(findUsageTokens(event), 100);
	});

	it("extracts input/output tokens (Anthropic-style)", () => {
		const event = { usage: { input_tokens: 200, output_tokens: 40 } };
		assert.equal(findUsageTokens(event), 240);
	});

	it("extracts total_token_count from a Google usage_metadata block", () => {
		const event = { usage_metadata: { prompt_token_count: 300, candidates_token_count: 75, total_token_count: 375 } };
		assert.equal(findUsageTokens(event), 375);
	});

	it("sums prompt+candidates when total_token_count is absent", () => {
		const event = { usage_metadata: { prompt_token_count: 300, candidates_token_count: 75 } };
		assert.equal(findUsageTokens(event), 375);
	});

	it("walks nested arrays looking for usage", () => {
		const event = {
			choices: [
				{ message: { content: "hello" } },
				{ usage: { total_tokens: 42 } },
			],
		};
		assert.equal(findUsageTokens(event), 42);
	});

	it("returns null when no usage block is present", () => {
		assert.equal(findUsageTokens({ foo: "bar", baz: [1, 2, 3] }), null);
	});

	it("returns null for non-object input", () => {
		assert.equal(findUsageTokens("string"), null);
		assert.equal(findUsageTokens(42), null);
		assert.equal(findUsageTokens(null), null);
	});

	it("stops at the first hit (no double counting)", () => {
		const event = {
			usage: { total_tokens: 100 },
			nested: { usage: { total_tokens: 200 } },
		};
		assert.equal(findUsageTokens(event), 100);
	});
});

// ── estimateTokens ────────────────────────────────────────────────────

describe("estimateTokens", () => {
	it("prefers the usage block when present", () => {
		const event = { usage: { total_tokens: 1234 } };
		assert.equal(estimateTokens(event, 999_999), 1234);
	});

	it("falls back to chars/4 heuristic when usage is absent", () => {
		// 800 chars → 200 tokens
		assert.equal(estimateTokens({}, 800), 200);
	});

	it("rounds up fractional token estimates", () => {
		// 5 chars → ceil(5/4) = 2 tokens
		assert.equal(estimateTokens({}, 5), 2);
	});

	it("returns 0 when both response and request are empty", () => {
		assert.equal(estimateTokens({}, 0), 0);
	});
});

// ── resolveMetricsThresholds ──────────────────────────────────────────

describe("resolveMetricsThresholds", () => {
	it("reads thresholds from config.securityPolicy", () => {
		const cfg = configWithPolicy({
			toolCallsPerTurn: 100,
			confirmationsPerSession: 200,
			tokensPerTurnWarn: 1000,
			toolCallsPerMinuteWarn: 10,
			tokensSessionWarn: 5000,
		});
		const t = resolveMetricsThresholds(cfg);
		assert.equal(t.tokensPerTurnWarn, 1000);
		assert.equal(t.toolCallsPerMinuteWarn, 10);
		assert.equal(t.tokensSessionWarn, 5000);
	});

	it("falls back to DEFAULT_METRICS_THRESHOLDS when securityPolicy is absent", () => {
		const cfg = makeConfig(); // no securityPolicy
		const t = resolveMetricsThresholds(cfg);
		assert.equal(t.tokensPerTurnWarn, DEFAULT_METRICS_THRESHOLDS.tokensPerTurnWarn);
		assert.equal(t.toolCallsPerMinuteWarn, DEFAULT_METRICS_THRESHOLDS.toolCallsPerMinuteWarn);
		assert.equal(t.tokensSessionWarn, DEFAULT_METRICS_THRESHOLDS.tokensSessionWarn);
	});

	it("falls back per-field when a threshold is missing", () => {
		const cfg = configWithPolicy({
			toolCallsPerTurn: 100,
			confirmationsPerSession: 200,
			// only tokensPerTurnWarn supplied; the other two should default
			tokensPerTurnWarn: 4242,
		});
		const t = resolveMetricsThresholds(cfg);
		assert.equal(t.tokensPerTurnWarn, 4242);
		assert.equal(t.toolCallsPerMinuteWarn, DEFAULT_METRICS_THRESHOLDS.toolCallsPerMinuteWarn);
		assert.equal(t.tokensSessionWarn, DEFAULT_METRICS_THRESHOLDS.tokensSessionWarn);
	});

	it("treats a 0 (or negative) value as unset and falls back", () => {
		const cfg = configWithPolicy({
			toolCallsPerTurn: 100,
			confirmationsPerSession: 200,
			tokensPerTurnWarn: 0,
			toolCallsPerMinuteWarn: -1,
			tokensSessionWarn: 0,
		});
		const t = resolveMetricsThresholds(cfg);
		assert.equal(t.tokensPerTurnWarn, DEFAULT_METRICS_THRESHOLDS.tokensPerTurnWarn);
		assert.equal(t.toolCallsPerMinuteWarn, DEFAULT_METRICS_THRESHOLDS.toolCallsPerMinuteWarn);
		assert.equal(t.tokensSessionWarn, DEFAULT_METRICS_THRESHOLDS.tokensSessionWarn);
	});
});

// ── Registration: Scanner contract ────────────────────────────────────

describe("registerMetricsScanner — Scanner contract", () => {
	let tempDir: string;
	let auditFile: string;
	let prevAuditFile: string;
	let pi: ExtensionAPI;
	let handlers: Record<string, Array<(event: any, ctx: any) => unknown>>;

	beforeEach(() => {
		_resetAllForTest();
		tempDir = mkdtempSync(resolve(tmpdir(), "pi-metrics-reg-"));
		auditFile = resolve(tempDir, "audit.jsonl");
		prevAuditFile = _setAuditFileForTest(auditFile);
		initAuditLog();
		const mockPi = createMockPi();
		pi = mockPi.pi;
		handlers = mockPi.handlers;
	});

	afterEach(() => {
		_setAuditFileForTest(prevAuditFile);
		_resetAllForTest();
		if (tempDir && existsSync(tempDir)) rmSync(tempDir, { recursive: true, force: true });
	});

	it("does NOT block before_provider_request — returns undefined (AC#3)", () => {
		registerMetricsScanner(pi, () => makeConfig());
		const payload = { messages: [{ role: "user", content: "hello world" }] };
		const result = dispatchBeforeProviderRequest(handlers, payload);
		assert.equal(result, undefined, "before_provider_request must return undefined");
		// And it must NOT mutate the payload.
		assert.deepEqual(payload, { messages: [{ role: "user", content: "hello world" }] });
	});

	it("does NOT block after_provider_response — has no return value to act as a verdict (AC#3)", () => {
		registerMetricsScanner(pi, () => makeConfig());
		// Capture a request first so the fallback has something to chew on.
		dispatchBeforeProviderRequest(handlers, { messages: [{ role: "user", content: "hello" }] });
		// after_provider_response returns void; nothing for the runtime to
		// interpret as a block verdict. The fact that it does not throw is
		// the contract — there is no value to assert on, so we assert the
		// handler's return type is undefined.
		const ctx = { hasUI: false, ui: { notify: () => {} } };
		const ret = handlers["after_provider_response"][0](
			{ type: "after_provider_response", status: 200, headers: {} },
			ctx,
		);
		assert.equal(ret, undefined, "after_provider_response must not return a verdict");
	});

	it("emits a turn.metrics audit event on every after_provider_response", () => {
		registerMetricsScanner(pi, () => makeConfig());
		dispatchBeforeProviderRequest(handlers, { messages: [{ role: "user", content: "hello" }] });
		dispatchAfterProviderResponse(handlers);

		const entries = readAuditEntries(auditFile);
		const metricsEvents = entries.filter((e) => e.type === "turn.metrics");
		assert.equal(metricsEvents.length, 1, "exactly one turn.metrics event");
		const details = metricsEvents[0].details as Record<string, unknown>;
		assert.equal(typeof details.tokensTurn, "number", "tokensTurn must be numeric");
		assert.equal(typeof details.tokensSession, "number", "tokensSession must be numeric");
		// Severity is info — not a warning.
		assert.equal(metricsEvents[0].severity, "info");
	});

	it("uses provider usage when present in the response event", () => {
		registerMetricsScanner(pi, () => makeConfig());
		dispatchBeforeProviderRequest(handlers, { messages: [{ content: "irrelevant" }] });
		dispatchAfterProviderResponse(handlers, {
			type: "after_provider_response",
			status: 200,
			headers: {},
			usage: { total_tokens: 4321 },
		});
		const entries = readAuditEntries(auditFile);
		const m = entries.find((e) => e.type === "turn.metrics")!;
		assert.equal((m.details as any).tokensTurn, 4321);
	});

	it("falls back to chars/4 heuristic when usage is absent", () => {
		registerMetricsScanner(pi, () => makeConfig());
		// 40 chars of strings → 10 tokens.
		const payload = { messages: [{ role: "user", content: "0123456789" }] };
		// "user" + "0123456789" = 4 + 10 = 14 chars → ceil(14/4) = 4 tokens
		dispatchBeforeProviderRequest(handlers, payload);
		dispatchAfterProviderResponse(handlers);
		const entries = readAuditEntries(auditFile);
		const m = entries.find((e) => e.type === "turn.metrics")!;
		assert.equal((m.details as any).tokensTurn, 4);
	});

	it("accumulates tokensSession across turns", () => {
		registerMetricsScanner(pi, () => makeConfig());
		// Turn 1: 4 tokens
		dispatchBeforeProviderRequest(handlers, { messages: [{ role: "user", content: "0123456789" }] });
		dispatchAfterProviderResponse(handlers);
		// Turn 2: 4 tokens (no turn_start yet → _tokensThisTurn overwritten,
		// but _tokensSessionTotal accumulates)
		dispatchBeforeProviderRequest(handlers, { messages: [{ role: "user", content: "0123456789" }] });
		dispatchAfterProviderResponse(handlers);

		const entries = readAuditEntries(auditFile);
		const metrics = entries.filter((e) => e.type === "turn.metrics");
		assert.equal(metrics.length, 2);
		assert.equal((metrics[1].details as any).tokensSession, 8);
	});

	it("emits an anomaly audit event + notify when tokensPerTurnWarn is exceeded (AC#2)", () => {
		const cfg = configWithPolicy({
			toolCallsPerTurn: 100,
			confirmationsPerSession: 200,
			tokensPerTurnWarn: 100, // low threshold to trigger
			toolCallsPerMinuteWarn: 9999,
			tokensSessionWarn: 999_999,
		});
		registerMetricsScanner(pi, () => cfg);

		const notify = mock.fn();
		const ctx = { hasUI: true, ui: { notify } };

		// Inject usage to cross the threshold deterministically.
		dispatchBeforeProviderRequest(handlers, { messages: [{ content: "x" }] });
		dispatchAfterProviderResponse(
			handlers,
			{ type: "after_provider_response", status: 200, headers: {}, usage: { total_tokens: 500 } },
			ctx,
		);

		const entries = readAuditEntries(auditFile);
		const anomalies = entries.filter((e) => e.type === "anomaly");
		assert.equal(anomalies.length, 1, "exactly one anomaly event");
		const details = anomalies[0].details as Record<string, unknown>;
		assert.equal(details.kind, "tokens-per-turn");
		assert.equal(details.value, 500);
		assert.equal(details.threshold, 100);
		assert.equal(anomalies[0].severity, "warning");

		// User was notified once.
		assert.equal(notify.mock.calls.length, 1);
		const [message, severity] = notify.mock.calls[0].arguments as [string, string];
		assert.match(message, /token/i);
		assert.equal(severity, "warning");
	});

	it("emits an anomaly when toolCallsPerMinuteWarn is exceeded", async () => {
		const cfg = configWithPolicy({
			toolCallsPerTurn: 100,
			confirmationsPerSession: 200,
			tokensPerTurnWarn: 999_999,
			toolCallsPerMinuteWarn: 2, // low threshold
			tokensSessionWarn: 999_999,
		});
		registerMetricsScanner(pi, () => cfg);

		// Three rapid turns → window count crosses the threshold of 2.
		for (let i = 0; i < 3; i++) {
			dispatchBeforeProviderRequest(handlers, { messages: [{ content: "x" }] });
			dispatchAfterProviderResponse(handlers);
		}

		const entries = readAuditEntries(auditFile);
		const anomalies = entries.filter((e) => e.type === "anomaly");
		const toolCallAnomalies = anomalies.filter(
			(a) => (a.details as Record<string, unknown>).kind === "tool-calls-per-minute",
		);
		assert.ok(toolCallAnomalies.length >= 1, "at least one tool-calls-per-minute anomaly");
		const details = toolCallAnomalies[0].details as Record<string, unknown>;
		assert.equal(details.threshold, 2);
		assert.ok((details.value as number) > 2);
	});

	it("emits an anomaly when tokensSessionWarn is exceeded", () => {
		const cfg = configWithPolicy({
			toolCallsPerTurn: 100,
			confirmationsPerSession: 200,
			tokensPerTurnWarn: 999_999,
			toolCallsPerMinuteWarn: 999_999,
			tokensSessionWarn: 1000,
		});
		registerMetricsScanner(pi, () => cfg);

		// Single turn crossing session threshold.
		dispatchBeforeProviderRequest(handlers, { messages: [{ content: "x" }] });
		dispatchAfterProviderResponse(
			handlers,
			{ type: "after_provider_response", status: 200, headers: {}, usage: { total_tokens: 1500 } },
		);

		const entries = readAuditEntries(auditFile);
		const anomalies = entries.filter((e) => e.type === "anomaly");
		const sessionAnomalies = anomalies.filter(
			(a) => (a.details as Record<string, unknown>).kind === "session-tokens",
		);
		assert.equal(sessionAnomalies.length, 1);
		const details = sessionAnomalies[0].details as Record<string, unknown>;
		assert.equal(details.value, 1500);
		assert.equal(details.threshold, 1000);
	});

	it("does not emit anomalies when thresholds are respected", () => {
		const cfg = configWithPolicy({
			toolCallsPerTurn: 100,
			confirmationsPerSession: 200,
			tokensPerTurnWarn: 10_000,
			toolCallsPerMinuteWarn: 100,
			tokensSessionWarn: 100_000,
		});
		registerMetricsScanner(pi, () => cfg);

		dispatchBeforeProviderRequest(handlers, { messages: [{ content: "small" }] });
		dispatchAfterProviderResponse(handlers);

		const entries = readAuditEntries(auditFile);
		assert.equal(entries.filter((e) => e.type === "anomaly").length, 0);
	});

	it("resets per-turn counters on turn_start", () => {
		registerMetricsScanner(pi, () => makeConfig());

		// Turn 1
		dispatchBeforeProviderRequest(handlers, { messages: [{ content: "0123456789" }] });
		dispatchAfterProviderResponse(handlers);
		// turn_start resets _tokensThisTurn and _pendingRequestChars
		handlers["turn_start"][0]({ type: "turn_start", turnIndex: 1, timestamp: Date.now() }, { hasUI: false, ui: { notify: () => {} } });

		const snap = _snapshotForTest();
		assert.equal(snap.tokensThisTurn, 0, "tokensThisTurn must be reset");
		assert.equal(snap.pendingRequestChars, 0, "pendingRequestChars must be reset");
		// Session total is NOT reset by turn_start.
		assert.ok(snap.tokensSessionTotal > 0, "tokensSessionTotal must persist across turns");
	});

	it("resets all session counters on session_start", () => {
		registerMetricsScanner(pi, () => makeConfig());

		// Generate some state.
		dispatchBeforeProviderRequest(handlers, { messages: [{ content: "0123456789" }] });
		dispatchAfterProviderResponse(handlers);

		handlers["session_start"][0](
			{ type: "session_start", reason: "new" },
			{ hasUI: false, ui: { notify: () => {} } },
		);

		const snap = _snapshotForTest();
		assert.equal(snap.tokensThisTurn, 0);
		assert.equal(snap.tokensSessionTotal, 0);
		assert.equal(snap.toolCallsInWindow, 0);
		assert.equal(snap.pendingRequestChars, 0);
	});

	it("does NOT log secrets in turn.metrics — only token counts (AC#4)", () => {
		registerMetricsScanner(pi, () => makeConfig());
		// Payload contains realistic secrets; the secret scanner would have
		// redacted them in production. The metrics scanner receives the
		// (potentially redacted) payload and must NEVER log the strings —
		// only the resulting token count.
		const payload = {
			messages: [
				{
					role: "user",
					content:
						"my aws key is AKIAIOSFODNN7EXAMPLE and my github token is ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789a",
				},
			],
		};
		dispatchBeforeProviderRequest(handlers, payload);
		dispatchAfterProviderResponse(handlers);

		const rawLog = readFileSync(auditFile, "utf-8");
		const entries = readAuditEntries(auditFile);
		const metricsEvent = entries.find((e) => e.type === "turn.metrics");
		assert.ok(metricsEvent, "turn.metrics event must be emitted");

		// The details object must contain ONLY numeric token counts and the
		// audit record must not contain any of the original secret strings.
		const details = metricsEvent!.details as Record<string, unknown>;
		const keys = Object.keys(details).sort();
		assert.deepEqual(keys, ["tokensSession", "tokensTurn"]);
		assert.equal(typeof details.tokensTurn, "number");
		assert.equal(typeof details.tokensSession, "number");

		assert.ok(!rawLog.includes("AKIAIOSFODNN7EXAMPLE"), "aws key must not be logged");
		assert.ok(!rawLog.includes("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789a"), "github token must not be logged");
	});

	it("does NOT log secrets in anomaly events either (AC#4)", () => {
		const cfg = configWithPolicy({
			toolCallsPerTurn: 100,
			confirmationsPerSession: 200,
			tokensPerTurnWarn: 1,
			toolCallsPerMinuteWarn: 999_999,
			tokensSessionWarn: 999_999,
		});
		registerMetricsScanner(pi, () => cfg);
		const payload = {
			messages: [{ role: "user", content: "secret=sk-ant-api03-abcdefghijklmnopqrstuvwxyz" }],
		};
		dispatchBeforeProviderRequest(handlers, payload);
		dispatchAfterProviderResponse(handlers);

		const rawLog = readFileSync(auditFile, "utf-8");
		const entries = readAuditEntries(auditFile);
		const anomalies = entries.filter((e) => e.type === "anomaly");
		assert.ok(anomalies.length >= 1);

		// Anomaly details must contain only kind/value/threshold.
		const details = anomalies[0].details as Record<string, unknown>;
		const keys = Object.keys(details).sort();
		assert.deepEqual(keys, ["kind", "threshold", "value"]);

		assert.ok(!rawLog.includes("sk-ant-api03-abcdefghijklmnopqrstuvwxyz"), "anthropic key must not be logged");
	});
});

// ── Dashboard: aggregateSessionMetrics (AC#1) ─────────────────────────

describe("aggregateSessionMetrics (dashboard AC#1)", () => {
	let tempDir: string;
	let auditFile: string;
	let prevAuditFile: string;

	beforeEach(() => {
		_resetAllForTest();
		tempDir = mkdtempSync(resolve(tmpdir(), "pi-metrics-dash-"));
		auditFile = resolve(tempDir, "audit.jsonl");
		prevAuditFile = _setAuditFileForTest(auditFile);
		initAuditLog();
	});

	afterEach(() => {
		_setAuditFileForTest(prevAuditFile);
		_resetAllForTest();
		if (tempDir && existsSync(tempDir)) rmSync(tempDir, { recursive: true, force: true });
	});

	it("returns zeroed metrics when the audit log is missing", () => {
		const m = aggregateSessionMetrics();
		assert.equal(m.tokensSession, 0);
		assert.equal(m.turnCount, 0);
		assert.equal(m.toolCallsPerMinute, 0);
	});

	it("sums tokensTurn across turn.metrics events for the current session", () => {
		// Hand-write audit entries directly so the test does not depend
		// on the scanner's own write path (independent verification).
		const entries: AuditEntry[] = [
			{ timestamp: new Date().toISOString(), sessionId: getSessionId(), type: "turn.metrics", severity: "info", details: { tokensTurn: 100, tokensSession: 100 } },
			{ timestamp: new Date().toISOString(), sessionId: getSessionId(), type: "turn.metrics", severity: "info", details: { tokensTurn: 250, tokensSession: 350 } },
			{ timestamp: new Date().toISOString(), sessionId: getSessionId(), type: "turn.metrics", severity: "info", details: { tokensTurn: 50, tokensSession: 400 } },
		];
		writeFileSync(auditFile, entries.map((e) => JSON.stringify(e)).join("\n") + "\n", "utf-8");

		const m = aggregateSessionMetrics();
		assert.equal(m.turnCount, 3);
		assert.equal(m.tokensSession, 400); // 100 + 250 + 50
	});

	it("counts only turn.metrics events within the last 60s as tool_calls/min", () => {
		const now = Date.now();
		const oldIso = new Date(now - 5 * 60_000).toISOString(); // 5 minutes ago
		const recentIso = new Date(now - 10_000).toISOString(); // 10s ago
		const entries: AuditEntry[] = [
			{ timestamp: oldIso, sessionId: getSessionId(), type: "turn.metrics", severity: "info", details: { tokensTurn: 1, tokensSession: 1 } },
			{ timestamp: recentIso, sessionId: getSessionId(), type: "turn.metrics", severity: "info", details: { tokensTurn: 1, tokensSession: 2 } },
			{ timestamp: recentIso, sessionId: getSessionId(), type: "turn.metrics", severity: "info", details: { tokensTurn: 1, tokensSession: 3 } },
		];
		writeFileSync(auditFile, entries.map((e) => JSON.stringify(e)).join("\n") + "\n", "utf-8");

		const m = aggregateSessionMetrics();
		assert.equal(m.turnCount, 3);
		assert.equal(m.toolCallsPerMinute, 2); // the two recent entries
	});

	it("ignores entries from a different session", () => {
		const entries: AuditEntry[] = [
			{ timestamp: new Date().toISOString(), sessionId: "other-session", type: "turn.metrics", severity: "info", details: { tokensTurn: 9999, tokensSession: 9999 } },
			{ timestamp: new Date().toISOString(), sessionId: getSessionId(), type: "turn.metrics", severity: "info", details: { tokensTurn: 42, tokensSession: 42 } },
		];
		writeFileSync(auditFile, entries.map((e) => JSON.stringify(e)).join("\n") + "\n", "utf-8");

		const m = aggregateSessionMetrics();
		assert.equal(m.turnCount, 1);
		assert.equal(m.tokensSession, 42);
	});

	it("ignores non-turn.metrics events", () => {
		const entries: AuditEntry[] = [
			{ timestamp: new Date().toISOString(), sessionId: getSessionId(), type: "anomaly", severity: "warning", details: { kind: "tokens-per-turn", value: 1, threshold: 1 } },
			{ timestamp: new Date().toISOString(), sessionId: getSessionId(), type: "secret.redacted", severity: "warning", details: { patternName: "aws-access-key", originalLength: 20 } },
			{ timestamp: new Date().toISOString(), sessionId: getSessionId(), type: "turn.metrics", severity: "info", details: { tokensTurn: 100, tokensSession: 100 } },
		];
		writeFileSync(auditFile, entries.map((e) => JSON.stringify(e)).join("\n") + "\n", "utf-8");

		const m = aggregateSessionMetrics();
		assert.equal(m.turnCount, 1);
		assert.equal(m.tokensSession, 100);
	});
});

// ── Dashboard command renders metrics (AC#1 end-to-end) ───────────────

describe("/security dashboard renders metrics section (AC#1)", () => {
	let tempDir: string;
	let auditFile: string;
	let prevAuditFile: string;

	beforeEach(() => {
		_resetAllForTest();
		tempDir = mkdtempSync(resolve(tmpdir(), "pi-metrics-cmd-"));
		auditFile = resolve(tempDir, "audit.jsonl");
		prevAuditFile = _setAuditFileForTest(auditFile);
		initAuditLog();
	});

	afterEach(() => {
		_setAuditFileForTest(prevAuditFile);
		_resetAllForTest();
		if (tempDir && existsSync(tempDir)) rmSync(tempDir, { recursive: true, force: true });
	});

	it("the /security command output includes tokens/session and tool_calls/min", async () => {
		// Seed the audit log with a few turn.metrics events for this session.
		const entries: AuditEntry[] = [
			{ timestamp: new Date().toISOString(), sessionId: getSessionId(), type: "turn.metrics", severity: "info", details: { tokensTurn: 1234, tokensSession: 1234 } },
			{ timestamp: new Date().toISOString(), sessionId: getSessionId(), type: "turn.metrics", severity: "info", details: { tokensTurn: 2766, tokensSession: 4000 } },
		];
		writeFileSync(auditFile, entries.map((e) => JSON.stringify(e)).join("\n") + "\n", "utf-8");

		// Build a mock pi that captures the registered command handler.
		// The handler is captured in an object property so TypeScript keeps
		// it at its declared type at the read point; a `let` captured only
		// inside the closure would stay narrowed to `null`, making the
		// non-null assertion collapse to `never` under strict mode (R6).
		type DashboardCtx = {
			hasUI: boolean;
			ui: { notify: (message: string, severity?: "info" | "warning" | "error") => void };
		};
		type DashboardHandler = (args: string | undefined, ctx: DashboardCtx) => Promise<void>;
		const captured: { handler?: DashboardHandler } = {};
		const pi = {
			on() {},
			registerCommand(name: string, def: { handler: DashboardHandler }) {
				if (name === "security") captured.handler = def.handler;
			},
		};

		const { registerAuditCommand } = await import("../lib/audit.js");
		registerAuditCommand(pi as unknown as ExtensionAPI, makeConfig());

		assert.ok(captured.handler, "/security command must be registered");
		const notify = mock.fn();
		await captured.handler!(undefined, { hasUI: true, ui: { notify } });

		assert.equal(notify.mock.calls.length, 1, "dashboard must notify once");
		const [message] = notify.mock.calls[0].arguments as [string, string];
		assert.match(message, /Metrics \(this session\)/, "dashboard must have a metrics section");
		// toLocaleString() may render the thousands separator differently
		// across locales ("," / non-breaking space / "."), so match the
		// digit groups loosely rather than asserting a literal "4,000".
		assert.match(message, /Tokens:\s*4[\s.,]?000\s*\(2 turns\)/, "dashboard must show summed tokens/session (1234 + 2766 = 4000) and turn count");
		assert.match(message, /Tool calls\/min/, "dashboard must show tool_calls/min estimate");
	});
});
