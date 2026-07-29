/**
 * Unit + integration tests for lib/rate-limiter.ts and its wiring into
 * the guard pipeline (P2-3: rate-limiting of tool calls / confirmations).
 *
 * Coverage:
 *   - Pure module: checkLimit across both scopes, resetTurn,
 *     resetSession.
 *   - Integration via the guard pipeline mock pi:
 *       * exceeding toolCallsPerTurn blocks + audits ratelimit.block
 *       * turn_start resets the per-turn counter
 *       * exceeding confirmationsPerSession converts a confirm into a block
 *       * generous defaults do not block normal usage
 *   - Config layering: security-policy.json is machine-only (AC#4).
 */
import { describe, it, beforeEach, afterEach, mock } from "node:test";
import assert from "node:assert/strict";
import {
	existsSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { resolve } from "node:path";
import { tmpdir } from "node:os";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import type { Config } from "../lib/config.js";
import type { GuardEvaluators } from "../lib/guard-pipeline.js";
import { registerGuardPipeline } from "../lib/guard-pipeline.js";
import { initAuditLog, _setAuditFileForTest } from "../lib/audit.js";
import {
	checkLimit,
	resetTurn,
	resetSession,
	_resetAllForTest,
	_snapshotForTest,
} from "../lib/rate-limiter.js";
import {
	loadConfig,
	loadSecurityPolicy,
	DEFAULT_SECURITY_POLICY,
} from "../lib/config.js";

// ── Fixtures ──────────────────────────────────────────────────────────

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

/**
 * Minimal pi stub capturing both `tool_call` and `turn_start` handlers so
 * integration tests can drive the pipeline and simulate turn boundaries.
 */
function makeMockPi() {
	const handlers = new Map<string, (...args: unknown[]) => unknown>();
	const pi = {
		on(event: string, handler: (...args: unknown[]) => unknown) {
			handlers.set(event, handler);
		},
	};
	return {
		pi: pi as unknown as ExtensionAPI,
		invokeToolCall(event: { toolName: string; input: unknown }, ctx: unknown) {
			const h = handlers.get("tool_call");
			if (!h) throw new Error("tool_call handler not registered");
			return h(event, ctx);
		},
		fireTurnStart() {
			const h = handlers.get("turn_start");
			if (h) (h as () => void)();
		},
	};
}

/** ctx with a UI: confirm() approves, notify() is recorded. */
function makeCtxWithUI(confirmReturn = true) {
	const notifyCalls: string[] = [];
	let confirmCalls = 0;
	return {
		ctx: {
			hasUI: true,
			ui: {
				notify: (msg: string) => { notifyCalls.push(msg); },
				confirm: async () => { confirmCalls++; return confirmReturn; },
			},
		},
		notifyCalls,
		getConfirmCalls: () => confirmCalls,
	};
}

function makeCtxNoUI() {
	return { hasUI: false, ui: { notify() {}, confirm: async () => false } };
}

/** Guard evaluators that always allow (used for tool_calls cap testing). */
function makeAllowGuards(): GuardEvaluators {
	return {
		evaluateBoundary: () => ({ action: "allow" as const }),
		evaluateProtectedPaths: () => ({ action: "allow" as const }),
		classifyCommand: () => ({ action: "allow" as const, category: "safe" as const }),
	};
}

/** Guard evaluators where boundary always returns confirm (for confirmation cap). */
function makeBoundaryConfirmGuards(): GuardEvaluators {
	return {
		evaluateBoundary: () => ({
			action: "confirm" as const,
			message: "Read outside boundary?",
		}),
		evaluateProtectedPaths: () => ({ action: "allow" as const }),
		classifyCommand: () => ({ action: "allow" as const, category: "safe" as const }),
	};
}

// ── Pure unit tests ───────────────────────────────────────────────────

describe("rate-limiter: checkLimit (tool_calls)", () => {
	beforeEach(() => _resetAllForTest());

	it("allows the first `limit` calls and blocks call limit+1", () => {
		const limits = {
			toolCallsPerTurn: 3,
			confirmationsPerSession: 100,
		};
		assert.deepEqual(checkLimit("tool_calls", limits), { allowed: true, count: 1, limit: 3 });
		assert.deepEqual(checkLimit("tool_calls", limits), { allowed: true, count: 2, limit: 3 });
		assert.deepEqual(checkLimit("tool_calls", limits), { allowed: true, count: 3, limit: 3 });
		const over = checkLimit("tool_calls", limits);
		assert.equal(over.allowed, false);
		assert.equal(over.count, 4);
		assert.equal(over.limit, 3);
		assert.match(over.reason ?? "", /tool_calls rate limit exceeded/);
	});

	it("every call past the limit is blocked (no recovery without reset)", () => {
		const limits = {
			toolCallsPerTurn: 1,
			confirmationsPerSession: 100,
		};
		checkLimit("tool_calls", limits); // 1, allowed
		for (let i = 0; i < 5; i++) {
			const r = checkLimit("tool_calls", limits);
			assert.equal(r.allowed, false, `call ${i + 2} must be blocked`);
		}
	});

	it("resetTurn zeroes the per-turn counter so calls are allowed again", () => {
		const limits = {
			toolCallsPerTurn: 2,
			confirmationsPerSession: 100,
		};
		checkLimit("tool_calls", limits);
		checkLimit("tool_calls", limits);
		assert.equal(checkLimit("tool_calls", limits).allowed, false);
		resetTurn();
		assert.equal(checkLimit("tool_calls", limits).allowed, true);
		assert.equal(_snapshotForTest().toolCalls, 1);
	});
});

describe("rate-limiter: checkLimit (confirmations)", () => {
	beforeEach(() => _resetAllForTest());

	it("caps cumulative confirmations per session", () => {
		const limits = {
			toolCallsPerTurn: 100,
			confirmationsPerSession: 2,
		};
		assert.equal(checkLimit("confirmations", limits).allowed, true);
		assert.equal(checkLimit("confirmations", limits).allowed, true);
		assert.equal(checkLimit("confirmations", limits).allowed, false);
		assert.match(checkLimit("confirmations", limits).reason ?? "", /confirmations rate limit exceeded/);
	});

	it("resetSession zeroes the confirmation counter", () => {
		const limits = {
			toolCallsPerTurn: 100,
			confirmationsPerSession: 1,
		};
		checkLimit("confirmations", limits);
		assert.equal(checkLimit("confirmations", limits).allowed, false);
		resetSession();
		assert.equal(checkLimit("confirmations", limits).allowed, true);
	});

	it("resetTurn does NOT reset the confirmation counter (independent lifecycles)", () => {
		const limits = {
			toolCallsPerTurn: 100,
			confirmationsPerSession: 1,
		};
		checkLimit("confirmations", limits);
		assert.equal(checkLimit("confirmations", limits).allowed, false);
		resetTurn();
		assert.equal(checkLimit("confirmations", limits).allowed, false, "confirmations are session-scoped");
	});
});

// ── Integration: tool_calls cap via guard pipeline ─────────────────────

describe("guard-pipeline: tool_calls rate limit (AC#1)", () => {
	let tempDir: string;
	let previousAuditFile: string;

	beforeEach(() => {
		_resetAllForTest();
		tempDir = resolve(tmpdir(), `pi-rl-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(tempDir, { recursive: true });
		previousAuditFile = _setAuditFileForTest(resolve(tempDir, "audit.jsonl"));
		initAuditLog();
	});

	afterEach(() => {
		_setAuditFileForTest(previousAuditFile);
		_resetAllForTest();
		if (tempDir && existsSync(tempDir)) rmSync(tempDir, { recursive: true, force: true });
	});

	function readAuditEntries(): Array<{ type: string; severity: string; details: Record<string, unknown> }> {
		const file = resolve(tempDir, "audit.jsonl");
		if (!existsSync(file)) return [];
		return readFileSync(file, "utf-8")
			.trim()
			.split("\n")
			.filter(Boolean)
			.map((line) => JSON.parse(line));
	}

	it("exceeding toolCallsPerTurn blocks the next call and audits ratelimit.block", async () => {
		const { pi, invokeToolCall } = makeMockPi();
		registerGuardPipeline(
			pi,
			() => makeConfig({
				securityPolicy: {
					toolCallsPerTurn: 2,
					confirmationsPerSession: 100,
				},
			}),
			makeAllowGuards(),
		);

		// First two calls pass through (counter 1, 2).
		const r1 = await invokeToolCall({ toolName: "read", input: { path: "a.txt" } }, makeCtxNoUI());
		const r2 = await invokeToolCall({ toolName: "read", input: { path: "b.txt" } }, makeCtxNoUI());
		assert.equal(r1, undefined);
		assert.equal(r2, undefined);

		// Third call is blocked (counter 3 > 2).
		const r3 = await invokeToolCall({ toolName: "read", input: { path: "c.txt" } }, makeCtxNoUI());
		assert.deepEqual(r3, { block: true, reason: (r3 as { reason: string }).reason });
		assert.match((r3 as { reason: string }).reason, /tool_calls rate limit exceeded/);

		const blocks = readAuditEntries().filter((e) => e.type === "ratelimit.block");
		assert.equal(blocks.length, 1, "exactly one ratelimit.block audit event");
		assert.equal(blocks[0].severity, "warning");
		assert.equal(blocks[0].details.scope, "tool_calls");
		assert.equal(blocks[0].details.count, 3);
		assert.equal(blocks[0].details.limit, 2);
		assert.equal(blocks[0].details.tool, "read");
	});

	it("fail-closed: subsequent calls in the same turn stay blocked", async () => {
		const { pi, invokeToolCall } = makeMockPi();
		registerGuardPipeline(
			pi,
			() => makeConfig({
				securityPolicy: {
					toolCallsPerTurn: 1,
					confirmationsPerSession: 100,
				},
			}),
			makeAllowGuards(),
		);

		await invokeToolCall({ toolName: "read", input: { path: "a.txt" } }, makeCtxNoUI());
		const r2 = await invokeToolCall({ toolName: "read", input: { path: "b.txt" } }, makeCtxNoUI());
		const r3 = await invokeToolCall({ toolName: "read", input: { path: "c.txt" } }, makeCtxNoUI());
		assert.ok((r2 as { block?: boolean }).block, "2nd call blocked");
		assert.ok((r3 as { block?: boolean }).block, "3rd call still blocked");
		// Two ratelimit.block events (one per blocked call).
		assert.equal(
			readAuditEntries().filter((e) => e.type === "ratelimit.block").length,
			2,
		);
	});
});

// ── Integration: turn_start resets the tool_calls counter (AC#2) ────────

describe("guard-pipeline: turn_start resets the tool_calls counter (AC#2)", () => {
	let tempDir: string;
	let previousAuditFile: string;

	beforeEach(() => {
		_resetAllForTest();
		tempDir = resolve(tmpdir(), `pi-rl-turn-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(tempDir, { recursive: true });
		previousAuditFile = _setAuditFileForTest(resolve(tempDir, "audit.jsonl"));
		initAuditLog();
	});

	afterEach(() => {
		_setAuditFileForTest(previousAuditFile);
		_resetAllForTest();
		if (tempDir && existsSync(tempDir)) rmSync(tempDir, { recursive: true, force: true });
	});

	it("a blocked tool_calls limit is lifted after turn_start fires", async () => {
		const { pi, invokeToolCall, fireTurnStart } = makeMockPi();
		registerGuardPipeline(
			pi,
			() => makeConfig({
				securityPolicy: {
					toolCallsPerTurn: 2,
					confirmationsPerSession: 100,
				},
			}),
			makeAllowGuards(),
		);

		// Exhaust the per-turn limit.
		await invokeToolCall({ toolName: "read", input: { path: "a.txt" } }, makeCtxNoUI());
		await invokeToolCall({ toolName: "read", input: { path: "b.txt" } }, makeCtxNoUI());
		const blocked = await invokeToolCall({ toolName: "read", input: { path: "c.txt" } }, makeCtxNoUI());
		assert.ok((blocked as { block?: boolean }).block, "3rd call in turn 1 is blocked");

		// New turn resets the counter.
		fireTurnStart();

		const afterReset = await invokeToolCall({ toolName: "read", input: { path: "d.txt" } }, makeCtxNoUI());
		assert.equal(afterReset, undefined, "first call of the new turn must pass");

		// And the limit applies again within the new turn.
		await invokeToolCall({ toolName: "read", input: { path: "e.txt" } }, makeCtxNoUI());
		const blockedAgain = await invokeToolCall({ toolName: "read", input: { path: "f.txt" } }, makeCtxNoUI());
		assert.ok((blockedAgain as { block?: boolean }).block, "limit re-applies in the new turn");
	});
});

// ── Integration: confirmations cap converts confirm → block (AC#3) ──────

describe("guard-pipeline: confirmations cap converts a confirm into a block (AC#3)", () => {
	let tempDir: string;
	let previousAuditFile: string;

	beforeEach(() => {
		_resetAllForTest();
		tempDir = resolve(tmpdir(), `pi-rl-conf-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(tempDir, { recursive: true });
		previousAuditFile = _setAuditFileForTest(resolve(tempDir, "audit.jsonl"));
		initAuditLog();
	});

	afterEach(() => {
		_setAuditFileForTest(previousAuditFile);
		_resetAllForTest();
		if (tempDir && existsSync(tempDir)) rmSync(tempDir, { recursive: true, force: true });
	});

	function readAuditEntries(): Array<{ type: string; severity: string; details: Record<string, unknown> }> {
		const file = resolve(tempDir, "audit.jsonl");
		if (!existsSync(file)) return [];
		return readFileSync(file, "utf-8")
			.trim()
			.split("\n")
			.filter(Boolean)
			.map((line) => JSON.parse(line));
	}

	it("once the cap is hit, a would-be-confirm is blocked with no further dialogs", async () => {
		const { pi, invokeToolCall } = makeMockPi();
		registerGuardPipeline(
			pi,
			() => makeConfig({
				securityPolicy: {
					toolCallsPerTurn: 100,
					confirmationsPerSession: 1,
				},
			}),
			makeBoundaryConfirmGuards(),
		);

		const { ctx, getConfirmCalls } = makeCtxWithUI(true);

		// 1st confirm verdict: under cap → dialog shown & approved.
		const r1 = await invokeToolCall({ toolName: "read", input: { path: "/etc/hosts" } }, ctx);
		assert.equal(r1, undefined, "first confirm is approved and passes");
		assert.equal(getConfirmCalls(), 1, "exactly one confirm dialog shown so far");

		// 2nd confirm verdict: cap exceeded → blocked instead of prompting.
		const r2 = await invokeToolCall({ toolName: "read", input: { path: "/etc/passwd" } }, ctx);
		assert.ok((r2 as { block?: boolean }).block, "would-be-confirm must become a block");
		assert.match((r2 as { reason: string }).reason, /confirmations rate limit exceeded/);
		assert.equal(getConfirmCalls(), 1, "no additional confirm dialog after the cap");

		const confBlocks = readAuditEntries().filter(
			(e) => e.type === "ratelimit.block" && e.details.scope === "confirmations",
		);
		assert.equal(confBlocks.length, 1);
		assert.equal(confBlocks[0].details.count, 2);
		assert.equal(confBlocks[0].details.limit, 1);
	});
});

// ── Integration: generous defaults do not block normal usage (AC#5) ─────

describe("guard-pipeline: generous defaults do not block normal usage (AC#5)", () => {
	let tempDir: string;
	let previousAuditFile: string;

	beforeEach(() => {
		_resetAllForTest();
		tempDir = resolve(tmpdir(), `pi-rl-def-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(tempDir, { recursive: true });
		previousAuditFile = _setAuditFileForTest(resolve(tempDir, "audit.jsonl"));
		initAuditLog();
	});

	afterEach(() => {
		_setAuditFileForTest(previousAuditFile);
		_resetAllForTest();
		if (tempDir && existsSync(tempDir)) rmSync(tempDir, { recursive: true, force: true });
	});

	function readAuditEntries(): Array<{ type: string; details: Record<string, unknown> }> {
		const file = resolve(tempDir, "audit.jsonl");
		if (!existsSync(file)) return [];
		return readFileSync(file, "utf-8")
			.trim()
			.split("\n")
			.filter(Boolean)
			.map((line) => JSON.parse(line));
	}

	it("a single tool call under DEFAULT_SECURITY_POLICY is allowed and not audited as ratelimit.block", async () => {
		const { pi, invokeToolCall } = makeMockPi();
		// No securityPolicy override → defaults (100/200/500) apply.
		registerGuardPipeline(pi, () => makeConfig(), makeAllowGuards());

		const result = await invokeToolCall(
			{ toolName: "read", input: { path: "src/foo.txt" } },
			makeCtxNoUI(),
		);
		assert.equal(result, undefined, "a single tool call must pass under defaults");
		assert.equal(
			readAuditEntries().filter((e) => e.type === "ratelimit.block").length,
			0,
			"no ratelimit.block event for normal usage",
		);
	});

	it("DEFAULT_SECURITY_POLICY exposes the documented generous thresholds", () => {
		assert.equal(DEFAULT_SECURITY_POLICY.toolCallsPerTurn, 100);
		assert.equal(DEFAULT_SECURITY_POLICY.confirmationsPerSession, 200);
	});
});

// ── Config layering: security-policy.json is machine-only (AC#4) ────────

describe("security-policy.json — machine-only (AC#4)", () => {
	let consoleErrorMock: ReturnType<typeof mock.method>;
	let projectDir: string;

	beforeEach(() => {
		consoleErrorMock = mock.method(console, "error", () => {});
		projectDir = mkdtempSync(resolve(tmpdir(), "pi-policy-proj-"));
	});

	afterEach(() => {
		consoleErrorMock.mock.restore();
		if (projectDir && existsSync(projectDir)) rmSync(projectDir, { recursive: true, force: true });
	});

	it("ignores a project-layer security-policy.json that tries to raise limits, and warns", () => {
		const secDir = resolve(projectDir, ".pi/security");
		mkdirSync(secDir, { recursive: true });
		// A project-layer file that would disable rate limiting (huge limits).
		writeFileSync(
			resolve(secDir, "security-policy.json"),
			JSON.stringify({
				toolCallsPerTurn: 999999,
				confirmationsPerSession: 999999,
			}),
			"utf-8",
		);

		const policy = loadSecurityPolicy(projectDir);

		// A warning was emitted mentioning the ignored file.
		const warnings = consoleErrorMock.mock.calls
			.map((c) => String(c.arguments[0]))
			.filter((s) => s.includes("security-policy.json") && s.includes("IGNORED"));
		assert.ok(warnings.length >= 1, "a warning must be emitted for the project-layer file");

		// The raised project-layer limits must NOT be applied.
		assert.notEqual(policy.toolCallsPerTurn, 999999, "raised tool-call limit must be ignored");
		assert.notEqual(policy.confirmationsPerSession, 999999, "raised confirmation limit must be ignored");
		// Shipped defaults are still in effect.
		assert.equal(policy.toolCallsPerTurn, DEFAULT_SECURITY_POLICY.toolCallsPerTurn);
		assert.equal(policy.confirmationsPerSession, DEFAULT_SECURITY_POLICY.confirmationsPerSession);
	});

	it("loadConfig also ignores the project-layer policy and applies defaults", () => {
		const secDir = resolve(projectDir, ".pi/security");
		mkdirSync(secDir, { recursive: true });
		writeFileSync(
			resolve(secDir, "security-policy.json"),
			JSON.stringify({
				toolCallsPerTurn: 7,
				confirmationsPerSession: 7,
			}),
			"utf-8",
		);

		const config = loadConfig(projectDir);
		assert.ok(config.securityPolicy, "loadConfig must populate securityPolicy");
		assert.notEqual(config.securityPolicy!.toolCallsPerTurn, 7);
		assert.notEqual(config.securityPolicy!.confirmationsPerSession, 7);

		const warned = consoleErrorMock.mock.calls
			.map((c) => String(c.arguments[0]))
			.some((s) => s.includes("security-policy.json") && s.includes("IGNORED"));
		assert.ok(warned, "loadConfig must warn when ignoring the project-layer policy");
	});

	it("with no project-layer file, no warning is emitted and defaults apply", () => {
		const policy = loadSecurityPolicy(projectDir);
		const warned = consoleErrorMock.mock.calls
			.map((c) => String(c.arguments[0]))
			.some((s) => s.includes("security-policy.json"));
		assert.equal(warned, false, "no warning when no project-layer file is present");
		assert.equal(policy.toolCallsPerTurn, DEFAULT_SECURITY_POLICY.toolCallsPerTurn);
	});
});
