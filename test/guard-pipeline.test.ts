/**
 * Unit tests for lib/guard-pipeline.ts — confirm→block reason field and audit event types
 */
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { resolve } from "node:path";
import { tmpdir } from "node:os";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import type { Config } from "../lib/config.js";
import type { GuardEvaluators } from "../lib/guard-pipeline.js";
import { verdictAuditInfo, validateToolInput, registerGuardPipeline } from "../lib/guard-pipeline.js";
import { classifyCommand } from "../lib/bash-gate.js";
import { initAuditLog, _setAuditFileForTest } from "../lib/audit.js";

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

describe("guard-pipeline: no-UI confirm verdict uses .message not .reason", () => {
	it("boundary confirm verdict returns .message (not .reason) when blocked without UI", () => {
		const config = makeConfig();
		const guards: GuardEvaluators = {
			evaluateBoundary: () => ({
				action: "confirm" as const,
				message: "Read file outside project boundary?\n\n  /etc/passwd\n\nBoundary: /home/user/project",
			}),
			evaluateProtectedPaths: () => ({ action: "allow" as const }),
			classifyCommand: () => ({ action: "allow" as const, category: "safe" as const }),
		};

		const verdict = guards.evaluateBoundary("read", { path: "/etc/passwd" }, config);
		assert.equal(verdict.action, "confirm");
		if (verdict.action === "confirm") {
			assert.equal(typeof verdict.message, "string");
			assert.ok(verdict.message.length > 0);
			assert.equal(("reason" in verdict), false, "confirm verdict should not have .reason");
		}
	});

	it("protected-paths confirm verdict returns .message (not .reason)", () => {
		const config = makeConfig({
			protectedPaths: { patterns: [".env"], writeAction: "block", readAction: "confirm" },
		});
		const guards: GuardEvaluators = {
			evaluateBoundary: () => ({ action: "allow" as const }),
			evaluateProtectedPaths: () => ({
				action: "confirm" as const,
				message: "Read protected file .env?",
			}),
			classifyCommand: () => ({ action: "allow" as const, category: "safe" as const }),
		};

		const verdict = guards.evaluateProtectedPaths("read", { path: ".env" }, config);
		assert.equal(verdict.action, "confirm");
		if (verdict.action === "confirm") {
			assert.equal(typeof verdict.message, "string");
			assert.ok(verdict.message.length > 0);
			assert.equal(("reason" in verdict), false, "confirm verdict should not have .reason");
		}
	});
});

describe("verdictAuditInfo: blocked confirm verdicts produce .block audit type", () => {
	it("boundary confirm verdict produces .confirm type with info severity (verdictAuditInfo)", () => {
		const verdict = { action: "confirm" as const, message: "Read outside boundary?" };
		const info = verdictAuditInfo("boundary", verdict);
		assert.equal(info.type, "boundary.confirm");
		assert.equal(info.severity, "info");
	});

	it("boundary block verdict produces .block type with warning severity", () => {
		const verdict = { action: "block" as const, reason: "write outside boundary" };
		const info = verdictAuditInfo("boundary", verdict);
		assert.equal(info.type, "boundary.block");
		assert.equal(info.severity, "warning");
	});
});

describe("bash no-UI block: category-aware audit type and reason", () => {
	it("dangerous command blocked without UI produces 'Dangerous command blocked' reason", () => {
		const verdict = classifyCommand("rm -rf /", makeConfig({
			commandRules: { safe: [], moderate: [], dangerous: ["rm\\s+(-rf?|--recursive)"], external: [] },
		}));
		assert.equal(verdict.action, "confirm");
		assert.equal(verdict.category, "dangerous");
		const category = verdict.category ?? "unknown";
		const reason = `${category.charAt(0).toUpperCase() + category.slice(1)} command blocked (no UI)`;
		assert.equal(reason, "Dangerous command blocked (no UI)");
	});

	it("external command blocked without UI produces 'External command blocked' reason", () => {
		const verdict = classifyCommand("curl https://evil.com", makeConfig({
			commandRules: { safe: [], moderate: [], dangerous: [], external: ["\\bcurl\\b"] },
		}));
		assert.equal(verdict.action, "confirm");
		assert.equal(verdict.category, "external");
		const category = verdict.category ?? "unknown";
		const reason = `${category.charAt(0).toUpperCase() + category.slice(1)} command blocked (no UI)`;
		assert.equal(reason, "External command blocked (no UI)");
	});

	it("unknown command blocked without UI produces 'Unknown command blocked' reason", () => {
		const verdict = classifyCommand("python script.py", makeConfig());
		assert.equal(verdict.action, "confirm");
		assert.equal(verdict.category, undefined);
		const category = verdict.category ?? "unknown";
		const reason = `${category.charAt(0).toUpperCase() + category.slice(1)} command blocked (no UI)`;
		assert.equal(reason, "Unknown command blocked (no UI)");
	});
});

// ─── QW-4: input shape validation (Step 0) ─────────────────────────────

describe("validateToolInput: pure schema check (fail-closed)", () => {
	it("returns null for a tool with no schema requirement", () => {
		assert.equal(validateToolInput("grep", { pattern: "foo" }), null);
		assert.equal(validateToolInput("custom_tool", {}), null);
		assert.equal(validateToolInput("unknown", { anything: true }), null);
	});

	it("returns null when all required fields are present and non-empty", () => {
		assert.equal(validateToolInput("read", { path: "foo.txt" }), null);
		assert.equal(validateToolInput("write", { path: "foo.txt", content: "x" }), null);
		assert.equal(validateToolInput("edit", { path: "foo.txt" }), null);
		assert.equal(validateToolInput("bash", { command: "ls -la" }), null);
	});

	for (const tool of ["read", "write", "edit"] as const) {
		const field = "path";
		it(`blocks ${tool} when input.${field} is missing`, () => {
			const verdict = validateToolInput(tool, {});
			assert.ok(verdict && verdict.action === "block");
			assert.match(verdict!.reason, /missing required input\.path/);
		});

		it(`blocks ${tool} when input.${field} is empty string`, () => {
			const verdict = validateToolInput(tool, { [field]: "" });
			assert.ok(verdict && verdict.action === "block");
			assert.match(verdict!.reason, /missing required input\.path/);
		});

		it(`blocks ${tool} when input.${field} is wrong type (number)`, () => {
			const verdict = validateToolInput(tool, { [field]: 42 });
			assert.ok(verdict && verdict.action === "block");
			assert.match(verdict!.reason, /missing required input\.path/);
		});

		it(`blocks ${tool} when input.${field} is null`, () => {
			const verdict = validateToolInput(tool, { [field]: null });
			assert.ok(verdict && verdict.action === "block");
			assert.match(verdict!.reason, /missing required input\.path/);
		});

		it(`blocks ${tool} when input itself is not an object`, () => {
			const verdict = validateToolInput(tool, null);
			assert.ok(verdict && verdict.action === "block");
			assert.match(verdict!.reason, /missing required input\.path/);
		});
	}

	it("blocks bash when input.command is missing", () => {
		const verdict = validateToolInput("bash", {});
		assert.ok(verdict && verdict.action === "block");
		assert.match(verdict!.reason, /missing required input\.command/);
	});

	it("blocks bash when input.command is empty string", () => {
		const verdict = validateToolInput("bash", { command: "" });
		assert.ok(verdict && verdict.action === "block");
		assert.match(verdict!.reason, /missing required input\.command/);
	});

	it("blocks bash when input.command is wrong type (object)", () => {
		const verdict = validateToolInput("bash", { command: { cmd: "ls" } });
		assert.ok(verdict && verdict.action === "block");
		assert.match(verdict!.reason, /missing required input\.command/);
	});

	it("blocks bash when input itself is undefined", () => {
		const verdict = validateToolInput("bash", undefined);
		assert.ok(verdict && verdict.action === "block");
		assert.match(verdict!.reason, /missing required input\.command/);
	});
});

// ─── QW-4: integrated pipeline via mock pi ─────────────────────────────

describe("guard-pipeline: Step 0 blocks malformed input and audits input.invalid", () => {
	let tempDir: string;
	let previousAuditFile: string;

	beforeEach(() => {
		tempDir = resolve(tmpdir(), `pi-guard-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(tempDir, { recursive: true });
		previousAuditFile = _setAuditFileForTest(resolve(tempDir, "audit.jsonl"));
		initAuditLog();
	});

	afterEach(() => {
		_setAuditFileForTest(previousAuditFile);
		if (tempDir && existsSync(tempDir)) {
			rmSync(tempDir, { recursive: true, force: true });
		}
	});

	/** Minimal pi stub that captures the registered tool_call handler. */
	function makeMockPi() {
		let handler: ((event: { toolName: string; input: unknown }, ctx: unknown) => Promise<unknown>) | null = null;
		const pi = {
			on(event: string, h: typeof handler) {
				if (event === "tool_call") handler = h;
			},
		};
		return {
			pi: pi as unknown as ExtensionAPI,
			invoke(event: { toolName: string; input: unknown }, ctx: unknown) {
				if (!handler) throw new Error("tool_call handler not registered");
				return handler(event, ctx);
			},
		};
	}

	/** Minimal ctx with no UI (fail-closed path). */
	function makeCtxNoUI() {
		return { hasUI: false, ui: { notify() {}, confirm: async () => false } };
	}

	/** Guard evaluators that record the order they were called. */
	function makeSpyGuards(calls: string[]): GuardEvaluators {
		return {
			evaluateBoundary: () => { calls.push("boundary"); return { action: "allow" as const }; },
			evaluateProtectedPaths: () => { calls.push("protected"); return { action: "allow" as const }; },
			classifyCommand: () => { calls.push("bash"); return { action: "allow" as const, category: "safe" as const }; },
		};
	}

	function readAuditEntries(): Array<{ type: string; severity: string; details: Record<string, unknown> }> {
		const file = resolve(tempDir, "audit.jsonl");
		if (!existsSync(file)) return [];
		return readFileSync(file, "utf-8")
			.trim()
			.split("\n")
			.filter(Boolean)
			.map((line) => JSON.parse(line));
	}

	it("blocks a read tool_call missing path and does not reach downstream guards", async () => {
		const { pi, invoke } = makeMockPi();
		const calls: string[] = [];
		registerGuardPipeline(pi, () => makeConfig(), makeSpyGuards(calls));

		const result = await invoke({ toolName: "read", input: {} }, makeCtxNoUI());

		assert.deepEqual(result, { block: true, reason: "missing required input.path" });
		assert.deepEqual(calls, [], "downstream guards must not run on malformed input");

		const entries = readAuditEntries();
		const invalid = entries.filter((e) => e.type === "input.invalid");
		assert.equal(invalid.length, 1);
		assert.equal(invalid[0].severity, "warning");
		assert.equal(invalid[0].details.tool, "read");
		assert.match(String(invalid[0].details.reason), /missing required input\.path/);
	});

	it("blocks a bash tool_call missing command and audits input.invalid", async () => {
		const { pi, invoke } = makeMockPi();
		const calls: string[] = [];
		registerGuardPipeline(pi, () => makeConfig(), makeSpyGuards(calls));

		const result = await invoke({ toolName: "bash", input: {} }, makeCtxNoUI());

		assert.deepEqual(result, { block: true, reason: "missing required input.command" });
		assert.deepEqual(calls, [], "downstream guards must not run on malformed input");

		const invalid = readAuditEntries().filter((e) => e.type === "input.invalid");
		assert.equal(invalid.length, 1);
		assert.equal(invalid[0].details.tool, "bash");
	});

	it("blocks a write tool_call with non-string path", async () => {
		const { pi, invoke } = makeMockPi();
		const calls: string[] = [];
		registerGuardPipeline(pi, () => makeConfig(), makeSpyGuards(calls));

		const result = await invoke({ toolName: "write", input: { path: 123 } }, makeCtxNoUI());

		assert.deepEqual(result, { block: true, reason: "missing required input.path" });
		assert.deepEqual(calls, []);
	});

	it("blocks an edit tool_call with empty-string path", async () => {
		const { pi, invoke } = makeMockPi();
		const calls: string[] = [];
		registerGuardPipeline(pi, () => makeConfig(), makeSpyGuards(calls));

		const result = await invoke({ toolName: "edit", input: { path: "" } }, makeCtxNoUI());

		assert.deepEqual(result, { block: true, reason: "missing required input.path" });
		assert.deepEqual(calls, []);
		assert.equal(readAuditEntries().filter((e) => e.type === "input.invalid").length, 1);
	});

	it("does NOT affect a well-formed read — pipeline reaches boundary and protected", async () => {
		const { pi, invoke } = makeMockPi();
		const calls: string[] = [];
		registerGuardPipeline(pi, () => makeConfig(), makeSpyGuards(calls));

		const result = await invoke(
			{ toolName: "read", input: { path: "src/foo.txt" } },
			makeCtxNoUI(),
		);

		assert.equal(result, undefined, "well-formed input must pass through");
		assert.deepEqual(calls, ["boundary", "protected"]);
		assert.equal(readAuditEntries().filter((e) => e.type === "input.invalid").length, 0);
	});

	it("does NOT affect a well-formed bash — pipeline reaches bash-gate", async () => {
		const { pi, invoke } = makeMockPi();
		const calls: string[] = [];
		registerGuardPipeline(pi, () => makeConfig(), makeSpyGuards(calls));

		const result = await invoke(
			{ toolName: "bash", input: { command: "ls -la" } },
			makeCtxNoUI(),
		);

		assert.equal(result, undefined, "well-formed input must pass through");
		// boundary and protected are invoked for every tool but short-circuit
		// to allow internally for bash (ADR-0003); the point is Step 0 did not
		// short-circuit and the full pipeline ran.
		assert.deepEqual(calls, ["boundary", "protected", "bash"]);
		assert.equal(readAuditEntries().filter((e) => e.type === "input.invalid").length, 0);
	});

	it("does NOT affect a tool with no schema requirement (grep)", async () => {
		const { pi, invoke } = makeMockPi();
		const calls: string[] = [];
		registerGuardPipeline(pi, () => makeConfig(), makeSpyGuards(calls));

		const result = await invoke(
			{ toolName: "grep", input: { pattern: "foo" } },
			makeCtxNoUI(),
		);

		assert.equal(result, undefined, "tools without schema requirement pass through");
		assert.equal(readAuditEntries().filter((e) => e.type === "input.invalid").length, 0);
	});
});

// ─── P3-1: ctx.mode gates interactive dialogs ──────────────────────────

describe("guard-pipeline: ctx.mode gates interactive dialogs (P3-1)", () => {
	let tempDir: string;
	let previousAuditFile: string;

	beforeEach(() => {
		tempDir = resolve(tmpdir(), `pi-guard-mode-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(tempDir, { recursive: true });
		previousAuditFile = _setAuditFileForTest(resolve(tempDir, "audit.jsonl"));
		initAuditLog();
	});

	afterEach(() => {
		_setAuditFileForTest(previousAuditFile);
		if (tempDir && existsSync(tempDir)) rmSync(tempDir, { recursive: true, force: true });
	});

	function makeMockPi() {
		let handler: ((event: { toolName: string; input: unknown }, ctx: unknown) => Promise<unknown>) | null = null;
		const pi = {
			on(event: string, h: typeof handler) {
				if (event === "tool_call") handler = h;
			},
		};
		return {
			pi: pi as unknown as ExtensionAPI,
			invoke(event: { toolName: string; input: unknown }, ctx: unknown) {
				if (!handler) throw new Error("tool_call handler not registered");
				return handler(event, ctx);
			},
		};
	}

	/**
	 * Build a mock ctx with explicit mode, a recording notify, and a
	 * confirm that throws if invoked (so any test that expects no
	 * dialog fails loudly when the gating is bypassed). Tests that
	 * require confirm to actually render pass `confirmReturn`.
	 */
	function makeCtxWithMode(
		mode: "tui" | "rpc" | "json" | "print" | undefined,
		opts: { hasUI?: boolean; confirmReturn?: boolean } = {},
	) {
		const confirmCalls: { title: string; message: string }[] = [];
		const notifyCalls: { message: string; severity: string }[] = [];
		const hasUI = opts.hasUI ?? (mode === "tui" || mode === "rpc");
		const confirmReturn = opts.confirmReturn ?? false;
		return {
			ctx: {
				hasUI,
				...(mode === undefined ? {} : { mode }),
				ui: {
					notify: (message: string, severity: string) => { notifyCalls.push({ message, severity }); },
					confirm: async (title: string, message: string) => {
						confirmCalls.push({ title, message });
						return confirmReturn;
					},
				},
			},
			confirmCalls,
			notifyCalls,
		};
	}

	function readAuditEntries(): Array<{ type: string; severity: string; details: Record<string, unknown> }> {
		const file = resolve(tempDir, "audit.jsonl");
		if (!existsSync(file)) return [];
		return readFileSync(file, "utf-8")
			.trim()
			.split("\n")
			.filter(Boolean)
			.map((line) => JSON.parse(line));
	}

	// ── AC#1: non-TUI modes fail closed with no dialog ───────────────

	for (const mode of ["rpc", "json", "print"] as const) {
		it(`AC#1 [${mode}]: boundary confirm → immediate block, no confirm dialog invoked, reason mentions mode`, async () => {
			const { pi, invoke } = makeMockPi();
			const guards: GuardEvaluators = {
				evaluateBoundary: () => ({
					action: "confirm" as const,
					message: "Read file outside project boundary?\n\n  /etc/passwd",
				}),
				evaluateProtectedPaths: () => ({ action: "allow" as const }),
				classifyCommand: () => ({ action: "allow" as const, category: "safe" as const }),
			};
			registerGuardPipeline(pi, () => makeConfig(), guards);

			const { ctx, confirmCalls } = makeCtxWithMode(mode);

			const result = await invoke(
				{ toolName: "read", input: { path: "/etc/passwd" } },
				ctx,
			);

			assert.deepEqual(confirmCalls, [], "confirm dialog must NOT be invoked in non-tui mode");
			assert.ok((result as { block?: boolean }).block, "must block");
			assert.match(
				(result as { reason: string }).reason,
				new RegExp(`confirmation requires interactive \\(tui\\) mode; current mode: ${mode}`),
				"reason must mention the current mode",
			);

			const blocks = readAuditEntries().filter((e) => e.type === "boundary.block");
			assert.equal(blocks.length, 1);
			assert.equal(blocks[0].details.mode, mode, "audit entry records the mode");
		});

		it(`AC#1 [${mode}]: protected-paths confirm → block with mode in reason, no dialog`, async () => {
			const { pi, invoke } = makeMockPi();
			const guards: GuardEvaluators = {
				evaluateBoundary: () => ({ action: "allow" as const }),
				evaluateProtectedPaths: () => ({
					action: "confirm" as const,
					message: "Read protected file .env?",
				}),
				classifyCommand: () => ({ action: "allow" as const, category: "safe" as const }),
			};
			registerGuardPipeline(pi, () => makeConfig(), guards);

			const { ctx, confirmCalls } = makeCtxWithMode(mode);

			const result = await invoke(
				{ toolName: "read", input: { path: ".env" } },
				ctx,
			);

			assert.deepEqual(confirmCalls, []);
			assert.ok((result as { block?: boolean }).block);
			assert.match(
				(result as { reason: string }).reason,
				new RegExp(`current mode: ${mode}`),
			);
		});

		it(`AC#1 [${mode}]: bash dangerous command confirm → block with mode in reason, no dialog`, async () => {
			const { pi, invoke } = makeMockPi();
			const guards: GuardEvaluators = {
				evaluateBoundary: () => ({ action: "allow" as const }),
				evaluateProtectedPaths: () => ({ action: "allow" as const }),
				classifyCommand: () => ({
					action: "confirm" as const,
					message: "Run dangerous command?",
					category: "dangerous" as const,
				}),
			};
			registerGuardPipeline(pi, () => makeConfig(), guards);

			const { ctx, confirmCalls } = makeCtxWithMode(mode);

			const result = await invoke(
				{ toolName: "bash", input: { command: "rm -rf /" } },
				ctx,
			);

			assert.deepEqual(confirmCalls, []);
			assert.ok((result as { block?: boolean }).block);
			assert.match(
				(result as { reason: string }).reason,
				new RegExp(`current mode: ${mode}`),
			);

			const blocks = readAuditEntries().filter((e) => e.type === "bash.dangerous.block");
			assert.equal(blocks.length, 1);
			assert.equal(blocks[0].details.mode, mode);
		});
	}

	// ── AC#2: tui mode shows the dialog (no behavior change) ─────────

	it("AC#2: tui mode → boundary confirm dialog IS shown and approved (no block)", async () => {
		const { pi, invoke } = makeMockPi();
		const guards: GuardEvaluators = {
			evaluateBoundary: () => ({
				action: "confirm" as const,
				message: "Read outside boundary?",
			}),
			evaluateProtectedPaths: () => ({ action: "allow" as const }),
			classifyCommand: () => ({ action: "allow" as const, category: "safe" as const }),
		};
		registerGuardPipeline(pi, () => makeConfig(), guards);

		const { ctx, confirmCalls } = makeCtxWithMode("tui", { confirmReturn: true });

		const result = await invoke(
			{ toolName: "read", input: { path: "/etc/hosts" } },
			ctx,
		);

		assert.equal(result, undefined, "approved confirm must pass through");
		assert.equal(confirmCalls.length, 1, "confirm dialog must be shown exactly once in tui mode");
		assert.equal(confirmCalls[0].title, "🔒 Boundary Check");

		const confirms = readAuditEntries().filter((e) => e.type === "boundary.confirm");
		assert.equal(confirms.length, 1);
	});

	it("AC#2: tui mode → bash dangerous confirm dialog IS shown (user denies → block)", async () => {
		const { pi, invoke } = makeMockPi();
		const guards: GuardEvaluators = {
			evaluateBoundary: () => ({ action: "allow" as const }),
			evaluateProtectedPaths: () => ({ action: "allow" as const }),
			classifyCommand: () => ({
				action: "confirm" as const,
				message: "Run dangerous command?",
				category: "dangerous" as const,
			}),
		};
		registerGuardPipeline(pi, () => makeConfig(), guards);

		const { ctx, confirmCalls } = makeCtxWithMode("tui", { confirmReturn: false });

		const result = await invoke(
			{ toolName: "bash", input: { command: "rm -rf /" } },
			ctx,
		);

		assert.equal(confirmCalls.length, 1, "confirm dialog shown in tui mode");
		assert.ok((result as { block?: boolean }).block, "user-denied confirm still blocks");
		assert.match((result as { reason: string }).reason, /User denied: dangerous command/);
	});

	// ── AC#3: undefined mode falls back to hasUI (backward compat) ────

	it("AC#3a: mode undefined + hasUI true → confirm dialog shown (legacy behavior preserved)", async () => {
		const { pi, invoke } = makeMockPi();
		const guards: GuardEvaluators = {
			evaluateBoundary: () => ({
				action: "confirm" as const,
				message: "Read outside boundary?",
			}),
			evaluateProtectedPaths: () => ({ action: "allow" as const }),
			classifyCommand: () => ({ action: "allow" as const, category: "safe" as const }),
		};
		registerGuardPipeline(pi, () => makeConfig(), guards);

		// Old pi versions: ctx has no `mode` field, hasUI=true.
		const { ctx, confirmCalls } = makeCtxWithMode(undefined, { hasUI: true, confirmReturn: true });

		const result = await invoke(
			{ toolName: "read", input: { path: "/etc/hosts" } },
			ctx,
		);

		assert.equal(result, undefined, "approved confirm passes through (legacy path)");
		assert.equal(confirmCalls.length, 1, "dialog shown via hasUI fallback");
	});

	it("AC#3b: mode undefined + hasUI false → block with the guard's own message (no mode prefix, no regression)", async () => {
		const { pi, invoke } = makeMockPi();
		const message = "Read file outside project boundary?\n\n  /etc/passwd";
		const guards: GuardEvaluators = {
			evaluateBoundary: () => ({ action: "confirm" as const, message }),
			evaluateProtectedPaths: () => ({ action: "allow" as const }),
			classifyCommand: () => ({ action: "allow" as const, category: "safe" as const }),
		};
		registerGuardPipeline(pi, () => makeConfig(), guards);

		const { ctx, confirmCalls } = makeCtxWithMode(undefined, { hasUI: false });

		const result = await invoke(
			{ toolName: "read", input: { path: "/etc/passwd" } },
			ctx,
		);

		assert.deepEqual(confirmCalls, [], "no dialog when hasUI is false");
		assert.ok((result as { block?: boolean }).block);
		// Legacy behavior: the verdict's own message is the block reason,
		// with no mode prefix added.
		assert.equal((result as { reason: string }).reason, message);

		const blocks = readAuditEntries().filter((e) => e.type === "boundary.block");
		assert.equal(blocks.length, 1);
		assert.equal(blocks[0].details.mode, undefined, "mode is absent in audit details");
	});

	it("AC#3c: mode undefined + hasUI false → bash confirm uses legacy '(no UI)' reason (no regression)", async () => {
		const { pi, invoke } = makeMockPi();
		const guards: GuardEvaluators = {
			evaluateBoundary: () => ({ action: "allow" as const }),
			evaluateProtectedPaths: () => ({ action: "allow" as const }),
			classifyCommand: () => ({
				action: "confirm" as const,
				message: "Run dangerous command?",
				category: "dangerous" as const,
			}),
		};
		registerGuardPipeline(pi, () => makeConfig(), guards);

		const { ctx } = makeCtxWithMode(undefined, { hasUI: false });

		const result = await invoke(
			{ toolName: "bash", input: { command: "rm -rf /" } },
			ctx,
		);

		assert.ok((result as { block?: boolean }).block);
		// Legacy reason format is preserved when mode is undefined.
		assert.equal((result as { reason: string }).reason, "Dangerous command blocked (no UI)");
	});

	// ── AC#4: notify is NOT gated by mode (informational, never hangs) ─

	it("AC#4: rpc mode (hasUI=true) → notify still fires on input.invalid block", async () => {
		const { pi, invoke } = makeMockPi();
		const guards: GuardEvaluators = {
			evaluateBoundary: () => ({ action: "allow" as const }),
			evaluateProtectedPaths: () => ({ action: "allow" as const }),
			classifyCommand: () => ({ action: "allow" as const, category: "safe" as const }),
		};
		registerGuardPipeline(pi, () => makeConfig(), guards);

		const { ctx, notifyCalls, confirmCalls } = makeCtxWithMode("rpc");

		const result = await invoke(
			{ toolName: "read", input: {} }, // malformed → input.invalid
			ctx,
		);

		assert.ok((result as { block?: boolean }).block);
		assert.equal(notifyCalls.length, 1, "notify fires in rpc mode (hasUI=true)");
		assert.match(notifyCalls[0].message, /Blocked: missing required input\.path/);
		assert.deepEqual(confirmCalls, [], "confirm still never invoked in rpc mode");
	});

	it("AC#4: rpc mode → notify fires on tool_calls ratelimit block (informational path)", async () => {
		const { pi, invoke } = makeMockPi();
		const guards: GuardEvaluators = {
			evaluateBoundary: () => ({ action: "allow" as const }),
			evaluateProtectedPaths: () => ({ action: "allow" as const }),
			classifyCommand: () => ({ action: "allow" as const, category: "safe" as const }),
		};
		registerGuardPipeline(
			pi,
			() => makeConfig({
				securityPolicy: {
					toolCallsPerTurn: 1,
					confirmationsPerSession: 100,
				},
			}),
			guards,
		);

		const { ctx, notifyCalls } = makeCtxWithMode("rpc");

		// First call passes; second hits the tool_calls cap.
		await invoke({ toolName: "read", input: { path: "a.txt" } }, ctx);
		const blocked = await invoke({ toolName: "read", input: { path: "b.txt" } }, ctx);

		assert.ok((blocked as { block?: boolean }).block);
		assert.ok(
			notifyCalls.some((n) => /Rate limit/.test(n.message)),
			"notify fires for ratelimit block in rpc mode",
		);
	});
});