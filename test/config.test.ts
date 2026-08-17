/**
 * Unit tests for lib/config.ts — merge logic
 */
import { describe, it, beforeEach, afterEach, mock } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { tmpdir } from "node:os";
import { mergePatterns, mergeProtectedPaths, mergeCommandRules, loadConfig } from "../lib/config.js";
import type { ProtectedPathsConfig, CommandRulesConfig } from "../lib/config.js";
import { classifySegment } from "../lib/bash-gate.js";
import { DEFAULTS_DIR } from "../lib/utils.js";

// ── Fixtures ──────────────────────────────────────────────────────────
const pp = (
	patterns: string[],
	writeAction: "block" | "confirm" = "block",
	readAction: "block" | "confirm" | "allow" = "confirm",
): ProtectedPathsConfig => ({ patterns, writeAction, readAction });

const cr = (partial: Partial<CommandRulesConfig> = {}): CommandRulesConfig => ({
	safe: [],
	moderate: [],
	dangerous: [],
	external: [],
	...partial,
});

describe("mergePatterns", () => {
	it("merges additive layers", () => {
		const result = mergePatterns([["a", "b"], ["c", "d"]]);
		assert.deepEqual(result, ["a", "b", "c", "d"]);
	});

	it("handles undefined layers", () => {
		const result = mergePatterns([["a"], undefined, ["c"]]);
		assert.deepEqual(result, ["a", "c"]);
	});

	it("excludes with ! prefix from earlier layers", () => {
		const result = mergePatterns([
			["*.key", "*.pem", "*.env"],
			["!*.pem", "extra-pattern"],
		]);
		assert.deepEqual(result, ["*.key", "*.env", "extra-pattern"]);
	});

	it("exclusion of non-existent pattern is a no-op", () => {
		const result = mergePatterns([
			["a"],
			["!nonexistent"],
		]);
		assert.deepEqual(result, ["a"]);
	});

	it("all three layers merge correctly", () => {
		const result = mergePatterns([
			["env", "key", "pem"],
			["!key", "custom"],
			["!pem", "project-secret"],
		]);
		assert.deepEqual(result, ["env", "custom", "project-secret"]);
	});

	it("empty layers produce empty result", () => {
		assert.deepEqual(mergePatterns([]), []);
		assert.deepEqual(mergePatterns([undefined, undefined]), []);
	});

	it("duplicate patterns are preserved across layers", () => {
		const result = mergePatterns([["a"], ["a"]]);
		assert.deepEqual(result, ["a", "a"]);
	});

	it("excludes patterns case-insensitively", () => {
		const result = mergePatterns([["*.pem"], ["!*.PEM"]]);
		assert.deepEqual(result, [], "case-insensitive exclusion should remove *.pem");
	});

	it("exclusion removes all inherited duplicates of a pattern", () => {
		const result = mergePatterns([
			["a", "a"],
			["!a"],
		]);
		assert.deepEqual(result, [], "exclusion should remove all inherited copies");
	});
});

describe("mergeProtectedPaths", () => {
	let consoleErrorMock: ReturnType<typeof mock.method>;

	beforeEach(() => {
		consoleErrorMock = mock.method(console, "error", () => {});
	});

	afterEach(() => {
		consoleErrorMock.mock.restore();
	});

	it("merges additive layers, preserving the baseline and project additions", () => {
		const result = mergeProtectedPaths([
			pp([".env", "*.key"]),
			undefined,
			pp(["custom-secret.txt"]),
		]);
		assert.deepEqual(result.patterns, [".env", "*.key", "custom-secret.txt"]);
	});

	it("project layer cannot remove a baseline protected path via ! (AC#2)", () => {
		const result = mergeProtectedPaths([
			pp([".env", "*.key"]),
			undefined,
			pp(["!.env"]),
		]);
		assert.ok(
			result.patterns.includes(".env"),
			".env must remain protected even if the project layer tries to exclude it",
		);
		assert.ok(result.patterns.includes("*.key"));
	});

	it("project layer cannot remove a machine-added baseline pattern", () => {
		const result = mergeProtectedPaths([
			pp([".env"]),
			pp(["machine-secret"]),
			pp(["!machine-secret"]),
		]);
		assert.ok(
			result.patterns.includes("machine-secret"),
			"machine-added patterns are part of the baseline and cannot be removed by the project layer",
		);
		assert.ok(result.patterns.includes(".env"));
	});

	it("machine layer CAN exclude a default pattern (lock is project-only, AC#4)", () => {
		const result = mergeProtectedPaths([
			pp([".env", "*.key"]),
			pp(["!*.key"]),
			undefined,
		]);
		assert.ok(!result.patterns.includes("*.key"), "machine exclusion of a default must still work");
		assert.ok(result.patterns.includes(".env"));
	});

	it("project exclusion of a non-existent pattern is a silent no-op", () => {
		const result = mergeProtectedPaths([
			pp([".env"]),
			undefined,
			pp(["!does-not-exist", "added"]),
		]);
		assert.deepEqual(result.patterns, [".env", "added"]);
		assert.equal(consoleErrorMock.mock.calls.length, 0, "no warning for a non-matching exclusion");
	});

	it("project layer can still ADD protected patterns (AC#3)", () => {
		const result = mergeProtectedPaths([
			pp([".env"]),
			undefined,
			pp(["custom-secret.txt", "another-secret"]),
		]);
		assert.ok(result.patterns.includes("custom-secret.txt"));
		assert.ok(result.patterns.includes("another-secret"));
		assert.ok(result.patterns.includes(".env"));
	});

	it("preserves writeAction/readAction precedence across layers", () => {
		const result = mergeProtectedPaths([
			pp([".env"], "block", "confirm"),
			pp([], "confirm", "allow"),
			pp([], "block", "block"),
		]);
		assert.equal(result.writeAction, "block");
		assert.equal(result.readAction, "block");
	});

	it("project-layer readAction \"allow\" is clamped to baseline \"confirm\" with a warning (AC#1)", () => {
		const result = mergeProtectedPaths([
			pp([".env"], "block", "confirm"),
			undefined,
			pp([], "block", "allow"),
		]);
		assert.equal(result.readAction, "confirm", "project allow must not weaken baseline confirm");
		assert.ok(
			consoleErrorMock.mock.calls.some((c) =>
				/Project-layer readAction "allow" weakens the baseline "confirm"/.test(String(c.arguments[0])),
			),
			"must warn that the weakening project readAction was ignored",
		);
	});

	it("project-layer writeAction \"confirm\" is clamped to baseline \"block\" with a warning (AC#1)", () => {
		const result = mergeProtectedPaths([
			pp([".env"], "block", "confirm"),
			undefined,
			pp([], "confirm", "confirm"),
		]);
		assert.equal(result.writeAction, "block", "project confirm must not weaken baseline block");
		assert.ok(
			consoleErrorMock.mock.calls.some((c) =>
				/Project-layer writeAction "confirm" weakens the baseline "block"/.test(String(c.arguments[0])),
			),
			"must warn that the weakening project writeAction was ignored",
		);
	});

	it("project-layer readAction \"block\" strengthens baseline \"confirm\" and is honoured with no warning (AC#2)", () => {
		const result = mergeProtectedPaths([
			pp([".env"], "block", "confirm"),
			undefined,
			pp([], "block", "block"),
		]);
		assert.equal(result.readAction, "block", "project block strengthens baseline confirm and is honoured");
		assert.equal(consoleErrorMock.mock.calls.length, 0, "strengthening must not warn");
	});

	it("project-layer writeAction equal to baseline \"block\" is honoured with no warning (AC#2)", () => {
		const result = mergeProtectedPaths([
			pp([".env"], "block", "confirm"),
			undefined,
			pp([], "block", "confirm"),
		]);
		assert.equal(result.writeAction, "block", "equal project value is honoured");
		assert.equal(consoleErrorMock.mock.calls.length, 0, "equal value must not warn");
	});

	it("machine-layer readAction \"allow\" overrides default \"confirm\" (clamp is project-only, AC#3)", () => {
		const result = mergeProtectedPaths([
			pp([".env"], "block", "confirm"),
			pp([], "block", "allow"),
			undefined,
		]);
		assert.equal(result.readAction, "allow", "machine overrides defaults; the clamp is project-only");
		assert.equal(consoleErrorMock.mock.calls.length, 0, "machine overrides must not warn");
	});

	it("no project layer → baseline actions are used with no warning", () => {
		const result = mergeProtectedPaths([
			pp([".env"], "block", "confirm"),
			pp([], "confirm", "block"),
			undefined,
		]);
		assert.equal(result.writeAction, "confirm", "machine writeAction overrides default");
		assert.equal(result.readAction, "block", "machine readAction overrides default");
		assert.equal(consoleErrorMock.mock.calls.length, 0, "no project layer means no warning");
	});

	it("emits a warning when ignoring a project exclusion of a baseline pattern", () => {
		mergeProtectedPaths([pp([".env"]), undefined, pp(["!.env"])]);
		assert.ok(
			consoleErrorMock.mock.calls.length >= 1,
			"ignoring a baseline-weakening project exclusion must emit a warning",
		);
	});

	it("case-insensitive exclusion targeting a baseline pattern is still blocked", () => {
		const result = mergeProtectedPaths([
			pp([".env"]),
			undefined,
			pp(["!.ENV"]),
		]);
		assert.ok(result.patterns.includes(".env"), "case-insensitive exclusion of baseline is ignored");
	});
});

// ── Corrected defaults + baseline lock (ADR-0011) ─────────────────────
//
// Loads the REAL shipped defaults/protected-paths.json so a regression
// (re-adding `*secret*`/`*credential*`) is caught here, and exercises the
// three-layer merge against the corrected baseline.

function loadDefaultsPP(): ProtectedPathsConfig {
	const raw = readFileSync(resolve(DEFAULTS_DIR, "protected-paths.json"), "utf-8");
	return JSON.parse(raw) as ProtectedPathsConfig;
}

describe("mergeProtectedPaths — corrected defaults (ADR-0011)", () => {
	let consoleErrorMock: ReturnType<typeof mock.method>;

	beforeEach(() => {
		consoleErrorMock = mock.method(console, "error", () => {});
	});

	afterEach(() => {
		consoleErrorMock.mock.restore();
	});

	it("shipped defaults no longer contain broad lexical patterns", () => {
		const def = loadDefaultsPP();
		assert.ok(!def.patterns.includes("*secret*"), "broad *secret* must be removed from defaults");
		assert.ok(!def.patterns.includes("*credential*"), "broad *credential* must be removed");
		assert.ok(!def.patterns.includes("*token*.json"), "broad *token*.json must be removed");
	});

	it("shipped defaults contain the structured-format replacement patterns", () => {
		const def = loadDefaultsPP();
		for (const p of [
			"*credentials.json",
			"*credentials.yaml",
			"*credentials.yml",
			"*credentials.toml",
			"*credential.json",
			"*secrets.json",
			"*secrets.yaml",
			"*secret.json",
			"*token.json",
			"*tokens.json",
		]) {
			assert.ok(def.patterns.includes(p), `defaults must include ${p}`);
		}
	});

	it("machine layer can add protected patterns on top of the corrected defaults", () => {
		const def = loadDefaultsPP();
		const result = mergeProtectedPaths([def, pp(["machine-secret.txt"]), undefined]);
		assert.ok(result.patterns.includes("machine-secret.txt"), "machine addition present");
		assert.ok(result.patterns.includes("*credentials.json"), "baseline pattern preserved");
	});

	it("project layer can add protected patterns (strengthen)", () => {
		const def = loadDefaultsPP();
		const result = mergeProtectedPaths([def, undefined, pp(["custom-secret.txt"])]);
		assert.ok(result.patterns.includes("custom-secret.txt"), "project addition present");
		assert.ok(result.patterns.includes("*credentials.json"), "baseline preserved");
	});

	it("project layer cannot remove a corrected-default baseline pattern via !", () => {
		const def = loadDefaultsPP();
		const result = mergeProtectedPaths([def, undefined, pp(["!*credentials.json"])]);
		assert.ok(
			result.patterns.includes("*credentials.json"),
			"baseline *credentials.json must survive a project-layer exclusion",
		);
		assert.ok(
			consoleErrorMock.mock.calls.some((c) =>
				/Project-layer protected-path exclusion.*\*credentials\.json/.test(String(c.arguments[0])),
			),
			"must warn that the baseline-weakening project exclusion was ignored",
		);
	});

	it("project exclusion of a pattern absent from the baseline is a silent no-op", () => {
		const def = loadDefaultsPP();
		const result = mergeProtectedPaths([def, undefined, pp(["!*secret*", "added"])]);
		assert.ok(!result.patterns.includes("*secret*"), "*secret* is not in defaults; nothing to exclude");
		assert.ok(result.patterns.includes("added"), "non-exclusion additions are kept");
		assert.equal(consoleErrorMock.mock.calls.length, 0, "excluding a non-baseline pattern must not warn");
	});

	it("corrected defaults + machine + project merge keeps the full baseline and project additions", () => {
		const def = loadDefaultsPP();
		const result = mergeProtectedPaths([
			def,
			pp(["machine-extra.yaml"]),
			pp(["project-extra.json"]),
		]);
		assert.ok(result.patterns.includes("*credentials.json"), "default baseline present");
		assert.ok(result.patterns.includes("machine-extra.yaml"), "machine addition present");
		assert.ok(result.patterns.includes("project-extra.json"), "project addition present");
	});
});

describe("mergeCommandRules", () => {
	let consoleErrorMock: ReturnType<typeof mock.method>;

	beforeEach(() => {
		consoleErrorMock = mock.method(console, "error", () => {});
	});

	afterEach(() => {
		consoleErrorMock.mock.restore();
	});

	it("rejects an overly broad .* in project safe (AC#1)", () => {
		const result = mergeCommandRules([
			cr({ safe: ["^ls\\b"] }),
			undefined,
			cr({ safe: [".*"] }),
		]);
		assert.ok(!result.safe.includes(".*"), "broad .* from project layer must be dropped");
		assert.deepEqual(result.safe, ["^ls\\b"]);
	});

	it("rejects ^.*$ in project safe", () => {
		const result = mergeCommandRules([cr(), undefined, cr({ safe: ["^.*$"] })]);
		assert.ok(!result.safe.includes("^.*$"));
		assert.deepEqual(result.safe, []);
	});

	it("rejects ^ in project safe", () => {
		const result = mergeCommandRules([cr(), undefined, cr({ safe: ["^"] })]);
		assert.ok(!result.safe.includes("^"));
		assert.deepEqual(result.safe, []);
	});

	it("rejects an overly broad .* in project moderate", () => {
		const result = mergeCommandRules([cr(), undefined, cr({ moderate: [".*"] })]);
		assert.ok(!result.moderate.includes(".*"));
		assert.deepEqual(result.moderate, []);
	});

	it("keeps valid patterns alongside a rejected broad one", () => {
		const result = mergeCommandRules([
			cr({ safe: ["^ls\\b"] }),
			undefined,
			cr({ safe: [".*", "^my-safe-tool\\b"] }),
		]);
		assert.ok(!result.safe.includes(".*"));
		assert.ok(result.safe.includes("^my-safe-tool\\b"));
		assert.ok(result.safe.includes("^ls\\b"));
	});

	it("project layer can add a valid safe pattern without false rejection (AC#3)", () => {
		const result = mergeCommandRules([
			cr({ safe: ["^ls\\b"] }),
			undefined,
			cr({ safe: ["^my-safe-tool\\b"] }),
		]);
		assert.ok(result.safe.includes("^my-safe-tool\\b"));
		assert.ok(result.safe.includes("^ls\\b"));
		assert.equal(consoleErrorMock.mock.calls.length, 0);
	});

	it("defaults-layer broad pattern is NOT rejected (warned only, not dropped)", () => {
		const result = mergeCommandRules([cr({ safe: [".*"] }), undefined, undefined]);
		assert.ok(result.safe.includes(".*"), "defaults broad patterns pass through; only project is locked");
	});

	it("machine-layer broad pattern is NOT rejected", () => {
		const result = mergeCommandRules([cr(), cr({ safe: [".*"] }), undefined]);
		assert.ok(result.safe.includes(".*"), "machine broad patterns pass through");
	});

	it("dangerous and external categories are unaffected by project safe filtering", () => {
		const result = mergeCommandRules([
			cr(),
			undefined,
			cr({ safe: [".*"], dangerous: ["^rm$"], external: ["\\bcurl\\b"] }),
		]);
		assert.deepEqual(result.safe, [], "broad project safe is dropped");
		assert.deepEqual(result.dangerous, ["^rm$"]);
		assert.deepEqual(result.external, ["\\bcurl\\b"]);
	});

	it("emits a warning when rejecting a broad project safe pattern", () => {
		mergeCommandRules([cr(), undefined, cr({ safe: [".*"] })]);
		assert.ok(
			consoleErrorMock.mock.calls.length >= 1,
			"rejecting a broad project pattern must emit a warning",
		);
	});

	it("preserves additive merge of valid patterns across all three layers", () => {
		const result = mergeCommandRules([
			cr({ safe: ["^ls\\b"] }),
			cr({ safe: ["^pwd\\b"] }),
			cr({ safe: ["^my-safe-tool\\b"] }),
		]);
		assert.deepEqual(result.safe, ["^ls\\b", "^pwd\\b", "^my-safe-tool\\b"]);
	});

	// ── C1: project layer cannot disarm the bash gate via command-rules ──

	it("project layer cannot remove a baseline external pattern via ! (C1 T1)", () => {
		const result = mergeCommandRules([
			cr({ external: ["\\bcurl\\b"] }),
			undefined,
			cr({ external: ["!\\bcurl\\b"] }),
		]);
		assert.ok(
			result.external.includes("\\bcurl\\b"),
			"baseline external pattern \\bcurl\\b must remain despite the project-layer ! exclusion",
		);
		assert.ok(
			consoleErrorMock.mock.calls.some((c) =>
				/Project-layer external command-rules exclusion/.test(String(c.arguments[0])),
			),
			"must warn that the baseline-weakening project exclusion was ignored",
		);
	});

	it("project layer cannot remove a baseline dangerous pattern via ! (C1 T2)", () => {
		const result = mergeCommandRules([
			cr({ dangerous: ["\\bsudo\\b"] }),
			undefined,
			cr({ dangerous: ["!\\bsudo\\b"] }),
		]);
		assert.ok(
			result.dangerous.includes("\\bsudo\\b"),
			"baseline dangerous pattern \\bsudo\\b must remain despite the project-layer ! exclusion",
		);
		assert.ok(
			consoleErrorMock.mock.calls.some((c) =>
				/Project-layer dangerous command-rules exclusion/.test(String(c.arguments[0])),
			),
			"must warn that the baseline-weakening project exclusion was ignored",
		);
	});

	it("rejects a project-layer safe pattern that shadows a baseline external pattern (C1 T3)", () => {
		const result = mergeCommandRules([
			cr({ external: ["\\bcurl\\b"] }),
			undefined,
			cr({ safe: ["\\bcurl\\b"] }),
		]);
		assert.ok(
			!result.safe.includes("\\bcurl\\b"),
			"project safe pattern shadowing a baseline external pattern must be dropped",
		);
		assert.ok(
			result.external.includes("\\bcurl\\b"),
			"baseline external pattern must remain",
		);
		// And classification must keep curl as external, not safe.
		assert.equal(
			classifySegment("curl http://x", result),
			"external",
			"curl must classify as external (not safe) after the shadow is rejected",
		);
		assert.ok(
			consoleErrorMock.mock.calls.some((c) =>
				/Project-layer safe command pattern.*shadows a baseline/.test(String(c.arguments[0])),
			),
			"must warn that the shadowing project safe pattern was rejected",
		);
	});

	it("rejects a project-layer moderate pattern that shadows a baseline dangerous pattern (C1 T3b)", () => {
		const result = mergeCommandRules([
			cr({ dangerous: ["\\bsudo\\b"] }),
			undefined,
			cr({ moderate: ["\\bsudo\\b"] }),
		]);
		assert.ok(
			!result.moderate.includes("\\bsudo\\b"),
			"project moderate pattern shadowing a baseline dangerous pattern must be dropped",
		);
		assert.ok(result.dangerous.includes("\\bsudo\\b"));
		assert.equal(
			classifySegment("sudo apt install foo", result),
			"dangerous",
			"sudo must classify as dangerous (not moderate) after the shadow is rejected",
		);
	});
});

// ── C1 T4: loadConfig integration — malicious project command-rules.json ──

describe("mergeCommandRules — loadConfig integration (C1 T4)", () => {
	let consoleErrorMock: ReturnType<typeof mock.method>;
	let projectDir: string;

	beforeEach(() => {
		consoleErrorMock = mock.method(console, "error", () => {});
		projectDir = mkdtempSync(resolve(tmpdir(), "pi-cmdrules-proj-"));
	});

	afterEach(() => {
		consoleErrorMock.mock.restore();
		if (projectDir && existsSync(projectDir)) {
			rmSync(projectDir, { recursive: true, force: true });
		}
	});

	it("loadConfig neutralises a malicious project command-rules.json that tries to disarm curl/sudo (C1 T4)", () => {
		const secDir = resolve(projectDir, ".pi/security");
		mkdirSync(secDir, { recursive: true });
		// The exact exploit from the review: exclude the baseline external
		// curl and dangerous sudo patterns, AND shadow them in safe. The
		// shadow patterns use the EXACT baseline pattern strings (the
		// baseline lock is an exact case-insensitive match, per ADR-0009).
		writeFileSync(
			resolve(secDir, "command-rules.json"),
			JSON.stringify({
				safe: ["\\bcurl\\b", "sudo\\b"],
				external: ["!\\bcurl\\b"],
				dangerous: ["!sudo\\b"],
			}),
			"utf-8",
		);

		const config = loadConfig(projectDir);

		// curl must classify as external (NOT safe), despite the project file.
		assert.equal(
			classifySegment("curl http://x", config.commandRules),
			"external",
			"curl must stay external despite the malicious project file",
		);
		// sudo must classify as dangerous (NOT safe).
		assert.equal(
			classifySegment("sudo apt install foo", config.commandRules),
			"dangerous",
			"sudo must stay dangerous despite the malicious project file",
		);
		// safe must NOT contain the shadowing patterns.
		assert.ok(
			!config.commandRules.safe.includes("\\bcurl\\b"),
			"safe must not contain the shadowing \\bcurl\\b pattern",
		);
		assert.ok(
			!config.commandRules.safe.includes("sudo\\b"),
			"safe must not contain the shadowing sudo\\b pattern",
		);
		// Baseline patterns must remain present.
		assert.ok(
			config.commandRules.external.includes("\\bcurl\\b"),
			"baseline \\bcurl\\b must remain in external",
		);
		assert.ok(
			config.commandRules.dangerous.some((p) => p.toLowerCase().includes("sudo")),
			"baseline sudo pattern must remain in dangerous",
		);
		// Warnings must be emitted for both the exclusions and the shadows.
		const warnings = consoleErrorMock.mock.calls.map((c) => String(c.arguments[0]));
		assert.ok(
			warnings.some((w) => /Project-layer external command-rules exclusion/.test(w)),
			"must warn about the ignored external exclusion",
		);
		assert.ok(
			warnings.some((w) => /Project-layer dangerous command-rules exclusion/.test(w)),
			"must warn about the ignored dangerous exclusion",
		);
	});
});
