/**
 * Unit tests for lib/config.ts — merge logic
 */
import { describe, it, beforeEach, afterEach, mock } from "node:test";
import assert from "node:assert/strict";
import { mergePatterns, mergeProtectedPaths, mergeCommandRules } from "../lib/config.js";
import type { ProtectedPathsConfig, CommandRulesConfig } from "../lib/config.js";

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
});
