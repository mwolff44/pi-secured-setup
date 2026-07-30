/**
 * Unit tests for lib/protected-paths.ts
 */
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, symlinkSync, writeFileSync, rmSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import { tmpdir } from "node:os";
import { evaluateProtectedPaths, matchGlob } from "../lib/protected-paths.js";
import type { Config } from "../lib/config.js";

function makeConfig(overrides: Partial<Config> = {}): Config {
	return {
		cwd: "/home/user/project",
		protectedPaths: {
			patterns: [".env", ".env.*", "*.key", "*.pem", "*secret*", "*credential*"],
			writeAction: "block",
			readAction: "confirm",
		},
		commandRules: { safe: [], moderate: [], dangerous: [], external: [] },
		allowedExternal: { paths: [] },
		audit: { maxFileSize: 10_000_000, maxFiles: 3 },
		injection: { patterns: [], threshold: 3 },
		...overrides,
	};
}

describe("matchGlob", () => {
	it("matches exact filename", () => {
		assert.equal(matchGlob(".env", "/home/user/project/.env"), true);
	});

	it("matches * wildcard", () => {
		assert.equal(matchGlob("*.key", "/home/user/project/server.key"), true);
	});

	it("matches * in middle", () => {
		assert.equal(matchGlob("*secret*", "/home/user/project/my-secret-config.yaml"), true);
	});

	it("matches .env.* pattern", () => {
		assert.equal(matchGlob(".env.*", "/home/user/project/.env.local"), true);
	});

	it("does not match unrelated files", () => {
		assert.equal(matchGlob("*.key", "/home/user/project/keyboard.ts"), false);
	});

	it("does not match when pattern is more specific than path", () => {
		assert.equal(matchGlob(".env", "/home/user/project/.envrc"), false);
	});

	it("matches basename when full path doesn't match", () => {
		assert.equal(matchGlob("*.key", "server.key"), true);
	});

	it("rejects patterns longer than 256 characters", () => {
		const longPattern = "a".repeat(257);
		assert.equal(matchGlob(longPattern, "anything"), false);
	});

	it("rejects patterns with more than 8 globstar segments", () => {
		const pattern = "**/**/**/**/**/**/**/**/**/*.env";
		assert.equal(matchGlob(pattern, "/deep/nested/path/.env"), false);
	});

	it("rejects patterns with too many single-star wildcards (ReDoS protection)", () => {
		const pattern = "*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*.txt";
		assert.equal(matchGlob(pattern, "some/path.txt"), false);
	});

	it("does not hang on adversarial glob patterns", () => {
		const start = Date.now();
		matchGlob("*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*.txt", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
		const elapsed = Date.now() - start;
		assert.ok(elapsed < 500, `adversarial pattern took ${elapsed}ms, should be < 500ms`);
	});
});

describe("evaluateProtectedPaths", () => {
	it("allows bash (not applicable)", () => {
		const config = makeConfig();
		const result = evaluateProtectedPaths("bash", { command: "cat .env" }, config);
		assert.equal(result.action, "allow");
	});

	it("allows unknown tool names", () => {
		const config = makeConfig();
		const result = evaluateProtectedPaths("grep", { pattern: "foo" }, config);
		assert.equal(result.action, "allow");
	});

	it("blocks write to .env", () => {
		const config = makeConfig();
		const result = evaluateProtectedPaths("write", { path: ".env" }, config);
		assert.equal(result.action, "block");
	});

	it("blocks write to .env.local", () => {
		const config = makeConfig();
		const result = evaluateProtectedPaths("write", { path: ".env.production" }, config);
		assert.equal(result.action, "block");
	});

	it("blocks write to *.key file", () => {
		const config = makeConfig();
		const result = evaluateProtectedPaths("write", { path: "server.key" }, config);
		assert.equal(result.action, "block");
	});

	it("blocks edit to protected path", () => {
		const config = makeConfig();
		const result = evaluateProtectedPaths("edit", { path: ".env" }, config);
		assert.equal(result.action, "block");
	});

	it("confirms read from .env (default readAction)", () => {
		const config = makeConfig();
		const result = evaluateProtectedPaths("read", { path: ".env" }, config);
		assert.equal(result.action, "confirm");
	});

	it("allows read when readAction is allow", () => {
		const config = makeConfig({
			protectedPaths: {
				patterns: [".env"],
				writeAction: "block",
				readAction: "allow",
			},
		});
		const result = evaluateProtectedPaths("read", { path: ".env" }, config);
		assert.equal(result.action, "allow");
	});

	it("blocks read when readAction is block", () => {
		const config = makeConfig({
			protectedPaths: {
				patterns: [".env"],
				writeAction: "block",
				readAction: "block",
			},
		});
		const result = evaluateProtectedPaths("read", { path: ".env" }, config);
		assert.equal(result.action, "block");
	});

	it("allows write to non-protected file", () => {
		const config = makeConfig();
		const result = evaluateProtectedPaths("write", { path: "src/index.ts" }, config);
		assert.equal(result.action, "allow");
	});

	it("matches *secret* pattern", () => {
		const config = makeConfig();
		const result = evaluateProtectedPaths("write", { path: "config/secret-key.yaml" }, config);
		assert.equal(result.action, "block");
	});

	it("returns allow when path is missing", () => {
		const config = makeConfig();
		const result = evaluateProtectedPaths("read", {}, config);
		assert.equal(result.action, "allow");
	});

	it("handles uppercase tool name 'Read' same as 'read'", () => {
		const config = makeConfig();
		const result = evaluateProtectedPaths("Read", { path: ".env" }, config);
		assert.equal(result.action, "confirm");
	});

	it("handles uppercase tool name 'WRITE' same as 'write'", () => {
		const config = makeConfig();
		const result = evaluateProtectedPaths("WRITE", { path: ".env" }, config);
		assert.equal(result.action, "block");
	});
});

// ── M1 (Weft): symlink real-target matching ───────────────────────────
//
// `evaluateProtectedPaths` previously matched only the lexical path, so an
// in-boundary symlink whose real target (outside the boundary, or matching
// a protected pattern by its real name) was not caught. Defense-in-depth:
// resolve the real target and match patterns against BOTH the lexical and
// real paths.

describe("evaluateProtectedPaths — symlink real-target matching (M1 Weft)", () => {
	let boundary: string;
	let outside: string;

	beforeEach(() => {
		boundary = mkdtempSync(resolve(tmpdir(), "pi-pp-boundary-"));
		outside = mkdtempSync(resolve(tmpdir(), "pi-pp-outside-"));
	});

	afterEach(() => {
		if (boundary && existsSync(boundary)) rmSync(boundary, { recursive: true, force: true });
		if (outside && existsSync(outside)) rmSync(outside, { recursive: true, force: true });
	});

	function cfg(patterns: string[], readAction: "confirm" | "block" | "allow" = "confirm"): Config {
		return {
			cwd: boundary,
			protectedPaths: { patterns, writeAction: "block", readAction },
			commandRules: { safe: [], moderate: [], dangerous: [], external: [] },
			allowedExternal: { paths: [] },
			audit: { maxFileSize: 10_000_000, maxFiles: 3 },
			injection: { patterns: [], threshold: 3 },
		};
	}

	it("matches a symlink whose real target matches a protected pattern (M1 T10)", () => {
		// secrets.env lives OUTSIDE the boundary; an in-boundary symlink points at it.
		const realTarget = resolve(outside, "secrets.env");
		writeFileSync(realTarget, "SECRET=shhh", "utf-8");
		const linkPath = resolve(boundary, "link");
		symlinkSync(realTarget, linkPath);
		assert.ok(existsSync(linkPath), "precondition: symlink exists");

		const config = cfg(["*.env"], "confirm");

		// Reading the in-boundary symlink via a relative path must be caught
		// because its REAL target basename is `secrets.env` (matches `*.env`).
		const result = evaluateProtectedPaths("read", { path: "./link" }, config);
		assert.notEqual(
			result.action,
			"allow",
			`reading an in-boundary symlink to a protected real target must confirm/block, got allow`,
		);
		assert.ok(
			result.action === "confirm" || result.action === "block",
			`expected confirm or block, got ${result.action}`,
		);
	});

	it("matches a symlink whose real target matches a pattern the lexical name does not (M1 T10b)", () => {
		// The symlink's lexical name is `link` (no protected extension); the
		// real target is `id_rsa` inside a `.ssh` dir outside the boundary.
		const realSshDir = resolve(outside, ".ssh");
		mkdirSync(realSshDir, { recursive: true });
		const realTarget = resolve(realSshDir, "id_rsa");
		writeFileSync(realTarget, "key", "utf-8");
		const linkPath = resolve(boundary, "link");
		symlinkSync(realTarget, linkPath);

		const config = cfg(["*id_rsa*"], "confirm");

		const result = evaluateProtectedPaths("read", { path: "./link" }, config);
		assert.notEqual(
			result.action,
			"allow",
			"symlink whose real target matches the protected pattern must be caught",
		);
	});

	it("blocks write to an in-boundary symlink pointing at a protected real target (M1 T10c)", () => {
		const realTarget = resolve(outside, "secrets.env");
		writeFileSync(realTarget, "SECRET=shhh", "utf-8");
		const linkPath = resolve(boundary, "link");
		symlinkSync(realTarget, linkPath);

		const config = cfg(["*.env"]);

		const result = evaluateProtectedPaths("write", { path: "./link" }, config);
		assert.equal(result.action, "block", "write via symlink to protected real target must block");
	});
});
