/**
 * Unit tests for lib/protected-paths.ts
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
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
		assert.ok(elapsed < 100, `adversarial pattern took ${elapsed}ms, should be < 100ms`);
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
