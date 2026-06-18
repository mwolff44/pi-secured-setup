/**
 * Unit tests for lib/boundary.ts
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { evaluateBoundary } from "../lib/boundary.js";
import type { Config } from "../lib/config.js";

function makeConfig(overrides: Partial<Config> = {}): Config {
	return {
		cwd: "/home/user/project",
		protectedPaths: { patterns: [], writeAction: "block", readAction: "confirm" },
		commandRules: { safe: [], moderate: [], dangerous: [], external: [] },
		allowedExternal: { paths: [] },
		audit: { maxFileSize: 10_000_000, maxFiles: 3 },
		...overrides,
	};
}

describe("evaluateBoundary", () => {
	it("allows bash commands (ADR-0003)", () => {
		const config = makeConfig();
		const result = evaluateBoundary("bash", { command: "rm -rf /" }, config);
		assert.equal(result.action, "allow");
	});

	it("allows unknown tool names", () => {
		const config = makeConfig();
		const result = evaluateBoundary("grep", { pattern: "foo", path: "/home/user/project/file.ts" }, config);
		assert.equal(result.action, "allow");
	});

	it("allows read inside boundary", () => {
		const config = makeConfig();
		const result = evaluateBoundary("read", { path: "src/file.ts" }, config);
		assert.equal(result.action, "allow");
	});

	it("allows write inside boundary", () => {
		const config = makeConfig();
		const result = evaluateBoundary("write", { path: "src/file.ts" }, config);
		assert.equal(result.action, "allow");
	});

	it("blocks write outside boundary", () => {
		const config = makeConfig();
		const result = evaluateBoundary("write", { path: "/home/user/other-project/file.ts" }, config);
		assert.equal(result.action, "block");
	});

	it("blocks edit outside boundary", () => {
		const config = makeConfig();
		const result = evaluateBoundary("edit", { path: "/home/user/other-project/file.ts" }, config);
		assert.equal(result.action, "block");
	});

	it("confirms read outside boundary", () => {
		const config = makeConfig();
		const result = evaluateBoundary("read", { path: "/home/user/other-project/file.ts" }, config);
		assert.equal(result.action, "confirm");
	});

	it("allows read outside boundary if in allowed-external", () => {
		const config = makeConfig({
			allowedExternal: { paths: ["/tmp"] },
		});
		const result = evaluateBoundary("read", { path: "/tmp/cache.txt" }, config);
		assert.equal(result.action, "allow");
	});

	it("allows write outside boundary if in allowed-external", () => {
		const config = makeConfig({
			allowedExternal: { paths: ["/tmp"] },
		});
		const result = evaluateBoundary("write", { path: "/tmp/output.txt" }, config);
		assert.equal(result.action, "allow");
	});

	it("allows ~ paths in allowed-external", () => {
		const config = makeConfig({
			allowedExternal: { paths: ["~/.agents/skills"] },
		});
		const home = process.env.HOME || "/home/user";
		const result = evaluateBoundary("read", { path: `${home}/.agents/skills/my-skill/SKILL.md` }, config);
		assert.equal(result.action, "allow");
	});

	it("returns allow when path is missing", () => {
		const config = makeConfig();
		const result = evaluateBoundary("read", {}, config);
		assert.equal(result.action, "allow");
	});

	it("handles uppercase tool name 'Read' same as 'read'", () => {
		const config = makeConfig();
		const result = evaluateBoundary("Read", { path: "/home/user/other-project/file.ts" }, config);
		assert.equal(result.action, "confirm");
	});

	it("handles uppercase tool name 'WRITE' same as 'write'", () => {
		const config = makeConfig();
		const result = evaluateBoundary("WRITE", { path: "/home/user/other-project/file.ts" }, config);
		assert.equal(result.action, "block");
	});
});
