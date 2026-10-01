/**
 * Unit tests for lib/utils.ts
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import {
	expandTilde,
	resolvePath,
	isInsideDir,
	isInsideDirWith,
	sha256,
	generateSessionId,
} from "../lib/utils.js";

describe("expandTilde", () => {
	it("expands ~/ to home directory", () => {
		const result = expandTilde("~/foo/bar");
		assert.ok(!result.startsWith("~"), `should not start with ~: ${result}`);
		assert.ok(result.endsWith("/foo/bar"), `should end with /foo/bar: ${result}`);
	});

	it("expands bare ~ to home directory", () => {
		const result = expandTilde("~");
		assert.ok(!result.includes("~"), `should not contain ~: ${result}`);
	});

	it("leaves absolute paths unchanged", () => {
		assert.equal(expandTilde("/tmp/foo"), "/tmp/foo");
	});

	it("leaves relative paths unchanged", () => {
		assert.equal(expandTilde("foo/bar"), "foo/bar");
	});
});

describe("resolvePath", () => {
	it("resolves relative paths against base", () => {
		const result = resolvePath("/home/user/project", "src/file.ts");
		assert.equal(result, "/home/user/project/src/file.ts");
	});

	it("expands tilde paths", () => {
		const result = resolvePath("/home/user/project", "~/secret");
		assert.ok(!result.includes("~"), `should not contain ~: ${result}`);
		assert.ok(result.endsWith("/secret"), `should end with /secret: ${result}`);
	});

	it("leaves absolute paths as-is (normalized)", () => {
		const result = resolvePath("/home/user/project", "/tmp/foo");
		assert.equal(result, "/tmp/foo");
	});
});

describe("isInsideDir", () => {
	it("file inside parent is true", () => {
		assert.equal(isInsideDir("/home/user/project", "/home/user/project/src/file.ts"), true);
	});

	it("exact match is true", () => {
		assert.equal(isInsideDir("/home/user/project", "/home/user/project"), true);
	});

	it("sibling directory is false", () => {
		assert.equal(isInsideDir("/home/user/project-a", "/home/user/project-b/file.ts"), false);
	});

	it("parent directory is false", () => {
		assert.equal(isInsideDir("/home/user/project", "/home/user"), false);
	});

	it("completely different path is false", () => {
		assert.equal(isInsideDir("/home/user/project", "/tmp/foo"), false);
	});

	it("sibling with shared prefix is false", () => {
		assert.equal(isInsideDir("/home/user/project", "/home/user/project-b/file.ts"), false);
	});
});

describe("isInsideDirWith — Windows paths", () => {
	const win = path.win32;

	it("file inside parent is true", () => {
		assert.equal(isInsideDirWith(win, "C:\\Users\\me\\proj", "C:\\Users\\me\\proj\\src\\a.ts"), true);
	});

	it("exact match is true", () => {
		assert.equal(isInsideDirWith(win, "C:\\Users\\me\\proj", "C:\\Users\\me\\proj"), true);
	});

	it("drive letter and folder case are ignored", () => {
		assert.equal(isInsideDirWith(win, "C:\\Users\\me\\proj", "c:\\users\\ME\\Proj\\a.ts"), true);
	});

	it("forward slashes are accepted", () => {
		assert.equal(isInsideDirWith(win, "C:\\Users\\me\\proj", "C:/Users/me/proj/a.ts"), true);
	});

	it("sibling with shared prefix is false", () => {
		assert.equal(isInsideDirWith(win, "C:\\Users\\me\\proj", "C:\\Users\\me\\proj-b\\a.ts"), false);
	});

	it("parent directory is false", () => {
		assert.equal(isInsideDirWith(win, "C:\\Users\\me\\proj", "C:\\Users\\me"), false);
	});

	it("other drive is false", () => {
		assert.equal(isInsideDirWith(win, "C:\\Users\\me\\proj", "D:\\proj\\a.ts"), false);
	});

	it("traversal out of the parent is false", () => {
		assert.equal(isInsideDirWith(win, "C:\\Users\\me\\proj", "C:\\Users\\me\\proj\\..\\other\\a.ts"), false);
	});
});

describe("sha256", () => {
	it("produces a consistent hex digest", () => {
		const hash = sha256("hello world");
		assert.equal(hash, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
	});

	it("different inputs produce different hashes", () => {
		assert.notEqual(sha256("foo"), sha256("bar"));
	});
});

describe("generateSessionId", () => {
	it("returns unique session IDs", () => {
		const id1 = generateSessionId();
		const id2 = generateSessionId();
		assert.notEqual(id1, id2);
	});

	it("includes a crypto-random hex segment", () => {
		const id = generateSessionId();
		const parts = id.split("-");
		assert.ok(parts.length >= 2, "session ID should have at least 2 parts");
		assert.ok(parts[1].length === 8, "random segment should be 8 hex chars");
		assert.ok(/^[0-9a-f]{8}$/.test(parts[1]), "random segment should be hex");
	});
});
