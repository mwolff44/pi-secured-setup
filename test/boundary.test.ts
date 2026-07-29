/**
 * Unit tests for lib/boundary.ts
 */
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, symlinkSync, writeFileSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { evaluateBoundary } from "../lib/boundary.js";
import type { Config } from "../lib/config.js";

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

// ── ADR-0005: symlink resolution ──────────────────────────────────────
// Skipped on Windows where unprivileged symlink creation is unreliable.
const isWindows = process.platform === "win32";

describe("evaluateBoundary — symlink resolution (ADR-0005)", () => {
	// Per-test scratch directories, cleaned up after the suite.
	let cwdDir: string;
	let outsideDir: string;
	let allowedDir: string;

	before(() => {
		if (isWindows) return;
		cwdDir = mkdtempSync(join(tmpdir(), "pi-boundary-cwd-"));
		outsideDir = mkdtempSync(join(tmpdir(), "pi-boundary-outside-"));
		allowedDir = mkdtempSync(join(tmpdir(), "pi-boundary-allowed-"));
	});

	after(() => {
		if (isWindows) return;
		for (const d of [cwdDir, outsideDir, allowedDir]) {
			if (d && existsSync(d)) rmSync(d, { recursive: true, force: true });
		}
	});

	it("blocks write to a symlink inside cwd that points outside", { skip: isWindows }, () => {
		// `evil` lives inside cwd but resolves to outsideDir/secret.txt
		const symlinkPath = join(cwdDir, "evil");
		const target = join(outsideDir, "secret.txt");
		writeFileSync(target, "top-secret\n");
		symlinkSync(target, symlinkPath);

		const config = makeConfig({ cwd: cwdDir });
		const result = evaluateBoundary("write", { path: symlinkPath }, config);
		assert.equal(result.action, "block");
	});

	it("blocks edit to a symlink inside cwd that points outside", { skip: isWindows }, () => {
		const symlinkPath = join(cwdDir, "evil-edit");
		const target = join(outsideDir, "secret-edit.txt");
		writeFileSync(target, "top-secret\n");
		symlinkSync(target, symlinkPath);

		const config = makeConfig({ cwd: cwdDir });
		const result = evaluateBoundary("edit", { path: symlinkPath }, config);
		assert.equal(result.action, "block");
	});

	it("confirms read of a symlink inside cwd that points outside", { skip: isWindows }, () => {
		const symlinkPath = join(cwdDir, "evil-read");
		const target = join(outsideDir, "secret-read.txt");
		writeFileSync(target, "top-secret\n");
		symlinkSync(target, symlinkPath);

		const config = makeConfig({ cwd: cwdDir });
		const result = evaluateBoundary("read", { path: symlinkPath }, config);
		assert.equal(result.action, "confirm");
	});

	it("blocks write to a broken symlink inside cwd (fail-closed)", { skip: isWindows }, () => {
		const symlinkPath = join(cwdDir, "broken-write");
		// Target deliberately does not exist → broken symlink.
		symlinkSync(join(outsideDir, "nonexistent-target"), symlinkPath);

		const config = makeConfig({ cwd: cwdDir });
		const result = evaluateBoundary("write", { path: symlinkPath }, config);
		assert.equal(result.action, "block");
	});

	it("blocks edit to a broken symlink inside cwd (fail-closed)", { skip: isWindows }, () => {
		const symlinkPath = join(cwdDir, "broken-edit");
		symlinkSync(join(outsideDir, "nonexistent-target-edit"), symlinkPath);

		const config = makeConfig({ cwd: cwdDir });
		const result = evaluateBoundary("edit", { path: symlinkPath }, config);
		assert.equal(result.action, "block");
	});

	it("confirms read of a broken symlink inside cwd (fail-closed)", { skip: isWindows }, () => {
		const symlinkPath = join(cwdDir, "broken-read");
		symlinkSync(join(outsideDir, "nonexistent-target-read"), symlinkPath);

		const config = makeConfig({ cwd: cwdDir });
		const result = evaluateBoundary("read", { path: symlinkPath }, config);
		assert.equal(result.action, "confirm");
	});

	it("allows write to a regular file inside cwd (happy path, no regression)", { skip: isWindows }, () => {
		const filePath = join(cwdDir, "normal.txt");
		writeFileSync(filePath, "ok\n");

		const config = makeConfig({ cwd: cwdDir });
		const result = evaluateBoundary("write", { path: filePath }, config);
		assert.equal(result.action, "allow");
	});

	it("allows read of a regular file inside cwd (happy path, no regression)", { skip: isWindows }, () => {
		const filePath = join(cwdDir, "normal-read.txt");
		writeFileSync(filePath, "ok\n");

		const config = makeConfig({ cwd: cwdDir });
		const result = evaluateBoundary("read", { path: filePath }, config);
		assert.equal(result.action, "allow");
	});

	it("allows write to a not-yet-existing file inside cwd (new-file target)", { skip: isWindows }, () => {
		// A write target for a file that does not exist yet must still evaluate
		// lexically as inside the boundary (preserves existing semantics).
		const filePath = join(cwdDir, "brand-new.txt");

		const config = makeConfig({ cwd: cwdDir });
		const result = evaluateBoundary("write", { path: filePath }, config);
		assert.equal(result.action, "allow");
	});

	it("allows access through a real allowedExternal directory after realpath resolution", { skip: isWindows }, () => {
		// Create a nested directory under allowedDir so we exercise the
		// isInsideDir comparison against the resolved realpath.
		const nested = join(allowedDir, "nested");
		mkdirSync(nested, { recursive: true });
		const filePath = join(nested, "data.txt");
		writeFileSync(filePath, "ok\n");

		const config = makeConfig({
			cwd: cwdDir,
			allowedExternal: { paths: [allowedDir] },
		});
		const readResult = evaluateBoundary("read", { path: filePath }, config);
		assert.equal(readResult.action, "allow");

		const writeResult = evaluateBoundary("write", { path: filePath }, config);
		assert.equal(writeResult.action, "allow");
	});

	it("detects a symlink whose target escapes cwd even when allowedExternal lists cwd itself", { skip: isWindows }, () => {
		// Sanity: an allowed-external entry equal to cwd must not cause an
		// escaping symlink to be allowed. The symlink resolves outside cwd,
		// and outside the (equal) allowed entry too.
		const symlinkPath = join(cwdDir, "evil-allowed-check");
		const target = join(outsideDir, "escape-via-allowed.txt");
		writeFileSync(target, "top-secret\n");
		symlinkSync(target, symlinkPath);

		const config = makeConfig({
			cwd: cwdDir,
			allowedExternal: { paths: [cwdDir] },
		});
		const result = evaluateBoundary("write", { path: symlinkPath }, config);
		assert.equal(result.action, "block");
	});
});
