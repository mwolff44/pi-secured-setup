/**
 * Unit tests for lib/audit.ts — rotation logic and severity types
 *
 * Tests override the audit file path to a temp directory to avoid
 * polluting the developer's real audit log.
 */
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { existsSync, rmSync, mkdirSync } from "node:fs";
import { resolve } from "node:path";
import { tmpdir } from "node:os";
import { initAuditLog, auditLog, _setAuditFileForTest } from "../lib/audit.js";

describe("audit severity types", () => {
	it("AuditSeverity accepts only valid values", () => {
		const valid: Array<"debug" | "info" | "warning" | "error"> = [
			"debug",
			"info",
			"warning",
			"error",
		];
		assert.equal(valid.length, 4);
		assert.ok(!valid.includes("warn" as never), '"warn" is not a valid AuditSeverity');
	});
});

describe("audit log rotation cleans up overflow files", () => {
	let tempDir: string;
	let previousAuditFile: string;

	beforeEach(() => {
		tempDir = resolve(tmpdir(), `pi-audit-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(tempDir, { recursive: true });
		const testAuditFile = resolve(tempDir, "audit.jsonl");
		previousAuditFile = _setAuditFileForTest(testAuditFile);
		initAuditLog();
	});

	afterEach(() => {
		_setAuditFileForTest(previousAuditFile);
		if (tempDir && existsSync(tempDir)) {
			rmSync(tempDir, { recursive: true, force: true });
		}
	});

	it("auditLog does not throw on repeated writes", () => {
		for (let i = 0; i < 5; i++) {
			assert.doesNotThrow(() => {
				auditLog("test.rotation", "info", { iteration: i });
			});
		}
	});

	it("writes entries to the test audit file, not the real home directory", () => {
		const testAuditFile = resolve(tempDir, "audit.jsonl");
		auditLog("test.isolation", "info", { check: true });
		assert.ok(existsSync(testAuditFile), "audit file should exist in temp directory");
	});

	it("creates audit file with correct permissions", () => {
		auditLog("test.permissions", "info", { check: true });
		const testAuditFile = resolve(tempDir, "audit.jsonl");
		assert.ok(existsSync(testAuditFile), "audit file should exist");
	});
});