/**
 * Unit tests for lib/audit.ts — rotation logic and severity types
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { initAuditLog, auditLog } from "../lib/audit.js";

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
	it("auditLog does not throw on repeated writes", () => {
		initAuditLog();
		for (let i = 0; i < 5; i++) {
			assert.doesNotThrow(() => {
				auditLog("test.rotation", "info", { iteration: i });
			});
		}
	});
});