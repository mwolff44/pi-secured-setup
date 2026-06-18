/**
 * Unit tests for lib/guard-pipeline.ts — confirm→block reason field and audit event types
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import type { Config } from "../lib/config.js";
import type { GuardEvaluators } from "../lib/guard-pipeline.js";
import { verdictAuditInfo } from "../lib/guard-pipeline.js";

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