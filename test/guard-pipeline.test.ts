/**
 * Unit tests for lib/guard-pipeline.ts — confirm→block reason field
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import type { Config } from "../lib/config.js";
import type { GuardEvaluators } from "../lib/guard-pipeline.js";

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