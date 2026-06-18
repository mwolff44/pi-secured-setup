/**
 * Guard pipeline orchestrator — single combined `tool_call` handler.
 *
 * ADR-0001: All three Guard modules (boundary, protected-paths, bash-gate)
 * are evaluated by a single handler in fixed order. First block wins.
 * No short-circuit past a confirmation.
 *
 * Pipeline order:
 *   1. Boundary evaluation (read/write/edit only)
 *   2. Protected paths evaluation (read/write/edit only)
 *   3. Bash command classification (bash only)
 */
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import type { Config } from "./config.js";
import type { GuardVerdict } from "./boundary.js";
import { evaluateBoundary } from "./boundary.js";
import { evaluateProtectedPaths } from "./protected-paths.js";
import { classifyCommand } from "./bash-gate.js";
import { auditLog, type AuditSeverity } from "./audit.js";
import { redactString } from "./secret-scanner.js";

/**
 * The audit event type prefix and severity for each verdict.
 */
export function verdictAuditInfo(
	guard: string,
	verdict: GuardVerdict & { category?: string },
): { type: string; severity: AuditSeverity } {
	const action = verdict.action;

	if (action === "allow" && "category" in verdict && verdict.category) {
		// Bash auto-approve categories
		return {
			type: `bash.${verdict.category}`,
			severity: verdict.category === "moderate" ? "info" : "debug",
		};
	}

	if (action === "allow") {
		return { type: `${guard}.allow`, severity: "debug" };
	}
	if (action === "block") {
		return { type: `${guard}.block`, severity: "warning" };
	}
	// confirm
	return { type: `${guard}.confirm`, severity: "info" };
}

/**
 * Guard evaluator functions injected from the entry point.
 * Each is a pure function for independent testability.
 */
export interface GuardEvaluators {
	evaluateBoundary: typeof evaluateBoundary;
	evaluateProtectedPaths: typeof evaluateProtectedPaths;
	classifyCommand: typeof classifyCommand;
}

/**
 * Register the single combined guard pipeline on the pi extension API.
 *
 * @param pi         — Extension API
 * @param getConfig  — Function returning the current (reloadable) config
 * @param guards     — Pure evaluator functions
 */
export function registerGuardPipeline(
	pi: ExtensionAPI,
	getConfig: () => Config,
	guards: GuardEvaluators,
): void {
	pi.on("tool_call", async (event, ctx) => {
		const config = getConfig();
		const toolName = (event.toolName as string).toLowerCase();
		const input = event.input as Record<string, unknown>;

		// ── Step 1: Boundary ────────────────────────────────────────
		const boundaryVerdict = guards.evaluateBoundary(toolName, input, config);

		if (boundaryVerdict.action === "block") {
			const { type, severity } = verdictAuditInfo("boundary", boundaryVerdict);
			auditLog(type, severity, {
				tool: toolName,
				path: input.path ?? "",
				boundary: config.cwd,
				reason: boundaryVerdict.reason,
			});

			if (ctx.hasUI) {
				ctx.ui.notify(`🚫 Blocked: ${boundaryVerdict.reason}`, "warning");
			}
			return { block: true, reason: boundaryVerdict.reason };
		}

		if (boundaryVerdict.action === "confirm") {
			if (!ctx.hasUI) {
				auditLog("boundary.block", "warning", {
					tool: toolName,
					path: input.path ?? "",
					boundary: config.cwd,
					reason: "blocked (no UI for confirmation)",
				});
				return { block: true, reason: boundaryVerdict.message };
			}

			const approved = await ctx.ui.confirm("🔒 Boundary Check", boundaryVerdict.message);
			if (!approved) {
				auditLog("boundary.block", "warning", {
					tool: toolName,
					path: input.path ?? "",
					boundary: config.cwd,
					reason: "user denied",
				});
				return { block: true, reason: `User denied: outside boundary` };
			}

			auditLog("boundary.confirm", "info", {
				tool: toolName,
				path: input.path ?? "",
				boundary: config.cwd,
			});
		}

		// ── Step 2: Protected Paths ─────────────────────────────────
		const protectedVerdict = guards.evaluateProtectedPaths(toolName, input, config);

		if (protectedVerdict.action === "block") {
			const { type, severity } = verdictAuditInfo("protected", protectedVerdict);
			auditLog(type, severity, {
				tool: toolName,
				path: input.path ?? "",
				reason: protectedVerdict.reason,
			});

			if (ctx.hasUI) {
				ctx.ui.notify(`🚫 Blocked: ${protectedVerdict.reason}`, "warning");
			}
			return { block: true, reason: protectedVerdict.reason };
		}

		if (protectedVerdict.action === "confirm") {
			if (!ctx.hasUI) {
				auditLog("protected.block", "warning", {
					tool: toolName,
					path: input.path ?? "",
					reason: "blocked (no UI for confirmation)",
				});
				return { block: true, reason: protectedVerdict.message };
			}

			const approved = await ctx.ui.confirm("🔒 Protected Path", protectedVerdict.message);
			if (!approved) {
				auditLog("protected.block", "warning", {
					tool: toolName,
					path: input.path ?? "",
					reason: "user denied",
				});
				return { block: true, reason: `User denied: protected path` };
			}

			auditLog("protected.confirm", "info", {
				tool: toolName,
				path: input.path ?? "",
			});
		}

		// ── Step 3: Bash Gate (bash tool only) ──────────────────────
		if (toolName === "bash") {
			const command = input.command as string | undefined;
			if (!command) return undefined;

			const safeCommand = redactString(command, { skipCommentLines: false }).result;
			const bashVerdict = guards.classifyCommand(command, config);

			// Auto-approve safe and moderate
			if (bashVerdict.action === "allow") {
				const { type, severity } = verdictAuditInfo("bash", bashVerdict);
				auditLog(type, severity, {
					tool: "bash",
					command: safeCommand,
					category: bashVerdict.category ?? "unknown",
				});
				return undefined; // pass through
			}

			// Confirm dangerous, external, and unknown commands
			if (bashVerdict.action === "confirm") {
				if (!ctx.hasUI) {
					const category = bashVerdict.category ?? "unknown";
					auditLog(`bash.${category}.block`, "warning", {
						tool: "bash",
						command: safeCommand,
						category,
						reason: "blocked (no UI for confirmation)",
					});
					return { block: true, reason: `${category.charAt(0).toUpperCase() + category.slice(1)} command blocked (no UI)` };
				}

				const approved = await ctx.ui.confirm("🔒 Bash Command", bashVerdict.message);
				const category = bashVerdict.category ?? "unknown";

				if (!approved) {
					auditLog(`bash.${category}.block`, "warning", {
						tool: "bash",
						command: safeCommand,
						category,
						reason: "user denied",
					});
					return { block: true, reason: `User denied: ${category} command` };
				}

				auditLog(`bash.${category}.confirm`, "info", {
					tool: "bash",
					command: safeCommand,
					category,
				});
			}
		}

		// All checks passed
		return undefined;
	});
}
