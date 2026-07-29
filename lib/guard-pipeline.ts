/**
 * Guard pipeline orchestrator — single combined `tool_call` handler.
 *
 * ADR-0001: All three Guard modules (boundary, protected-paths, bash-gate)
 * are evaluated by a single handler in fixed order. First block wins.
 * No short-circuit past a confirmation.
 *
 * Pipeline order:
 *   0. Input shape validation (read/write/edit/bash) — QW-4
 *   1. Boundary evaluation (read/write/edit only)
 *   2. Protected paths evaluation (read/write/edit only)
 *   3. Bash command classification (bash only)
 */
import type { ExtensionAPI, ExtensionUIContext } from "@earendil-works/pi-coding-agent";
import { DEFAULT_SECURITY_POLICY, type Config } from "./config.js";
import type { GuardVerdict } from "./boundary.js";
import { evaluateBoundary } from "./boundary.js";
import { evaluateProtectedPaths } from "./protected-paths.js";
import { classifyCommand, detectExfiltration } from "./bash-gate.js";
import { auditLog, type AuditSeverity } from "./audit.js";
import { redactString } from "./secret-scanner.js";
import { checkLimit, resetTurn, type SecurityLimits } from "./rate-limiter.js";

/**
 * Required input fields per tool name. Tools not listed here have no
 * schema requirement and pass through input validation. Keys are matched
 * against the lowercased tool name.
 */
const REQUIRED_INPUT_FIELDS: Record<string, readonly string[]> = {
	bash: ["command"],
	read: ["path"],
	write: ["path"],
	edit: ["path"],
};

/**
 * Pre-validate the shape of `input` for a given tool before any other
 * guard runs. Runs as Step 0 of the pipeline (QW-4).
 *
 * Fail-closed: any malformed input for a known tool blocks execution.
 * A field is considered missing when it is absent, not a string, or
 * an empty string.
 *
 * @param toolName — already-lowercased tool name
 * @param input    — raw `event.input` value (may be any shape)
 * @returns `null` when input is well-formed (or the tool has no schema
 *          requirement); a `block` verdict otherwise.
 */
export function validateToolInput(
	toolName: string,
	input: unknown,
): { action: "block"; reason: string } | null {
	const required = REQUIRED_INPUT_FIELDS[toolName];
	if (!required) return null; // no schema requirement for this tool

	if (typeof input !== "object" || input === null) {
		return {
			action: "block",
			reason: `missing required input.${required[0]}`,
		};
	}

	const record = input as Record<string, unknown>;
	for (const field of required) {
		const value = record[field];
		if (typeof value !== "string" || value.length === 0) {
			return {
				action: "block",
				reason: `missing required input.${field}`,
			};
		}
	}
	return null;
}

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
 * Minimal ctx shape used by the pipeline helpers (structural — the
 * real pi `ExtensionContext` satisfies this). Only the fields the
 * pipeline actually reads are typed, so unit tests can construct cheap
 * mocks.
 */
interface PipelineCtx {
	/** Whether dialog-capable UI is available (true in TUI and RPC modes). */
	hasUI: boolean;
	/**
	 * Current pi run mode. Pi versions before 0.78.1 do not set this
	 * field; `undefined` triggers the backward-compat fallback in
	 * {@link canShowDialog}.
	 */
	mode?: PiMode;
	/**
	 * Subset of the real pi {@link ExtensionUIContext}. Using `Pick`
	 * rather than mirroring signatures keeps the local interface
	 * assignable from a real `ExtensionContext` (R6: strict mode +
	 * strictFunctionTypes require the narrowed `notify` severity union
	 * to match the upstream type, not a bare `string`).
	 */
	ui: Pick<ExtensionUIContext, "notify" | "confirm">;
}

/**
 * Backward-compatible alias kept for any external callers; new code
 * should use {@link PipelineCtx}.
 */
type NotifyCtx = PipelineCtx;

/**
 * The set of pi run modes. Mirrors the unexported `ExtensionMode` from
 * `@earendil-works/pi-coding-agent` (not part of the package's public
 * type surface). Only `"tui"` can render blocking interactive dialogs
 * (`ctx.ui.confirm`, `ctx.ui.select`); in `"rpc"`, `"json"`, and
 * `"print"` modes such a dialog would hang the agent or fail silently.
 *
 * Keep these literal values in sync with the upstream type.
 */
type PiMode = "tui" | "rpc" | "json" | "print";

/**
 * Read `ctx.mode` defensively. Returns `undefined` for pi versions
 * older than 0.78.1, which do not populate the field even though the
 * current type declaration marks it as required.
 */
function modeOf(ctx: { mode?: PiMode }): PiMode | undefined {
	return ctx.mode;
}

/**
 * Decide whether an interactive (blocking) dialog can be shown for the
 * current tool call.
 *
 * Returns `true` only when:
 *   - `ctx.mode === "tui"` — the only mode where `ctx.ui.confirm` /
 *     `ctx.ui.select` can actually render, OR
 *   - `ctx.mode` is `undefined` AND `ctx.hasUI === true` — older pi
 *     versions without the `mode` field fall back to the legacy gate
 *     for backward compatibility.
 *
 * In all other cases — `"rpc"`, `"json"`, `"print"`, or any future
 * non-TUI mode — interactive dialogs would hang or fail silently, so
 * the caller must fail closed (block with an explicit reason).
 *
 * Note that `hasUI` is `true` in BOTH TUI and RPC modes (see
 * `ExtensionContext.hasUI`), so the legacy `!hasUI` check alone is
 * insufficient to detect non-interactive contexts — that is exactly
 * the gap this helper closes (P3-1).
 */
function canShowDialog(ctx: PipelineCtx): boolean {
	const mode = modeOf(ctx);
	if (mode === undefined) return ctx.hasUI; // backward compat
	return mode === "tui";
}

/**
 * Build the block reason returned to pi when a guard verdict that would
 * normally `confirm` cannot, because the current run mode does not
 * support interactive dialogs.
 *
 * - In a known non-TUI mode (`rpc`, `json`, `print`), the reason
 *   mentions the mode explicitly so the agent and operator can see why
 *   confirmation was refused.
 * - For older pi versions where `ctx.mode` is absent (and `hasUI` is
 *   also false), `base` is returned unchanged so existing block
 *   messages do not change — no regression (P3-1 AC#3).
 *
 * @param base — The guard's own message (the would-be dialog body) or a
 *              legacy "no UI" reason.
 */
function dialogBlockReason(base: string, ctx: PipelineCtx): string {
	const mode = modeOf(ctx);
	if (mode === undefined) return base;
	return `confirmation requires interactive (tui) mode; current mode: ${mode}`;
}

/**
 * Enforce the per-session confirmation cap. Call at each confirm point
 * AFTER the dialog-capability check (so {@link canShowDialog} returned
 * `true`), before showing `ctx.ui.confirm(...)`.
 *
 * Increments the confirmation counter on every call. Returns a block
 * verdict when the cap is exceeded (preventing further dialog spam);
 * `null` when the confirm dialog may proceed. When blocked, emits a
 * `ratelimit.block` audit event and notifies the user.
 */
function confirmationCapBlock(
	policy: SecurityLimits,
	ctx: PipelineCtx,
): { block: true; reason: string } | null {
	const rl = checkLimit("confirmations", policy);
	if (rl.allowed) return null;
	auditLog("ratelimit.block", "warning", {
		scope: "confirmations",
		count: rl.count,
		limit: rl.limit,
	});
	if (ctx.hasUI) {
		ctx.ui.notify(
			`🚫 Confirmation rate limit exceeded (${rl.count}/${rl.limit} this session) — blocking instead of prompting`,
			"warning",
		);
	}
	return { block: true, reason: rl.reason ?? "confirmation rate limit exceeded" };
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

		// ── Step 0: Input shape validation (QW-4) ───────────────────
		// Fail-closed: malformed input for read/write/edit/bash blocks
		// before any other guard runs.
		const inputVerdict = validateToolInput(toolName, input);
		if (inputVerdict) {
			auditLog("input.invalid", "warning", {
				tool: toolName,
				reason: inputVerdict.reason,
			});

			if (ctx.hasUI) {
				ctx.ui.notify(`🚫 Blocked: ${inputVerdict.reason}`, "warning");
			}
			return { block: true, reason: inputVerdict.reason };
		}

		// ── Step 0.5: Rate-limit check (tool_calls scope) ──────────
		// Fail-closed: once the per-turn tool-call cap is exceeded, every
		// subsequent tool call in the turn is blocked and audited. Caps
		// runaway loops / denial-of-wallet (Practice #5).
		const policy = config.securityPolicy ?? DEFAULT_SECURITY_POLICY;
		const toolLimit = checkLimit("tool_calls", policy);
		if (!toolLimit.allowed) {
			auditLog("ratelimit.block", "warning", {
				scope: "tool_calls",
				tool: toolName,
				count: toolLimit.count,
				limit: toolLimit.limit,
			});
			if (ctx.hasUI) {
				ctx.ui.notify(`🚫 Rate limit: ${toolLimit.reason}`, "warning");
			}
			return {
				block: true,
				reason: toolLimit.reason ?? "tool_calls rate limit exceeded",
			};
		}

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
			if (!canShowDialog(ctx)) {
				auditLog("boundary.block", "warning", {
					tool: toolName,
					path: input.path ?? "",
					boundary: config.cwd,
					reason: dialogBlockReason("blocked (no UI for confirmation)", ctx),
					mode: modeOf(ctx),
				});
				return { block: true, reason: dialogBlockReason(boundaryVerdict.message, ctx) };
			}

			const cap = confirmationCapBlock(policy, ctx);
			if (cap) return cap;

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
			if (!canShowDialog(ctx)) {
				auditLog("protected.block", "warning", {
					tool: toolName,
					path: input.path ?? "",
					reason: dialogBlockReason("blocked (no UI for confirmation)", ctx),
					mode: modeOf(ctx),
				});
				return { block: true, reason: dialogBlockReason(protectedVerdict.message, ctx) };
			}

			const cap = confirmationCapBlock(policy, ctx);
			if (cap) return cap;

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

			// P1-2: Exfiltration detection runs BEFORE classifyCommand. Any
			// finding escalates the verdict (most-restrictive wins, ADR-0001)
			// and produces a separate `bash.exfil` audit entry — independent
			// of the pattern-based classification outcome. The audit command
			// is redacted so secret values are not logged in plaintext.
			const exfilFindings = detectExfiltration(command);
			if (exfilFindings.length > 0) {
				auditLog("bash.exfil", "warning", {
					tool: "bash",
					command: safeCommand,
					findings: exfilFindings.map((f) => ({ kind: f.kind, detail: f.detail })),
				});
			}

			const baseVerdict = guards.classifyCommand(command, config);

			// Escalate allow → confirm when exfil/secret findings are present.
			// secret findings imply at minimum `confirm`; write-action tools
			// would `block`, but the bash gate only runs for the bash tool.
			let bashVerdict = baseVerdict;
			if (exfilFindings.length > 0 && baseVerdict.action === "allow") {
				bashVerdict = {
					action: "confirm",
					message: `⚠️ Potential secret/exfiltration detected — allow execution?\n\n  ${command}\n\nIndicators: ${exfilFindings
						.map((f) => `${f.kind}:${f.detail}`)
						.join(", ")}`,
					category: baseVerdict.category,
				};
			}

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
				if (!canShowDialog(ctx)) {
					const category = bashVerdict.category ?? "unknown";
					const baseReason = `${category.charAt(0).toUpperCase() + category.slice(1)} command blocked (no UI)`;
					auditLog(`bash.${category}.block`, "warning", {
						tool: "bash",
						command: safeCommand,
						category,
						reason: dialogBlockReason("blocked (no UI for confirmation)", ctx),
						mode: modeOf(ctx),
					});
					return { block: true, reason: dialogBlockReason(baseReason, ctx) };
				}

				const cap = confirmationCapBlock(policy, ctx);
				if (cap) return cap;

				// R5: redact the command within the dialog message. The verdict
				// message (built by classifyCommand or exfil escalation) embeds
				// the raw command, which may carry a secret (e.g. a bearer token
				// in a curl -H argument). Classification ran on the real command
				// above; only the displayed copy is sanitized. Literal split/join
				// (not regex) avoids escaping issues when the command contains
				// regex-special characters. When there are no secrets,
				// safeCommand === command so the message is unchanged.
				const displayMessage = bashVerdict.message.split(command).join(safeCommand);
				const approved = await ctx.ui.confirm("🔒 Bash Command", displayMessage);
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

	// Reset the per-turn tool-call counter at the start of each turn so
	// the `tool_calls` scope is bounded to a single turn (Practice #5).
	pi.on("turn_start", () => {
		resetTurn();
	});
}
