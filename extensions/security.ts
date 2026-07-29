/**
 * pi-secured-setup — Security extension entry point.
 *
 * Multi-layer security: Guards that block dangerous actions,
 * Scanners that detect risks, and an audit trail that records everything.
 */
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { loadConfig } from "../lib/config.js";
import { registerAuditCommand, initAuditLog, auditLog, getSessionId } from "../lib/audit.js";
import { registerGuardPipeline } from "../lib/guard-pipeline.js";
import { evaluateBoundary } from "../lib/boundary.js";
import { evaluateProtectedPaths } from "../lib/protected-paths.js";
import { classifyCommand } from "../lib/bash-gate.js";
import { registerSecretScanner } from "../lib/secret-scanner.js";
import { registerInjectionScanner } from "../lib/injection-scanner.js";
import { registerMetricsScanner } from "../lib/metrics-scanner.js";
import { registerSkillScanner, triggerSkillReview } from "../lib/skill-scanner.js";
import { resetSession, resetTurn } from "../lib/rate-limiter.js";

export default function (pi: ExtensionAPI) {
	// Initialise session-scoped audit
	initAuditLog();

	// Load merged config (defaults → machine → project)
	let config = loadConfig(process.cwd());

	// Register /security commands (dashboard, skills, trust, allow, clean)
	registerAuditCommand(pi, config);

	// Register the single combined guard pipeline (ADR-0001)
	registerGuardPipeline(
		pi,
		() => config,
		{
			evaluateBoundary,
			evaluateProtectedPaths,
			classifyCommand,
		},
	);

	// Scanners (observe, don't block)
	registerSecretScanner(pi, () => config);
	registerInjectionScanner(pi, () => config);
	registerMetricsScanner(pi, () => config);
	registerSkillScanner(pi, () => config);

	// Record session start and reload config with correct cwd
	pi.on("session_start", async (_event, ctx) => {
		// Reload config in case cwd changed (resume, fork, etc.)
		config = loadConfig(ctx.cwd);

		// Reset rate-limiter counters for the new session: confirmations
		// are scoped per session, and defensively reset the per-turn
		// tool-call counter too (turn_start also resets it per turn).
		resetSession();
		resetTurn();

		auditLog("session.loaded", "info", {
			cwd: ctx.cwd,
			sessionId: getSessionId(),
			protectedPatternsCount: config.protectedPaths.patterns.length,
			commandRuleCategories: Object.keys(config.commandRules),
		});
	});
}
