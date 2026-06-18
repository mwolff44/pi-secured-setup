/**
 * Append-only JSONL audit logger + `/security` command registration.
 *
 * Audit entries are appended to `~/.pi/agent/security/audit.jsonl`.
 * Log rotation is configurable via `audit-config.json`.
 */
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import {
	appendFileSync,
	existsSync,
	readFileSync,
	renameSync,
	statSync,
	unlinkSync,
	writeFileSync,
} from "node:fs";
import { resolve } from "node:path";
import type { Config, AuditConfig } from "./config.js";
import { MACHINE_CONFIG_DIR, generateSessionId } from "./utils.js";

// ── Types ─────────────────────────────────────────────────────────────

export type AuditSeverity = "debug" | "info" | "warning" | "error";

export interface AuditEntry {
	timestamp: string;
	sessionId: string;
	type: string;
	severity: AuditSeverity;
	details: Record<string, unknown>;
}

// ── Audit logger ──────────────────────────────────────────────────────

const AUDIT_FILE = resolve(MACHINE_CONFIG_DIR, "audit.jsonl");

let _sessionId = "";

/**
 * Initialise the session-scoped audit logger. Called once at extension load.
 */
export function initAuditLog(): void {
	_sessionId = generateSessionId();
}

/**
 * Return the current session ID.
 */
export function getSessionId(): string {
	return _sessionId;
}

/**
 * Append a single audit entry to the JSONL log.
 */
export function auditLog(
	type: string,
	severity: AuditSeverity,
	details: Record<string, unknown>,
): void {
	const entry: AuditEntry = {
		timestamp: new Date().toISOString(),
		sessionId: _sessionId,
		type,
		severity,
		details,
	};

	try {
		ensureLogExists();
		appendFileSync(AUDIT_FILE, JSON.stringify(entry) + "\n", "utf-8");
		maybeRotate();
	} catch (err) {
		// Audit logging must never crash the extension.
		console.error("[pi-secured-setup] audit log write failed:", err);
	}
}

// ── Log rotation ──────────────────────────────────────────────────────

function ensureLogExists(): void {
	if (!existsSync(AUDIT_FILE)) {
		writeFileSync(AUDIT_FILE, "", { mode: 0o600 });
	}
}

/**
 * Check if rotation is needed and perform it.
 * Rotation renames the current log to `audit.jsonl.1`, `audit.jsonl.2`, etc.
 * Files beyond `maxFiles` are deleted.
 */
function maybeRotate(): void {
	let config: AuditConfig;
	try {
		const raw = readFileSync(resolve(MACHINE_CONFIG_DIR, "audit-config.json"), "utf-8");
		config = JSON.parse(raw);
	} catch {
		config = { maxFileSize: 10 * 1024 * 1024, maxFiles: 3 };
	}

	let size: number;
	try {
		size = statSync(AUDIT_FILE).size;
	} catch {
		return;
	}

	if (size < config.maxFileSize) return;

	// Delete the oldest rotated file to prevent stale data and Windows rename conflicts
	const oldestFile = `${AUDIT_FILE}.${config.maxFiles}`;
	if (existsSync(oldestFile)) {
		try {
			unlinkSync(oldestFile);
		} catch {
			// Best-effort: on Windows this may fail if the file is locked
		}
	}

	// Shift existing rotated files: .N → .N+1
	for (let i = config.maxFiles - 1; i >= 1; i--) {
		const src = `${AUDIT_FILE}.${i}`;
		const dest = `${AUDIT_FILE}.${i + 1}`;
		if (existsSync(src)) {
			renameSync(src, dest);
		}
	}

	// Current → .1
	renameSync(AUDIT_FILE, `${AUDIT_FILE}.1`);

	// Ensure new empty log file exists with correct permissions
	ensureLogExists();

	// Remove files beyond maxFiles (cleanup of any leftover overflow files)
	for (let i = config.maxFiles + 1; ; i++) {
		const file = `${AUDIT_FILE}.${i}`;
		if (!existsSync(file)) break;
		try {
			unlinkSync(file);
		} catch {
			break;
		}
	}
}

// ── Log reading (for dashboard) ───────────────────────────────────────

/**
 * Read the most recent N entries from the audit log.
 */
function readRecentEntries(limit: number): AuditEntry[] {
	if (!existsSync(AUDIT_FILE)) return [];

	try {
		const content = readFileSync(AUDIT_FILE, "utf-8").trim();
		if (!content) return [];

		const lines = content.split("\n");
		const tail = lines.slice(-limit);

		const entries: AuditEntry[] = [];
		for (const line of tail) {
			try {
				entries.push(JSON.parse(line) as AuditEntry);
			} catch {
				// Skip malformed lines
			}
		}
		return entries;
	} catch {
		return [];
	}
}

/**
 * Count events for the current session.
 */
function countSessionEvents(): {
	blocked: number;
	confirmed: number;
	autoApproved: number;
	secretsRedacted: number;
} {
	if (!existsSync(AUDIT_FILE)) {
		return { blocked: 0, confirmed: 0, autoApproved: 0, secretsRedacted: 0 };
	}

	let blocked = 0;
	let confirmed = 0;
	let autoApproved = 0;
	let secretsRedacted = 0;

	try {
		const content = readFileSync(AUDIT_FILE, "utf-8").trim();
		if (!content) return { blocked: 0, confirmed: 0, autoApproved: 0, secretsRedacted: 0 };

		const lines = content.split("\n");
		for (const line of lines) {
			let entry: AuditEntry;
			try {
				entry = JSON.parse(line) as AuditEntry;
			} catch {
				continue;
			}

			if (entry.sessionId !== _sessionId) continue;

			if (entry.type.endsWith(".block")) blocked++;
			else if (entry.type.endsWith(".confirm")) confirmed++;
			else if (entry.type === "bash.safe" || entry.type === "bash.moderate") autoApproved++;
			else if (entry.type === "secret.redacted") secretsRedacted++;
		}
	} catch {
		// fall through
	}

	return { blocked, confirmed, autoApproved, secretsRedacted };
}

// ── Skill status bridge ───────────────────────────────────────────────

/**
 * Module-level reference to skill status function.
 * Set by the skill scanner when it loads, consumed by the dashboard.
 */
let _getSkillStatus: (() => { approved: number; pending: number; denied: number }) | null = null;

/**
 * Called by skill-scanner.ts to register its status function.
 */
export function setSkillStatusFn(fn: typeof _getSkillStatus): void {
	_getSkillStatus = fn;
}

// ── Dashboard formatting ──────────────────────────────────────────────

function formatDashboard(): string {
	const counts = countSessionEvents();
	const recent = readRecentEntries(20);
	const sessionRecent = recent.filter((e) => e.sessionId === _sessionId);

	const lines: string[] = [];
	lines.push(`🔒 Security Dashboard — Session ${_sessionId}`);
	lines.push("");
	lines.push("This session:");
	lines.push(`  🔴 Blocked:       ${counts.blocked} actions`);
	lines.push(`  🟡 Confirmed:     ${counts.confirmed} actions`);
	lines.push(`  🔵 Auto-approved: ${counts.autoApproved} actions`);
	lines.push(`  ⚠️  Secrets redacted: ${counts.secretsRedacted}`);

	// Skill status section
	if (_getSkillStatus) {
		try {
			const skillStatus = _getSkillStatus();
			lines.push("");
			lines.push("Skill status:");
			lines.push(`  ✅ ${skillStatus.approved} approved, ⚠️ ${skillStatus.pending} pending, 🚫 ${skillStatus.denied} denied`);
		} catch {
			// ignore
		}
	}

	if (sessionRecent.length > 0) {
		lines.push("");
		lines.push("Recent events:");
		for (const entry of sessionRecent.slice(-10)) {
			const time = entry.timestamp.slice(11, 16); // HH:MM
			const type = entry.type;
			const tool = (entry.details.tool as string) ?? "";
			const path = (entry.details.path as string) ?? (entry.details.command as string) ?? "";
			const reason = (entry.details.reason as string) ?? "";

			let tag: string;
			if (type.endsWith(".block")) tag = "BLOCKED";
			else if (type.endsWith(".confirm")) tag = "CONFIRMED";
			else if (type === "secret.redacted") tag = "REDACTED";
			else if (type.startsWith("bash.")) tag = "AUTO";
			else tag = "EVENT";

			lines.push(`  ${time} [${tag}] ${tool}${path ? " → " + path : ""}${reason ? " (" + reason + ")" : ""}`);
		}
	}

	lines.push("");
	lines.push(`Log file: ${AUDIT_FILE}`);
	return lines.join("\n");
}

// ── Command registration ──────────────────────────────────────────────

/**
 * Register the `/security` command and its sub-commands.
 */
export function registerAuditCommand(pi: ExtensionAPI, _config: Config): void {
	pi.registerCommand("security", {
		description: "Security dashboard: view blocked/confirmed counts, recent events",
		handler: async (_args, ctx) => {
			const dashboard = formatDashboard();
			ctx.ui.notify(dashboard, "info");
		},
	});

	pi.registerCommand("security:skills", {
		description: "Re-trigger skill approval flow for all pending/unapproved skills",
		handler: async (_args, ctx) => {
			const { triggerSkillReview } = await import("./skill-scanner.js");
			await triggerSkillReview(ctx);
		},
	});

	pi.registerCommand("security:trust", {
		description: "Approve a skill by name, persist to config",
		handler: async (args, ctx) => {
			if (!args) {
				ctx.ui.notify("Usage: /security:trust <skill-name>", "warning");
				return;
			}
			const skillName = args.trim();
			const { trustSkill } = await import("./skill-scanner.js");
			const result = trustSkill(skillName);
			if (result.ok) {
				ctx.ui.notify(`✅ ${result.message}`, "info");
			} else {
				ctx.ui.notify(`❌ ${result.message}`, "warning");
			}
		},
	});

	pi.registerCommand("security:allow", {
		description: "Add external path to allowed-external.json",
		handler: async (args, ctx) => {
			if (!args) {
				ctx.ui.notify("Usage: /security:allow <path>", "warning");
				return;
			}
			const path = args.trim();
			const { allowExternalPath } = await import("./config.js");
			const result = allowExternalPath(path);
			if (result.ok) {
				ctx.ui.notify(`✅ ${result.message}`, "info");
			} else {
				ctx.ui.notify(`❌ ${result.message}`, "warning");
			}
		},
	});

	pi.registerCommand("security:clean", {
		description: "Trim audit log (remove entries older than N days)",
		handler: async (args, ctx) => {
			const days = parseInt(args || "30", 10);
			if (isNaN(days) || days <= 0) {
				ctx.ui.notify("Usage: /security:clean <days>", "warning");
				return;
			}

			if (!existsSync(AUDIT_FILE)) {
				ctx.ui.notify("No audit log to clean.", "info");
				return;
			}

			const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
			const content = readFileSync(AUDIT_FILE, "utf-8").trim();
			if (!content) {
				ctx.ui.notify("Audit log is empty.", "info");
				return;
			}

			const lines = content.split("\n");
			let removed = 0;
			const kept: string[] = [];

			for (const line of lines) {
				try {
					const entry = JSON.parse(line) as AuditEntry;
					if (entry.timestamp >= cutoff) {
						kept.push(line);
					} else {
						removed++;
					}
				} catch {
					kept.push(line); // keep malformed lines
				}
			}

			writeFileSync(AUDIT_FILE, kept.join("\n") + (kept.length > 0 ? "\n" : ""), "utf-8");

			auditLog("audit.clean", "info", { removed, remaining: kept.length, olderThan: cutoff });
			ctx.ui.notify(`Cleaned audit log: removed ${removed} entries older than ${days} days.`, "info");
		},
	});
}
