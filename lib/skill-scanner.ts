/**
 * Skill scanner — SKILL.md hash verification + change detection.
 *
 * Scans skill directories on `session_start`, hashes each `SKILL.md`,
 * and compares against stored approvals. New or changed skills trigger
 * an approval prompt. Previously skipped/unapproved skills show a
 * notification only (no blocking prompt).
 *
 * ADR-0004: Only SKILL.md is hashed. Supporting scripts are covered
 * by the bash Guard.
 */
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { existsSync, readFileSync, writeFileSync, readdirSync, statSync } from "node:fs";
import { resolve, join } from "node:path";
import { homedir } from "node:os";
import type { Config } from "./config.js";
import { MACHINE_CONFIG_DIR, sha256 } from "./utils.js";
import { auditLog, setSkillStatusFn } from "./audit.js";

// ── Types ─────────────────────────────────────────────────────────────

interface SkillScannerContext {
	hasUI: boolean;
	ui: {
		notify(message: string, severity: string): void;
		confirm(title: string, message: string): Promise<boolean>;
		select(title: string, options: string[]): Promise<string>;
	};
	cwd?: string;
}

interface SkillApproval {
	path: string;
	hash: string;
	approvedAt: string | null;
	source: string;
	status: "approved" | "denied" | "skipped";
}

interface SkillApprovalsDb {
	version: number;
	skills: Record<string, SkillApproval>;
}

// ── Approvals DB ──────────────────────────────────────────────────────

const APPROVALS_FILE = resolve(MACHINE_CONFIG_DIR, "skill-approvals.json");

function loadApprovals(): SkillApprovalsDb {
	if (!existsSync(APPROVALS_FILE)) {
		return { version: 1, skills: {} };
	}
	try {
		const raw = readFileSync(APPROVALS_FILE, "utf-8");
		return JSON.parse(raw) as SkillApprovalsDb;
	} catch {
		return { version: 1, skills: {} };
	}
}

function saveApprovals(db: SkillApprovalsDb): void {
	writeFileSync(APPROVALS_FILE, JSON.stringify(db, null, 2) + "\n", "utf-8");
}

/**
 * Migrate old name-based keys to path-based keys.
 * Discovers all skills and re-keys any entry whose key matches a skill name
 * but differs from the skill's path.
 */
export function migrateNameBasedKeys(db: SkillApprovalsDb, cwd: string): SkillApprovalsDb {
	const skills = discoverAllSkills(cwd);
	const migrated = { ...db.skills };
	let changed = false;

	for (const skill of skills) {
		// If there's an entry keyed by name but not by path, migrate it
		const nameEntry = migrated[skill.name];
		const pathEntry = migrated[skill.skillMdPath];
		if (nameEntry && !pathEntry) {
			migrated[skill.skillMdPath] = nameEntry;
			delete migrated[skill.name];
			changed = true;
		}
	}

	if (changed) {
		db.skills = migrated;
		saveApprovals(db);
	}
	return db;
}

// ── Skill discovery ───────────────────────────────────────────────────

interface DiscoveredSkill {
	name: string;
	skillMdPath: string;
	source: string;
}

/**
 * Discover skills in a single directory.
 * A skill is any subdirectory containing a `SKILL.md` file.
 */
function discoverSkillsInDir(dir: string, sourceLabel: string): DiscoveredSkill[] {
	if (!existsSync(dir)) return [];

	const skills: DiscoveredSkill[] = [];
	let entries: string[];

	try {
		entries = readdirSync(dir);
	} catch {
		return [];
	}

	for (const entry of entries) {
		const fullPath = join(dir, entry);
		let isDir: boolean;
		try {
			isDir = statSync(fullPath).isDirectory();
		} catch {
			continue;
		}

		if (!isDir) continue;

		const skillMdPath = join(fullPath, "SKILL.md");
		if (existsSync(skillMdPath)) {
			skills.push({
				name: entry,
				skillMdPath,
				source: sourceLabel,
			});
		}
	}

	return skills;
}

/**
 * Discover all skills across all standard directories.
 */
function discoverAllSkills(cwd: string): DiscoveredSkill[] {
	const skills: DiscoveredSkill[] = [];

	// Global skill directories
	skills.push(...discoverSkillsInDir(resolve(homedir(), ".pi/agent/skills"), "~/.pi/agent/skills/"));
	skills.push(...discoverSkillsInDir(resolve(homedir(), ".agents/skills"), "~/.agents/skills/"));

	// Project-local skill directories (cwd only, no ancestor walking)
	skills.push(...discoverSkillsInDir(resolve(cwd, ".pi/skills"), ".pi/skills/"));
	skills.push(...discoverSkillsInDir(resolve(cwd, ".agents/skills"), ".agents/skills/"));

	return skills;
}

// ── Approval flow ─────────────────────────────────────────────────────

type SkillAlertType = "new" | "changed" | "unapproved";

interface SkillAlert {
	skill: DiscoveredSkill;
	type: SkillAlertType;
	storedHash?: string;
	currentHash: string;
}

/**
 * Compare discovered skills against the approvals DB and generate alerts.
 */
function generateAlerts(
	skills: DiscoveredSkill[],
	db: SkillApprovalsDb,
): SkillAlert[] {
	const alerts: SkillAlert[] = [];

	for (const skill of skills) {
		let content: string;
		try {
			content = readFileSync(skill.skillMdPath, "utf-8");
		} catch {
			continue; // Can't read SKILL.md — skip
		}

		const currentHash = "sha256:" + sha256(content);
		const existing = db.skills[skill.skillMdPath];

		if (!existing) {
			// New skill — no entry in DB
			alerts.push({ skill, type: "new", currentHash });
		} else if (existing.hash !== currentHash) {
			// Changed SKILL.md
			alerts.push({
				skill,
				type: "changed",
				storedHash: existing.hash,
				currentHash,
			});
		} else if (existing.status !== "approved") {
			// Previously skipped or denied — notification only
			alerts.push({ skill, type: "unapproved", currentHash });
		}
		// else: approved and unchanged — silent
	}

	return alerts;
}

// ── Approval flow ─────────────────────────────────────────────────────
async function runApprovalFlow(
	alerts: SkillAlert[],
	db: SkillApprovalsDb,
	ctx: SkillScannerContext,
	forAll: boolean = false,
): Promise<SkillApprovalsDb> {
	// Separate actionable alerts from notification-only
	const actionable = alerts.filter((a) => a.type === "new" || a.type === "changed" || forAll);
	const notificationOnly = alerts.filter((a) => a.type === "unapproved" && !forAll);

	// Show notification for previously unapproved skills (not blocking)
	if (notificationOnly.length > 0 && ctx.hasUI) {
		const names = notificationOnly.map((a) => a.skill.name).join(", ");
		ctx.ui.notify(
			`⚠️ ${notificationOnly.length} unapproved skill(s): ${names}. Use /security:skills to review.`,
			"warning",
		);
	}

	// Prompt for new/changed skills
	for (const alert of actionable) {
		if (!ctx.hasUI) {
			// No UI — log but don't block
			auditLog(
				alert.type === "new" ? "skill.new" : alert.type === "changed" ? "skill.changed" : "skill.unapproved",
				"warning",
				{
					skill: alert.skill.name,
					path: alert.skill.skillMdPath,
					status: "pending (no UI)",
				},
			);
			continue;
		}

		// Show details
		let message = `Skill: ${alert.skill.name}\n`;
		message += `Source: ${alert.skill.source}\n`;
		message += `Path: ${alert.skill.skillMdPath}\n\n`;

		if (alert.type === "new") {
			message += "🆕 New skill detected.\n\n";
			// Show a preview of SKILL.md content (first 30 lines)
			try {
				const content = readFileSync(alert.skill.skillMdPath, "utf-8");
				const preview = content.split("\n").slice(0, 30).join("\n");
				message += `--- SKILL.md preview ---\n${preview}\n---`;
			} catch {
				message += "(Could not read SKILL.md)";
			}
		} else if (alert.type === "changed") {
			message += "🔄 SKILL.md content has changed.\n\n";
			// Show a diff
			try {
				const newContent = readFileSync(alert.skill.skillMdPath, "utf-8");
				// We don't have old content stored, so just show new content preview
				message += `--- SKILL.md (current) ---\n${newContent.split("\n").slice(0, 30).join("\n")}\n---`;
			} catch {
				message += "(Could not read SKILL.md)";
			}
		} else {
			// unapproved — forced re-review via /security:skills
			message += "⚠️ This skill has not been approved.\n";
			try {
				const content = readFileSync(alert.skill.skillMdPath, "utf-8");
				const preview = content.split("\n").slice(0, 30).join("\n");
				message += `\n--- SKILL.md preview ---\n${preview}\n---`;
			} catch {
				message += "(Could not read SKILL.md)";
			}
		}

		const choice = await ctx.ui.select(
			`🔒 Skill Review: ${alert.skill.name}`,
			["Approve", "Deny", "Skip"],
		);

		const now = new Date().toISOString();

		if (choice === "Approve") {
			db.skills[alert.skill.skillMdPath] = {
				path: alert.skill.skillMdPath,
				hash: alert.currentHash,
				approvedAt: now,
				source: alert.skill.source,
				status: "approved",
			};
			auditLog("skill.approved", "info", {
				skill: alert.skill.name,
				path: alert.skill.skillMdPath,
				hash: alert.currentHash,
			});
		} else if (choice === "Deny") {
			db.skills[alert.skill.skillMdPath] = {
				path: alert.skill.skillMdPath,
				hash: alert.currentHash,
				approvedAt: null,
				source: alert.skill.source,
				status: "denied",
			};
			auditLog("skill.denied", "warning", {
				skill: alert.skill.name,
				path: alert.skill.skillMdPath,
			});
		} else {
			// Skip — update hash but don't mark as approved
			db.skills[alert.skill.skillMdPath] = {
				path: alert.skill.skillMdPath,
				hash: alert.currentHash,
				approvedAt: null,
				source: alert.skill.source,
				status: "skipped",
			};
			auditLog("skill.new", "warning", {
				skill: alert.skill.name,
				path: alert.skill.skillMdPath,
				status: "skipped",
			});
		}
	}

	return db;
}



/**
 * Trust a skill by name — persist approval to config.
 * Called by the `/security:trust` command.
 */
export function trustSkill(skillName: string): { ok: boolean; message: string } {
	if (!/^[a-zA-Z0-9_-]+$/.test(skillName)) {
		return { ok: false, message: "Skill name must be alphanumeric with hyphens/underscores." };
	}

	// Find the skill across all directories
	const allSkills = discoverAllSkills(process.cwd());
	const skill = allSkills.find((s) => s.name === skillName);

	if (!skill) {
		return { ok: false, message: `Skill "${skillName}" not found in any skill directory.` };
	}

	let content: string;
	try {
		content = readFileSync(skill.skillMdPath, "utf-8");
	} catch {
		return { ok: false, message: `Could not read ${skill.skillMdPath}.` };
	}

	const currentHash = "sha256:" + sha256(content);
	const db = loadApprovals();

	db.skills[skill.skillMdPath] = {
		path: skill.skillMdPath,
		hash: currentHash,
		approvedAt: new Date().toISOString(),
		source: skill.source,
		status: "approved",
	};

	saveApprovals(db);

	auditLog("skill.approved", "info", {
		skill: skillName,
		path: skill.skillMdPath,
		hash: currentHash,
		source: "command",
	});

	return { ok: true, message: `Skill "${skillName}" approved (${skill.source}).` };
}

// ── Skill counts for dashboard ────────────────────────────────────────

export interface SkillStatusSummary {
	approved: number;
	pending: number;
	denied: number;
}

/**
 * Get skill approval status counts.
 */
export function getSkillStatus(): SkillStatusSummary {
	const db = loadApprovals();
	let approved = 0;
	let pending = 0;
	let denied = 0;

	for (const skill of Object.values(db.skills)) {
		if (skill.status === "approved") approved++;
		else if (skill.status === "denied") denied++;
		else pending++;
	}

	return { approved, pending, denied };
}

// ── Scanner registration ──────────────────────────────────────────────

/**
 * Register the skill scanner on the pi extension API.
 *
 * Scans skills on `session_start` and prompts for approval of new/changed
 * skills. Registers the `/security:skills` command for re-triggering.
 */
export function registerSkillScanner(
	pi: ExtensionAPI,
	getConfig: () => Config,
): void {
	// Register skill status function for the dashboard
	setSkillStatusFn(getSkillStatus);

	pi.on("session_start", async (_event, ctx) => {
		const config = getConfig();
		const skills = discoverAllSkills(config.cwd);
		let db = loadApprovals();
		db = migrateNameBasedKeys(db, config.cwd);
		const alerts = generateAlerts(skills, db);

		if (alerts.length === 0) return; // All clean

		const actionable = alerts.filter((a) => a.type === "new" || a.type === "changed");

		if (actionable.length > 0) {
			const updatedDb = await runApprovalFlow(alerts, db, ctx);
			saveApprovals(updatedDb);
		} else {
			// Only unapproved notifications
			const notificationOnly = alerts.filter((a) => a.type === "unapproved");
			if (notificationOnly.length > 0 && ctx.hasUI) {
				const names = notificationOnly.map((a) => a.skill.name).join(", ");
				ctx.ui.notify(
					`⚠️ ${notificationOnly.length} unapproved skill(s): ${names}. Use /security:skills to review.`,
					"warning",
				);
			}
		}
	});
}

/**
 * Re-trigger the full skill approval flow for all skills.
 * Called by the `/security:skills` command.
 */
export async function triggerSkillReview(ctx: SkillScannerContext): Promise<void> {
	const cwd = ctx.cwd ?? process.cwd();
	const skills = discoverAllSkills(cwd);
	let db = loadApprovals();
	db = migrateNameBasedKeys(db, cwd);

	// Force review of all skills regardless of status
	const allAlerts: SkillAlert[] = skills.map((skill) => {
		let content: string;
		try {
			content = readFileSync(skill.skillMdPath, "utf-8");
		} catch {
			return null;
		}

		const currentHash = "sha256:" + sha256(content);
		const existing = db.skills[skill.skillMdPath];
		const type: SkillAlertType =
			!existing ? "new" :
			existing.status !== "approved" ? "unapproved" :
			existing.hash !== currentHash ? "changed" :
			"unapproved"; // approved but force re-review

		return { skill, type, currentHash } as SkillAlert;
	}).filter((a): a is SkillAlert => a !== null);

	const updatedDb = await runApprovalFlow(allAlerts, db, ctx, true);
	saveApprovals(updatedDb);
}
