/**
 * Skill scanner — SKILL.md hash verification + change detection.
 *
 * Scans skill directories on `session_start`, hashes each `SKILL.md`,
 * and compares against stored approvals. New, changed, and previously-skipped
 * skills trigger an approval prompt (skipped = deferred decision, re-prompted
 * once per session). Previously denied skills show a notification only
 * (explicit permanent refusal, no blocking prompt).
 *
 * ADR-0004: Only SKILL.md is hashed. Supporting scripts are covered
 * by the bash Guard.
 */
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { existsSync, readFileSync, writeFileSync, readdirSync, statSync, mkdirSync, chmodSync } from "node:fs";
import { resolve, join, dirname } from "node:path";
import { homedir } from "node:os";
import type { Config } from "./config.js";
import { MACHINE_CONFIG_DIR, sha256 } from "./utils.js";
import { auditLog, setSkillStatusFn } from "./audit.js";
import { detectInjection } from "./injection-scanner.js";

// ── Types ─────────────────────────────────────────────────────────────

export interface SkillScannerContext {
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

export interface SkillApprovalsDb {
	version: number;
	skills: Record<string, SkillApproval>;
}

// ── Approvals DB ──────────────────────────────────────────────────────

let _approvalsFile = resolve(MACHINE_CONFIG_DIR, "skill-approvals.json");

/**
 * Override the approvals file path for testing. Returns the previous value
 * so tests can restore it in afterEach.
 */
export function _setApprovalsFileForTest(path: string): string {
	const prev = _approvalsFile;
	_approvalsFile = path;
	return prev;
}

function loadApprovals(): SkillApprovalsDb {
	if (!existsSync(_approvalsFile)) {
		return { version: 1, skills: {} };
	}
	try {
		const raw = readFileSync(_approvalsFile, "utf-8");
		return JSON.parse(raw) as SkillApprovalsDb;
	} catch {
		return { version: 1, skills: {} };
	}
}

export function saveApprovals(db: SkillApprovalsDb): void {
	mkdirSync(dirname(_approvalsFile), { recursive: true });
	writeFileSync(_approvalsFile, JSON.stringify(db, null, 2) + "\n", { encoding: "utf-8", mode: 0o600 });
	ensureApprovalsFileMode();
}

/**
 * Best-effort: re-chmod the approvals file to 0o600 on POSIX if it already
 * exists with overly-open permissions. The `mode` option passed to
 * writeFileSync only applies on file creation — it is ignored when
 * overwriting an existing file — so this corrects any pre-existing file
 * that was created with looser perms.
 */
function ensureApprovalsFileMode(): void {
	if (process.platform === "win32") return;
	if (!existsSync(_approvalsFile)) return;
	try {
		const mode = statSync(_approvalsFile).mode & 0o777;
		if (mode !== 0o600) {
			chmodSync(_approvalsFile, 0o600);
		}
	} catch {
		// Best-effort: don't crash save if chmod fails.
	}
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
		// If there's an entry keyed by name, migrate or clean it up
		const nameEntry = migrated[skill.name];
		const pathEntry = migrated[skill.skillMdPath];
		if (nameEntry && !pathEntry) {
			// Migrate name-key to path-key, fixing the path field
			migrated[skill.skillMdPath] = { ...nameEntry, path: skill.skillMdPath };
			delete migrated[skill.name];
			changed = true;
		} else if (nameEntry && pathEntry) {
			// Path-based key already exists — remove stale name-based key
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

export interface DiscoveredSkill {
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

export type SkillAlertType = "new" | "changed" | "skipped" | "denied";

export interface SkillAlert {
	skill: DiscoveredSkill;
	type: SkillAlertType;
	storedHash?: string;
	currentHash: string;
}

/**
 * Compare discovered skills against the approvals DB and generate alerts.
 *
 * Alert semantics:
 *   - `new`      : no DB entry yet                          → actionable
 *   - `changed`  : SKILL.md hash differs from stored        → actionable
 *   - `skipped`  : user deferred the decision (not decided)  → actionable (re-prompt)
 *   - `denied`   : user explicitly refused (permanent)       → notification only
 *   - `approved` : hash matches and status is approved       → silent (no alert)
 *
 * `skipped` is treated as a deferred decision: the user has not yet made a
 * choice, so we re-prompt once per session to obtain one. `denied` is an
 * explicit, permanent refusal — we only surface a notification, never a
 * blocking prompt. The user may still re-trigger a review of denied skills
 * on demand via `/security:skills` (which sets `forAll`).
 */
export function generateAlerts(
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
		} else if (existing.status === "skipped") {
			// Deferred decision — re-prompt each session (actionable)
			alerts.push({ skill, type: "skipped", currentHash });
		} else if (existing.status === "denied") {
			// Explicit permanent refusal — notification only
			alerts.push({ skill, type: "denied", currentHash });
		}
		// else: approved and unchanged — silent
	}

	return alerts;
}

// ── Approval flow ─────────────────────────────────────────────────────
export async function runApprovalFlow(
	alerts: SkillAlert[],
	db: SkillApprovalsDb,
	ctx: SkillScannerContext,
	forAll: boolean = false,
): Promise<SkillApprovalsDb> {
	// Separate actionable alerts (prompt) from notification-only.
	// `skipped` is actionable (deferred decision → re-prompt each session);
	// `denied` is notification-only (explicit permanent refusal). `forAll`
	// (set by `/security:skills`) forces every alert actionable so the user
	// can re-review even denied skills on demand.
	const actionable = alerts.filter(
		(a) => a.type === "new" || a.type === "changed" || a.type === "skipped" || forAll,
	);
	const notificationOnly = alerts.filter((a) => a.type === "denied" && !forAll);

	// Notify about denied skills without blocking (notification-only)
	if (notificationOnly.length > 0 && ctx.hasUI) {
		const names = notificationOnly.map((a) => a.skill.name).join(", ");
		ctx.ui.notify(
			`⚠️ ${notificationOnly.length} denied skill(s): ${names}. Use /security:skills to review.`,
			"warning",
		);
	}

	// Prompt for actionable skills (new / changed / skipped, or any when forAll)
	for (const alert of actionable) {
		// Read the FULL SKILL.md content once. Used for both the 30-line
		// preview AND injection detection. Detecting on the full content
		// (not just the preview) ensures a payload hidden below line 30
		// is still surfaced (P0-3).
		let content: string | null = null;
		try {
			content = readFileSync(alert.skill.skillMdPath, "utf-8");
		} catch {
			// Leave null — the preview branch emits "(Could not read SKILL.md)".
		}

		// Aggregate pattern names + counts only — NEVER log or display
		// verbatim matched text. Parity with the injection scanner's own
		// audit discipline: logging attacker-controlled content would
		// amplify the very payload we are defending against (P0-3, ADR-0006).
		const suspiciousPatterns: Record<string, number> = {};
		if (content !== null) {
			for (const { patternName } of detectInjection(content)) {
				suspiciousPatterns[patternName] = (suspiciousPatterns[patternName] ?? 0) + 1;
			}
		}
		const hasWarnings = Object.keys(suspiciousPatterns).length > 0;

		if (!ctx.hasUI) {
			// No UI — log but don't block. Surface suspicious-pattern
			// counts so the signal is captured non-interactively (P0-3).
			auditLog(
				alert.type === "new" ? "skill.new"
					: alert.type === "changed" ? "skill.changed"
					: alert.type === "skipped" ? "skill.skipped"
					: "skill.denied",
				"warning",
				{
					skill: alert.skill.name,
					path: alert.skill.skillMdPath,
					status: "pending (no UI)",
					...(hasWarnings ? { suspiciousPatterns } : {}),
				},
			);
			continue;
		}

		// Build the approval dialog message. The full message is passed as
		// the select prompt so the reviewer sees the preview + any warnings
		// before choosing (the pi select API renders its first argument as
		// the dialog prompt).
		let message = `🔒 Skill Review: ${alert.skill.name}\n\n`;
		message += `Skill: ${alert.skill.name}\n`;
		message += `Source: ${alert.skill.source}\n`;
		message += `Path: ${alert.skill.skillMdPath}\n\n`;

		if (alert.type === "new") {
			message += "🆕 New skill detected.\n\n";
		} else if (alert.type === "changed") {
			message += "🔄 SKILL.md content has changed.\n\n";
		} else {
			// `skipped` (deferred decision, re-prompting) or `denied` (only
			// reachable here under forced re-review via /security:skills,
			// since denied is otherwise notification-only). The actionable
			// vs. notification distinction is enforced by the filter above.
			message += "🔒 This skill requires an approval decision.\n\n";
		}

		// Surface injection findings as a prominent warning BEFORE the
		// preview so the reviewer sees the risk before reading the
		// (potentially manipulative) content. This is a SCANNER — it
		// augments the prompt only and CANNOT block loading the skill
		// (ADR-0004 / CONTEXT.md: "a Scanner ... never prevent(s) a tool
		// from running"). The user remains free to Approve/Deny/Skip.
		if (hasWarnings) {
			const summary = Object.entries(suspiciousPatterns)
				.map(([name, count]) => `${name} (${count})`)
				.join(", ");
			message += `⚠️ Suspicious patterns detected in SKILL.md: ${summary}\n`;
			message += "Review carefully before approving.\n\n";
		}

		if (content !== null) {
			const preview = content.split("\n").slice(0, 30).join("\n");
			const label = alert.type === "changed" ? "SKILL.md (current)" : "SKILL.md preview";
			message += `--- ${label} ---\n${preview}\n---`;
		} else {
			message += "(Could not read SKILL.md)";
		}

		const choice = await ctx.ui.select(message, ["Approve", "Deny", "Skip"]);

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
	let db = loadApprovals();
	db = migrateNameBasedKeys(db, process.cwd());

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

		const actionable = alerts.filter(
			(a) => a.type === "new" || a.type === "changed" || a.type === "skipped",
		);

		if (actionable.length > 0) {
			const updatedDb = await runApprovalFlow(alerts, db, ctx);
			saveApprovals(updatedDb);
		} else {
			// Only denied notifications (notification-only)
			const notificationOnly = alerts.filter((a) => a.type === "denied");
			if (notificationOnly.length > 0 && ctx.hasUI) {
				const names = notificationOnly.map((a) => a.skill.name).join(", ");
				ctx.ui.notify(
					`⚠️ ${notificationOnly.length} denied skill(s): ${names}. Use /security:skills to review.`,
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
		// `/security:skills` forces re-review of every skill (forAll=true
		// below makes them all actionable). The type only drives the prompt
		// message; it does not gate prompting here.
		const type: SkillAlertType =
			!existing ? "new" :
			existing.status === "skipped" ? "skipped" :
			existing.status === "denied" ? "denied" :
			existing.hash !== currentHash ? "changed" :
			"skipped"; // approved & unchanged — re-prompt for re-confirmation

		return { skill, type, currentHash } as SkillAlert;
	}).filter((a): a is SkillAlert => a !== null);

	const updatedDb = await runApprovalFlow(allAlerts, db, ctx, true);
	saveApprovals(updatedDb);
}
