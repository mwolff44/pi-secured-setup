/**
 * Unit tests for lib/skill-scanner.ts — migration and key handling
 */
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, writeFileSync, rmSync, existsSync } from "node:fs";
import { resolve, join } from "node:path";
import { tmpdir } from "node:os";
import { migrateNameBasedKeys } from "../lib/skill-scanner.js";
import type { SkillApprovalsDb } from "../lib/skill-scanner.js";

function makeDb(skills: SkillApprovalsDb["skills"] = {}): SkillApprovalsDb {
	return { version: 1, skills };
}

describe("migrateNameBasedKeys", () => {
	let tempDir: string;

	beforeEach(() => {
		tempDir = resolve(tmpdir(), `pi-skill-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(tempDir, { recursive: true });
	});

	afterEach(() => {
		if (tempDir && existsSync(tempDir)) {
			rmSync(tempDir, { recursive: true, force: true });
		}
	});

	it("does nothing when DB is empty", () => {
		const db = makeDb();
		const result = migrateNameBasedKeys(db, "/nonexistent");
		assert.deepEqual(result.skills, {});
	});

	it("does nothing when keys are already path-based", () => {
		const pathKey = "/home/user/.agents/skills/my-skill/SKILL.md";
		const db = makeDb({
			[pathKey]: {
				path: pathKey,
				hash: "sha256:abc123",
				approvedAt: "2025-01-01",
				source: "~/.agents/skills/",
				status: "approved",
			},
		});
		const result = migrateNameBasedKeys(db, "/nonexistent");
		assert.ok(result.skills[pathKey]);
		assert.equal(Object.keys(result.skills).length, 1);
	});

	it("preserves name-based keys when skill directory is not discoverable", () => {
		// Simulate an old DB keyed by skill name
		// Use a collision-resistant name to avoid nondeterministic failure
		// if a developer happens to have a real skill with this name installed
		const nameKey = "__pi-test-nonexistent-skill-7f3a__";
		const pathKey = `/home/user/.pi/agent/skills/${nameKey}/SKILL.md`;
		const db = makeDb({
			[nameKey]: {
				path: pathKey,
				hash: "sha256:abc123",
				approvedAt: "2025-01-01",
				source: "~/.pi/agent/skills/",
				status: "approved",
			},
		});

		// migrateNameBasedKeys discovers skills in cwd and remaps
		// Since /nonexistent won't have skills, we can only test that
		// the function doesn't crash and preserves existing entries
		// when no skills are discovered
		const result = migrateNameBasedKeys(db, "/nonexistent");
		// With no skills discovered, name-based key can't be migrated
		assert.ok(result.skills[nameKey]);
	});

	it("removes stale name-based key when path-based key already exists", () => {
		// Create a real skill on disk so it's discoverable
		const skillName = "__pi-test-dup-skill-7f3a__";
		const skillDir = join(tempDir, ".agents", "skills", skillName);
		mkdirSync(skillDir, { recursive: true });
		writeFileSync(join(skillDir, "SKILL.md"), "# Test skill");
		const pathKey = join(skillDir, "SKILL.md");

		const db = makeDb({
			[skillName]: {
				path: pathKey,
				hash: "sha256:old",
				approvedAt: "2025-01-01",
				source: "~/.agents/skills/",
				status: "approved",
			},
			[pathKey]: {
				path: pathKey,
				hash: "sha256:new",
				approvedAt: "2025-06-01",
				source: ".agents/skills/",
				status: "approved",
			},
		});

		const result = migrateNameBasedKeys(db, tempDir);
		assert.equal(Object.keys(result.skills).length, 1, "should have only one key after migration");
		assert.ok(result.skills[pathKey], "path-based key should remain");
		assert.ok(!result.skills[skillName], "stale name-based key should be removed");
	});

	it("updates path field to match new key during migration", () => {
		// Create a real skill on disk so it's discoverable
		const skillName = "__pi-test-pathfix-skill-7f3a__";
		const skillDir = join(tempDir, ".agents", "skills", skillName);
		mkdirSync(skillDir, { recursive: true });
		writeFileSync(join(skillDir, "SKILL.md"), "# Test skill");
		const pathKey = join(skillDir, "SKILL.md");

		const db = makeDb({
			[skillName]: {
				path: "/old/wrong/path/SKILL.md", // stale path field
				hash: "sha256:abc",
				approvedAt: "2025-01-01",
				source: ".agents/skills/",
				status: "approved",
			},
		});

		const result = migrateNameBasedKeys(db, tempDir);
		assert.ok(result.skills[pathKey], "should be keyed by correct path");
		assert.equal(result.skills[pathKey].path, pathKey, "path field should be updated to match the key");
		assert.ok(!result.skills[skillName], "name-based key should be removed");
	});
});