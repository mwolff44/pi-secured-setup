/**
 * Unit tests for lib/skill-scanner.ts — migration and key handling
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { migrateNameBasedKeys } from "../lib/skill-scanner.js";
import type { SkillApprovalsDb } from "../lib/skill-scanner.js";

function makeDb(skills: SkillApprovalsDb["skills"] = {}): SkillApprovalsDb {
	return { version: 1, skills };
}

describe("migrateNameBasedKeys", () => {
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
		const nameKey = "my-skill";
		const pathKey = "/home/user/.pi/agent/skills/my-skill/SKILL.md";
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
});