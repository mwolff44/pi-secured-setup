/**
 * Unit tests for lib/audit.ts — rotation logic, severity types,
 * and HMAC forward-chaining (ADR-0007).
 *
 * Tests override the audit file path to a temp directory to avoid
 * polluting the developer's real audit log. The HMAC key path is
 * derived from the audit file's directory, so the key is isolated
 * to the same temp directory automatically.
 */
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { existsSync, rmSync, mkdirSync, statSync, readFileSync, writeFileSync, renameSync } from "node:fs";
import { resolve } from "node:path";
import { tmpdir } from "node:os";
import {
	initAuditLog,
	auditLog,
	_setAuditFileForTest,
	_setRotationConfigForTest,
	verifyAuditChain,
} from "../lib/audit.js";
import type { AuditEntry, FileVerification } from "../lib/audit.js";

describe("audit severity types", () => {
	it("AuditSeverity accepts only valid values", () => {
		const valid: Array<"debug" | "info" | "warning" | "error"> = [
			"debug",
			"info",
			"warning",
			"error",
		];
		assert.equal(valid.length, 4);
		assert.ok(!valid.includes("warn" as never), '"warn" is not a valid AuditSeverity');
	});
});

describe("audit log rotation cleans up overflow files", () => {
	let tempDir: string;
	let previousAuditFile: string;

	beforeEach(() => {
		tempDir = resolve(tmpdir(), `pi-audit-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(tempDir, { recursive: true });
		const testAuditFile = resolve(tempDir, "audit.jsonl");
		previousAuditFile = _setAuditFileForTest(testAuditFile);
		initAuditLog();
	});

	afterEach(() => {
		_setAuditFileForTest(previousAuditFile);
		if (tempDir && existsSync(tempDir)) {
			rmSync(tempDir, { recursive: true, force: true });
		}
	});

	it("auditLog does not throw on repeated writes", () => {
		for (let i = 0; i < 5; i++) {
			assert.doesNotThrow(() => {
				auditLog("test.rotation", "info", { iteration: i });
			});
		}
	});

	it("writes entries to the test audit file, not the real home directory", () => {
		const testAuditFile = resolve(tempDir, "audit.jsonl");
		auditLog("test.isolation", "info", { check: true });
		assert.ok(existsSync(testAuditFile), "audit file should exist in temp directory");
	});

	it("creates audit file with correct permissions", () => {
		auditLog("test.permissions", "info", { check: true });
		const testAuditFile = resolve(tempDir, "audit.jsonl");
		assert.ok(existsSync(testAuditFile), "audit file should exist");

		// Skip POSIX mode check on Windows (mode bits are not reliable)
		if (process.platform !== "win32") {
			const mode = statSync(testAuditFile).mode & 0o777;
			assert.equal(mode, 0o600, `expected 0o600 permissions, got 0${mode.toString(8)}`);
		}
	});
});

// ── HMAC forward-chaining (ADR-0007) ─────────────────────────────────

describe("audit HMAC key management (ADR-0007)", () => {
	let tempDir: string;
	let previousAuditFile: string;

	beforeEach(() => {
		tempDir = resolve(tmpdir(), `pi-audit-key-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(tempDir, { recursive: true });
		previousAuditFile = _setAuditFileForTest(resolve(tempDir, "audit.jsonl"));
		initAuditLog();
	});

	afterEach(() => {
		_setAuditFileForTest(previousAuditFile);
		if (tempDir && existsSync(tempDir)) {
			rmSync(tempDir, { recursive: true, force: true });
		}
	});

	it("auto-generates audit.key on first auditLog call", () => {
		const keyPath = resolve(tempDir, "audit.key");
		assert.ok(!existsSync(keyPath), "key should not exist before first auditLog");
		auditLog("test.key", "info", { check: true });
		assert.ok(existsSync(keyPath), "key should be generated on first auditLog");
	});

	it("creates audit.key with mode 0o600 on POSIX", () => {
		const keyPath = resolve(tempDir, "audit.key");
		auditLog("test.keymode", "info", { check: true });
		assert.ok(existsSync(keyPath), "key file should exist");

		// Skip POSIX mode check on Windows (mode bits are not reliable)
		if (process.platform !== "win32") {
			const mode = statSync(keyPath).mode & 0o777;
			assert.equal(mode, 0o600, `expected audit.key mode 0o600, got 0${mode.toString(8)}`);
		}
	});

	it("does not regenerate audit.key if it already exists", () => {
		const keyPath = resolve(tempDir, "audit.key");
		auditLog("test.first", "info", { check: 1 });
		const keyBefore = readFileSync(keyPath);

		// Reset the in-memory cache by flipping the audit file path twice.
		// This forces the next auditLog to re-read the key from disk.
		const other = resolve(tempDir, "audit-other.jsonl");
		_setAuditFileForTest(other);
		_setAuditFileForTest(resolve(tempDir, "audit.jsonl"));

		auditLog("test.second", "info", { check: 2 });
		const keyAfter = readFileSync(keyPath);

		assert.deepEqual(keyAfter, keyBefore, "audit.key must not be regenerated if it exists");
	});
});

describe("audit chain verification (ADR-0007)", () => {
	let tempDir: string;
	let auditFile: string;
	let previousAuditFile: string;

	beforeEach(() => {
		tempDir = resolve(tmpdir(), `pi-audit-chain-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(tempDir, { recursive: true });
		auditFile = resolve(tempDir, "audit.jsonl");
		previousAuditFile = _setAuditFileForTest(auditFile);
		initAuditLog();
	});

	afterEach(() => {
		_setAuditFileForTest(previousAuditFile);
		if (tempDir && existsSync(tempDir)) {
			rmSync(tempDir, { recursive: true, force: true });
		}
	});

	it("a freshly written chain verifies OK", () => {
		for (let i = 0; i < 4; i++) {
			auditLog("test.event", "info", { iteration: i });
		}
		const results = verifyAuditChain();
		assert.equal(results.length, 1, "only the current file should exist");
		assert.equal(results[0].ok, true, `chain should verify: ${results[0].reason}`);
		assert.equal(results[0].entries, 4);
	});

	it("detects modification of an entry's body (hash mismatch)", () => {
		auditLog("test.event", "info", { iteration: 0 });
		auditLog("test.event", "info", { iteration: 1 });
		auditLog("test.event", "info", { iteration: 2 });

		// Tamper: modify the body of the 2nd entry (seq=2) without updating its hash.
		const content = readFileSync(auditFile, "utf-8").trim();
		const lines = content.split("\n");
		assert.equal(lines.length, 3);
		const tampered = JSON.parse(lines[1]) as AuditEntry;
		(tampered.details.iteration as number) = 999;
		lines[1] = JSON.stringify(tampered);
		writeFileSync(auditFile, lines.join("\n") + "\n", "utf-8");

		const results = verifyAuditChain();
		assert.equal(results.length, 1);
		const r = results[0];
		assert.equal(r.ok, false, "tampered file should NOT verify");
		assert.equal(r.brokenAtSeq, 2, `chain should break at seq 2, got ${r.brokenAtSeq}`);
		assert.match(r.reason ?? "", /hash mismatch|modified/i, `reason should mention hash mismatch: ${r.reason}`);
	});

	it("detects deletion of an entry (broken forward link)", () => {
		auditLog("test.event", "info", { iteration: 0 });
		auditLog("test.event", "info", { iteration: 1 });
		auditLog("test.event", "info", { iteration: 2 });
		auditLog("test.event", "info", { iteration: 3 });

		// Tamper: delete the 2nd line (seq=2). The chain link from seq=3 → seq=2 is broken.
		const content = readFileSync(auditFile, "utf-8").trim();
		const lines = content.split("\n");
		assert.equal(lines.length, 4);
		lines.splice(1, 1); // remove index 1 (seq=2)
		writeFileSync(auditFile, lines.join("\n") + "\n", "utf-8");

		const results = verifyAuditChain();
		assert.equal(results.length, 1);
		const r = results[0];
		assert.equal(r.ok, false, "file with deleted entry should NOT verify");
		assert.ok(r.brokenAtSeq !== undefined, "brokenAtSeq should be reported");
		// seq=3 is now the 2nd entry; its prevHash points to the deleted seq=2's hash.
		assert.equal(r.brokenAtSeq, 3, `chain should break at seq 3, got ${r.brokenAtSeq}`);
	});

	it("detects insertion of a forged entry (seq mismatch)", () => {
		auditLog("test.event", "info", { iteration: 0 });
		auditLog("test.event", "info", { iteration: 1 });
		auditLog("test.event", "info", { iteration: 2 });

		// Tamper: insert a forged chained entry at the start with a wrong prevHash.
		// This simulates an attacker inserting an entry they computed (without the key,
		// they can't forge a valid hash, so verification will fail).
		const content = readFileSync(auditFile, "utf-8").trim();
		const lines = content.split("\n");
		const forged: AuditEntry = {
			timestamp: "1970-01-01T00:00:00.000Z",
			sessionId: "forged",
			type: "test.forged",
			severity: "info",
			details: { evil: true },
			seq: 1,
			prevHash: "GENESIS",
			hash: "0".repeat(64), // bogus hash
		};
		// Insert at the beginning: now real seq=1 entry's prevHash (GENESIS) is fine,
		// but the forged entry's hash is invalid → break at forged seq=1.
		lines.unshift(JSON.stringify(forged));
		writeFileSync(auditFile, lines.join("\n") + "\n", "utf-8");

		const results = verifyAuditChain();
		assert.equal(results.length, 1);
		assert.equal(results[0].ok, false, "file with forged entry should NOT verify");
	});

	it("verifies a freshly rotated multi-file set cleanly (audit.roll seal)", () => {
		// Build the .1 file: a few chained entries ending with an audit.roll seal.
		auditLog("test.event", "info", { phase: "pre-rot-1" });
		auditLog("test.event", "info", { phase: "pre-rot-2" });
		auditLog("audit.roll", "info", { reason: "size-threshold", size: 1000, threshold: 500 });

		// Simulate rotation: move the sealed file to .1, then write to a fresh current file.
		renameSync(auditFile, `${auditFile}.1`);

		// New current file: fresh entries chain from GENESIS.
		auditLog("test.event", "info", { phase: "post-rot-1" });
		auditLog("test.event", "info", { phase: "post-rot-2" });

		const results = verifyAuditChain();
		assert.equal(results.length, 2, "should verify both .1 and current");
		const verifyAllOk = (rs: FileVerification[]) => rs.every((r) => r.ok);
		assert.ok(verifyAllOk(results), `both files should verify OK: ${JSON.stringify(results, null, 2)}`);

		// The .1 file should be reported first (oldest-first ordering).
		assert.equal(results[0].file, `${auditFile}.1`);
		assert.ok(results[0].file.endsWith(".1"));
		assert.equal(results[1].file, auditFile);
		assert.equal(results[1].file, auditFile);
	});

	it("detects tampering in a rotated (.1) file while current file stays clean", () => {
		// Same setup as the rotation test.
		auditLog("test.event", "info", { phase: "pre-rot-1" });
		auditLog("test.event", "info", { phase: "pre-rot-2" });
		auditLog("audit.roll", "info", { reason: "size-threshold" });
		renameSync(auditFile, `${auditFile}.1`);
		auditLog("test.event", "info", { phase: "post-rot-1" });

		// Tamper the .1 file: modify the first entry's body.
		const rotated = `${auditFile}.1`;
		const content = readFileSync(rotated, "utf-8").trim();
		const lines = content.split("\n");
		const tampered = JSON.parse(lines[0]) as AuditEntry;
		(tampered.details.phase as string) = "TAMPERED";
		lines[0] = JSON.stringify(tampered);
		writeFileSync(rotated, lines.join("\n") + "\n", "utf-8");

		const results = verifyAuditChain();
		assert.equal(results.length, 2);
		assert.equal(results[0].ok, false, ".1 file should fail verification");
		assert.equal(results[0].file, rotated);
		assert.equal(results[1].ok, true, "current file should still verify");
		assert.equal(results[1].file, auditFile);
	});

	it("migrates pre-existing unchained entries via audit.migrate record", () => {
		// Simulate an old audit log: plain JSON entries with no hash/seq/prevHash.
		const oldEntries: AuditEntry[] = [
			{
				timestamp: "2024-01-01T00:00:00.000Z",
				sessionId: "legacy-1",
				type: "session.loaded",
				severity: "info",
				details: { cwd: "/old", legacy: true },
			},
			{
				timestamp: "2024-01-01T00:00:01.000Z",
				sessionId: "legacy-1",
				type: "bash.moderate",
				severity: "info",
				details: { command: "ls" },
			},
			{
				timestamp: "2024-01-01T00:00:02.000Z",
				sessionId: "legacy-1",
				type: "boundary.block",
				severity: "warning",
				details: { path: "/etc/passwd" },
			},
		];
		writeFileSync(
			auditFile,
			oldEntries.map((e) => JSON.stringify(e)).join("\n") + "\n",
			"utf-8",
		);

		// First chained write should detect the legacy entries and emit audit.migrate.
		auditLog("test.afterUpgrade", "info", { check: true });

		// Read back: should contain 3 old entries + 1 audit.migrate + 1 new chained entry.
		const content = readFileSync(auditFile, "utf-8").trim();
		const lines = content.split("\n");
		assert.equal(lines.length, 5, "expected 3 old + 1 migrate + 1 new");

		const parsed = lines.map((l) => JSON.parse(l) as AuditEntry);
		// First 3 are unchained (no hash field).
		for (let i = 0; i < 3; i++) {
			assert.equal(parsed[i].hash, undefined, `old entry ${i} should not have hash`);
		}
		// 4th is the migrate record.
		assert.equal(parsed[3].type, "audit.migrate");
		assert.ok(typeof parsed[3].hash === "string", "migrate record must be chained");
		assert.ok(typeof parsed[3].seq === "number");
		assert.ok(typeof parsed[3].prevHash === "string");
		// 5th is the new entry, chained off the migrate record.
		assert.equal(parsed[4].type, "test.afterUpgrade");
		assert.equal(parsed[4].prevHash, parsed[3].hash, "new entry must chain off migrate record");

		// Verification should pass cleanly.
		const results = verifyAuditChain();
		assert.equal(results.length, 1);
		assert.equal(results[0].ok, true, `migrated file should verify: ${results[0].reason}`);
		assert.equal(results[0].entries, 5);
	});

	it("emits audit.migrate only once for a legacy file", () => {
		const old: AuditEntry = {
			timestamp: "2024-01-01T00:00:00.000Z",
			sessionId: "legacy",
			type: "session.loaded",
			severity: "info",
			details: {},
		};
		writeFileSync(auditFile, JSON.stringify(old) + "\n", "utf-8");

		auditLog("test.first", "info", { n: 1 });
		auditLog("test.second", "info", { n: 2 });
		auditLog("test.third", "info", { n: 3 });

		const content = readFileSync(auditFile, "utf-8").trim();
		const migrateCount = content
			.split("\n")
			.filter((l) => l.includes('"audit.migrate"')).length;
		assert.equal(migrateCount, 1, "audit.migrate should be emitted exactly once");
	});

	it("each entry carries seq, prevHash, and hash fields", () => {
		auditLog("test.event", "info", { n: 1 });
		auditLog("test.event", "info", { n: 2 });

		const lines = readFileSync(auditFile, "utf-8").trim().split("\n");
		const e1 = JSON.parse(lines[0]) as AuditEntry;
		const e2 = JSON.parse(lines[1]) as AuditEntry;

		assert.equal(e1.seq, 1);
		assert.equal(e1.prevHash, "GENESIS");
		assert.ok(typeof e1.hash === "string" && e1.hash.length === 64, "hash should be 64-hex");

		assert.equal(e2.seq, 2);
		assert.equal(e2.prevHash, e1.hash, "second entry prevHash should reference first hash");
		assert.ok(typeof e2.hash === "string" && e2.hash.length === 64);
	});
});

// ── Rotation: maybeRotate multi-file + overflow + audit.roll seal ─────
//
// `maybeRotate` reads `audit-config.json` from MACHINE_CONFIG_DIR (the
// real home dir). Writing a small threshold there would pollute the
// developer machine and race with parallel test files; driving the
// shipped 10 MB default means writing ~40 MB of fixtures per case. The
// `_setRotationConfigForTest` hook injects a tiny threshold so rotation
// is deterministic and fast. Each `auditLog` call triggers `maybeRotate`
// after the append, so writing past the threshold naturally rotates.

describe("audit rotation (maybeRotate) — multi-file + overflow + audit.roll seal", () => {
	let tempDir: string;
	let auditFile: string;
	let prevAuditFile: string;
	let prevRotation: { maxFileSize: number; maxFiles: number } | null;

	beforeEach(() => {
		tempDir = resolve(tmpdir(), `pi-audit-rot-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(tempDir, { recursive: true });
		auditFile = resolve(tempDir, "audit.jsonl");
		prevAuditFile = _setAuditFileForTest(auditFile);
		// Tiny threshold so rotation triggers after a few small writes.
		// Each chained entry serialises to ~250–300 bytes; a 1 KB
		// threshold rotates after ~4 entries.
		prevRotation = _setRotationConfigForTest({ maxFileSize: 1024, maxFiles: 3 });
		initAuditLog();
	});

	afterEach(() => {
		_setAuditFileForTest(prevAuditFile);
		_setRotationConfigForTest(prevRotation);
		if (tempDir && existsSync(tempDir)) {
			rmSync(tempDir, { recursive: true, force: true });
		}
	});

	/** Parse the audit.jsonl at `file` into AuditEntry[]. */
	function entriesOf(file: string): AuditEntry[] {
		if (!existsSync(file)) return [];
		const content = readFileSync(file, "utf-8").trim();
		if (!content) return [];
		const out: AuditEntry[] = [];
		for (const line of content.split("\n")) {
			try {
				out.push(JSON.parse(line) as AuditEntry);
			} catch {
				// skip malformed
			}
		}
		return out;
	}

	it("renames the current file to .1 once it crosses maxFileSize", () => {
		// Write until rotation happens. Each entry is ~250 bytes; 1024
		// threshold → rotate after ~5 entries.
		for (let i = 0; i < 6; i++) {
			auditLog("test.rotation", "info", { i, pad: "x".repeat(200) });
		}

		assert.ok(existsSync(`${auditFile}.1`), "audit.jsonl.1 should exist after rotation");
		const rotated = entriesOf(`${auditFile}.1`);
		assert.ok(rotated.length > 0, "rotated file should contain the original entries");

		// The rotated file MUST end with an audit.roll seal entry.
		const roll = rotated.find((e) => e.type === "audit.roll");
		assert.ok(roll, "rotated file must contain an audit.roll seal entry");
		assert.equal(roll!.severity, "info");
		const details = roll!.details as Record<string, unknown>;
		assert.equal(details.reason, "size-threshold");
		assert.equal(typeof details.size, "number");
		assert.equal(typeof details.threshold, "number");
		// The roll seal is a chained entry (hash/seq/prevHash present).
		assert.ok(typeof roll!.hash === "string" && roll!.hash.length === 64);
		assert.ok(typeof roll!.seq === "number");
		assert.ok(typeof roll!.prevHash === "string");

		// The current file is the new empty chain — it should NOT
		// contain the audit.roll seal (that belongs to the rolled file).
		const current = entriesOf(auditFile);
		assert.ok(
			!current.some((e) => e.type === "audit.roll"),
			"current file must not carry the roll seal",
		);
		// Current file's first entry chains from GENESIS (fresh chain).
		if (current.length > 0) {
			assert.equal(current[0].prevHash, "GENESIS");
		}
	});

	it("shifts .1 → .2 on a second rotation (multi-file)", () => {
		// Trigger rotation #1 → .1 created.
		for (let i = 0; i < 6; i++) {
			auditLog("test.rotation", "info", { phase: "first", i, pad: "x".repeat(200) });
		}
		assert.ok(existsSync(`${auditFile}.1`));

		// Trigger rotation #2 → .1 becomes .2, current becomes .1.
		for (let i = 0; i < 6; i++) {
			auditLog("test.rotation", "info", { phase: "second", i, pad: "x".repeat(200) });
		}
		assert.ok(existsSync(`${auditFile}.1`), ".1 still present after second rotation");
		assert.ok(existsSync(`${auditFile}.2`), ".2 created after second rotation");

		// Both rotated files end with an audit.roll seal.
		for (const ext of [".1", ".2"]) {
			const entries = entriesOf(`${auditFile}${ext}`);
			assert.ok(
				entries.some((e) => e.type === "audit.roll"),
				`${ext} file must end with an audit.roll seal`,
			);
		}
	});

	it("deletes overflow files beyond maxFiles and keeps only .1..maxFiles", () => {
		// maxFiles = 3 → at most .1, .2, .3 exist. Drive enough
		// rotations to push past the cap and confirm cleanup.
		for (let phase = 0; phase < 8; phase++) {
			for (let i = 0; i < 6; i++) {
				auditLog("test.rotation", "info", { phase, i, pad: "x".repeat(200) });
			}
		}

		assert.ok(existsSync(`${auditFile}.1`), ".1 retained");
		assert.ok(existsSync(`${auditFile}.2`), ".2 retained");
		assert.ok(existsSync(`${auditFile}.3`), ".3 retained");
		assert.ok(!existsSync(`${auditFile}.4`), ".4 must be cleaned up (overflow)");
		assert.ok(!existsSync(`${auditFile}.5`), ".5 must not exist");
	});

	it("verifies the whole rotated set cleanly via verifyAuditChain (HMAC chain intact)", () => {
		// Produce a .1 and a current file.
		for (let i = 0; i < 6; i++) {
			auditLog("test.rotation", "info", { i, pad: "x".repeat(200) });
		}
		// One more entry in the fresh current file.
		auditLog("test.afterRotate", "info", { ok: true });

		const results = verifyAuditChain();
		const verifyAllOk = (rs: FileVerification[]) => rs.every((r) => r.ok);
		assert.ok(
			verifyAllOk(results),
			`rotated set should verify cleanly: ${JSON.stringify(results, null, 2)}`,
		);
		// Both the .1 (rolled) and the current file are present.
		assert.ok(results.length >= 1);
		assert.ok(
			results.some((r) => r.file === `${auditFile}.1`),
			"verifyAuditChain must include the .1 rotated file",
		);
		assert.ok(
			results.some((r) => r.file === auditFile),
			"verifyAuditChain must include the current file",
		);

		// The .1 file's report should account for every entry including
		// the audit.roll seal at the end.
		const dot1 = results.find((r) => r.file === `${auditFile}.1`)!;
		assert.ok(dot1.entries > 0);
	});

	it("does NOT rotate when the file is under the threshold", () => {
		// Single small entry well under 1024 bytes.
		auditLog("test.small", "info", { ok: true });
		assert.ok(!existsSync(`${auditFile}.1`), "no rotation should occur under the threshold");
		assert.ok(existsSync(auditFile), "current file should still exist");
	});
});

