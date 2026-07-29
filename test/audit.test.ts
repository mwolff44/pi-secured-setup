/**
 * Unit tests for lib/audit.ts — rotation logic, severity types,
 * and HMAC forward-chaining (ADR-0007).
 *
 * Tests override the audit file path to a temp directory to avoid
 * polluting the developer's real audit log. The HMAC key path is
 * derived from the audit file's directory, so the key is isolated
 * to the same temp directory automatically.
 */
import { describe, it, beforeEach, afterEach, mock } from "node:test";
import assert from "node:assert/strict";
import { existsSync, rmSync, mkdirSync, statSync, readFileSync, writeFileSync, renameSync, unlinkSync } from "node:fs";
import { resolve } from "node:path";
import { tmpdir } from "node:os";
import {
	initAuditLog,
	auditLog,
	_setAuditFileForTest,
	_setRotationConfigForTest,
	verifyAuditChain,
	rechainEntries,
} from "../lib/audit.js";
import type { AuditEntry, FileVerification } from "../lib/audit.js";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

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

	it("regenerates audit.key when it is shorter than 32 bytes (R8)", () => {
		const keyPath = resolve(tempDir, "audit.key");
		// Pre-seed a too-short key (4 bytes) — simulates an operator
		// hand-writing a weak key.
		const shortKey = Buffer.from([1, 2, 3, 4]);
		writeFileSync(keyPath, shortKey, { mode: 0o600 });
		assert.equal(statSync(keyPath).size, 4, "pre-seed sanity check");

		const errSpy = mock.method(console, "error");
		try {
			auditLog("test.shortkey", "info", { check: true });
		} finally {
			errSpy.mock.restore();
		}

		// Key file must now be 32 bytes and differ from the short key.
		const regenerated = readFileSync(keyPath);
		assert.equal(regenerated.length, 32, "regenerated key must be 32 bytes");
		assert.ok(!regenerated.equals(shortKey), "key must differ from the short key");

		// The overwrite path must keep 0o600 perms on POSIX.
		if (process.platform !== "win32") {
			const mode = statSync(keyPath).mode & 0o777;
			assert.equal(mode, 0o600, `regenerated key must keep 0o600, got 0${mode.toString(8)}`);
		}

		// A warning must have been logged for the short key.
		const warned = errSpy.mock.calls.some((c) => {
			const arg = c.arguments[0];
			return typeof arg === "string" && /audit key too short/i.test(arg);
		});
		assert.ok(warned, "must log a 'too short' warning before regenerating");
	});

	it("accepts a pre-existing audit.key of exactly 32 bytes (no regeneration)", () => {
		const keyPath = resolve(tempDir, "audit.key");
		// Pre-seed a valid 32-byte key.
		const validKey = Buffer.alloc(32, 0xab);
		writeFileSync(keyPath, validKey, { mode: 0o600 });

		const errSpy = mock.method(console, "error");
		try {
			auditLog("test.exact32", "info", { check: true });
		} finally {
			errSpy.mock.restore();
		}

		const after = readFileSync(keyPath);
		assert.equal(after.length, 32, "key must remain 32 bytes");
		assert.ok(after.equals(validKey), "key must be byte-for-byte unchanged");

		// No short-key warning for a key that meets the threshold.
		const warned = errSpy.mock.calls.some((c) => {
			const arg = c.arguments[0];
			return typeof arg === "string" && /audit key too short/i.test(arg);
		});
		assert.equal(warned, false, "must NOT warn for a valid-length key");
	});

	it("accepts a pre-existing audit.key longer than 32 bytes (threshold is >=)", () => {
		const keyPath = resolve(tempDir, "audit.key");
		// Pre-seed a 64-byte key — exceeds the minimum, must be accepted.
		const longKey = Buffer.alloc(64, 0xcd);
		writeFileSync(keyPath, longKey, { mode: 0o600 });

		const errSpy = mock.method(console, "error");
		try {
			auditLog("test.long64", "info", { check: true });
		} finally {
			errSpy.mock.restore();
		}

		const after = readFileSync(keyPath);
		assert.equal(after.length, 64, "key must remain 64 bytes (meets minimum)");
		assert.ok(after.equals(longKey), "key must be byte-for-byte unchanged");

		const warned = errSpy.mock.calls.some((c) => {
			const arg = c.arguments[0];
			return typeof arg === "string" && /audit key too short/i.test(arg);
		});
		assert.equal(warned, false, "must NOT warn for a key that meets the minimum");
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

// ── Rotation-sequence gap detection (R9 follow-up) ───────────────────
//
// `verifyAuditChain` discovers rotated files by scanning `.1`, `.2`, ...
// and now walks EVERY file number up to the highest present one (capped
// at 99) instead of stopping at the first missing file. A retained
// middle file deleted by a keyless attacker (e.g. `.2` removed while
// `.1` and `.3` remain) would otherwise halt the scan at `.2` and
// silently ignore `.3`, leaving the deletion undetected. Each missing
// number strictly below the highest present file is reported as a gap
// finding. Each rotated file remains independently chain-verified from
// GENESIS (ADR-0007); cross-file crypto binding is an accepted residual
// risk bounded by key custody.

describe("audit rotation-sequence gap detection (R9)", () => {
	let tempDir: string;
	let auditFile: string;
	let keyPath: string;
	let previousAuditFile: string;

	beforeEach(() => {
		tempDir = resolve(tmpdir(), `pi-audit-gap-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(tempDir, { recursive: true });
		auditFile = resolve(tempDir, "audit.jsonl");
		keyPath = resolve(tempDir, "audit.key");
		previousAuditFile = _setAuditFileForTest(auditFile);
		initAuditLog();
	});

	afterEach(() => {
		_setAuditFileForTest(previousAuditFile);
		if (tempDir && existsSync(tempDir)) {
			rmSync(tempDir, { recursive: true, force: true });
		}
	});

	/** Trigger audit.key generation by writing one real chained entry. */
	function ensureKey(): void {
		auditLog("test.bootstrap", "info", { ok: true });
		assert.ok(existsSync(keyPath), "audit.key must exist after bootstrap");
	}

	/** Read the audit.key from the temp dir as a Buffer. */
	function loadKey(): Buffer {
		assert.ok(existsSync(keyPath), "audit.key must exist; call ensureKey() first");
		return readFileSync(keyPath);
	}

	/**
	 * Write a valid independently-chained rotated file at
	 * `${auditFile}.${n}` (each file chains from GENESIS per ADR-0007),
	 * sealed with an `audit.roll` entry at the end so it is
	 * self-contained and verifiable.
	 */
	function seedRotated(n: number, bodies: AuditEntry[]): void {
		const key = loadKey();
		const withRoll: AuditEntry[] = [
			...bodies,
			{
				timestamp: new Date().toISOString(),
				sessionId: "seed-session",
				type: "audit.roll",
				severity: "info",
				details: { reason: "size-threshold" },
			},
		];
		const chained = rechainEntries(withRoll, key);
		writeFileSync(
			`${auditFile}.${n}`,
			chained.map((e) => JSON.stringify(e)).join("\n") + "\n",
			"utf-8",
		);
	}

	/** A minimal body entry for seeding rotated files. */
	function body(idx: number): AuditEntry {
		return {
			timestamp: new Date().toISOString(),
			sessionId: "seed-session",
			type: "test.event",
			severity: "info",
			details: { idx },
		};
	}

	it("detects a gap when a middle rotated file is deleted (R9)", () => {
		ensureKey();
		seedRotated(1, [body(1), body(2)]);
		seedRotated(2, [body(3), body(4)]);
		seedRotated(3, [body(5), body(6)]);

		// Sanity: contiguous set verifies cleanly before deletion.
		const before = verifyAuditChain();
		assert.ok(
			before.every((r) => r.ok),
			`seeded contiguous set must verify before deletion: ${JSON.stringify(before)}`,
		);

		// ATTACKER SIMULATION: delete the middle rotated file (.2)
		// without the key. A keyless attacker can delete files but
		// cannot forge a valid HMAC chain.
		unlinkSync(`${auditFile}.2`);
		assert.ok(!existsSync(`${auditFile}.2`), ".2 must be deleted");

		const results = verifyAuditChain();

		// The gap for .2 must be reported with ok:false and a reason
		// mentioning the missing file / deletion.
		const gap = results.find((r) => r.file === `${auditFile}.2`);
		assert.ok(gap, "result must include a finding for the deleted .2");
		assert.equal(gap!.ok, false, "gap finding must be ok:false");
		assert.equal(gap!.entries, 0, "gap finding has no entries");
		assert.match(
			gap!.reason ?? "",
			/missing|gap|deletion/i,
			`reason must mention the missing/deletion: ${gap!.reason}`,
		);

		// The overall report must NOT be all-ok when a gap is present.
		assert.ok(
			results.some((r) => !r.ok),
			"a gap finding must surface as a non-ok result",
		);
	});

	it("does NOT silently ignore `.3` when `.2` is missing (R9)", () => {
		ensureKey();
		seedRotated(1, [body(1)]);
		seedRotated(2, [body(2)]);
		seedRotated(3, [body(3)]);

		// Delete .2 — previously the scan stopped at the first missing
		// file (.2) and .3 was silently dropped from the result set.
		unlinkSync(`${auditFile}.2`);

		const results = verifyAuditChain();

		// .3 MUST now appear in the result set (no longer ignored) and
		// verify OK.
		const dot3 = results.find((r) => r.file === `${auditFile}.3`);
		assert.ok(dot3, ".3 must NOT be silently ignored when .2 is missing");
		assert.equal(dot3!.ok, true, `.3 should verify OK: ${dot3!.reason}`);
		assert.ok(dot3!.entries > 0, ".3 should contain its sealed entries");

		// AND a gap finding for .2 must be present.
		const gap = results.find((r) => r.file === `${auditFile}.2`);
		assert.ok(gap, "gap finding for .2 must be reported");
		assert.equal(gap!.ok, false);

		// .1 must still verify.
		const dot1 = results.find((r) => r.file === `${auditFile}.1`);
		assert.ok(dot1, ".1 must be verified");
		assert.equal(dot1!.ok, true, `.1 should verify OK: ${dot1!.reason}`);

		// Ordering: oldest-first → .3, .2-gap, .1, current.
		const files = results.map((r) => r.file);
		assert.deepEqual(
			files,
			[`${auditFile}.3`, `${auditFile}.2`, `${auditFile}.1`, auditFile],
			"oldest-first order with the .2 gap between .3 and .1",
		);
	});

	it("contiguous rotation (`.1`, `.2`, `.3`) reports no gap", () => {
		ensureKey();
		seedRotated(1, [body(1), body(2)]);
		seedRotated(2, [body(3), body(4)]);
		seedRotated(3, [body(5), body(6)]);

		const results = verifyAuditChain();

		assert.ok(
			results.every((r) => r.ok),
			`contiguous set must verify with no gaps: ${JSON.stringify(results, null, 2)}`,
		);
		// No gap finding: every rotated entry corresponds to an
		// existing file (a gap finding has ok:false AND entries === 0).
		const gaps = results.filter((r) => !r.ok && r.entries === 0);
		assert.equal(gaps.length, 0, "no gap finding expected for a contiguous set");
		// All three rotated files plus the current file, oldest-first.
		assert.equal(results.length, 4, "expected .3, .2, .1, current");
		assert.equal(results[0].file, `${auditFile}.3`);
		assert.equal(results[3].file, auditFile);
	});

	it("partial fill (only `.1`) reports no spurious gap", () => {
		ensureKey();
		seedRotated(1, [body(1), body(2)]);
		// No .2 / .3 — rotation has not reached them yet.

		const results = verifyAuditChain();

		// maxPresent == 1 → nothing higher present → no gap.
		assert.ok(
			results.every((r) => r.ok),
			`partial fill must not produce a spurious gap: ${JSON.stringify(results, null, 2)}`,
		);
		const gaps = results.filter((r) => !r.ok && r.entries === 0);
		assert.equal(gaps.length, 0, "no gap finding expected when only .1 is present");

		// Expect .1 + current (oldest-first).
		assert.equal(results.length, 2);
		assert.equal(results[0].file, `${auditFile}.1`);
		assert.equal(results[1].file, auditFile);
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

// ── /security:clean — re-seal the HMAC chain (R2 follow-up) ───────────
//
// `/security:clean <days>` trims entries older than N days. The trim
// removes entries from the middle of the chain, so without re-sealing
// the surviving entries' prevHash links point to deleted predecessors
// and `/security:verify` reports "chain broken" — indistinguishable
// from attacker deletion. The fix re-seals the chain over the kept
// entries from GENESIS using the local audit.key, so a user-initiated
// trim verifies OK while an attacker deletion (no key) still breaks.
//
// These tests drive the command via a mocked `pi.registerCommand`
// (same pattern as metrics-scanner.test.ts). The key path derives
// from the audit file's directory, so `_setAuditFileForTest` isolates
// the key to the temp dir.

describe("/security:clean — re-seals HMAC chain (R2)", () => {
	let tempDir: string;
	let auditFile: string;
	let keyPath: string;
	let previousAuditFile: string;

	beforeEach(() => {
		tempDir = resolve(
			tmpdir(),
			`pi-audit-clean-${Date.now()}-${Math.random().toString(36).slice(2)}`,
		);
		mkdirSync(tempDir, { recursive: true });
		auditFile = resolve(tempDir, "audit.jsonl");
		keyPath = resolve(tempDir, "audit.key");
		previousAuditFile = _setAuditFileForTest(auditFile);
		initAuditLog();
	});

	afterEach(() => {
		_setAuditFileForTest(previousAuditFile);
		if (tempDir && existsSync(tempDir)) {
			rmSync(tempDir, { recursive: true, force: true });
		}
	});

	/** Read the audit.key from the temp dir as a Buffer. */
	function loadKey(): Buffer {
		assert.ok(existsSync(keyPath), "audit.key must exist; call auditLog() first to generate it");
		return readFileSync(keyPath);
	}

	/**
	 * Build a fully-chained audit file from a list of entries with
	 * arbitrary timestamps. Useful for seeding backdated entries that
	 * `auditLog` (which always stamps `new Date()`) cannot produce.
	 */
	function seedChainedEntries(entries: AuditEntry[]): void {
		const key = loadKey();
		const chained = rechainEntries(entries, key);
		writeFileSync(
			auditFile,
			chained.map((e) => JSON.stringify(e)).join("\n") + "\n",
			"utf-8",
		);
	}

	/** Build a single AuditEntry with the given timestamp + index. */
	function entryAt(timestamp: string, idx: number): AuditEntry {
		return {
			timestamp,
			sessionId: "seed-session",
			type: "test.event",
			severity: "info",
			details: { idx },
		};
	}

	/**
	 * Capture and invoke the `/security:clean` command handler. Mirrors
	 * the mock-pi pattern in metrics-scanner.test.ts.
	 *
	 * The handler is captured into an object property rather than a
	 * `let` variable: TypeScript keeps an object property at its declared
	 * type (`CleanHandler | undefined`) at read points, so the non-null
	 * assertion yields a callable function. A `let` captured only inside
	 * the mock's closure would stay narrowed to its `null` initializer,
	 * making the assertion collapse to `never` under strict mode (R6).
	 */
	async function runClean(days: number): Promise<{ notify: ReturnType<typeof mock.fn> }> {
		type CleanCtx = { ui: { notify: (message: string, severity?: "info" | "warning" | "error") => void } };
		type CleanHandler = (args: string, ctx: CleanCtx) => Promise<void>;
		const captured: { handler?: CleanHandler } = {};
		const pi = {
			on() {},
			registerCommand(name: string, def: { handler: CleanHandler }) {
				if (name === "security:clean") captured.handler = def.handler;
			},
		};

		const { registerAuditCommand } = await import("../lib/audit.js");
		registerAuditCommand(pi as unknown as ExtensionAPI, {} as never);

		assert.ok(captured.handler, "/security:clean command must be registered");
		const notify = mock.fn();
		await captured.handler!(String(days), { ui: { notify } });
		return { notify };
	}

	it("after clean removes entries, verifyAuditChain returns OK", async () => {
		// First call generates the audit.key.
		auditLog("test.bootstrap", "info", { ok: true });

		// Seed a mix of old + new chained entries across a date range.
		const now = Date.now();
		const dayMs = 24 * 60 * 60 * 1000;
		const seeded: AuditEntry[] = [
			entryAt(new Date(now - 60 * dayMs).toISOString(), 0), // 60d ago → removed
			entryAt(new Date(now - 50 * dayMs).toISOString(), 1), // 50d ago → removed
			entryAt(new Date(now - 5 * dayMs).toISOString(), 2), // 5d ago → kept
			entryAt(new Date(now - 1 * dayMs).toISOString(), 3), // 1d ago → kept
			entryAt(new Date(now).toISOString(), 4), // now → kept
		];
		seedChainedEntries(seeded);

		// Sanity: the seeded chain verifies before clean.
		let before = verifyAuditChain();
		assert.equal(before.length, 1);
		assert.equal(before[0].ok, true, `seeded chain should verify: ${before[0].reason}`);

		// Clean with a 30-day cutoff: removes the two oldest entries.
		await runClean(30);

		// After clean, verify must still return OK.
		const after = verifyAuditChain();
		assert.equal(after.length, 1, "only the current file should exist");
		assert.equal(
			after[0].ok,
			true,
			`chain should verify after clean: ${after[0].reason}`,
		);
		// 3 kept entries + 1 audit.clean = 4.
		assert.equal(after[0].entries, 4);
	});

	it("kept entries form a valid forward chain (seq from 1, prevHash links)", async () => {
		auditLog("test.bootstrap", "info", { ok: true });

		const now = Date.now();
		const dayMs = 24 * 60 * 60 * 1000;
		seedChainedEntries([
			entryAt(new Date(now - 60 * dayMs).toISOString(), 0), // removed
			entryAt(new Date(now - 1 * dayMs).toISOString(), 1), // kept
			entryAt(new Date(now).toISOString(), 2), // kept
		]);

		await runClean(30);

		const lines = readFileSync(auditFile, "utf-8").trim().split("\n");
		const entries = lines.map((l) => JSON.parse(l) as AuditEntry);

		// First entry is the first KEPT entry, re-chained from GENESIS.
		assert.equal(entries[0].seq, 1, "first kept entry must have seq=1");
		assert.equal(entries[0].prevHash, "GENESIS", "first kept entry prevHash = GENESIS");

		// Walk the chain: each entry's prevHash == prior entry's hash,
		// and seq is monotonic from 1.
		for (let i = 1; i < entries.length; i++) {
			assert.equal(
				entries[i].seq,
				entries[i - 1].seq! + 1,
				`seq must be monotonic at index ${i}`,
			);
			assert.equal(
				entries[i].prevHash,
				entries[i - 1].hash,
				`prevHash at index ${i} must reference prior entry's hash`,
			);
		}

		// The last entry is the audit.clean event (appended via auditLog).
		assert.equal(entries[entries.length - 1].type, "audit.clean");
	});

	it("audit.clean event is appended and chains correctly onto the re-sealed entries", async () => {
		auditLog("test.bootstrap", "info", { ok: true });

		const now = Date.now();
		const dayMs = 24 * 60 * 60 * 1000;
		seedChainedEntries([
			entryAt(new Date(now - 60 * dayMs).toISOString(), 0), // removed
			entryAt(new Date(now - 1 * dayMs).toISOString(), 1), // kept
		]);

		await runClean(30);

		const lines = readFileSync(auditFile, "utf-8").trim().split("\n");
		const entries = lines.map((l) => JSON.parse(l) as AuditEntry);

		// Last entry is audit.clean.
		const clean = entries[entries.length - 1];
		assert.equal(clean.type, "audit.clean");
		assert.equal(typeof clean.hash, "string", "audit.clean must be chained (hash)");
		assert.equal(typeof clean.seq, "number", "audit.clean must be chained (seq)");
		assert.equal(typeof clean.prevHash, "string", "audit.clean must be chained (prevHash)");

		// Its prevHash must reference the last re-sealed kept entry's hash.
		const lastKept = entries[entries.length - 2];
		assert.equal(
			clean.prevHash,
			lastKept.hash,
			"audit.clean prevHash must chain off the last kept entry",
		);
		assert.equal(clean.seq, lastKept.seq! + 1, "audit.clean seq must follow last kept entry");

		// Details must record the trim.
		assert.equal(clean.details.removed, 1);
		assert.equal(clean.details.remaining, 1);
		assert.equal(clean.details.resealed, true);
	});

	it("attacker middle-deletion (no re-seal) still breaks the chain (regression guard)", async () => {
		auditLog("test.bootstrap", "info", { ok: true });

		const now = Date.now();
		const dayMs = 24 * 60 * 60 * 1000;
		// All entries within the kept window so clean would no-op —
		// this isolates the attacker-deletion scenario from clean.
		seedChainedEntries([
			entryAt(new Date(now - 5 * dayMs).toISOString(), 0),
			entryAt(new Date(now - 4 * dayMs).toISOString(), 1),
			entryAt(new Date(now - 3 * dayMs).toISOString(), 2),
			entryAt(new Date(now - 2 * dayMs).toISOString(), 3),
			entryAt(new Date(now - 1 * dayMs).toISOString(), 4),
		]);

		// Before tampering: verifies OK.
		let results = verifyAuditChain();
		assert.equal(results[0].ok, true, "seeded chain must verify before tampering");

		// ATTACKER SIMULATION: read the file, delete a MIDDLE line,
		// write it back WITHOUT re-sealing. No key needed for deletion.
		const content = readFileSync(auditFile, "utf-8").trim();
		const lines = content.split("\n");
		assert.equal(lines.length, 5);
		lines.splice(2, 1); // remove index 2 (the middle entry, seq=3)
		writeFileSync(auditFile, lines.join("\n") + "\n", "utf-8");

		// Verify MUST report broken. This proves the re-seal during
		// clean does NOT mask real tampering — only the key-holder can
		// produce a valid chain after a deletion.
		results = verifyAuditChain();
		assert.equal(results.length, 1);
		const r = results[0];
		assert.equal(r.ok, false, "attacker deletion must break the chain");
		assert.ok(r.brokenAtSeq !== undefined, "brokenAtSeq must be reported");
		// seq=4 was the entry after the deleted seq=3; its prevHash still
		// points to the (now-deleted) seq=3's hash.
		assert.equal(r.brokenAtSeq, 4, `chain should break at seq 4, got ${r.brokenAtSeq}`);
	});

	it("removed === 0 is a NO-OP — original hashes preserved, file unchanged", async () => {
		auditLog("test.bootstrap", "info", { ok: true });

		const now = Date.now();
		const dayMs = 24 * 60 * 60 * 1000;
		// All entries within a 5-day window; clean with 30-day cutoff
		// removes nothing.
		seedChainedEntries([
			entryAt(new Date(now - 5 * dayMs).toISOString(), 0),
			entryAt(new Date(now - 3 * dayMs).toISOString(), 1),
			entryAt(new Date(now - 1 * dayMs).toISOString(), 2),
		]);

		// Snapshot the exact file bytes before clean.
		const before = readFileSync(auditFile, "utf-8");

		const { notify } = await runClean(30);

		// File must be byte-for-byte unchanged.
		const after = readFileSync(auditFile, "utf-8");
		assert.equal(after, before, "no-op clean must not rewrite the file");

		// No audit.clean event was emitted.
		assert.equal(
			after.includes('"audit.clean"'),
			false,
			"no-op clean must not append audit.clean",
		);

		// Verify still OK.
		const results = verifyAuditChain();
		assert.equal(results[0].ok, true, `verify must still pass: ${results[0].reason}`);
		assert.equal(results[0].entries, 3, "all 3 entries preserved");

		// User was still notified.
		assert.equal(notify.mock.calls.length, 1);
		const [msg] = notify.mock.calls[0].arguments as [string, string];
		assert.match(msg, /nothing to clean/i);
	});

	it("all entries removed → file contains only audit.clean chained from GENESIS", async () => {
		auditLog("test.bootstrap", "info", { ok: true });

		const now = Date.now();
		const dayMs = 24 * 60 * 60 * 1000;
		// All entries very old → all removed by a 30-day cutoff.
		seedChainedEntries([
			entryAt(new Date(now - 100 * dayMs).toISOString(), 0),
			entryAt(new Date(now - 90 * dayMs).toISOString(), 1),
			entryAt(new Date(now - 80 * dayMs).toISOString(), 2),
		]);

		await runClean(30);

		// After clean: only audit.clean remains, chained from GENESIS.
		const lines = readFileSync(auditFile, "utf-8").trim().split("\n");
		assert.equal(lines.length, 1, "only audit.clean should remain");
		const only = JSON.parse(lines[0]) as AuditEntry;
		assert.equal(only.type, "audit.clean");
		assert.equal(only.seq, 1, "audit.clean must be seq=1 (fresh chain from GENESIS)");
		assert.equal(only.prevHash, "GENESIS", "audit.clean prevHash = GENESIS");
		assert.equal(typeof only.hash, "string");

		// Verify OK.
		const results = verifyAuditChain();
		assert.equal(results.length, 1);
		assert.equal(results[0].ok, true, `verify must pass: ${results[0].reason}`);
		assert.equal(results[0].entries, 1);
	});
});

