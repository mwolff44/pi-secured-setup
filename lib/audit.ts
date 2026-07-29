/**
 * Append-only JSONL audit logger + `/security` command registration.
 *
 * Audit entries are appended to `~/.pi/agent/security/audit.jsonl`.
 * Log rotation is configurable via `audit-config.json`.
 *
 * Tamper-evidence (ADR-0007): each entry carries `seq`, `prevHash`, and
 * `hash` forming an HMAC-SHA256 forward chain keyed by a machine-local
 * `audit.key` (mode 0o600). Insertion/deletion/modification of any entry
 * breaks the chain and is reported by `/security:verify`.
 */
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import {
	appendFileSync,
	chmodSync,
	existsSync,
	mkdirSync,
	readFileSync,
	renameSync,
	statSync,
	unlinkSync,
	writeFileSync,
} from "node:fs";
import { resolve, dirname } from "node:path";
import { randomBytes } from "node:crypto";
import type { Config } from "./config.js";
import { MACHINE_CONFIG_DIR, generateSessionId, sha256, hmacSha256 } from "./utils.js";

// ── Types ─────────────────────────────────────────────────────────────

export type AuditSeverity = "debug" | "info" | "warning" | "error";

export interface AuditEntry {
	timestamp: string;
	sessionId: string;
	type: string;
	severity: AuditSeverity;
	details: Record<string, unknown>;
	/** Monotonic per-file sequence number (chained entries only). */
	seq?: number;
	/** Hash of the previous entry in this file (`"GENESIS"` for the first). */
	prevHash?: string;
	/** HMAC-SHA256(key, prevHash || sha256(canonicalJSON(body))). */
	hash?: string;
}

// ── Audit logger ──────────────────────────────────────────────────────

let _auditFile = resolve(MACHINE_CONFIG_DIR, "audit.jsonl");

/**
 * Override the audit file path for testing. Returns the previous value
 * so tests can restore it in afterEach.
 *
 * The HMAC key path is derived from the audit file's directory, so
 * overriding this also isolates the key to the same temp directory.
 */
export function _setAuditFileForTest(path: string): string {
	const prev = _auditFile;
	_auditFile = path;
	_cachedKey = null; // invalidate; key path is derived from _auditFile
	return prev;
}

/**
 * Rotation config override (test-only). `maybeRotate` normally reads
 * `audit-config.json` from {@link MACHINE_CONFIG_DIR}, which points at
 * the user's real home directory. Tests cannot safely write a small
 * threshold there (it would pollute the developer's machine and race
 * with parallel test files sharing the home dir), and driving the
 * shipped 10 MB default means writing ~40 MB of fixtures per rotation
 * case. This hook lets rotation unit tests inject a tiny threshold so
 * multi-file rotation, overflow cleanup, and the `audit.roll` seal can
 * be exercised deterministically. Pass `null` to restore the
 * file-read behaviour.
 */
let _rotationConfigOverride: { maxFileSize: number; maxFiles: number } | null = null;
export function _setRotationConfigForTest(
	config: { maxFileSize: number; maxFiles: number } | null,
): { maxFileSize: number; maxFiles: number } | null {
	const prev = _rotationConfigOverride;
	_rotationConfigOverride = config;
	return prev;
}

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

// ── HMAC key management (ADR-0007) ────────────────────────────────────

const GENESIS_HASH = "GENESIS";

/**
 * Required HMAC key length in bytes (ADR-0007). Single source of truth
 * for both the acceptance threshold in {@link loadAuditKey} and the
 * `randomBytes` generation call.
 */
const AUDIT_KEY_BYTES = 32;

let _cachedKey: Buffer | null = null;

/**
 * Resolve the audit key path. Co-located with the audit file so that
 * overriding the audit file path for tests also isolates the key.
 */
function getAuditKeyPath(): string {
	return resolve(dirname(_auditFile), "audit.key");
}

/**
 * Load (or generate on first run) the {@link AUDIT_KEY_BYTES}-byte HMAC
 * key. The key is written with mode 0o600 on POSIX. Returns null if the
 * key cannot be loaded or generated — callers must handle this gracefully
 * (append without hash).
 *
 * A pre-existing key file shorter than {@link AUDIT_KEY_BYTES} bytes is
 * treated as a misconfiguration: a warning is logged, and a fresh
 * {@link AUDIT_KEY_BYTES}-byte key is generated and OVERWRITES the short
 * file. Regenerating the key means the HMAC chain can no longer verify
 * entries signed with the old (short) key — `verifyAuditChain` will
 * report those legacy entries as hash-mismatched. This is correct: a
 * short key was never a trustworthy signing key, and the regenerated
 * key starts a trustworthy chain going forward. The legacy entries
 * remain in the append-only log but verify as broken, which honestly
 * reflects the prior misconfiguration.
 */
function loadAuditKey(): Buffer | null {
	if (_cachedKey) return _cachedKey;

	const keyPath = getAuditKeyPath();
	try {
		if (existsSync(keyPath)) {
			const raw = readFileSync(keyPath);
			// Accept the key only if it meets the minimum length. A short
			// key (e.g. an operator hand-wrote 4 bytes) is rejected and
			// falls through to the regeneration path below — defense in
			// depth for the documented "32 random bytes" contract.
			if (raw && raw.length >= AUDIT_KEY_BYTES) {
				_cachedKey = raw;
				return _cachedKey;
			}
			if (raw && raw.length > 0) {
				console.error(
					`[pi-secured-setup] audit key too short (${raw.length} bytes); regenerating a secure ${AUDIT_KEY_BYTES}-byte key.`,
				);
			}
		}
		// Generate a new AUDIT_KEY_BYTES-byte key (first run, missing
		// file, empty file, or rejected-too-short file).
		const key = randomBytes(AUDIT_KEY_BYTES);
		mkdirSync(dirname(keyPath), { recursive: true });
		writeFileSync(keyPath, key, { mode: 0o600 });
		ensureKeyFileMode(keyPath);
		_cachedKey = key;
		return _cachedKey;
	} catch (err) {
		console.error("[pi-secured-setup] audit key load failed:", err);
		return null;
	}
}

/**
 * Best-effort: re-chmod the key file to 0o600 on POSIX if it already
 * exists with overly-open permissions. The `mode` option passed to
 * writeFileSync only applies on file creation; this corrects any
 * pre-existing file that was created with looser perms.
 */
function ensureKeyFileMode(keyPath: string): void {
	if (process.platform === "win32") return;
	if (!existsSync(keyPath)) return;
	try {
		const mode = statSync(keyPath).mode & 0o777;
		if (mode !== 0o600) {
			chmodSync(keyPath, 0o600);
		}
	} catch {
		// Best-effort: don't crash if chmod fails.
	}
}

// ── Canonical JSON & hash computation ─────────────────────────────────

/**
 * Deterministic JSON serialisation: object keys sorted recursively,
 * no extra whitespace. Arrays preserve order. Used to produce a stable
 * input to the body hash so the chain verifies across implementations.
 */
function canonicalJSON(value: unknown): string {
	if (value === null || typeof value !== "object") {
		return JSON.stringify(value);
	}
	if (Array.isArray(value)) {
		return "[" + value.map(canonicalJSON).join(",") + "]";
	}
	const obj = value as Record<string, unknown>;
	const keys = Object.keys(obj).sort();
	return (
		"{" +
		keys
			.map((k) => JSON.stringify(k) + ":" + canonicalJSON(obj[k]))
			.join(",") +
		"}"
	);
}

/**
 * Body = entry without `hash` and `prevHash` (so the body still carries
 * `seq`, `timestamp`, `sessionId`, `type`, `severity`, `details`).
 */
function entryBody(entry: AuditEntry): Record<string, unknown> {
	const body: Record<string, unknown> = {};
	for (const [k, v] of Object.entries(entry)) {
		if (k === "hash" || k === "prevHash") continue;
		body[k] = v;
	}
	return body;
}

/**
 * Compute the chained hash for an entry.
 *   hash = HMAC-SHA256(key, prevHash || sha256(canonicalJSON(body)))
 */
function computeEntryHash(entry: AuditEntry, key: Buffer, prevHash: string): string {
	const bodyHash = sha256(canonicalJSON(entryBody(entry)));
	return hmacSha256(key, prevHash + bodyHash);
}

/**
 * Rebuild a brand-new forward chain over `entries` from GENESIS.
 *
 * Each entry keeps its body fields (`timestamp`, `sessionId`, `type`,
 * `severity`, `details`, plus any extras) verbatim, but receives a
 * fresh `seq` (1..n), `prevHash` (`{@link GENESIS_HASH}` for the first
 * entry, the prior entry's new `hash` otherwise), and `hash` computed
 * via {@link computeEntryHash}. Stale `seq`/`prevHash`/`hash` are
 * dropped and replaced.
 *
 * Used by `/security:clean` to re-seal the chain after trimming old
 * entries so `/security:verify` stays green. Only the key-holder can
 * produce a valid re-seal — an attacker who deletes entries without
 * the key cannot forge a passing chain, so verify still detects real
 * tampering. This mirrors the synthetic-hashing loop inside
 * {@link computeChainStateAndMigrate} but writes back fresh chain
 * fields rather than synthesising them only to emit an
 * `audit.migrate` record.
 *
 * Exported so tests can build valid chains from arbitrary timestamps.
 */
export function rechainEntries(entries: AuditEntry[], key: Buffer): AuditEntry[] {
	let prevHash = GENESIS_HASH;
	let seq = 0;
	const out: AuditEntry[] = [];
	for (const entry of entries) {
		seq++;
		// Clone non-chain fields verbatim, drop stale seq/prevHash/hash.
		const rebuilt: AuditEntry = { ...entry } as AuditEntry;
		delete (rebuilt as Partial<AuditEntry>).seq;
		delete (rebuilt as Partial<AuditEntry>).prevHash;
		delete (rebuilt as Partial<AuditEntry>).hash;
		rebuilt.seq = seq;
		rebuilt.prevHash = prevHash;
		rebuilt.hash = computeEntryHash(rebuilt, key, prevHash);
		prevHash = rebuilt.hash;
		out.push(rebuilt);
	}
	return out;
}

/**
 * Read all entries from the current audit file. Returns [] on missing
 * or unreadable file. Malformed lines are skipped.
 */
function readAllEntries(file: string): AuditEntry[] {
	if (!existsSync(file)) return [];
	try {
		const content = readFileSync(file, "utf-8").trim();
		if (!content) return [];
		const entries: AuditEntry[] = [];
		for (const line of content.split("\n")) {
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
 * Determine the chain state (prevHash + last seq) of the current file.
 *
 * If the file contains pre-existing unchained entries (no hash/seq/prevHash),
 * exactly one `audit.migrate` record is appended to seal the transition
 * before returning. The migrate record's `prevHash` is the synthetic hash
 * of the last unchained entry (computed over its available fields, chained
 * from GENESIS through all prior unchained entries).
 *
 * Returns `{ prevHash: GENESIS_HASH, seq: 0 }` for an empty or missing file.
 */
function computeChainStateAndMigrate(key: Buffer | null): {
	prevHash: string;
	seq: number;
} {
	const entries = readAllEntries(_auditFile);
	if (entries.length === 0) return { prevHash: GENESIS_HASH, seq: 0 };

	const last = entries[entries.length - 1];
	if (
		typeof last.hash === "string" &&
		typeof last.seq === "number" &&
		typeof last.prevHash === "string"
	) {
		// Already chained — resume.
		return { prevHash: last.hash, seq: last.seq };
	}

	// File has unchained entries. Walk them, compute synthetic hashes,
	// and emit a single `audit.migrate` record to seal the transition.
	if (!key) {
		// No key available — cannot compute synthetic hashes or seal.
		// Best-effort: chain from GENESIS.
		return { prevHash: GENESIS_HASH, seq: 0 };
	}

	let prevHash = GENESIS_HASH;
	let seq = 0;
	let unchainedCount = 0;
	for (const e of entries) {
		if (
			typeof e.hash === "string" &&
			typeof e.seq === "number" &&
			typeof e.prevHash === "string"
		) {
			prevHash = e.hash;
			seq = e.seq;
			continue;
		}
		unchainedCount++;
		const synthetic = computeEntryHash(e, key, prevHash);
		prevHash = synthetic;
	}

	// Append the migrate record (sealed with the chain).
	const migrate: AuditEntry = {
		timestamp: new Date().toISOString(),
		sessionId: _sessionId,
		type: "audit.migrate",
		severity: "info",
		details: { migratedCount: unchainedCount },
		seq: seq + 1,
		prevHash,
	};
	migrate.hash = computeEntryHash(migrate, key, prevHash);
	try {
		appendFileSync(_auditFile, JSON.stringify(migrate) + "\n", "utf-8");
	} catch (err) {
		console.error("[pi-secured-setup] audit.migrate append failed:", err);
	}
	return { prevHash: migrate.hash as string, seq: migrate.seq as number };
}

/**
 * Internal: append a single chained entry to the current file. Used by
 * both `auditLog` (user events) and `maybeRotate` (the `audit.roll` seal).
 * Does NOT trigger rotation.
 *
 * SECURITY: this path is intentionally NOT rate-limited. For a
 * tamper-evident forensic log, silently dropping an entry when a rate
 * budget is exhausted would be an anti-pattern: an attacker who triggers
 * a flood could suppress the evidence of their real actions by pushing
 * legitimate entries out of the window. The real DoS surface (disk fill)
 * is already bounded by rotation (`maxFileSize` × `maxFiles` ≈ 30 MB
 * cap), and the write rate is already indirectly bounded by the
 * `tool_calls`-per-turn cap, since every audited Guard event originates
 * from a rate-limited tool call. See ADR-0010.
 */
function appendChained(
	type: string,
	severity: AuditSeverity,
	details: Record<string, unknown>,
): void {
	ensureLogExists();
	const key = loadAuditKey();
	const state = computeChainStateAndMigrate(key);
	const entry: AuditEntry = {
		timestamp: new Date().toISOString(),
		sessionId: _sessionId,
		type,
		severity,
		details,
		seq: state.seq + 1,
		prevHash: state.prevHash,
	};
	if (key) {
		entry.hash = computeEntryHash(entry, key, state.prevHash);
	}
	appendFileSync(_auditFile, JSON.stringify(entry) + "\n", "utf-8");
}

/**
 * Append a single audit entry to the JSONL log. Best-effort: if hashing
 * or chained-append fails, the entry is still appended without hash fields
 * so logging never blocks the extension.
 */
export function auditLog(
	type: string,
	severity: AuditSeverity,
	details: Record<string, unknown>,
): void {
	try {
		appendChained(type, severity, details);
		maybeRotate();
	} catch (err) {
		// Audit logging must never crash the extension.
		console.error("[pi-secured-setup] audit log write failed:", err);
		// Fallback: append a plain unchained entry so the event is recorded.
		try {
			ensureLogExists();
			const basic: AuditEntry = {
				timestamp: new Date().toISOString(),
				sessionId: _sessionId,
				type,
				severity,
				details,
			};
			appendFileSync(_auditFile, JSON.stringify(basic) + "\n", "utf-8");
		} catch (innerErr) {
			console.error("[pi-secured-setup] audit log fallback write failed:", innerErr);
		}
	}
}

// ── Log rotation ──────────────────────────────────────────────────────

function ensureLogExists(): void {
	if (!existsSync(_auditFile)) {
		writeFileSync(_auditFile, "", { mode: 0o600 });
	}
}

/**
 * Check if rotation is needed and perform it.
 * Rotation renames the current log to `audit.jsonl.1`, `audit.jsonl.2`, etc.
 * Files beyond `maxFiles` are deleted.
 *
 * Before renaming, the current file is sealed with an `audit.roll` entry
 * (chained) so the rotated file is self-contained and verifiable. The new
 * empty file starts a fresh chain (`prevHash = "GENESIS"`).
 */
function maybeRotate(): void {
	let config: { maxFileSize: number; maxFiles: number };
	if (_rotationConfigOverride) {
		config = _rotationConfigOverride;
	} else {
		try {
			const raw = readFileSync(resolve(MACHINE_CONFIG_DIR, "audit-config.json"), "utf-8");
			config = JSON.parse(raw);
		} catch {
			config = { maxFileSize: 10 * 1024 * 1024, maxFiles: 3 };
		}
	}

	let size: number;
	try {
		size = statSync(_auditFile).size;
	} catch {
		return;
	}

	if (size < config.maxFileSize) return;

	// Seal the current file with an `audit.roll` entry before rotating.
	// Best-effort: if this fails, continue rotation without the seal.
	try {
		appendChained("audit.roll", "info", {
			reason: "size-threshold",
			size,
			threshold: config.maxFileSize,
		});
	} catch (err) {
		console.error("[pi-secured-setup] audit.roll seal failed:", err);
	}

	// Delete the oldest rotated file to prevent stale data and Windows rename conflicts
	const oldestFile = `${_auditFile}.${config.maxFiles}`;
	if (existsSync(oldestFile)) {
		try {
			unlinkSync(oldestFile);
		} catch {
			// Best-effort: on Windows this may fail if the file is locked
		}
	}

	// Shift existing rotated files: .N → .N+1
	for (let i = config.maxFiles - 1; i >= 1; i--) {
		const src = `${_auditFile}.${i}`;
		const dest = `${_auditFile}.${i + 1}`;
		if (existsSync(src)) {
			renameSync(src, dest);
		}
	}

	// Current → .1
	renameSync(_auditFile, `${_auditFile}.1`);

	// Ensure new empty log file exists with correct permissions
	ensureLogExists();

	// Remove files beyond maxFiles (cleanup of any leftover overflow files)
	for (let i = config.maxFiles + 1; ; i++) {
		const file = `${_auditFile}.${i}`;
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
	if (!existsSync(_auditFile)) return [];

	try {
		const content = readFileSync(_auditFile, "utf-8").trim();
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
	if (!existsSync(_auditFile)) {
		return { blocked: 0, confirmed: 0, autoApproved: 0, secretsRedacted: 0 };
	}

	let blocked = 0;
	let confirmed = 0;
	let autoApproved = 0;
	let secretsRedacted = 0;

	try {
		const content = readFileSync(_auditFile, "utf-8").trim();
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

/**
 * Session metrics aggregated from `turn.metrics` audit events written by
 * the metrics scanner (P2-5). Surfaces token totals and an approximate
 * tool-calls-per-minute figure on the `/security` dashboard.
 */
export interface SessionMetrics {
	/** Cumulative tokens this session (sum of `tokensTurn` per turn.metrics). */
	tokensSession: number;
	/** Number of provider turns observed this session. */
	turnCount: number;
	/**
	 * Approximate tool calls per minute: count of `turn.metrics` events
	 * recorded in the last 60 seconds (sliding window). Each provider
	 * round-trip counts as one event.
	 */
	toolCallsPerMinute: number;
}

/**
 * Aggregate `turn.metrics` events for the current session into a
 * `SessionMetrics` summary. Returns zeroed metrics when the log is
 * missing or empty. Used by the `/security` dashboard.
 */
export function aggregateSessionMetrics(): SessionMetrics {
	const result: SessionMetrics = {
		tokensSession: 0,
		turnCount: 0,
		toolCallsPerMinute: 0,
	};
	if (!existsSync(_auditFile)) return result;

	try {
		const content = readFileSync(_auditFile, "utf-8").trim();
		if (!content) return result;

		const now = Date.now();
		let recent = 0;
		for (const line of content.split("\n")) {
			let entry: AuditEntry;
			try {
				entry = JSON.parse(line) as AuditEntry;
			} catch {
				continue;
			}
			if (entry.sessionId !== _sessionId) continue;
			if (entry.type !== "turn.metrics") continue;

			result.turnCount++;
			const turnTokens = entry.details.tokensTurn;
			if (typeof turnTokens === "number") result.tokensSession += turnTokens;

			const ts = Date.parse(entry.timestamp);
			if (!Number.isNaN(ts) && now - ts <= 60_000) recent++;
		}
		result.toolCallsPerMinute = recent;
	} catch {
		// fall through with whatever was accumulated
	}
	return result;
}

// ── Chain verification (ADR-0007) ─────────────────────────────────────

export interface FileVerification {
	file: string;
	ok: boolean;
	entries: number;
	/** `seq` of the entry where the chain breaks (chained entries only). */
	brokenAtSeq?: number;
	/** 0-based line index where verification failed. */
	brokenAtIndex?: number;
	/** Human-readable reason for the failure. */
	reason?: string;
}

/**
 * Verify a single file's chain. Walks entries, recomputes each chained
 * entry's hash, and verifies the forward link to the previous entry.
 * Pre-existing unchained entries are walked with synthetic hashes so the
 * chain can pass through them to any subsequent `audit.migrate` record.
 *
 * Each file starts from `prevHash = "GENESIS"` (files are independently
 * verifiable; `audit.roll` is the logical end-of-file marker).
 */
function verifyFile(file: string, key: Buffer | null): FileVerification {
	if (!existsSync(file)) {
		return { file, ok: true, entries: 0 };
	}

	let content: string;
	try {
		content = readFileSync(file, "utf-8");
	} catch (err) {
		return {
			file,
			ok: false,
			entries: 0,
			reason: `unreadable file: ${(err as Error).message}`,
		};
	}

	const trimmed = content.trim();
	if (!trimmed) return { file, ok: true, entries: 0 };

	const lines = trimmed.split("\n");
	let prevHash = GENESIS_HASH;
	let expectedSeq = 1;
	let entries = 0;

	for (let i = 0; i < lines.length; i++) {
		let entry: AuditEntry;
		try {
			entry = JSON.parse(lines[i]) as AuditEntry;
		} catch {
			return {
				file,
				ok: false,
				entries,
				brokenAtIndex: i,
				reason: "malformed JSON line",
			};
		}
		entries++;

		const isChained =
			typeof entry.hash === "string" &&
			typeof entry.prevHash === "string" &&
			typeof entry.seq === "number";

		if (isChained) {
			if (!key) {
				return {
					file,
					ok: false,
					entries,
					brokenAtSeq: entry.seq,
					brokenAtIndex: i,
					reason: "audit key unavailable — cannot verify",
				};
			}
			if (entry.prevHash !== prevHash) {
				return {
					file,
					ok: false,
					entries,
					brokenAtSeq: entry.seq,
					brokenAtIndex: i,
					reason: `chain link broken: prevHash does not match preceding entry`,
				};
			}
			if (entry.seq !== expectedSeq) {
				return {
					file,
					ok: false,
					entries,
					brokenAtSeq: entry.seq,
					brokenAtIndex: i,
					reason: `seq mismatch: expected ${expectedSeq}, got ${entry.seq}`,
				};
			}
			const expected = computeEntryHash(entry, key, entry.prevHash as string);
			if (entry.hash !== expected) {
				return {
					file,
					ok: false,
					entries,
					brokenAtSeq: entry.seq,
					brokenAtIndex: i,
					reason: "hash mismatch — entry modified or forged",
				};
			}
			prevHash = entry.hash as string;
			expectedSeq = (entry.seq as number) + 1;
		} else if (key) {
			// Pre-existing unchained entry: compute synthetic hash so the
			// chain can continue through it to a subsequent audit.migrate.
			prevHash = computeEntryHash(entry, key, prevHash);
		}
		// If no key and entry is unchained, accept without verification.
	}

	return { file, ok: true, entries };
}

/**
 * Replay the chain over the current file and all rotated files (`.N` … `.1`,
 * oldest first). Returns one `FileVerification` per file in oldest-first
 * order. Used by the `/security:verify` command and by tests.
 */
export function verifyAuditChain(): FileVerification[] {
	const key = loadAuditKey();
	const results: FileVerification[] = [];

	// Discover rotated files and order oldest-first (.N → .1).
	let maxN = 0;
	for (let i = 1; ; i++) {
		if (existsSync(`${_auditFile}.${i}`)) {
			maxN = i;
		} else {
			break;
		}
	}
	for (let i = maxN; i >= 1; i--) {
		results.push(verifyFile(`${_auditFile}.${i}`, key));
	}
	if (existsSync(_auditFile)) {
		results.push(verifyFile(_auditFile, key));
	}

	return results;
}

/**
 * Human-readable summary of chain verification.
 */
function formatVerifyReport(results: FileVerification[]): string {
	const lines: string[] = [];
	lines.push("🔍 Audit chain verification");
	lines.push("");
	const allOk = results.every((r) => r.ok);
	if (results.length === 0) {
		lines.push("No audit files to verify.");
		return lines.join("\n");
	}
	lines.push(allOk ? "✅ All files verified — chain intact." : "❌ Tampering detected.");
	lines.push("");
	for (const r of results) {
		const label = r.file === _auditFile ? `${r.file} (current)` : r.file;
		if (r.ok) {
			lines.push(`  ✅ ${label}: ${r.entries} entries, chain intact`);
		} else {
			const at =
				r.brokenAtSeq !== undefined
					? `seq ${r.brokenAtSeq}`
					: r.brokenAtIndex !== undefined
						? `line ${r.brokenAtIndex}`
						: "unknown";
			lines.push(`  ❌ ${label}: broken at ${at} — ${r.reason}`);
		}
	}
	return lines.join("\n");
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
	const metrics = aggregateSessionMetrics();
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

	// Metrics section (P2-5): token totals + tool-call rate, aggregated
	// from `turn.metrics` audit events. The metrics scanner is an
	// observer; these numbers are point-in-time approximations derived
	// from the audit log.
	lines.push("");
	lines.push("Metrics (this session):");
	lines.push(`  📊 Tokens:        ${metrics.tokensSession.toLocaleString()} (${metrics.turnCount} turn${metrics.turnCount === 1 ? "" : "s"})`);
	lines.push(`  ⚡ Tool calls/min: ${metrics.toolCallsPerMinute}`);

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
	lines.push(`Log file: ${_auditFile}`);
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
		description:
			"Trim audit log (remove entries older than N days). " +
			"Re-seals the HMAC forward chain over the kept entries from " +
			"GENESIS so /security:verify stays green after a user-initiated " +
			"trim. Only the key-holder can re-seal; an attacker deleting " +
			"entries without audit.key cannot forge a valid chain, so " +
			"verify still detects real tampering.",
		handler: async (args, ctx) => {
			const days = parseInt(args || "30", 10);
			if (isNaN(days) || days <= 0) {
				ctx.ui.notify("Usage: /security:clean <days>", "warning");
				return;
			}

			if (!existsSync(_auditFile)) {
				ctx.ui.notify("No audit log to clean.", "info");
				return;
			}

			const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
			const content = readFileSync(_auditFile, "utf-8").trim();
			if (!content) {
				ctx.ui.notify("Audit log is empty.", "info");
				return;
			}

			const lines = content.split("\n");
			let removed = 0;
			const keptEntries: AuditEntry[] = [];
			const keptRaw: string[] = []; // byte-for-byte original lines (fallback path)
			const keptMalformed: string[] = []; // unparseable lines, preserved as-is

			for (const line of lines) {
				try {
					const entry = JSON.parse(line) as AuditEntry;
					if (entry.timestamp >= cutoff) {
						keptEntries.push(entry);
						keptRaw.push(line);
					} else {
						removed++;
					}
				} catch {
					keptMalformed.push(line); // keep malformed lines
				}
			}

			// NO-OP when nothing changed: preserve the original file
			// (and its original hashes) verbatim. No audit.clean event
			// is emitted, no rewrite, no re-chain. Avoids spurious
			// rewrites that would invalidate the existing chain.
			if (removed === 0) {
				ctx.ui.notify(
					`Audit log: nothing to clean (0 entries older than ${days} days).`,
					"info",
				);
				return;
			}

			const key = loadAuditKey();
			if (key) {
				// Re-seal the chain over kept entries from GENESIS so
				// /security:verify stays green. Only the key-holder can
				// produce a valid chain.
				const rechained = rechainEntries(keptEntries, key);
				const outLines = [
					...rechained.map((e) => JSON.stringify(e)),
					...keptMalformed,
				];
				writeFileSync(
					_auditFile,
					outLines.length > 0 ? outLines.join("\n") + "\n" : "",
					"utf-8",
				);
			} else {
				// No key available — cannot re-seal. Fall back to writing
				// the kept entries verbatim (preserving their stale chain
				// fields). /security:verify will report the chain as
				// broken, which is honest: without the key we cannot
				// produce a valid forward chain and cannot distinguish
				// this trim from attacker deletion.
				const outLines = [...keptRaw, ...keptMalformed];
				writeFileSync(
					_auditFile,
					outLines.length > 0 ? outLines.join("\n") + "\n" : "",
					"utf-8",
				);
			}

			// Append audit.clean via auditLog. computeChainStateAndMigrate
			// will detect the already-rechained kept entries (they have
			// hash/seq/prevHash) and just resume — no double-migrate.
			auditLog("audit.clean", "info", {
				removed,
				remaining: keptEntries.length,
				olderThan: cutoff,
				resealed: key !== null,
			});
			ctx.ui.notify(
				`Cleaned audit log: removed ${removed} entries older than ${days} days.`,
				"info",
			);
		},
	});

	pi.registerCommand("security:verify", {
		description: "Verify audit log chain integrity (HMAC forward-chaining, ADR-0007)",
		handler: async (_args, ctx) => {
			const results = verifyAuditChain();
			const report = formatVerifyReport(results);
			ctx.ui.notify(report, results.every((r) => r.ok) ? "info" : "warning");
		},
	});
}
