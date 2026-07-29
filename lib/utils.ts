/**
 * Shared utilities for the pi-secured-setup extension.
 */
import { createHash, createHmac, randomBytes } from "node:crypto";
import { resolve, normalize, dirname } from "node:path";
import { homedir } from "node:os";
import { realpathSync, lstatSync } from "node:fs";

// ── Path helpers ──────────────────────────────────────────────────────

/**
 * Resolve `~` to the user's home directory.
 */
export function expandTilde(path: string): string {
	if (path.startsWith("~/")) {
		return resolve(homedir(), path.slice(2));
	}
	if (path === "~") {
		return homedir();
	}
	return path;
}

/**
 * Resolve a potentially-relative path against a base directory.
 * Handles `~` expansion and normalises the result.
 */
export function resolvePath(base: string, path: string): string {
	const expanded = expandTilde(path);
	if (expanded === path && !path.startsWith("/")) {
		return normalize(resolve(base, path));
	}
	return normalize(expanded);
}

/**
 * Check whether `child` is inside `parent` (both absolute normalised paths).
 */
export function isInsideDir(parent: string, child: string): boolean {
	const rel = normalize(child);
	const dir = normalize(parent);
	return rel.startsWith(dir + "/") || rel === dir;
}

// ── Symlink resolution ────────────────────────────────────────────────

/**
 * Signal thrown by `resolveRealPath` when the path is a symlink whose
 * target does not exist (broken symlink). Callers (the boundary layer)
 * catch this to apply fail-closed semantics.
 */
export class BrokenSymlinkError extends Error {
	readonly path: string;
	constructor(path: string) {
		super(`broken symlink: ${path}`);
		this.name = "BrokenSymlinkError";
		this.path = path;
	}
}

/**
 * Resolve a path to its real (symlink-free) absolute form via `fs.realpathSync`.
 *
 * Behaviour:
 *   - File exists and is resolvable → returns the realpath.
 *   - Path does not exist at all (no symlink, no file) → returns the lexical
 *     path unchanged. This preserves existing semantics for write targets
 *     that have not been created yet (e.g. new files inside the boundary).
 *   - Path is a symlink whose target is missing (broken symlink) → throws
 *     `BrokenSymlinkError`. The caller applies fail-closed semantics.
 *
 * See ADR-0005 for the rationale and the acknowledged TOCTOU window.
 */
export function resolveRealPath(p: string): string {
	try {
		return realpathSync(p);
	} catch (err) {
		// Distinguish "broken symlink" from "missing file".
		try {
			const stat = lstatSync(p);
			if (stat.isSymbolicLink()) {
				throw new BrokenSymlinkError(p);
			}
		} catch (innerErr) {
			if (innerErr instanceof BrokenSymlinkError) throw innerErr;
			// lstat itself failed — the path simply does not exist.
		}
		// Missing file (not a symlink): preserve lexical behaviour.
		return p;
	}
}

// ── Hashing ───────────────────────────────────────────────────────────

/**
 * Compute a sha256 hex digest of a string.
 */
export function sha256(content: string): string {
	return createHash("sha256").update(content).digest("hex");
}

/**
 * Compute an HMAC-SHA256 hex digest of `message` under `key`.
 * Used by the audit log forward-chaining (ADR-0007).
 */
export function hmacSha256(key: Buffer, message: string): string {
	return createHmac("sha256", key).update(message).digest("hex");
}

// ── Defaults directory ────────────────────────────────────────────────

/**
 * Absolute path to the `defaults/` directory shipped with this package.
 * Works regardless of cwd by resolving relative to this source file.
 */
import { fileURLToPath } from "node:url";

const _thisDir = dirname(fileURLToPath(import.meta.url));
export const DEFAULTS_DIR = resolve(_thisDir, "..", "defaults");

/**
 * Machine-level config directory (~/.pi/agent/security/).
 */
export const MACHINE_CONFIG_DIR = resolve(homedir(), ".pi/agent/security");

/**
 * Project-level config directory (resolved relative to cwd at runtime).
 */
export function projectConfigDir(cwd: string): string {
	return resolve(cwd, ".pi/security");
}

// ── ID generation ─────────────────────────────────────────────────────

let _sessionCounter = 0;

/**
 * Generate a short random session ID (used to correlate audit entries).
 */
export function generateSessionId(): string {
	_sessionCounter++;
	const ts = Date.now().toString(36);
	const rand = randomBytes(4).toString("hex");
	return `${ts}-${rand}-${_sessionCounter}`;
}
