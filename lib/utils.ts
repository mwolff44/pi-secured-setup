/**
 * Shared utilities for the pi-secured-setup extension.
 */
import { createHash, randomBytes } from "node:crypto";
import { resolve, normalize, dirname } from "node:path";
import { homedir } from "node:os";

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

// ── Hashing ───────────────────────────────────────────────────────────

/**
 * Compute a sha256 hex digest of a string.
 */
export function sha256(content: string): string {
	return createHash("sha256").update(content).digest("hex");
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
