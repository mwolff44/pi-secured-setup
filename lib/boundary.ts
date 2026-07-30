/**
 * Boundary evaluation — pure function.
 *
 * Enforces that `read`, `write`, and `edit` operations stay within the
 * project boundary (cwd). Bash commands are NOT subject to boundary
 * enforcement (ADR-0003).
 *
 * Read outside boundary → confirm
 * Write/Edit outside boundary → block
 * Allowed external paths → allow
 *
 * ADR-0005: paths are resolved through `fs.realpathSync` before comparison
 * so that symlinks inside `cwd` pointing outside cannot escape the boundary.
 * Broken symlinks fail-closed (write/edit → block, read → confirm). A small
 * TOCTOU window between evaluation and execution is documented in ADR-0005
 * and accepted — the boundary is a guardrail, not a hard OS sandbox.
 */
import type { Config } from "./config.js";
import { resolvePath, isInsideDir, expandTilde, resolveRealPath, BrokenSymlinkError } from "./utils.js";

export type GuardVerdict =
	| { action: "allow" }
	| { action: "block"; reason: string }
	| { action: "confirm"; message: string };

/**
 * Resolve `cwd` through realpath with a lexical fallback. The fallback
 * preserves behaviour for callers that pass a non-existent cwd (e.g. unit
 * tests). In production, cwd is the launch directory and always exists.
 */
function resolveRealCwd(cwd: string): string {
	try {
		return resolveRealPath(cwd);
	} catch {
		return cwd;
	}
}

/**
 * Evaluate whether a tool call is within the project boundary.
 *
 * @param toolName — "read", "write", "edit", "bash", etc.
 * @param input   — Tool call parameters (mutable record)
 * @param config  — Merged runtime configuration
 */
export function evaluateBoundary(
	toolName: string,
	input: Record<string, unknown>,
	config: Config,
): GuardVerdict {
	const normalisedTool = toolName.toLowerCase();

	// ADR-0003: bash is not subject to boundary enforcement
	if (normalisedTool === "bash") return { action: "allow" };

	// Only applies to path-based tools
	if (normalisedTool !== "read" && normalisedTool !== "write" && normalisedTool !== "edit") {
		return { action: "allow" };
	}

	const rawPath = input.path as string | undefined;
	if (!rawPath) return { action: "allow" };

	// ADR-0005: resolve cwd once and the target through realpath so symlinks
	// cannot escape the boundary. Broken symlinks fail-closed below.
	const realCwd = resolveRealCwd(config.cwd);
	const targetPath = resolvePath(config.cwd, rawPath);

	let realTarget: string;
	try {
		realTarget = resolveRealPath(targetPath);
	} catch (err) {
		// Broken symlink — fail-closed per ADR-0005.
		const reason = err instanceof BrokenSymlinkError
			? `broken symlink outside boundary (${targetPath})`
			: `unresolvable path outside boundary (${targetPath})`;
		if (normalisedTool === "write" || normalisedTool === "edit") {
			return { action: "block", reason };
		}
		return {
			action: "confirm",
			message: `Read broken symlink inside boundary?\n\n  ${targetPath}\n\nBoundary: ${config.cwd}`,
		};
	}

	// Inside boundary — allow
	if (isInsideDir(realCwd, realTarget)) {
		return { action: "allow" };
	}

	// Outside boundary — check allowed-external list.
	// ADR-0005: resolve each entry through realpath; on failure (broken
	// symlink or unreadable), skip that entry rather than crashing the loop.
	for (const allowedEntry of config.allowedExternal.paths) {
		const expanded = expandTilde(allowedEntry);
		let resolvedAllowed: string;
		try {
			resolvedAllowed = resolveRealPath(expanded);
		} catch {
			continue; // broken-symlink entry — skip defensively
		}
		if (isInsideDir(resolvedAllowed, realTarget) || realTarget === resolvedAllowed) {
			return { action: "allow" };
		}
	}

	// Outside boundary — apply tool-specific action
	if (normalisedTool === "write" || normalisedTool === "edit") {
		return {
			action: "block",
			reason: `write outside project boundary (${realTarget})`,
		};
	}

	// read outside boundary
	return {
		action: "confirm",
		message: `Read file outside project boundary?\n\n  ${realTarget}\n\nBoundary: ${config.cwd}`,
	};
}
