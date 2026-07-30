/**
 * Protected paths evaluation — pure function.
 *
 * Matches file paths against glob-like patterns to identify sensitive files.
 * Patterns are merged from defaults → machine → project (with `!` exclusion).
 *
 * Write/Edit to protected path → block
 * Read from protected path → confirm (configurable)
 */
import type { Config } from "./config.js";
import { resolvePath, resolveRealPath, BrokenSymlinkError } from "./utils.js";
import type { GuardVerdict } from "./boundary.js";

/**
 * Match a file path against a simple glob pattern.
 *
 * Supports:
 *   `*`     — any sequence of characters (except /)
 *   `**`    — any sequence of characters including /
 *   `?`     — single character
 *   literal — exact match
 *
 * Patterns are matched against the relative path from cwd and the basename.
 */
export function matchGlob(pattern: string, filePath: string): boolean {
	// Guard against adversarial patterns
	if (pattern.length > 256) return false;
	if ((pattern.match(/\*\*/g) ?? []).length > 8) return false;

	// Count single-star wildcards (not globstar **) to prevent ReDoS
	const singleStars = pattern.replace(/\*\*/g, "").match(/\*/g);
	if (singleStars && singleStars.length > 16) return false;

	// Convert glob to regex
	const regexStr = pattern
		.replace(/[.+^${}()|[\]\\]/g, "\\$&") // escape regex specials (except * and ?)
		.replace(/\*\*/g, "{{GLOBSTAR}}")      // placeholder for **
		.replace(/\*/g, "[^/]*")                // * matches anything except /
		.replace(/\?/g, "[^/]")                 // ? matches single non-/
		.replace(/\{\{GLOBSTAR\}\}/g, ".*");    // ** matches anything including /

	const regex = new RegExp(`(^|/)${regexStr}$`, "i");
	return regex.test(filePath) || regex.test(filePath.split("/").pop() ?? "");
}

/**
 * Evaluate whether a tool call targets a protected path.
 *
 * @param toolName — "read", "write", "edit", "bash", etc.
 * @param input   — Tool call parameters
 * @param config  — Merged runtime configuration
 */
export function evaluateProtectedPaths(
	toolName: string,
	input: Record<string, unknown>,
	config: Config,
): GuardVerdict {
	const normalisedTool = toolName.toLowerCase();

	// Not applicable to bash
	if (normalisedTool === "bash") return { action: "allow" };

	// Only applies to path-based tools
	if (normalisedTool !== "read" && normalisedTool !== "write" && normalisedTool !== "edit") {
		return { action: "allow" };
	}

	const rawPath = input.path as string | undefined;
	if (!rawPath) return { action: "allow" };

	const targetPath = resolvePath(config.cwd, rawPath);
	const patterns = config.protectedPaths.patterns;

	// Defense-in-depth (M1 Weft): a symlink inside the boundary may point at
	// a real target whose name matches a protected pattern even though the
	// symlink's lexical name does not. Resolve the real target and match
	// against BOTH the lexical path and the real path. Broken symlinks fall
	// back to the lexical path (the boundary layer applies fail-closed
	// semantics for writes; here we keep the lexical match so an
	// intentional-but-unresolved path still matches by intent).
	let realTarget: string = targetPath;
	try {
		realTarget = resolveRealPath(targetPath);
	} catch (err) {
		if (err instanceof BrokenSymlinkError) {
			realTarget = targetPath; // lexical fallback for broken symlinks
		} else {
			realTarget = targetPath;
		}
	}

	const candidatePaths = realTarget === targetPath ? [targetPath] : [targetPath, realTarget];

	// Check against all merged patterns.
	let matched = false;
	for (const pattern of patterns) {
		for (const candidate of candidatePaths) {
			if (matchGlob(pattern, candidate)) {
				matched = true;
				break;
			}
			// Also try matching against the basename.
			const basename = candidate.split("/").pop() ?? "";
			if (matchGlob(pattern, basename)) {
				matched = true;
				break;
			}
		}
		if (matched) break;
	}

	if (!matched) return { action: "allow" };

	// Protected path matched — apply action based on tool type
	if (normalisedTool === "write" || normalisedTool === "edit") {
		return {
			action: "block",
			reason: `write to protected path: ${targetPath}`,
		};
	}

	// Read from protected path — check configured read action
	const readAction = config.protectedPaths.readAction;
	if (readAction === "allow") return { action: "allow" };
	if (readAction === "block") {
		return {
			action: "block",
			reason: `read from protected path: ${targetPath}`,
		};
	}

	// Default: confirm
	return {
		action: "confirm",
		message: `Read from protected path?\n\n  ${targetPath}\n\nThis file matches a protected pattern.`,
	};
}
