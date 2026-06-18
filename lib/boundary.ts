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
 */
import type { Config } from "./config.js";
import { resolvePath, isInsideDir, expandTilde } from "./utils.js";

export type GuardVerdict =
	| { action: "allow" }
	| { action: "block"; reason: string }
	| { action: "confirm"; message: string };

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

	const targetPath = resolvePath(config.cwd, rawPath);

	// Inside boundary — allow
	if (isInsideDir(config.cwd, targetPath)) {
		return { action: "allow" };
	}

	// Outside boundary — check allowed-external list
	const allowed = config.allowedExternal.paths.map((p) => expandTilde(p));
	for (const allowedPath of allowed) {
		if (isInsideDir(allowedPath, targetPath) || targetPath === allowedPath) {
			return { action: "allow" };
		}
	}

	// Outside boundary — apply tool-specific action
	if (normalisedTool === "write" || normalisedTool === "edit") {
		return {
			action: "block",
			reason: `write outside project boundary (${targetPath})`,
		};
	}

	// read outside boundary
	return {
		action: "confirm",
		message: `Read file outside project boundary?\n\n  ${targetPath}\n\nBoundary: ${config.cwd}`,
	};
}
