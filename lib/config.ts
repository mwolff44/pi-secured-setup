/**
 * Config loader — three-layer merge with `!` exclusion.
 *
 * Layers (later layers override / extend earlier):
 *   1. defaults/     — shipped with the package
 *   2. ~/.pi/agent/security/ — machine-specific
 *   3. .pi/security/ — project-specific (relative to cwd)
 *
 * Pattern lists are additive. A `!` prefix on a pattern in a later layer
 * excludes the matching inherited pattern from an earlier layer.
 * Non-pattern scalar fields (e.g. writeAction, readAction) in later layers
 * replace earlier values.
 */
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { resolve } from "node:path";
import {
	DEFAULTS_DIR,
	MACHINE_CONFIG_DIR,
	projectConfigDir,
	expandTilde,
} from "./utils.js";

// ── Types ─────────────────────────────────────────────────────────────

export interface ProtectedPathsConfig {
	patterns: string[];
	writeAction: "block" | "confirm";
	readAction: "block" | "confirm" | "allow";
}

export interface CommandRulesConfig {
	safe: string[];
	moderate: string[];
	dangerous: string[];
	external: string[];
}

export interface AllowedExternalConfig {
	paths: string[];
}

export interface AuditConfig {
	maxFileSize: number;
	maxFiles: number;
}

export interface Config {
	protectedPaths: ProtectedPathsConfig;
	commandRules: CommandRulesConfig;
	allowedExternal: AllowedExternalConfig;
	audit: AuditConfig;
	cwd: string;
}

// ── Layer loading ─────────────────────────────────────────────────────

/**
 * Read and parse a JSON file. Returns `undefined` if the file does not exist.
 */
function readJsonFile<T>(filePath: string): T | undefined {
	if (!existsSync(filePath)) return undefined;
	try {
		const raw = readFileSync(filePath, "utf-8");
		return JSON.parse(raw) as T;
	} catch {
		return undefined;
	}
}

/**
 * Load a config file from the three layers. Returns the values in priority
 * order: [defaults, machine, project]. Missing files produce `undefined`.
 */
function loadLayers<T>(filename: string, cwd: string): [T | undefined, T | undefined, T | undefined] {
	return [
		readJsonFile<T>(resolve(DEFAULTS_DIR, filename)),
		readJsonFile<T>(resolve(MACHINE_CONFIG_DIR, filename)),
		readJsonFile<T>(resolve(projectConfigDir(cwd), filename)),
	];
}

// ── Merge logic ───────────────────────────────────────────────────────

/**
 * Merge an array of pattern strings across layers.
 * - Patterns without `!` prefix are additive.
 * - Patterns with `!` prefix exclude the matching inherited pattern from
 *   earlier layers.
 */
export function mergePatterns(layers: (string[] | undefined)[]): string[] {
	const base: string[] = [];

	for (const patterns of layers) {
		if (!patterns) continue;

		const exclusions: string[] = [];
		const additions: string[] = [];

		for (const p of patterns) {
			if (p.startsWith("!")) {
				exclusions.push(p.slice(1));
			} else {
				additions.push(p);
			}
		}

		// Remove all previously-added patterns that match an exclusion
		for (const exc of exclusions) {
			const excLower = exc.toLowerCase();
			for (let i = base.length - 1; i >= 0; i--) {
				if (base[i].toLowerCase() === excLower) {
					base.splice(i, 1);
				}
			}
		}

		// Append new patterns
		base.push(...additions);
	}

	return base;
}

/**
 * Merge protected-paths config across three layers.
 */
function mergeProtectedPaths(
	layers: [ProtectedPathsConfig | undefined, ProtectedPathsConfig | undefined, ProtectedPathsConfig | undefined],
): ProtectedPathsConfig {
	const [def, machine, project] = layers;

	const result: ProtectedPathsConfig = {
		patterns: mergePatterns([def?.patterns, machine?.patterns, project?.patterns]),
		writeAction: project?.writeAction ?? machine?.writeAction ?? def?.writeAction ?? "block",
		readAction: project?.readAction ?? machine?.readAction ?? def?.readAction ?? "confirm",
	};

	return result;
}

/**
 * Merge command-rules config across three layers.
 * Each category is merged independently.
 */
function mergeCommandRules(
	layers: [CommandRulesConfig | undefined, CommandRulesConfig | undefined, CommandRulesConfig | undefined],
): CommandRulesConfig {
	const [def, machine, project] = layers;

	const categories: (keyof CommandRulesConfig)[] = ["safe", "moderate", "dangerous", "external"];
	const result = {} as CommandRulesConfig;

	for (const cat of categories) {
		result[cat] = mergePatterns([def?.[cat], machine?.[cat], project?.[cat]]);
	}

	return result;
}

/**
 * Merge allowed-external paths across three layers.
 */
function mergeAllowedExternal(
	layers: [AllowedExternalConfig | undefined, AllowedExternalConfig | undefined, AllowedExternalConfig | undefined],
): AllowedExternalConfig {
	return {
		paths: mergePatterns([layers[0]?.paths, layers[1]?.paths, layers[2]?.paths]),
	};
}

// ── First-run setup ───────────────────────────────────────────────────

/**
 * Ensure the machine config directory exists with default configs.
 * This is a no-op if the directory already exists.
 */
export function ensureMachineConfigDir(): void {
	if (!existsSync(MACHINE_CONFIG_DIR)) {
		mkdirSync(MACHINE_CONFIG_DIR, { recursive: true });
	}

	// Copy default configs only if they don't already exist
	const files = [
		"protected-paths.json",
		"command-rules.json",
		"allowed-external.json",
		"audit-config.json",
	];

	for (const file of files) {
		const src = resolve(DEFAULTS_DIR, file);
		const dest = resolve(MACHINE_CONFIG_DIR, file);
		if (!existsSync(dest) && existsSync(src)) {
			const content = readFileSync(src, "utf-8");
			writeFileSync(dest, content, "utf-8");
		}
	}
}

// ── Public API ────────────────────────────────────────────────────────

/**
 * Load and merge configuration from all three layers.
 *
 * @param cwd — The project boundary (current working directory).
 */
export function loadConfig(cwd: string): Config {
	ensureMachineConfigDir();

	const protectedPathsLayers = loadLayers<ProtectedPathsConfig>("protected-paths.json", cwd);
	const commandRulesLayers = loadLayers<CommandRulesConfig>("command-rules.json", cwd);
	const allowedExternalLayers = loadLayers<AllowedExternalConfig>("allowed-external.json", cwd);

	// Audit config only exists at machine level
	const auditConfig =
		readJsonFile<AuditConfig>(resolve(MACHINE_CONFIG_DIR, "audit-config.json")) ??
		readJsonFile<AuditConfig>(resolve(DEFAULTS_DIR, "audit-config.json")) ??
		{ maxFileSize: 10 * 1024 * 1024, maxFiles: 3 };

	const result: Config = {
		protectedPaths: mergeProtectedPaths(protectedPathsLayers),
		commandRules: mergeCommandRules(commandRulesLayers),
		allowedExternal: mergeAllowedExternal(allowedExternalLayers),
		audit: auditConfig,
		cwd,
	};

	// Security warnings for weak configurations
	if (result.protectedPaths.patterns.length === 0) {
		console.error("[pi-secured-setup] WARNING: No protected path patterns are active. Sensitive files like .env, *.key, and *.pem will not be guarded.");
	}
	for (const pattern of result.commandRules.safe) {
		if (pattern === ".*" || pattern === "^.*$") {
			console.error(`[pi-secured-setup] WARNING: Overly broad safe command pattern "${pattern}" detected. All commands will be classified as safe.`);
		}
	}

	return result;
}

/**
 * Reload the config — useful after admin commands that persist config changes.
 * Re-reads all layers from disk.
 */
export function reloadConfig(cwd: string): Config {
	return loadConfig(cwd);
}

/**
 * Add an external path to the machine-level allowed-external.json.
 * Persists to disk immediately.
 */
export function allowExternalPath(path: string): { ok: boolean; message: string } {
	const configFile = resolve(MACHINE_CONFIG_DIR, "allowed-external.json");

	let config: AllowedExternalConfig;
	if (existsSync(configFile)) {
		try {
			config = JSON.parse(readFileSync(configFile, "utf-8")) as AllowedExternalConfig;
		} catch {
			config = { paths: [] };
		}
	} else {
		config = { paths: [] };
	}

	// Normalise the path
	const normalised = expandTilde(path);

	if (config.paths.some((p) => expandTilde(p) === normalised)) {
		return { ok: false, message: `Path "${path}" is already in allowed-external.json.` };
	}

	config.paths.push(normalised);
	writeFileSync(configFile, JSON.stringify(config, null, 2) + "\n", "utf-8");

	return { ok: true, message: `Added "${path}" to allowed-external.json. Reload config to apply.` };
}
