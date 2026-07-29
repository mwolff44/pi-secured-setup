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
 * Non-pattern scalar fields (e.g. writeAction, readAction) follow a
 * strengthen-only rule at the project layer: a project value may only be
 * more restrictive than the defaults+machine baseline. Machine overrides
 * of defaults are unconstrained (the operator's prerogative). See ADR-0009.
 */
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { resolve } from "node:path";
import {
	DEFAULTS_DIR,
	MACHINE_CONFIG_DIR,
	projectConfigDir,
	expandTilde,
} from "./utils.js";
import type { SecurityLimits } from "./rate-limiter.js";

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

/**
 * A single injection-detection rule. `pattern` is a raw regex string compiled
 * at runtime (case-insensitive). Invalid patterns are skipped by the scanner.
 */
export interface InjectionRule {
	name: string;
	pattern: string;
}

/**
 * Injection-detection configuration. Machine-only: a project-layer
 * `injection-rules.json` is ignored (warned) so a checked-in file cannot
 * weaken detection. See ADR-0006.
 */
export interface InjectionRulesConfig {
	patterns: InjectionRule[];
	threshold: number;
}

/**
 * Rate-limiting policy. Machine-only (see `loadSecurityPolicy`): a
 * project-layer `security-policy.json` cannot raise limits or disable
 * rate limiting. Follows the same baseline-strengthening principle as
 * `audit-config.json` and `injection-rules.json` (ADR-0009).
 *
 * The shape is shared with the rate limiter (`SecurityLimits`), which
 * owns the definition so it has no inbound lib dependencies.
 */
export type SecurityPolicy = SecurityLimits;

/**
 * Shipped default rate-limiting policy. Generous thresholds that avoid
 * blocking legitimate heavy workflows while still capping runaway loops
 * (tool_calls), dialog spam (confirmations), and audit flooding
 * (audit_writes). The three trailing anomaly thresholds are consumed by
 * the metrics scanner (P2-5); they are populated here so callers reading
 * `config.securityPolicy` always see them.
 */
export const DEFAULT_SECURITY_POLICY: SecurityPolicy = {
	toolCallsPerTurn: 100,
	confirmationsPerSession: 200,
	auditWritesPerSecond: 500,
	tokensPerTurnWarn: 8000,
	toolCallsPerMinuteWarn: 60,
	tokensSessionWarn: 50000,
};

export interface Config {
	protectedPaths: ProtectedPathsConfig;
	commandRules: CommandRulesConfig;
	allowedExternal: AllowedExternalConfig;
	audit: AuditConfig;
	injection: InjectionRulesConfig;
	/**
	 * Rate-limiting policy (machine-only). Optional so existing test
	 * fixtures that build a `Config` literal do not break; runtime config
	 * from `loadConfig` always sets this. Code that consumes it must fall
	 * back to `DEFAULT_SECURITY_POLICY` when absent.
	 */
	securityPolicy?: SecurityPolicy;
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
 * Command patterns contributed by the project layer that match every command.
 * Such patterns would classify all commands as `safe`/`moderate` and disarm the
 * bash gate. They are rejected (dropped) when coming from the project layer so
 * the affected commands fall back to `unknown` → confirm. See ADR-0009.
 */
const OVERLY_BROAD_COMMAND_PATTERNS: ReadonlySet<string> = new Set([".*", "^.*$", "^"]);

/**
 * Case-insensitive membership check, matching the case-insensitive `!`
 * exclusion semantics in `mergePatterns`.
 */
function containsIgnoreCase(patterns: string[], target: string): boolean {
	const lower = target.toLowerCase();
	return patterns.some((p) => p.toLowerCase() === lower);
}

/**
 * Drop overly-broad `safe`/`moderate` patterns contributed by the project
 * layer. Exclusions (prefixed with `!`) are passed through unchanged so the
 * project layer's non-baseline exclusion semantics are preserved. See ADR-0009.
 */
function rejectBroadProjectPatterns(patterns: string[], category: string): string[] {
	const kept: string[] = [];
	for (const p of patterns) {
		if (p.startsWith("!")) {
			kept.push(p);
			continue;
		}
		if (OVERLY_BROAD_COMMAND_PATTERNS.has(p)) {
			console.error(`[pi-secured-setup] WARNING: Overly broad ${category} command pattern "${p}" from the project layer was rejected (would classify all commands as ${category}). The pattern falls back to unknown→confirm.`);
			continue;
		}
		kept.push(p);
	}
	return kept;
}

/**
 * Restrictiveness rank of a protected-path scalar action. Higher = more
 * restrictive. Used to enforce the immovable-baseline lock on the
 * `writeAction`/`readAction` scalars (ADR-0009): the project layer may
 * only make them more restrictive, never weaker.
 *
 *   allow   → 0  (least restrictive; readAction only)
 *   confirm → 1
 *   block   → 2  (most restrictive)
 *
 * Unknown values rank as `confirm` (1) so a malformed project value can
 * never silently weaken the baseline.
 */
function protectedActionRank(action: string | undefined): number {
	switch (action) {
		case "allow":
			return 0;
		case "confirm":
			return 1;
		case "block":
			return 2;
		default:
			return 1; // unknown → treated as confirm
	}
}

/**
 * Return the more restrictive of two protected-path actions. Ties resolve
 * to the first operand. Undefined operands fall back to `confirm` so the
 * function is total over its (possibly malformed) input space.
 */
function mostRestrictive(
	a: "block" | "confirm" | "allow" | undefined,
	b: "block" | "confirm" | "allow" | undefined,
): "block" | "confirm" | "allow" {
	return protectedActionRank(a) >= protectedActionRank(b) ? (a ?? "confirm") : (b ?? "confirm");
}

/**
 * Merge protected-paths config across three layers.
 *
 * The protected-path patterns contributed by the defaults and machine layers
 * form an immovable baseline. The project layer may add new patterns but cannot
 * remove baseline patterns via `!`: a project-layer exclusion that targets a
 * baseline pattern is ignored with a warning (the baseline pattern stays).
 * Machine-layer exclusions of default patterns are unaffected. See ADR-0009.
 *
 * The same immovable-baseline lock applies to the scalar `writeAction` and
 * `readAction` fields: the project layer may only make them MORE restrictive
 * (rank order `allow` < `confirm` < `block`). A project-layer value that would
 * weaken the baseline is ignored with a warning, and the baseline value is
 * kept. Machine-layer overrides of defaults are unaffected (the operator's
 * prerogative) — the clamp applies exclusively to the project layer.
 */
export function mergeProtectedPaths(
	layers: [ProtectedPathsConfig | undefined, ProtectedPathsConfig | undefined, ProtectedPathsConfig | undefined],
): ProtectedPathsConfig {
	const [def, machine, project] = layers;

	// Baseline = defaults + machine. Machine exclusions of defaults are honoured.
	const baseline = mergePatterns([def?.patterns, machine?.patterns]);

	// Apply the project layer, enforcing the immovable-baseline lock.
	const additions: string[] = [];
	if (project?.patterns) {
		for (const p of project.patterns) {
			if (p.startsWith("!")) {
				const target = p.slice(1);
				// The project layer cannot remove baseline patterns.
				if (containsIgnoreCase(baseline, target)) {
					console.error(`[pi-secured-setup] WARNING: Project-layer protected-path exclusion "${p}" targets a baseline pattern and was ignored. The project layer can strengthen but not weaken the baseline (see ADR-0009).`);
				}
				// else: excluding a non-existent pattern is a silent no-op,
				// matching mergePatterns' behaviour.
				continue;
			}
			additions.push(p);
		}
	}

	// Baseline scalar actions come from defaults + machine. Machine overrides
	// defaults (the operator's prerogative); that interaction is unchanged.
	const baselineWrite: "block" | "confirm" = machine?.writeAction ?? def?.writeAction ?? "block";
	const baselineRead: "block" | "confirm" | "allow" = machine?.readAction ?? def?.readAction ?? "confirm";

	// Clamp the project layer to the baseline: the project may only make the
	// scalar actions MORE restrictive (ADR-0009). A weaker project value is
	// ignored with a warning, and the baseline is kept.
	let writeAction: "block" | "confirm" = baselineWrite;
	if (project?.writeAction !== undefined) {
		if (protectedActionRank(project.writeAction) < protectedActionRank(baselineWrite)) {
			console.error(`[pi-secured-setup] WARNING: Project-layer writeAction "${project.writeAction}" weakens the baseline "${baselineWrite}" and was ignored. The project layer can strengthen but not weaken the baseline (see ADR-0009).`);
		} else {
			writeAction = mostRestrictive(baselineWrite, project.writeAction) as "block" | "confirm";
		}
	}

	let readAction: "block" | "confirm" | "allow" = baselineRead;
	if (project?.readAction !== undefined) {
		if (protectedActionRank(project.readAction) < protectedActionRank(baselineRead)) {
			console.error(`[pi-secured-setup] WARNING: Project-layer readAction "${project.readAction}" weakens the baseline "${baselineRead}" and was ignored. The project layer can strengthen but not weaken the baseline (see ADR-0009).`);
		} else {
			readAction = mostRestrictive(baselineRead, project.readAction);
		}
	}

	return {
		patterns: [...baseline, ...additions],
		writeAction,
		readAction,
	};
}

/**
 * Merge command-rules config across three layers.
 * Each category is merged independently.
 *
 * Overly-broad `safe`/`moderate` patterns contributed by the project layer are
 * rejected (dropped) so affected commands fall back to `unknown` → confirm.
 * Defaults and machine layers are unaffected. See ADR-0009.
 */
export function mergeCommandRules(
	layers: [CommandRulesConfig | undefined, CommandRulesConfig | undefined, CommandRulesConfig | undefined],
): CommandRulesConfig {
	const [def, machine, project] = layers;

	const categories: (keyof CommandRulesConfig)[] = ["safe", "moderate", "dangerous", "external"];
	const result = {} as CommandRulesConfig;

	for (const cat of categories) {
		let projectCat = project?.[cat];
		if (projectCat && (cat === "safe" || cat === "moderate")) {
			projectCat = rejectBroadProjectPatterns(projectCat, cat);
		}
		result[cat] = mergePatterns([def?.[cat], machine?.[cat], projectCat]);
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
		"injection-rules.json",
		"security-policy.json",
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
 * Load the rate-limiting policy. Machine-only: a project-layer
 * `security-policy.json` cannot raise limits or disable rate limiting,
 * so a checked-in file is ignored with a warning. This follows the same
 * baseline-strengthening principle as `audit-config.json` and
 * `injection-rules.json` (ADR-0009): the project layer may strengthen
 * security but never weaken it.
 *
 * Resolution order: machine layer → shipped defaults → hard-coded
 * `DEFAULT_SECURITY_POLICY` fallback.
 */
export function loadSecurityPolicy(cwd: string): SecurityPolicy {
	const projectPath = resolve(projectConfigDir(cwd), "security-policy.json");
	if (existsSync(projectPath)) {
		console.error("[pi-secured-setup] WARNING: A project-layer security-policy.json was detected at .pi/security/security-policy.json and will be IGNORED. Rate-limiting policy is machine-only and cannot be configured by the project layer. A checked-in file cannot raise limits or disable rate limiting (see ADR-0009).");
	}
	return (
		readJsonFile<SecurityPolicy>(resolve(MACHINE_CONFIG_DIR, "security-policy.json")) ??
		readJsonFile<SecurityPolicy>(resolve(DEFAULTS_DIR, "security-policy.json")) ??
		DEFAULT_SECURITY_POLICY
	);
}

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

	// Injection rules are machine-only (ADR-0006). The project layer is
	// ignored entirely — a checked-in `.pi/security/injection-rules.json`
	// cannot weaken or disable detection. A detected project-layer file is
	// warned about so operators know their file had no effect.
	const projectInjectionPath = resolve(projectConfigDir(cwd), "injection-rules.json");
	if (existsSync(projectInjectionPath)) {
		console.error("[pi-secured-setup] WARNING: A project-layer injection-rules.json was detected at .pi/security/injection-rules.json and will be IGNORED. Injection detection rules are machine-only and cannot be configured by the project layer (see ADR-0006).");
	}
	const injectionRules: InjectionRulesConfig =
		readJsonFile<InjectionRulesConfig>(resolve(MACHINE_CONFIG_DIR, "injection-rules.json")) ??
		readJsonFile<InjectionRulesConfig>(resolve(DEFAULTS_DIR, "injection-rules.json")) ??
		{ patterns: [], threshold: 3 };

	// Rate-limiting policy is machine-only (same principle as audit-config
	// and injection-rules, ADR-0009): a checked-in `.pi/security/
	// security-policy.json` cannot raise limits or disable rate limiting.
	const securityPolicy = loadSecurityPolicy(cwd);

	const result: Config = {
		protectedPaths: mergeProtectedPaths(protectedPathsLayers),
		commandRules: mergeCommandRules(commandRulesLayers),
		allowedExternal: mergeAllowedExternal(allowedExternalLayers),
		audit: auditConfig,
		injection: injectionRules,
		securityPolicy,
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
