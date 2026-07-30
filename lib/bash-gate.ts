/**
 * Bash command classification — pure function.
 *
 * Classifies bash commands into SAFE / MODERATE / DANGEROUS / EXTERNAL
 * categories based on regex rules merged from defaults → machine → project.
 *
 * DANGEROUS → confirm
 * EXTERNAL  → confirm
 * MODERATE  → allow (logged)
 * SAFE      → allow (logged)
 * Unknown   → confirm
 *
 * Handles pipes by classifying each component and taking the most dangerous.
 */
import type { Config } from "./config.js";
import type { GuardVerdict } from "./boundary.js";
import { findSecrets } from "./secret-scanner.js";

type CommandCategory = "safe" | "moderate" | "dangerous" | "external";

const CATEGORY_PRIORITY: CommandCategory[] = ["dangerous", "external", "moderate", "safe"];

// ── Exfiltration detection ────────────────────────────────────────────

/**
 * A single exfiltration finding on a bash command.
 * - `kind: "secret"` — a credential pattern matched inside the command string.
 * - `kind: "exfil"`  — a suspicious exfiltration shape matched (data-carrying
 *   query param, base64 blob in a URL, command substitution feeding an
 *   external command, etc.).
 */
export interface ExfilFinding {
	kind: "secret" | "exfil";
	detail: string;
}

/**
 * Commands that move data off the local machine. When a command-substitution
 * (`$(...)` / `<file`) is detected inside one of these, we treat it as
 * exfiltration of whatever the substitution reads.
 *
 * The list intentionally favours tools whose PURPOSE is data egress. For
 * tools with both benign and egress subcommands (notably `docker`), we match
 * only the egress subcommands (`docker push`, `docker save`) to avoid noise
 * on benign invocations like `docker ps`. Bare commands like `aws`/`gcloud`/
 * `az`/`kubectl`/`helm` always talk to a remote control plane and are matched
 * wholesale — the heuristic still requires a paired file read, so a bare
 * `aws sts get-caller-identity` does NOT fire.
 */
const EXTERNAL_COMMANDS =
	/\b(?:curl|wget|ssh|scp|rsync|nc|netcat|dig|nslookup|host|aws|gcloud|az|kubectl|helm|ftp|sftp|lftp|openssl|socat|terraform)\b|docker\s+(?:push|save)\b/i;

/**
 * Query-parameter names that routinely carry exfiltrated payloads. We only
 * flag these specific shapes to avoid penalising every legitimate query string.
 */
const EXFIL_QUERY_PARAM = /[?&](?:d|data|q|query|msg|message|p|payload|c|cmd)=(?=[^&\s]+)/i;

/**
 * Base64-looking blob longer than 64 chars appearing as a URL argument.
 * Anchored to `?`/`=` so that long path components are not penalised.
 */
const BASE64_BLOB_IN_URL = /[?=][A-Za-z0-9+/]{64,}={0,2}(?=[&\s"']|$)/;

/**
 * Command substitution (`$(...)` or `< file`) that reads file contents.
 * `$(cat .env)`, `$(< .env)`, `` `cat ~/.ssh/id_rsa` ``, `$(awk ... file)`,
 * `$(python -c '...' file)` all match.
 */
const SUBSTITUTION_READING_FILES =
	/\$\(\s*(?:cat|head|tail|od|hexdump|base64|xxd|awk|sed|perl|python3|python|ruby|tee|dd|tar|zip)\s+/i;

/**
 * File-reading command followed (anywhere in the same piped segment) by a
 * path-like token — `/` (absolute path), `~` (home), or a dotfile prefix
 * (`.env`, `.ssh/...`, `.bashrc`). Used by the pipe-based exfil heuristic.
 *
 * `tee` is deliberately EXCLUDED here: in a pipe context `tee` is the sink
 * (it writes to a file), so `curl ... | tee file` is ingress, not exfil.
 * (`tee` remains in {@link SUBSTITUTION_READING_FILES} for the vanishingly
 * rare `$(tee ...)` shape, which is harmless to flag.)
 *
 * Path-like-token requirement keeps the heuristic conservative: `cat foo |
 * grep bar` has no path indicator and does not fire.
 */
const FILE_READ_WITH_PATH =
	/\b(?:cat|head|tail|od|hexdump|base64|xxd|awk|sed|perl|python3|python|ruby|dd|tar|zip)\b[^|]*?(?:\/|~|\.\w)/i;

/**
 * Process substitution (`<(...)`) that reads file contents.
 * `curl --data @<(cat .env)`, `wget --post-file=<(base64 ~/.ssh/id_rsa)`.
 * Distinct from `$(...)` command substitution and `$(< file)` redirection:
 * process substitution spawns a subprocess whose stdout is wired to a
 * /dev/fd/N path consumed by the external command. See N4.
 */
const PROCESS_SUBSTITUTION_READING_FILES =
	/<\(\s*(?:cat|head|tail|od|hexdump|base64|xxd|awk|sed|perl|python3|python|ruby|tee|dd|tar|zip)\s+/i;

/**
 * Detect exfiltration indicators in a bash command string.
 *
 * Returns one {@link ExfilFinding} per distinct indicator. Does NOT redact —
 * the caller is responsible for redacting the command before audit logging
 * (see `redactString`).
 *
 * False-positive posture: query-param and base64 rules only fire on the
 * specific shapes documented above; benign URLs without those shapes do not
 * produce `exfil` findings. The substitution and pipe heuristics only fire on
 * the COMBINATION of an external egress tool AND a file read, so benign
 * standalone invocations (`aws sts get-caller-identity`, `docker ps`) do not.
 *
 * BEST-EFFORT HEURISTIC — not a boundary. This function only escalates a
 * verdict to `confirm`; the command-classification layer ({@link
 * classifyCommand}) is the real gate. It cannot catch every exfil channel (a
 * custom script like `./exfil.sh .env`, an interpreted one-liner with no
 * recognisable tool name, an encrypted tunnel, etc.), and that is by design:
 * the goal is to catch the common, recognisable exfil shapes without flooding
 * benign dev commands with confirmation prompts.
 */
export function detectExfiltration(command: string): ExfilFinding[] {
	const findings: ExfilFinding[] = [];

	// (a) Secret-in-command — reuse the scanner's pattern table.
	const secrets = findSecrets(command);
	for (const { patternName } of secrets) {
		findings.push({ kind: "secret", detail: patternName });
	}

	// (b) Exfiltration shapes.
	if (EXFIL_QUERY_PARAM.test(command)) {
		findings.push({ kind: "exfil", detail: "data-carrying query parameter" });
	}

	if (BASE64_BLOB_IN_URL.test(command)) {
		findings.push({ kind: "exfil", detail: "large base64 blob in URL argument" });
	}

	// Command substitution feeding an external command.
	// Detect `$(...)` reading files OR `< file` redirection inside the same
	// command as an external tool.
	if (EXTERNAL_COMMANDS.test(command)) {
		if (SUBSTITUTION_READING_FILES.test(command)) {
			findings.push({
				kind: "exfil",
				detail: "command substitution reading files feeds external command",
			});
		} else if (/\$\(\s*<\s*\S+/i.test(command) || /`\s*(?:cat|head|tail|base64)\s+/i.test(command)) {
			findings.push({
				kind: "exfil",
				detail: "command substitution reading files feeds external command",
			});
		} else if (PROCESS_SUBSTITUTION_READING_FILES.test(command)) {
			// Process substitution <(cat .env) feeding an external command (N4).
			findings.push({
				kind: "exfil",
				detail: "process substitution reading files feeds external command",
			});
		}
	}

	// Pipe-based exfil: a file-reading command on the LEFT of a pipe feeds an
	// external egress command on the RIGHT. Direction matters — ingress
	// (external LEFT, file-write RIGHT, e.g. `curl ... | tee file`) is NOT
	// flagged, because nothing on the local machine is leaving via the pipe.
	// A doubled `||` is logical OR, not a pipe, and is masked out first.
	const hasPipe = command.replace(/\|\|/g, "  ").includes("|");
	if (hasPipe) {
		const externalMatch = EXTERNAL_COMMANDS.exec(command);
		if (
			externalMatch !== null &&
			FILE_READ_WITH_PATH.test(command.slice(0, externalMatch.index))
		) {
			findings.push({
				kind: "exfil",
				detail: "piped file read feeds external command",
			});
		}
	}

	return findings;
}

/**
 * Compile a list of command-rule patterns into RegExp instances, skipping
 * patterns that are not valid regex. Compiled with the case-insensitive
 * flag to match the original `new RegExp(pattern, "i")` semantics.
 */
function compilePatterns(patterns: string[]): RegExp[] {
	const compiled: RegExp[] = [];
	for (const pattern of patterns) {
		try {
			compiled.push(new RegExp(pattern, "i"));
		} catch {
			// Skip invalid regex patterns (preserves prior behaviour).
		}
	}
	return compiled;
}

/**
 * L3: memoised compilation cache. Keyed by the rules object identity (a
 * `WeakMap` so a reloaded config's old rules object is garbage-collected).
 * `config.commandRules` is stable across calls within a session, so repeat
 * classifications reuse the compiled regexes instead of recompiling the
 * whole rule set on every call. Recompiles only when the rules object
 * identity changes (e.g. `loadConfig` on a new session).
 */
const _regexCache = new WeakMap<Record<CommandCategory, string[]>, Record<CommandCategory, RegExp[]>>();

function getCompiledRules(rules: Record<CommandCategory, string[]>): Record<CommandCategory, RegExp[]> {
	let compiled = _regexCache.get(rules);
	if (!compiled) {
		compiled = {
			safe: compilePatterns(rules.safe),
			moderate: compilePatterns(rules.moderate),
			dangerous: compilePatterns(rules.dangerous),
			external: compilePatterns(rules.external),
		};
		_regexCache.set(rules, compiled);
	}
	return compiled;
}

/**
 * Test-only: return the cached compiled regexes for a given rules object,
 * or `undefined` if not yet compiled. Lets the L3 test assert that repeat
 * `classifySegment` calls reuse the SAME RegExp instances (identity) rather
 * than recompiling.
 */
export function _compiledRegexesForTest(
	rules: Record<CommandCategory, string[]>,
): Record<CommandCategory, RegExp[]> | undefined {
	return _regexCache.get(rules);
}

/**
 * Classify a single command segment against the rule patterns.
 *
 * Compiled regexes are memoised per rules object (L3): repeat calls with the
 * same `rules` reference reuse the cached `RegExp` instances instead of
 * recompiling.
 */
export function classifySegment(command: string, rules: Record<CommandCategory, string[]>): CommandCategory | null {
	const compiled = getCompiledRules(rules);
	for (const category of CATEGORY_PRIORITY) {
		for (const regex of compiled[category]) {
			if (regex.test(command)) {
				return category;
			}
		}
	}
	return null;
}

/**
 * Split a command string by shell operators into individual segments.
 *
 * Handles quoting (single, double), subshells (`$(...)`), backticks, process
 * substitution (`<(...)` / `>(...)`), and heredocs (`<<EOF`, `<<'EOF'`,
 * `<<-EOF`). Splits on `|`, `;`, `&&`, `||` (in that precedence order for
 * `||` vs `|`).
 *
 * Heredoc bodies are absorbed and never emitted as segments — so a body line
 * like `rm -rf /` inside a heredoc is not classified as a standalone command
 * (P3-3). Process-substitution interiors are emitted as additional segments,
 * mirroring `$(...)` handling.
 */
export function splitCommand(command: string): string[] {
	const segments: string[] = [];
	let current = "";
	let i = 0;
	// FIFO of heredoc bodies to skip once the opener line ends. Each entry is
	// the delimiter to match on its own line, plus whether `<<-` tab-stripping
	// applies. Multiple queued heredocs (e.g. `cmd <<A <<B`) are consumed in
	// order at the next newline, matching bash's input-stream ordering.
	const heredocQueue: { delim: string; stripTabs: boolean }[] = [];

	while (i < command.length) {
		const ch = command[i];

		// Handle single-quoted strings
		if (ch === "'") {
			current += ch;
			i++;
			while (i < command.length && command[i] !== "'") {
				current += command[i];
				i++;
			}
			if (i < command.length) {
				current += command[i];
				i++;
			}
			continue;
		}

		// Handle double-quoted strings
		if (ch === '"') {
			current += ch;
			i++;
			while (i < command.length && command[i] !== '"') {
				if (command[i] === "\\" && i + 1 < command.length) {
					current += command[i] + command[i + 1];
					i += 2;
				} else {
					current += command[i];
					i++;
				}
			}
			if (i < command.length) {
				current += command[i];
				i++;
			}
			continue;
		}

		// Handle $(...) subshells
		if (ch === "$" && i + 1 < command.length && command[i + 1] === "(") {
			const start = i;
			let depth = 1;
			current += command[i] + command[i + 1];
			i += 2;
			while (i < command.length && depth > 0) {
				const innerCh = command[i];

				// TODO: Quote-handling logic is duplicated from the top-level loop.
				// If more nesting types are added, extract into a shared helper.
				if (innerCh === "'") {
					current += innerCh;
					i++;
					while (i < command.length && command[i] !== "'") {
						current += command[i];
						i++;
					}
					if (i < command.length) { current += command[i]; i++; }
					continue;
				}

				if (innerCh === '"') {
					current += innerCh;
					i++;
					while (i < command.length && command[i] !== '"') {
						if (command[i] === "\\" && i + 1 < command.length) {
							current += command[i] + command[i + 1];
							i += 2;
						} else {
							current += command[i];
							i++;
						}
					}
					if (i < command.length) { current += command[i]; i++; }
					continue;
				}

				if (innerCh === "(") depth++;
				if (innerCh === ")") depth--;
				current += innerCh;
				i++;
			}
			// Extract inner command for separate classification
			const innerStart = start + 2;
			const innerEnd = i - 1;
			if (innerEnd > innerStart) {
				segments.push(command.slice(innerStart, innerEnd).trim());
			}
			continue;
		}

		// Handle process substitution <(...) and >(...) — extract the interior
		// as a separate segment, mirroring $(...) handling (P3-3).
		if ((ch === "<" || ch === ">") && i + 1 < command.length && command[i + 1] === "(") {
			const start = i;
			let depth = 1;
			current += command[i] + command[i + 1];
			i += 2;
			while (i < command.length && depth > 0) {
				const innerCh = command[i];

				if (innerCh === "'") {
					current += innerCh;
					i++;
					while (i < command.length && command[i] !== "'") {
						current += command[i];
						i++;
					}
					if (i < command.length) {
						current += command[i];
						i++;
					}
					continue;
				}

				if (innerCh === '"') {
					current += innerCh;
					i++;
					while (i < command.length && command[i] !== '"') {
						if (command[i] === "\\" && i + 1 < command.length) {
							current += command[i] + command[i + 1];
							i += 2;
						} else {
							current += command[i];
							i++;
						}
					}
					if (i < command.length) {
						current += command[i];
						i++;
					}
					continue;
				}

				if (innerCh === "(") depth++;
				if (innerCh === ")") depth--;
				current += innerCh;
				i++;
			}
			const innerStart = start + 2;
			const innerEnd = i - 1;
			if (innerEnd > innerStart) {
				segments.push(command.slice(innerStart, innerEnd).trim());
			}
			continue;
		}

		// Handle heredoc openers <<DELIM, <<-DELIM, <<'DELIM', <<"DELIM"
		// (but NOT <<< here-strings). The body is absorbed at the next newline
		// and never emitted as segments, so a body line like `rm -rf /` is not
		// misclassified as a standalone command (P3-3).
		if (
			ch === "<" &&
			i + 1 < command.length &&
			command[i + 1] === "<" &&
			!(i + 2 < command.length && command[i + 2] === "<")
		) {
			let j = i + 2;
			let stripTabs = false;
			if (j < command.length && command[j] === "-") {
				stripTabs = true;
				j++;
			}
			// Skip spaces/tabs between `<<` and the delimiter.
			while (j < command.length && (command[j] === " " || command[j] === "\t")) {
				j++;
			}
			let delim = "";
			if (j < command.length && (command[j] === "'" || command[j] === '"' || command[j] === "\\")) {
				const quote = command[j];
				if (quote === "\\") {
					j++;
					if (j < command.length) {
						delim = command[j];
						j++;
					}
				} else {
					j++;
					while (j < command.length && command[j] !== quote) {
						delim += command[j];
						j++;
					}
					if (j < command.length && command[j] === quote) {
						j++;
					}
				}
			} else {
				while (j < command.length && !/[\s;|&<>()`'"]/.test(command[j])) {
					delim += command[j];
					j++;
				}
			}
			// Append the opener (e.g. `<<EOF`, `<<'EOF'`, `<<-EOF`) so the
			// opener command is classified as a single unit.
			current += command.slice(i, j);
			if (delim) {
				heredocQueue.push({ delim, stripTabs });
			}
			i = j;
			continue;
		}

		// Handle backtick subshells
		if (ch === "`") {
			const start = i;
			current += ch;
			i++;
			while (i < command.length && command[i] !== "`") {
				current += command[i];
				i++;
			}
			if (i < command.length) {
				current += command[i];
				i++;
			}
			// Extract inner command
			const inner = command.slice(start + 1, i - 1).trim();
			if (inner) {
				segments.push(inner);
			}
			continue;
		}

		// Handle || (must check before |)
		if (ch === "|" && i + 1 < command.length && command[i + 1] === "|") {
			if (current.trim()) segments.push(current.trim());
			current = "";
			i += 2;
			continue;
		}

		// Handle &&
		if (ch === "&" && i + 1 < command.length && command[i + 1] === "&") {
			if (current.trim()) segments.push(current.trim());
			current = "";
			i += 2;
			continue;
		}

		// Handle | (pipe)
		if (ch === "|") {
			if (current.trim()) segments.push(current.trim());
			current = "";
			i++;
			continue;
		}

		// Handle ;
		if (ch === ";") {
			if (current.trim()) segments.push(current.trim());
			current = "";
			i++;
			continue;
		}

		// Handle newline: if heredoc bodies are pending, absorb them now so
		// they are never emitted as command segments (P3-3). When no heredoc
		// is pending, a newline is treated as an ordinary character (preserves
		// pre-existing behaviour — newlines are not command separators here).
		if (ch === "\n") {
			if (heredocQueue.length > 0) {
				if (current.trim()) {
					segments.push(current.trim());
					current = "";
				}
				i++; // consume the opener line's terminating newline
				while (heredocQueue.length > 0) {
					const hd = heredocQueue.shift()!;
					let lineStart = i;
					let found = false;
					while (lineStart <= command.length) {
						let lineEnd = lineStart;
						while (lineEnd < command.length && command[lineEnd] !== "\n") {
							lineEnd++;
						}
						let line = command.slice(lineStart, lineEnd);
						if (hd.stripTabs) {
							line = line.replace(/^\t+/, "");
						}
						if (line === hd.delim) {
							found = true;
							i = lineEnd < command.length ? lineEnd + 1 : command.length;
							break;
						}
						if (lineEnd >= command.length) {
							break;
						}
						lineStart = lineEnd + 1;
					}
					if (!found) {
						// Unterminated heredoc — absorb the remainder of input.
						i = command.length;
						heredocQueue.length = 0;
						break;
					}
				}
				continue;
			}
			current += ch;
			i++;
			continue;
		}

		current += ch;
		i++;
	}

	if (current.trim()) {
		segments.push(current.trim());
	}

	return segments;
}

/**
 * Detect shell brace expansion in a segment.
 *
 * Brace expansion (`{a,b}`, `{a,b,c}`, `{1..10}`) can hide dangerous argument
 * sets behind a compact notation, so any segment containing it is escalated to
 * confirmation (P3-3). Parameter expansion (`${VAR}`) is explicitly excluded.
 *
 * Conservative by design: an awk script like `awk '{print $1, $2}'` will also
 * match (comma inside braces) — escalation is preferred over silent allow.
 */
export function containsBraceExpansion(segment: string): boolean {
	const re = /\{([^{}]*)\}/g;
	let m: RegExpExecArray | null;
	while ((m = re.exec(segment)) !== null) {
		const inner = m[1];
		const braceIdx = m.index;
		// Skip `${...}` parameter expansion.
		if (braceIdx > 0 && segment[braceIdx - 1] === "$") {
			continue;
		}
		if (inner.includes(",") || /\.\./.test(inner)) {
			return true;
		}
	}
	return false;
}

/**
 * Classify a bash command string.
 *
 * @param command — The full bash command string
 * @param config  — Merged runtime configuration
 * @returns GuardVerdict with an extra `category` in details for audit
 */
export function classifyCommand(
	command: string,
	config: Config,
): GuardVerdict & { category?: CommandCategory } {
	const segments = splitCommand(command);

	let highestCategory: CommandCategory | null = null;
	const rules = config.commandRules;

	for (const segment of segments) {
		if (!segment) continue;
		const cat = classifySegment(segment, rules);
		if (cat !== null) {
			if (highestCategory === null) {
				highestCategory = cat;
			} else if (
				CATEGORY_PRIORITY.indexOf(cat) < CATEGORY_PRIORITY.indexOf(highestCategory)
			) {
				highestCategory = cat;
			}
		}
	}

	// Brace-expansion escalation: any segment carrying brace expansion is
	// forced to at least `confirm`, even when the base classification would
	// `allow` (P3-3).
	const braceEscalate = segments.some((s) => !!s && containsBraceExpansion(s));

	// No known pattern matched → unknown command → confirm
	if (highestCategory === null) {
		const message = braceEscalate
			? `Unknown command with brace expansion — allow execution?\n\n  ${command}\n\nBrace expansion can hide dangerous argument sets.`
			: `Unknown command — allow execution?\n\n  ${command}\n\nThis command doesn't match any known safety classification.`;
		return {
			action: "confirm",
			message,
			category: undefined,
		};
	}

	// SAFE and MODERATE are auto-approved — unless brace expansion escalates.
	if (highestCategory === "safe" || highestCategory === "moderate") {
		if (braceEscalate) {
			return {
				action: "confirm",
				message: `⚠️ Brace expansion detected — allow execution?\n\n  ${command}\n\nBrace expansion can hide dangerous argument sets. Classification: ${highestCategory.toUpperCase()}`,
				category: highestCategory,
			};
		}
		return { action: "allow", category: highestCategory };
	}

	// DANGEROUS and EXTERNAL require confirmation
	const label = highestCategory === "dangerous" ? "Dangerous" : "External";
	return {
		action: "confirm",
		message: `⚠️ ${label} command — allow execution?\n\n  ${command}\n\nClassification: ${highestCategory.toUpperCase()}`,
		category: highestCategory,
	};
}
