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

type CommandCategory = "safe" | "moderate" | "dangerous" | "external";

const CATEGORY_PRIORITY: CommandCategory[] = ["dangerous", "external", "moderate", "safe"];

/**
 * Classify a single command segment against the rule patterns.
 */
export function classifySegment(command: string, rules: Record<CommandCategory, string[]>): CommandCategory | null {
	for (const category of CATEGORY_PRIORITY) {
		const patterns = rules[category];
		for (const pattern of patterns) {
			try {
				const regex = new RegExp(pattern, "i");
				if (regex.test(command)) {
					return category;
				}
			} catch {
				// Skip invalid regex patterns
			}
		}
	}
	return null;
}

/**
 * Split a command string by shell operators into individual segments.
 * Handles quoting (single, double), subshells ($(...)), and backticks.
 * Splits on |, ;, &&, || (in that precedence order for || vs |).
 */
export function splitCommand(command: string): string[] {
	const segments: string[] = [];
	let current = "";
	let i = 0;

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

		current += ch;
		i++;
	}

	if (current.trim()) {
		segments.push(current.trim());
	}

	return segments;
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

	// No known pattern matched → unknown command → confirm
	if (highestCategory === null) {
		return {
			action: "confirm",
			message: `Unknown command — allow execution?\n\n  ${command}\n\nThis command doesn't match any known safety classification.`,
			category: undefined,
		};
	}

	// SAFE and MODERATE are auto-approved
	if (highestCategory === "safe") {
		return { action: "allow", category: "safe" };
	}

	if (highestCategory === "moderate") {
		return { action: "allow", category: "moderate" };
	}

	// DANGEROUS and EXTERNAL require confirmation
	const label = highestCategory === "dangerous" ? "Dangerous" : "External";
	return {
		action: "confirm",
		message: `⚠️ ${label} command — allow execution?\n\n  ${command}\n\nClassification: ${highestCategory.toUpperCase()}`,
		category: highestCategory,
	};
}
