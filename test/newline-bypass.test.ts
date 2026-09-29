/**
 * Regression tests for the greywall command.deny bypass.
 *
 * Greywall 0.3.7 splits a command string on `|`, `||`, `&&` and `;`, then
 * matches each segment by strict prefix. It does NOT split on newlines, so a
 * dangerous command placed on the second line of a script, in a heredoc, or in
 * a `.sh` file traverses `command.deny` unseen. Measured on 2026-08-17:
 *
 *   greywall --profile pi -c 'true; git push --force'   -> blocked
 *   greywall --profile pi -c 'true\ngit push --force'   -> PASSES
 *   greywall --profile pi -c 'bash script.sh'           -> PASSES
 *
 * The sandbox cannot close this, because it only ever sees an already-split
 * shell string. The bash gate can, because it inspects the tool call payload
 * with unanchored regexes tested against the whole segment. These tests pin
 * that property so it is not lost by accident.
 *
 * Nothing here executes a command: classifyCommand is a pure function that
 * takes a string and returns a verdict.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { classifyCommand, splitCommand } from "../lib/bash-gate.js";
import { loadConfig } from "../lib/config.js";

const config = loadConfig("/tmp/not-a-real-project");

describe("dangerous patterns must stay unanchored", () => {
	it("git push --force is matchable mid-string", () => {
		const pattern = "git push\\s+--force";
		assert.ok(
			config.commandRules.dangerous.includes(pattern),
			"the force-push rule disappeared from command-rules.json",
		);
		assert.equal(
			pattern.startsWith("^"),
			false,
			"anchoring this pattern would reopen the greywall newline bypass",
		);
	});
});

describe("newlines are not command separators", () => {
	it("a multi-line script stays a single segment", () => {
		const segments = splitCommand("echo avant\ngit push --force\necho apres");
		assert.equal(segments.length, 1);
		assert.ok(segments[0].includes("\n"));
	});
});

describe("the forms that defeat greywall are still caught", () => {
	const cases: Record<string, string> = {
		"semicolon (greywall blocks this one too)": "true; git push --force",
		"newline": "echo avant\ngit push --force\necho apres",
		"indented second line": "cd /repo\n  git push --force origin main\n",
		"here-string": 'bash <<< "git push --force"',
	};

	for (const [name, command] of Object.entries(cases)) {
		it(name, () => {
			const verdict = classifyCommand(command, config);
			assert.equal(verdict.category, "dangerous");
			assert.equal(verdict.action, "confirm");
		});
	}
});

describe("heredoc bodies are absorbed, so the force-push rule never sees them", () => {
	const heredoc = "bash <<EOF\ngit push --force\nEOF";

	it("only the opener is classified", () => {
		assert.deepEqual(splitCommand(heredoc), ["bash <<EOF"]);
	});

	it("it is still stopped, but by the unknown-command fallback", () => {
		const verdict = classifyCommand(heredoc, config);
		assert.equal(verdict.action, "confirm");
		assert.equal(verdict.category, undefined);
	});

	// Absorbing heredoc bodies is deliberate (P3-3): it stops a body line such
	// as `rm -rf /` from being misclassified as a standalone command. The cost
	// is that the heredoc form relies on `bash` staying unclassified. Since
	// command rules are additive, a project-level .pi/security/command-rules.json
	// can classify it and silently turn a confirmation into an auto-approval.
	it("classifying bash as safe or moderate would auto-approve the heredoc", () => {
		for (const category of ["safe", "moderate"] as const) {
			const relaxed = structuredClone(config);
			relaxed.commandRules[category] = [...relaxed.commandRules[category], "^bash\\b"];
			const verdict = classifyCommand(heredoc, relaxed);
			assert.equal(
				verdict.action,
				"allow",
				`documents the hazard: ^bash\\b in ${category} lets the heredoc through`,
			);
		}
	});
});

describe("no false positives", () => {
	it("a benign multi-line script is not dangerous", () => {
		const verdict = classifyCommand("git status\ngit diff --stat\nls -la", config);
		assert.notEqual(verdict.category, "dangerous");
	});

	it("a normal push is not dangerous", () => {
		const verdict = classifyCommand("git push origin main", config);
		assert.notEqual(verdict.category, "dangerous");
	});
});
