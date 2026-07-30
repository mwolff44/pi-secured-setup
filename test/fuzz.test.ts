/**
 * Fuzz / property tests — "never throws, never hangs" over randomized inputs.
 *
 * Two pure functions sit on the hot path of the bash gate and protected
 * paths: {@link splitCommand} and {@link matchGlob}. Both accept
 * attacker-controlled strings (a bash command / a glob pattern), so a
 * regex-engine path that hangs or a parser that throws would be a
 * denial-of-service vector. This harness throws ~250 randomized inputs
 * at each function — including adversarial shapes (deeply nested
 * parens, many globstars, mixed quotes) — and asserts:
 *
 *   - the function never throws, AND
 *   - each call completes well under the 500 ms ReDoS budget.
 *
 * The RNG is seeded so the corpus is deterministic across runs / CI.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { splitCommand } from "../lib/bash-gate.js";
import { matchGlob } from "../lib/protected-paths.js";

// ── Deterministic PRNG (mulberry32) ───────────────────────────────────

/**
 * Seedable PRNG so the fuzz corpus is reproducible in CI. Returns a
 * function producing floats in [0, 1).
 */
function mulberry32(seed: number): () => number {
	let s = seed >>> 0;
	return function () {
		s = (s + 0x6d2b79f5) >>> 0;
		let t = Math.imul(s ^ (s >>> 15), 1 | s);
		t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
		return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
	};
}

// ── Character pools ───────────────────────────────────────────────────

const SHELL_CHARS = "()[]{}<>|&; \t\n'\"`$\\=/*?abcdef0123456789.";
const GLOB_CHARS = "*?/[]{}().+^abcdef0123456789_-";
const PATH_CHARS = "abcdef0123456789_-.\\/";

const REENTRANT_SEED = 0xc0ffee;

/** Generate `n` random strings of length up to `maxLen` from `pool`. */
function randomStrings(
	rng: () => number,
	n: number,
	maxLen: number,
	pool: string,
): string[] {
	const out: string[] = [];
	for (let i = 0; i < n; i++) {
		const len = 1 + Math.floor(rng() * maxLen);
		let s = "";
		for (let j = 0; j < len; j++) {
			s += pool[Math.floor(rng() * pool.length)];
		}
		out.push(s);
	}
	return out;
}

/** Build a string of `n` repeated `token`s — adversarial nesting. */
function repeated(token: string, n: number): string {
	let s = "";
	for (let i = 0; i < n; i++) s += token;
	return s;
}

// ── Corpus builders ───────────────────────────────────────────────────

/**
 * Build the splitCommand corpus: random shell-y strings plus a set of
 * committed adversarial shapes (deeply nested subshells, heredoc-like
 * sequences, many globstars, unterminated quotes, command substitution
 * chains). Adversarial shapes are hardcoded so the fuzz always visits
 * them even if the random pool misses them.
 */
function buildSplitCommandCorpus(): string[] {
	const rng = mulberry32(REENTRANT_SEED ^ 0x5ac0ffee);
	const inputs: string[] = [];

	// (1) ~120 purely random shell-ish strings, length 1..80.
	inputs.push(...randomStrings(rng, 150, 80, SHELL_CHARS));

	// (2) ~50 longer random strings, length 80..400 (parser depth stress).
	inputs.push(...randomStrings(rng, 60, 400, SHELL_CHARS));

	// (3) Adversarial shapes — committed so they are always exercised.
	inputs.push(repeated("(", 200)); // deeply nested subshell openers
	inputs.push(repeated(")", 200));
	inputs.push(`echo ${repeated("$(cat ", 40)}x${repeated(")", 40)}`); // nested command sub
	inputs.push(repeated("`", 100)); // unterminated backticks
	inputs.push(repeated('"', 100)); // unterminated double quotes
	inputs.push(repeated("'", 100)); // unterminated single quotes
	inputs.push(`cmd ${repeated("<<EOF\nbody\nEOF\n", 20)}`); // heredoc run
	inputs.push(`cmd <<'EOF'\n${repeated("not-the-delim\n", 200)}EOF`); // long heredoc body
	inputs.push(repeated("a | ", 200)); // long pipe chain
	inputs.push(repeated("a && ", 200)); // long && chain
	inputs.push(repeated("a ; ", 200)); // long ;-chain
	inputs.push(`echo ${repeated("<(cat x) ", 40)}`); // process substitution
	inputs.push(repeated("${", 100) + repeated("}", 100)); // unbalanced expansion
	inputs.push("$(" + repeated("echo ", 200)); // unbalanced command sub
	inputs.push("\\"); // dangling escape
	inputs.push("\\u0000"); // NUL-ish escape (no actual NUL — invalid in JS string)
	inputs.push("echo \n\n\n\n"); // trailing newlines
	inputs.push(" "); // single space
	inputs.push(""); // empty string (also handled by randomStrings length>=1, but explicit)
	inputs.push("\x00"); // actual NUL byte
	return inputs;
}

/**
 * Build the matchGlob corpus: (pattern, path) pairs. Patterns mix
 * globstars, single stars, `?`, character classes, and regex specials
 * that the matcher must escape. Adversarial patterns (many globstars,
 * many single stars beyond the documented caps) are committed so the
 * ReDoS guards are always exercised.
 */
function buildMatchGlobCorpus(): Array<{ pattern: string; path: string }> {
	const rngP = mulberry32(REENTRANT_SEED ^ 0x9ab1de);
	const rngPath = mulberry32(REENTRANT_SEED ^ 0x4a5e01);
	const pairs: Array<{ pattern: string; path: string }> = [];

	// (1) ~120 (random pattern, random path).
	const patterns = randomStrings(rngP, 190, 60, GLOB_CHARS);
	const paths = randomStrings(rngPath, 190, 120, PATH_CHARS);
	for (let i = 0; i < patterns.length; i++) {
		pairs.push({ pattern: patterns[i], path: paths[i] ?? paths[0] });
	}

	// (2) Adversarial patterns — committed so they always run.
	const advPatterns = [
		repeated("*", 64), // 64 single stars (far past the 16 cap)
		repeated("**/", 40), // 40 globstars (past the 8 cap)
		"*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*.txt", // classic ReDoS shape (16 stars)
		"*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*.txt", // 19 stars
		repeated("?", 300), // many single-char wildcards
		"*." + repeated("*", 50), // globstars + single stars
		"**/**/**/**/**/**/**/**/*.env", // 8 globstars (at the cap)
		"[a-z" + repeated("0-9", 100) + "]", // malformed char class
		repeated("[", 100), // unterminated char class
		repeated("(", 100), // unescaped regex openers
		"x".repeat(300), // over-length pattern (>256 cap)
		"", // empty pattern
		"*.env",
		"**/*.key",
		"*secret*",
	];
	const advPaths = [
		"/home/user/project/.env",
		"/deep/nested/path/server.key",
		"some/secret/config.yaml",
		"x".repeat(300),
		"",
		"/a/b/c/d/e/f/g/h/i/j/k/.env",
		"keyboard.ts",
	];
	for (let i = 0; i < advPatterns.length; i++) {
		pairs.push({ pattern: advPatterns[i], path: advPaths[i % advPaths.length] });
	}
	return pairs;
}

// ── Tests ─────────────────────────────────────────────────────────────

describe("fuzz: splitCommand never throws or hangs", () => {
	const corpus = buildSplitCommandCorpus();
	const TIMEOUT_MS = 500;

	it(`runs ${corpus.length}+ randomized/adversarial inputs without crashing`, () => {
		assert.ok(corpus.length >= 200, `corpus must have >=200 inputs, got ${corpus.length}`);
		for (const input of corpus) {
			assert.doesNotThrow(() => {
				const segments = splitCommand(input);
				assert.ok(Array.isArray(segments), "splitCommand must always return an array");
			}, `splitCommand threw on input: ${JSON.stringify(input).slice(0, 80)}`);
		}
	});

	it("completes every call within the ReDoS budget (500 ms each)", () => {
		for (const input of corpus) {
			const start = Date.now();
			splitCommand(input);
			const elapsed = Date.now() - start;
			assert.ok(
				elapsed < TIMEOUT_MS,
				`splitCommand took ${elapsed}ms on input: ${JSON.stringify(input).slice(0, 80)}`,
			);
		}
	});
});

describe("fuzz: matchGlob never throws or hangs", () => {
	const corpus = buildMatchGlobCorpus();
	const TIMEOUT_MS = 500;

	it(`runs ${corpus.length}+ randomized/adversarial inputs without crashing`, () => {
		assert.ok(corpus.length >= 200, `corpus must have >=200 inputs, got ${corpus.length}`);
		for (const { pattern, path } of corpus) {
			assert.doesNotThrow(() => {
				const result = matchGlob(pattern, path);
				assert.equal(typeof result, "boolean", "matchGlob must always return a boolean");
			}, `matchGlob threw on pattern=${JSON.stringify(pattern).slice(0, 80)} path=${JSON.stringify(path).slice(0, 80)}`);
		}
	});

	it("completes every call within the ReDoS budget (500 ms each)", () => {
		for (const { pattern, path } of corpus) {
			const start = Date.now();
			matchGlob(pattern, path);
			const elapsed = Date.now() - start;
			assert.ok(
				elapsed < TIMEOUT_MS,
				`matchGlob took ${elapsed}ms on pattern=${JSON.stringify(pattern).slice(0, 80)}`,
			);
		}
	});
});
