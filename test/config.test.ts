/**
 * Unit tests for lib/config.ts — merge logic
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mergePatterns } from "../lib/config.js";

describe("mergePatterns", () => {
	it("merges additive layers", () => {
		const result = mergePatterns([["a", "b"], ["c", "d"]]);
		assert.deepEqual(result, ["a", "b", "c", "d"]);
	});

	it("handles undefined layers", () => {
		const result = mergePatterns([["a"], undefined, ["c"]]);
		assert.deepEqual(result, ["a", "c"]);
	});

	it("excludes with ! prefix from earlier layers", () => {
		const result = mergePatterns([
			["*.key", "*.pem", "*.env"],
			["!*.pem", "extra-pattern"],
		]);
		assert.deepEqual(result, ["*.key", "*.env", "extra-pattern"]);
	});

	it("exclusion of non-existent pattern is a no-op", () => {
		const result = mergePatterns([
			["a"],
			["!nonexistent"],
		]);
		assert.deepEqual(result, ["a"]);
	});

	it("all three layers merge correctly", () => {
		const result = mergePatterns([
			["env", "key", "pem"],
			["!key", "custom"],
			["!pem", "project-secret"],
		]);
		assert.deepEqual(result, ["env", "custom", "project-secret"]);
	});

	it("empty layers produce empty result", () => {
		assert.deepEqual(mergePatterns([]), []);
		assert.deepEqual(mergePatterns([undefined, undefined]), []);
	});

	it("duplicate patterns are preserved across layers", () => {
		const result = mergePatterns([["a"], ["a"]]);
		assert.deepEqual(result, ["a", "a"]);
	});

	it("excludes patterns case-insensitively", () => {
		const result = mergePatterns([["*.pem"], ["!*.PEM"]]);
		assert.deepEqual(result, [], "case-insensitive exclusion should remove *.pem");
	});

	it("exclusion removes all inherited duplicates of a pattern", () => {
		const result = mergePatterns([
			["a", "a"],
			["!a"],
		]);
		assert.deepEqual(result, [], "exclusion should remove all inherited copies");
	});
});
