/**
 * Unit tests for lib/secret-scanner.ts
 */
import { describe, it, beforeEach, afterEach, mock } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, rmSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { tmpdir } from "node:os";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import type { Config } from "../lib/config.js";
import { initAuditLog, _setAuditFileForTest } from "../lib/audit.js";
import type { AuditEntry } from "../lib/audit.js";
import {
	isPlaceholder,
	isCommentLine,
	redactString,
	walkAndRedact,
	walkAndRedactPEMOnly,
	resolveScanBudget,
	sumStringBytes,
	registerSecretScanner,
	DEFAULT_SCAN_BUDGET_BYTES,
	type Redaction,
} from "../lib/secret-scanner.js";

describe("isPlaceholder", () => {
	it("detects YOUR_ prefix", () => {
		assert.equal(isPlaceholder("YOUR_API_KEY"), true);
	});

	it("detects <placeholder>", () => {
		assert.equal(isPlaceholder("<insert-key-here>"), true);
	});

	it("detects xxx placeholder", () => {
		assert.equal(isPlaceholder("xxxxxx"), true);
	});

	it("detects *** placeholder", () => {
		assert.equal(isPlaceholder("***"), true);
	});

	it("detects REPLACE_ prefix", () => {
		assert.equal(isPlaceholder("REPLACE_WITH_KEY"), true);
	});

	it("detects example prefix", () => {
		assert.equal(isPlaceholder("example_key_value"), true);
	});

	it("does not flag real values", () => {
		assert.equal(isPlaceholder("AKIAIOSFODNN7EXAMPLE"), false);
		assert.equal(isPlaceholder("sk-ant-api03-real-key"), false);
	});
});

describe("isCommentLine", () => {
	it("detects # comments", () => {
		assert.equal(isCommentLine("# AWS_KEY=secret"), true);
	});

	it("detects // comments", () => {
		assert.equal(isCommentLine("// const key = 'secret'"), true);
	});

	it("detects -- comments", () => {
		assert.equal(isCommentLine("-- password: secret"), true);
	});

	it("detects /* comments", () => {
		assert.equal(isCommentLine("/* secret stuff */"), true);
	});

	it("does not flag non-comments", () => {
		assert.equal(isCommentLine('password = "secret"'), false);
		assert.equal(isCommentLine("const x = 1"), false);
	});

	it("handles leading whitespace", () => {
		assert.equal(isCommentLine("  # indented comment"), true);
	});
});

describe("redactString", () => {
	it("redacts AWS access keys", () => {
		const { result, redactions } = redactString("key=AKIAIOSFODNN7EXAMPLE");
		assert.ok(result.includes("***REDACTED:aws-access-key***"));
		assert.equal(redactions.length, 1);
		assert.equal(redactions[0].patternName, "aws-access-key");
	});

	it("redacts Anthropic keys", () => {
		const { result } = redactString("ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz");
		assert.ok(result.includes("***REDACTED:anthropic-key***"));
	});

	it("redacts private key headers", () => {
		const { result } = redactString("-----BEGIN RSA PRIVATE KEY-----");
		assert.ok(result.includes("***REDACTED:private-key***"));
	});

	it("redacts GitHub tokens", () => {
		const { result } = redactString("token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789a");
		assert.ok(result.includes("***REDACTED:github-token***"));
	});

	it("redacts DB connection strings", () => {
		const { result } = redactString("DATABASE_URL=postgres://user:pass@host:5432/db");
		assert.ok(result.includes("***REDACTED:db-connection***"));
	});

	it("redacts Slack tokens", () => {
		const { result } = redactString("SLACK_TOKEN=xoxb-XXXXXXXXXX-aaaaaaaaaaaaaaaa");
		assert.ok(result.includes("***REDACTED:slack-token***"));
	});

	it("redacts passwords in config", () => {
		const { result } = redactString('password="supersecret123"');
		assert.ok(result.includes("***REDACTED:password***"));
	});

	it("redacts unquoted passwords", () => {
		const { result, redactions } = redactString("password=MyS3cret123");
		assert.ok(redactions.length > 0, "should redact unquoted password");
		assert.ok(result.includes("***REDACTED:password***"));
	});

	it("redacts secrets on single-line comment strings by default (M1 Warp)", () => {
		// Commented-out credentials are extremely common in config files the
		// agent reads (# API_KEY=sk-ant-..., // password=hunter2). They must
		// not reach the LLM in plaintext. Comment-skipping is a display
		// concern, not a redaction concern (see M1 finding).
		const { result, redactions } = redactString("# password=\"supersecret123\"");
		assert.ok(redactions.length > 0, "should redact secret on comment line by default");
		assert.ok(result.includes("***REDACTED:password***"), "secret must be redacted");
	});

	it("redacts secrets on non-comment lines in multi-line strings", () => {
		const input = "# .env example\nAPI_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz";
		const { result, redactions } = redactString(input);
		assert.ok(redactions.length > 0, "should redact secret on second line");
		assert.ok(result.includes("***REDACTED:anthropic-key***"), "secret should be redacted");
		assert.ok(result.startsWith("# .env example\n"), "comment line should be preserved");
	});

	it("skips only comment lines in multi-line strings", () => {
		const input = "# comment\npassword=\"supersecret123\"\n# another comment";
		const { result, redactions } = redactString(input);
		assert.ok(redactions.length > 0, "should redact secret on non-comment line");
		assert.ok(result.includes("***REDACTED:password***"), "password should be redacted");
		assert.ok(result.includes("# comment"), "comment line preserved");
		assert.ok(result.includes("# another comment"), "another comment preserved");
	});

	it("redacts all secrets in multi-line strings with no comments", () => {
		const input = "aws=AKIAIOSFODNN7EXAMPLE\ndb=postgres://user:pass@host/db";
		const { result, redactions } = redactString(input);
		assert.ok(redactions.length >= 2, "should redact both secrets");
		assert.ok(result.includes("***REDACTED:aws-access-key***"));
		assert.ok(result.includes("***REDACTED:db-connection***"));
	});

	it("does not redact normal strings", () => {
		const { result, redactions } = redactString("just a normal log line");
		assert.equal(redactions.length, 0);
		assert.equal(result, "just a normal log line");
	});

	it("handles multiple secrets in one string", () => {
		const { result, redactions } = redactString(
			"aws=AKIAIOSFODNN7EXAMPLE db=postgres://user:pass@host/db",
		);
		assert.ok(result.includes("***REDACTED:aws-access-key***"));
		assert.ok(result.includes("***REDACTED:db-connection***"));
		assert.ok(redactions.length >= 2);
	});

	it("preserves surrounding text", () => {
		const { result } = redactString("The key is AKIAIOSFODNN7EXAMPLE in production");
		assert.ok(result.startsWith("The key is "));
		assert.ok(result.includes("in production"));
	});

	it("redacts entire multi-line PEM private key block", () => {
		const pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/y7\n-----END RSA PRIVATE KEY-----";
		const { result, redactions } = redactString(pem);
		assert.ok(redactions.length > 0, "should redact PEM key block");
		assert.ok(result.includes("***REDACTED:private-key***"), "result should contain redaction marker");
		assert.ok(!result.includes("MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn"), "PEM body should be redacted");
		assert.ok(!result.includes("END RSA PRIVATE KEY"), "END line should be redacted");
	});

	it("redacts EC private key block", () => {
		const pem = "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIJSJ\n-----END EC PRIVATE KEY-----";
		const { result, redactions } = redactString(pem);
		assert.ok(redactions.length > 0, "should redact EC key block");
		assert.ok(result.includes("***REDACTED:private-key***"));
		assert.ok(!result.includes("MHQCAQEEIJSJ"), "EC key body should be redacted");
	});

	it("does not redact fake PEM block", () => {
		const fake = "-----BEGIN FAKE KEY-----\nsome data\n-----END FAKE KEY-----";
		const { result, redactions } = redactString(fake);
		assert.equal(redactions.length, 0, "should not redact fake PEM block");
		assert.equal(result, fake);
	});

	it("redacts secrets on comment lines when skipCommentLines is false", () => {
		const input = "# password=MyS3cret123";
		const { result, redactions } = redactString(input, { skipCommentLines: false });
		assert.ok(redactions.length > 0, "should redact secret on comment line when skipCommentLines is false");
		assert.ok(result.includes("***REDACTED:password***"));
	});

	it("redacts secrets on comment lines by default (M1 Warp)", () => {
		// The old default (skipCommentLines: true) leaked commented-out
		// secrets to the LLM. The default is now false so commented
		// credentials are redacted. Callers may still opt out explicitly.
		const input = "# password=MyS3cret123";
		const { result, redactions } = redactString(input);
		assert.ok(redactions.length > 0, "should redact secret on comment line by default");
		assert.ok(result.includes("***REDACTED:password***"));
	});

	it("redacts commented-out AWS key in a .env-style line (M1 Warp)", () => {
		// Exact scenario from the Warp finding: a commented production key
		// in a config file the agent reads must not reach the LLM.
		const input = "# AWS_KEY=AKIAIOSFODNN7EXAMPLE";
		const { result, redactions } = redactString(input);
		assert.ok(redactions.length > 0, "commented AWS key must be redacted");
		assert.ok(result.includes("***REDACTED:aws-access-key***"));
	});
});

describe("walkAndRedact", () => {
	it("redacts secrets in nested objects", () => {
		const payload = {
			messages: [
				{ role: "user", content: "Here is my key: AKIAIOSFODNN7EXAMPLE" },
			],
		};
		const redactions: Redaction[] = [];
		walkAndRedact(payload, redactions);
		assert.ok(redactions.length > 0);
		assert.ok(
			(payload.messages[0] as { content: string }).content.includes("***REDACTED:aws-access-key***"),
		);
	});

	it("redacts secrets in arrays", () => {
		const arr = ["normal", "AKIAIOSFODNN7EXAMPLE", "also normal"];
		const redactions: Redaction[] = [];
		walkAndRedact(arr, redactions);
		assert.equal(redactions.length, 1);
		assert.ok(arr[1].includes("***REDACTED:aws-access-key***"));
	});

	it("handles non-string primitives", () => {
		const obj = { num: 42, bool: true, nil: null };
		const redactions: Redaction[] = [];
		walkAndRedact(obj, redactions);
		assert.equal(redactions.length, 0);
		assert.equal(obj.num, 42);
		assert.equal(obj.bool, true);
		assert.equal(obj.nil, null);
	});

	it("respects depth limit", () => {
		const deep = { a: { b: { c: { d: { e: "AKIAIOSFODNN7EXAMPLE" } } } } };
		const redactions: Redaction[] = [];
		walkAndRedact(deep, redactions, 0);
		// Should still work — depth 5 is well within limit of 50
		assert.ok(redactions.length > 0);
	});
});

// ── Scan budget helpers (ADR-0013) ─────────────────────────────────────

describe("resolveScanBudget", () => {
	function configWith(scanBudgetBytes?: number): Config {
		return {
			cwd: "/home/user/project",
			protectedPaths: { patterns: [], writeAction: "block", readAction: "confirm" },
			commandRules: { safe: [], moderate: [], dangerous: [], external: [] },
			allowedExternal: { paths: [] },
			audit: { maxFileSize: 10_000_000, maxFiles: 3 },
			injection: { patterns: [], threshold: 3 },
			...(scanBudgetBytes === undefined
				? {}
				: { securityPolicy: { toolCallsPerTurn: 100, confirmationsPerSession: 200, scanBudgetBytes } }),
		};
	}

	it("falls back to the shipped default when securityPolicy is absent", () => {
		assert.equal(resolveScanBudget(configWith()), DEFAULT_SCAN_BUDGET_BYTES);
		assert.equal(DEFAULT_SCAN_BUDGET_BYTES, 2 * 1024 * 1024, "shipped default is 2 MiB");
	});

	it("honours a positive machine-layer override", () => {
		assert.equal(resolveScanBudget(configWith(1024)), 1024);
		assert.equal(resolveScanBudget(configWith(64 * 1024 * 1024)), 64 * 1024 * 1024);
	});

	it("falls back to the default for zero, negative, or missing values", () => {
		assert.equal(resolveScanBudget(configWith(0)), DEFAULT_SCAN_BUDGET_BYTES);
		assert.equal(resolveScanBudget(configWith(-1)), DEFAULT_SCAN_BUDGET_BYTES);
	});
});

describe("sumStringBytes", () => {
	it("returns 0 for empty / non-string payloads", () => {
		assert.equal(sumStringBytes({}), 0);
		assert.equal(sumStringBytes({ num: 42, bool: true, nil: null }), 0);
	});

	it("sums UTF-8 byte lengths, not UTF-16 code units", () => {
		assert.equal(sumStringBytes("a"), 1);
		assert.equal(sumStringBytes("é"), 2); // 2 UTF-8 bytes
		assert.equal(sumStringBytes("中"), 3); // 3 UTF-8 bytes
		assert.equal(sumStringBytes({ a: "aa", b: ["中", "é"] }), 2 + 3 + 2);
	});

	it("walks nested objects and arrays", () => {
		const payload = { messages: [{ role: "user", content: "hello world" }] };
		assert.equal(sumStringBytes(payload), "user".length + "hello world".length);
	});

	it("respects the depth cap (no crash on deep nesting)", () => {
		let deep: unknown = "x";
		for (let i = 0; i < 60; i++) deep = { nested: deep };
		assert.doesNotThrow(() => sumStringBytes(deep));
	});
});

describe("walkAndRedactPEMOnly", () => {
	it("redacts real PEM private-key blocks", () => {
		const pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/y7\n-----END RSA PRIVATE KEY-----";
		const redactions: Redaction[] = [];
		const result = walkAndRedactPEMOnly(pem, redactions) as string;
		assert.ok(result.includes("***REDACTED:private-key***"));
		assert.equal(redactions.length, 1);
		assert.equal(redactions[0].patternName, "private-key");
	});

	it("does NOT run the line-by-line patterns (PEM-only pass)", () => {
		const text = "key=AKIAIOSFODNN7EXAMPLE and password=hunter2secret";
		const redactions: Redaction[] = [];
		const result = walkAndRedactPEMOnly(text, redactions) as string;
		assert.equal(result, text, "non-PEM secrets are left for the (skipped) full scan");
		assert.equal(redactions.length, 0);
	});

	it("walks nested payloads and passes non-strings through", () => {
		const payload = {
			num: 42,
			messages: [{ role: "user", content: "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIJSJ\n-----END EC PRIVATE KEY-----" }],
		};
		const redactions: Redaction[] = [];
		walkAndRedactPEMOnly(payload, redactions);
		assert.equal(redactions.length, 1);
		assert.ok((payload.messages[0] as { content: string }).content.includes("***REDACTED:private-key***"));
		assert.equal(payload.num, 42);
	});
});

// ── Registration: scan budget enforcement (ADR-0013) ───────────────────

describe("registerSecretScanner — scan budget (ADR-0013)", () => {
	let tempDir: string;
	let prevAuditFile: string;
	let pi: ExtensionAPI;
	let handlers: Record<string, Array<(event: any, ctx: any) => unknown>>;

	/** Tiny budget (1 KiB) so over-budget cases are cheap to build. */
	const TINY_BUDGET = 1024;

	function makeConfig(budget: number): Config {
		return {
			cwd: "/home/user/project",
			protectedPaths: { patterns: [], writeAction: "block", readAction: "confirm" },
			commandRules: { safe: [], moderate: [], dangerous: [], external: [] },
			allowedExternal: { paths: [] },
			audit: { maxFileSize: 10_000_000, maxFiles: 3 },
			injection: { patterns: [], threshold: 3 },
			securityPolicy: { toolCallsPerTurn: 100, confirmationsPerSession: 200, scanBudgetBytes: budget },
		};
	}

	function createMockPi(): {
		pi: ExtensionAPI;
		handlers: Record<string, Array<(event: any, ctx: any) => unknown>>;
	} {
		const handlers: Record<string, Array<(event: any, ctx: any) => unknown>> = {};
		const pi = {
			on(event: string, handler: (event: any, ctx: any) => unknown) {
				(handlers[event] ??= []).push(handler);
			},
			registerCommand() {},
		} as unknown as ExtensionAPI;
		return { pi, handlers };
	}

	function readAuditEntries(file: string): AuditEntry[] {
		if (!existsSync(file)) return [];
		const content = readFileSync(file, "utf-8").trim();
		if (!content) return [];
		const entries: AuditEntry[] = [];
		for (const line of content.split("\n")) {
			try {
				entries.push(JSON.parse(line) as AuditEntry);
			} catch {
				// skip malformed
			}
		}
		return entries;
	}

	beforeEach(() => {
		tempDir = mkdtempSync(resolve(tmpdir(), "pi-sec-budget-"));
		prevAuditFile = _setAuditFileForTest(resolve(tempDir, "audit.jsonl"));
		initAuditLog();
		const mockPi = createMockPi();
		pi = mockPi.pi;
		handlers = mockPi.handlers;
		registerSecretScanner(pi, () => makeConfig(TINY_BUDGET));

		// Reset per-turn scanner state.
		handlers["turn_start"][0]({ type: "turn_start", turnIndex: 0, timestamp: Date.now() }, { hasUI: false, ui: { notify: () => {} } });
	});

	afterEach(() => {
		_setAuditFileForTest(prevAuditFile);
		if (tempDir && existsSync(tempDir)) rmSync(tempDir, { recursive: true, force: true });
	});

	it("over-budget payload: exactly ONE secret.skipped audit entry, ONE notification, no silent skip", () => {
		const notify = mock.fn();
		const ctx = { hasUI: true, ui: { notify } };
		const payload = { messages: [{ role: "user", content: "x".repeat(TINY_BUDGET * 2) }] };

		const result = handlers["before_provider_request"][0](
			{ type: "before_provider_request", payload },
			ctx,
		);
		handlers["after_provider_response"][0]({ type: "after_provider_response", status: 200, headers: {} }, ctx);

		// Exactly one audit entry, and it is the skip event.
		const entries = readAuditEntries(resolve(tempDir, "audit.jsonl"));
		assert.equal(entries.length, 1, "exactly one audit entry for the over-budget request");
		assert.equal(entries[0].type, "secret.skipped");
		assert.equal(entries[0].severity, "warning");
		const details = entries[0].details as Record<string, unknown>;
		assert.equal(details.budget, TINY_BUDGET);
		assert.equal(typeof details.bytes, "number");
		assert.ok((details.bytes as number) > TINY_BUDGET);

		// Exactly one notification, mentioning the skip.
		assert.equal(notify.mock.calls.length, 1, "exactly one notification");
		const message = String((notify.mock.calls[0].arguments as unknown[])[0]);
		assert.ok(/secret scan skipped/i.test(message), `notification must mention the skip: ${message}`);

		// Payload unchanged (no secrets to redact) — handler returns undefined.
		assert.equal(result, undefined);
	});

	it("over-budget payload still redacts PEM private keys (budget must not bypass PEM redaction)", () => {
		const notify = mock.fn();
		const ctx = { hasUI: true, ui: { notify } };
		const pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/y7\n-----END RSA PRIVATE KEY-----";
		const payload = {
			messages: [
				{
					role: "user",
					content: `${pem}\nand also key=AKIAIOSFODNN7EXAMPLE in the same oversized message ${"y".repeat(TINY_BUDGET)}`,
				},
			],
		};

		handlers["before_provider_request"][0]({ type: "before_provider_request", payload }, ctx);
		handlers["after_provider_response"][0]({ type: "after_provider_response", status: 200, headers: {} }, ctx);

		const content = (payload as any).messages[0].content as string;
		assert.ok(content.includes("***REDACTED:private-key***"), "PEM key must still be redacted over budget");
		assert.ok(!content.includes("MIIEowIBAAKCAQEA"), "PEM body must not survive");

		// The line-by-line scan was skipped: the AWS key is NOT redacted,
		// and the audit says so (secret.skipped), plus the PEM redaction.
		assert.ok(content.includes("AKIAIOSFODNN7EXAMPLE"), "line-by-line scan is skipped over budget (documented)");
		const entries = readAuditEntries(resolve(tempDir, "audit.jsonl"));
		assert.equal(entries.filter((e) => e.type === "secret.skipped").length, 1, "one skip event");
		const pemEntries = entries.filter((e) => e.type === "secret.redacted");
		assert.equal(pemEntries.length, 1, "the PEM redaction is still audited");
		assert.equal((pemEntries[0].details as Record<string, unknown>).patternName, "private-key");

		// Notifications: skip + redacted.
		const messages = notify.mock.calls.map((c) => String((c.arguments as unknown[])[0]));
		assert.equal(messages.filter((m) => /secret scan skipped/i.test(m)).length, 1);
		assert.equal(messages.filter((m) => /secret\(s\) redacted/i.test(m)).length, 1);
	});

	it("under-budget payload: full scan, no skip event (regression guard)", () => {
		const ctx = { hasUI: false, ui: { notify: () => {} } };
		const payload = { messages: [{ role: "user", content: "key=AKIAIOSFODNN7EXAMPLE short message" }] };

		const result = handlers["before_provider_request"][0](
			{ type: "before_provider_request", payload },
			ctx,
		);

		const content = (payload as any).messages[0].content as string;
		assert.ok(content.includes("***REDACTED:aws-access-key***"), "full scan must run under budget");
		assert.equal(result, payload, "modified payload is returned");

		const entries = readAuditEntries(resolve(tempDir, "audit.jsonl"));
		assert.equal(entries.filter((e) => e.type === "secret.skipped").length, 0, "no skip event under budget");
		assert.equal(entries.filter((e) => e.type === "secret.redacted").length, 1);
	});

	it("counts skip notifications per turn (drained once)", () => {
		const notify = mock.fn();
		const ctx = { hasUI: true, ui: { notify } };
		const big = "z".repeat(TINY_BUDGET * 2);

		// Two over-budget requests within one turn.
		handlers["before_provider_request"][0]({ type: "before_provider_request", payload: { messages: [{ role: "user", content: big }] } }, ctx);
		handlers["before_provider_request"][0]({ type: "before_provider_request", payload: { messages: [{ role: "user", content: big }] } }, ctx);
		handlers["after_provider_response"][0]({ type: "after_provider_response", status: 200, headers: {} }, ctx);

		const skipMessages = notify.mock.calls
			.map((c) => String((c.arguments as unknown[])[0]))
			.filter((m) => /secret scan skipped/i.test(m));
		assert.equal(skipMessages.length, 1, "one skip notification per turn");
		assert.ok(/2 request\(s\)/.test(skipMessages[0]), "notification aggregates the skipped requests");
	});

	it("turn_start resets the per-turn skip counter", () => {
		const notify = mock.fn();
		const ctx = { hasUI: true, ui: { notify } };
		const big = "z".repeat(TINY_BUDGET * 2);

		handlers["before_provider_request"][0]({ type: "before_provider_request", payload: { messages: [{ role: "user", content: big }] } }, ctx);
		// Reset before the response fires.
		handlers["turn_start"][0]({ type: "turn_start", turnIndex: 1, timestamp: Date.now() }, ctx);
		handlers["after_provider_response"][0]({ type: "after_provider_response", status: 200, headers: {} }, ctx);

		assert.equal(notify.mock.calls.length, 0, "counter reset must suppress the notification");
	});
});
