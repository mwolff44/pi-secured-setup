/**
 * Unit tests for lib/secret-scanner.ts
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
	isPlaceholder,
	isCommentLine,
	redactString,
	walkAndRedact,
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

	it("skips single-line comment strings", () => {
		const { result, redactions } = redactString("# password=\"supersecret123\"");
		assert.equal(redactions.length, 0);
		assert.equal(result, "# password=\"supersecret123\"");
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
