# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.1] - 2026-08-17

### Fixed
- Injection scanner no longer scans the trusted system prompt. The system prompt is agent infrastructure, not user input, and wrapping legitimate examples of injection phrasing inside it (e.g. an `AGENTS.md` rule that quotes "Ignore previous instructions" to describe what to watch for) in `[UNTRUSTED CONTENT]` markers corrupted the context of smaller / local models and could crash the session (issue #14). The scanner now skips the well-known system-prompt carrier locations across every provider pi ships: the top-level `system` (Anthropic) and `systemInstruction` (Google) fields, and messages carrying `role: "system"` or `role: "developer"` (OpenAI Chat / Codex / Anthropic developer role). User messages, tool results, and fetched content are still scanned. The walk remains provider-agnostic — it skips a bounded allowlist of trusted carriers rather than parsing provider message structure (ADR-0002/0006 preserved).
- Raised the metrics anomaly thresholds to avoid false positives on modern large-context models: `tokensPerTurnWarn` 8000 → 32000 and `tokensSessionWarn` 50000 → 200000 (`toolCallsPerMinuteWarn` unchanged at 60). The metrics scanner never blocks, so the previous low thresholds produced noisy warnings on legitimate heavy workflows. Existing users keep their machine-layer `security-policy.json` customisations; see the README troubleshooting for adopting the raised defaults.
- Documented the injection scanner, metrics scanner, `injection-rules.json`, and `security-policy.json` in the README. The Scanners table, Config files table, and a new Anomaly thresholds section now describe how to tune the machine-only pattern set and thresholds (a project-layer file is ignored — ADR-0006/0009).
- Reduced protected-paths false positives: replaced the broad lexical defaults `*secret*`, `*credential*`, and `*token*.json` with precise patterns targeting structured credential/secret/token files by extension (`*credentials.{json,yaml,yml,toml}`, `*credential.{json,yaml,yml,toml}`, `*secrets.{json,yaml,yml,toml}`, `*secret.{json,yaml,yml,toml}`, `*token.json`, `*tokens.json`). Source files named `credentials.go`, `secret.go`, `token.go`, and `credentials.ts` are no longer blocked; structured files like `oauth-credentials.json` and `secrets.json` remain protected. The secret scanner (ADR-0002) still covers secret content regardless of filename. See ADR-0011.

### Changed
- Bumped `undici` override to `^8.10.0` ( Dependabot #13)
- Bumped `brace-expansion` to `5.0.9` (Dependabot #12)
- Bumped `tsx` dev dependency (Dependabot #11)

## [1.1.0] - 2026-07-30

### Added
- OWASP AI Agent Security hardening: 13 gaps remediated against the OWASP AI Agent Security Cheat Sheet
- HMAC-SHA256 forward-chained audit log with machine-local `audit.key` (0o600) and `/security:verify` tamper-evidence command
- Bash exfiltration detection: secrets in commands, data-carrying query parameters, large base64 blobs, command substitution, pipe-based exfil, cloud CLIs (aws/gcloud/docker), and process substitution `<(...)`
- Symlink-aware boundary enforcement via `realpath` with fail-closed semantics for broken symlinks (ADR-0005)
- Rate limiting: per-turn `tool_calls` and per-session `confirmations` caps with `ratelimit.block` audit events
- Prompt-injection heuristic scanner (wraps `[UNTRUSTED CONTENT]`, surfaces findings at skill approval, never blocks)
- Token/anomaly metrics scanner (`turn.metrics` + `anomaly` audit events)
- Tool-input shape validation (fail-closed for malformed inputs)
- `ctx.mode` gating: non-TUI modes fail closed for any action requiring confirmation
- Bash tokenizer hardened: heredocs, process substitution, brace expansion
- CI workflow: `test` + `typecheck` + two-tier `npm audit` (critical blocks, high advisory) + CycloneDX SBOM
- Dependabot config for npm and GitHub Actions
- 6 new ADRs (0005–0010)
- Integration, fuzz, and rotation test suites; coverage gate at 86% (lib/ measured 90.33%)

### Fixed
- Config baseline lock extended to all command-rules categories — the project layer can no longer disarm the bash Guard via `!` exclusions or `safe` shadowing of baseline `dangerous`/`external` patterns (C1)
- Audit truncation/deletion detection: `/security:verify` now flags a missing or empty active `audit.jsonl` when rotated files exist (H1)
- Protected-paths matching now resolves symlink real targets, not just lexical paths (M1)
- Secret scanner now redacts secrets on comment lines by default — commented-out credentials no longer reach the LLM (M1)
- Timing-safe hash comparison in `verifyFile` via `crypto.timingSafeEqual` (N1)
- Process-substitution `<(...)` exfiltration now detected by `detectExfiltration` (N4)
- Rotation-sequence gap detection in `verifyAuditChain` for deleted middle files (R9)
- HMAC key length enforced (≥32 bytes, else regenerate) (R8)
- `/security:clean` re-seals the HMAC chain instead of breaking it (R2)
- Project-layer scalar `writeAction`/`readAction` clamped to baseline restrictiveness (R3)
- Secrets redacted in the bash confirm dialog message (R5)
- `strict:true` enabled in tsconfig (16 type errors → 0, no suppressions) (R6)
- Two-tier `npm audit` gate in CI (critical blocks, high advisory) (R7)
- Removed unused `audit_writes` rate-limit scope (R1)
- Dead import removed; `noUnusedLocals` enabled in tsconfig (L1)

### Changed
- Bumped peer dependencies `@earendil-works/pi-ai`, `@earendil-works/pi-coding-agent`, and `@earendil-works/pi-tui` from `^0.82.1` to `^0.83.0`
- Bumped `protobufjs` override to `^7.6.5` (GHSA-j3f2-48v5-ccww)
- Bumped `tsx` dev dependency to `4.23.1`
- Bumped GitHub Actions to v7: `actions/checkout`, `actions/setup-node`, `actions/upload-artifact`
- Audit chain state cached between writes (O(n)→O(1) per event) (L2)
- Classification regexes precompiled and memoised per rules object (L3)

### Security
- Resolved the last open Dependabot alert: `protobufjs` 7.6.4 → 7.6.5 (CVE-2026-59877, DoS via infinite loop in `.proto` option parsing)
- All 14 Dependabot advisories now closed (undici, ws, protobufjs, brace-expansion)

### Notes
- No breaking API changes; the new `Config` fields are optional with shipped defaults.
- Encryption-at-rest and multi-agent security remain explicitly out of scope (documented in ADR-0007/0008).

## [1.0.4] - 2026-07-28

### Changed
- Bumped peer dependencies `@earendil-works/pi-ai`, `@earendil-works/pi-coding-agent`, and `@earendil-works/pi-tui` from `^0.79.9` to `^0.82.1`
- Synchronized `package-lock.json` with the peer dependency bump

### Notes
- No breaking API changes affect this extension. The v0.82.1 release adds Claude Opus 5 support, Anthropic gateway bearer auth, and faster model catalogs — none of which alter the `ExtensionAPI` surface used by the guards or scanners (`tool_call`, `session_start`, `before_provider_request`, `after_provider_response`, `turn_start`, `registerCommand`).
- The `outputPad` setting exposed to custom message renderers is additive and does not affect this extension.

## [1.0.3] - 2026-06-22

### Changed
- Bumped peer dependencies `@earendil-works/pi-ai`, `@earendil-works/pi-coding-agent`, and `@earendil-works/pi-tui` from `^0.79.6` to `^0.79.9`
- Synchronized `package-lock.json` with the peer dependency bump

### Security
- Resolved 10 Dependabot advisories that remained in `@earendil-works/pi-coding-agent@0.79.6` bundled copies, now fixed by the upstream `0.79.9` release
- `undici` (7): GHSA-vxpw-j846-p89q, GHSA-38rv-x7px-6hhq, GHSA-vmh5-mc38-953g, GHSA-p88m-4jfj-68fv, GHSA-pr7r-676h-xcf6, GHSA-g8m3-5g58-fq7m, GHSA-35p6-xmwp-9g52
- `protobufjs` (2): GHSA-wcpc-wj8m-hjx6, GHSA-f38q-mgvj-vph7
- `ws` (1): GHSA-96hv-2xvq-fx4p

## [1.0.2] - 2026-06-18

### Fixed
- Patched non-bundled transitive dependencies reachable via `@earendil-works/pi-ai` → `@google/genai` using npm `overrides`
- Bumped `protobufjs` to `7.6.4` and `ws` to `8.21.0` in the non-bundled dependency tree

### Security
- Mitigated Dependabot advisories for `protobufjs` (GHSA-wcpc-wj8m-hjx6, GHSA-f38q-mgvj-vph7, GHSA-jggg-4jg4-v7c6) and `ws` (GHSA-96hv-2xvq-fx4p, GHSA-58qx-3vcg-4xpx) where reachable
- Bundled copies inside `@earendil-works/pi-coding-agent@0.79.6` (`undici`, `protobufjs`, `ws`) remain and require an upstream bump from the `@earendil-works` publisher

## [1.0.1] - 2026-06-18

### Fixed
- Resolved critical and high-severity security vulnerabilities
- Fixed bugs in `splitCommand` and `triggerSkillReview`
- Made subshell splitting quote-aware and improved audit redaction
- Isolated audit tests from the real `HOME` directory and prevented skill name collisions
- Addressed all remaining Copilot PR review findings

### Changed
- Migrated package namespace from `@mariozechner` to `@earendil-works`
- Updated dependencies and documented future improvements

## [1.0.0] - 2026-05-07

### Added
- Initial release
- Guards: boundary enforcement, protected paths, and bash gate
- Scanners: secret detection and skill approval
- Append-only rotating JSONL audit trail
- Layered configuration (defaults, machine, project)
- Test suite
