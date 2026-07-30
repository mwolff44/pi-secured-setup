# Pi Secured Setup

A distributable pi-agent extension package providing multi-layer security: guards that block dangerous actions, scanners that detect risks, and an audit trail that records everything.

## Language

**Guard**:
A module that can block a tool call before execution via the `tool_call` event. Guards have an enforce-and-log posture.
_Avoid_: Protector, filter, interceptor

**Scanner**:
A module that observes data without blocking tool execution. Scanners detect, report, and transform — but never prevent a tool from running.
_Avoid_: Detector, monitor, checker

**Boundary**:
The directory from which pi was launched (`cwd`). File operations via `read`, `write`, and `edit` tools are evaluated relative to this root. Bash commands are not subject to boundary enforcement — they are governed by command classification instead. The boundary is never inferred by walking up the filesystem.
_Avoid_: Project root, project scope, workspace

**Protected path**:
A file pattern (glob) identifying sensitive files that require elevated permission to access. Protected paths are matched against tool call targets.
_Avoid_: Sensitive file, restricted file, blocked file

**Protected baseline**:
The set of protected-path patterns contributed by the `defaults` and `machine` config layers, which the `project` layer cannot remove. A `!` exclusion in the project layer that targets a baseline pattern is ignored (with a warning). The project layer may only ADD protected patterns (strengthen), never weaken the baseline. The same lock applies to the scalar `writeAction`/`readAction` fields: ranked `allow` < `confirm` < `block`, the project layer may only make them MORE restrictive, and a weaker value (e.g. `readAction:"allow"` against a baseline `"confirm"`) is ignored with a warning while the baseline value is kept. Machine-layer overrides of defaults are unconstrained — the clamp is project-only.
_Avoid_: Immutable paths, locked patterns

**Skill approval**:
A recorded decision (with cryptographic hash) that a specific skill is trusted. Only the `SKILL.md` file is hashed — it is the sole file that enters the LLM context. Supporting scripts are protected by the bash Guard. Approvals are stored in `skill-approvals.json` and verified on every session start. New or changed skills prompt for a decision once. A decision has three states: **approved** (explicitly trusted, hash recorded), **denied** (explicit permanent refusal — subsequent sessions notify only and do NOT re-prompt), and **skipped** (deferred — subsequent sessions RE-PROMPT, since skipped is treated as pending, not approved). Re-trigger with `/security:skills`.
_Avoid_: Skill validation, skill verification, skill allowlist

**Audit event**:
A single append-only JSONL record of a security-relevant action: blocks, confirmations, redactions, skill changes. The log rotates automatically based on configurable thresholds (default: 10MB per file, 3 files retained). Entries are forward-chained with an HMAC so the log is tamper-evident and verifiable via `/security:verify` (see Audit integrity).
_Avoid_: Log entry, security log, event

**Audit integrity**:
A forward-chained HMAC (SHA-256) over audit entries, keyed by a machine-local `audit.key` (mode `0o600`). Each entry carries `seq`, `prevHash`, and `hash`; tampering (modification, deletion, insertion) breaks the chain and is reported by `/security:verify`. Rotation seals each file with an `audit.roll` record.
_Avoid_: Audit signing, log encryption (encryption at rest is explicitly out of scope)

**Secret**:
A credential value (API key, password, token, private key, connection string) that must not reach the LLM context in plaintext. Redacted values are replaced with `***REDACTED:{pattern-name}***` so the agent retains type information without the value.
_Avoid_: Credential, sensitive data, key (ambiguous with cryptographic key)

**Injection scanner**:
A Scanner that detects heuristic prompt-injection patterns (role-override, fake structural tags, instruction smuggling) by walking the provider payload strings — provider-agnostic, like the secret scanner. Detected segments are wrapped in `[UNTRUSTED CONTENT]…[/UNTRUSTED CONTENT]` markers; the user is notified and an `injection.detected` audit event is emitted. It NEVER blocks (Scanner semantics). Patterns are loaded machine-only from `injection-rules.json`.
_Avoid_: Prompt filter, injection blocker, jailbreak detector

**Metrics scanner**:
A Scanner that estimates tokens per turn (from provider `usage` when present, else chars/4 heuristic) and emits `turn.metrics` audit events. When a threshold (tokens per turn, tokens per session, tool calls per minute) is exceeded, it emits an `anomaly` warning and notifies. It NEVER blocks.
_Avoid_: Cost tracker, billing monitor

**Config layer**:
One of three configuration sources, merged in priority order: defaults (shipped with package), machine (`~/.pi/agent/security/`), project (`.pi/security/`). All configurable files (`protected-paths.json`, `command-rules.json`, `allowed-external.json`) can exist at any layer. Later layers add patterns with a `!` prefix to exclude inherited patterns from earlier layers. The protected patterns contributed by `defaults` and `machine` form a protected baseline that the project layer cannot weaken. `injection-rules.json` and `security-policy.json` are machine-only and are not loaded from the project layer.
_Avoid_: Config level, config source, config tier

**Command classification**:
The assignment of a bash command to one of four categories: SAFE, MODERATE, DANGEROUS, or EXTERNAL. SAFE and MODERATE are severity levels. DANGEROUS covers destructive operations. EXTERNAL covers any command that sends data outside the machine, regardless of severity.
_Avoid_: Risk level, threat level, command rating

**Bash exfiltration detection**:
Inspection of a bash command's content (in addition to its classification) for secrets or exfiltration shapes — a secret embedded in a `curl` argument, data-carrying query parameters (`?d=`), large base64 blobs, or command substitution feeding an EXTERNAL command. A finding escalates the verdict to at least `confirm` and emits a `bash.exfil` audit event.
_Avoid_: Exfil blocker, data-leak filter

**Rate limiting**:
Per-turn and per-session caps (tool calls per turn, confirmations per session) enforced by the guard pipeline. Exceeding a cap blocks the next call with a `ratelimit.block` audit event. Limits are loaded machine-only from `security-policy.json` — the project layer cannot raise or disable them.
_Avoid_: Throttling, quota

## Relationships

- A **Guard** operates on tool calls *before* execution via a single combined `tool_call` handler. A **Scanner** operates on tool results or provider payloads *after* execution.
- **Guard pipeline** evaluates checks in fixed order: input-shape validation → rate-limit check → boundary → protected-paths → bash-gate (with bash exfiltration detection before classification). First block wins. No short-circuit past a confirmation.
- An **Injection scanner** and a **Metrics scanner** join the **Secret scanner** as `before_provider_request`/`after_provider_response` observers.
- Symlinks are resolved (`realpath`) before boundary checks; broken symlinks fail closed (write/edit block, read confirm).
- Non-interactive modes (`ctx.mode !== "tui"`) fail closed for any action requiring confirmation.
- Secret scanning is provider-agnostic: the Scanner recursively walks the provider payload for all string values and runs regex matching, ignoring message structure differences between Anthropic, OpenAI, Google, etc.
- **Boundary** defines the geographic limit for Guards. **Protected paths** define the logical limit within that boundary.
- **Command classification** determines how the bash Guard responds to a given command.
- **Secret** scanning is performed by a Scanner that redacts values in the provider payload.
- **Skill approval** is managed by a Scanner that detects changes and prompts for decisions.
- Every Guard and Scanner action produces an **Audit event**.
- **Config layers** are merged to produce the runtime configuration for all Guards and Scanners. Pattern lists are additive; a `!` prefix on a pattern in a later layer excludes the matching inherited pattern.

## Example dialogue

> **Dev:** "Can the skill module block a malicious skill from loading?"
> **Domain expert:** "No — the skill module is a Scanner. It detects changes, shows diffs, and prompts for approval, but it cannot prevent pi from loading a skill file. Only Guards can block actions."

> **Dev:** "What's the difference between boundary enforcement and protected paths?"
> **Domain expert:** "Boundary is geographic — 'is this file inside cwd?' Protected paths are logical — 'even though this file IS inside cwd, is it sensitive?' Boundary is checked first, then protected paths."

> **Dev:** "If a secret appears in a bash output, what happens?"
> **Domain expert:** "The bash Guard classifies the command and may block or confirm it. But if the command runs and the output contains a Secret, the secret Scanner redacts it from the provider payload before it reaches the LLM. The scan is provider-agnostic — it walks all text strings in the payload regardless of message format."

> **Dev:** "What happens when I switch models from Anthropic to OpenAI?"
> **Domain expert:** "Nothing changes for the Scanner. It doesn't parse message structure — it just finds string values and runs regex. Provider switching is transparent."

> **Dev:** "If a fetched web page contains 'ignore previous instructions', what happens?"
> **Domain expert:** "The injection scanner is a Scanner — it wraps the suspicious segment in `[UNTRUSTED CONTENT]…[/UNTRUSTED CONTENT]` markers, notifies you, and emits an `injection.detected` audit event, but it cannot block the provider call. Only Guards block."

## Design constraints

- All three Guard modules (boundary, protected-paths, bash-gate) are evaluated by a single `tool_call` handler. They export pure evaluation functions, not independent event registrations. This ensures deterministic ordering and prevents multiple confirmation dialogs for a single tool call.
- Scanners (secret, injection, metrics) never block; they only detect, mark, and notify. Only Guards block.
- The project config layer may strengthen but never weaken security: it cannot remove protected-path baselines, raise rate limits, weaken injection rules, or alter audit rotation.
- Audit entries are tamper-evident (HMAC forward chain); `/security:verify` replays the chain.
- Skill approval prompts fire once per skill change. Subsequent sessions display a notification for unapproved skills without blocking. Use `/security:skills` to re-trigger the approval flow.
- The `/security` command is a dashboard for visibility. `/security:trust <skill>` and `/security:allow <path>` are convenience commands that persist config changes and auto-reload. No session-scoped overrides exist — all changes are persistent.

## Flagged ambiguities

- "Block" vs "confirm" — resolved: **block** means the action is rejected with no option to proceed in that tool call. **Confirm** means a dialog is shown and the user can choose to proceed.
- "NETWORK" was renamed to **EXTERNAL** — resolved: the concern is data leaving the machine, not networking per se. EXTERNAL better captures commands like `aws`, `gcloud`, `docker push` that may not use raw network sockets but send data externally.
- "Skill verification" was used ambiguously to mean both hash-checking and approval — resolved: **skill approval** is the human decision; **hash verification** is the mechanical integrity check.
