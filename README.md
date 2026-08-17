# Pi Secured Setup

A distributable pi-agent extension providing multi-layer security: **Guards** that block dangerous actions, **Scanners** that detect risks, and an **audit trail** that records everything.

## Installation

```bash
# Install from git
pi install git:github.com/mwolff44/pi-secured-setup

# Pin to a version
pi install git:github.com/mwolff44/pi-secured-setup@v1.0.0

# Update (pulls latest, never touches local config)
pi update pi-secured-setup
```

## What It Does

### Guards (block before execution)

| Guard | Applies To | Behavior |
|-------|-----------|----------|
| **Boundary** | `read`, `write`, `edit` | Blocks writes outside the project directory (`cwd`). Confirms reads outside boundary. External paths can be whitelisted. |
| **Protected paths** | `read`, `write`, `edit` | Blocks writes to sensitive files (`.env`, `*.key`, `*.pem`, structured credential files like `*credentials.json`, `*secrets.yaml`, etc.). Confirms reads. Patterns are configurable. |
| **Bash gate** | `bash` | Classifies commands as SAFE / MODERATE / DANGEROUS / EXTERNAL. Dangerous and external commands require confirmation. Unknown commands also require confirmation. |

All three guards run in a **single combined handler** (ADR-0001) with fixed order: boundary → protected-paths → bash-gate. First block wins.

### Scanners (observe, don't block)

| Scanner | Mechanism | Behavior |
|---------|-----------|----------|
| **Secret scanner** | `before_provider_request` | Recursively walks the provider payload for strings matching 15+ secret patterns (AWS keys, LLM keys, private keys, DB connection strings, GitHub tokens, etc.). Redacts as `***REDACTED:{pattern-name}***`. Provider-agnostic. |
| **Injection scanner** | `before_provider_request` | Heuristically detects prompt-injection patterns (role-override, fake structural tags, instruction smuggling) in the provider payload and wraps suspicious segments in `[UNTRUSTED CONTENT]…[/UNTRUSTED CONTENT]` markers. The trusted system prompt is excluded from scanning. Emits an `injection.detected` audit event and notifies. Never blocks. Patterns are machine-only configurable (`injection-rules.json`). |
| **Metrics scanner** | `before_provider_request` + `after_provider_response` | Estimates tokens per turn (provider `usage` when present, else chars/4), emits `turn.metrics` audit events, and warns on anomaly thresholds (tokens per turn, tokens per session, tool calls per minute). Never blocks. Thresholds are machine-only configurable (`security-policy.json`). |
| **Skill scanner** | `session_start` | Hashes `SKILL.md` for every discovered skill. Prompts for approval of new or changed skills. Previously skipped/unapproved skills show a notification only. |

### Audit log

Every guard and scanner action is recorded as a JSONL entry in `~/.pi/agent/security/audit.jsonl`. The log rotates automatically (default: 10MB per file, 3 files retained).

## Commands

| Command | Description |
|---------|-------------|
| `/security` | Dashboard — blocked/confirmed counts, recent events, skill status |
| `/security:skills` | Re-trigger skill approval flow for all skills |
| `/security:trust <skill>` | Approve a skill by name, persist to config |
| `/security:allow <path>` | Add an external path to the allowed list |
| `/security:clean [days]` | Trim audit log entries older than N days (default: 30) |

## Configuration

Configuration is loaded from three layers, merged in priority order:

```
1. defaults/              — shipped with the package
2. ~/.pi/agent/security/  — machine-specific overrides
3. .pi/security/          — project-specific overrides (relative to cwd)
```

Pattern lists are **additive** — each layer can add new patterns. A `!` prefix **excludes** an inherited pattern:

```jsonc
// .pi/security/protected-paths.json — project override
{
  "patterns": [
    "!*credentials.json", // Remove the inherited *credentials.json pattern (ignored — baseline; see ADR-0009)
    "config/local.json"   // Add a project-specific pattern
  ],
  "readAction": "allow" // Override: don't confirm reads for protected files
}
```

> **Note:** the project layer cannot remove baseline patterns via `!` — such exclusions are ignored with a warning (ADR-0009). A project can only **add** patterns (strengthen). To relax a default, use the machine layer (`~/.pi/agent/security/`).

Non-pattern fields (like `writeAction`, `readAction`) in later layers replace earlier values, clamped to the baseline restrictiveness at the project layer.

### What gets protected — naming vs. content

The shipped defaults protect files by **format and role**, not by the presence of a keyword in the filename. Source files named `credentials.go`, `secret.go`, `token.go`, or `credentials.ts` are **not** protected by default — they are code, not secrets. The defaults target structured credential/secret/token files with sensitive extensions:

- `.env`, `.env.*` — environment files
- `*.key`, `*.pem`, `*.p12`, `*.pfx` — private keys and certificates
- `id_rsa*`, `id_ed25519*`, `id_ecdsa*` — SSH keys
- `*credentials.{json,yaml,yml,toml}`, `*credential.{json,yaml,yml,toml}` — credential files
- `*secrets.{json,yaml,yml,toml}`, `*secret.{json,yaml,yml,toml}` — secret files
- `*token.json`, `*tokens.json` — token files

A source file named `secret.go` stays editable; a structured file named `oauth-credentials.json` is blocked. This avoids blocking legitimate source files while guarding files that, by convention, carry real secrets.

The **secret scanner** (ADR-0002) provides a second, independent layer: regardless of a file's name, any secret value that reaches the provider payload is redacted before it enters the LLM context. Together, the protected-paths guard covers *files sensitive by naming convention*, and the secret scanner covers *content sensitive by shape*.

### Config files

| File | Layer | Purpose |
|------|-------|---------|
| `protected-paths.json` | all | Glob patterns for sensitive files + read/write actions |
| `command-rules.json` | all | Regex patterns for SAFE / MODERATE / DANGEROUS / EXTERNAL command classification |
| `allowed-external.json` | all | Paths outside the project boundary that are allowed |
| `audit-config.json` | machine | Log rotation settings (`maxFileSize`, `maxFiles`) |
| `injection-rules.json` | machine | Prompt-injection heuristic patterns + per-turn `threshold` (a project-layer file is ignored — see ADR-0006) |
| `security-policy.json` | machine | Rate limits (`toolCallsPerTurn`, `confirmationsPerSession`) + metrics anomaly thresholds (`tokensPerTurnWarn`, `toolCallsPerMinuteWarn`, `tokensSessionWarn`). A project-layer file is ignored — see ADR-0009. |
| `skill-approvals.json` | machine | Auto-managed — skill hashes + approval decisions |

### Per-project example

To add project-specific security rules, create a `.pi/security/` directory in your project root:

```bash
mkdir -p .pi/security
```

Then add any of these files:

```jsonc
// .pi/security/protected-paths.json
{
  "patterns": [
    "config/production.json",
    "secrets/*.yml"
  ]
}
```

```jsonc
// .pi/security/command-rules.json
{
  "dangerous": [
    "terraform destroy",
    "kubectl delete"
  ]
}
```

```jsonc
// .pi/security/allowed-external.json
{
  "paths": [
    "../shared-lib"
  ]
}
```

### Anomaly thresholds (metrics scanner)

The metrics scanner warns when token or tool-call counters cross a threshold — it never blocks. The shipped defaults are generous (tuned for modern large-context models), but operators with very large contexts or tight budgets can tune them in the **machine-layer** `~/.pi/agent/security/security-policy.json`:

```jsonc
{
  "tokensPerTurnWarn": 32000,      // warn when a single turn exceeds N tokens
  "toolCallsPerMinuteWarn": 60,    // warn above N provider round-trips per minute
  "tokensSessionWarn": 200000      // warn when the cumulative session total exceeds N tokens
}
```

Set a field to `0` to disable that specific warning. The project layer cannot raise or disable these thresholds (ADR-0009) — a checked-in `.pi/security/security-policy.json` is ignored with a warning. Reload with `/reload` after editing.

### Injection scanner patterns

The injection scanner ships a curated, machine-only pattern set in `~/.pi/agent/security/injection-rules.json`. Each entry is a case-insensitive regex with a name; the `threshold` field controls when the per-turn notification escalates from `warning` to `error`:

```jsonc
{
  "patterns": [
    { "name": "ignore-previous-instructions", "pattern": "ignore (?:all |the |everything |any |your )?(?:previous|prior|above|earlier) (?:instructions|rules|prompts?)" }
    // …more shipped patterns
  ],
  "threshold": 3
}
```

The trusted system prompt is excluded from scanning, so legitimate examples of injection phrasing inside it (e.g. an `AGENTS.md` rule that quotes "Ignore previous instructions" to describe what to watch for) are not wrapped in `[UNTRUSTED CONTENT]` markers. A project-layer `injection-rules.json` is ignored — see ADR-0006.

## Architecture

See [CONTEXT.md](CONTEXT.md) for domain terminology and [docs/adr/](docs/adr/) for architectural decision records.

```
extensions/
  security.ts           # Entry point
lib/
  config.ts             # Three-layer config merge with ! exclusion
  guard-pipeline.ts     # Single combined tool_call handler (ADR-0001)
  boundary.ts           # Boundary evaluation (ADR-0003)
  protected-paths.ts    # Protected path glob matching
  bash-gate.ts          # Command classification (SAFE/MODERATE/DANGEROUS/EXTERNAL)
  rate-limiter.ts       # Per-turn / per-session caps (ADR-0009)
  secret-scanner.ts     # Provider-agnostic secret redaction (ADR-0002)
  injection-scanner.ts  # Heuristic prompt-injection marking (ADR-0006)
  metrics-scanner.ts    # Token / anomaly metrics + warnings
  skill-scanner.ts      # SKILL.md hash verification (ADR-0004)
  audit.ts              # JSONL audit log + HMAC chain + /security commands
  utils.ts              # Shared helpers
defaults/
  protected-paths.json  # Default global protected patterns
  command-rules.json    # Default command classification rules
  allowed-external.json # Default allowed external paths
  audit-config.json     # Default rotation settings
  injection-rules.json  # Default injection heuristic patterns (machine-only)
  security-policy.json  # Default rate limits + anomaly thresholds (machine-only)
```

## First-run experience

1. Extension loads → detects no `~/.pi/agent/security/` directory
2. Creates directory with default configs
3. Scans all skills → prompts approval for each one (once)
4. Ready — all guards and scanners active

## Emergency bypass

There is no bypass flag. If a guard is too restrictive:
1. Edit the config file (`~/.pi/agent/security/` or `.pi/security/`)
2. Run `/reload` to apply changes

## Troubleshooting

### I updated to the latest version, but `credentials.go` / `secret.go` is still blocked

The corrected defaults (ADR-0011) target structured credential files by extension (`*credentials.json`, `*secrets.yaml`, etc.) rather than matching the keyword in any filename. If a source file named `credentials.go` is still blocked after updating, your **machine-layer** config still contains the old broad patterns.

The machine config (`~/.pi/agent/security/protected-paths.json`) is copied from the shipped defaults **only on first run** — it is never overwritten by `pi update` (so your customisations are preserved). This means a machine config copied from an older version of the package still carries the broad `*secret*` / `*credential*` / `*token*.json` patterns, and those are merged additively on top of the corrected defaults.

To adopt the corrected defaults at the machine layer, pick one:

```bash
# Option A — re-trigger the copy from the shipped defaults (loses machine-layer customisations)
rm ~/.pi/agent/security/protected-paths.json
# The next pi session recreates it from the updated defaults/

# Option B — keep your customisations, just remove the three broad patterns
# Edit ~/.pi/agent/security/protected-paths.json and delete the lines:
#   "*secret*", "*credential*", "*token*.json"
```

You can verify which patterns are active with `/security` (dashboard shows the merged protected-path list).

### A file I consider sensitive is not protected by default

The defaults protect files by **format and role**, not by keyword in the filename. A file like `token-handler.json` or `secret-manager.yaml` is not protected because its name describes a *role*, not a secret. If your project genuinely needs to protect such a file, add a specific pattern in `.pi/security/protected-paths.json`:

```jsonc
{
  "patterns": ["token-handler.json", "secret-manager.yaml"]
}
```

Remember: the **secret scanner** (ADR-0002) still redacts any secret value that reaches the provider payload, regardless of the source file's name. The protected-paths guard covers *files sensitive by naming convention*; the secret scanner covers *content sensitive by shape*.

### I updated to the latest version, but I still get token-spike / session-budget warnings

The metrics anomaly thresholds were raised (tokens per turn 8000 → 32000, session budget 50000 → 200000) to avoid false positives on modern large-context models. The machine config (`~/.pi/agent/security/security-policy.json`) is copied from the shipped defaults **only on first run** — it is never overwritten by `pi update` (so your customisations are preserved). This means a machine config copied from an older version still carries the old low thresholds.

To adopt the raised defaults, pick one:

```bash
# Option A — re-trigger the copy from the shipped defaults (loses machine-layer customisations)
rm ~/.pi/agent/security/security-policy.json
# The next pi session recreates it from the updated defaults/

# Option B — keep your customisations, just raise the three thresholds
# Edit ~/.pi/agent/security/security-policy.json and set:
#   "tokensPerTurnWarn": 32000,
#   "toolCallsPerMinuteWarn": 60,
#   "tokensSessionWarn": 200000
```

You can also tune the thresholds to your model's context size (e.g. set `tokensSessionWarn` to ~2/3 of your context window). Set a field to `0` to disable that specific warning.

### The injection scanner flags legitimate content

The injection scanner is heuristic by nature and may flag legitimate text that happens to match an injection pattern. The trusted system prompt is excluded from scanning, so examples inside it are safe. If a pattern produces false positives on user or tool-result content, you can remove or tighten it in the machine-layer `~/.pi/agent/security/injection-rules.json`, then run `/reload`.
