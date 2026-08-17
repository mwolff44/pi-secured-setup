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

| File | Purpose |
|------|---------|
| `protected-paths.json` | Glob patterns for sensitive files + read/write actions |
| `command-rules.json` | Regex patterns for SAFE / MODERATE / DANGEROUS / EXTERNAL command classification |
| `allowed-external.json` | Paths outside the project boundary that are allowed |
| `audit-config.json` | Log rotation settings (`maxFileSize`, `maxFiles`) |
| `skill-approvals.json` | Auto-managed — skill hashes + approval decisions |

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
  secret-scanner.ts     # Provider-agnostic secret redaction (ADR-0002)
  skill-scanner.ts      # SKILL.md hash verification (ADR-0004)
  audit.ts              # JSONL audit log + rotation + /security commands
  utils.ts              # Shared helpers
defaults/
  protected-paths.json  # Default global protected patterns
  command-rules.json    # Default command classification rules
  allowed-external.json # Default allowed external paths
  audit-config.json     # Default rotation settings
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
