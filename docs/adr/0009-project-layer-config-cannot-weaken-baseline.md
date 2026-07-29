# 0009 Project-layer config cannot weaken baseline security

The project config layer (`.pi/security/`) can only strengthen, never weaken, the security baseline established by the defaults and machine layers. The protected-path patterns contributed by the defaults and machine layers form an immovable baseline: a `!` exclusion coming from the project layer that would remove a baseline pattern is ignored. Project-layer `safe` and `moderate` command patterns that are overly broad — `.*`, `^.*$`, or `^`, which match every command — are rejected outright rather than merely warned about. The previous behaviour only emitted `console.error` warnings, which are easily ignored.

## Considered options

- **Block the entire config load when a weakening pattern is detected:** Abort `loadConfig` if the project layer contains a baseline-weakening pattern or an overly broad command pattern. Rejected because the detection is intentionally conservative — a false positive would block all work, including benign projects that happen to ship a `.pi/security/` file. The cost of a config-load failure is a dead agent; the cost of a dropped pattern is a single extra confirmation dialog.

- **Warning only (previous behaviour):** Continue emitting `console.error` for baseline-weakening and overly broad patterns, but honour them. Rejected because warnings are passive and easily missed — the agent continues and the guard is disarmed. A checked-out repository is a common attack vector (a malicious `.pi/security/command-rules.json` shipped with the repo), so silent acceptance is the wrong default.

- **Treat defaults+machine protected patterns as an immovable baseline; reject overly-broad project `safe`/`moderate` patterns (chosen):** The project layer may add new protected patterns and new specific command patterns, strengthening the posture. It may not remove baseline protected paths via `!`, and its broad command patterns are dropped so the affected commands fall back to `unknown` → confirm. Defaults and machine layers retain full `!` exclusion power — only the project layer is constrained. An explicit machine-level opt-out remains available for operators who genuinely need to relax a default.

## Consequences

- The project layer cannot remove defaults+machine protected paths via `!`; such exclusions are ignored with a `console.error` warning, and the baseline pattern stays in the merged result.
- Broad `safe`/`moderate` patterns (`.*`, `^.*$`, `^`) contributed by the project layer are rejected (dropped, not added) with a `console.error` warning. The affected commands are absent from `safe`/`moderate` and therefore classify as `unknown` → confirm downstream.
- Defaults and machine layers are unaffected: their broad patterns still trigger the existing weak-config warning (warn only, not reject), and machine-layer `!` exclusions of default patterns still work. The lock applies exclusively to the project layer.
- The project layer can still add new protected patterns (e.g. `custom-secret.txt`) and specific valid command patterns (e.g. `^my-safe-tool\b`) without false rejection — the lock targets weakening, not strengthening.
- `mergePatterns` is unchanged; the baseline lock is applied in `mergeProtectedPaths` and `mergeCommandRules`, where layer origins are known. Existing `!` exclusion semantics across layers (including machine-layer exclusions) are preserved.
- The `audit-config.json` file remains machine-only — the project layer has never been able to influence it, and that does not change here.
- An explicit machine-level opt-out is still possible: an operator who needs to relax a default protected path can add the exclusion at the machine layer (`~/.pi/agent/security/`), which is under the operator's control rather than checked into a repository.
