# 0013 Product boundary: settings and agent behavior, not generated code

pi-secured-setup secures the **agent's settings and behavior**: the boundary its file tools operate in, the protected paths it may not touch, the bash gate that classifies what it may execute, the redaction and injection marking that control what enters its context, and the tamper-evident audit trail of all of the above. It does **not** secure the **code the agent generates** — reviewing a produced patch for injection vulnerabilities, unsafe patterns, or project code standards is a different concern with different inputs, different actors, and a different deployment surface. That rules channel lives in a separate extension (the pi-code-rules plan); it will never be a pattern list in this package. Drawing the boundary explicitly keeps each extension's threat model honest: this one defends the *agent's interaction with the machine and the provider*, not the artifacts it writes.

## Considered options

- **Grow this package into an "agent security + code rules" bundle:** Rejected. Generated-code review is prompt-driven and project-specific (per-language standards, review conventions), while everything here is behavior-driven and machine-scoped (`~/.pi/agent/security/` config, ADR-0009 baseline locks). Bundling both would drag project-layer code-style preferences into a package whose baseline doctrine is deliberately machine-only, and every code-rule feature would inherit this package's guard/scanner contracts that do not fit it.

- **Stay silent on the boundary and let scope emerge:** Rejected as the status quo. Requests to "make the agent write secure code" would keep landing on this package's config surface, and each ad-hoc accommodation (a code-patterns file here, a linting hook there) would erode the config-layer invariants (ADR-0006/0009) that make the baseline tamper-resistant.

- **Document the boundary and route code rules to a separate extension (chosen):** The README states the scope in one sentence, this ADR records the decision, and the code-rules channel is deferred to its own extension with its own config surface, audit vocabulary, and threat model.

## Consequences

- The package's scope is the security of settings and agent behavior: boundary, protected paths, bash gate, secret redaction, injection marking, and audit. Feature requests outside that scope are routed elsewhere, starting with the code-rules extension (see the pi-code-rules plan).
- No config file in this package gains fields about generated code; the machine-only layering doctrine (ADR-0006/0009) stays intact.
- The scan bounds shipped in the same release are an application of this boundary, not a widening of it: they bound what the extension itself guarantees — `LINE_SCAN_CAP` caps the injection scan window per line, `scanBudgetBytes` caps the secret scan per provider request (skips are audited and notified, never silent, and PEM redaction still runs), and the load-time probe rejects pathologically slow operator patterns. Coverage traded away by a bound is always announced in the audit log; silent degradation is the one outcome this package refuses.
- Documented trade-offs hold: the injection scanner is heuristic and its per-line cap means content beyond 4096 characters per line is not scanned; the secret scan budget means over-budget payloads skip line-by-line redaction (visible as `secret.skipped`); the load probe is a net, not a guarantee, against subtle pathological regexes.
