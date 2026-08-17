# 0012 Injection scanner excludes the trusted system prompt

The injection scanner (ADR-0006) recursively walks every string value in the provider payload and wraps matches in `[UNTRUSTED CONTENT]…[/UNTRUSTED CONTENT]` markers. This walk included the system prompt, which is trusted agent infrastructure — not user input, tool output, or fetched content. System prompts routinely contain legitimate examples of injection phrasing (e.g. an `AGENTS.md` rule that quotes "Ignore previous instructions" to describe what the model should watch for). Wrapping those examples in `[UNTRUSTED CONTENT]` markers produced false-positive warnings on every turn and, worse, corrupted the context of smaller / local models (e.g. Llama.cpp): the markers bled into tool-call arguments, JSON parsing failed, and the session crashed in a retry loop (issue #14).

## Considered options

- **Rephrase or allowlist the literal trigger phrases in AGENTS.md / the rulebook:** Rejected as whack-a-mole. The system prompt is assembled from many sources (pi's built-in system prompt, AGENTS.md, CONTEXT.md, skill instructions, tool descriptions), any of which may legitimately quote injection phrasing. Chasing each phrase would fragile and would not solve the root cause: the scanner was scanning trusted infrastructure.

- **Exclude the system prompt from injection scanning (chosen):** The scanner skips a bounded, provider-agnostic allowlist of the well-known carrier locations for the system prompt across every provider pi ships: the top-level `system` (Anthropic Messages API) and `systemInstruction` (Google Generative AI) fields, and messages carrying `role: "system"` or `role: "developer"` (OpenAI Chat / Codex Responses / Anthropic developer role). Every other string in the payload — user messages, assistant messages, tool results, fetched content — is still scanned. This does not parse arbitrary provider message structure (ADR-0002 is preserved): it skips a fixed set of carrier keys and message roles, then continues the symmetric string walk everywhere else.

- **Make the system-prompt exclusion configurable:** Rejected. The trust boundary between the system prompt and user/tool content is structural, not a preference. Allowing a project layer to re-enable scanning of the system prompt would let a checked-in file reintroduce the crash loop. The exclusion is unconditional.

## Consequences

- The trusted system prompt is never wrapped in `[UNTRUSTED CONTENT]` markers, eliminating the false-positive warnings and the local-model crash loop reported in issue #14.
- User messages, assistant messages, tool-result messages, and any other string in the payload are still scanned and marked — the injection defense for untrusted content is unchanged.
- The walk remains provider-agnostic. The scanner does not branch on provider; it skips a constant set of carrier keys (`system`, `systemInstruction`) and message roles (`system`, `developer`) that are stable across provider API versions, then continues the recursive string walk. Switching providers changes nothing.
- ADR-0002 (provider-agnostic string walk) and ADR-0006 (heuristic payload scanner, never blocks) are preserved. The exclusion is a bounded refinement of *which strings* are walked, not a change to the walk's mechanics or the scanner's non-blocking contract.
- The secret scanner (ADR-0002) is unchanged: it still walks the entire payload including the system prompt, because secrets must be redacted wherever they appear. The trust boundary for injection scanning (skip the system prompt) does not apply to secret scanning (redact everywhere) — the two scanners answer different questions.
