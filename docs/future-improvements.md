# Future Improvements — New APIs from Dependency Updates

This document lists new APIs available after the 0.74.0 → 0.79.6 upgrade of `@earendil-works/pi-coding-agent` and how they could enhance pi-secured-setup.

---

## 1. `ctx.isProjectTrusted()` — v0.79.1

**Current behavior**: Skill-scanner prompts for approval on every new or changed skill, regardless of project trust status.

**Proposed enhancement**: Check project trust status before displaying skill approval prompts. If the project is already trusted, skip redundant skill approval flows or show a lighter notification.

**Target module**: `lib/skill-scanner.ts`

**Implementation sketch**:
```typescript
// In registerSkillScanner or triggerSkillReview
if (ctx.isProjectTrusted && ctx.isProjectTrusted()) {
  // Project is trusted — show notification only, don't block
}
```

**Risk**: Low — additive, no breaking change to existing flow.

**Priority**: Medium

---

## 2. `project_trust` event — v0.79.0

**Current behavior**: Config is reloaded on `session_start`. No integration with project trust decisions.

**Proposed enhancement**: The `project_trust` event is a **decision request**, not a notification. The extension handler *returns* a trust decision (`{ trusted: "yes" | "no" | "undecided" }`), rather than passively receiving it. This could be used to enforce security policy on trust decisions — e.g., auto-deny trust for projects with unapproved skills.

**Target module**: `extensions/security.ts`

**Implementation sketch**:
```typescript
pi.on("project_trust", async (event, ctx) => {
  // event has: { type: "project_trust", cwd: string }
  // Handler RETURNS the trust decision, does not read it from the event.
  const skills = discoverAllSkills(event.cwd);
  const unapproved = skills.filter(s => !isApproved(s));
  if (unapproved.length > 0) {
    auditLog("project_trust_denied", "warn", { unapprovedSkills: unapproved.map(s => s.name) });
    return { trusted: "no" as const };
  }
  return { trusted: "yes" as const };
});
```

**Risk**: Low — additive event handler, no existing behavior changes. Note: this replaces pi's default trust prompt for projects where the extension is active, so it should be carefully designed.

**Priority**: Low

---

## 3. `BeforeAgentStartEvent.systemPromptOptions` — v0.79.1

**Current behavior**: Audit log records guard blocks, confirmations, and secret redactions. No visibility into system prompt configuration.

**Proposed enhancement**: The `before_agent_start` event already carries `systemPromptOptions` on the event object, providing traceability of which security-relevant prompt options were active. This avoids the need for `ctx.getSystemPromptOptions()`, which is only available in command handlers (`ExtensionCommandContext`), not event handlers.

**Target module**: `lib/audit.ts`

**Implementation sketch**:
```typescript
pi.on("before_agent_start", async (event, ctx) => {
  if (event.systemPromptOptions) {
    auditLog("agent_prompt_options", "info", { systemPromptOptions: event.systemPromptOptions });
  }
});
```

**Risk**: Low — additive audit entry, no behavior changes.

**Priority**: Low

---

## 4. `ctx.mode` — v0.78.1

**Current behavior**: Guard confirmation dialogs (`ctx.ui.confirm`, `ctx.ui.select`) are shown regardless of execution mode. In non-interactive modes (RPC, JSON, print), these may hang or fail silently.

**Proposed enhancement**: Adapt Guard behavior based on `ctx.mode`:
- In `"tui"` mode: show interactive dialogs as today
- In `"rpc"`, `"json"`, or `"print"` mode: auto-block dangerous operations or log and skip confirmation

**Target module**: `lib/guard-pipeline.ts`

**Implementation sketch**:
```typescript
if (ctx.mode !== "tui") {
  // Non-interactive mode: auto-block dangerous actions instead of prompting
  return { verdict: "block", reason: "Non-interactive mode: dangerous action requires confirmation" };
}
```

**Risk**: Medium — changes Guard behavior in non-interactive modes. Requires testing with pi running in RPC mode.

**Priority**: High — this is a real usability issue when pi runs in non-interactive contexts.

---

## Priority Summary

| # | API | Priority | Risk | Module |
|---|-----|----------|------|--------|
| 4 | `ctx.mode` | **High** | Medium | guard-pipeline.ts |
| 1 | `ctx.isProjectTrusted()` | Medium | Low | skill-scanner.ts |
| 2 | `project_trust` event | Low | Low | extensions/security.ts |
| 3 | `before_agent_start.systemPromptOptions` | Low | Low | audit.ts |