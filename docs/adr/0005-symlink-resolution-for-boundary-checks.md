# 0005 Symlink resolution for boundary checks

Boundary evaluation resolves symlinks via `fs.realpathSync` before comparing paths against `cwd` and `allowedExternal`. The previous lexical-only comparison (normalize + `startsWith`) allowed a symlink created inside `cwd` but pointing outside to escape the boundary undetected, letting `read`, `write`, and `edit` operate on files outside the project boundary.

## Considered options

- **Lexical-only (previous behaviour):** Compare paths via `isInsideDir` after `normalize`, with no filesystem access. Rejected because a symlink inside `cwd` whose target lives outside (e.g. `ln -s /etc/passwd ./passwd`) defeats the boundary check entirely — the lexical path is inside `cwd`, but the real target is not. The same bypass applies to the `allowedExternal` loop.

- **`fs.realpathSync` on every check, fail-closed on broken symlinks (chosen):** Resolve `config.cwd` once per call, resolve `targetPath` via `realpathSync`, and resolve each `allowedExternal` entry before comparing. Broken symlinks (where `realpathSync` throws but `lstatSync` reports a symlink) are treated fail-closed: write/edit → block, read → confirm. A small TOCTOU window remains between evaluation and execution — this is acceptable because the boundary is a guardrail (defense in depth), not a hard OS-level sandbox; the bash Guard and command classification provide additional layers.

- **`lstat` + reject all symlinks:** Refuse any path whose `lstat` reports a symbolic link, regardless of target. Rejected because legitimate symlinked directories are common in real projects: monorepo workspaces, `npm link`-ed packages, linked `node_modules`, and OS-managed `/etc`-style path layouts. Rejecting them all would make the boundary unusable in those projects.

## Consequences

- Symlink-escape attempts are detected: a symlink inside `cwd` pointing to `/etc/passwd` (or any external location) is treated as outside the boundary.
- Broken symlinks now fail-closed instead of silently passing or crashing. write/edit on a broken symlink is blocked; read on a broken symlink requires confirmation.
- Missing paths (e.g. a write target for a file not yet created) still evaluate lexically, preserving existing semantics for new-file creation inside the boundary.
- `allowedExternal` entries that resolve to a broken symlink are skipped; entries that simply do not exist fall back to lexical comparison (defensive — does not crash the loop).
- Each boundary check incurs a `realpathSync` syscall. The cost is negligible: boundary checks run at most once per tool call, not per byte.
- A TOCTOU window exists between evaluation and execution: a path could be replaced with a symlink (or vice versa) after the guard runs and before the tool executes. This is documented and accepted — the boundary is one layer of defense, not a sandbox.
- `isInsideDir` remains a pure string helper with its signature unchanged; resolution is performed by the boundary layer that calls it.
