# 0007 Audit log tamper-evidence via HMAC forward-chaining

The audit log is append-only but forgeable: any process with write access to `~/.pi/agent/security/audit.jsonl` can modify, insert, or delete entries undetected. This ADR introduces tamper-evidence via an HMAC-SHA256 forward chain, providing integrity protection without depending on a remote key-management service.

## Considered options

- **HMAC-SHA256 forward chain with a machine-local key (chosen):** Each entry carries `seq`, `prevHash`, and `hash`. The key (`audit.key`, 32 random bytes, mode 0o600) is generated on first run at `~/.pi/agent/security/audit.key` and never leaves the machine. `hash = HMAC-SHA256(key, prevHash || sha256(canonicalJSON(entry_body)))` creates a blockchain-style forward link over the entry body (which includes `seq`, `timestamp`, `sessionId`, `type`, `severity`, `details`). Insertion, deletion, and modification of any entry break the chain and are reported by `/security:verify`. The key never leaves the machine; compromise of the host is required to forge a self-consistent chain.

- **Detached signature per rotation file:** Sign each rotated file as a whole (e.g. an Ed25519 signature appended at rotation time). Rejected because a whole-file signature cannot localise tampering within a file — the verifier learns the file was modified but not which entry. The per-entry HMAC chain pinpoints the broken `seq`.

- **Sequence numbers only:** Add a monotonic `seq` to each entry with no cryptographic binding between entries. Rejected as trivially forgeable — an attacker can rewrite entries while preserving seq order. Provides ordering, not integrity.

- **Encryption at rest:** Encrypt the audit log so only an authorised reader can read it. Rejected as out of scope: disk encryption is an OS-level concern (LUKS, FileVault, BitLocker). The audit log needs integrity (detect tampering), not confidentiality (hide contents); the file is meant to be human-readable for forensics.

## Consequences

- Each entry carries three new fields: `seq` (monotonic per file), `prevHash`, and `hash`. Pre-existing entries written before this ADR lack these fields and are handled by a one-time `audit.migrate` record that seals the transition; its `prevHash` is a synthetic hash computed over the last pre-hash entry's available fields. Old entries are not rewritten in place — the migrate record marks the boundary.
- A machine-local key at `~/.pi/agent/security/audit.key` (mode 0o600) is auto-generated on first run via `crypto.randomBytes(32)`. The key is never transmitted off the machine. Compromise of the key enables undetected forgery of new chains; this extension provides tamper-evidence, not tamper-prevention — OS-level access control on the key file is the outer defence.
- `/security:verify` replays the chain over the current file plus any rotated files (`.1`, `.2`, …) and reports per-file OK or the `seq`/index where the chain breaks (tampering localised).
- On rotation, the current file is sealed with an `audit.roll` entry (chained) before being renamed to `.1`. The new empty file starts a fresh chain with `prevHash = "GENESIS"`. Each file is independently verifiable; the `audit.roll` marker is the logical link between files (a rotated file is expected to end with `audit.roll`, the next file is expected to start from `GENESIS`).
- Hash computation is best-effort: if the key cannot be loaded or hashing fails, the entry is appended without `hash`/`prevHash`/`seq` (graceful degradation) so the "audit must never crash the extension" guarantee is preserved.
- The forward chain detects modification, insertion, and deletion of entries within a file. It does not detect a wholesale replacement of the file by an attacker holding the key; defence against that requires OS-level access control on `audit.key` and is outside this extension's scope.
- Verification cost is O(n) over total entries; acceptable for the audit use case where files are bounded by rotation (default 10 MB / 3 files).
