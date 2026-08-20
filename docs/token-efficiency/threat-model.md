# Threat model

## Assets

- source and repository integrity;
- provider/API/OAuth/session credentials;
- Codex conversation/session privacy;
- routing authority and user model/effort choice;
- correctness of validation reuse;
- bounded local CPU, memory, disk, and output.

## Trust boundaries

Codex, selected provider endpoints, OS credential storage, and explicitly trusted hook/CLI binaries are dependencies. Repository source, indexed text, hook JSON, task fields, command output, cache files, and concurrent writers are untrusted inputs. Git blob IDs identify content; they do not authorize reading it.

## Threats and controls

| Threat | Control | Negative test |
| --- | --- | --- |
| traversal, symlink/reparse escape, ancestor swap | contained relative paths; reject links/reparse; snapshot identities and revalidate before/after open/replace | `..`, absolute, link/junction, changed ancestor during operation |
| state corruption or concurrent overwrite | bounded strict schema; same-directory atomic replace; lock/compare-update; quarantine | truncated/oversize/deep JSON, two writers |
| source/prompt leakage through index | derived metadata only; live range after blob validation; never persist range | SQLite byte scan for source marker |
| telemetry/lane cross-contamination | separate schemas/files; exact allowlist; reject unknown before mutation | path/session/command/prompt/output/auth fields |
| validation false hit | domain-separated versioned identities; exact complete deterministic pass; advisory-only disk hit; final/release/security bypass | cross-namespace collision, changed hash/env/status, timeout/cancel/corrupt |
| repeated known failure treated as pass | failure entries are hints only | known failure never returns success |
| prompt injection in indexed text | symbols/headings treated as data; no indexed instruction execution | hostile heading/query/wildcard |
| secret in task packet | field-level detection and fail-closed rejection | token/key patterns in every field |
| secret in streamed output | overlap-aware redaction before memory/disk; bounded binary decode | secret split across chunks, invalid UTF-8 |
| output/disk/process exhaustion | bounds before read/parse/spawn; no log default; verified process-tree termination | exact/over cap, infinite output, child process, cleanup failure, disk-full |
| unsupported hook/config invention | live host capability probe plus current schema validation; supported response fields only; manual fallback | disabled capability with valid event, unknown event/config response |
| route downgrade | precedence user > `AGENTS.md` > configured route > recommendation | explicit/repository route suppresses profile |
| cache/prompt instability | canonical UTF-8/NFC/LF/ordered JSON; no timestamps/UUIDs/absolute paths | Windows/POSIX golden packet |

## Non-goals and residual risk

- Instruction-only seat isolation is not engine-enforced when MCP caller identity is absent.
- Windows ACL hardening is limited where Python lacks a portable exact DACL API; unsafe path/reparse/hard-link behavior still fails closed.
- Identity revalidation detects observed ancestor replacement. Platforms without directory-relative open/replace retain a narrow hostile OS scheduling race; local cache/state is therefore not a secret store or cross-trust security boundary.
- A cache file writable by the same OS principal is not authenticated evidence. Strict schema and key-digest checks reject malformed metadata only. Disk hits remain explicitly untrusted advisory hints and cannot release final, security, or release validation.
- Resume capability and usage counters vary by client. Fallback starts a new session and reports missing usage.
- Static packet token estimates cannot prove provider-side billed tokens or cache hits.
- Final/security-critical validation is rerun even when a cache key matches.

State/cache corruption may discard optimization state. Process-tree cleanup failure is a hard execution error, not successful completion. Neither condition may weaken source integrity, approvals, or authoritative validation outcome.
