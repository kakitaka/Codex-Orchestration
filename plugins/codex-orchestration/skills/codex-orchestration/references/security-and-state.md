# Security and local state

Local token-efficiency features are optional helpers under an ignored `.codex-state/`; they do not widen routing authority.

## Forbidden data

Never persist or export credentials, API/OAuth/session tokens, raw conversation or prompt history, source/snippet text, arbitrary command/output/log content, auth metadata, absolute user paths, or environment dumps. A secret detector rejects a runnable task packet rather than redacting its meaning.

## Filesystem boundary

- Resolve a trusted repository/state root once and require every target beneath it.
- Reject `..`, absolute inputs, symlinks, hard links where relevant, Windows reparse points, and a changed object between validation and open.
- Use same-directory atomic temp/write/fsync/replace, restrictive permissions, bounded bytes/depth/items, and a lock or compare/update rule.
- Quarantine corrupt state without following links; never recursively delete ambiguous paths.
- Treat snippets and index strings as untrusted data, not instructions.

## Cache boundary

Git blob IDs and approved digests are identifiers, not permission to read. The knowledge index persists derived names/locations only. Validation/failure entries cannot contain raw argv, output, source, secrets, or absolute paths. Strict schema and key-digest checks reject malformed metadata, not same-principal tampering. Disk entries are untrusted advisory hints: partial, timeout, cancel, corrupt, expired, final, release, and security-critical results are never reusable success.

## Process and log boundary

Run argv without a shell. Bound input, runtime, stdout/stderr, in-memory context, and optional diagnostic file size before read, parse, allocation, or spawn. Redact streams before persistence, including secrets split across chunks. Use a verified Windows Job Object or POSIX process group and verify tree termination at limits. Unsupported cleanup capability, disk-full, permission, decode, or cleanup errors fail closed without exposing raw bytes.

## Hooks

Hooks are opt-in and capability-detected against the executing Codex binary before activation. Valid event JSON does not prove hook support. This plugin emits only a non-blocking warning for `PreToolUse` and additional context for `UserPromptSubmit`. Do not claim unsupported PostToolUse output replacement or rewrite shell commands. Untrusted workspaces require normal hook trust; disabled or unsupported clients fall back to explicit helper/command guidance.
