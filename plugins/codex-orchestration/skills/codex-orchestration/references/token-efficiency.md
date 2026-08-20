# Token efficiency

Use deterministic local code before LLM work. Token reduction must preserve task success and distinguish measured tokens from estimates.

## Context order

Keep exact stable prefixes ahead of task data:

1. system/static rules;
2. stable role;
3. stable project rules;
4. stable tool definitions;
5. dynamic `TASK_PACKET_V1`;
6. current task-specific evidence.

No timestamp, UUID, session ID, absolute path, unstable Git SHA, unordered JSON key, or redundant prose belongs in stable prompt builders.

## Profiles

`lean`, `balanced`, and `quality` constrain Advisor loops and packet/wave estimated-token budgets. `legacy` preserves the published eight-review behavior. Profiles recommend routes only after user instructions, `AGENTS.md`, and configured route. Omitted profile on legacy saved state preserves schema 5; explicit selection enables schema 6.

## Knowledge and validation reuse

The local knowledge index stores derived headings, symbols, imports, dependency names, relative paths, line numbers, and Git blob IDs only. It never stores source text, snippets, prompts, logs, embeddings, or LLM summaries. Revalidate containment and blob ID before reading a live range.

Validation cache keys keep command, executable, environment, source, test, configuration, and dependency-lock identities in separate canonical domains. Strict schema and key-digest checks reject malformed metadata but do not authenticate state writable by the same OS principal. Reuse requires an explicit untrusted-advisory lookup of a complete deterministic identity-complete pass for ordinary validation. Final, release, security, and fresh validation bypass the cache. Known failures are hypothesis hints, never success.

## Session lanes

Session lanes are local resume hints keyed by exact repo/worktree/branch/model/effort/cwd/sandbox/approval/tool-profile match. Resume requires current-client support plus a caller-held capability that authenticates the lane, packet, resume handle, exact profile, and expiry; the capability is never stored with lane data. Any mismatch starts a new session. Lane/resume IDs never enter telemetry or Git.

## Telemetry

Store approved numeric usage/counters and approved packet/blob IDs only. Calculate:

```text
uncached_input_tokens = input_tokens - cached_input_tokens
cache_hit_ratio = cached_input_tokens / input_tokens
```

Missing usage remains absent/`NOT_MEASURED`, never zero. Telemetry contains no path, branch, command, prompt, source/snippet, output/log, environment, auth, session/lane/resume ID, or arbitrary tag. Export is opt-in aggregate-only.

Use `scripts/token_lint.py` before handoff. CI performs static checks and never calls a paid model.
