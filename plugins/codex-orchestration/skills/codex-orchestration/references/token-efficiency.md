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

Validation cache keys include ordered command identity digest, relative cwd, executable/environment fingerprints, relevant source/test/config/lock hashes, and format version. Reuse only a completed deterministic pass for ordinary validation. Final/security/fresh validation bypasses the cache. Known failures are hypothesis hints, never success.

## Session lanes

Session lanes are local resume hints keyed by exact repo/worktree/branch/model/effort/cwd/sandbox/approval/tool-profile match. Lane identity uses a local HMAC key. Resume only when the current Codex exposes resume and every field matches; otherwise start a new session. Lane/resume IDs never enter telemetry or Git.

## Telemetry

Store approved numeric usage/counters and approved packet/blob IDs only. Calculate:

```text
uncached_input_tokens = input_tokens - cached_input_tokens
cache_hit_ratio = cached_input_tokens / input_tokens
```

Missing usage remains absent/`NOT_MEASURED`, never zero. Telemetry contains no path, branch, command, prompt, source/snippet, output/log, environment, auth, session/lane/resume ID, or arbitrary tag. Export is opt-in aggregate-only.

Use `scripts/token_lint.py` before handoff. CI performs static checks and never calls a paid model.
