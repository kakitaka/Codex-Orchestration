# Token-efficiency architecture

Codex-Orchestration 0.11.0 adds deterministic local helpers around the existing root/Executor/auditor workflow. Helpers reduce repeated context and noisy tool results; they do not replace Codex scheduling, sandboxing, approval, or provider routing.

## Data flow

```text
stable skill/router
        |
        +--> one routed reference
        |
        +--> derived knowledge lookup --(blob revalidation)--> live bounded range
        |
        +--> canonical TASK_PACKET_V1 --> duplicate/wave budget --> child fork_turns=none
        |
        +--> bounded argv tool --> validation/failure cache hint
        |
        +--> approved counters only --> local telemetry aggregate
```

Stable instructions precede dynamic packet/evidence so identical prefixes remain byte-identical. No timestamp, UUID, session ID, absolute path, or changing Git SHA enters a stable prompt builder.

## Components

| Component | Deterministic input | Persistent output | Never persists |
| --- | --- | --- | --- |
| `task_packet.py` | fixed fields and repository-relative paths | none | conversation, secret-bearing or semantically redacted packets |
| `token_profiles.py` | profile plus higher-priority route constraints | nullable profile in current schema 8; historical schema 6 remains readable | user/model override mutation |
| `context_index.py` | tracked files and Git blob IDs | derived headings, symbols, imports, line numbers | source, snippet, prompt, embedding, LLM summary |
| `validation_cache.py` | domain-separated command, executable, environment, dependency, source, test, and configuration fingerprints | bounded untrusted advisory pass/failure metadata | argv text, output, source, secrets, absolute paths |
| `session_telemetry.py` | exact lane fields or telemetry allowlist | separate lane state and telemetry state | capability secret, conversation, raw prompt, logs, cross-store IDs |
| `bounded_run.py` | argv and byte/time bounds | no log by default; optional capped redacted diagnostic | raw output or unredacted secret |
| `token_hook.py` | bounded current hook JSON | supported hook response only | prompt history or rewritten command |
| `token_lint.py` | repository text/paths | findings only | model calls or telemetry |

## Context lifecycle

1. Read the thin `SKILL.md`.
2. Select only matching references.
3. Query the derived index by path/symbol/heading/blob when prior knowledge may apply.
4. Fetch a live source range only after containment and current-blob validation.
5. Build canonical `TASK_PACKET_V1`; reject secrets and hard-budget excess.
6. Spawn with `fork_turns="none"`; never send full history.
7. Bound tool output; use exact advisory validation hits only for ordinary work. Final, release, and security validation reruns.
8. Record numeric usage/counters when exposed; leave missing fields unmeasured.

## Model and effort precedence

The helper recommendation ladder is conditional:

```text
Luna medium -> Terra medium/high -> Sol high -> Max only after risk or unresolved difficulty
```

Resolution order is user instruction, applicable `AGENTS.md`, configured route, then profile recommendation. The AGENTS parser must pass an exact structured model/effort pair; free text cannot silently elevate a route. A valid repository requirement therefore remains authoritative. Profiles cannot lower a selected route, approve a plan, or release an Executor.

## State boundary

All runtime state is local and Git-ignored under `.codex-state/`. Knowledge, validation, lane, and telemetry schemas are separate. Atomic/contained writes, bounded payloads, corruption recovery, and link/reparse/hard-link rejection apply to every state file. Strict schema and key-digest checks reject malformed cache metadata; they do not authenticate state writable by the same OS principal. See [threat-model.md](threat-model.md).
