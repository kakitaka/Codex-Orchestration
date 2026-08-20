# Delegation and bounded execution

Use this reference only when root has an approved, independent implementation or audit slice.

## Spawn

- Use `fork_turns = "none"` for different model, effort, or custom agent. Never use `fork_turns = "all"` with overrides.
- Send one deterministic `TASK_PACKET_V1`; never copy full conversation history.
- Give exact non-overlapping write ownership. A child cannot redesign root's plan, contact another seat, or spawn descendants.
- Do not delegate merely to prove orchestration. Keep sequential, small, tightly coupled, or context-heavy work with root.
- No fixed worker limit. Control duplication and cost through packet/wave budgets and exact duplicate detection.

## TASK_PACKET_V1

Render stable role/project/tool instructions first, then dynamic packet and current evidence. `TASK_PACKET_V1` has exactly these 12 fields, in this order; do not add aliases or extra keys:

1. `VERSION`
2. `ROLE`
3. `STATIC_RULES`
4. `GOAL`
5. `BASE_REVISION`
6. `FILES_ALLOWED`
7. `FILES_FORBIDDEN`
8. `KNOWN_FACTS`
9. `CONSTRAINTS`
10. `ACCEPTANCE_CRITERIA`
11. `VALIDATION`
12. `OUTPUT_CONTRACT`

Canonical form uses normalized Unicode, LF newlines, repository-relative `/` paths, deterministic ordering, compact UTF-8 JSON, and no terminal newline. Secret detection rejects packet creation; it never silently redacts a runnable packet. Use packet digest to stop exact duplicate assignments. Legacy callers may normalize their input aliases in the compatibility builder, but emitted packets retain only the 12 canonical fields above.

## Budget and routing

Soft packet/wave limits trigger root review; hard limits block dispatch. A budget limit never approves a plan or releases a worker. Every hard-budget rejection exposes this exact deterministic remediation sequence:

```text
deduplicate repeated evidence -> replace full source/logs with bounded relevant snippets -> split into independent packets
```

Apply the stages in order. Do not silently truncate executable work or release a rejected packet. Generic recommendation ladder when no higher-priority route applies:

```text
Luna medium -> Terra medium/high -> Sol high -> max only for unresolved difficulty or high risk
```

User choices, applicable `AGENTS.md`, and configured routes always outrank this recommendation. Escalate effort/model only after concrete failure, ambiguity, security/data-loss risk, or a high-risk final audit.

## Tool output

Prefer targeted commands, `--stat`, `--name-only`, short tracebacks, focused `rg`, and relevant line ranges. Do not put recursive listings, full diffs/logs, verbose tests, huge JSON, or full source files into history.

Use `bounded_run.py` for noisy commands. Default keeps no full log. Optional local diagnostic logs are redacted, capped, contained, ignored by Git, and represented to the model only by error/category, bounded first/last context, and relative path.
