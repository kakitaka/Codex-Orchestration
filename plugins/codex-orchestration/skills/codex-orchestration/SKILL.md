---
name: codex-orchestration
description: Use for natural-language questions or requests about whether Kimi K3 or another audited External Model is available or callable as Designer or another role, and for assigning models to Planner, Advisor, Designer, Executor, researcher, reviewer, writer, or supervisor roles. Also use when the user invokes Codex Orchestration to update the plugin, create custom roles, define a workflow, or set up, inspect, repair, change, disable, or temporarily override model routing. Keep the selected task model as root and preserve Codex's Goal, permissions, integration, and verification behavior.
---

# Codex Orchestration

The model selected when this Codex task started is already the orchestrator. Never ask the user to configure another one and never change the root model on this skill's behalf. This skill adds routes to Codex's existing multi-agent flow; it is not a second scheduler.

## Progressive-disclosure dispatch

Read this file first. Then read every matching reference below completely before acting. Do not load unrelated references. When a request spans rows, read only those rows.

| Request | Required reference |
| --- | --- |
| Invocation, seat labels, activation, read-only availability | [invocation-and-routing.md](references/invocation-and-routing.md) |
| Native setup, status, repair, disable, or plugin update | [native-lifecycle.md](references/native-lifecycle.md) |
| Planner, Advisor, Designer, or approval loop | [planner-advisor-workflow.md](references/planner-advisor-workflow.md) |
| Executor spawn, TASK_PACKET, budgets, tool output | [delegation.md](references/delegation.md) |
| Arbitrary or provider-pinned custom role | [custom-roles.md](references/custom-roles.md) |
| Token profiles, caches, session lanes, telemetry | [token-efficiency.md](references/token-efficiency.md) |
| State, secrets, paths, logs, threat boundaries | [security-and-state.md](references/security-and-state.md) |
| Capability mismatch, older client, or fallback | [troubleshooting.md](references/troubleshooting.md) |
| Audited External Model lifecycle | [external-models.md](references/external-models.md) |
| Provider/model facts and native routing boundaries | [providers-and-models.md](references/providers-and-models.md) |
| Rare legacy-contract audit only | [compatibility-contract.md](references/compatibility-contract.md) |

The compatibility contract preserves detailed published wording but is not a normal task dependency. Load it only for a compatibility audit or when a routed reference explicitly says a legacy detail is required.

## Stable authority rules

- The current task model remains the root. Root owns intent, canonical plan, decomposition, approvals, integration, final verification, and the user-facing result.
- Explicit user instructions win. An explicit `no subagents` instruction always wins.
- Model and reasoning resolution order: current user choice, applicable repository/global `AGENTS.md`, configured route, then token-profile recommendation. Never lower or replace a higher-precedence choice.
- Explicit seat labels are authoritative: `planner:` configures only Planner, `advisor:` only Advisor, `designer:` only Designer, and `executor:` only Executor. Never reinterpret a supplied `planner:` model as an Advisor.
- An omitted planner means the current root model plans. An omitted advisor means `advisor: none`; omitted designer means `designer: none`.
- Codex decides whether a plan helps and whether delegation is useful. Never force a spawn or fixed worker count. Keep simple, tightly coupled, context-heavy, and root-owned work with root.
- This skill does not create or change Goal state, weaken approvals or permissions, or change global agent limits.

## Stable routing rules

- Direct model overrides keep the root's provider. Verify same-provider identity before a direct override; otherwise require a provider-pinned custom agent.
- Every different-model, different-effort, or custom-agent child uses `fork_turns = "none"`. Never use the default `all`; full-history forks inherit root route and duplicate conversation context.
- A child receives one self-contained bounded packet and never spawns descendants or contacts another seat. Planner, Advisor, Designer, and Executors report only to root.
- Planner/Advisor failure, malformed output, unavailable route, stale plan, or exhausted review budget is not approval. Only `PLAN_APPROVED` releases Executor work; `PLAN_REVISE` returns to root with a compact cumulative findings ledger. Never exceed eight total Advisor reviews under the legacy profile.
- Designer may edit only explicitly delegated design artifacts, never revises the canonical plan, changes implementation code, or releases Executor.

## Stable packet and context rules

Use `TASK_PACKET_V1` for cross-model delegation. Required fields:

```text
VERSION
ROLE
STATIC_RULES
GOAL
BASE_REVISION
FILES_ALLOWED
FILES_FORBIDDEN
KNOWN_FACTS
CONSTRAINTS
ACCEPTANCE_CRITERIA
VALIDATION
OUTPUT_CONTRACT
```

Generate packets deterministically with repository-relative normalized paths and stable ordering. Put stable role/project/tool rules before the dynamic packet and current evidence. Do not include timestamps, UUIDs, session IDs, absolute user paths, raw conversation history, or unrelated Git state. If the packet cannot carry enough context safely, keep work with root.

## Stable safety and truth rules

- Never put API keys, OAuth/session tokens, credentials, conversation text, raw prompts, private source excerpts, or unredacted logs into Git, telemetry, task state, or model-facing diagnostics.
- Never authorize paid probes, provider changes, external publication, credential enrollment, destructive replacement, or deletion from an availability question or model seat label.
- State and caches stay under a contained ignored local directory, reject links/path traversal, write atomically, and fail closed on corruption or ambiguity.
- Report `native policy installed`, `policy effective`, `route accepted`, and `used and confirmed` as different states. Child prose claiming a model name is not proof. Never report a prompt preference as confirmed execution.
- Token and credit claims require measurements. Missing usage remains `NOT_MEASURED`; never call a model-weighted credit example fewer raw tokens.

## Public entry points

These are Codex prompts, not shell commands:

```text
$codex-orchestration:codex-orchestration setup executor: GPT-5.6 Luna Extra High
$codex-orchestration:codex-orchestration setup planner: Claude Fable 5 High, advisor: GPT-5.6 Sol High, executor: GPT-5.6 Luna Extra High
$codex-orchestration:codex-orchestration status
$codex-orchestration:codex-orchestration repair
$codex-orchestration:codex-orchestration disable
$codex-orchestration:codex-orchestration --update
```

Natural-language availability questions trigger read-only discovery only. Example: `is Kimi available to use as Designer?`

## Resources

Helper scripts live in `scripts/`; provider manifests in `providers/`. Run helpers only after reading the routed lifecycle/security reference. Use current-host capability detection rather than assuming a version supports a field.
