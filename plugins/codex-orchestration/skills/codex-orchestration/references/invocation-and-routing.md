# Invocation and routing

Use this reference for explicit invocation, natural-language discovery, literal seat assignments, activation reporting, and current-task overrides.

## Invocation

`$codex-orchestration:codex-orchestration` at the start of an ordinary Codex prompt is explicit invocation. `/skills` is Codex discovery, not a plugin command. Natural-language questions about an audited External Model or a model assigned to Planner, Advisor, Designer, Executor, researcher, reviewer, writer, or supervisor are implicit invocation.

Implicit invocation is discovery, not mutation authority. For availability, run read-only status and distinguish:

- `supported`: bundled manifest recognizes the exact provider/model;
- `configured`: required local non-secret provider and role records exist;
- `locally ready`: local authorization checks pass;
- `callable now`: current task exposes the exact sealed route;
- `used and confirmed`: runtime identity is mechanically exposed.

Never infer External Model availability from currently exposed MCP or subagent tools. A visible Fable tool is not an exhaustive provider inventory. Read-only discovery never authorizes configuration, credentials, Gate 0 billing, connection, or spend.

## Seats and omissions

Treat labels literally and preserve user order. Omission rules:

- Planner omitted: root plans; no Planner route.
- Advisor omitted: `Advisor: none`; do not ask a separate Advisor question.
- Designer omitted: `Designer: none`.
- Executor omitted during persistent setup: collect the missing required Executor, without reinterpreting another seat.

An explicit External Model seat label such as `Designer: Kimi K3` enters the audited External Model status lifecycle. It never becomes `--designer-model`, never enters native routing state, and never uses `agents.spawn_agent`. If ready, root uses the sealed invoke path; otherwise report the exact lifecycle state and next action.

## Activation reporting

Print one plain line per explicitly supplied model-bearing seat, preserve the user's seat order, and omit implicit-root or `none` seats:

```text
Planner — Fable 5 high: Activated
Designer — Kimi K3: Activated
Executor — GPT-5.6 Sol high: Activated
```

Use `Activated` only after the exact route is locally ready and callable for the task. Otherwise print its lifecycle state and next action. Requested text, saved config, or model self-report does not prove runtime use.

## Current-task override

A current-task override is temporary and does not rewrite persistent setup. User model/effort/no-subagent instructions remain authoritative. Direct routes require the inherited provider to match; an ambiguous provider requires a scope-qualified custom agent.
