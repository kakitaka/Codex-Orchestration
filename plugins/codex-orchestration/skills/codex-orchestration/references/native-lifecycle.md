# Native lifecycle

Use this reference for persistent native routing setup, status, repair, disable, or plugin update. Read [security-and-state.md](security-and-state.md) too before a write.

## Setup

Persistent setup is preview-first and uses `scripts/configure_native_routing.py`. It manages only:

- `hide_spawn_agent_metadata`
- capability-detected `expose_spawn_agent_model_overrides`
- `tool_namespace`
- `multi_agent_mode_hint_text`
- `usage_hint_text`

The `terra-luna-sol-escalation` preset additionally and reversibly manages
`features.multi_agent`, `agents.enabled`, `agents.default_subagent_model`, and
`agents.default_subagent_reasoning_effort`. It never writes a worker or concurrency
limit.

Use Codex App Server `config/read(includeLayers=true)` then `config/batchWrite(expectedVersion=...)`, followed by exact user/effective readback. Do not add `enabled = true`. The validated namespace is `tool_namespace = "agents"`; never patch the reserved `collaboration.spawn_agent` schema.

Capability-test the four core fields and the direct-override exposure field when present with every known shared-config client under an isolated `CODEX_HOME`. A false exposure readback is `DISABLED`; an absent field is `UNSUPPORTED`, not effective. `--allow-incompatible-client` requires explicit user acceptance. Disable must remain available even when compatibility probes fail.

Normal setup stores pre-setup values and rolls back config if state persistence fails. Refuse pre-existing hint replacement unless `--replace-existing-policy` is explicit. New setup writes combined schema 8. Status accepts historical schemas 1–5, both exact schema-6 variants, and schema 7 without migration.

### Terra–Luna–Sol escalation preset

Treat the exact request `setup preset: Terra-Luna-Sol Escalation` as persistent
native setup for `--preset terra-luna-sol-escalation`. It seals Luna @ Max as the
default Executor route, leaves Planner, Advisor, and Designer unset, and records no
root model. The user selects Terra @ Max when starting the next task. Sol @ Max is
an escalation-only audit for the enumerated high-risk cases in
[providers-and-models.md](providers-and-models.md), never a persisted Advisor.

Exact policy: expected root `gpt-5.6-terra` at `max`; saved Executor
`gpt-5.6-luna` at `max`; optional escalation Advisor `gpt-5.6-sol` at `max`.
Ordinary work has no Advisor approval loop. Escalation requires security, auth, or
secrets; database schema or destructive migration; public API or
backward-compatibility risk; cross-subsystem architecture change; repeated
implementation or test failures; unresolved root cause; high-risk release; or an
explicit user request. Immediately verify same-provider inheritance and current
callability; do not substitute a model when either check fails.

Preview, then apply only after the preview succeeds:

```text
python <skill-dir>/scripts/configure_native_routing.py --codex-bin <active-codex-binary> --preset terra-luna-sol-escalation
python <skill-dir>/scripts/configure_native_routing.py --codex-bin <active-codex-binary> --preset terra-luna-sol-escalation --apply
```

An optional `--token-profile` may accompany the preset because it controls packet,
wave, and review budgets rather than changing the sealed route. Never combine the
preset with direct seat arguments. Entering or leaving the preset boundary requires
disable followed by fresh setup so prior subagent values remain restorable. Spawn
the saved Executor by omitting direct `model` and `reasoning_effort`.

## Status and repair

Status distinguishes user-layer installation from effective workspace policy and live route confirmation. `status --require-effective` fails on override, drift, missing role, or unavailable required route.

Repair requires preview then `--repair --apply`. It may restore only marked hint strings when every other managed control and saved snapshot matches. It leaves the original restore snapshot intact, preserves concurrent edits, and never reads or changes credentials, chats, sessions, or provider secrets. Restart Codex and start a new task after repair.

## Disable and change

Disable compares every owned value before restoration. Refuse to erase managed fields after user drift. Without valid state, only marked strings prove ownership; leave fields with unknown prior values intact. Setup/change/disable never deletes user-owned custom roles.

An Opus-involved seat replacement or move follows the existing disable-then-fresh-setup contract. Fable/Opus details remain in [providers-and-models.md](providers-and-models.md).

## Update the plugin

Update only an enabled installation from the canonical Git marketplace after strict native inventory. Use Codex's native plugin manager:

```text
codex plugin list --json
codex plugin marketplace upgrade codex-orchestration
codex plugin add codex-orchestration@codex-orchestration
```

Never run `plugin remove` during update. Do not wrap these commands in a custom downloader or inspect/touch routing, credentials, chats, or sessions. Verify canonical source, nondecreasing SemVer, and retained enabled state. Restart Codex Desktop and start a new task; the current task retains already loaded instructions and MCP processes.
