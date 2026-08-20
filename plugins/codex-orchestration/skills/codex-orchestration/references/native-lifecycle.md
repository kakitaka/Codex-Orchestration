# Native lifecycle

Use this reference for persistent native routing setup, status, repair, disable, or plugin update. Read [security-and-state.md](security-and-state.md) too before a write.

## Setup

Persistent setup is preview-first and uses `scripts/configure_native_routing.py`. It manages only:

- `hide_spawn_agent_metadata`
- capability-detected `expose_spawn_agent_model_overrides`
- `tool_namespace`
- `multi_agent_mode_hint_text`
- `usage_hint_text`

Use Codex App Server `config/read(includeLayers=true)` then `config/batchWrite(expectedVersion=...)`, followed by exact user/effective readback. Do not add `enabled = true`. The validated namespace is `tool_namespace = "agents"`; never patch the reserved `collaboration.spawn_agent` schema.

Capability-test the four core fields and the direct-override exposure field when present with every known shared-config client under an isolated `CODEX_HOME`. A false exposure readback is `DISABLED`; an absent field is `UNSUPPORTED`, not effective. `--allow-incompatible-client` requires explicit user acceptance. Disable must remain available even when compatibility probes fail.

Normal setup stores pre-setup values and rolls back config if state persistence fails. Refuse pre-existing hint replacement unless `--replace-existing-policy` is explicit. An absent token profile preserves legacy schema 5; explicit profile selection may use schema 6.

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
