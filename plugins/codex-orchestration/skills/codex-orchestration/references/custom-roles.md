# Custom roles

Use this reference for arbitrary user-owned roles or durable provider-pinned Planner/Advisor/Executor routes. For audited External Models, also read [external-models.md](external-models.md).

## Locations and ownership

Project role:

```text
<trusted-project>/.codex/agents/<role-name>.toml
```

Personal role:

```text
~/.codex/agents/<role-name>.toml
```

Arbitrary native roles are user-owned. Preview before creation, use a new regular file, refuse symlinked/hard-linked paths and collisions, and never overwrite or remove an existing role implicitly. Start a new task after creation because roles do not hot-load.

## Provider pinning

Direct child overrides inherit root provider. A cross-provider durable role requires an already authenticated Codex-compatible provider and a loaded custom agent that pins `model`, `model_reasoning_effort`, and `model_provider`. Never create an unreviewed provider definition or infer Responses-protocol compatibility from an Anthropic Messages endpoint.

Verify personal role names with `--personal-route-names`, current workspace shadowing, exact scope, and effective metadata before use. A same-name project role blocks trust in a personal route.

## Authority

Role instructions are bounded by root's packet, current task permission mode by default, and normal sandbox/approval behavior. They never bypass the parent task's authority. Root orchestrator owns every handoff, integration, and verification.

Custom workflows such as `researcher -> reviewer -> writer` leave Goal lifecycle and limits under Codex's normal Goal controls. The plugin does not silently create, pause, resume, or clear a Goal.
