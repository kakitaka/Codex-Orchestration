# Compatibility and fallback

Use feature detection, not version inference, whenever a Codex config, hook, agent, model, effort, namespace, or resume feature may be absent.

## Capability order

1. active host App Server/capability schema;
2. current model catalog and accepted spawn controls;
3. loaded scope-qualified custom agent;
4. exact binary diagnostics;
5. current official provider documentation.

A config parse probe is not a live route confirmation. A shell CLI catalog may differ from Desktop. A saved role is not hot-loaded into the current task.

## Safe fallbacks

- Native policy unsupported or overridden: use task-local root orchestration without writing unknown fields.
- Hooks unsupported/untrusted: run the bounded helper explicitly; do not install a fictional hook field.
- Resume unsupported or lane mismatch: start a new session and keep lane data local.
- Direct provider identity ambiguous: use a provider-pinned custom agent or report unavailable.
- Packet too large or semantically incomplete: keep work with root.
- Advisor unavailable/malformed/exhausted: block Executor; failure is never approval.
- Validation cache uncertain/corrupt/final/security-critical: run fresh validation.
- Telemetry usage absent: report `NOT_MEASURED`.

Older clients sharing the same config can reject newer fields. Probe every known binary in isolation before setup. Prefer updating an incompatible client; use `--allow-incompatible-client` only after explicit acceptance. Disable remains available.

After setup, update, repair, disable, or custom-agent changes, fully quit and reopen Codex and start a new task. A loaded MCP process cannot be replaced retroactively.
