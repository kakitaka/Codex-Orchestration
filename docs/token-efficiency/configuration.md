# Configuration and fallback

Token-efficiency helpers are opt-in except static Skill slimming and CI lint. Existing schemas remain readable without status-time migration; new setup writes combined schema 8 while an omitted token profile retains legacy behavior.

## Native profile

After confirming the active binary and shared clients, preview then apply native setup with `--token-profile lean|balanced|quality|legacy`. Omitting the option:

- records a nullable profile on new schema-8 state;
- preserves an already saved schema-6 or schema-8 profile during explicit setup;
- never silently chooses a new profile.

The validator accepts historical schemas 1–5, disambiguates the two exact
schema-6 shapes (`token_profile` versus `preset`), and accepts callable preset
schema 7. Read-only status never rewrites those files.

Profiles govern Advisor-loop and estimated packet/wave budgets only. Model/effort precedence remains user, applicable `AGENTS.md`, configured route, profile recommendation.

## Local state

Use repository-local `.codex-state/` or an explicitly contained equivalent. Do not place it under a symlink/reparse point or commit it. Recommended logical stores:

```text
.codex-state/context/index.sqlite
.codex-state/validation-cache.json
.codex-state/session-lanes.json
.codex-state/.session-lane-key
.codex-state/usage/usage.jsonl
```

The exact helper API chooses names and enforces containment. Lane data and its authentication material cannot alias the same file. Do not hand-edit state to bypass schema validation.

## Bounded commands

Call `bounded_run.py --compact-json` with an ordered argv, byte/time bounds, and no diagnostic-log option for normal model-facing work. The compact projection omits duplicate combined stream boundaries; the default CLI shape remains available for compatibility. Prefer targeted native command flags first. Enable a diagnostic log only for a concrete debugging need; its path must stay relative to the approved state root.

## Hooks

Codex 0.147 exposes stable hooks. Hook activation remains opt-in because project hooks require trust and older/shared clients may reject current fields. The enabled helper first probes the executing Codex binary and exact `hooks` feature readback; schema-valid event JSON alone is not a capability signal. Use `token_hook.py` only for:

- `PreToolUse`: conservative non-blocking warning;
- `UserPromptSubmit`: bounded `additionalContext` hint.

Do not configure command rewriting or PostToolUse output replacement. A project may add the helper through trusted `hooks.json` or inline `[[hooks.PreToolUse]]` / `[[hooks.UserPromptSubmit]]` only after the capability probe and active schema accept the event and command hook. A disabled, unsupported, malformed, or timed-out probe emits no hook advice. The fallback is an explicit bounded helper command.

## Session lanes

Resume is eligible only when repo, worktree, branch, model, effort, cwd, sandbox, approval, and tool profile all match, the active client exposes resume, and a caller-held capability authenticates the lane, packet, handle, and expiry. The capability is never stored with lane data. A mismatch, missing capability, expired handle, corrupt state, or unsupported resume starts a new session. Session/resume identifiers remain local and never enter Git or telemetry.

## Capability snapshot

Implementation was checked against local `codex-cli 0.147.0`:

| Capability | Probe result | Behavior |
| --- | --- | --- |
| lifecycle hooks | stable/enabled | opt-in hook helper |
| multi-agent | stable/enabled | bounded `fork_turns="none"` packet |
| direct spawn model overrides | independently exposed by current v2 schema | manage/read back when supported; false=`DISABLED`, absent=`UNSUPPORTED` |
| `resume` command | exposed | exact-match lane eligibility only |
| native token-budget feature | unavailable/disabled | plugin-side deterministic estimates |
| usage counters | not guaranteed in every client path | absent remains `NOT_MEASURED` |

Always rerun capability/strict-config probes on the executing host. Version text alone is not authority.
