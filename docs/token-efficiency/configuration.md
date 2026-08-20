# Configuration and fallback

Token-efficiency helpers are opt-in except static Skill slimming and CI lint. Existing setup without a token profile retains schema 5 and legacy behavior.

## Native profile

After confirming the active binary and shared clients, preview then apply the existing native setup with `--token-profile lean|balanced|quality|legacy`. Omitting the option:

- keeps new/legacy schema-5 state at schema 5;
- preserves an already saved schema-6 profile;
- never silently chooses a new profile.

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

The exact helper API chooses names and enforces containment. Do not hand-edit state to bypass schema validation.

## Bounded commands

Call `bounded_run.py` with an ordered argv, byte/time bounds, and no diagnostic-log option for normal work. Prefer targeted native command flags first. Enable a diagnostic log only for a concrete debugging need; its path must stay relative to the approved state root.

## Hooks

Codex 0.147 exposes stable hooks. Hook activation remains opt-in because project hooks require trust and older/shared clients may reject current fields. Use `token_hook.py` only for:

- `PreToolUse`: conservative non-blocking warning;
- `UserPromptSubmit`: bounded `additionalContext` hint.

Do not configure command rewriting or PostToolUse output replacement. A project may add the helper through trusted `hooks.json` or inline `[[hooks.PreToolUse]]` / `[[hooks.UserPromptSubmit]]` only after its active Codex schema accepts the event and command hook. If unsupported, run bounded helpers explicitly.

## Session lanes

Resume is eligible only when repo, worktree, branch, model, effort, cwd, sandbox, approval, and tool profile all match and the active client exposes resume. A mismatch, missing key, corrupt state, or unsupported resume starts a new session. Session/resume identifiers remain local and never enter Git or telemetry.

## Capability snapshot

Implementation was checked against local `codex-cli 0.147.0`:

| Capability | Probe result | Behavior |
| --- | --- | --- |
| lifecycle hooks | stable/enabled | opt-in hook helper |
| multi-agent | stable/enabled | bounded `fork_turns="none"` packet |
| `resume` command | exposed | exact-match lane eligibility only |
| native token-budget feature | unavailable/disabled | plugin-side deterministic estimates |
| usage counters | not guaranteed in every client path | absent remains `NOT_MEASURED` |

Always rerun capability/strict-config probes on the executing host. Version text alone is not authority.
