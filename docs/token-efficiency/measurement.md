# Measurement protocol

Token efficiency has two evidence levels: deterministic static metrics and live usage emitted by an authorized model run. Never substitute estimates for live counters.

## Baseline at specification commit

Commit `ee43f3a522460888fa7c4174f53e9e5b4980267c`:

| Metric | Baseline |
| --- | ---: |
| core `SKILL.md` | 56,463 bytes / 707 lines |
| all Skill Markdown | 98,030 bytes |
| root `AGENTS.md` | 732 bytes / 7 lines |
| quick preflight | pass locally; hosted gates partial |
| native-Windows full preflight | pre-existing portability failures in POSIX metadata/hard-link fixtures plus fake executable naming |

The final comparison must use the same paths and deterministic tokenizer/byte estimator. Full-suite acceptance is differential: new failures block; a narrowly documented Windows baseline may remain only when node ID and normalized signature match the pre-change commit.

## Fixed benchmark tasks

Use no paid model in normal CI. Run every fixture from the same exact clean commit; a skipped, mixed-checkout, or unsuccessful fixture fails the benchmark gate. Static fixtures cover:

1. explicit setup/status routing;
2. one small isolated implementation packet;
3. one duplicate packet in a wave;
4. unchanged symbol/heading lookup;
5. unchanged deterministic validation pass;
6. repeated known failure hint;
7. bounded noisy tool output;
8. exact-match and mismatched session lane.

Record task success and deterministic test result beside context byte/token estimates. Validation-cache hits remain untrusted advisory evidence. Security, release, and final validation bypass result reuse.

## Usage fields

When an authorized client exposes usage, record only:

- `input_tokens`
- `cached_input_tokens`
- `uncached_input_tokens = input_tokens - cached_input_tokens`
- `output_tokens`
- `reasoning_output_tokens`
- `cache_hit_ratio = cached_input_tokens / input_tokens`
- approved agent/tool/read/duplicate/cache-hit counters

If any counter is unavailable, store/report `NOT_MEASURED`, not zero. No raw prompt, source, output, command, path, session, or auth data enters measurement artifacts.

## Free passive local report

`scripts/passive_usage_report.py` reads already-written Codex session JSONL and writes nothing. It performs no network or model call, exports numeric aggregates only, and never emits a path, session ID, prompt, source, or tool output. It sums event-level `last_token_usage`; it deliberately ignores cumulative `total_token_usage` so a session is not double-counted.

Compare explicit periods in one command:

```text
python scripts/passive_usage_report.py --sessions-root <codex-sessions-root> --baseline-start 2026-08-20T03:59:30Z --baseline-end 2026-08-20T14:23:44Z --start 2026-08-20T23:58:05Z --end 2026-08-21T04:27:21Z --pretty
```

The report gives input/cached/uncached/output token rates, cache-hit ratio, input and uncached-input tokens per usage event, model-and-effort strata, root-or-legacy versus worker strata, and fixed task-family strata. Model identifiers must match a bounded current Codex model shape or become `unknown`; arbitrary metadata strings are never exported. The task-family vocabulary is `implementation`, `research`, `audit`, `validation`, `documentation`, `configuration`, `operations`, `testing`, and `other`. Missing or malformed role metadata is treated as `root_or_legacy`; missing or unknown task metadata is treated as `other`. Task-family output is limited to that bounded vocabulary and never emits a raw task name. A monotone high-water estimate of the 10,080-minute quota's percentage-points/hour is also included. Quota percentage and raw token volume are separate measures.

Comparison uses usage-event shares with a fixed absolute tolerance of 0.10 (10 percentage points) for model, effort, their joint distribution, root/worker, and task-family. Any `unknown` model/effort or `other` task-family share is uninformative and returns a `MISSING_*_MIX` reason; it is never accepted as evidence of matched work. A changed or unmeasured composition returns `comparison.status = NOT_COMPARABLE`; the stable `comparison.metrics` keys remain present but all are `NOT_MEASURED`, so no token delta is implied. A like-for-like comparison returns `COMPARABLE` and keeps `interpretation = OBSERVATIONAL_ONLY`.

Quota-rate comparison is `NOT_MEASURED` unless each report has exactly one measured weekly window and both windows have the same normalized reset bucket. Multiple windows, a missing bucket, or different buckets are never combined.

## Comparison

Report before and after independently for core Skill bytes/lines, selected-reference bytes, deterministic packet bytes, duplicate suppression, advisory validation/failure-cache hits, and bounded output bytes. Bind baseline bytes to the declared Git object and after bytes to the clean benchmark commit. Claim provider cache-hit improvement only from actual cached/input counters; otherwise report architecture readiness plus `NOT_MEASURED`.
