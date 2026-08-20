# CI quality gate

`required-gate` is the single merge gate for repository CI. Every pull request and
every push to `main` runs without `paths` exclusions. Failure, cancellation, or a
skipped dependency makes the aggregate gate fail closed.

## Threat model

An ordinary contributor may change any tracked file, including workflows, tests,
configuration, documentation, and assets. CI runs candidate code only with
read-only repository permission; CODEOWNERS plus the hosted ruleset protects the
CI trust boundary. Repository administrators remain able to change host settings.

## Metrics

- Branch coverage measures all Python under `scripts/` and the packaged skill
  `scripts/` directory. The conservative initial floor is 68.0%; raise it only
  after hosted runs establish a stable baseline. CI uploads `coverage.json`.
- Cosmic Ray mutates only `external_cli_trust.py`, a representative security
  boundary, with a five-second per-mutant timeout.
  CI uploads the survival rate. The score is informational until enough runs
  establish a stable project threshold; tool, baseline, or execution failures
  still fail the job.

## Hosted protection

Repository files alone do not activate merge protection. Until the GitHub ruleset
below is enabled and smoke-tested, status is `IMPLEMENTED_NOT_ACTIVATED`.

Protect `main` with one ruleset:

1. Require pull requests, one code-owner approval, dismissal of stale approvals,
   approval after the latest push, resolved conversations, and an up-to-date base.
2. Require the default-branch `.github/workflows/ci.yml` workflow when supported;
   otherwise require the `required-gate` check from GitHub Actions. Also require
   the existing `analyze (python)` CodeQL check.
3. Block force pushes and branch deletion. Give routine contributors no bypass.

`CODEOWNERS` covers workflows, tests, production scripts, and metric settings, so
an ordinary pull request cannot weaken the trust boundary without owner approval.

Positive smoke test: a documentation-only pull request runs every dependency and
ends with `required-gate=success`. Negative smoke tests: a failing test, cancelled
dependency, or skipped dependency leaves `required-gate` non-success; a trust
boundary edit cannot merge without code-owner approval.
