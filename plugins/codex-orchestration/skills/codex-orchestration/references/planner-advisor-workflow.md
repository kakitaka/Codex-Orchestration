# Planner, Advisor, and Designer workflow

Root owns the canonical plan and mediates every seat. Planner and Advisor never contact one another directly, contact Executors, edit implementation, or spawn descendants.

## Route resolution

For both persistent setup and task-local overrides, explicit user choice wins, followed by applicable `AGENTS.md`, configured route, then profile recommendation. Reject the same direct model ID or same custom-agent identity for Planner and Advisor. At most one bundled Claude subscription seat may be active.

Fable Planner uses `create_plan` and `revise_plan`; Fable Advisor uses `review_plan`. Every call is fresh and self-contained. Current MCP requests do not carry caller identity, so caller isolation is instruction-enforced; no-tools bridge execution is the mechanical boundary.

## Approval loop

1. Root prepares canonical plan version N plus stable finding IDs and a compact cumulative findings ledger.
2. Planner creates/revises only when configured; otherwise root plans.
3. Advisor reviews a fresh complete packet and returns only `PLAN_APPROVED` or `PLAN_REVISE` plus findings.
4. Reject stale source versions, malformed signals, transport failures, wrong routes, and missing context. They never count as approval.
5. `PLAN_APPROVED` ends review immediately. `PLAN_REVISE` updates the ledger and returns to the same Planner route.
6. Never exceed the selected profile's review budget; legacy maximum is eight total Advisor reviews. Review eight without approval returns `NOT_ADVISOR_APPROVED` and blocks Executor release.

Configured planning seats are required for non-trivial Executor work unless the user explicitly made that seat best-effort for the current task. An unavailable Executor may leave work with root; it does not authorize a substitute model.

## Designer handoff

Designer receives only approved design requirements and explicitly owned design artifacts. Designer may use the same model as another seat, but remains root-directed. It never revises the canonical plan, modifies implementation files, approves work, or releases Executor.
