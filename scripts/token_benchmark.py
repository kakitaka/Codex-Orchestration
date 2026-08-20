#!/usr/bin/env python3
"""Deterministic no-model context-size benchmark for fixed orchestration tasks."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SKILL_ROOT = (
    ROOT / "plugins" / "codex-orchestration" / "skills" / "codex-orchestration"
)
BASELINE_COMMIT = "ee43f3a522460888fa7c4174f53e9e5b4980267c"
BASELINE_CORE_BYTES = 56_463
BASELINE_CORE_LINES = 707
BASELINE_SKILL_MARKDOWN_BYTES = 98_030
BASELINE_AGENTS_BYTES = 732
BASELINE_AGENTS_LINES = 7
HELPER_SCRIPTS = SKILL_ROOT / "scripts"
if str(HELPER_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(HELPER_SCRIPTS))
from task_packet import build_task_packet  # noqa: E402


def _size(path: Path) -> dict[str, int]:
    raw = path.read_bytes()
    return {
        "bytes": len(raw),
        "estimated_tokens_bytes_div_4": (len(raw) + 3) // 4,
        "lines": len(raw.decode("utf-8").splitlines()),
    }


def _task(name: str, before: int, after_paths: list[Path]) -> dict[str, object]:
    after = sum(path.stat().st_size for path in after_paths)
    reduction = 0.0 if before == 0 else (before - after) / before
    return {
        "name": name,
        "before_context_bytes": before,
        "after_context_bytes": after,
        "before_estimated_tokens_bytes_div_4": (before + 3) // 4,
        "after_estimated_tokens_bytes_div_4": (after + 3) // 4,
        "estimated_context_reduction_ratio": round(reduction, 6),
        "live_usage": {
            "input_tokens": None,
            "cached_input_tokens": None,
            "uncached_input_tokens": None,
            "output_tokens": None,
            "reasoning_output_tokens": None,
            "cache_hit_ratio": None,
            "status": "NOT_MEASURED",
        },
    }


def collect(repo_root: Path = ROOT) -> dict[str, object]:
    skill_root = (
        repo_root
        / "plugins"
        / "codex-orchestration"
        / "skills"
        / "codex-orchestration"
    )
    core = skill_root / "SKILL.md"
    references = skill_root / "references"
    markdown_paths = sorted(skill_root.rglob("*.md"))
    normal_paths = [
        path for path in markdown_paths if path.name != "compatibility-contract.md"
    ]
    agents = repo_root / "AGENTS.md"
    external_baseline = BASELINE_CORE_BYTES + (
        references / "external-models.md"
    ).stat().st_size
    packet = build_task_packet(
        role="implementation-worker",
        static_rules=["Do not spawn descendants.", "fork_turns=none"],
        goal="Update one owned helper without repository-wide exploration.",
        base_revision="baseline",
        files_allowed=["scripts/example.py", "tests/test_example.py"],
        files_forbidden=[".codex-state"],
        known_facts=["The helper is deterministic."],
        constraints=["Preserve unrelated work."],
        acceptance_criteria=["Focused test passes."],
        validation="python -m unittest tests.test_example",
        output_contract="Changed files and test result only.",
    )
    after_always_loaded = core.stat().st_size + agents.stat().st_size
    before_always_loaded = BASELINE_CORE_BYTES + BASELINE_AGENTS_BYTES
    return {
        "schema": 1,
        "baseline_commit": BASELINE_COMMIT,
        "measurement_kind": "deterministic_bytes_and_bytes_div_4_estimate",
        "paid_model_calls": 0,
        "core_skill": {
            "before": {
                "bytes": BASELINE_CORE_BYTES,
                "lines": BASELINE_CORE_LINES,
                "estimated_tokens_bytes_div_4": (BASELINE_CORE_BYTES + 3) // 4,
            },
            "after": _size(core),
        },
        "skill_markdown": {
            "before_bytes": BASELINE_SKILL_MARKDOWN_BYTES,
            "after_all_bytes": sum(path.stat().st_size for path in markdown_paths),
            "after_normal_route_bytes": sum(path.stat().st_size for path in normal_paths),
            "compatibility_archive_loaded_by_default": False,
        },
        "agents_context": {
            "before": {"bytes": BASELINE_AGENTS_BYTES, "lines": BASELINE_AGENTS_LINES},
            "after": _size(agents),
        },
        "always_loaded_context": {
            "before_bytes": before_always_loaded,
            "after_bytes": after_always_loaded,
            "estimated_reduction_ratio": round(
                (before_always_loaded - after_always_loaded)
                / before_always_loaded,
                6,
            ),
        },
        "task_packet_fixture": {
            "bytes": len(packet.canonical_bytes),
            "estimated_tokens_bytes_div_4": (
                len(packet.canonical_bytes) + 3
            )
            // 4,
            "sha256": packet.sha256,
        },
        "fixed_tasks": [
            _task(
                "native_status",
                BASELINE_CORE_BYTES,
                [core, references / "native-lifecycle.md"],
            ),
            _task(
                "approved_delegation",
                BASELINE_CORE_BYTES,
                [
                    core,
                    references / "planner-advisor-workflow.md",
                    references / "delegation.md",
                ],
            ),
            _task(
                "external_model_availability",
                external_baseline,
                [
                    core,
                    references / "invocation-and-routing.md",
                    references / "external-models.md",
                ],
            ),
        ],
    }


def parse_args(arguments: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    parser.add_argument("--pretty", action="store_true")
    return parser.parse_args(arguments)


def main(arguments: list[str] | None = None) -> int:
    args = parse_args(arguments)
    payload = collect(args.repo_root.resolve())
    print(
        json.dumps(
            payload,
            ensure_ascii=False,
            indent=2 if args.pretty else None,
            sort_keys=True,
            separators=None if args.pretty else (",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
