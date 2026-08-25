from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "passive_usage_report.py"
SPEC = importlib.util.spec_from_file_location("passive_usage_report", SCRIPT)
assert SPEC and SPEC.loader
REPORT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = REPORT
SPEC.loader.exec_module(REPORT)


def instant(value: str):
    return REPORT._parse_instant(value)


def write_entries(root: Path, day: str, entries: list[dict[str, object]]) -> None:
    target = root.joinpath(*day.split("/"), "session.jsonl")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        "".join(json.dumps(entry, separators=(",", ":")) + "\n" for entry in entries),
        encoding="utf-8",
    )


def turn(
    model: str = "gpt-5.6-luna",
    effort: str = "max",
    timestamp: str = "2026-08-20T02:50:00Z",
    **metadata: object,
) -> dict[str, object]:
    payload: dict[str, object] = {"model": model, "effort": effort}
    payload.update(metadata)
    return {"timestamp": timestamp, "type": "turn_context", "payload": payload}


def event(
    timestamp: str,
    *,
    input_tokens: int,
    cached_input_tokens: int,
    output_tokens: int = 0,
    reasoning_output_tokens: int = 0,
    used_percent: int | None = None,
    resets_at: int = 1_787_801_594,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "info": {
            "last_token_usage": {
                "input_tokens": input_tokens,
                "cached_input_tokens": cached_input_tokens,
                "output_tokens": output_tokens,
                "reasoning_output_tokens": reasoning_output_tokens,
            }
        }
    }
    if used_percent is not None:
        payload["rate_limits"] = {
            "primary": {
                "window_minutes": 10_080,
                "resets_at": resets_at,
                "used_percent": used_percent,
            }
        }
    return {"timestamp": timestamp, "type": "event_msg", "payload": payload}


class PassiveUsageReportTests(unittest.TestCase):
    def test_aggregates_event_usage_and_monotone_weekly_high_water(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_entries(
                root,
                "2026/08/20",
                [
                    turn(),
                    event(
                        "2026-08-20T03:00:00Z",
                        input_tokens=1_000,
                        cached_input_tokens=800,
                        output_tokens=100,
                        reasoning_output_tokens=40,
                        used_percent=1,
                    ),
                    event(
                        "2026-08-20T04:00:00Z",
                        input_tokens=500,
                        cached_input_tokens=200,
                        output_tokens=50,
                        reasoning_output_tokens=10,
                        used_percent=3,
                    ),
                    event(
                        "2026-08-20T05:00:00Z",
                        input_tokens=200,
                        cached_input_tokens=100,
                        used_percent=2,
                    ),
                ],
            )
            report = REPORT.collect(
                root,
                start=instant("2026-08-20T03:00:00Z"),
                end=instant("2026-08-20T06:00:00Z"),
            )

        usage = report["usage"]
        self.assertEqual(usage["usage_events"], 3)
        self.assertEqual(usage["input_tokens"], 1_700)
        self.assertEqual(usage["cached_input_tokens"], 1_100)
        self.assertEqual(usage["uncached_input_tokens"], 600)
        self.assertEqual(usage["output_tokens"], 150)
        self.assertEqual(usage["reasoning_output_tokens"], 50)
        self.assertEqual(usage["cache_hit_ratio"], 0.647059)
        self.assertEqual(usage["by_model_effort"][0]["model"], "gpt-5.6-luna")
        weekly = report["weekly_limit"]["windows"][0]
        self.assertEqual(weekly["used_percent_delta"], 2.0)
        self.assertEqual(weekly["last_high_water_at"], "2026-08-20T04:00:00Z")
        self.assertEqual(weekly["used_percent_per_hour"], 2.0)
        self.assertEqual(weekly["minutes_per_percentage_point"], 30.0)

    def test_ignores_raw_content_and_reports_missing_counters(self) -> None:
        sentinel = "private prompt text must never be exported"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_entries(
                root,
                "2026/08/20",
                [
                    turn(),
                    {"timestamp": "2026-08-20T03:00:00Z", "type": "response_item", "payload": {"content": sentinel}},
                    {"timestamp": "2026-08-20T03:01:00Z", "type": "event_msg", "payload": {"info": {"last_token_usage": {}}}},
                ],
            )
            target = root / "2026" / "08" / "20" / "session.jsonl"
            deep_json = (
                '{"timestamp":"2026-08-20T03:02:00Z","type":"event_msg","payload":'
                + '{"metadata":' * 10_000
                + "{}"
                + "}" * 10_000
                + "}\n"
            )
            target.write_text(
                target.read_text(encoding="utf-8") + "{not-json}\n" + deep_json,
                encoding="utf-8",
            )
            report = REPORT.collect(
                root,
                start=instant("2026-08-20T03:00:00Z"),
                end=instant("2026-08-20T04:00:00Z"),
            )

        serialized = json.dumps(report)
        self.assertNotIn(sentinel, serialized)
        self.assertNotIn(str(root), serialized)
        self.assertEqual(report["usage"]["status"], "NOT_MEASURED")
        self.assertEqual(report["weekly_limit"]["status"], "NOT_MEASURED")
        self.assertEqual(report["scan"]["malformed_lines"], 2)
        self.assertEqual(report["scan"]["invalid_usage_events"], 1)

    def test_comparison_normalizes_rates_and_marks_observational(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_entries(
                root,
                "2026/08/20",
                [
                    turn(task_family="testing"),
                    event("2026-08-20T03:00:00Z", input_tokens=100, cached_input_tokens=50, used_percent=1),
                    event("2026-08-20T04:00:00Z", input_tokens=100, cached_input_tokens=50, used_percent=2),
                ],
            )
            write_entries(
                root,
                "2026/08/21",
                [
                    {"timestamp": "2026-08-21T03:00:00Z", "type": "turn_context", "payload": {"model": "gpt-5.6-luna", "effort": "max", "task_family": "testing"}},
                    event("2026-08-21T03:00:00Z", input_tokens=200, cached_input_tokens=100, used_percent=1),
                    event("2026-08-21T04:00:00Z", input_tokens=200, cached_input_tokens=100, used_percent=3),
                ],
            )
            baseline = REPORT.collect(root, start=instant("2026-08-20T03:00:00Z"), end=instant("2026-08-20T05:00:00Z"))
            candidate = REPORT.collect(root, start=instant("2026-08-21T03:00:00Z"), end=instant("2026-08-21T05:00:00Z"))
            comparison = REPORT.compare(baseline, candidate)

        metrics = comparison["comparison"]["metrics"]
        self.assertEqual(comparison["interpretation"], "OBSERVATIONAL_ONLY")
        self.assertEqual(metrics["uncached_input_tokens_per_hour"]["baseline"], 50.0)
        self.assertEqual(metrics["uncached_input_tokens_per_hour"]["candidate"], 100.0)
        self.assertEqual(metrics["weekly_used_percent_per_hour"]["relative_change"], 1.0)

    def test_adds_per_event_and_bounded_role_task_family_aggregates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_entries(
                root,
                "2026/08/20",
                [
                    turn(),
                    event(
                        "2026-08-20T03:00:00Z",
                        input_tokens=100,
                        cached_input_tokens=50,
                    ),
                    {
                        "timestamp": "2026-08-20T03:15:00Z",
                        "type": "session_meta",
                        "payload": {
                            "thread_source": "subagent",
                            "source": {"subagent": {"kind": "worker"}},
                        },
                    },
                    turn(
                        timestamp="2026-08-20T03:30:00Z",
                        task_family="implementation",
                    ),
                    event(
                        "2026-08-20T04:00:00Z",
                        input_tokens=300,
                        cached_input_tokens=200,
                    ),
                ],
            )
            report = REPORT.collect(
                root,
                start=instant("2026-08-20T03:00:00Z"),
                end=instant("2026-08-20T05:00:00Z"),
            )

        usage = report["usage"]
        self.assertEqual(usage["rates_per_usage_event"]["input_tokens"], 200.0)
        self.assertEqual(
            usage["rates_per_usage_event"]["uncached_input_tokens"], 75.0
        )
        self.assertNotIn("rates_per_event", usage)
        self.assertNotIn("input_tokens_per_event", usage)
        self.assertEqual(
            {row["root_worker"] for row in usage["by_root_worker"]},
            {"root_or_legacy", "worker"},
        )
        self.assertEqual(usage["mix"]["root_worker"]["worker"], 0.5)
        self.assertEqual(usage["mix"]["task_family"]["implementation"], 0.5)
        self.assertNotIn("task_family_name", json.dumps(report))

    def test_malformed_metadata_falls_back_without_exporting_raw_task_name(self) -> None:
        sentinel = "private task title must never be exported"
        model_sentinel = "gpt-private-task-title-must-never-leak"
        deep_metadata: dict[str, object] = {}
        for _ in range(REPORT.MAX_METADATA_DEPTH + 4):
            deep_metadata = {"metadata": deep_metadata}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_entries(
                root,
                "2026/08/20",
                [
                    turn(
                        model=model_sentinel,
                        effort={},  # type: ignore[arg-type]
                        is_worker="yes",
                        task_family={"name": sentinel},
                        metadata=deep_metadata,
                    ),
                    event(
                        "2026-08-20T03:00:00Z",
                        input_tokens=100,
                        cached_input_tokens=0,
                    ),
                    {
                        "timestamp": "2026-08-20T03:01:00Z",
                        "type": "turn_context",
                        "payload": {"task": sentinel},
                    },
                    event(
                        "2026-08-20T03:02:00Z",
                        input_tokens=100,
                        cached_input_tokens=0,
                    ),
                ],
            )
            report = REPORT.collect(
                root,
                start=instant("2026-08-20T03:00:00Z"),
                end=instant("2026-08-20T04:00:00Z"),
            )

        serialized = json.dumps(report)
        self.assertNotIn(sentinel, serialized)
        self.assertNotIn(model_sentinel, serialized)
        self.assertEqual(report["usage"]["mix"]["root_worker"], {"root_or_legacy": 1.0})
        self.assertEqual(report["usage"]["mix"]["task_family"], {"other": 1.0})
        self.assertEqual(report["usage"]["mix"]["model"], {"unknown": 1.0})
        self.assertEqual(report["usage"]["mix"]["effort"], {"unknown": 1.0})
        self.assertEqual(
            REPORT.compare(report, report)["comparison"]["reason_codes"],
            [
                "MISSING_MODEL_MIX",
                "MISSING_EFFORT_MIX",
                "MISSING_TASK_FAMILY_MIX",
            ],
        )

    def test_mix_mismatch_is_not_comparable_with_reason_codes_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_entries(
                root,
                "2026/08/20",
                [
                    turn(),
                    event("2026-08-20T03:00:00Z", input_tokens=100, cached_input_tokens=0),
                ],
            )
            write_entries(
                root,
                "2026/08/21",
                [
                    turn(
                        timestamp="2026-08-21T02:50:00Z",
                        is_worker=True,
                        task_family="research",
                    ),
                    event("2026-08-21T03:00:00Z", input_tokens=100, cached_input_tokens=0),
                ],
            )
            baseline = REPORT.collect(
                root,
                start=instant("2026-08-20T03:00:00Z"),
                end=instant("2026-08-20T04:00:00Z"),
            )
            candidate = REPORT.collect(
                root,
                start=instant("2026-08-21T03:00:00Z"),
                end=instant("2026-08-21T04:00:00Z"),
            )
            comparison = REPORT.compare(baseline, candidate)

        result = comparison["comparison"]
        self.assertEqual(result["status"], "NOT_COMPARABLE")
        self.assertEqual(
            result["reason_codes"],
            ["ROOT_WORKER_MIX_MISMATCH", "MISSING_TASK_FAMILY_MIX"],
        )
        self.assertTrue(
            all(metric["status"] == "NOT_MEASURED" for metric in result["metrics"].values())
        )
        self.assertNotIn("research", json.dumps(result))

        common_mix = {
            "model": {"gpt-5.6-terra": 0.5, "gpt-5.6-luna": 0.5},
            "effort": {"medium": 0.5, "max": 0.5},
            "root_worker": {"root_or_legacy": 1.0},
            "task_family": {"testing": 1.0},
        }
        baseline_usage = {
            "mix": common_mix,
            "by_model_effort": [
                {"model": "gpt-5.6-terra", "effort": "medium", "usage_events": 1},
                {"model": "gpt-5.6-luna", "effort": "max", "usage_events": 1},
            ],
        }
        candidate_usage = {
            "mix": common_mix,
            "by_model_effort": [
                {"model": "gpt-5.6-terra", "effort": "max", "usage_events": 1},
                {"model": "gpt-5.6-luna", "effort": "medium", "usage_events": 1},
            ],
        }
        joint = REPORT.compare(
            {"usage": baseline_usage},
            {"usage": candidate_usage},
        )["comparison"]
        self.assertEqual(joint["reason_codes"], ["MODEL_EFFORT_MIX_MISMATCH"])

    def test_quota_rate_requires_one_matching_reset_bucket(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_entries(
                root,
                "2026/08/20",
                [
                    turn(task_family="testing"),
                    event(
                        "2026-08-20T03:00:00Z",
                        input_tokens=100,
                        cached_input_tokens=0,
                        used_percent=1,
                        resets_at=1_787_801_594,
                    ),
                    event(
                        "2026-08-20T03:30:00Z",
                        input_tokens=100,
                        cached_input_tokens=0,
                        used_percent=2,
                        resets_at=1_787_802_594,
                    ),
                ],
            )
            write_entries(
                root,
                "2026/08/21",
                [
                    turn(
                        timestamp="2026-08-21T02:50:00Z",
                        task_family="testing",
                    ),
                    event(
                        "2026-08-21T03:00:00Z",
                        input_tokens=100,
                        cached_input_tokens=0,
                        used_percent=1,
                        resets_at=1_787_801_594,
                    ),
                    event(
                        "2026-08-21T03:30:00Z",
                        input_tokens=100,
                        cached_input_tokens=0,
                        used_percent=2,
                        resets_at=1_787_801_594,
                    ),
                ],
            )
            baseline = REPORT.collect(
                root,
                start=instant("2026-08-20T03:00:00Z"),
                end=instant("2026-08-20T04:00:00Z"),
            )
            candidate = REPORT.collect(
                root,
                start=instant("2026-08-21T03:00:00Z"),
                end=instant("2026-08-21T04:00:00Z"),
            )
            comparison = REPORT.compare(baseline, candidate)

        self.assertEqual(comparison["comparison"]["status"], "COMPARABLE")
        self.assertEqual(
            comparison["comparison"]["metrics"]["weekly_used_percent_per_hour"]["status"],
            "NOT_MEASURED",
        )


if __name__ == "__main__":
    unittest.main()
