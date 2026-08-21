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


def turn(model: str = "gpt-5.6-luna", effort: str = "max") -> dict[str, object]:
    return {"timestamp": "2026-08-20T02:50:00Z", "type": "turn_context", "payload": {"model": model, "effort": effort}}


def event(
    timestamp: str,
    *,
    input_tokens: int,
    cached_input_tokens: int,
    output_tokens: int = 0,
    reasoning_output_tokens: int = 0,
    used_percent: int | None = None,
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
                "resets_at": 1_787_801_594,
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
            target.write_text(target.read_text(encoding="utf-8") + "{not-json}\n", encoding="utf-8")
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
        self.assertEqual(report["scan"]["malformed_lines"], 1)
        self.assertEqual(report["scan"]["invalid_usage_events"], 1)

    def test_comparison_normalizes_rates_and_marks_observational(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_entries(
                root,
                "2026/08/20",
                [
                    turn(),
                    event("2026-08-20T03:00:00Z", input_tokens=100, cached_input_tokens=50, used_percent=1),
                    event("2026-08-20T04:00:00Z", input_tokens=100, cached_input_tokens=50, used_percent=2),
                ],
            )
            write_entries(
                root,
                "2026/08/21",
                [
                    {"timestamp": "2026-08-21T03:00:00Z", "type": "turn_context", "payload": {"model": "gpt-5.6-luna", "effort": "max"}},
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


if __name__ == "__main__":
    unittest.main()
