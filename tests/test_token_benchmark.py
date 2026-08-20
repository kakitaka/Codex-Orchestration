from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "token_benchmark.py"
SPEC = importlib.util.spec_from_file_location("token_benchmark", SCRIPT)
assert SPEC and SPEC.loader
BENCHMARK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BENCHMARK)


class TokenBenchmarkTests(unittest.TestCase):
    def test_fixed_benchmark_is_static_and_does_not_invent_live_usage(self) -> None:
        payload = BENCHMARK.collect(REPO_ROOT)
        self.assertEqual(payload["paid_model_calls"], 0)
        self.assertEqual(payload["baseline_commit"], BENCHMARK.BASELINE_COMMIT)
        tasks = payload["fixed_tasks"]
        self.assertEqual(
            [task["name"] for task in tasks],
            [
                "native_status",
                "approved_delegation",
                "external_model_availability",
            ],
        )
        for task in tasks:
            self.assertGreater(task["estimated_context_reduction_ratio"], 0)
            usage = task["live_usage"]
            self.assertEqual(usage["status"], "NOT_MEASURED")
            self.assertTrue(
                all(value is None for key, value in usage.items() if key != "status")
            )

    def test_core_skill_after_is_smaller_than_before_and_bounded(self) -> None:
        payload = BENCHMARK.collect(REPO_ROOT)
        core = payload["core_skill"]
        self.assertLess(core["after"]["bytes"], core["before"]["bytes"])
        self.assertLessEqual(core["after"]["bytes"], 12 * 1024)
        self.assertFalse(
            payload["skill_markdown"]["compatibility_archive_loaded_by_default"]
        )
        self.assertGreater(
            payload["always_loaded_context"]["estimated_reduction_ratio"], 0.8
        )
        self.assertGreater(payload["task_packet_fixture"]["bytes"], 0)
        self.assertEqual(
            payload["task_packet_fixture"],
            BENCHMARK.collect(REPO_ROOT)["task_packet_fixture"],
        )


if __name__ == "__main__":
    unittest.main()
