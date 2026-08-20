from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "token_benchmark.py"
SPEC = importlib.util.spec_from_file_location("token_benchmark", SCRIPT)
assert SPEC and SPEC.loader
BENCHMARK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BENCHMARK)


class TokenBenchmarkTests(unittest.TestCase):
    def test_clean_scope_rejects_a_dirty_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(
                ["git", "-C", str(root), "config", "user.email", "test@example.invalid"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(root), "config", "user.name", "Token Benchmark"],
                check=True,
            )
            tracked = root / "tracked.txt"
            tracked.write_text("baseline\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(root), "add", "tracked.txt"], check=True)
            subprocess.run(["git", "-C", str(root), "commit", "-qm", "baseline"], check=True)
            tracked.write_text("dirty\n", encoding="utf-8")
            with self.assertRaisesRegex(
                BENCHMARK.BenchmarkError, "clean exact-HEAD checkout"
            ):
                BENCHMARK._repo_scope(root, require_clean=True)

    def test_fixed_benchmark_is_static_and_does_not_invent_live_usage(self) -> None:
        payload = BENCHMARK.collect(REPO_ROOT, require_clean=False)
        self.assertEqual(payload["paid_model_calls"], 0)
        self.assertEqual(payload["baseline_commit"], BENCHMARK.BASELINE_COMMIT)
        tasks = payload["fixed_tasks"]
        self.assertEqual(
            [task["name"] for task in tasks],
            list(BENCHMARK.REQUIRED_TASK_NAMES),
        )
        for task in tasks:
            self.assertGreater(task["estimated_context_reduction_ratio"], 0)
            self.assertTrue(task["success"])
            self.assertEqual(task["test_result"], "PASS")
            usage = task["live_usage"]
            self.assertEqual(usage["status"], "NOT_MEASURED")
            self.assertTrue(
                all(value is None for key, value in usage.items() if key != "status")
            )

    def test_core_skill_after_is_smaller_than_before_and_bounded(self) -> None:
        payload = BENCHMARK.collect(REPO_ROOT, require_clean=False)
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
            BENCHMARK.collect(REPO_ROOT, require_clean=False)["task_packet_fixture"],
        )


if __name__ == "__main__":
    unittest.main()
