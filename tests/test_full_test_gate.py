from __future__ import annotations

from collections import Counter
from contextlib import redirect_stderr
from datetime import date
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "full_test_gate.py"
SPEC = importlib.util.spec_from_file_location("full_test_gate", SCRIPT)
assert SPEC and SPEC.loader
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class FullTestGateTests(unittest.TestCase):
    def test_parser_extracts_nodes_and_normalized_exception_signatures(self) -> None:
        output = """======================================================================
FAIL: test_mode (test_configure.ConfigureTests.test_mode)
----------------------------------------------------------------------
Traceback (most recent call last):
  File "C:\\repo\\tests\\test_configure.py", line 1, in test_mode
AssertionError: 420 != 292

======================================================================
ERROR: test_link (test_configure.ConfigureTests.test_link)
----------------------------------------------------------------------
Traceback (most recent call last):
OSError: [WinError 1314] privilege absent

----------------------------------------------------------------------
Ran 2 tests
"""
        failures = GATE.parse_failures(output, Path("C:/repo"))
        self.assertEqual(GATE.parse_test_count(output), 2)
        self.assertEqual(
            failures,
            [
                GATE.Failure(
                    "ERROR",
                    "test_configure.ConfigureTests.test_link",
                    "OSError: [WinError 1314] privilege absent",
                ),
                GATE.Failure(
                    "FAIL",
                    "test_configure.ConfigureTests.test_mode",
                    "AssertionError: 420 != 292",
                ),
            ],
        )

    def test_missing_test_count_is_detectable(self) -> None:
        self.assertIsNone(GATE.parse_test_count("FAILED without summary"))

    def test_test_id_discovery_keeps_subtest_and_interleaved_start_lines(self) -> None:
        output = "\n".join(
            (
                "test_plain (test_mod.Tests.test_plain) ... ok",
                "test_subtests (test_mod.Tests.test_subtests) ... ",
                "  test_subtests (test_mod.Tests.test_subtests) (case=1) ... FAIL",
                "test_prints (test_mod.Tests.test_prints) ... diagnostic text",
            )
        )
        self.assertEqual(
            GATE.discover_test_ids(output),
            (
                "test_plain (test_mod.Tests.test_plain)",
                "test_prints (test_mod.Tests.test_prints)",
                "test_subtests (test_mod.Tests.test_subtests)",
            ),
        )

    def test_run_gate_rejects_test_loss_and_unparseable_nonzero(self) -> None:
        scenarios = (
            (
                "too few tests",
                SimpleNamespace(
                    exit_category="ok",
                    exit_code=0,
                    stdout_first="Ran 383 tests in 1.0s\nOK\n",
                    stderr_first="",
                ),
            ),
            (
                "unparseable failure",
                SimpleNamespace(
                    exit_category="nonzero",
                    exit_code=1,
                    stdout_first="Ran 384 tests in 1.0s\nFAILED\n",
                    stderr_first="collection failed without a unittest block",
                ),
            ),
        )
        for label, result in scenarios:
            with self.subTest(label=label), mock.patch.object(
                GATE, "run_bounded", return_value=result
            ), redirect_stderr(io.StringIO()):
                self.assertEqual(
                    GATE.run_gate(REPO_ROOT, REPO_ROOT / "unused.json", platform="win32"),
                    1,
                )

    def _baseline(self, path: Path, entries: list[dict[str, object]]) -> None:
        path.write_text(
            json.dumps(
                {
                    "schema": 1,
                    "commit": "ee43f3a522460888fa7c4174f53e9e5b4980267c",
                    "platform": "win32",
                    "rationale": "pre-existing native Windows fixture mismatch",
                    "owner": "Codex-Orchestration maintainers",
                    "expires": "2099-01-01",
                    "entries": entries,
                }
            ),
            encoding="utf-8",
        )

    def test_baseline_is_strict_and_exact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "baseline.json"
            entry = {
                "kind": "FAIL",
                "node": "test_legacy.LegacyTests.test_mode",
                "signature": "AssertionError: mode mismatch",
                "occurrences": 1,
            }
            self._baseline(path, [entry])
            expected = GATE.load_baseline(path, today=date(2026, 8, 20))
            failure = GATE.Failure(
                entry["kind"], entry["node"], entry["signature"]
            )
            self.assertEqual(expected, Counter({failure: 1}))
            self.assertEqual(
                GATE.compare_failures(Counter({failure: 1}), expected), ([], [])
            )
            extra = GATE.Failure("ERROR", "test_other.Other.test_new", "OSError: x")
            actual = Counter({failure: 1, extra: 1})
            self.assertEqual(GATE.compare_failures(actual, expected)[0], [extra])

    def test_baseline_cannot_exempt_new_token_efficiency_tests(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "baseline.json"
            self._baseline(
                path,
                [
                    {
                        "kind": "FAIL",
                        "node": "test_token_lint.TokenLintTests.test_regression",
                        "signature": "AssertionError: regression",
                        "occurrences": 1,
                    }
                ],
            )
            with self.assertRaisesRegex(ValueError, "cannot exempt"):
                GATE.load_baseline(path, today=date(2026, 8, 20))

    def test_production_baseline_is_bound_by_content_digest(self) -> None:
        baseline = REPO_ROOT / "tests" / "baselines" / "windows-ee43f3a.json"
        GATE.load_baseline(
            baseline,
            today=date(2026, 8, 20),
            expected_sha256=GATE.WINDOWS_BASELINE_SHA256,
        )
        with tempfile.TemporaryDirectory() as temporary:
            changed = Path(temporary) / "baseline.json"
            payload = json.loads(baseline.read_text(encoding="utf-8"))
            payload["rationale"] += " modified"
            changed.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "bound base-commit"):
                GATE.load_baseline(
                    changed,
                    today=date(2026, 8, 20),
                    expected_sha256=GATE.WINDOWS_BASELINE_SHA256,
                )

    def test_expired_and_unknown_field_baselines_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "baseline.json"
            entry = {
                "kind": "FAIL",
                "node": "test_legacy.LegacyTests.test_mode",
                "signature": "AssertionError: mode mismatch",
                "occurrences": 1,
            }
            self._baseline(path, [entry])
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["expires"] = "2020-01-01"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "expired"):
                GATE.load_baseline(path, today=date(2026, 8, 20))
            payload["expires"] = "2099-01-01"
            payload["raw_log"] = "forbidden"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "schema mismatch"):
                GATE.load_baseline(path, today=date(2026, 8, 20))


if __name__ == "__main__":
    unittest.main()
