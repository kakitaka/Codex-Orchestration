from __future__ import annotations

import importlib.util
import io
import math
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "plugins" / "codex-orchestration" / "skills" / "codex-orchestration" / "scripts" / "bounded_run.py"
SPEC = importlib.util.spec_from_file_location("bounded_run_under_test", SCRIPT)
assert SPEC and SPEC.loader
bounded_run = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = bounded_run
SPEC.loader.exec_module(bounded_run)


class BoundedRunTests(unittest.TestCase):
    def test_windows_job_limit_flag_uses_the_struct_field(self) -> None:
        info = bounded_run._JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        flag = bounded_run._WindowsJob._JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        info.BasicLimitInformation.LimitFlags = flag
        self.assertEqual(info.BasicLimitInformation.LimitFlags, flag)
        self.assertGreater(
            bounded_run._JOBOBJECT_BASIC_LIMIT_INFORMATION.LimitFlags.offset, 0
        )

    @unittest.skipUnless(os.name == "nt", "Windows Job Object behavior")
    def test_windows_job_process_id_list_has_a_fixed_bound(self) -> None:
        info = bounded_run._JOBOBJECT_BASIC_PROCESS_ID_LIST()
        self.assertEqual(
            len(info.ProcessIdList), bounded_run.MAX_JOB_PROCESS_IDS
        )
        self.assertEqual(
            bounded_run._WindowsJob._JOB_OBJECT_BASIC_PROCESS_ID_LIST, 3
        )

    @unittest.skipUnless(os.name == "nt", "Windows Job Object behavior")
    def test_windows_job_verify_empty_terminates_and_waits_for_active_processes(self) -> None:
        controller = object.__new__(bounded_run._WindowsJob)
        controller._assigned = True
        controller._empty_verified = False
        controller._active_process_count = mock.Mock(side_effect=[1, 0])
        controller.terminate = mock.Mock(return_value=True)
        self.assertTrue(controller.verify_empty())
        controller.terminate.assert_called_once_with()
        self.assertTrue(controller._empty_verified)

    def test_redacts_secret_split_across_chunks(self) -> None:
        redactor = bounded_run.StreamingRedactor(["secret-value-123"])
        result = redactor.feed(b"prefix secret-")
        result += redactor.feed(b"value-123 suffix")
        result += redactor.flush()
        self.assertEqual(result, b"prefix [REDACTED] suffix")
        self.assertNotIn(b"secret-value-123", result)

    def test_redacts_secret_crossing_actual_emission_boundary(self) -> None:
        secret = b"A" * (bounded_run.MAX_SECRET_BYTES - 1) + b"B"
        redactor = bounded_run.StreamingRedactor([secret])
        start = redactor._carry_limit - 6
        first_read = (
            b"P" * start
            + secret
            + b"Q" * (bounded_run.READ_CHUNK_BYTES - start - len(secret))
        )
        self.assertEqual(len(first_read), bounded_run.READ_CHUNK_BYTES)
        result = redactor.feed(first_read) + redactor.flush()
        self.assertNotIn(secret, result)
        self.assertIn(b"[REDACTED]", result)

    def test_retains_redacted_important_line_outside_head_and_tail(self) -> None:
        code = (
            "import sys; sys.stdout.write("
            "'HEAD\\n' + 'x' * 200 + '\\nERROR: middle failure traceback\\n'"
            " + 'y' * 200 + '\\nTAIL\\n')"
        )
        result = bounded_run.run_bounded(
            [sys.executable, "-c", code],
            timeout=5,
            max_bytes=4096,
            head_bytes=16,
            tail_bytes=16,
        )
        self.assertNotIn("middle", result.stdout_first)
        self.assertNotIn("middle", result.stdout_last)
        self.assertIn("ERROR: middle failure traceback", result.important_lines)
        self.assertEqual(result.to_dict()["important_lines"], list(result.important_lines))

    def test_important_window_keeps_error_in_middle_of_huge_line(self) -> None:
        code = (
            "import sys; sys.stdout.write("
            "'x' * 5000 + ' ERROR: late assertion ' + 'y' * 5000 + '\\n')"
        )
        result = bounded_run.run_bounded(
            [sys.executable, "-c", code],
            timeout=5,
            max_bytes=32 * 1024,
            head_bytes=16,
            tail_bytes=16,
        )
        self.assertTrue(
            any("ERROR: late assertion" in line for line in result.important_lines)
        )
        self.assertTrue(
            all(
                len(line.encode("utf-8")) <= bounded_run.MAX_IMPORTANT_LINE_BYTES
                for line in result.important_lines
            )
        )

    def test_oversized_secret_is_rejected_before_process_launch(self) -> None:
        with mock.patch.object(bounded_run.subprocess, "Popen") as popen:
            with self.assertRaises(ValueError):
                bounded_run.run_bounded(
                    [sys.executable, "-c", "print('should not run')"],
                    secrets=[b"x" * (bounded_run.MAX_SECRET_BYTES + 1)],
                )
            popen.assert_not_called()

    def test_oversized_inherited_secret_is_rejected_without_log_leak(self) -> None:
        secret = "inherited-secret-" + ("x" * bounded_run.MAX_SECRET_BYTES)
        with tempfile.TemporaryDirectory() as directory:
            log_path = Path(directory) / "diagnostic.json"
            with mock.patch.dict(
                bounded_run.os.environ,
                {"BOUNDED_RUN_SECRET_TOKEN": secret},
                clear=False,
            ), mock.patch.object(bounded_run.subprocess, "Popen") as popen:
                with self.assertRaises(ValueError) as raised:
                    bounded_run.run_bounded(
                        [sys.executable, "-c", "print('must not run')"],
                        log_path=log_path,
                    )
                popen.assert_not_called()
            self.assertNotIn(secret, str(raised.exception))
            self.assertFalse(log_path.exists())

    @unittest.skipUnless(os.name == "nt", "Windows Job Object behavior")
    def test_windows_spawn_assigns_before_resume_and_requires_close(self) -> None:
        class FakeProcess:
            pid = 1234
            _handle = 1
            stdin = None
            stdout = io.BytesIO()
            stderr = io.BytesIO()
            returncode = 0

            def poll(self):
                return self.returncode

            def wait(self, timeout=None):
                return self.returncode

        controller = object.__new__(bounded_run._WindowsJob)
        events: list[str] = []
        controller.attach = mock.Mock(side_effect=lambda process: events.append("attach"))
        controller.resume = mock.Mock(side_effect=lambda process: events.append("resume"))
        controller.verify_empty = mock.Mock(return_value=True)
        controller.close = mock.Mock(return_value=True)
        process = FakeProcess()
        with mock.patch.object(bounded_run, "_prepare_tree_controller", return_value=controller), mock.patch.object(
            bounded_run.subprocess, "Popen", return_value=process
        ) as popen:
            result = bounded_run.run_bounded([sys.executable, "-c", "print('ok')"])
        flags = popen.call_args.kwargs["creationflags"]
        self.assertTrue(flags & getattr(bounded_run.subprocess, "CREATE_SUSPENDED", 0x4))
        self.assertEqual(events, ["attach", "resume"])
        controller.verify_empty.assert_called_once_with()
        controller.close.assert_called_once_with()
        self.assertEqual(result.exit_category, "ok")

    @unittest.skipUnless(os.name == "nt", "Windows Job Object behavior")
    def test_windows_success_with_job_close_failure_is_cleanup_error(self) -> None:
        class FakeProcess:
            pid = 1234
            _handle = 1
            stdin = None
            stdout = io.BytesIO()
            stderr = io.BytesIO()
            returncode = 0

            def poll(self):
                return self.returncode

            def wait(self, timeout=None):
                return self.returncode

        controller = object.__new__(bounded_run._WindowsJob)
        controller.attach = mock.Mock()
        controller.resume = mock.Mock()
        controller.verify_empty = mock.Mock(return_value=True)
        controller.close = mock.Mock(return_value=False)
        with mock.patch.object(bounded_run, "_prepare_tree_controller", return_value=controller), mock.patch.object(
            bounded_run.subprocess, "Popen", return_value=FakeProcess()
        ):
            result = bounded_run.run_bounded([sys.executable, "-c", "print('ok')"])
        self.assertEqual(result.exit_category, "cleanup_error")

    def test_caps_infinite_output_and_uses_no_shell(self) -> None:
        code = "import sys; sys.stdout.write('x' * 10000000); sys.stdout.flush()"
        result = bounded_run.run_bounded(
            [sys.executable, "-c", code], timeout=5, max_bytes=2048, head_bytes=512, tail_bytes=512
        )
        self.assertEqual(result.exit_category, "output_limit")
        self.assertTrue(result.truncated)
        self.assertLessEqual(len(result.stdout_first.encode()), 512)
        self.assertLessEqual(len(result.stdout_last.encode()), 512)

    def test_timeout_terminates_process_tree_best_effort(self) -> None:
        result = bounded_run.run_bounded(
            [sys.executable, "-c", "import time; time.sleep(10)"], timeout=0.1, max_bytes=1024
        )
        self.assertEqual(result.exit_category, "timeout")

    def test_non_finite_timeout_is_rejected_before_process_launch(self) -> None:
        for timeout in (math.nan, math.inf, -math.inf):
            with self.subTest(timeout=timeout), mock.patch.object(
                bounded_run.subprocess, "Popen"
            ) as popen, self.assertRaisesRegex(ValueError, "positive"):
                bounded_run.run_bounded(
                    [sys.executable, "-c", "print('must not run')"],
                    timeout=timeout,
                )
            popen.assert_not_called()

    def test_binary_output_is_safe_json_text(self) -> None:
        result = bounded_run.run_bounded(
            [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'\\xff\\xfe\\x00')"],
            timeout=5,
            max_bytes=1024,
        )
        self.assertEqual(result.exit_category, "ok")
        self.assertIn("\ufffd", result.stdout_first)

    def test_diagnostic_log_is_redacted_and_relative(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "state").mkdir()
            result = bounded_run.run_bounded(
                [sys.executable, "-c", "print('secret-value-123')"],
                root=root,
                log_path="state/diagnostic.json",
                secrets=["secret-value-123"],
            )
            self.assertEqual(result.log_path, "state/diagnostic.json")
            data = (root / "state" / "diagnostic.json").read_text(encoding="utf-8")
            self.assertNotIn("secret-value-123", data)
            self.assertNotIn('"argv"', data)
            if os.name != "nt":
                self.assertEqual((root / "state" / "diagnostic.json").stat().st_mode & 0o777, 0o600)

    def test_log_path_escape_and_write_failure_are_clean(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            escaped = bounded_run.run_bounded(
                [sys.executable, "-c", "print('ok')"], root=root, log_path="../outside.log"
            )
            self.assertIsNone(escaped.log_path)
            self.assertIsNotNone(escaped.log_error)
            with mock.patch.object(bounded_run, "_atomic_log", side_effect=PermissionError("denied")):
                failed = bounded_run.run_bounded(
                    [sys.executable, "-c", "print('ok')"], root=root, log_path="diagnostic.log"
                )
            self.assertIsNone(failed.log_path)
            self.assertIn("PermissionError", failed.log_error or "")

    def test_state_root_cannot_escape_approved_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            outside = Path(directory) / "outside"
            root.mkdir()
            outside.mkdir()
            result = bounded_run.run_bounded(
                [sys.executable, "-c", "print('ok')"],
                root=root,
                state_root=outside,
                log_path="diagnostic.json",
            )
            self.assertIsNone(result.log_path)
            self.assertIn("ValueError", result.log_error or "")
            self.assertFalse((outside / "diagnostic.json").exists())

    def test_missing_command_is_structured(self) -> None:
        result = bounded_run.run_bounded(["definitely-not-a-real-command-xyz"], timeout=1)
        self.assertEqual(result.exit_category, "start_error")
        self.assertIsNone(result.exit_code)


if __name__ == "__main__":
    unittest.main()
