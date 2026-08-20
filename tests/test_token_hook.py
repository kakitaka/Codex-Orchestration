from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "plugins" / "codex-orchestration" / "skills" / "codex-orchestration" / "scripts" / "token_hook.py"
SPEC = importlib.util.spec_from_file_location("token_hook_under_test", SCRIPT)
assert SPEC and SPEC.loader
token_hook = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = token_hook
SPEC.loader.exec_module(token_hook)


class TokenHookTests(unittest.TestCase):
    def test_targeted_command_passes_exact_empty_object(self) -> None:
        diagnostics = io.StringIO()
        response = token_hook.process_payload(
            {"event": "PreToolUse", "tool_name": "shell_command", "tool_input": {"command": "rg -n foo src/app.py"}},
            diagnostics=diagnostics,
        )
        self.assertEqual(response, {})
        self.assertEqual(diagnostics.getvalue(), "")

    def test_recursive_and_verbose_commands_warn_without_rewrite(self) -> None:
        response = token_hook.process_payload(
            {"event": "PreToolUse", "tool_input": {"command": "Get-ChildItem -Recurse"}}
        )
        self.assertEqual(set(response), {"systemMessage"})
        self.assertIn("recursive", response["systemMessage"])
        response = token_hook.process_payload(
            {"event": "PreToolUse", "tool_input": {"command": "python -m pytest -vv tests/test_one.py"}}
        )
        self.assertEqual(set(response), {"systemMessage"})
        self.assertIn("verbose test", response["systemMessage"])

    def test_unbounded_git_output_warns_but_bounded_target_passes(self) -> None:
        broad = token_hook.process_payload(
            {"event": "PreToolUse", "tool_input": {"command": "git log --oneline"}}
        )
        self.assertEqual(broad, {})  # oneline is a compact, intentional form
        broad = token_hook.process_payload(
            {"event": "PreToolUse", "tool_input": {"command": "git log"}}
        )
        self.assertIn("systemMessage", broad)
        bounded = token_hook.process_payload(
            {"event": "PreToolUse", "tool_input": {"command": "git diff -- src/app.py"}}
        )
        self.assertEqual(bounded, {})

    def test_user_prompt_returns_only_additional_context(self) -> None:
        response = token_hook.process_payload({"event": "UserPromptSubmit", "prompt": "inspect this repo"})
        self.assertEqual(set(response), {"hookSpecificOutput"})
        hook_output = response["hookSpecificOutput"]
        self.assertEqual(hook_output["hookEventName"], "UserPromptSubmit")
        self.assertLessEqual(
            len(hook_output["additionalContext"]), token_hook.MAX_CONTEXT_CHARS
        )

    def test_unsupported_post_tool_and_unknown_event_fail_open(self) -> None:
        diagnostics = io.StringIO()
        self.assertEqual(
            token_hook.process_payload({"event": "PostToolUse", "tool_output": "huge"}, diagnostics=diagnostics),
            {},
        )
        self.assertIn("output replacement", diagnostics.getvalue())
        self.assertEqual(token_hook.process_payload({"event": "FutureEvent"}, diagnostics=diagnostics), {})

    def test_cli_is_opt_in_and_stdout_is_exact_json(self) -> None:
        payload = json.dumps({"event": "PreToolUse", "tool_input": {"command": "ls -R"}})
        output = io.StringIO()
        diagnostics = io.StringIO()
        self.assertEqual(token_hook.main([], stdin=io.StringIO(payload), stdout=output, stderr=diagnostics), 0)
        self.assertEqual(output.getvalue(), "{}\n")
        output = io.StringIO()
        self.assertEqual(token_hook.main(["--enable"], stdin=io.StringIO(payload), stdout=output, stderr=diagnostics), 0)
        self.assertIn("systemMessage", json.loads(output.getvalue()))

    def test_malformed_and_oversize_input_are_bounded_fail_open(self) -> None:
        output = io.StringIO()
        diagnostics = io.StringIO()
        self.assertEqual(token_hook.main(["--enable"], stdin=io.StringIO("{"), stdout=output, stderr=diagnostics), 0)
        self.assertEqual(output.getvalue(), "{}\n")
        output = io.StringIO()
        oversized = "x" * (token_hook.MAX_INPUT_BYTES + 100)
        self.assertEqual(token_hook.main(["--enable"], stdin=io.StringIO(oversized), stdout=output, stderr=diagnostics), 0)
        self.assertEqual(output.getvalue(), "{}\n")
        self.assertIn("bounded", diagnostics.getvalue())


if __name__ == "__main__":
    unittest.main()
