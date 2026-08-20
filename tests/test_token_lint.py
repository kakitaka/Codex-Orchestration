from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import sys
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "token_lint.py"
SPEC = importlib.util.spec_from_file_location("token_lint_under_test", SCRIPT)
assert SPEC and SPEC.loader
token_lint = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = token_lint
SPEC.loader.exec_module(token_lint)


class TokenLintTests(unittest.TestCase):
    def _clean_root(self) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        (root / "src").mkdir()
        (root / "AGENTS.md").write_text("# Rules\n", encoding="utf-8")
        (root / "SKILL.md").write_text("# Skill\n\nSee [reference](references/one.md).\n", encoding="utf-8")
        (root / "references").mkdir()
        (root / "references" / "one.md").write_text("# Reference\n", encoding="utf-8")
        (root / "src" / "app.py").write_text("print('targeted')\n", encoding="utf-8")
        return root

    def test_clean_minimal_fixture(self) -> None:
        root = self._clean_root()
        self.assertEqual(token_lint.scan(root), [])

    def test_budgets_and_broken_reference(self) -> None:
        root = self._clean_root()
        (root / "SKILL.md").write_text("x" * (token_lint.MAX_SKILL_BYTES + 1), encoding="utf-8")
        (root / "AGENTS.md").write_text("# Rules\n" + "line\n" * (token_lint.MAX_AGENTS_LINES + 1), encoding="utf-8")
        (root / "src" / "broken.md").write_text("[missing](nope.md)\n", encoding="utf-8")
        codes = {finding.code for finding in token_lint.scan(root)}
        self.assertIn("SKILL_BYTES", codes)
        self.assertIn("AGENTS_LINES", codes)
        self.assertIn("BROKEN_REFERENCE", codes)

    def test_duplicate_prompt_blocks(self) -> None:
        root = self._clean_root()
        block = "A stable instruction block that should only be present once. " * 8
        (root / "src" / "one.md").write_text(block, encoding="utf-8")
        (root / "src" / "two.md").write_text(block, encoding="utf-8")
        findings = token_lint.scan(root)
        self.assertTrue(any(finding.code == "DUPLICATE_PROMPT_BLOCK" for finding in findings))

    def test_runtime_regression_classes(self) -> None:
        root = self._clean_root()
        (root / "src" / "runtime.py").write_text(
            "DEFAULT_EFFORT = 'max'\n"
            "fork_turns = 'all'\n"
            "max_workers = 4\n"
            "pytest -vv\n"
            "git diff\n"
            "ls -R\n"
            "print(json.dumps(output, indent=2))\n",
            encoding="utf-8",
        )
        (root / "src" / "task_packet.py").write_text(
            "import time\n"
            "import uuid\n"
            "stamp = time.time()\n"
            "identifier = uuid.uuid4()\n"
            "home = Path.home()\n",
            encoding="utf-8",
        )
        codes = {finding.code for finding in token_lint.scan(root)}
        for code in (
            "ACCIDENTAL_MAX_DEFAULT",
            "FORK_TURNS_ALL",
            "NOISY_PYTEST",
            "UNBOUNDED_GIT_OUTPUT",
            "RECURSIVE_LISTING",
            "HUGE_JSON_OUTPUT",
            "DYNAMIC_PACKET_SOURCE",
            "USER_PATH_IN_PACKET",
            "FIXED_WORKER_LIMIT",
        ):
            self.assertIn(code, codes)

    def test_always_loaded_prompt_cannot_default_to_max(self) -> None:
        root = self._clean_root()
        (root / "SKILL.md").write_text(
            "# Skill\n\nreasoning_effort = max\n", encoding="utf-8"
        )
        findings = token_lint.scan(root)
        self.assertTrue(
            any(finding.code == "ACCIDENTAL_MAX_DEFAULT" for finding in findings)
        )

    def test_artifact_and_mcp_defaults(self) -> None:
        root = self._clean_root()
        state = root / ".codex-state"
        state.mkdir()
        (state / "conversation.jsonl").write_text("raw\n", encoding="utf-8")
        (root / ".mcp.json").write_text(
            json.dumps({"mcpServers": {"all": {"include_all_tools": True, "tools": ["*"]}}}),
            encoding="utf-8",
        )
        codes = {finding.code for finding in token_lint.scan(root)}
        self.assertIn("COMMITTED_CODEX_STATE", codes)
        self.assertIn("BROAD_MCP_DEFAULT", codes)

    def test_codex_state_finding_requires_a_git_tracked_path(self) -> None:
        root = self._clean_root()
        state = root / ".codex-state"
        state.mkdir()
        state_file = state / "conversation.jsonl"
        state_file.write_text("AKIA" + "A" * 16 + "\n", encoding="utf-8")
        tracked = b"AGENTS.md\0SKILL.md\0references/one.md\0src/app.py\0"
        result = token_lint.subprocess.CompletedProcess(
            args=["git", "ls-files"], returncode=0, stdout=tracked
        )
        with patch.object(token_lint.subprocess, "run", return_value=result):
            findings = token_lint.scan(root)
        ignored_codes = {finding.code for finding in findings}
        self.assertNotIn("COMMITTED_CODEX_STATE", ignored_codes)
        self.assertNotIn("SECRET_LITERAL", ignored_codes)

        tracked_state = tracked + b".codex-state/conversation.jsonl\0"
        result = token_lint.subprocess.CompletedProcess(
            args=["git", "ls-files"], returncode=0, stdout=tracked_state
        )
        with patch.object(token_lint.subprocess, "run", return_value=result):
            findings = token_lint.scan(root)
        self.assertIn("COMMITTED_CODEX_STATE", {finding.code for finding in findings})

    def test_secret_literal_is_rejected_without_echo(self) -> None:
        root = self._clean_root()
        secret = "AKIA" + "A" * 16
        (root / "src" / "leak.txt").write_text(secret, encoding="utf-8")
        findings = token_lint.scan(root)
        secret_findings = [item for item in findings if item.code == "SECRET_LITERAL"]
        self.assertEqual(len(secret_findings), 1)
        self.assertNotIn(secret, str(secret_findings[0]))

    def test_findings_sorted_and_output_bounded(self) -> None:
        root = self._clean_root()
        for index in range(10):
            (root / "src" / f"bad{index}.py").write_text("DEFAULT_EFFORT = 'max'\n", encoding="utf-8")
        findings = token_lint.scan(root, max_findings=3)
        self.assertEqual(len(findings), 3)
        self.assertEqual(findings, sorted(findings, key=lambda finding: (finding.path, finding.line, finding.code, finding.message)))
        self.assertEqual(len(token_lint.scan(root, max_findings=0)), 0)


if __name__ == "__main__":
    unittest.main()
