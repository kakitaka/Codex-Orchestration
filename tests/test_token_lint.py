from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
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

    def _git_results(
        self, root: Path, tracked: bytes
    ) -> list[token_lint.subprocess.CompletedProcess[bytes]]:
        top = token_lint.subprocess.CompletedProcess(
            args=["git", "rev-parse"],
            returncode=0,
            stdout=(str(root.resolve()) + "\n").encode("utf-8"),
        )
        files = token_lint.subprocess.CompletedProcess(
            args=["git", "ls-files"], returncode=0, stdout=tracked
        )
        return [top, files]

    def _scan_fixture(
        self, root: Path, *, max_findings: int = token_lint.DEFAULT_MAX_FINDINGS
    ) -> list[token_lint.Finding]:
        tracked = sorted(
            path.relative_to(root).as_posix()
            for path in root.rglob("*")
            if path.is_file() and not path.is_symlink()
        )
        tracked_bytes = ("\0".join(tracked) + "\0").encode("utf-8")
        with patch.object(
            token_lint.subprocess,
            "run",
            side_effect=self._git_results(root, tracked_bytes),
        ):
            return token_lint.scan(root, max_findings=max_findings)

    def test_clean_minimal_fixture(self) -> None:
        root = self._clean_root()
        self.assertEqual(self._scan_fixture(root), [])

    def test_budgets_and_broken_reference(self) -> None:
        root = self._clean_root()
        (root / "SKILL.md").write_text("x" * (token_lint.MAX_SKILL_BYTES + 1), encoding="utf-8")
        (root / "AGENTS.md").write_text("# Rules\n" + "line\n" * (token_lint.MAX_AGENTS_LINES + 1), encoding="utf-8")
        (root / "src" / "broken.md").write_text("[missing](nope.md)\n", encoding="utf-8")
        codes = {finding.code for finding in self._scan_fixture(root)}
        self.assertIn("SKILL_BYTES", codes)
        self.assertIn("AGENTS_LINES", codes)
        self.assertIn("BROKEN_REFERENCE", codes)

    def test_oversized_always_loaded_files_cannot_skip_byte_budgets(self) -> None:
        root = self._clean_root()
        for name in ("AGENTS.md", "SKILL.md"):
            with (root / name).open("wb") as handle:
                handle.truncate(token_lint.MAX_FILE_BYTES + 1)
        codes = {finding.code for finding in self._scan_fixture(root)}
        self.assertIn("AGENTS_BYTES", codes)
        self.assertIn("SKILL_BYTES", codes)

    def test_duplicate_prompt_blocks(self) -> None:
        root = self._clean_root()
        block = "A stable instruction block that should only be present once. " * 8
        (root / "src" / "one.md").write_text(block, encoding="utf-8")
        (root / "src" / "two.md").write_text(block, encoding="utf-8")
        findings = self._scan_fixture(root)
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
        codes = {finding.code for finding in self._scan_fixture(root)}
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
        findings = self._scan_fixture(root)
        self.assertTrue(
            any(finding.code == "ACCIDENTAL_MAX_DEFAULT" for finding in findings)
        )

    def test_only_exact_reviewed_preset_effort_constants_allow_max(self) -> None:
        root = self._clean_root()
        scripts = root / "plugins" / "codex-orchestration" / "skills" / "codex-orchestration" / "scripts"
        scripts.mkdir(parents=True)
        routing = scripts / "routing_state.py"
        routing.write_text(
            'TERRA_LUNA_SOL_ESCALATION_ROOT_EFFORT = "max"\n'
            'TERRA_LUNA_SOL_ESCALATION_EXECUTOR_EFFORT = "max"\n'
            'TERRA_LUNA_SOL_ESCALATION_ADVISOR_EFFORT = "max"\n',
            encoding="utf-8",
        )
        self.assertFalse(
            any(
                finding.code == "ACCIDENTAL_MAX_DEFAULT"
                for finding in self._scan_fixture(root)
            )
        )

        routing.write_text(
            'TERRA_LUNA_SOL_ESCALATION_WORKER_EFFORT = "max"\n',
            encoding="utf-8",
        )
        self.assertTrue(
            any(
                finding.code == "ACCIDENTAL_MAX_DEFAULT"
                for finding in self._scan_fixture(root)
            )
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
        codes = {finding.code for finding in self._scan_fixture(root)}
        self.assertIn("COMMITTED_CODEX_STATE", codes)
        self.assertIn("BROAD_MCP_DEFAULT", codes)

    def test_codex_state_finding_requires_a_git_tracked_path(self) -> None:
        root = self._clean_root()
        state = root / ".codex-state"
        state.mkdir()
        state_file = state / "conversation.jsonl"
        state_file.write_text("AKIA" + "A" * 16 + "\n", encoding="utf-8")
        tracked = b"AGENTS.md\0SKILL.md\0references/one.md\0src/app.py\0"
        with patch.object(
            token_lint.subprocess,
            "run",
            side_effect=self._git_results(root, tracked),
        ):
            findings = token_lint.scan(root)
        ignored_codes = {finding.code for finding in findings}
        self.assertNotIn("COMMITTED_CODEX_STATE", ignored_codes)
        self.assertNotIn("SECRET_LITERAL", ignored_codes)

        tracked_state = tracked + b".codex-state/conversation.jsonl\0"
        with patch.object(
            token_lint.subprocess,
            "run",
            side_effect=self._git_results(root, tracked_state),
        ):
            findings = token_lint.scan(root)
        self.assertIn("COMMITTED_CODEX_STATE", {finding.code for finding in findings})

    def test_git_scope_does_not_inspect_any_untracked_file(self) -> None:
        root = self._clean_root()
        untracked = root / "private-untracked.py"
        untracked.write_text(
            "DEFAULT_EFFORT = 'max'\nAKIA" + "A" * 16 + "\n",
            encoding="utf-8",
        )
        tracked = b"AGENTS.md\0SKILL.md\0references/one.md\0src/app.py\0"
        with patch.object(
            token_lint.subprocess,
            "run",
            side_effect=self._git_results(root, tracked),
        ):
            findings = token_lint.scan(root)
        self.assertTrue(all(item.path != "private-untracked.py" for item in findings))

    def test_repository_contracts_never_read_an_untracked_plugin_tree(self) -> None:
        root = self._clean_root()
        plugin = root / "plugins/codex-orchestration"
        scripts = plugin / "skills/codex-orchestration/scripts"
        scripts.mkdir(parents=True)
        (plugin / ".codex-plugin").mkdir()
        (plugin / ".codex-plugin/plugin.json").write_text("{}", encoding="utf-8")
        (scripts / "task_packet.py").write_text(
            "raise RuntimeError('untracked')", encoding="utf-8"
        )
        tracked = b"AGENTS.md\0SKILL.md\0references/one.md\0src/app.py\0"
        with (
            patch.object(
                token_lint.subprocess,
                "run",
                side_effect=self._git_results(root, tracked),
            ),
            patch.object(
                token_lint,
                "_literal_assignment",
                side_effect=AssertionError("untracked contract read"),
            ),
        ):
            findings = token_lint.scan(root)
        self.assertTrue(all("plugins/" not in item.path for item in findings))

    def test_markdown_links_use_the_tracked_index_not_untracked_files(self) -> None:
        root = self._clean_root()
        (root / "AGENTS.md").write_text("[private](private.md)\n", encoding="utf-8")
        (root / "private.md").write_text("untracked private text", encoding="utf-8")
        tracked = b"AGENTS.md\0SKILL.md\0references/one.md\0src/app.py\0"
        with patch.object(
            token_lint.subprocess,
            "run",
            side_effect=self._git_results(root, tracked),
        ):
            findings = token_lint.scan(root)
        broken = [item for item in findings if item.code == "BROKEN_REFERENCE"]
        self.assertEqual(len(broken), 1)
        self.assertEqual(broken[0].path, "AGENTS.md")
        self.assertNotIn("private text", str(broken[0]))

    def test_git_discovery_failure_fails_closed_without_filesystem_scan(self) -> None:
        root = self._clean_root()
        private = root / "private-untracked.py"
        private.write_text("AKIA" + "A" * 16, encoding="utf-8")
        with patch.object(token_lint.subprocess, "run", side_effect=OSError("git missing")):
            findings = token_lint.scan(root)
        self.assertEqual([item.code for item in findings], ["GIT_TRACKING_UNAVAILABLE"])
        self.assertTrue(all(item.path != "private-untracked.py" for item in findings))

    def test_repository_subdirectory_is_not_accepted_as_lint_root(self) -> None:
        root = self._clean_root()
        top = token_lint.subprocess.CompletedProcess(
            args=["git", "rev-parse"],
            returncode=0,
            stdout=(str(root.resolve()) + "\n").encode("utf-8"),
        )
        with patch.object(token_lint.subprocess, "run", side_effect=[top]):
            findings = token_lint.scan(root / "src")
        self.assertEqual([item.code for item in findings], ["GIT_TRACKING_UNAVAILABLE"])

    def test_unsafe_tracked_entry_is_reported_instead_of_skipped(self) -> None:
        root = self._clean_root()
        (root / ".venv").mkdir()
        link = root / ".venv/link.py"
        link.write_text("placeholder", encoding="utf-8")
        tracked = b".venv/link.py\0"
        with (
            patch.object(
                token_lint.subprocess,
                "run",
                side_effect=self._git_results(root, tracked),
            ),
            patch.object(token_lint, "_tracked_regular_file", return_value=False),
        ):
            findings = token_lint.scan(root)
        unsafe = [item for item in findings if item.code == "UNSAFE_TRACKED_PATH"]
        self.assertEqual(len(unsafe), 1)
        self.assertEqual(unsafe[0].path, ".venv/link.py")

    def test_hardlinked_tracked_file_is_not_read(self) -> None:
        root = self._clean_root()
        source = root / "src/hardlink-source.py"
        alias = root / "src/hardlink-alias.py"
        source.write_text("PRIVATE_SENTINEL", encoding="utf-8")
        try:
            os.link(source, alias)
        except OSError:
            self.skipTest("hardlinks unavailable")
        self.assertFalse(
            token_lint._tracked_regular_file(
                root, alias, {"src/hardlink-alias.py"}
            )
        )

    def test_secret_literal_is_rejected_without_echo(self) -> None:
        root = self._clean_root()
        secret = "AKIA" + "A" * 16
        (root / "src" / "leak.txt").write_text(secret, encoding="utf-8")
        findings = self._scan_fixture(root)
        secret_findings = [item for item in findings if item.code == "SECRET_LITERAL"]
        self.assertEqual(len(secret_findings), 1)
        self.assertNotIn(secret, str(secret_findings[0]))

    def test_findings_sorted_and_output_bounded(self) -> None:
        root = self._clean_root()
        for index in range(10):
            (root / "src" / f"bad{index}.py").write_text("DEFAULT_EFFORT = 'max'\n", encoding="utf-8")
        findings = self._scan_fixture(root, max_findings=3)
        self.assertEqual(len(findings), 3)
        self.assertEqual(findings, sorted(findings, key=lambda finding: (finding.path, finding.line, finding.code, finding.message)))
        with self.assertRaisesRegex(ValueError, "positive"):
            self._scan_fixture(root, max_findings=0)

    def test_cli_rejects_zero_finding_limit(self) -> None:
        root = self._clean_root()
        with (
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaisesRegex(SystemExit, "2"),
        ):
            token_lint.main(["--root", str(root), "--max-findings", "0"])


if __name__ == "__main__":
    unittest.main()
