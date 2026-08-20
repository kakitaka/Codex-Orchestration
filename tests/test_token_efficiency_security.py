from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "plugins/codex-orchestration/skills/codex-orchestration/scripts"
sys.path.insert(0, str(SCRIPTS))

import bounded_run  # noqa: E402
import task_packet  # noqa: E402
import token_budget  # noqa: E402


def _packet_values() -> dict[str, object]:
    return {
        "role": "implementation-worker",
        "static_rules": ["fork_turns=none"],
        "goal": "Edit one file.",
        "base_revision": "abc123",
        "files_allowed": ["src/app.py"],
        "files_forbidden": ["private.txt"],
        "known_facts": ["One fact."],
        "constraints": ["One constraint."],
        "acceptance_criteria": ["One criterion."],
        "validation": "python -m unittest tests.test_app",
        "output_contract": "Changed files and test result.",
    }


class TokenEfficiencySecurityTests(unittest.TestCase):
    def test_secret_like_material_is_rejected_from_every_variable_packet_field(self) -> None:
        cases: list[tuple[str, object]] = [
            ("role", "password=hunter2"),
            ("static_rules", ["password=hunter2"]),
            ("goal", "password=hunter2"),
            ("base_revision", "password=hunter2"),
            ("files_allowed", ["ghp_abcdefghijklmnopqrstuvwx.txt"]),
            ("files_forbidden", ["ghp_abcdefghijklmnopqrstuvwx.txt"]),
            ("known_facts", ["password=hunter2"]),
            ("constraints", ["password=hunter2"]),
            ("acceptance_criteria", ["password=hunter2"]),
            ("validation", "password=hunter2"),
            ("output_contract", "password=hunter2"),
        ]
        for field, value in cases:
            with self.subTest(field=field):
                values = _packet_values()
                values[field] = value
                with self.assertRaises(task_packet.PacketSecretError) as raised:
                    task_packet.build_task_packet(**values)
                self.assertNotIn("hunter2", str(raised.exception))
                self.assertNotIn("abcdefghijkl", str(raised.exception))

    def test_shell_metacharacters_remain_one_literal_argv_value(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            marker = root / "must-not-exist.txt"
            literal = f"; open('{marker}', 'w').write('bad')"
            result = bounded_run.run_bounded(
                [sys.executable, "-c", "import sys; print(sys.argv[1])", literal],
                cwd=root,
                timeout=5,
                max_bytes=4096,
            )
            self.assertEqual(result.exit_category, "ok")
            self.assertIn(literal, result.stdout_first)
            self.assertFalse(marker.exists())

    def test_budget_remediation_never_replays_raw_evidence(self) -> None:
        sentinel = "PRIVATE_SOURCE_SENTINEL"
        result = token_budget.remediate_hard_budget(
            [sentinel, sentinel, f"ERROR {sentinel}"], max_snippets=2
        )
        self.assertNotIn(sentinel, repr(result))
        self.assertLessEqual(len(result["deduplicated_digests"]), 64)


if __name__ == "__main__":
    unittest.main()
