from __future__ import annotations

from pathlib import Path
import sys
import unittest


SCRIPTS = (
    Path(__file__).resolve().parents[1]
    / "plugins"
    / "codex-orchestration"
    / "skills"
    / "codex-orchestration"
    / "scripts"
)
sys.path.insert(0, str(SCRIPTS))

import token_budget as budgets  # noqa: E402


class TokenBudgetTests(unittest.TestCase):
    def test_hard_rejection_surfaces_exact_ordered_remediation(self) -> None:
        decision = budgets.evaluate_hard_budget(101, 100, kind="wave")
        self.assertFalse(decision.accepted)
        self.assertTrue(decision.hard_exceeded)
        self.assertEqual(
            decision.remediation,
            (
                "deduplicate repeated evidence",
                "replace full source/logs with bounded relevant snippets",
                "split into independent packets",
            ),
        )
        self.assertEqual(decision.to_dict()["remediation"], list(decision.remediation))
        self.assertIn("deduplicate repeated evidence ->", decision.message)

    def test_non_overflow_is_accepted_without_remediation(self) -> None:
        decision = budgets.evaluate_hard_budget(50, 100, used_tokens=20)
        self.assertTrue(decision.accepted)
        self.assertFalse(decision.hard_exceeded)
        self.assertEqual(decision.remediation, ())

    def test_remediation_stages_are_bounded_and_independent(self) -> None:
        result = budgets.remediate_hard_budget(
            ["same evidence", "same evidence", "ERROR: relevant", "full source"],
            max_chars=24,
            max_snippets=2,
            max_items_per_packet=1,
        )
        self.assertEqual(result["steps"], list(budgets.HARD_BUDGET_REMEDIATION))
        self.assertEqual(len(result["deduplicated_evidence"]), 3)
        self.assertLessEqual(sum(len(item) for item in result["bounded_relevant_snippets"]), 24)
        packets = result["independent_packets"]
        flattened = [item for packet in packets for item in packet]
        self.assertEqual(flattened, result["bounded_relevant_snippets"])
        self.assertEqual(len(flattened), len(set(flattened)))

    def test_split_never_breaks_item_or_character_bounds_to_meet_count(self) -> None:
        with self.assertRaisesRegex(budgets.TokenBudgetError, "evidence item"):
            budgets.split_independent_packets(["x" * 11], max_chars=10)
        with self.assertRaisesRegex(budgets.TokenBudgetError, "packet count"):
            budgets.split_independent_packets(
                ["aa", "bb", "cc"], max_items=1, packet_count=2
            )


if __name__ == "__main__":
    unittest.main()
