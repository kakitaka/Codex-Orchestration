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

import token_profiles as profiles  # noqa: E402


class TokenProfileTests(unittest.TestCase):
    def test_profiles_match_compatibility_contract(self) -> None:
        self.assertEqual(profiles.get_profile("lean").advisor_loops, 1)
        self.assertEqual(profiles.get_profile("balanced").advisor_loops, 2)
        self.assertEqual(profiles.get_profile("quality").advisor_loops, 4)
        self.assertEqual(profiles.get_profile("legacy").advisor_loops, 8)
        self.assertEqual(
            profiles.profile_budgets("lean"),
            {
                "packet_soft_tokens": 3000,
                "packet_hard_tokens": 6000,
                "wave_soft_tokens": 12000,
                "wave_hard_tokens": 20000,
            },
        )
        self.assertEqual(
            profiles.profile_budgets("balanced"),
            {
                "packet_soft_tokens": 5000,
                "packet_hard_tokens": 9000,
                "wave_soft_tokens": 24000,
                "wave_hard_tokens": 36000,
            },
        )
        self.assertEqual(
            profiles.profile_budgets("quality"),
            {
                "packet_soft_tokens": 8000,
                "packet_hard_tokens": 14000,
                "wave_soft_tokens": 48000,
                "wave_hard_tokens": 72000,
            },
        )
        self.assertIsNone(profiles.get_profile("legacy").packet_soft_tokens)

    def test_recommendation_ladder_and_worker_requirement(self) -> None:
        self.assertEqual(
            profiles.recommend_route("lean"),
            {"model": "gpt-5.6-luna", "effort": "medium"},
        )
        self.assertEqual(
            profiles.recommend_route("balanced"),
            {"model": "gpt-5.6-terra", "effort": "medium"},
        )
        self.assertEqual(
            profiles.recommend_route("quality"),
            {"model": "gpt-5.6-sol", "effort": "high"},
        )
        self.assertEqual(
            profiles.recommend_route("quality", escalation=1),
            {"model": "gpt-5.6-sol", "effort": "max"},
        )
        self.assertEqual(
            profiles.recommend_route(
                "quality",
                worker_requirement={"model": "gpt-5.6-luna", "effort": "max"},
            ),
            {"model": "gpt-5.6-luna", "effort": "max"},
        )
        self.assertEqual(
            profiles.recommend_route("quality", worker_requirement="Luna Max"),
            {"model": "gpt-5.6-sol", "effort": "high"},
        )
        with self.assertRaises(profiles.TokenProfileError):
            profiles.recommend_route(
                "lean", worker_requirement={"model": "not-luna", "effort": "max"}
            )

    def test_review_roles_have_sol_high_floor(self) -> None:
        for seat in ("auditor", "advisor", "reviewer", "Reviewer"):
            with self.subTest(seat=seat):
                self.assertEqual(
                    profiles.recommend_route("lean", seat=seat),
                    {"model": "gpt-5.6-sol", "effort": "high"},
                )
        self.assertEqual(
            profiles.recommend_route("lean", seat="reviewer", escalation=1),
            {"model": "gpt-5.6-sol", "effort": "max"},
        )

    def test_worker_requirement_is_agents_precedence_but_explicit_values_win(self) -> None:
        result = profiles.resolve_route(
            profile="lean",
            worker_requirement={"model": "gpt-5.6-luna", "effort": "max"},
            configured={"model": "configured", "effort": "medium"},
        )
        self.assertEqual(result, {"model": "gpt-5.6-luna", "effort": "max"})

        explicit_model = profiles.resolve_route(
            profile="lean",
            explicit={"model": "user-model"},
            worker_requirement={"model": "gpt-5.6-luna", "effort": "max"},
            configured={"model": "configured", "effort": "medium"},
        )
        self.assertEqual(
            explicit_model,
            {"model": "user-model", "effort": "max"},
        )
        explicit_effort = profiles.resolve_route(
            profile="lean",
            explicit={"effort": "low"},
            worker_requirement={"model": "gpt-5.6-luna", "effort": "max"},
            configured={"model": "configured", "effort": "medium"},
        )
        self.assertEqual(
            explicit_effort,
            {"model": "gpt-5.6-luna", "effort": "low"},
        )
        sourced = profiles.resolve_route_with_source(
            profile="lean",
            worker_requirement={"model": "gpt-5.6-luna", "effort": "max"},
            configured={"model": "configured", "effort": "medium"},
        )
        self.assertEqual(sourced["source"], "agents")
        self.assertEqual(sourced["model_source"], "agents")
        self.assertEqual(sourced["effort_source"], "agents")

        with self.assertRaisesRegex(profiles.TokenProfileError, "conflicting explicit"):
            profiles.resolve_route(
                explicit={"model": "first"}, explicit_model="second"
            )

    def test_precedence_does_not_mutate_routes(self) -> None:
        configured = {"model": "configured", "effort": "high"}
        result = profiles.resolve_route(
            profile="quality",
            explicit={"model": "explicit", "effort": "low"},
            agents={"model": "agents", "effort": "medium"},
            configured=configured,
        )
        self.assertEqual(result["model"], "explicit")
        self.assertEqual(result["effort"], "low")
        self.assertEqual(configured, {"model": "configured", "effort": "high"})

        result = profiles.resolve_route(
            profile="lean",
            agents={"model": "agents", "effort": "medium"},
            configured=configured,
        )
        self.assertEqual(result["model"], "agents")
        self.assertEqual(result["effort"], "medium")

        sourced = profiles.resolve_route_with_source(
            profile="lean",
            explicit={"model": "explicit"},
            agents={"effort": "high"},
            configured=configured,
        )
        self.assertEqual(sourced["model_source"], "explicit")
        self.assertEqual(sourced["effort_source"], "agents")


if __name__ == "__main__":
    unittest.main()
