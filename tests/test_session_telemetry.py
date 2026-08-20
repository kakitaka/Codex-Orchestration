from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "plugins/codex-orchestration/skills/codex-orchestration/scripts"
sys.path.insert(0, str(SCRIPTS))

import session_telemetry as telemetry  # noqa: E402


def context() -> dict[str, str]:
    return {
        "repo_relative": ".",
        "worktree_relative": ".",
        "branch": "main",
        "model": "gpt-5.6-luna",
        "effort": "max",
        "cwd_relative": "plugins",
        "sandbox": "workspace-write",
        "approval": "never",
        "tool_profile": "default",
    }


class SessionTelemetryTests(unittest.TestCase):
    def test_hmac_lane_stability_and_exact_resume(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = telemetry.SessionLaneManager(root)
            first = manager.get_or_create(
                context(),
                caller_capability="caller-capability",
                resume_id="thread-opaque-123",
            )
            second = manager.get_or_create(context(), caller_capability="caller-capability")
            self.assertEqual(first["lane_id"], second["lane_id"])
            self.assertEqual(first["resume_id"], "thread-opaque-123")
            self.assertEqual(
                manager.resume(
                    first["lane_id"],
                    context(),
                    caller_capability="caller-capability",
                )["resume_id"],
                "thread-opaque-123",
            )
            mismatch = dict(context(), model="gpt-5.6-terra")
            fresh = manager.resume(first["lane_id"], mismatch, caller_capability="caller-capability")
            self.assertNotEqual(fresh["lane_id"], first["lane_id"])
            self.assertNotIn("resume_id", fresh)
            wrong_capability = manager.resume(first["lane_id"], context(), caller_capability="other-capability")
            self.assertNotEqual(wrong_capability["lane_id"], first["lane_id"])
            self.assertNotIn("resume_id", wrong_capability)
            raw = (root / ".codex-state/session-lanes.json").read_bytes()
            self.assertNotIn(str(root).encode(), raw)
            self.assertNotIn(b"caller-capability", raw)

    def test_copied_lane_state_is_scoped_to_repository_path(self) -> None:
        with tempfile.TemporaryDirectory() as first_tmp, tempfile.TemporaryDirectory() as second_tmp:
            first_root = Path(first_tmp)
            second_root = Path(second_tmp)
            first = telemetry.SessionLaneManager(first_root).get_or_create(
                context(), caller_capability="local", resume_id="thread-from-first"
            )
            shutil.copytree(first_root / ".codex-state", second_root / ".codex-state")
            copied = telemetry.SessionLaneManager(second_root).get_or_create(
                context(), caller_capability="local"
            )
            self.assertNotEqual(first["lane_id"], copied["lane_id"])
            self.assertNotIn("resume_id", copied)

    def test_corrupt_lane_state_falls_back(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = telemetry.SessionLaneManager(root)
            manager.get_or_create(context())
            target = root / ".codex-state/session-lanes.json"
            target.write_bytes(b"not-json")
            next_lane = manager.get_or_create(dict(context(), branch="dev"))
            self.assertEqual(next_lane["branch"], "dev")
            self.assertTrue(list(target.parent.glob("session-lanes.json.lanes-corrupt-*")))

    def test_incomplete_lane_with_optional_field_recovers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = telemetry.SessionLaneManager(root)
            target = root / ".codex-state/session-lanes.json"
            target.parent.mkdir(parents=True, exist_ok=True)
            malformed = {
                "format_version": 1,
                "lanes": [{"lane_id": "lane-v1-" + "a" * 64, "resume_id": "opaque"}],
            }
            target.write_text(json.dumps(malformed), encoding="utf-8")
            self.assertEqual(manager.list_lanes(), [])
            self.assertTrue(list(target.parent.glob("session-lanes.json.lanes-corrupt-*")))

    def test_telemetry_allowlist_and_missing_usage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = telemetry.TelemetryStore(root)
            event = store.record(
                {
                    "format_version": 1,
                    "input_tokens": 100,
                    "cached_input_tokens": 25,
                    "output_tokens": 10,
                    "reasoning_effort": "high",
                    "model": "gpt-5.6-luna",
                    "git_blob_ids": ["a" * 40],
                }
            )
            self.assertEqual(event["uncached_input_tokens"], 75)
            self.assertNotIn("input_tokens", store.record({"format_version": 1}))
            raw_before = (root / ".codex-state/usage/usage.jsonl").read_bytes()
            for forbidden in (
                "prompt", "source", "output", "branch", "cwd", "lane_id", "argv", "auth", "secret", "command"
            ):
                with self.subTest(field=forbidden), self.assertRaises(telemetry.TelemetryError):
                    store.record({"format_version": 1, forbidden: "forbidden value"})
                self.assertEqual((root / ".codex-state/usage/usage.jsonl").read_bytes(), raw_before)
            with self.assertRaises(telemetry.TelemetryError):
                store.record({"format_version": 1, "git_blob_ids": {"src.py": "a" * 40}})
            with self.assertRaises(telemetry.TelemetryError):
                store.record({"format_version": 1, "model": "sk-" + "a" * 24})
            self.assertNotIn(b"forbidden value", raw_before)

    def test_aggregate_export_is_opt_in_and_path_free(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = telemetry.TelemetryStore(root)
            store.record({"format_version": 1, "input_tokens": 10, "cached_input_tokens": 5})
            with self.assertRaises(telemetry.TelemetryError):
                store.export_aggregate()
            aggregate = store.export_aggregate(opt_in=True)
            self.assertEqual(aggregate["input_tokens"], 10)
            self.assertEqual(aggregate["cache_hit_ratio"], 0.5)
            self.assertNotIn(str(root), repr(aggregate))

    def test_ratio_requires_consistent_paired_counters(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = telemetry.TelemetryStore(Path(tmp))
            with self.assertRaisesRegex(telemetry.TelemetryError, "does not match"):
                store.record(
                    {
                        "input_tokens": 100,
                        "cached_input_tokens": 25,
                        "cache_hit_ratio": 0.5,
                    }
                )
            with self.assertRaisesRegex(telemetry.TelemetryError, "paired"):
                store.record({"cache_hit_ratio": 0.5})
            store.record({"input_tokens": 100})
            store.record({"cached_input_tokens": 90})
            aggregate = store.export_aggregate(opt_in=True)
            self.assertNotIn("cache_hit_ratio", aggregate)


if __name__ == "__main__":
    unittest.main()
