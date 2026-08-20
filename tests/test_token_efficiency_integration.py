from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "plugins/codex-orchestration/skills/codex-orchestration/scripts"
sys.path.insert(0, str(SCRIPTS))

import context_index  # noqa: E402
import session_telemetry  # noqa: E402
import task_packet  # noqa: E402
import validation_cache  # noqa: E402


class TokenEfficiencyIntegrationTests(unittest.TestCase):
    def test_deterministic_packet_index_cache_lane_and_telemetry_flow(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "src" / "worker.py"
            source.parent.mkdir()
            source.write_text("import json\n\nclass Worker:\n    pass\n", encoding="utf-8")

            packet = task_packet.build_task_packet(
                role="implementation-worker",
                static_rules=["fork_turns=none", "Do not spawn descendants."],
                goal="Change the owned worker.",
                base_revision="abc123",
                files_allowed=["src/worker.py"],
                files_forbidden=["secrets.txt"],
                known_facts=["Worker is isolated.", "Worker is isolated."],
                constraints=["Preserve unrelated files."],
                acceptance_criteria=["Focused validation passes."],
                validation="python -m unittest tests.test_worker",
                output_contract="Changed files and validation result only.",
                repo_root=root,
            )
            budget = task_packet.WaveBudget("lean")
            self.assertTrue(budget.consume(packet).accepted)
            duplicate = budget.consume(packet)
            self.assertTrue(duplicate.duplicate)
            self.assertFalse(duplicate.accepted)

            with context_index.ContextIndex(root) as index:
                metadata = index.index_file("src/worker.py")
                self.assertEqual(index.query("Worker")[0]["blob_id"], metadata["blob_id"])
                live = index.fetch_lines("src/worker.py", 1, 1)
                self.assertEqual([line.replace("\r\n", "\n") for line in live], ["import json\n"])

            key = validation_cache.make_validation_key(
                [sys.executable, "-m", "unittest", "tests.test_worker"],
                executable=sys.executable,
                executable_version=sys.version.split()[0],
                source_blob_ids={"src/worker.py": metadata["blob_id"]},
                lock_hashes={"requirements.txt": "b" * 40},
                config_hashes={"pyproject.toml": "c" * 40},
                env_allowlist={"CI": "true"},
            )
            validation = validation_cache.ValidationCache(root)
            validation.record_result(key, status="passed", exit_category="success", exit_code=0)
            self.assertIsNotNone(validation.lookup(key))
            self.assertIsNone(validation.lookup(key, purpose="final"))
            self.assertIsNone(validation.lookup(key, purpose="security"))
            validation.record_result(key, status="failed", exit_category="assertion", exit_code=1)
            self.assertIsNone(validation.lookup(key))
            self.assertIsNotNone(validation.failure_hint(key))

            lane_context = {
                "repo_relative": ".",
                "worktree_relative": ".",
                "branch": "main",
                "model": "gpt-5.6-luna",
                "effort": "medium",
                "cwd_relative": "src",
                "sandbox": "workspace-write",
                "approval": "never",
                "tool_profile": "lean",
            }
            lanes = session_telemetry.SessionLaneManager(root)
            first = lanes.get_or_create(lane_context, caller_capability="local")
            self.assertEqual(lanes.resume(first["lane_id"], lane_context, caller_capability="local"), first)
            changed = lanes.resume(
                first["lane_id"],
                dict(lane_context, model="gpt-5.6-terra"),
                caller_capability="local",
            )
            self.assertNotEqual(changed["lane_id"], first["lane_id"])

            usage = session_telemetry.TelemetryStore(root)
            event = usage.record(
                {
                    "input_tokens": 100,
                    "cached_input_tokens": 60,
                    "output_tokens": 10,
                    "reasoning_output_tokens": 5,
                    "agent_count": 1,
                    "tool_call_count": 2,
                    "duplicate_packet_count": 1,
                    "validation_cache_hit_count": 1,
                    "failure_cache_hit_count": 1,
                    "model": "gpt-5.6-luna",
                    "reasoning_effort": "medium",
                    "task_packet_digest": packet.sha256,
                    "git_blob_ids": [metadata["blob_id"]],
                }
            )
            self.assertEqual(event["uncached_input_tokens"], 40)
            self.assertEqual(event["cache_hit_ratio"], 0.6)
            raw = (root / ".codex-state/usage/usage.jsonl").read_text(encoding="utf-8")
            self.assertNotIn("class Worker", raw)
            self.assertNotIn(str(root), raw)


if __name__ == "__main__":
    unittest.main()
