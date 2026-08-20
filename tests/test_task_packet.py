from __future__ import annotations

from pathlib import Path
import sys
import tempfile
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

import task_packet as packets  # noqa: E402


def make_packet(**overrides: object) -> packets.TaskPacket:
    values: dict[str, object] = {
        "role": "implementation-worker",
        "static_rules": ["Do not spawn descendants.", "fork_turns=none"],
        "goal": "e\r\n\u0065\u0301",
        "base_revision": "abc123",
        "files_allowed": ["b\\src.py", "a.py", "a.py"],
        "files_forbidden": ["secrets.txt"],
        "known_facts": ["z", "e\u0301", "z"],
        "constraints": ["owned files only", "owned files only"],
        "acceptance_criteria": ["pass", "pass"],
        "validation_command": "pytest\r\n-q",
        "expected_output": "all pass",
    }
    values.update(overrides)
    return packets.build_task_packet(**values)


class TaskPacketTests(unittest.TestCase):
    def test_fixed_order_normalization_and_stable_hash(self) -> None:
        first = make_packet()
        second = packets.build_task_packet(
            goal="e\né",
            role="implementation-worker",
            static_rules=["fork_turns=none", "Do not spawn descendants."],
            base_revision="abc123",
            files_allowed=["a.py", "b/src.py"],
            files_forbidden=["secrets.txt"],
            known_facts=["é", "z"],
            constraints=["owned files only"],
            acceptance_criteria=["pass"],
            validation_command="pytest\n-q",
            expected_output="all pass",
        )
        self.assertEqual(tuple(first), packets.PACKET_KEYS)
        self.assertEqual(
            packets.PACKET_KEYS,
            (
                "VERSION",
                "ROLE",
                "STATIC_RULES",
                "GOAL",
                "BASE_REVISION",
                "FILES_ALLOWED",
                "FILES_FORBIDDEN",
                "KNOWN_FACTS",
                "CONSTRAINTS",
                "ACCEPTANCE_CRITERIA",
                "VALIDATION",
                "OUTPUT_CONTRACT",
            ),
        )
        self.assertEqual(first.canonical_bytes, second.canonical_bytes)
        self.assertEqual(first.sha256, second.sha256)
        self.assertNotIn(b"\r", first.canonical_bytes)
        self.assertFalse(first.canonical_bytes.endswith(b"\n"))
        self.assertEqual(first.canonical_bytes.decode("utf-8").encode("utf-8"), first.canonical_bytes)
        with self.assertRaises(TypeError):
            first.payload["GOAL"] = "mutated"  # type: ignore[index]
        reversed_mapping = dict(reversed(list(first.to_dict().items())))
        rebuilt = packets.build_task_packet(reversed_mapping)
        self.assertEqual(rebuilt.canonical_bytes, first.canonical_bytes)

    def test_secret_rejection_has_only_field_and_category(self) -> None:
        with self.assertRaises(packets.PacketSecretError) as raised:
            make_packet(known_facts=["api_key=sk-12345678901234567890"])
        self.assertEqual(raised.exception.field, "KNOWN_FACTS")
        self.assertEqual(raised.exception.category, "openai_key")
        self.assertNotIn("123456789012", str(raised.exception))

    def test_unstable_values_are_rejected_from_cacheable_prefix(self) -> None:
        with self.assertRaises(packets.PacketSchemaError):
            make_packet(static_rules=["generated 2026-08-20T12:30:00Z"])
        with self.assertRaises(packets.PacketSchemaError):
            make_packet(static_rules=["read C:\\Users\\alice\\private.txt"])

    def test_dynamic_text_cannot_serialize_user_absolute_paths(self) -> None:
        cases = (
            {"goal": "Inspect C:\\Users\\alice\\repo"},
            {"known_facts": ["checkout is D:\\work\\repo"]},
            {"constraints": ["read /home/alice/private"]},
            {"constraints": ["read /root/private"]},
            {"known_facts": ["checkout is /workspace/alice/repo"]},
            {"goal": r"Inspect \\server\private\repo"},
            {"goal": "Inspect //server/private/repo"},
            {"goal": "read //server"},
            {"goal": r"read \\server"},
            {"goal": "read ///"},
            {"validation_command": "tar -C/root/private -cf archive.tar ."},
            {"validation_command": "tar -C//server/share -cf archive.tar ."},
            {"validation_command": r"tar -C\\server\share -cf archive.tar ."},
            {"known_facts": ["workspace:/root/private"]},
            {"goal": "cd /"},
            {"goal": "read /@scope/private"},
            {"goal": r"read \Windows\System32"},
            {"validation_command": "python C:\\Users\\alice\\validate.py"},
            {"expected_output": "write /tmp/alice/report.json"},
        )
        for overrides in cases:
            with self.subTest(overrides=overrides), self.assertRaisesRegex(
                packets.PacketSchemaError, "user-specific absolute path"
            ) as raised:
                make_packet(**overrides)
            self.assertNotIn("alice", str(raised.exception))

    def test_stable_url_and_relative_paths_remain_allowed(self) -> None:
        packet = make_packet(
            known_facts=["source https://github.com/openai/codex"],
            constraints=[
                "inspect src/app.py",
                "python ./scripts/check.py",
                "git -Csrc/subdir status",
                "cc -Iinclude/project file.c",
                r"python .\scripts\check.py",
                r"inspect src\app.py",
            ],
        )
        text = packet.canonical_bytes.decode("utf-8")
        self.assertIn("https://github.com/openai/codex", text)
        self.assertIn("src/app.py", text)
        self.assertIn("python ./scripts/check.py", text)
        self.assertIn("git -Csrc/subdir status", text)
        self.assertIn("cc -Iinclude/project file.c", text)
        self.assertIn(r"python .\scripts\check.py", packet.payload["CONSTRAINTS"])
        self.assertIn(r"inspect src\app.py", packet.payload["CONSTRAINTS"])

    def test_traversal_and_symlink_are_rejected(self) -> None:
        with self.assertRaises(packets.PacketPathError):
            make_packet(files_allowed=["../outside"])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target.txt"
            target.write_text("x", encoding="utf-8")
            link = root / "link.txt"
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):
                return
            with self.assertRaises(packets.PacketPathError):
                make_packet(files_allowed=["link.txt"], repo_root=root)

    def test_duplicate_registry_and_wave_budget(self) -> None:
        packet = make_packet()
        registry = packets.DuplicatePacketRegistry()
        self.assertTrue(registry.register(packet))
        self.assertFalse(registry.register(packet))

        budget = packets.WaveBudget(soft_tokens=10, hard_tokens=20)
        soft = budget.consume(packet, estimated_tokens=11)
        self.assertTrue(soft.accepted)
        self.assertTrue(soft.soft_exceeded)
        self.assertFalse(budget.can_release_executor())
        hard = budget.consume(10)
        self.assertFalse(hard.accepted)
        self.assertTrue(hard.hard_exceeded)
        self.assertEqual(
            hard.remediation,
            (
                "deduplicate repeated evidence",
                "replace full source/logs with bounded relevant snippets",
                "split into independent packets",
            ),
        )
        self.assertEqual(budget.used_tokens, 11)

        packet_budget = packets.PacketBudget("lean")
        soft_packet = packet_budget.consume(packet, estimated_tokens=4_000)
        self.assertTrue(soft_packet.accepted)
        self.assertTrue(soft_packet.blocking)
        hard_packet = packets.PacketBudget("lean").consume(
            packet, estimated_tokens=7_000
        )
        self.assertFalse(hard_packet.accepted)
        self.assertTrue(hard_packet.hard_exceeded)


if __name__ == "__main__":
    unittest.main()
