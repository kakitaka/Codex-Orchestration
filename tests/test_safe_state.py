from __future__ import annotations

import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / "plugins/codex-orchestration/skills/codex-orchestration/scripts"
sys.path.insert(0, str(SCRIPTS))

import safe_state as state  # noqa: E402


class SafeStateTests(unittest.TestCase):
    def test_atomic_json_and_bounds(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            digest = state.write_json(root, ".codex-state/state.json", {"a": [1, 2]})
            self.assertEqual(state.read_json(root, ".codex-state/state.json"), {"a": [1, 2]})
            self.assertEqual(len(digest), 64)
            with self.assertRaises(state.StateCorruptError):
                state.write_json(root, "too-deep.json", [[[[1]]]], max_depth=2)

    def test_traversal_and_links_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside_tmp:
            root = Path(tmp)
            with self.assertRaises(state.UnsafePathError):
                state.resolve_state_path(root, "../outside.json")
            with self.assertRaises(state.UnsafePathError):
                state.resolve_state_path(root, str(root / "sub" / ".." / "state.json"))
            outside = Path(outside_tmp) / "outside-state.json"
            outside.write_text("{}", encoding="utf-8")
            link = root / "link.json"
            try:
                link.symlink_to(outside)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation unavailable")
            with self.assertRaises(state.UnsafePathError):
                state.read_json(root, "link.json")

    def test_corrupt_state_is_quarantined(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "state.json"
            target.write_bytes(b"{not-json")
            self.assertEqual(
                state.read_json(root, "state.json", default={"fresh": True}, quarantine_corrupt=True),
                {"fresh": True},
            )
            self.assertFalse(target.exists())
            self.assertTrue(list(root.glob("state.json.corrupt-*")))

    def test_ancestor_swap_during_read_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state.write_json(root, ".codex-state/state.json", {"safe": True})
            state_dir = root / ".codex-state"
            displaced = root / ".codex-state-displaced"
            original_revalidate = state._revalidate_ancestors
            calls = 0

            def revalidate_then_swap(snapshot: object) -> None:
                nonlocal calls
                calls += 1
                original_revalidate(snapshot)
                if calls == 1:
                    state_dir.rename(displaced)
                    state_dir.mkdir()
                    (state_dir / "state.json").write_text(
                        '{"attacker":true}', encoding="utf-8"
                    )

            with mock.patch.object(
                state, "_revalidate_ancestors", side_effect=revalidate_then_swap
            ), self.assertRaisesRegex(state.UnsafePathError, "ancestor changed"):
                state.read_bytes(root, ".codex-state/state.json")
            self.assertGreaterEqual(calls, 2)

    def test_compare_and_update_are_atomic(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = ".codex-state/state.json"
            state.write_json(root, target, {"value": 0})
            with self.assertRaises(state.ConcurrentUpdateError):
                state.write_json(root, target, {"value": 1}, expected_digest="0" * 64)

            def bump(value: object) -> object:
                self.assertIsInstance(value, dict)
                mapping = value if isinstance(value, dict) else {}
                return {"value": int(mapping["value"]) + 1}

            errors: list[Exception] = []

            def worker() -> None:
                try:
                    for _ in range(20):
                        state.update_json(root, target, bump, default={"value": 0})
                except Exception as exc:  # pragma: no cover - diagnostic assertion below
                    errors.append(exc)

            threads = [threading.Thread(target=worker) for _ in range(4)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertFalse(errors)
            self.assertEqual(state.read_json(root, target)["value"], 80)


if __name__ == "__main__":
    unittest.main()
