from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "check_playbook_staleness.py"
SPEC = importlib.util.spec_from_file_location("check_playbook_staleness", SCRIPT)
assert SPEC and SPEC.loader
PLAYBOOK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PLAYBOOK)


class PlaybookStalenessTests(unittest.TestCase):
    def _fixture(self, root: Path, **entry_changes: object) -> tuple[Path, Path]:
        source = root / "src.py"
        source.write_text("def stable():\n    return 1\n", encoding="utf-8")
        directory = root / "docs" / "codex-playbooks"
        directory.mkdir(parents=True)
        entry: dict[str, object] = {
            "path": "src.py",
            "blob": PLAYBOOK._blob_id(source),
            "symbols": ["stable"],
            "headings": [],
            "failure_labels": [],
            "validation": "unit",
        }
        entry.update(entry_changes)
        path = directory / "fixture.json"
        path.write_text(
            json.dumps(
                {"version": 1, "name": "fixture", "entries": [entry]},
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        return directory, source

    def test_current_derived_metadata_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory, _source = self._fixture(root)
            self.assertEqual(PLAYBOOK.check_playbooks(root, directory), [])

    def test_changed_source_is_stale(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory, source = self._fixture(root)
            source.write_text("def stable():\n    return 2\n", encoding="utf-8")
            findings = PLAYBOOK.check_playbooks(root, directory)
            self.assertEqual(len(findings), 1)
            self.assertIn("stale blob", findings[0])

    def test_source_text_field_is_rejected_before_use(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory, _source = self._fixture(root, source_text="private")
            findings = PLAYBOOK.check_playbooks(root, directory)
            self.assertEqual(len(findings), 1)
            self.assertIn("schema mismatch", findings[0])

    def test_traversal_and_absolute_paths_are_rejected(self) -> None:
        for unsafe in ("../outside.py", str(Path.cwd().resolve() / "outside.py")):
            with self.subTest(unsafe=unsafe), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                directory, _source = self._fixture(root, path=unsafe)
                findings = PLAYBOOK.check_playbooks(root, directory)
                self.assertEqual(len(findings), 1)
                self.assertIn("path", findings[0])

    def test_symlink_source_is_rejected_when_supported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target.py"
            target.write_text("safe\n", encoding="utf-8")
            link = root / "link.py"
            try:
                link.symlink_to(target)
            except OSError:
                self.skipTest("symlink creation unavailable")
            directory, _source = self._fixture(
                root, path="link.py", blob=PLAYBOOK._blob_id(target)
            )
            findings = PLAYBOOK.check_playbooks(root, directory)
            self.assertEqual(len(findings), 1)
            self.assertIn("symlink", findings[0])

    def test_repository_playbook_uses_available_stdlib_tests(self) -> None:
        path = REPO_ROOT / "docs" / "codex-playbooks" / "token-efficiency-v1.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        for entry in payload["entries"]:
            command = entry["validation"]
            with self.subTest(source=entry["path"]):
                self.assertTrue(command.startswith("python -m unittest tests."))
                self.assertNotIn("pytest", command)
                module = command.split()[-1]
                test_path = REPO_ROOT.joinpath(*module.split(".")).with_suffix(".py")
                self.assertTrue(test_path.is_file(), test_path)


if __name__ == "__main__":
    unittest.main()
