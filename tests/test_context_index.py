from __future__ import annotations

import contextlib
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / "plugins/codex-orchestration/skills/codex-orchestration/scripts"
sys.path.insert(0, str(SCRIPTS))

import context_index as index  # noqa: E402


class ContextIndexTests(unittest.TestCase):
    def test_git_blob_id_supports_sha1_and_sha256_repositories(self) -> None:
        data = b"content\n"
        self.assertEqual(len(index.git_blob_id(data, object_format="sha1")), 40)
        self.assertEqual(len(index.git_blob_id(data, object_format="sha256")), 64)
        with self.assertRaises(ValueError):
            index.git_blob_id(data, object_format="future")

    def test_limits_reject_bool_float_zero_and_hardlink_database(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaises(ValueError):
                index.ContextIndex(root, source_max_bytes=True)
            with self.assertRaises(ValueError):
                index.ContextIndex(root, query_limit=0)
            with self.assertRaises(ValueError):
                index.ContextIndex(root, query_limit=1.5)
            original = root / "original.sqlite"
            original.write_bytes(b"not sqlite")
            linked = root / "linked.sqlite"
            try:
                linked.hardlink_to(original)
            except (OSError, NotImplementedError):
                self.skipTest("hardlink creation unavailable")
            with self.assertRaises(index.UnsafePathError):
                index.ContextIndex(root, db_path=linked)

    def test_metadata_only_index_query_and_live_lines(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "module.py"
            source.write_text(
                "# body secret should not be stored\nimport json\n\nclass Thing:\n"
                "    def run(self):\n        return 'body secret should not be stored'\n",
                encoding="utf-8",
            )
            with index.ContextIndex(root) as context:
                info = context.index_file(source)
                self.assertEqual(info["language"], "python")
                result = context.query("Thing")[0]
                self.assertEqual(result["symbols"][0]["name"], "Thing")
                self.assertNotIn("snippet", result)
                self.assertNotIn("text", result)
                self.assertEqual(context.fetch_lines("module.py", 1, 2)[1].replace("\r\n", "\n"), "import json\n")
                context.fetch_once("module.py", 1, 1)
                with self.assertRaises(index.RepeatedReadError):
                    context.fetch_once("module.py", 1, 1)
                database = Path(context.db_path).read_bytes()
                self.assertNotIn(b"body secret should not be stored", database)

    def test_blob_invalidation_and_wildcard_escaping(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "README.md"
            source.write_text("# Heading\nplain body\n", encoding="utf-8")
            with index.ContextIndex(root) as context:
                context.index_file("README.md")
                self.assertEqual(context.query("%"), [])
                source.write_text("# Changed\nnew body\n", encoding="utf-8")
                with self.assertRaises(index.StaleIndexError):
                    context.fetch_lines("README.md", 1, 1)
                self.assertIsNone(context.indexed_blob("README.md"))

    def test_invalid_utf8_and_path_links_are_not_indexed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside_tmp:
            root = Path(tmp)
            bad = root / "bad.py"
            bad.write_bytes(b"\xff\xfe")
            with index.ContextIndex(root) as context:
                with self.assertRaises(index.InvalidSourceEncoding):
                    context.index_file("bad.py")
                outside = Path(outside_tmp) / "outside.py"
                outside.write_text("class Outside: pass\n", encoding="utf-8")
                link = root / "link.py"
                try:
                    link.symlink_to(outside)
                except (OSError, NotImplementedError):
                    self.skipTest("symlink creation unavailable")
                with self.assertRaises(Exception):
                    context.index_file("link.py")

    def test_corrupt_sqlite_is_quarantined(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = root / "index.sqlite"
            db.write_bytes(b"not a sqlite database")
            with index.ContextIndex(root, db_path=db) as context:
                self.assertEqual(context.query("missing"), [])
            self.assertTrue(list(root.glob("index.sqlite.sqlite-corrupt-*")))

    def test_unknown_logical_schema_is_quarantined_and_rebuilt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            database = root / "index.sqlite"
            with index.ContextIndex(root, db_path=database):
                pass
            with contextlib.closing(sqlite3.connect(database)) as connection:
                connection.execute(
                    "UPDATE index_meta SET value = '999' WHERE key = 'format_version'"
                )
                connection.commit()
            with index.ContextIndex(root, db_path=database) as context:
                self.assertEqual(context.query("missing"), [])
            self.assertTrue(list(root.glob("index.sqlite.sqlite-schema-*")))
            with contextlib.closing(sqlite3.connect(database)) as connection:
                self.assertEqual(
                    connection.execute(
                        "SELECT value FROM index_meta WHERE key = 'format_version'"
                    ).fetchone(),
                    (str(index.INDEX_FORMAT_VERSION),),
                )

    def test_column_and_index_schema_mismatches_are_rebuilt(self) -> None:
        mutations = {
            "column": "ALTER TABLE files RENAME COLUMN language TO lang",
            "index": "DROP INDEX symbols_name",
            "trigger": (
                "CREATE TRIGGER block_files BEFORE INSERT ON files "
                "BEGIN SELECT RAISE(ABORT, 'blocked'); END"
            ),
            "view": "CREATE VIEW file_names AS SELECT path FROM files",
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for label, statement in mutations.items():
                with self.subTest(label=label):
                    database = root / f"{label}.sqlite"
                    with index.ContextIndex(root, db_path=database):
                        pass
                    with contextlib.closing(sqlite3.connect(database)) as connection:
                        connection.execute(statement)
                        connection.commit()
                    with index.ContextIndex(root, db_path=database) as context:
                        self.assertEqual(context.query("missing"), [])
                    self.assertTrue(
                        list(root.glob(f"{label}.sqlite.sqlite-schema-*"))
                    )
                    with contextlib.closing(sqlite3.connect(database)) as connection:
                        self.assertEqual(
                            index._schema_signature(connection),
                            index._expected_schema_signature(),
                        )

    def test_sensitive_generated_lock_and_binary_paths_are_excluded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in (".env", "package-lock.json", "private.pem", "bundle.min.js"):
                (root / name).write_text("metadata must not be indexed", encoding="utf-8")
            with index.ContextIndex(root) as context:
                for name in (".env", "package-lock.json", "private.pem", "bundle.min.js"):
                    with self.subTest(name=name), self.assertRaises(index.ContextIndexError):
                        context.index_file(name)

    def test_git_discovery_failure_does_not_walk_untracked_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            private = root / "private.py"
            private.write_text("class PrivateOnly: pass\n", encoding="utf-8")
            with index.ContextIndex(root) as context:
                with patch.object(index.subprocess, "run", side_effect=OSError("git unavailable")):
                    with patch.object(index.os, "walk", side_effect=AssertionError("filesystem fallback")):
                        with self.assertWarnsRegex(RuntimeWarning, "git ls-files unavailable"):
                            result = context.index_repository()
                self.assertEqual(result, [])
                self.assertIsNone(context.indexed_blob("private.py"))
                self.assertEqual(context.query("PrivateOnly"), [])
                status = context.repository_status
                self.assertEqual(status["status"], "unavailable")
                self.assertEqual(status["tracked_files"], 0)
                self.assertLessEqual(len(status["warning"]), index.MAX_REPOSITORY_WARNING_LENGTH)


if __name__ == "__main__":
    unittest.main()
