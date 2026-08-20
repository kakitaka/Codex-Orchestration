from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "plugins/codex-orchestration/skills/codex-orchestration/scripts"
sys.path.insert(0, str(SCRIPTS))

import validation_cache as cache  # noqa: E402


def digest(ch: str = "a") -> str:
    return ch * 40


def make_key() -> cache.ValidationCacheKey:
    return cache.make_validation_key(
        ["python", "-m", "unittest", "tests"],
        cwd_relative=".",
        executable=sys.executable,
        executable_version="3.test",
        source_blob_ids={"module.py": digest()},
        lock_hashes={"requirements.txt": digest("b")},
        config_hashes={"pyproject.toml": digest("c")},
        env_allowlist={"CI": "true"},
    )


class ValidationCacheTests(unittest.TestCase):
    def test_key_does_not_store_argv_or_absolute_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            key = cache.make_validation_key(
                ["tool", "--secret-argument"],
                cwd_relative=".",
                executable=sys.executable,
                executable_version="test",
                executable_digest=digest("d"),
            )
            encoded = repr(key.as_record()).encode()
            self.assertNotIn(b"secret-argument", encoded)
            self.assertNotIn(str(Path(tmp)).encode(), encoded)

    def test_only_complete_pass_reuses_and_failure_is_hint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            validation = cache.ValidationCache(Path(tmp), ttl_seconds=60)
            key = make_key()
            entry = validation.record_result(
                key,
                status="passed",
                exit_category="success",
                exit_code=0,
                duration_seconds=0.25,
                deterministic=True,
                complete=True,
                now=100,
            )
            self.assertTrue(entry.reusable)
            self.assertIsNotNone(validation.lookup(key, now=101))
            self.assertIsNone(validation.lookup(key, purpose="final", now=101))

            validation.record_result(
                key,
                status="timeout",
                exit_category="timeout",
                complete=False,
                deterministic=False,
                now=102,
            )
            self.assertIsNone(validation.lookup(key, now=103))
            self.assertIsNotNone(validation.failure_hint(key, now=103))

    def test_raw_fields_rejected_before_file_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            validation = cache.ValidationCache(root)
            key = make_key()
            target = root / ".codex-state/validation-cache.json"
            before = target.read_bytes() if target.exists() else None
            with self.assertRaises(cache.ValidationCacheInputError):
                validation.record_result(key, status="passed", exit_category="success", output="secret output")
            self.assertEqual(target.read_bytes() if target.exists() else None, before)
            with self.assertRaises(cache.ValidationCacheInputError):
                validation.record_result(
                    key,
                    status="failed",
                    exit_category="password=do-not-store",
                )

    def test_source_free_results_are_never_reused_or_failure_hints(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            validation = cache.ValidationCache(Path(tmp), ttl_seconds=60)
            key = cache.make_validation_key(
                ["python", "-m", "unittest"],
                executable=sys.executable,
                executable_version="3.test",
                lock_hashes={"requirements.txt": digest("b")},
                config_hashes={"pyproject.toml": digest("c")},
            )
            passed = validation.record_result(
                key,
                status="passed",
                exit_category="success",
                exit_code=0,
                now=100,
            )
            self.assertFalse(passed.reusable)
            self.assertIsNone(validation.lookup(key, now=101))
            failed = validation.record_result(
                key,
                status="failed",
                exit_category="assertion",
                exit_code=1,
                now=102,
            )
            self.assertFalse(failed.is_failure_hint)
            self.assertIsNone(validation.failure_hint(key, now=103))

    def test_corrupt_cache_recovers_safely(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".codex-state").mkdir()
            target = root / ".codex-state/validation-cache.json"
            target.write_bytes(b"{broken")
            validation = cache.ValidationCache(root)
            self.assertIsNone(validation.lookup(make_key()))
            validation.record_result(make_key(), status="passed", exit_category="success", now=1)
            self.assertNotIn(b"{broken", target.read_bytes())


if __name__ == "__main__":
    unittest.main()
