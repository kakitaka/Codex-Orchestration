from __future__ import annotations

import os
import math
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
        test_hashes={"tests/test_validation_cache.py": digest("d")},
        config_hashes={"pyproject.toml": digest("c")},
        env_allowlist={"CI": "true"},
    )


class ValidationCacheTests(unittest.TestCase):
    def test_advisory_trust_and_immutable_key_maps(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            validation = cache.ValidationCache(Path(tmp))
            key = make_key()
            entry = validation.record_result(
                key,
                status="passed",
                exit_category="success",
                exit_code=0,
                deterministic=True,
                complete=True,
                now=100,
            )
            self.assertEqual(entry.trust, cache.UNTRUSTED_ADVISORY)
            self.assertIsNone(validation.lookup(key, now=101))
            self.assertIs(validation.lookup(key, advisory=True, now=101).advisory, True)
            with self.assertRaises(TypeError):
                key.source_blob_ids["other.py"] = "a" * 64  # type: ignore[index]
            with self.assertRaises(cache.ValidationCacheInputError):
                cache.ValidationCacheKey(
                    cache.CACHE_FORMAT_VERSION,
                    key.argv_digest,
                    key.cwd_relative,
                    key.executable_digest,
                    {"module.py": "a" * 40},
                    key.lock_hashes,
                    key.config_hashes,
                    key.env_fingerprints,
                )

    def test_completion_defaults_fail_closed_and_direct_key_is_canonical(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            validation = cache.ValidationCache(Path(tmp))
            key = make_key()
            defaulted = validation.record_result(
                key,
                status="passed",
                exit_category="success",
                exit_code=0,
                now=100,
            )
            self.assertFalse(defaulted.reusable)
            self.assertIsNone(validation.lookup(key, advisory=True, now=101))

            direct = cache.ValidationCacheKey(
                key.format_version,
                key.argv_digest.upper(),
                "",
                key.executable_digest.upper(),
                key.source_blob_ids,
                key.lock_hashes,
                key.config_hashes,
                key.env_fingerprints,
                key.dependency_hashes,
                key.test_hashes,
            )
            self.assertEqual(direct.argv_digest, key.argv_digest)
            self.assertEqual(direct.executable_digest, key.executable_digest)
            self.assertEqual(direct.cwd_relative, ".")

    def test_namespace_and_numeric_validation(self) -> None:
        source_key = cache.make_validation_key(
            ["tool"],
            executable_digest=digest("d"),
            source_blob_ids={"same": digest()},
        )
        config_key = cache.make_validation_key(
            ["tool"],
            executable_digest=digest("d"),
            config_hashes={"same": digest()},
        )
        self.assertNotEqual(source_key.digest, config_key.digest)
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(cache.ValidationCacheInputError):
                cache.ValidationCache(Path(tmp), ttl_seconds=True)
            with self.assertRaises(cache.ValidationCacheInputError):
                cache.ValidationCache(Path(tmp), ttl_seconds=math.inf)

    def test_executable_identity_binds_path_and_content(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = root / "first/tool.bin"
            second = root / "second/tool.bin"
            first.parent.mkdir()
            second.parent.mkdir()
            first.write_bytes(b"AAAA")
            second.write_bytes(b"AAAA")
            fixed_ns = 1_700_000_000_000_000_000
            os.utime(first, ns=(fixed_ns, fixed_ns))
            os.utime(second, ns=(fixed_ns, fixed_ns))
            first_digest = cache.executable_identity_digest(first, "same-version")
            second_digest = cache.executable_identity_digest(second, "same-version")
            self.assertNotEqual(first_digest, second_digest)

            first.write_bytes(b"BBBB")
            os.utime(first, ns=(fixed_ns, fixed_ns))
            replaced_digest = cache.executable_identity_digest(first, "same-version")
            self.assertNotEqual(first_digest, replaced_digest)

    def test_key_does_not_store_argv_or_absolute_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            key = cache.make_validation_key(
                ["tool", "--secret-argument"],
                cwd_relative=".",
                executable_digest=digest("d"),
            )
            encoded = repr(key.as_record()).encode()
            self.assertNotIn(b"secret-argument", encoded)
            self.assertNotIn(str(Path(tmp)).encode(), encoded)

    def test_executable_and_precomputed_digest_are_mutually_exclusive(self) -> None:
        with self.assertRaisesRegex(cache.ValidationCacheInputError, "exclusive"):
            cache.make_validation_key(
                ["python", "-V"],
                executable=sys.executable,
                executable_digest=digest("d"),
            )

    def test_executable_hashing_has_a_size_bound(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            executable = Path(tmp) / "oversized.bin"
            with executable.open("wb") as handle:
                handle.truncate(cache.MAX_EXECUTABLE_BYTES + 1)
            with self.assertRaisesRegex(cache.ValidationCacheInputError, "bound"):
                cache.executable_identity_digest(executable, "test")

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
            self.assertIsNone(validation.lookup(key, now=101))
            self.assertIsNotNone(validation.lookup(key, advisory=True, now=101))
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
            self.assertIsNone(validation.failure_hint(key, now=103))
            self.assertIsNotNone(validation.failure_hint(key, advisory=True, now=103))

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
