"""Conservative cache for deterministic local validation results.

Only digests and small classification metadata are persisted.  In particular,
argv, executable paths, source text, command output, and environment values
never appear in the cache file.  A failure can be exposed as a hint to a
caller, but only a complete deterministic pass is reusable.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import math
import os
import re
import shutil
import stat
import time
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping, Sequence

try:
    from .safe_state import (
        SafeStateError,
        normalize_relative_path,
        quarantine_file,
        read_json,
        resolve_state_path,
        update_json,
    )
except ImportError:  # type: ignore
    from safe_state import (  # type: ignore
        SafeStateError,
        normalize_relative_path,
        quarantine_file,
        read_json,
        resolve_state_path,
        update_json,
    )


CACHE_FORMAT_VERSION = 2
DEFAULT_TTL_SECONDS = 24 * 60 * 60
MAX_ENTRIES = 512
MAX_CACHE_BYTES = 2 * 1024 * 1024
MAX_EXECUTABLE_BYTES = 64 * 1024 * 1024
MAX_TTL_SECONDS = 365 * 24 * 60 * 60
MAX_FUTURE_SKEW_SECONDS = 5 * 60
MAX_KEY_FIELDS = 2_048
UNTRUSTED_ADVISORY = "UNTRUSTED_ADVISORY"
_DIGEST_RE = r"^[0-9a-fA-F]{16,128}$"
_ALLOWED_PURPOSES = frozenset(
    {
        "ordinary",
        "advisory",
        "authoritative",
        "final",
        "release",
        "security",
        "fresh",
    }
)
_NON_REUSABLE = frozenset({"partial", "timeout", "timed_out", "cancel", "cancelled", "corrupt", "incomplete"})
_PASS = frozenset({"pass", "passed", "success", "ok", "complete", "completed"})
_FAIL = frozenset({"fail", "failed", "failure", "error"})
_CATEGORY_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")


class ValidationCacheError(ValueError):
    """Invalid cache input or malformed persisted cache."""


class ValidationCacheInputError(ValidationCacheError):
    """An unsafe command, path, digest, or forbidden raw field was supplied."""


def _canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ValidationCacheInputError("value cannot be canonicalized") from exc


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _exact_bounded_int(
    value: Any,
    field: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        raise ValidationCacheInputError(
            f"{field} must be an integer in [{minimum}, {maximum}]"
        )
    return value


def _validate_digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or len(value) < 16 or len(value) > 128:
        raise ValidationCacheInputError(f"invalid {field}")
    lowered = value.lower()
    if any(char not in "0123456789abcdef" for char in lowered):
        raise ValidationCacheInputError(f"invalid {field}")
    return lowered


def _normal_relative(value: Any, field: str, *, allow_root: bool = False) -> str:
    if not isinstance(value, str) or "\x00" in value:
        raise ValidationCacheInputError(f"invalid {field}")
    if allow_root and value in {"", "."}:
        return "."
    try:
        return normalize_relative_path(value)
    except SafeStateError as exc:
        raise ValidationCacheInputError(f"invalid {field}") from exc


def _normalize_hash_map(
    value: Mapping[str, str] | None,
    field: str,
    *,
    namespace: str,
) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValidationCacheInputError(f"{field} must be a mapping")
    if len(value) > 2048:
        raise ValidationCacheInputError(f"{field} exceeds bound")
    result: dict[str, str] = {}
    for raw_name, raw_digest in value.items():
        name = _normal_relative(raw_name, f"{field} name")
        if name in result:
            raise ValidationCacheInputError(f"duplicate {field} name")
        digest = _validate_digest(raw_digest, f"{field} value")
        # Category and path are part of the digest domain.  This prevents a
        # digest copied between source/config/test namespaces from colliding.
        result[name] = _digest(
            {"namespace": namespace, "path": name, "digest": digest}
        )
    return dict(sorted(result.items()))


def _normalize_env(value: Mapping[str, Any] | Sequence[str] | None) -> dict[str, str]:
    """Fingerprint only an explicit environment allowlist."""

    if value is None:
        return {}
    if isinstance(value, Mapping):
        items = list(value.items())
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        items = [(name, os.environ.get(name)) for name in value]
    else:
        raise ValidationCacheInputError("env_allowlist must be a mapping or sequence")
    if len(items) > 256:
        raise ValidationCacheInputError("env_allowlist exceeds bound")
    result: dict[str, str] = {}
    for raw_name, raw_value in items:
        if not isinstance(raw_name, str) or not raw_name or len(raw_name) > 128:
            raise ValidationCacheInputError("invalid environment name")
        if any(char in raw_name for char in "\x00\r\n=\\/"):
            raise ValidationCacheInputError("invalid environment name")
        if raw_value is None:
            # Missing usage is represented by absence, not a fabricated zero or value.
            continue
        if not isinstance(raw_value, str) or len(raw_value) > 4096:
            raise ValidationCacheInputError("invalid environment value")
        if raw_name in result:
            raise ValidationCacheInputError("duplicate environment name")
        result[raw_name] = _digest(
            {
                "namespace": "environment",
                "name": raw_name,
                "value_digest": _digest([raw_name, raw_value]),
            }
        )
    return dict(sorted(result.items()))


def executable_identity_digest(executable: str | os.PathLike[str], version: str | None = None) -> str:
    """Digest resolved executable identity and optional version without storing its path."""

    if not isinstance(executable, (str, os.PathLike)):
        raise ValidationCacheInputError("invalid executable")
    raw = os.fspath(executable)
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        raise ValidationCacheInputError("invalid executable")
    version_text = "" if version is None else version
    if not isinstance(version_text, str) or len(version_text) > 128 or "\x00" in version_text:
        raise ValidationCacheInputError("invalid executable version")
    resolved = shutil.which(raw) if not os.path.isabs(raw) else raw
    if resolved is None:
        raise ValidationCacheInputError("executable cannot be resolved")
    resolved = os.path.abspath(resolved)
    try:
        path_before = os.lstat(resolved)
    except OSError as exc:
        raise ValidationCacheInputError("executable cannot be inspected") from exc
    if os.path.islink(resolved) or bool(int(getattr(path_before, "st_file_attributes", 0)) & 0x0400):
        raise ValidationCacheInputError("executable symlink/reparse is not accepted")
    if not stat.S_ISREG(path_before.st_mode) or int(getattr(path_before, "st_nlink", 1)) > 1:
        raise ValidationCacheInputError("executable must be a single-link regular file")
    def object_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
        return (
            int(value.st_dev),
            int(value.st_ino),
            stat.S_IFMT(value.st_mode),
            int(value.st_size),
            int(getattr(value, "st_mtime_ns", 0)),
        )

    path_before_identity = object_identity(path_before)
    try:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(resolved, flags)
    except OSError as exc:
        raise ValidationCacheInputError("executable cannot be inspected") from exc
    content = hashlib.sha256()
    try:
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            before = os.fstat(handle.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise ValidationCacheInputError("executable must be a regular file")
            if int(getattr(before, "st_nlink", 1)) > 1:
                raise ValidationCacheInputError("executable hardlinks are not accepted")
            if object_identity(before) != path_before_identity:
                raise ValidationCacheInputError("executable changed before hashing")
            if before.st_size < 0 or before.st_size > MAX_EXECUTABLE_BYTES:
                raise ValidationCacheInputError("executable exceeds hashing bound")
            bytes_read = 0
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                bytes_read += len(chunk)
                if bytes_read > MAX_EXECUTABLE_BYTES:
                    raise ValidationCacheInputError("executable exceeds hashing bound")
                content.update(chunk)
            after = os.fstat(handle.fileno())
    except OSError as exc:
        raise ValidationCacheInputError("executable cannot be hashed") from exc
    try:
        path_after = os.lstat(resolved)
    except OSError as exc:
        raise ValidationCacheInputError("executable disappeared while hashing") from exc
    if os.path.islink(resolved) or bool(int(getattr(path_after, "st_file_attributes", 0)) & 0x0400):
        raise ValidationCacheInputError("executable changed to a link/reparse point")
    if not stat.S_ISREG(path_after.st_mode) or int(getattr(path_after, "st_nlink", 1)) > 1:
        raise ValidationCacheInputError("executable changed to an unsafe file")
    if object_identity(before) != object_identity(after):
        raise ValidationCacheInputError("executable changed while hashing")
    if object_identity(path_after) != object_identity(before):
        raise ValidationCacheInputError("executable path changed while hashing")
    identity = {
        "namespace": "executable",
        "basename": os.path.basename(resolved).lower(),
        "resolved_path_digest": _digest(
            [os.path.normcase(os.path.realpath(resolved))]
        ),
        "content_sha256": content.hexdigest(),
        "mode": stat.S_IMODE(before.st_mode),
        "size": int(before.st_size),
        "mtime_ns": int(before.st_mtime_ns),
        "version": version_text,
    }
    return _digest(identity)


@dataclass(frozen=True)
class ValidationCacheKey:
    format_version: int
    argv_digest: str
    cwd_relative: str
    executable_digest: str
    source_blob_ids: Mapping[str, str]
    lock_hashes: Mapping[str, str]
    config_hashes: Mapping[str, str]
    env_fingerprints: Mapping[str, str]
    dependency_hashes: Mapping[str, str] = field(default_factory=dict)
    test_hashes: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if type(self.format_version) is not int or self.format_version != CACHE_FORMAT_VERSION:
            raise ValidationCacheInputError("unsupported cache key format")
        object.__setattr__(
            self, "argv_digest", _validate_digest(self.argv_digest, "argv_digest")
        )
        object.__setattr__(
            self,
            "executable_digest",
            _validate_digest(self.executable_digest, "executable_digest"),
        )
        object.__setattr__(
            self,
            "cwd_relative",
            _normal_relative(self.cwd_relative, "cwd_relative", allow_root=True),
        )
        for name in (
            "source_blob_ids",
            "lock_hashes",
            "dependency_hashes",
            "test_hashes",
            "config_hashes",
            "env_fingerprints",
        ):
            value = getattr(self, name)
            if not isinstance(value, Mapping) or len(value) > MAX_KEY_FIELDS:
                raise ValidationCacheInputError(f"{name} must be a bounded mapping")
            normalized: dict[str, str] = {}
            for raw_path, raw_digest in value.items():
                path = _normal_relative(raw_path, f"{name} path")
                if path in normalized:
                    raise ValidationCacheInputError(f"duplicate {name} path")
                digest = _validate_digest(raw_digest, f"{name} digest")
                # make_validation_key emits 64-character namespaced digests.
                # Requiring that representation here prevents direct dataclass
                # construction from bypassing category canonicalization.
                if len(digest) != 64:
                    raise ValidationCacheInputError(f"{name} digest is not canonical")
                normalized[path] = digest
            object.__setattr__(self, name, MappingProxyType(dict(sorted(normalized.items()))))

    def as_record(self) -> dict[str, Any]:
        # Return fresh mutable copies so callers cannot mutate the key held by
        # a cache entry or change a later digest calculation.
        record = {
            "format_version": self.format_version,
            "argv_digest": self.argv_digest,
            "cwd_relative": self.cwd_relative,
            "executable_digest": self.executable_digest,
            "source_blob_ids": dict(self.source_blob_ids),
            "lock_hashes": dict(self.lock_hashes),
            "dependency_hashes": dict(self.dependency_hashes),
            "test_hashes": dict(self.test_hashes),
            "config_hashes": dict(self.config_hashes),
            "env_fingerprints": dict(self.env_fingerprints),
        }
        # Re-run validation on every public serialization path.
        type(self)(**record)
        return record

    @property
    def digest(self) -> str:
        return _digest(self.as_record())

    @property
    def identity_complete(self) -> bool:
        return all(
            bool(getattr(self, name))
            for name in (
                "source_blob_ids",
                "test_hashes",
                "config_hashes",
                "env_fingerprints",
            )
        ) and bool(self.lock_hashes or self.dependency_hashes) and bool(
            self.executable_digest
        )

    @classmethod
    def from_record(cls, value: Mapping[str, Any]) -> "ValidationCacheKey":
        required = {
            "format_version",
            "argv_digest",
            "cwd_relative",
            "executable_digest",
            "source_blob_ids",
            "lock_hashes",
            "dependency_hashes",
            "test_hashes",
            "config_hashes",
            "env_fingerprints",
        }
        if not isinstance(value, Mapping) or set(value) != required:
            raise ValidationCacheError("cache key schema is malformed")
        try:
            return cls(**dict(value))
        except (TypeError, ValueError, ValidationCacheError) as exc:
            raise ValidationCacheError("cache key identity is malformed") from exc


def make_validation_key(
    argv: Sequence[str],
    *,
    cwd_relative: str = ".",
    executable: str | os.PathLike[str] | None = None,
    executable_version: str | None = None,
    executable_digest: str | None = None,
    source_blob_ids: Mapping[str, str] | None = None,
    lock_hashes: Mapping[str, str] | None = None,
    config_hashes: Mapping[str, str] | None = None,
    dependency_hashes: Mapping[str, str] | None = None,
    test_hashes: Mapping[str, str] | None = None,
    env_allowlist: Mapping[str, Any] | Sequence[str] | None = None,
    format_version: int = CACHE_FORMAT_VERSION,
) -> ValidationCacheKey:
    """Build a cache key without retaining the ordered argv or absolute paths."""

    if type(format_version) is not int or format_version != CACHE_FORMAT_VERSION:
        raise ValidationCacheInputError("unsupported cache key format")
    if not isinstance(argv, Sequence) or isinstance(argv, (str, bytes, bytearray)):
        raise ValidationCacheInputError("argv must be an ordered sequence")
    if not argv or len(argv) > 512:
        raise ValidationCacheInputError("argv length exceeds bound")
    normalized_argv: list[str] = []
    for item in argv:
        if not isinstance(item, str) or not item or len(item) > 4096 or "\x00" in item:
            raise ValidationCacheInputError("argv contains an invalid argument")
        normalized_argv.append(item)
    argv_digest = _digest(
        {"namespace": "command_argv", "ordered_argv": normalized_argv}
    )
    cwd = _normal_relative(cwd_relative, "cwd_relative", allow_root=True)
    if executable_digest is not None and (
        executable is not None or executable_version is not None
    ):
        raise ValidationCacheInputError(
            "executable identity inputs and executable_digest are mutually exclusive"
        )
    if executable_digest is None:
        if executable is None:
            raise ValidationCacheInputError("executable or executable_digest is required")
        executable_digest = executable_identity_digest(executable, executable_version)
    else:
        executable_digest = _validate_digest(executable_digest, "executable_digest")
    source_ids = _normalize_hash_map(
        source_blob_ids, "source_blob_ids", namespace="relevant_sources"
    )
    locks = _normalize_hash_map(
        lock_hashes, "lock_hashes", namespace="dependency_lockfiles"
    )
    dependencies = _normalize_hash_map(
        dependency_hashes,
        "dependency_hashes",
        namespace="dependency_sources",
    )
    tests = _normalize_hash_map(
        test_hashes, "test_hashes", namespace="test_files"
    )
    configs = _normalize_hash_map(
        config_hashes, "config_hashes", namespace="configuration"
    )
    env = _normalize_env(env_allowlist)
    return ValidationCacheKey(
        format_version=format_version,
        argv_digest=argv_digest,
        cwd_relative=cwd,
        executable_digest=executable_digest,
        source_blob_ids=source_ids,
        lock_hashes=locks,
        config_hashes=configs,
        env_fingerprints=env,
        dependency_hashes=dependencies,
        test_hashes=tests,
    )


@dataclass(frozen=True)
class ValidationCacheEntry:
    key_digest: str
    key: dict[str, Any]
    status: str
    exit_category: str
    exit_code: int | None
    duration_ms: int | None
    deterministic: bool
    complete: bool
    created_at: int
    expires_at: int
    identity_complete: bool = False
    trust: str = UNTRUSTED_ADVISORY

    def __post_init__(self) -> None:
        key = ValidationCacheKey.from_record(self.key)
        if not isinstance(self.key_digest, str) or _validate_digest(
            self.key_digest, "cache key"
        ) != key.digest:
            raise ValidationCacheError("cache entry key digest mismatch")
        if self.status not in {
            "passed",
            "failed",
            "partial",
            "timeout",
            "timed_out",
            "cancel",
            "cancelled",
            "corrupt",
            "incomplete",
        }:
            raise ValidationCacheError("cache entry status is malformed")
        if not isinstance(self.exit_category, str) or _CATEGORY_RE.fullmatch(
            self.exit_category
        ) is None:
            raise ValidationCacheError("cache entry category is malformed")
        if self.exit_code is not None and (
            type(self.exit_code) is not int or abs(self.exit_code) > 2**31 - 1
        ):
            raise ValidationCacheError("cache entry exit code is malformed")
        if self.duration_ms is not None and (
            type(self.duration_ms) is not int
            or self.duration_ms < 0
            or self.duration_ms > 2**31 - 1
        ):
            raise ValidationCacheError("cache entry duration is malformed")
        if type(self.deterministic) is not bool or type(self.complete) is not bool:
            raise ValidationCacheError("cache entry completion flags are malformed")
        if type(self.created_at) is not int or type(self.expires_at) is not int:
            raise ValidationCacheError("cache entry timestamps are malformed")
        if (
            self.created_at < 0
            or self.expires_at < self.created_at
            or self.expires_at - self.created_at > MAX_TTL_SECONDS
        ):
            raise ValidationCacheError("cache entry timestamps are malformed")
        if type(self.identity_complete) is not bool:
            raise ValidationCacheError("cache entry identity flag is malformed")
        if self.trust != UNTRUSTED_ADVISORY:
            raise ValidationCacheError("cache entry trust semantics are malformed")
        record = key.as_record()
        for name in (
            "source_blob_ids",
            "lock_hashes",
            "dependency_hashes",
            "test_hashes",
            "config_hashes",
            "env_fingerprints",
        ):
            record[name] = MappingProxyType(dict(record[name]))
        object.__setattr__(self, "key", MappingProxyType(record))

    @property
    def reusable(self) -> bool:
        return (
            self.status == "passed"
            and self.complete
            and self.deterministic
            and self.identity_complete
            and self.exit_category == "success"
            and type(self.exit_code) is int
            and self.exit_code == 0
            and ValidationCacheKey.from_record(self.key).identity_complete
        )

    @property
    def is_failure_hint(self) -> bool:
        return (
            self.identity_complete
            and ValidationCacheKey.from_record(self.key).identity_complete
            and not self.reusable
            and self.status
            in {
                "failed",
                "partial",
                "timeout",
                "cancelled",
                "corrupt",
            }
        )

    @property
    def advisory(self) -> bool:
        return True


def _entry_from_record(key_digest: str, value: Mapping[str, Any]) -> ValidationCacheEntry:
    if not isinstance(value, Mapping):
        raise ValidationCacheError("cache entry is malformed")
    required = {
        "key",
        "status",
        "exit_category",
        "exit_code",
        "duration_ms",
        "deterministic",
        "complete",
        "created_at",
        "expires_at",
        "identity_complete",
        "trust",
    }
    if set(value) != required:
        raise ValidationCacheError("cache entry has unexpected fields")
    key = value["key"]
    if not isinstance(key, Mapping):
        raise ValidationCacheError("cache entry key is malformed")
    status = value["status"]
    if not isinstance(status, str) or status not in {
        "passed",
        "failed",
        "partial",
        "timeout",
        "timed_out",
        "cancel",
        "cancelled",
        "corrupt",
        "incomplete",
    }:
        raise ValidationCacheError("cache entry status is malformed")
    category = value["exit_category"]
    if not isinstance(category, str) or _CATEGORY_RE.fullmatch(category) is None:
        raise ValidationCacheError("cache entry category is malformed")
    exit_code = value["exit_code"]
    if exit_code is not None and (type(exit_code) is not int or abs(exit_code) > 2**31 - 1):
        raise ValidationCacheError("cache entry exit code is malformed")
    duration = value["duration_ms"]
    if duration is not None and (type(duration) is not int or duration < 0 or duration > 2**31 - 1):
        raise ValidationCacheError("cache entry duration is malformed")
    if type(value["deterministic"]) is not bool or type(value["complete"]) is not bool:
        raise ValidationCacheError("cache entry completion flags are malformed")
    created = value["created_at"]
    expires = value["expires_at"]
    if (
        type(created) is not int
        or type(expires) is not int
        or created < 0
        or expires < created
        or expires - created > MAX_TTL_SECONDS
    ):
        raise ValidationCacheError("cache entry timestamps are malformed")
    identity_complete = value["identity_complete"]
    trust = value["trust"]
    if type(identity_complete) is not bool or trust != UNTRUSTED_ADVISORY:
        raise ValidationCacheError("cache entry trust/identity metadata is malformed")
    return ValidationCacheEntry(
        key_digest=_validate_digest(key_digest, "cache key"),
        key=key,
        status=status,
        exit_category=category,
        exit_code=exit_code,
        duration_ms=duration,
        deterministic=value["deterministic"],
        complete=value["complete"],
        created_at=created,
        expires_at=expires,
        identity_complete=identity_complete,
        trust=trust,
    )


class ValidationCache:
    """Bounded JSON cache with safe-state atomic/concurrent updates."""

    def __init__(
        self,
        repo_root: os.PathLike[str] | str,
        path: os.PathLike[str] | str | None = None,
        *,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        max_entries: int = MAX_ENTRIES,
    ) -> None:
        self.repo_root = os.path.abspath(os.fspath(repo_root))
        self.target = path if path is not None else os.path.join(".codex-state", "validation-cache.json")
        self.ttl_seconds = _exact_bounded_int(
            ttl_seconds,
            "ttl_seconds",
            minimum=1,
            maximum=MAX_TTL_SECONDS,
        )
        self.max_entries = _exact_bounded_int(
            max_entries,
            "max_entries",
            minimum=1,
            maximum=4096,
        )
        self.cache_path = resolve_state_path(self.repo_root, self.target, create_parents=True)

    def _empty(self) -> dict[str, Any]:
        return {"format_version": CACHE_FORMAT_VERSION, "entries": {}}

    def _load(self) -> dict[str, Any]:
        value = read_json(
            self.repo_root,
            self.target,
            default=self._empty(),
            max_bytes=MAX_CACHE_BYTES,
            max_depth=12,
            max_items=self.max_entries * 32,
            quarantine_corrupt=True,
        )
        if not isinstance(value, Mapping) or set(value) != {"format_version", "entries"}:
            # Treat malformed state as empty.  The next valid write replaces it.
            with contextlib.suppress(Exception):
                quarantine_file(self.repo_root, self.target, suffix="cache-schema")
            return self._empty()
        if (
            type(value["format_version"]) is not int
            or value["format_version"] != CACHE_FORMAT_VERSION
            or not isinstance(value["entries"], Mapping)
        ):
            with contextlib.suppress(Exception):
                quarantine_file(self.repo_root, self.target, suffix="cache-schema")
            return self._empty()
        entries: dict[str, Any] = {}
        invalid_seen = False
        now_value = self._now(None)
        for raw_digest, raw_entry in value["entries"].items():
            try:
                key_digest = _validate_digest(raw_digest, "cache key")
                if not isinstance(raw_entry, Mapping):
                    raise ValidationCacheError("cache entry is malformed")
                parsed = _entry_from_record(key_digest, raw_entry)
            except ValidationCacheError:
                invalid_seen = True
                continue
            if parsed.key_digest != key_digest:
                invalid_seen = True
                continue
            if parsed.created_at > now_value + MAX_FUTURE_SKEW_SECONDS:
                invalid_seen = True
                continue
            entries[key_digest] = dict(raw_entry)
            if len(entries) >= self.max_entries:
                break
        if invalid_seen:
            with contextlib.suppress(Exception):
                quarantine_file(self.repo_root, self.target, suffix="cache-entry")
            return self._empty()
        return {"format_version": CACHE_FORMAT_VERSION, "entries": entries}

    @staticmethod
    def _now(now: int | float | None) -> int:
        if now is None:
            value = int(time.time())
        else:
            if type(now) is not int:
                raise ValidationCacheInputError("time must be an integer")
            value = now
        if value < 0:
            raise ValidationCacheInputError("time cannot be negative")
        return value

    def _key_record(self, key: ValidationCacheKey) -> dict[str, Any]:
        if not isinstance(key, ValidationCacheKey):
            raise ValidationCacheInputError("key must be ValidationCacheKey")
        try:
            return key.as_record()
        except (TypeError, ValueError, ValidationCacheError) as exc:
            raise ValidationCacheInputError("key identity is malformed") from exc

    def record_result(
        self,
        key: ValidationCacheKey,
        *,
        status: str,
        exit_category: str,
        exit_code: int | None = None,
        duration_seconds: float | int | None = None,
        deterministic: bool = False,
        complete: bool = False,
        ttl_seconds: int | None = None,
        now: int | float | None = None,
        output: Any = None,
        stdout: Any = None,
        stderr: Any = None,
        command: Any = None,
        source: Any = None,
        **forbidden: Any,
    ) -> ValidationCacheEntry:
        """Store only bounded result metadata; raw fields are rejected."""

        # Validate every argument before reading or mutating the cache file.
        key_record = self._key_record(key)
        if output is not None or stdout is not None or stderr is not None or command is not None or source is not None or forbidden:
            raise ValidationCacheInputError("raw command/output/source fields are forbidden")
        if not isinstance(status, str):
            raise ValidationCacheInputError("invalid status")
        normalized = status.lower()
        if normalized in _PASS:
            normalized = "passed"
        elif normalized in _FAIL:
            normalized = "failed"
        elif normalized not in _NON_REUSABLE:
            raise ValidationCacheInputError("unsupported validation status")
        elif normalized == "timed_out":
            normalized = "timeout"
        elif normalized == "cancel":
            normalized = "cancelled"
        if not isinstance(exit_category, str) or _CATEGORY_RE.fullmatch(exit_category) is None:
            raise ValidationCacheInputError("invalid exit category")
        if exit_code is not None and (type(exit_code) is not int or abs(exit_code) > 2**31 - 1):
            raise ValidationCacheInputError("invalid exit code")
        if duration_seconds is None:
            duration_ms = None
        else:
            if isinstance(duration_seconds, bool) or not isinstance(duration_seconds, (int, float)) or not math.isfinite(float(duration_seconds)):
                raise ValidationCacheInputError("invalid duration")
            if duration_seconds < 0 or duration_seconds > 2**31 / 1000:
                raise ValidationCacheInputError("duration exceeds bound")
            duration_ms = int(round(float(duration_seconds) * 1000))
        if type(deterministic) is not bool or type(complete) is not bool:
            raise ValidationCacheInputError("completion flags must be boolean")
        ttl = (
            self.ttl_seconds
            if ttl_seconds is None
            else _exact_bounded_int(
                ttl_seconds,
                "ttl_seconds",
                minimum=1,
                maximum=MAX_TTL_SECONDS,
            )
        )
        created = self._now(now)
        key_digest = key.digest
        raw_entry = {
            "key": key_record,
            "status": normalized,
            "exit_category": exit_category,
            "exit_code": exit_code,
            "duration_ms": duration_ms,
            "deterministic": deterministic,
            "complete": complete,
            "created_at": created,
            "expires_at": created + ttl,
            "identity_complete": key.identity_complete,
            "trust": UNTRUSTED_ADVISORY,
        }
        # Parse the constructed entry before touching disk.
        entry = _entry_from_record(key_digest, raw_entry)

        def update(current: Any) -> dict[str, Any]:
            if not isinstance(current, Mapping) or current.get("format_version") != CACHE_FORMAT_VERSION or not isinstance(current.get("entries"), Mapping):
                current = self._empty()
            entries = dict(current["entries"])
            entries[key_digest] = raw_entry
            # Remove expired entries first, then retain newest records.
            now_value = created
            fresh: list[tuple[str, Mapping[str, Any]]] = []
            for digest, candidate in entries.items():
                try:
                    parsed = _entry_from_record(str(digest), candidate)
                except ValidationCacheError:
                    continue
                if parsed.expires_at >= now_value:
                    fresh.append((str(digest), candidate))
            fresh.sort(key=lambda item: int(item[1]["created_at"]), reverse=True)
            return {
                "format_version": CACHE_FORMAT_VERSION,
                "entries": {digest: candidate for digest, candidate in fresh[: self.max_entries]},
            }

        update_json(
            self.repo_root,
            self.target,
            update,
            default=self._empty(),
            max_bytes=MAX_CACHE_BYTES,
            max_depth=12,
            max_items=self.max_entries * 32,
            quarantine_corrupt=True,
        )
        return entry

    put = record_result
    record = record_result

    def _entry_for(self, key: ValidationCacheKey, *, now: int | float | None = None) -> ValidationCacheEntry | None:
        if not isinstance(key, ValidationCacheKey):
            raise ValidationCacheInputError("key must be ValidationCacheKey")
        self._key_record(key)
        now_value = self._now(now)
        key_digest = key.digest
        state = self._load()
        raw = state["entries"].get(key_digest)
        if not isinstance(raw, Mapping):
            return None
        try:
            entry = _entry_from_record(key_digest, raw)
        except ValidationCacheError:
            return None
        if entry.expires_at < now_value:
            return None
        if entry.created_at > now_value + MAX_FUTURE_SKEW_SECONDS:
            return None
        # Recompute key digest from the persisted key; a forged map must not hit.
        entry_key_record = ValidationCacheKey.from_record(entry.key).as_record()
        if _digest(entry_key_record) != key_digest or entry_key_record != key.as_record():
            return None
        return entry

    def lookup(
        self,
        key: ValidationCacheKey,
        *,
        purpose: str = "ordinary",
        now: int | float | None = None,
        advisory: bool = False,
    ) -> ValidationCacheEntry | None:
        self._key_record(key)
        self._now(now)
        if purpose not in _ALLOWED_PURPOSES:
            raise ValidationCacheInputError("invalid validation purpose")
        if type(advisory) is not bool:
            raise ValidationCacheInputError("advisory mode must be boolean")
        if purpose == "advisory":
            advisory = True
        if purpose not in {"ordinary", "advisory"} or not advisory:
            return None
        entry = self._entry_for(key, now=now)
        return entry if entry is not None and entry.reusable else None

    get = lookup
    reusable = lookup

    def lookup_advisory(
        self,
        key: ValidationCacheKey,
        *,
        now: int | None = None,
    ) -> ValidationCacheEntry | None:
        return self.lookup(key, purpose="ordinary", now=now, advisory=True)

    def failure_hint(
        self,
        key: ValidationCacheKey,
        *,
        purpose: str = "ordinary",
        now: int | float | None = None,
        advisory: bool = False,
    ) -> ValidationCacheEntry | None:
        self._key_record(key)
        self._now(now)
        if purpose not in _ALLOWED_PURPOSES:
            raise ValidationCacheInputError("invalid validation purpose")
        if type(advisory) is not bool:
            raise ValidationCacheInputError("advisory mode must be boolean")
        if purpose == "advisory":
            advisory = True
        if purpose not in {"ordinary", "advisory"} or not advisory:
            return None
        entry = self._entry_for(key, now=now)
        return entry if entry is not None and entry.is_failure_hint else None

    get_failure_hint = failure_hint

    def clear_expired(self, *, now: int | float | None = None) -> int:
        now_value = self._now(now)
        removed = 0

        def update(current: Any) -> Any:
            nonlocal removed
            if not isinstance(current, Mapping) or not isinstance(current.get("entries"), Mapping):
                return self._empty()
            entries: dict[str, Any] = {}
            for digest, raw in current["entries"].items():
                try:
                    entry = _entry_from_record(str(digest), raw)
                except ValidationCacheError:
                    removed += 1
                    continue
                if entry.expires_at < now_value:
                    removed += 1
                else:
                    entries[str(digest)] = raw
            return {"format_version": CACHE_FORMAT_VERSION, "entries": entries}

        update_json(
            self.repo_root,
            self.target,
            update,
            default=self._empty(),
            max_bytes=MAX_CACHE_BYTES,
            max_depth=12,
            max_items=self.max_entries * 32,
            quarantine_corrupt=True,
        )
        return removed


build_cache_key = make_validation_key
ValidationKey = ValidationCacheKey
cache_key = make_validation_key
ValidationResultCache = ValidationCache


__all__ = [
    "CACHE_FORMAT_VERSION",
    "DEFAULT_TTL_SECONDS",
    "MAX_CACHE_BYTES",
    "MAX_EXECUTABLE_BYTES",
    "MAX_FUTURE_SKEW_SECONDS",
    "MAX_TTL_SECONDS",
    "UNTRUSTED_ADVISORY",
    "ValidationCache",
    "ValidationCacheEntry",
    "ValidationCacheError",
    "ValidationCacheInputError",
    "ValidationCacheKey",
    "ValidationKey",
    "ValidationResultCache",
    "build_cache_key",
    "cache_key",
    "executable_identity_digest",
    "make_validation_key",
]
