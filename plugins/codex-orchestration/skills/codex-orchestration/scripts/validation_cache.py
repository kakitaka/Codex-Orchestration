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
from dataclasses import dataclass
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


CACHE_FORMAT_VERSION = 1
DEFAULT_TTL_SECONDS = 24 * 60 * 60
MAX_ENTRIES = 512
MAX_CACHE_BYTES = 2 * 1024 * 1024
_DIGEST_RE = r"^[0-9a-fA-F]{16,128}$"
_ALLOWED_PURPOSES = frozenset({"ordinary", "final", "security", "fresh"})
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


def _normalize_hash_map(value: Mapping[str, str] | None, field: str) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValidationCacheInputError(f"{field} must be a mapping")
    if len(value) > 2048:
        raise ValidationCacheInputError(f"{field} exceeds bound")
    result: dict[str, str] = {}
    for raw_name, raw_digest in value.items():
        name = _normal_relative(raw_name, f"{field} name")
        result[name] = _validate_digest(raw_digest, f"{field} value")
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
        result[raw_name] = _digest([raw_name, raw_value])
    return dict(sorted(result.items()))


def executable_identity_digest(executable: str | os.PathLike[str], version: str | None = None) -> str:
    """Digest resolved executable identity and optional version without storing its path."""

    if not isinstance(executable, (str, os.PathLike)):
        raise ValidationCacheInputError("invalid executable")
    raw = os.fspath(executable)
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        raise ValidationCacheInputError("invalid executable")
    resolved = shutil.which(raw) if not os.path.isabs(raw) else raw
    if resolved is None:
        raise ValidationCacheInputError("executable cannot be resolved")
    if os.path.islink(resolved):
        raise ValidationCacheInputError("executable symlink is not accepted")
    try:
        details = os.stat(resolved, follow_symlinks=False)
    except OSError as exc:
        raise ValidationCacheInputError("executable cannot be inspected") from exc
    version_text = "" if version is None else version
    if not isinstance(version_text, str) or len(version_text) > 512 or "\x00" in version_text:
        raise ValidationCacheInputError("invalid executable version")
    identity = {
        "basename": os.path.basename(resolved).lower(),
        "mode": stat.S_IMODE(details.st_mode),
        "size": int(details.st_size),
        "mtime_ns": int(details.st_mtime_ns),
        "version": version_text,
    }
    return _digest(identity)


@dataclass(frozen=True)
class ValidationCacheKey:
    format_version: int
    argv_digest: str
    cwd_relative: str
    executable_digest: str
    source_blob_ids: dict[str, str]
    lock_hashes: dict[str, str]
    config_hashes: dict[str, str]
    env_fingerprints: dict[str, str]

    def as_record(self) -> dict[str, Any]:
        return {
            "format_version": self.format_version,
            "argv_digest": self.argv_digest,
            "cwd_relative": self.cwd_relative,
            "executable_digest": self.executable_digest,
            "source_blob_ids": self.source_blob_ids,
            "lock_hashes": self.lock_hashes,
            "config_hashes": self.config_hashes,
            "env_fingerprints": self.env_fingerprints,
        }

    @property
    def digest(self) -> str:
        return _digest(self.as_record())


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
    argv_digest = _digest({"ordered_argv": normalized_argv})
    cwd = _normal_relative(cwd_relative, "cwd_relative", allow_root=True)
    if executable_digest is None:
        if executable is None:
            raise ValidationCacheInputError("executable or executable_digest is required")
        executable_digest = executable_identity_digest(executable, executable_version)
    else:
        executable_digest = _validate_digest(executable_digest, "executable_digest")
    source_ids = _normalize_hash_map(source_blob_ids, "source_blob_ids")
    locks = _normalize_hash_map(lock_hashes, "lock_hashes")
    if dependency_hashes:
        locks.update(_normalize_hash_map(dependency_hashes, "dependency_hashes"))
        locks = dict(sorted(locks.items()))
    configs = _normalize_hash_map(config_hashes, "config_hashes")
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

    @property
    def reusable(self) -> bool:
        return (
            self.status == "passed"
            and self.complete
            and self.deterministic
            and self.exit_category == "success"
            and (self.exit_code in {None, 0})
            and bool(self.key.get("source_blob_ids"))
        )

    @property
    def is_failure_hint(self) -> bool:
        return bool(self.key.get("source_blob_ids")) and not self.reusable and self.status in {
            "failed",
            "partial",
            "timeout",
            "cancelled",
            "corrupt",
        }


def _entry_from_record(key_digest: str, value: Mapping[str, Any]) -> ValidationCacheEntry:
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
    }
    if set(value) != required:
        raise ValidationCacheError("cache entry has unexpected fields")
    key = value["key"]
    if not isinstance(key, Mapping):
        raise ValidationCacheError("cache entry key is malformed")
    status = value["status"]
    if not isinstance(status, str) or status not in _PASS | _FAIL | _NON_REUSABLE:
        raise ValidationCacheError("cache entry status is malformed")
    status = "passed" if status in _PASS else "failed" if status in _FAIL else status
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
    if type(created) is not int or type(expires) is not int or created < 0 or expires < created:
        raise ValidationCacheError("cache entry timestamps are malformed")
    return ValidationCacheEntry(
        key_digest=key_digest,
        key=dict(key),
        status=status,
        exit_category=category,
        exit_code=exit_code,
        duration_ms=duration,
        deterministic=value["deterministic"],
        complete=value["complete"],
        created_at=created,
        expires_at=expires,
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
        self.cache_path = resolve_state_path(self.repo_root, self.target, create_parents=True)
        self.ttl_seconds = int(ttl_seconds)
        self.max_entries = int(max_entries)
        if self.ttl_seconds <= 0 or self.max_entries <= 0 or self.max_entries > 4096:
            raise ValueError("invalid cache bounds")

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
        if value["format_version"] != CACHE_FORMAT_VERSION or not isinstance(value["entries"], Mapping):
            with contextlib.suppress(Exception):
                quarantine_file(self.repo_root, self.target, suffix="cache-schema")
            return self._empty()
        entries: dict[str, Any] = {}
        for raw_digest, raw_entry in value["entries"].items():
            try:
                key_digest = _validate_digest(raw_digest, "cache key")
                if not isinstance(raw_entry, Mapping):
                    continue
                parsed = _entry_from_record(key_digest, raw_entry)
            except ValidationCacheError:
                continue
            if parsed.key_digest != key_digest:
                continue
            entries[key_digest] = dict(raw_entry)
            if len(entries) >= self.max_entries:
                break
        return {"format_version": CACHE_FORMAT_VERSION, "entries": entries}

    @staticmethod
    def _now(now: int | float | None) -> int:
        value = int(time.time() if now is None else now)
        if value < 0:
            raise ValueError("time cannot be negative")
        return value

    def _key_record(self, key: ValidationCacheKey) -> dict[str, Any]:
        if not isinstance(key, ValidationCacheKey):
            raise ValidationCacheInputError("key must be ValidationCacheKey")
        return key.as_record()

    def record_result(
        self,
        key: ValidationCacheKey,
        *,
        status: str,
        exit_category: str,
        exit_code: int | None = None,
        duration_seconds: float | int | None = None,
        deterministic: bool = True,
        complete: bool = True,
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
        ttl = self.ttl_seconds if ttl_seconds is None else int(ttl_seconds)
        if ttl <= 0 or ttl > 365 * 24 * 60 * 60:
            raise ValidationCacheInputError("invalid TTL")
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
        key_digest = key.digest
        state = self._load()
        raw = state["entries"].get(key_digest)
        if not isinstance(raw, Mapping):
            return None
        try:
            entry = _entry_from_record(key_digest, raw)
        except ValidationCacheError:
            return None
        if entry.expires_at < self._now(now):
            return None
        # Recompute key digest from the persisted key; a forged map must not hit.
        if _digest(entry.key) != key_digest or entry.key != key.as_record():
            return None
        return entry

    def lookup(
        self,
        key: ValidationCacheKey,
        *,
        purpose: str = "ordinary",
        now: int | float | None = None,
    ) -> ValidationCacheEntry | None:
        if purpose not in _ALLOWED_PURPOSES:
            raise ValidationCacheInputError("invalid validation purpose")
        if purpose != "ordinary":
            return None
        entry = self._entry_for(key, now=now)
        return entry if entry is not None and entry.reusable else None

    get = lookup
    reusable = lookup

    def failure_hint(
        self,
        key: ValidationCacheKey,
        *,
        purpose: str = "ordinary",
        now: int | float | None = None,
    ) -> ValidationCacheEntry | None:
        if purpose not in _ALLOWED_PURPOSES:
            raise ValidationCacheInputError("invalid validation purpose")
        if purpose != "ordinary":
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
