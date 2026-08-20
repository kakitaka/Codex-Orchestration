"""Privacy-separated session telemetry and aggregate export.

The lane manager in this file is intentionally independent from telemetry
storage.  Lane state contains only normalized routing context and an opaque
HMAC lane ID; telemetry contains only the exact usage allowlist below.  Raw
conversation, source, command, path, and authentication values are rejected
before a telemetry file is read or changed.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import math
import ntpath
import os
import re
import secrets
import threading
import time
from typing import Any, Mapping, Sequence

try:
    from .safe_state import (
        StateCorruptError,
        UnsafePathError,
        atomic_write_bytes,
        normalize_relative_path,
        quarantine_file,
        read_bytes,
        resolve_state_path,
    )
    from .safe_state import _ancestor_snapshot  # type: ignore
    from .safe_state import _file_lock as _state_file_lock  # type: ignore
except ImportError:  # type: ignore
    from safe_state import (  # type: ignore
        StateCorruptError,
        UnsafePathError,
        atomic_write_bytes,
        normalize_relative_path,
        quarantine_file,
        read_bytes,
        resolve_state_path,
    )
    from safe_state import _ancestor_snapshot  # type: ignore
    from safe_state import _file_lock as _state_file_lock  # type: ignore


LANE_FORMAT_VERSION = 1
TELEMETRY_FORMAT_VERSION = 1
DEFAULT_TELEMETRY_PATH = os.path.join(".codex-state", "usage", "usage.jsonl")
DEFAULT_LANES_PATH = os.path.join(".codex-state", "session-lanes.json")
DEFAULT_LANE_KEY_PATH = os.path.join(".codex-state", ".session-lane-key")
MAX_TELEMETRY_EVENTS = 512
MAX_TELEMETRY_BYTES = 2 * 1024 * 1024
MAX_LANES = 128
MAX_LANE_BYTES = 256 * 1024
MAX_RESUME_EXPIRY = 2**63 - 1
_DIGEST_RE = re.compile(r"^[0-9a-fA-F]{16,128}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+/@-]{0,127}$")
_SENSITIVE_VALUE_RE = re.compile(
    r"(?i)(?:\b(?:sk|rk)-[A-Za-z0-9_-]{16,}\b|\bgh[pousr]_[A-Za-z0-9_]{20,}\b|"
    r"\bBearer\s+[A-Za-z0-9._~+/=-]{12,})"
)
_EXTRA_SENSITIVE_VALUE_RE = re.compile(
    r"(?i)(?:\bgithub_pat_[A-Za-z0-9_-]{12,}\b|\bAKIA[0-9A-Z]{16}\b|"
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----)"
)
_EFFORTS = frozenset({"minimal", "low", "medium", "high", "xhigh", "max", "ultra"})
_SANDBOXES = frozenset({"read-only", "workspace-write", "danger-full-access", "none", "default"})
_TELEMETRY_FIELDS = frozenset(
    {
        "format_version",
        "input_tokens",
        "cached_input_tokens",
        "uncached_input_tokens",
        "output_tokens",
        "reasoning_output_tokens",
        "cache_hit_ratio",
        "agent_count",
        "model",
        "model_approved_identifier",
        "reasoning_effort",
        "tool_call_count",
        "repeated_read_count",
        "duplicate_packet_count",
        "validation_cache_hit_count",
        "failure_cache_hit_count",
        "task_packet_digest",
        "git_blob_ids",
    }
)
_COUNT_FIELDS = frozenset(
    {
        "input_tokens",
        "cached_input_tokens",
        "uncached_input_tokens",
        "output_tokens",
        "reasoning_output_tokens",
        "agent_count",
        "tool_call_count",
        "repeated_read_count",
        "duplicate_packet_count",
        "validation_cache_hit_count",
        "failure_cache_hit_count",
    }
)
_LANE_IDENTITY_FIELDS = frozenset(
    {
        "repo_relative",
        "worktree_relative",
        "branch",
        "model",
        "effort",
        "cwd_relative",
        "sandbox",
        "approval",
        "tool_profile",
    }
)
_LANE_FIELDS = _LANE_IDENTITY_FIELDS | {
    "lane_id",
    "resume_tag",
    "resume_expires_at",
    "resume_task_packet_hash",
}
_RESUME_FIELDS = (
    "resume_tag",
    "resume_expires_at",
    "resume_task_packet_hash",
)
_LANE_FORBIDDEN_NAMES = frozenset(
    {
        "prompt",
        "conversation",
        "source",
        "output",
        "log",
        "auth",
        "token",
        "secret",
        "absolute_path",
        "repo_root",
        "cwd_absolute",
    }
)


class TelemetryError(ValueError):
    """Invalid, unknown, or privacy-sensitive telemetry input."""


class LaneError(ValueError):
    """Invalid or corrupt local session lane state."""


class LaneCapabilityError(LaneError):
    """A resume request did not carry the capability bound to the lane ID."""


_LOCAL_LOCK_GUARD = threading.RLock()
_LOCAL_LOCKS: dict[str, threading.RLock] = {}


def _local_lock(path: str) -> threading.RLock:
    with _LOCAL_LOCK_GUARD:
        return _LOCAL_LOCKS.setdefault(path, threading.RLock())


def _digest(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _require_digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise TelemetryError(f"invalid {field}")
    return value.lower()


def _is_sensitive(value: str) -> bool:
    return bool(
        _SENSITIVE_VALUE_RE.search(value)
        or _EXTRA_SENSITIVE_VALUE_RE.search(value)
    )


def _bounded_mapping_keys(value: Mapping[Any, Any], *, limit: int, error: str) -> list[Any]:
    keys: list[Any] = []
    for index, key in enumerate(value):
        if index >= limit:
            raise TelemetryError(error)
        keys.append(key)
    return keys


def _count(value: Any, field: str) -> int | None:
    if value is None:
        return None
    if type(value) is not int or value < 0 or value > 10**12:
        raise TelemetryError(f"invalid {field}")
    return value


def validate_telemetry_event(event: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the exact allowlist and return canonical event fields.

    This function is pure.  Callers can therefore reject a forbidden field
    before opening a state file, which is important for privacy tests.
    """

    if not isinstance(event, Mapping):
        raise TelemetryError("telemetry event must be an object")
    keys = _bounded_mapping_keys(
        event,
        limit=len(_TELEMETRY_FIELDS) + 1,
        error="telemetry event has too many fields",
    )
    unknown = set(keys) - _TELEMETRY_FIELDS
    if unknown:
        raise TelemetryError("unknown/forbidden telemetry fields")
    result: dict[str, Any] = {}
    version = event.get("format_version", TELEMETRY_FORMAT_VERSION)
    if type(version) is not int or version != TELEMETRY_FORMAT_VERSION:
        raise TelemetryError("unsupported telemetry format")
    result["format_version"] = version
    for field in _COUNT_FIELDS:
        if field in event:
            result[field] = _count(event[field], field)
    input_tokens = result.get("input_tokens")
    cached_tokens = result.get("cached_input_tokens")
    if input_tokens is not None and cached_tokens is not None:
        if cached_tokens > input_tokens:
            raise TelemetryError("cached input exceeds input")
        derived = input_tokens - cached_tokens
        if "uncached_input_tokens" in event and event["uncached_input_tokens"] not in {None, derived}:
            raise TelemetryError("uncached input does not match usage")
        result["uncached_input_tokens"] = derived
    elif "uncached_input_tokens" in event:
        result["uncached_input_tokens"] = _count(
            event["uncached_input_tokens"], "uncached_input_tokens"
        )
    supplied_ratio = event.get("cache_hit_ratio")
    if "cache_hit_ratio" in event and supplied_ratio is not None:
        if (
            isinstance(supplied_ratio, bool)
            or not isinstance(supplied_ratio, (int, float))
            or not math.isfinite(float(supplied_ratio))
            or supplied_ratio < 0
            or supplied_ratio > 1
        ):
            raise TelemetryError("invalid cache_hit_ratio")
        if input_tokens is None or cached_tokens is None or input_tokens == 0:
            raise TelemetryError("cache_hit_ratio requires paired nonzero usage counters")
    if input_tokens is not None and cached_tokens is not None:
        derived_ratio = None if input_tokens == 0 else cached_tokens / input_tokens
        if supplied_ratio is not None and abs(float(supplied_ratio) - derived_ratio) > 1e-12:
            raise TelemetryError("cache_hit_ratio does not match usage")
        result["cache_hit_ratio"] = derived_ratio
    elif "cache_hit_ratio" in event:
        # A null value is an explicit NOT_MEASURED marker.  Non-null values
        # without paired counters were rejected above.
        result["cache_hit_ratio"] = None
    for source_field in ("model", "model_approved_identifier"):
        if source_field in event:
            value = event[source_field]
            if value is None:
                continue
            if not isinstance(value, str) or _IDENTIFIER_RE.fullmatch(value) is None:
                raise TelemetryError("invalid approved model identifier")
            if _is_sensitive(value):
                raise TelemetryError("sensitive model identifier is forbidden")
            if os.path.isabs(value) or ntpath.isabs(value) or ntpath.splitdrive(value)[0]:
                raise TelemetryError("absolute model path is forbidden")
            if "model" in result and result["model"] != value:
                raise TelemetryError("conflicting model identifiers")
            result["model"] = value
    if "reasoning_effort" in event:
        effort = event["reasoning_effort"]
        if effort is not None and (not isinstance(effort, str) or effort not in _EFFORTS):
            raise TelemetryError("invalid reasoning effort")
        result["reasoning_effort"] = effort
    if "task_packet_digest" in event:
        digest = event["task_packet_digest"]
        result["task_packet_digest"] = None if digest is None else _require_digest(digest, "task_packet_digest")
    if "git_blob_ids" in event:
        blob_ids = event["git_blob_ids"]
        if blob_ids is None:
            result["git_blob_ids"] = None
        elif not isinstance(blob_ids, Sequence) or isinstance(blob_ids, (str, bytes, bytearray)):
            # A mapping would retain repository paths, which telemetry must not contain.
            raise TelemetryError("git_blob_ids must be a path-free sequence")
        else:
            if len(blob_ids) > 2048:
                raise TelemetryError("too many git blob IDs")
            normalized = sorted({_require_digest(item, "git_blob_id") for item in blob_ids})
            result["git_blob_ids"] = normalized
    # Keep canonical field order stable and preserve null only when supplied.
    return {key: result[key] for key in _TELEMETRY_FIELDS if key in result}


def serialize_event(event: Mapping[str, Any]) -> bytes:
    """Serialize one validated event as a single bounded JSON line."""

    normalized = validate_telemetry_event(event)
    encoded = json.dumps(normalized, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    if len(encoded) > 32 * 1024:
        raise TelemetryError("telemetry event exceeds bound")
    return encoded


def _normalize_rel(value: Any, field: str, *, root_allowed: bool = False) -> str:
    if not isinstance(value, str) or "\x00" in value:
        raise LaneError(f"invalid {field}")
    if root_allowed and value in {"", "."}:
        return "."
    try:
        return normalize_relative_path(value)
    except UnsafePathError as exc:
        raise LaneError(f"invalid {field}") from exc


def _lane_string(value: Any, field: str, *, max_length: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > max_length or "\x00" in value or "\r" in value or "\n" in value:
        raise LaneError(f"invalid {field}")
    if _is_sensitive(value):
        raise LaneError(f"sensitive {field} is forbidden")
    if field in _LANE_FORBIDDEN_NAMES:
        raise LaneError(f"forbidden lane field: {field}")
    # Branch/profile labels are identifiers, never filesystem paths.  This
    # also prevents a caller from smuggling a repository root into lane JSON.
    if os.path.isabs(value) or ntpath.isabs(value) or ntpath.splitdrive(value)[0]:
        raise LaneError(f"absolute {field} is forbidden")
    if any(part in {"", ".", ".."} for part in value.replace("\\", "/").split("/")):
        if field in {"branch", "approval", "tool_profile", "model"}:
            raise LaneError(f"path-like {field} is forbidden")
    if field in {"model", "approval", "tool_profile"} and _IDENTIFIER_RE.fullmatch(value) is None:
        raise LaneError(f"invalid {field}")
    return value


def _normalize_lane_context(context: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(context, Mapping):
        raise LaneError("lane context must be an object")
    keys: list[Any] = []
    for index, key in enumerate(context):
        if index >= len(_LANE_IDENTITY_FIELDS) + 1:
            raise LaneError("lane context has too many fields")
        keys.append(key)
    if set(keys) != _LANE_IDENTITY_FIELDS:
        raise LaneError("lane context must contain the exact identity fields")
    effort = context["effort"]
    sandbox = context["sandbox"]
    if not isinstance(effort, str) or effort not in _EFFORTS:
        raise LaneError("invalid reasoning effort")
    if not isinstance(sandbox, str) or sandbox not in _SANDBOXES:
        raise LaneError("invalid sandbox")
    result: dict[str, Any] = {
        "repo_relative": _normalize_rel(context["repo_relative"], "repo_relative", root_allowed=True),
        "worktree_relative": _normalize_rel(context["worktree_relative"], "worktree_relative", root_allowed=True),
        "branch": _lane_string(context["branch"], "branch"),
        "model": _lane_string(context["model"], "model"),
        "effort": effort,
        "cwd_relative": _normalize_rel(context["cwd_relative"], "cwd_relative", root_allowed=True),
        "sandbox": sandbox,
        "approval": _lane_string(context["approval"], "approval"),
        "tool_profile": _lane_string(context["tool_profile"], "tool_profile"),
    }
    return result


def _capability_tag(key: bytes, capability: str | None) -> str:
    if capability is None:
        raw = b""
    elif isinstance(capability, str) and capability and len(capability) <= 4096 and "\x00" not in capability:
        raw = capability.encode("utf-8", "strict")
    else:
        raise LaneCapabilityError("invalid caller capability")
    return hmac.new(key, b"capability\0" + raw, hashlib.sha256).hexdigest()


def _lane_id(
    key: bytes,
    context: Mapping[str, Any],
    capability: str | None,
    repo_scope: bytes,
) -> str:
    canonical = json.dumps(dict(context), ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    tag = _capability_tag(key, capability).encode("ascii")
    return "lane-v1-" + hmac.new(
        key,
        b"lane\0" + repo_scope + b"\0" + canonical + b"\0" + tag,
        hashlib.sha256,
    ).hexdigest()


def _task_packet_hash(value: Any) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-fA-F]{64}", value) is None:
        raise LaneCapabilityError("invalid task packet hash")
    return value.lower()


def _resume_tag(
    key: bytes,
    capability: str,
    lane_id: str,
    resume_id: str,
    task_packet_hash: str,
    context: Mapping[str, Any],
    expires_at: int,
) -> str:
    if (
        not isinstance(capability, str)
        or not capability
        or len(capability) > 4096
        or "\x00" in capability
        or type(expires_at) is not int
        or expires_at <= 0
        or expires_at > MAX_RESUME_EXPIRY
    ):
        raise LaneCapabilityError("invalid caller capability")
    exact_context = {
        field: context[field]
        for field in (
            "model",
            "effort",
            "cwd_relative",
            "sandbox",
            "tool_profile",
        )
    }
    canonical = json.dumps(
        {
            "lane_id": lane_id,
            "resume_id": resume_id,
            "task_packet_hash": task_packet_hash,
            "context": exact_context,
            "expires_at": expires_at,
        },
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    capability_key = hmac.new(
        key,
        b"resume-capability\0" + capability.encode("utf-8", "strict"),
        hashlib.sha256,
    ).digest()
    return "resume-v1-" + hmac.new(
        capability_key,
        b"resume\0" + canonical,
        hashlib.sha256,
    ).hexdigest()


def _validate_lane_record(record: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(record, Mapping) or set(record) - _LANE_FIELDS:
        raise LaneError("malformed lane record")
    required = {
        "lane_id",
        "repo_relative",
        "worktree_relative",
        "branch",
        "model",
        "effort",
        "cwd_relative",
        "sandbox",
        "approval",
        "tool_profile",
    }
    if not required <= set(record):
        raise LaneError("lane record is incomplete")
    lane_id = record["lane_id"]
    if not isinstance(lane_id, str) or not re.fullmatch(r"lane-v1-[0-9a-f]{64}", lane_id):
        raise LaneError("invalid lane ID")
    context = _normalize_lane_context({key: record[key] for key in _LANE_IDENTITY_FIELDS})
    result = {"lane_id": lane_id, **context}
    resume_fields = {
        "resume_tag",
        "resume_expires_at",
        "resume_task_packet_hash",
    }
    present_resume = resume_fields & set(record)
    if present_resume and present_resume != resume_fields:
        raise LaneError("resume tag record is incomplete")
    if present_resume:
        tag = record["resume_tag"]
        expiry = record["resume_expires_at"]
        task_hash = record["resume_task_packet_hash"]
        if (
            not isinstance(tag, str)
            or re.fullmatch(r"resume-v1-[0-9a-f]{64}", tag) is None
            or type(expiry) is not int
            or expiry <= 0
            or expiry > MAX_RESUME_EXPIRY
            or not isinstance(task_hash, str)
            or re.fullmatch(r"[0-9a-f]{64}", task_hash) is None
        ):
            raise LaneError("invalid resume tag record")
        result.update(
            {
                "resume_tag": tag,
                "resume_expires_at": expiry,
                "resume_task_packet_hash": task_hash,
            }
        )
    return result


class SessionLaneManager:
    """Manage exact-context HMAC lane IDs in a repository-local state file."""

    def __init__(
        self,
        repo_root: os.PathLike[str] | str,
        *,
        lanes_path: os.PathLike[str] | str = DEFAULT_LANES_PATH,
        key_path: os.PathLike[str] | str = DEFAULT_LANE_KEY_PATH,
        max_lanes: int = MAX_LANES,
        resume_enabled: bool = False,
        host_capability: bool = False,
    ) -> None:
        self.repo_root = os.path.abspath(os.fspath(repo_root))
        self.lanes_target = lanes_path
        self.key_target = key_path
        if type(max_lanes) is not int:
            raise ValueError("max_lanes must be an integer")
        if type(resume_enabled) is not bool or type(host_capability) is not bool:
            raise ValueError("resume feature flags must be literal bools")
        self.max_lanes = max_lanes
        self.resume_enabled = resume_enabled
        self.host_capability = host_capability
        if self.max_lanes <= 0 or self.max_lanes > 1024:
            raise ValueError("invalid lane bound")
        # Resolving creates only the local state directories; no source paths
        # are written into lane state.
        self.lanes_path = resolve_state_path(self.repo_root, self.lanes_target, create_parents=True)
        self.key_path = resolve_state_path(self.repo_root, self.key_target, create_parents=True)
        self._reject_aliasing_state_paths()
        self._key = self._load_or_create_key()
        scope_path = os.path.normcase(os.path.realpath(self.repo_root)).replace("\\", "/")
        self._repo_scope = hmac.new(
            self._key,
            b"repo-scope\0" + scope_path.encode("utf-8", "strict"),
            hashlib.sha256,
        ).digest()

    def _reject_aliasing_state_paths(self) -> None:
        lexical_lanes = os.path.normcase(os.path.abspath(self.lanes_path))
        lexical_key = os.path.normcase(os.path.abspath(self.key_path))
        if lexical_lanes == lexical_key:
            raise LaneError("lane data and key paths must differ")
        resolved_lanes = os.path.normcase(os.path.realpath(self.lanes_path))
        resolved_key = os.path.normcase(os.path.realpath(self.key_path))
        if resolved_lanes == resolved_key:
            raise LaneError("lane data and key paths resolve to the same object")
        try:
            if os.path.exists(self.lanes_path) and os.path.exists(self.key_path):
                if os.path.samefile(self.lanes_path, self.key_path):
                    raise LaneError("lane data and key paths alias")
        except OSError as exc:
            raise LaneError("could not inspect lane data/key identity") from exc

    def _load_or_create_key(self) -> bytes:
        with _local_lock(self.key_path), _state_file_lock(
            self.key_path,
            ancestor_snapshot=_ancestor_snapshot(self.repo_root, self.key_path),
        ):
            try:
                raw = read_bytes(self.repo_root, self.key_target, max_bytes=128)
            except (FileNotFoundError, StateCorruptError):
                raw = b""
            if len(raw) == 32:
                return raw
            if raw:
                with contextlib.suppress(Exception):
                    quarantine_file(self.repo_root, self.key_target, suffix="key-corrupt")
            key = secrets.token_bytes(32)
            atomic_write_bytes(self.repo_root, self.key_target, key, max_bytes=128)
            return key

    def _load(self) -> list[dict[str, Any]]:
        try:
            raw = read_bytes(self.repo_root, self.lanes_target, max_bytes=MAX_LANE_BYTES)
        except FileNotFoundError:
            return []
        try:
            value = json.loads(raw.decode("utf-8", "strict"))
            if not isinstance(value, Mapping) or set(value) != {"format_version", "lanes"} or value["format_version"] != LANE_FORMAT_VERSION:
                raise LaneError("lane file schema mismatch")
            lanes = value["lanes"]
            if not isinstance(lanes, list) or len(lanes) > self.max_lanes:
                raise LaneError("lane list exceeds bound")
            return [_validate_lane_record(item) for item in lanes]
        except (StateCorruptError, UnicodeDecodeError, json.JSONDecodeError, LaneError, TypeError, ValueError):
            with contextlib.suppress(Exception):
                quarantine_file(self.repo_root, self.lanes_target, suffix="lanes-corrupt")
            return []

    def _write(self, lanes: Sequence[Mapping[str, Any]]) -> None:
        normalized = [_validate_lane_record(lane) for lane in lanes]
        value = {"format_version": LANE_FORMAT_VERSION, "lanes": normalized[-self.max_lanes :]}
        encoded = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
        if len(encoded) > MAX_LANE_BYTES:
            raise LaneError("lane state exceeds bound")
        atomic_write_bytes(self.repo_root, self.lanes_target, encoded, max_bytes=MAX_LANE_BYTES)

    def get_or_create(
        self,
        context: Mapping[str, Any],
        *,
        caller_capability: str | None = None,
        resume_id: str | None = None,
        task_packet_hash: str | None = None,
        resume_expires_at: int | None = None,
    ) -> dict[str, Any]:
        return self._get_or_create(
            context,
            caller_capability=caller_capability,
            resume_id=resume_id,
            task_packet_hash=task_packet_hash,
            resume_expires_at=resume_expires_at,
        )

    def _get_or_create(
        self,
        context: Mapping[str, Any],
        *,
        caller_capability: str | None = None,
        resume_id: str | None = None,
        task_packet_hash: str | None = None,
        resume_expires_at: int | None = None,
        clear_existing_resume: bool = False,
    ) -> dict[str, Any]:
        normalized = _normalize_lane_context(context)
        normalized_resume: str | None = None
        if self.resume_enabled and self.host_capability and resume_id is not None:
            try:
                normalized_resume = _lane_string(resume_id, "resume_id")
            except LaneError:
                # Invalid or unsupported handles degrade to a fresh local lane;
                # they are never persisted or returned.
                normalized_resume = None
        resume_data: dict[str, Any] = {}
        if (
            self.resume_enabled
            and self.host_capability
            and normalized_resume is not None
            and caller_capability is not None
            and task_packet_hash is not None
            and type(resume_expires_at) is int
            and resume_expires_at > int(time.time())
        ):
            if resume_expires_at <= MAX_RESUME_EXPIRY:
                try:
                    normalized_task_hash = _task_packet_hash(task_packet_hash)
                except LaneCapabilityError:
                    normalized_task_hash = None
                if normalized_task_hash is not None:
                    resume_data = {
                        "resume_task_packet_hash": normalized_task_hash,
                        "resume_expires_at": resume_expires_at,
                    }
        resume_handle_allowed = normalized_resume is not None and bool(resume_data)
        lane_id = _lane_id(
            self._key, normalized, caller_capability, self._repo_scope
        )
        if resume_data:
            resume_data["resume_tag"] = _resume_tag(
                self._key,
                caller_capability,
                lane_id,
                normalized_resume,
                resume_data["resume_task_packet_hash"],
                normalized,
                resume_data["resume_expires_at"],
            )
        # A host that cannot safely handle resume must never preserve a
        # resume tuple read from copied/shared local state.  An explicitly
        # supplied handle (including an invalid or expired one) also marks
        # the current tuple as stale.  A plain get_or_create without a
        # handle keeps an unexpired tuple available for a later exact
        # resume request; expired tuples are cleared below.
        clear_stale_resume = (
            clear_existing_resume
            or resume_id is not None
            or not (self.resume_enabled and self.host_capability)
        )
        with _state_file_lock(
            self.lanes_path,
            ancestor_snapshot=_ancestor_snapshot(self.repo_root, self.lanes_path),
        ):
            lanes = self._load()
            if resume_data and resume_data["resume_expires_at"] <= int(time.time()):
                # Do not register a handle which expired while waiting for
                # the state lock.
                resume_data = {}
                resume_handle_allowed = False
            for index, lane in enumerate(lanes):
                if lane.get("lane_id") != lane_id:
                    continue
                lane_context = {key: lane[key] for key in _LANE_IDENTITY_FIELDS}
                if lane_context == normalized:
                    result = dict(lane)
                    if resume_handle_allowed:
                        if all(
                            lane.get(field) == value
                            for field, value in resume_data.items()
                        ):
                            result["resume_id"] = normalized_resume
                        else:
                            # A lane ID is capability/context bound, while
                            # its resume tuple is task/session bound.  A new
                            # registration therefore rotates the complete
                            # tuple as one locked write instead of rejecting
                            # the otherwise valid lane.
                            lanes[index] = {**lane, **resume_data}
                            self._write(lanes)
                            result = {**lanes[index], "resume_id": normalized_resume}
                    elif any(field in lane for field in _RESUME_FIELDS) and (
                        clear_stale_resume
                        or lane.get("resume_expires_at", 0) <= int(time.time())
                    ):
                        # Mismatch/expiry fallback must update persisted
                        # state, not merely hide stale fields in the return
                        # value.  Remove all tuple fields together so a
                        # concurrent reader can never observe mixed data.
                        lanes[index] = {
                            key: value
                            for key, value in lane.items()
                            if key not in _RESUME_FIELDS
                        }
                        self._write(lanes)
                        result = dict(lanes[index])
                    for field in _RESUME_FIELDS:
                        # Never expose the opaque persisted tuple without an
                        # exact, currently valid handle registration.
                        if not resume_handle_allowed:
                            result.pop(field, None)
                    return result
            new_lane = {"lane_id": lane_id, **normalized}
            if resume_data:
                new_lane.update(resume_data)
            self._write([*lanes, new_lane])
            result = dict(new_lane)
            if resume_handle_allowed:
                result["resume_id"] = normalized_resume
            return result

    create_or_resume = get_or_create
    resume_or_create = get_or_create

    def resume(
        self,
        lane_id: str,
        context: Mapping[str, Any],
        *,
        caller_capability: str | None = None,
        resume_id: str | None = None,
        task_packet_hash: str | None = None,
        resume_expires_at: int | None = None,
    ) -> dict[str, Any]:
        normalized = _normalize_lane_context(context)

        def fresh_fallback() -> dict[str, Any]:
            # A failed resume attempt revokes the persisted tuple for this
            # exact context/capability lane.  The helper performs that
            # mutation under the state lock and never returns its internals.
            fresh = self._get_or_create(
                normalized,
                caller_capability=caller_capability,
                clear_existing_resume=True,
            )
            fresh.pop("resume_id", None)
            for field in _RESUME_FIELDS:
                fresh.pop(field, None)
            return fresh

        if (
            not self.resume_enabled
            or not self.host_capability
            or caller_capability is None
            or resume_id is None
            or task_packet_hash is None
            or type(resume_expires_at) is not int
            or resume_expires_at <= int(time.time())
            or resume_expires_at > MAX_RESUME_EXPIRY
        ):
            return fresh_fallback()
        try:
            normalized_resume = _lane_string(resume_id, "resume_id")
            normalized_hash = _task_packet_hash(task_packet_hash)
        except LaneError:
            return fresh_fallback()
        expected = _lane_id(
            self._key, normalized, caller_capability, self._repo_scope
        )
        if lane_id == expected:
            with _state_file_lock(
                self.lanes_path,
                ancestor_snapshot=_ancestor_snapshot(self.repo_root, self.lanes_path),
            ):
                for lane in self._load():
                    lane_context = {
                        key: lane[key] for key in _LANE_IDENTITY_FIELDS
                    }
                    if lane.get("lane_id") == lane_id and lane_context == normalized:
                        expected_tag = _resume_tag(
                            self._key,
                            caller_capability,
                            lane_id,
                            normalized_resume,
                            normalized_hash,
                            normalized,
                            resume_expires_at,
                        )
                        if (
                            lane.get("resume_tag") == expected_tag
                            and lane.get("resume_task_packet_hash") == normalized_hash
                            and lane.get("resume_expires_at") == resume_expires_at
                            and lane.get("resume_expires_at", 0) > int(time.time())
                        ):
                            result = dict(lane)
                            result["resume_id"] = normalized_resume
                            return result
                return fresh_fallback()
        # A missing/mismatched lane becomes a context-derived local lane but
        # never carries a handle from either the requested or an existing lane.
        return fresh_fallback()

    def list_lanes(self) -> list[dict[str, Any]]:
        with _state_file_lock(
            self.lanes_path,
            ancestor_snapshot=_ancestor_snapshot(self.repo_root, self.lanes_path),
        ):
            return [dict(item) for item in self._load()]


class TelemetryStore:
    """Bounded JSONL usage store with opt-in aggregate export."""

    def __init__(
        self,
        repo_root: os.PathLike[str] | str,
        path: os.PathLike[str] | str = DEFAULT_TELEMETRY_PATH,
        *,
        max_events: int = MAX_TELEMETRY_EVENTS,
        max_bytes: int = MAX_TELEMETRY_BYTES,
        export_opt_in: bool = False,
    ) -> None:
        self.repo_root = os.path.abspath(os.fspath(repo_root))
        self.target = path
        self.path = resolve_state_path(self.repo_root, self.target, create_parents=True)
        if type(max_events) is not int or type(max_bytes) is not int:
            raise ValueError("telemetry bounds must be integers")
        self.max_events = max_events
        self.max_bytes = max_bytes
        if type(export_opt_in) is not bool:
            raise ValueError("export_opt_in must be a literal bool")
        self.export_opt_in = export_opt_in
        if self.max_events <= 0 or self.max_events > 4096 or self.max_bytes <= 0 or self.max_bytes > 16 * 1024 * 1024:
            raise ValueError("invalid telemetry bounds")

    @staticmethod
    def _parse(
        raw: bytes,
        *,
        max_events: int = MAX_TELEMETRY_EVENTS,
    ) -> list[dict[str, Any]]:
        if not raw:
            return []
        events: list[dict[str, Any]] = []
        for line in raw.splitlines():
            if not line:
                continue
            try:
                value = json.loads(line.decode("utf-8", "strict"))
                if not isinstance(value, Mapping) or "format_version" not in value:
                    raise TelemetryError("persisted telemetry event lacks format_version")
                normalized = validate_telemetry_event(value)
            except (UnicodeDecodeError, json.JSONDecodeError, TelemetryError, TypeError, ValueError) as exc:
                raise TelemetryError("telemetry file is corrupt") from exc
            events.append(normalized)
            if len(events) > max_events:
                raise TelemetryError("telemetry file exceeds event bound")
        return events

    def _load(self) -> list[dict[str, Any]]:
        try:
            raw = read_bytes(self.repo_root, self.target, max_bytes=self.max_bytes)
        except FileNotFoundError:
            return []
        except StateCorruptError:
            with contextlib.suppress(Exception):
                quarantine_file(self.repo_root, self.target, suffix="telemetry-corrupt")
            return []
        try:
            return self._parse(raw, max_events=self.max_events)
        except TelemetryError:
            with contextlib.suppress(Exception):
                quarantine_file(self.repo_root, self.target, suffix="telemetry-corrupt")
            return []

    def record(self, event: Mapping[str, Any]) -> dict[str, Any]:
        # This is deliberately first: forbidden input must not even inspect
        # the existing file, let alone mutate it.
        normalized = validate_telemetry_event(event)
        encoded_line = serialize_event(normalized) + b"\n"
        if len(encoded_line) > self.max_bytes:
            raise TelemetryError("event exceeds telemetry retention bound")
        with _local_lock(self.path), _state_file_lock(
            self.path,
            ancestor_snapshot=_ancestor_snapshot(self.repo_root, self.path),
        ):
            try:
                raw = read_bytes(self.repo_root, self.target, max_bytes=self.max_bytes)
                events = self._parse(raw, max_events=self.max_events)
            except FileNotFoundError:
                events = []
            except (StateCorruptError, TelemetryError):
                with contextlib.suppress(Exception):
                    quarantine_file(self.repo_root, self.target, suffix="telemetry-corrupt")
                events = []
            events.append(normalized)
            retained = events[-self.max_events :]
            while retained:
                candidate_bytes = b"".join(serialize_event(item) + b"\n" for item in retained)
                if len(candidate_bytes) <= self.max_bytes:
                    break
                retained = retained[1:]
            output = b"".join(serialize_event(item) + b"\n" for item in retained)
            atomic_write_bytes(self.repo_root, self.target, output, max_bytes=self.max_bytes)
        return dict(normalized)

    append = record
    record_event = record

    def events(self) -> list[dict[str, Any]]:
        with _local_lock(self.path), _state_file_lock(
            self.path,
            ancestor_snapshot=_ancestor_snapshot(self.repo_root, self.path),
        ):
            return [dict(event) for event in self._load()]

    def export_aggregate(self, *, opt_in: bool | None = None) -> dict[str, Any]:
        if opt_in is not None and type(opt_in) is not bool:
            raise TelemetryError("aggregate export opt-in must be a literal bool")
        enabled = self.export_opt_in if opt_in is None else opt_in
        if enabled is not True:
            raise TelemetryError("aggregate export requires explicit opt-in")
        events = self.events()
        aggregate: dict[str, Any] = {
            "format_version": TELEMETRY_FORMAT_VERSION,
            "event_count": len(events),
        }
        for field in sorted(_COUNT_FIELDS):
            values = [event[field] for event in events if isinstance(event.get(field), int)]
            if values:
                aggregate[field] = sum(values)
        paired = [
            event
            for event in events
            if isinstance(event.get("input_tokens"), int)
            and isinstance(event.get("cached_input_tokens"), int)
        ]
        paired_input = sum(event["input_tokens"] for event in paired)
        paired_cached = sum(event["cached_input_tokens"] for event in paired)
        if paired and paired_input > 0:
            aggregate["cache_hit_ratio"] = paired_cached / paired_input
        return aggregate

    export = export_aggregate


SessionLanes = SessionLaneManager
SessionLaneStore = SessionLaneManager
UsageTelemetry = TelemetryStore
Telemetry = TelemetryStore
LaneManager = SessionLaneManager
validate_event = validate_telemetry_event


__all__ = [
    "DEFAULT_LANE_KEY_PATH",
    "DEFAULT_LANES_PATH",
    "DEFAULT_TELEMETRY_PATH",
    "LANE_FORMAT_VERSION",
    "LaneCapabilityError",
    "LaneError",
    "LaneManager",
    "SessionLaneManager",
    "SessionLanes",
    "SessionLaneStore",
    "TELEMETRY_FORMAT_VERSION",
    "TelemetryError",
    "Telemetry",
    "TelemetryStore",
    "UsageTelemetry",
    "serialize_event",
    "validate_event",
    "validate_telemetry_event",
]
