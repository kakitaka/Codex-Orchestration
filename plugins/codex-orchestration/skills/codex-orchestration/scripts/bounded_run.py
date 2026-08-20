#!/usr/bin/env python3
"""Run one argv without a shell and keep its output bounded.

The module is deliberately self contained.  It is useful from hooks and from
small maintenance scripts where a normal ``subprocess.run(..., capture_output
=True)`` would allow an untrusted command to consume arbitrary memory.
"""

from __future__ import annotations

import argparse
from collections import deque
from dataclasses import dataclass
import ctypes
from ctypes import wintypes
import json
import math
import os
from pathlib import Path
import queue
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
from typing import Iterable, Mapping, Sequence


DEFAULT_TIMEOUT = 30.0
DEFAULT_MAX_BYTES = 64 * 1024
DEFAULT_HEAD_BYTES = 16 * 1024
DEFAULT_TAIL_BYTES = 16 * 1024
READ_CHUNK_BYTES = 8192
QUEUE_SIZE = 32
MAX_LOG_BYTES = 128 * 1024
MAX_SECRET_BYTES = 4096
MAX_SECRET_COUNT = 128
MAX_REDACTION_MATCH_BYTES = 4096
MAX_IMPORTANT_LINES = 32
MAX_IMPORTANT_LINE_BYTES = 4096
MAX_IMPORTANT_BYTES = 16 * 1024
MAX_TIMEOUT = 3600.0
MAX_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_ARG_COUNT = 4096
MAX_ARG_BYTES = 1 * 1024 * 1024
MAX_ENV_COUNT = 4096
MAX_ENV_BYTES = 4 * 1024 * 1024
MAX_THREAD_SCAN = 4096
MAX_JOB_PROCESS_IDS = 4096
MAX_PATH_BYTES = 4096
MAX_LOG_PATH_BYTES = 1024
_SENSITIVE_ENV_RE = re.compile(
    r"(?i)(?:token|secret|password|passwd|api[_-]?key|private[_-]?key|credential|auth)"
)


# These patterns are intentionally conservative.  They cover common bearer
# and developer-token forms without trying to guess arbitrary user data.
_SK_BODY_MAX = MAX_REDACTION_MATCH_BYTES - len(b"sk-")
_GH_BODY_MAX = MAX_REDACTION_MATCH_BYTES - len(b"ghp_")
_XOX_BODY_MAX = MAX_REDACTION_MATCH_BYTES - len(b"xoxb-")
_BEARER_SPACE_MAX = 8
_BEARER_BODY_MAX = MAX_REDACTION_MATCH_BYTES - len(b"Bearer") - _BEARER_SPACE_MAX
_GH_PAT_BODY_MAX = MAX_REDACTION_MATCH_BYTES - len(b"github_pat_")
_AWS_KEY_BODY_MAX = 16

# Keep the token forms bounded.  An unbounded ``+``/``{n,}`` pattern would
# force the streaming overlap to grow with attacker-controlled output.
_DEFAULT_SECRET_PATTERNS = (
    re.compile(rf"(?i)\b(?:sk|rk)-[A-Za-z0-9_-]{{16,{_SK_BODY_MAX}}}\b".encode("ascii")),
    re.compile(rf"\bgh[pousr]_[A-Za-z0-9_]{{20,{_GH_BODY_MAX}}}\b".encode("ascii")),
    re.compile(rf"\bxox[baprs]-[A-Za-z0-9-]{{16,{_XOX_BODY_MAX}}}\b".encode("ascii")),
    re.compile(rf"(?i)\bBearer\s{{1,8}}[A-Za-z0-9._~+/=-]{{12,{_BEARER_BODY_MAX}}}".encode("ascii")),
    re.compile(rf"\bgithub_pat_[A-Za-z0-9_]{{1,{_GH_PAT_BODY_MAX}}}\b".encode("ascii")),
    re.compile(rf"\bAKIA[0-9A-Z]{{{_AWS_KEY_BODY_MAX}}}\b".encode("ascii")),
)
_PARTIAL_SECRET_SUFFIX = re.compile(
    rf"(?i)(?:\b(?:sk|rk)-[A-Za-z0-9_-]{{0,{_SK_BODY_MAX}}}|"
    rf"\bgh[pousr]_[A-Za-z0-9_]{{0,{_GH_BODY_MAX}}}|"
    rf"\bxox[baprs]-[A-Za-z0-9-]{{0,{_XOX_BODY_MAX}}}|"
    rf"\bBearer\s{{1,8}}[A-Za-z0-9._~+/=-]{{0,{_BEARER_BODY_MAX}}}|"
    rf"\bgithub_pat_[A-Za-z0-9_]{{0,{_GH_PAT_BODY_MAX}}}|"
    rf"\bAKIA[0-9A-Z]{{0,{_AWS_KEY_BODY_MAX}}})\Z".encode("ascii")
)
_IMPORTANT_LINE_PATTERN = re.compile(
    rb"(?i)\b(?:error|fail|failure|failed|traceback|assertion|exception|fatal|panic)\b"
)
_MAX_IMPORTANT_PATTERN_BYTES = max(
    len(match) for match in (b"traceback", b"assertion", b"exception")
)


def _prefix_failure(pattern: bytes) -> tuple[int, ...]:
    table = [0] * len(pattern)
    matched = 0
    for index in range(1, len(pattern)):
        while matched and pattern[index] != pattern[matched]:
            matched = table[matched - 1]
        if pattern[index] == pattern[matched]:
            matched += 1
        table[index] = matched
    return tuple(table)


@dataclass(frozen=True)
class BoundedResult:
    """Small, JSON-friendly description of a bounded process invocation."""

    exit_category: str
    exit_code: int | None
    truncated: bool
    first: str
    last: str
    stdout_first: str
    stdout_last: str
    stderr_first: str
    stderr_last: str
    bytes_seen: int
    log_path: str | None = None
    log_error: str | None = None
    important_lines: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "exit_category": self.exit_category,
            "exit_code": self.exit_code,
            "truncated": self.truncated,
            "first": self.first,
            "last": self.last,
            "stdout_first": self.stdout_first,
            "stdout_last": self.stdout_last,
            "stderr_first": self.stderr_first,
            "stderr_last": self.stderr_last,
            "bytes_seen": self.bytes_seen,
            "important_lines": list(self.important_lines),
            "log_path": self.log_path,
            "log_error": self.log_error,
        }

    # Mapping-like access keeps the result convenient for callers that prefer
    # result["exit_category"] over result.exit_category.
    def __getitem__(self, key: str) -> object:
        return self.to_dict()[key]

    def get(self, key: str, default: object = None) -> object:
        return self.to_dict().get(key, default)


class StreamingRedactor:
    """Redact explicit secrets and common token forms across read boundaries."""

    def __init__(self, secrets: Iterable[str | bytes] = ()) -> None:
        values: list[bytes] = []
        for index, value in enumerate(secrets):
            if index >= MAX_SECRET_COUNT:
                raise ValueError("too many secrets")
            if isinstance(value, str):
                try:
                    value = value.encode("utf-8")
                except UnicodeError as exc:
                    raise ValueError("secret is not valid UTF-8") from exc
            elif isinstance(value, bytearray):
                value = bytes(value)
            if not isinstance(value, bytes):
                raise ValueError("secrets must be strings or bytes")
            if len(value) > MAX_SECRET_BYTES:
                raise ValueError("secret exceeds bounded length")
            if value:
                values.append(value)
        self._secrets = tuple(sorted(set(values), key=len, reverse=True))
        self._secret_failures = tuple(_prefix_failure(value) for value in self._secrets)
        self._patterns = _DEFAULT_SECRET_PATTERNS
        max_secret = max((len(value) for value in self._secrets), default=0)
        # Keep enough overlap for the largest bounded explicit or inferred
        # token. ``- 1`` is unsafe: its first byte could be emitted while the
        # rest still sits in the carry buffer.
        self._carry_limit = min(
            MAX_REDACTION_MATCH_BYTES,
            max(MAX_REDACTION_MATCH_BYTES, max_secret),
        )
        self._carry = b""

    def _replace(self, data: bytes) -> bytes:
        for secret in self._secrets:
            data = data.replace(secret, b"[REDACTED]")
        for pattern in self._patterns:
            data = pattern.sub(b"[REDACTED]", data)
        return data

    def _partial_start(self, data: bytes) -> int | None:
        """Return earliest suffix start that could continue into next feed."""
        earliest: int | None = None
        for secret, failure in zip(self._secrets, self._secret_failures):
            # KMP keeps this suffix-prefix check linear in the bounded input
            # instead of retrying every possible prefix length.
            matched = 0
            for byte in data:
                while matched and byte != secret[matched]:
                    matched = failure[matched - 1]
                if byte == secret[matched]:
                    matched += 1
                if matched == len(secret):
                    matched = failure[matched - 1]
            if matched:
                start = len(data) - matched
                earliest = start if earliest is None else min(earliest, start)
        inferred = _PARTIAL_SECRET_SUFFIX.search(data)
        if inferred is not None:
            start = inferred.start()
            earliest = start if earliest is None else min(earliest, start)
        return earliest

    def _crossing_start(self, data: bytes, split: int) -> int | None:
        """Find a complete known match that would straddle ``split``."""
        earliest: int | None = None
        for secret in self._secrets:
            start = data.find(secret)
            while start >= 0:
                end = start + len(secret)
                if start < split < end:
                    earliest = start if earliest is None else min(earliest, start)
                    break
                start = data.find(secret, start + 1)
        for pattern in self._patterns:
            for match in pattern.finditer(data):
                if match.start() < split < match.end():
                    start = match.start()
                    earliest = start if earliest is None else min(earliest, start)
        return earliest

    def feed(self, data: bytes) -> bytes:
        if not data:
            return b""
        joined = self._carry + data
        split = max(0, len(joined) - self._carry_limit)
        partial = self._partial_start(joined)
        if partial is not None and partial < split:
            split = partial
        crossing = self._crossing_start(joined, split)
        if crossing is not None:
            split = crossing
        ready, self._carry = joined[:split], joined[split:]
        return self._replace(ready)

    def flush(self) -> bytes:
        ready = self._carry
        self._carry = b""
        return self._replace(ready)


class _ImportantLineState:
    __slots__ = ("prefix", "important", "scan_tail", "matched", "has_data")

    def __init__(self) -> None:
        self.prefix = bytearray()
        self.important = bytearray()
        self.scan_tail = b""
        self.matched = False
        self.has_data = False


class _ImportantLines:
    """Retain a small set of redacted diagnostic lines outside head/tail."""

    def __init__(self) -> None:
        self._states: dict[str, _ImportantLineState] = {}
        self._lines: list[bytes] = []
        self._bytes = 0
        self._disabled = False

    def _state(self, name: str) -> _ImportantLineState:
        state = self._states.get(name)
        if state is None:
            state = _ImportantLineState()
            self._states[name] = state
        return state

    def _finish(self, name: str) -> None:
        state = self._states.get(name)
        if state is None or not state.has_data:
            if state is not None:
                state.prefix.clear()
                state.important.clear()
                state.scan_tail = b""
                state.matched = False
                state.has_data = False
            return
        line = bytes(state.important if state.matched else state.prefix).rstrip(b"\r")
        if state.matched and line and not self._disabled:
            line = line[:MAX_IMPORTANT_LINE_BYTES]
            remaining = MAX_IMPORTANT_BYTES - self._bytes
            if len(self._lines) >= MAX_IMPORTANT_LINES or remaining <= 0:
                self._disabled = True
            else:
                line = line[:remaining]
                if line:
                    self._lines.append(line)
                    self._bytes += len(line)
                    if len(self._lines) >= MAX_IMPORTANT_LINES or self._bytes >= MAX_IMPORTANT_BYTES:
                        self._disabled = True
        state.prefix.clear()
        state.important.clear()
        state.scan_tail = b""
        state.matched = False
        state.has_data = False

    def _add(self, name: str, data: bytes) -> None:
        if self._disabled:
            return
        state = self._state(name)
        if data:
            state.has_data = True
            scan = state.scan_tail + data
            match = None if state.matched else _IMPORTANT_LINE_PATTERN.search(scan)
            if match is not None:
                state.matched = True
                context_start = max(0, match.start() - 256)
                state.important.extend(
                    scan[context_start : context_start + MAX_IMPORTANT_LINE_BYTES]
                )
            elif state.matched and len(state.important) < MAX_IMPORTANT_LINE_BYTES:
                state.important.extend(
                    data[: MAX_IMPORTANT_LINE_BYTES - len(state.important)]
                )
            state.scan_tail = scan[-(_MAX_IMPORTANT_PATTERN_BYTES - 1):]
            if len(state.prefix) < MAX_IMPORTANT_LINE_BYTES:
                state.prefix.extend(data[: MAX_IMPORTANT_LINE_BYTES - len(state.prefix)])

    def feed(self, name: str, data: bytes) -> None:
        if not data or self._disabled:
            return
        for index, part in enumerate(data.split(b"\n")):
            if index:
                self._finish(name)
            self._add(name, part)

    def finish(self) -> None:
        for name in tuple(self._states):
            self._finish(name)

    def values(self) -> tuple[str, ...]:
        values: list[str] = []
        remaining = MAX_IMPORTANT_BYTES
        for line in self._lines:
            if remaining <= 0:
                break
            text = _safe_text_bounded(line, min(MAX_IMPORTANT_LINE_BYTES, remaining))
            if text:
                values.append(text)
                remaining -= len(text.encode("utf-8"))
        return tuple(values)


class _Capture:
    def __init__(self, max_bytes: int, head_bytes: int, tail_bytes: int) -> None:
        self.max_bytes = max_bytes
        requested = max(1, head_bytes) + max(1, tail_bytes)
        if requested > max_bytes:
            # Keep first and last sections within one capture budget even when
            # a caller supplies a very small overall byte limit.
            self.head_limit = min(max(0, head_bytes), max_bytes // 2)
            self.tail_limit = min(max(0, tail_bytes), max_bytes - self.head_limit)
        else:
            self.head_limit = min(max(0, head_bytes), max_bytes)
            self.tail_limit = min(max(0, tail_bytes), max_bytes - self.head_limit)
        self.head = bytearray()
        self.tail: deque[bytes] = deque()
        self.tail_size = 0
        self.bytes_seen = 0
        self.truncated = False

    def add(
        self,
        data: bytes,
        *,
        limit: int | None = None,
        mark_truncated: bool = True,
    ) -> None:
        if not data:
            return
        if limit is not None and len(data) > limit:
            data = data[: max(0, limit)]
            if mark_truncated:
                self.truncated = True
        if not data:
            return
        self.bytes_seen += len(data)
        if self.bytes_seen > self.max_bytes:
            self.truncated = True
        if len(self.head) < self.head_limit:
            take = min(self.head_limit - len(self.head), len(data))
            self.head.extend(data[:take])
        if self.tail_limit:
            self.tail.append(data)
            self.tail_size += len(data)
            while self.tail_size > self.tail_limit and self.tail:
                excess = self.tail_size - self.tail_limit
                first = self.tail[0]
                if len(first) <= excess:
                    self.tail.popleft()
                    self.tail_size -= len(first)
                else:
                    self.tail[0] = first[excess:]
                    self.tail_size -= excess

    def first_bytes(self) -> bytes:
        return bytes(self.head)

    def last_bytes(self) -> bytes:
        return b"".join(self.tail)


def _safe_text(data: bytes) -> str:
    # Replacement decoding prevents malformed process output from breaking the
    # JSON result, while never attempting to reconstruct hidden bytes.
    return data.decode("utf-8", errors="replace")


def _safe_text_bounded(data: bytes, limit: int) -> str:
    text = _safe_text(data)
    result: list[str] = []
    used = 0
    for char in text:
        encoded = char.encode("utf-8")
        if used + len(encoded) > limit:
            break
        result.append(char)
        used += len(encoded)
    return "".join(result)


def _under(base: Path, candidate: Path) -> bool:
    try:
        candidate.relative_to(base)
    except ValueError:
        return False
    return True


def _is_reparse(path: Path) -> bool:
    try:
        mode = path.stat(follow_symlinks=False)
    except OSError:
        return False
    attrs = getattr(mode, "st_file_attributes", 0)
    return bool(attrs & getattr(__import__("stat"), "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _is_hardlinked(path: Path) -> bool:
    """Reject a state/log path that aliases another filesystem name."""
    try:
        return int(path.stat(follow_symlinks=False).st_nlink) != 1
    except OSError:
        return True


def _git_root(path: Path) -> Path | None:
    """Return the exact Git top-level when ``path`` is a repository."""
    try:
        completed = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "--show-toplevel"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            shell=False,
            timeout=3,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    raw = completed.stdout
    if completed.returncode != 0 or not isinstance(raw, bytes) or len(raw) > MAX_PATH_BYTES:
        return None
    try:
        value = raw.decode("utf-8", "strict").strip("\r\n")
        result = Path(value).resolve(strict=True)
    except (OSError, UnicodeError, ValueError):
        return None
    return result if value and "\n" not in value and "\r" not in value else None


def _ignored_state_root(repo_root: Path, state_root: Path) -> bool:
    """Verify that the state root is Git-ignored without reading its content."""
    try:
        relative = state_root.relative_to(repo_root).as_posix()
    except ValueError:
        return False
    if relative != ".codex-state":
        return False
    try:
        completed = subprocess.run(
            ["git", "-C", str(repo_root), "check-ignore", "--quiet", "--", ".codex-state/probe"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            shell=False,
            timeout=3,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return completed.returncode == 0


def _checked_log_path(log_path: str | os.PathLike[str], *, root: Path | None,
                      state_root: Path | None) -> tuple[Path, str]:
    raw = os.fspath(log_path)
    if isinstance(raw, bytes):
        raw = os.fsdecode(raw)
    if not isinstance(raw, str) or len(raw.encode("utf-8", "surrogatepass")) > MAX_LOG_PATH_BYTES:
        raise ValueError("diagnostic log path exceeds bounded length")
    relative = Path(raw)
    if relative.is_absolute() or relative.drive:
        raise ValueError("diagnostic log path must be relative")
    if any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError("diagnostic log path contains an unsafe component")
    approved_root = Path(root).resolve(strict=True) if root is not None else None
    # A caller inside a real repository must opt into the repository state
    # root explicitly.  Otherwise a relative log path could silently land in
    # the checkout (or even replace a tracked README/config file).
    probe_root = approved_root if approved_root is not None else Path.cwd()
    git_root = _git_root(probe_root)
    if git_root is not None and approved_root != git_root:
        raise ValueError("diagnostic root must be the repository top level")
    if git_root is not None:
        expected_state = git_root / ".codex-state"
        if state_root is None:
            raise ValueError("diagnostic state root must be explicitly supplied")
        base_input = Path(state_root)
        try:
            if base_input.resolve(strict=True) != expected_state.resolve(strict=True):
                raise ValueError("diagnostic state root must be repository .codex-state")
        except FileNotFoundError as exc:
            raise ValueError("diagnostic state root must already exist") from exc
        if not _ignored_state_root(git_root, expected_state):
            raise ValueError("diagnostic state root is not Git-ignored")
    else:
        # Temporary non-Git fixtures used by callers may provide an explicit
        # directory.  A real repository always takes the strict branch above.
        base_input = Path(state_root if state_root is not None else (root or Path.cwd()))
    if base_input.is_symlink() or _is_reparse(base_input):
        raise ValueError("diagnostic state root is a link or reparse point")
    base = base_input.resolve(strict=True)
    if root is not None:
        approved_root = Path(root)
        if approved_root.is_symlink() or _is_reparse(approved_root):
            raise ValueError("diagnostic root is a link or reparse point")
        approved_root = approved_root.resolve(strict=True)
        if not _under(approved_root, base):
            raise ValueError("diagnostic state root escapes approved root")
        current = approved_root
        for part in base.relative_to(approved_root).parts:
            current = current / part
            if current.is_symlink() or _is_reparse(current):
                raise ValueError("diagnostic state root crosses a link or reparse point")
    if not base.is_dir():
        raise ValueError("diagnostic state root must be a directory")
    candidate = base.joinpath(relative)
    # Resolve existing components and reject links/reparse points even when
    # they happen to resolve inside the base directory.
    current = base
    for part in relative.parts:
        current = current / part
        if current.exists() or current.is_symlink():
            if current.is_symlink() or _is_reparse(current):
                raise ValueError("diagnostic log path crosses a link or reparse point")
    # The final parent may be created by the atomic writer.  Resolve it
    # lexically while the component walk above still rejects existing links.
    resolved_parent = candidate.parent.resolve(strict=False)
    if not _under(base, resolved_parent) or not _under(base, candidate.resolve(strict=False)):
        raise ValueError("diagnostic log path escapes allowed root")
    if not candidate.parent.is_dir():
        raise ValueError("diagnostic log parent must already exist")
    if candidate.exists() and _is_hardlinked(candidate):
        raise ValueError("diagnostic log target is hardlinked")
    return candidate, relative.as_posix()


def _atomic_log(path: Path, payload: bytes) -> None:
    if len(payload) > MAX_LOG_BYTES:
        raise ValueError("diagnostic log payload exceeds byte limit")
    if path.parent.is_symlink() or _is_reparse(path.parent) or not path.parent.is_dir():
        raise ValueError("diagnostic log parent became unsafe")
    if path.exists() and (path.is_symlink() or _is_reparse(path)):
        raise ValueError("diagnostic log target is unsafe")
    temporary: Path | None = None
    try:
        fd, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
        temporary = Path(name)
        os.chmod(name, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        if path.parent.is_symlink() or _is_reparse(path.parent):
            raise ValueError("diagnostic log parent changed during write")
        if path.exists() and (path.is_symlink() or _is_reparse(path)):
            raise ValueError("diagnostic log target changed during write")
        if path.exists() and _is_hardlinked(path):
            raise ValueError("diagnostic log target became hardlinked")
        os.replace(name, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    finally:
        if temporary is not None and temporary.exists():
            try:
                temporary.unlink()
            except OSError:
                pass


def _bounded_log_payload(result: BoundedResult) -> bytes:
    """Serialize a structurally reduced diagnostic object within the cap.

    Never truncate serialized JSON: doing so can turn a useful diagnostic into
    invalid data.  The fields are reduced before each serialization attempt.
    """
    payload = result.to_dict()
    text_fields = (
        "first",
        "last",
        "stdout_first",
        "stdout_last",
        "stderr_first",
        "stderr_last",
        "log_error",
    )
    for field in text_fields:
        value = payload.get(field)
        if isinstance(value, str):
            payload[field] = _safe_text_bounded(value.encode("utf-8"), MAX_LOG_BYTES // 8)
    important = payload.get("important_lines")
    if isinstance(important, list):
        payload["important_lines"] = [
            _safe_text_bounded(str(item).encode("utf-8"), MAX_IMPORTANT_LINE_BYTES)
            for item in important[:MAX_IMPORTANT_LINES]
        ]
    encoded = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    if len(encoded) <= MAX_LOG_BYTES:
        return encoded
    # Drop high-volume fields progressively, retaining the status and bounded
    # counters needed to understand the outcome.
    for field in ("important_lines", "first", "last", "stdout_last", "stderr_last"):
        payload.pop(field, None)
        encoded = json.dumps(
            payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        if len(encoded) <= MAX_LOG_BYTES:
            return encoded
    minimal = {
        key: payload[key]
        for key in ("exit_category", "exit_code", "truncated", "bytes_seen")
        if key in payload
    }
    encoded = json.dumps(minimal, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_LOG_BYTES:
        raise ValueError("diagnostic log payload cannot fit bounded schema")
    return encoded


class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = (
        ("PerProcessUserTimeLimit", ctypes.c_longlong),
        ("PerJobUserTimeLimit", ctypes.c_longlong),
        ("LimitFlags", ctypes.c_uint32),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", ctypes.c_uint32),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", ctypes.c_uint32),
        ("SchedulingClass", ctypes.c_uint32),
    )


class _IO_COUNTERS(ctypes.Structure):
    _fields_ = (
        ("ReadOperationCount", ctypes.c_ulonglong),
        ("WriteOperationCount", ctypes.c_ulonglong),
        ("OtherOperationCount", ctypes.c_ulonglong),
        ("ReadTransferCount", ctypes.c_ulonglong),
        ("WriteTransferCount", ctypes.c_ulonglong),
        ("OtherTransferCount", ctypes.c_ulonglong),
    )


class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = (
        ("BasicLimitInformation", _JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", _IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    )


class _THREADENTRY32(ctypes.Structure):
    _fields_ = (
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ThreadID", wintypes.DWORD),
        ("th32OwnerProcessID", wintypes.DWORD),
        ("tpBasePri", wintypes.LONG),
        ("tpDeltaPri", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
    )


class _JOBOBJECT_BASIC_PROCESS_ID_LIST(ctypes.Structure):
    _fields_ = (
        ("NumberOfAssignedProcesses", wintypes.DWORD),
        ("NumberOfProcessIdsInList", wintypes.DWORD),
        ("ProcessIdList", ctypes.c_size_t * MAX_JOB_PROCESS_IDS),
    )


class _WindowsJob:
    """Small ctypes wrapper for a kill-on-close Windows Job Object."""

    _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
    _JOB_OBJECT_BASIC_PROCESS_ID_LIST = 3
    _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
    _TH32CS_SNAPTHREAD = 0x00000004
    _THREAD_SUSPEND_RESUME = 0x0002
    _ERROR_NO_MORE_FILES = 18
    _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    def __init__(self) -> None:
        if os.name != "nt":
            raise RuntimeError("Windows Job Objects are unavailable on this OS")
        try:
            self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            self._create = self._kernel32.CreateJobObjectW
            self._set_info = self._kernel32.SetInformationJobObject
            self._query_info = self._kernel32.QueryInformationJobObject
            self._assign = self._kernel32.AssignProcessToJobObject
            self._terminate_process = self._kernel32.TerminateProcess
            self._close = self._kernel32.CloseHandle
            self._terminate = self._kernel32.TerminateJobObject
            self._snapshot = self._kernel32.CreateToolhelp32Snapshot
            self._thread_first = self._kernel32.Thread32First
            self._thread_next = self._kernel32.Thread32Next
            self._open_thread = self._kernel32.OpenThread
            self._resume_thread = self._kernel32.ResumeThread
            self._create.restype = ctypes.c_void_p
            self._set_info.restype = ctypes.c_int
            self._query_info.restype = ctypes.c_int
            self._assign.restype = ctypes.c_int
            self._terminate_process.restype = ctypes.c_int
            self._close.restype = ctypes.c_int
            self._terminate.restype = ctypes.c_int
            self._snapshot.restype = wintypes.HANDLE
            self._thread_first.restype = ctypes.c_int
            self._thread_next.restype = ctypes.c_int
            self._open_thread.restype = wintypes.HANDLE
            self._resume_thread.restype = wintypes.DWORD
            self._create.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
            self._set_info.argtypes = [
                wintypes.HANDLE,
                wintypes.DWORD,
                wintypes.LPVOID,
                wintypes.DWORD,
            ]
            self._query_info.argtypes = [
                wintypes.HANDLE,
                wintypes.DWORD,
                wintypes.LPVOID,
                wintypes.DWORD,
                ctypes.POINTER(wintypes.DWORD),
            ]
            self._assign.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
            self._terminate_process.argtypes = [wintypes.HANDLE, wintypes.UINT]
            self._close.argtypes = [wintypes.HANDLE]
            self._terminate.argtypes = [wintypes.HANDLE, wintypes.UINT]
            self._snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
            self._thread_first.argtypes = [
                wintypes.HANDLE,
                ctypes.POINTER(_THREADENTRY32),
            ]
            self._thread_next.argtypes = [
                wintypes.HANDLE,
                ctypes.POINTER(_THREADENTRY32),
            ]
            self._open_thread.argtypes = [
                wintypes.DWORD,
                wintypes.BOOL,
                wintypes.DWORD,
            ]
            self._resume_thread.argtypes = [wintypes.HANDLE]
        except (AttributeError, OSError) as exc:
            raise RuntimeError("Windows Job Object API is unavailable") from exc
        try:
            ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
            self._resume_process = ntdll.NtResumeProcess
            self._resume_process.restype = ctypes.c_long
            self._resume_process.argtypes = [wintypes.HANDLE]
        except (AttributeError, OSError):
            self._resume_process = None
        self.handle = self._create(None, None)
        if not self._valid_handle(self.handle):
            raise RuntimeError("CreateJobObjectW failed")
        self._assigned = False
        self._empty_verified = False
        info = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation.LimitFlags = (
            self._JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        )
        if not self._set_info(
            self.handle,
            self._JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            ctypes.byref(info),
            ctypes.sizeof(info),
        ):
            self.close()
            raise RuntimeError("SetInformationJobObject failed")

    @classmethod
    def _valid_handle(cls, handle: object) -> bool:
        value = getattr(handle, "value", handle)
        return value not in {None, 0, -1, cls._INVALID_HANDLE_VALUE}

    @staticmethod
    def _process_handle(process: subprocess.Popen[bytes]) -> object:
        handle = getattr(process, "_handle", None)
        if handle is None:
            raise RuntimeError("process handle unavailable for Job Object assignment")
        value = getattr(handle, "value", handle)
        try:
            return int(value)
        except (TypeError, ValueError):
            return value

    def assign(self, process: subprocess.Popen[bytes]) -> None:
        if not self._valid_handle(self.handle):
            raise RuntimeError("Job Object handle unavailable for assignment")
        process_handle = self._process_handle(process)
        if not self._assign(self.handle, process_handle):
            raise RuntimeError("AssignProcessToJobObject failed")
        self._assigned = True
        self._empty_verified = False

    attach = assign

    def resume(self, process: subprocess.Popen[bytes]) -> None:
        """Resume the one primary thread created with CREATE_SUSPENDED."""
        if not self._assigned:
            raise RuntimeError("process is not assigned to Job Object")
        pid = getattr(process, "pid", None)
        if not isinstance(pid, int) or pid <= 0:
            raise RuntimeError("process PID unavailable for resume")
        snapshot = self._snapshot(self._TH32CS_SNAPTHREAD, 0)
        if not self._valid_handle(snapshot):
            raise RuntimeError("CreateToolhelp32Snapshot failed")
        snapshot_close_failed = False
        direct_resume = False
        try:
            entry = _THREADENTRY32()
            entry.dwSize = ctypes.sizeof(entry)
            if not self._thread_first(snapshot, ctypes.byref(entry)):
                raise RuntimeError("Thread32First failed")
            # Some constrained Windows environments expose the Toolhelp API
            # but return an empty entry.  The process is still suspended, so
            # resuming the process handle is safe after Job assignment.
            if not entry.th32ThreadID or not entry.th32OwnerProcessID:
                direct_resume = True
            else:
                scanned = 0
                while scanned < MAX_THREAD_SCAN:
                    scanned += 1
                    if int(entry.th32OwnerProcessID) == pid:
                        thread = self._open_thread(
                            self._THREAD_SUSPEND_RESUME,
                            False,
                            int(entry.th32ThreadID),
                        )
                        if not self._valid_handle(thread):
                            raise RuntimeError("OpenThread failed")
                        thread_close_failed = False
                        try:
                            previous_count = int(self._resume_thread(thread))
                            if previous_count == 0xFFFFFFFF:
                                raise RuntimeError("ResumeThread failed")
                            if previous_count != 1:
                                raise RuntimeError("unexpected suspended-thread count")
                        finally:
                            if not self._close(thread):
                                thread_close_failed = True
                        if thread_close_failed:
                            raise RuntimeError("thread handle close failed")
                        break
                    if not self._thread_next(snapshot, ctypes.byref(entry)):
                        if ctypes.get_last_error() != self._ERROR_NO_MORE_FILES:
                            raise RuntimeError("Thread32Next failed")
                        raise RuntimeError("primary process thread not found")
                else:
                    raise RuntimeError("thread enumeration exceeded bounded limit")
        finally:
            if not self._close(snapshot):
                snapshot_close_failed = True
        if snapshot_close_failed:
            raise RuntimeError("thread snapshot handle close failed")
        if direct_resume:
            resume_process = getattr(self, "_resume_process", None)
            if resume_process is None or int(resume_process(self._process_handle(process))) != 0:
                raise RuntimeError("NtResumeProcess failed")

    def terminate(self, process: subprocess.Popen[bytes] | None = None) -> bool:
        if getattr(self, "_assigned", False):
            if not self._valid_handle(self.handle):
                return False
            return bool(self._terminate(self.handle, 1))
        if process is None:
            return False
        try:
            process_handle = self._process_handle(process)
        except RuntimeError:
            return False
        return bool(self._terminate_process(process_handle, 1))

    def _active_process_count(self) -> int:
        if not getattr(self, "_assigned", False):
            return 0
        if not self._valid_handle(self.handle):
            raise RuntimeError("Job Object handle unavailable for process query")
        info = _JOBOBJECT_BASIC_PROCESS_ID_LIST()
        returned = wintypes.DWORD()
        if not self._query_info(
            self.handle,
            self._JOB_OBJECT_BASIC_PROCESS_ID_LIST,
            ctypes.byref(info),
            ctypes.sizeof(info),
            ctypes.byref(returned),
        ):
            raise RuntimeError("QueryInformationJobObject failed")
        if int(returned.value) > ctypes.sizeof(info):
            raise RuntimeError("Job Object process query exceeded bounded size")
        assigned = int(info.NumberOfAssignedProcesses)
        listed = int(info.NumberOfProcessIdsInList)
        if (
            assigned > MAX_JOB_PROCESS_IDS
            or listed > MAX_JOB_PROCESS_IDS
            or assigned < listed
        ):
            raise RuntimeError("Job Object process list exceeded bounded limit")
        return max(assigned, listed)

    def _wait_empty(self, timeout: float = 1.0) -> bool:
        if not getattr(self, "_assigned", False):
            self._empty_verified = True
            return True
        try:
            wait_limit = float(timeout)
        except (TypeError, ValueError, OverflowError):
            return False
        if not math.isfinite(wait_limit) or wait_limit < 0:
            return False
        deadline = time.monotonic() + min(wait_limit, 1.0)
        while True:
            try:
                count = self._active_process_count()
            except (OSError, RuntimeError, ValueError, TypeError, ctypes.ArgumentError):
                return False
            if count == 0:
                self._empty_verified = True
                return True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(min(0.01, remaining))

    def verify_empty(self) -> bool:
        """Ensure no active process remains before closing the Job handle."""
        if getattr(self, "_empty_verified", False):
            return True
        try:
            count = self._active_process_count()
        except (OSError, RuntimeError, ValueError, TypeError, ctypes.ArgumentError):
            return False
        if count == 0:
            self._empty_verified = True
            return True
        if not self.terminate():
            return False
        return self._wait_empty()

    def close(self) -> bool:
        handle = getattr(self, "handle", None)
        if not self._valid_handle(handle):
            self.handle = None
            return True
        if self._close(handle):
            self.handle = None
            return True
        # Retain a failed handle so the bounded cleanup path can retry once.
        # Reporting success here would leave a live Job Object unaccounted for.
        return False


class _PosixProcessGroup:
    def __init__(self) -> None:
        if os.name == "nt" or not all(
            callable(getattr(os, name, None)) for name in ("killpg", "getpgid", "setsid")
        ):
            raise RuntimeError("POSIX process groups are unavailable on this OS")
        self.pgid: int | None = None

    def attach(self, process: subprocess.Popen[bytes]) -> None:
        pid = getattr(process, "pid", None)
        if not isinstance(pid, int) or pid <= 0:
            raise RuntimeError("process PID unavailable for process-group cleanup")
        try:
            self.pgid = os.getpgid(pid)
        except OSError as exc:
            raise RuntimeError("process group was not created") from exc
        if self.pgid != pid:
            raise RuntimeError("process did not become its own process-group leader")

    def signal(self, sig: int) -> bool:
        if self.pgid is None:
            return False
        try:
            os.killpg(self.pgid, sig)
            return True
        except ProcessLookupError:
            return True
        except OSError:
            return False

    def alive(self) -> bool:
        if self.pgid is None:
            return False
        try:
            os.killpg(self.pgid, 0)
        except ProcessLookupError:
            return False
        except OSError as exc:
            return exc.errno not in {getattr(__import__("errno"), "ESRCH", 3)}
        return True


def _prepare_tree_controller() -> _WindowsJob | _PosixProcessGroup:
    """Verify cleanup capability before spawning any untrusted process."""
    if os.name == "nt":
        return _WindowsJob()
    if os.name in {"posix"}:
        return _PosixProcessGroup()
    raise RuntimeError(f"unsupported process-tree platform: {os.name}")


def _terminate_tree(
    process: subprocess.Popen[bytes],
    controller: _WindowsJob | _PosixProcessGroup | None = None,
    *,
    force: bool = False,
) -> bool:
    """Terminate only through the verified tree controller and report success."""
    try:
        if isinstance(controller, _WindowsJob):
            # Closing the configured kill-on-close Job Object is the only
            # Windows tree-kill path. TerminateJobObject makes the result
            # prompt; CloseHandle still exercises the configured kill-on-close
            # cleanup. No root-only taskkill fallback exists.
            terminated = controller.terminate(process)
            if not terminated:
                return False
            try:
                process.wait(timeout=1)
            except (OSError, subprocess.TimeoutExpired):
                return False
            if process.poll() is None:
                return False
            if not controller._wait_empty():
                return False
            return controller.close()
        if isinstance(controller, _PosixProcessGroup):
            return controller.signal(signal.SIGKILL if force else signal.SIGTERM)
    except (OSError, RuntimeError, ValueError, TypeError, ctypes.ArgumentError):
        return False
    return False


def _hard_terminate(
    process: subprocess.Popen[bytes],
    controller: _WindowsJob | _PosixProcessGroup | None = None,
) -> bool:
    return _terminate_tree(process, controller, force=True)


def _bounded_int(value: object, *, name: str, minimum: int, maximum: int) -> int:
    if type(value) is not int:
        raise ValueError(f"{name} must be an integer")
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def _bounded_float(value: object, *, name: str, minimum: float, maximum: float) -> float:
    if type(value) not in {int, float}:
        raise ValueError(f"{name} must be a finite positive number")
    try:
        parsed = float(value)
    except (OverflowError, ValueError, TypeError) as exc:
        raise ValueError(f"{name} must be a finite positive number") from exc
    if not math.isfinite(parsed) or not minimum <= parsed <= maximum:
        raise ValueError(f"{name} must be a finite positive number between {minimum} and {maximum}")
    return parsed


def _bounded_text(value: object, *, name: str, maximum_bytes: int) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")
    if len(value.encode("utf-8", "surrogatepass")) > maximum_bytes:
        raise ValueError(f"{name} exceeds bounded length")
    return value


def _materialize_argv(argv: Iterable[str]) -> tuple[str, ...]:
    if isinstance(argv, (str, bytes, bytearray)):
        raise ValueError("argv must be a non-empty ordered iterable")
    values: list[str] = []
    total = 0
    try:
        iterator = iter(argv)
    except TypeError as exc:
        raise ValueError("argv must be an iterable") from exc
    for index, value in enumerate(iterator):
        if index >= MAX_ARG_COUNT:
            raise ValueError("argv has too many entries")
        if not isinstance(value, str) or not value:
            raise ValueError("argv entries must be non-empty strings")
        encoded = len(value.encode("utf-8", "surrogatepass"))
        total += encoded
        if total > MAX_ARG_BYTES:
            raise ValueError("argv exceeds bounded byte length")
        values.append(value)
    if not values:
        raise ValueError("argv must be a non-empty ordered iterable")
    return tuple(values)


def _materialize_env(env: Mapping[str, str] | None) -> tuple[dict[str, str] | None, tuple[str, ...]]:
    if env is None:
        return None, ()
    if isinstance(env, (str, bytes, bytearray)) or not hasattr(env, "items"):
        raise ValueError("env must be a mapping")
    values: dict[str, str] = {}
    sensitive: list[str] = []
    total = 0
    try:
        iterator = iter(env.items())
    except (AttributeError, TypeError) as exc:
        raise ValueError("env must expose an items iterable") from exc
    for index, pair in enumerate(iterator):
        if index >= MAX_ENV_COUNT:
            raise ValueError("env has too many entries")
        if not isinstance(pair, tuple) or len(pair) != 2:
            try:
                key, value = pair
            except (TypeError, ValueError) as exc:
                raise ValueError("env entries must be key/value pairs") from exc
        else:
            key, value = pair
        if not isinstance(key, str) or not key:
            raise ValueError("env keys must be non-empty strings")
        if not isinstance(value, str):
            raise ValueError("env values must be strings")
        size = len(key.encode("utf-8", "surrogatepass")) + len(value.encode("utf-8", "surrogatepass"))
        total += size
        if total > MAX_ENV_BYTES:
            raise ValueError("env exceeds bounded byte length")
        values[key] = value
        if _SENSITIVE_ENV_RE.search(key) or key.upper() in {
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "GITHUB_TOKEN",
            "GH_TOKEN",
        }:
            if value:
                sensitive.append(value)
    return values, tuple(sensitive)


def _inherited_env_secrets() -> tuple[str, ...]:
    """Collect bounded inherited secrets or reject an unsafe environment."""
    values: list[str] = []
    for index, (key, value) in enumerate(os.environ.items()):
        if index >= MAX_ENV_COUNT:
            raise ValueError("inherited environment exceeds bounded entry count")
        if not isinstance(key, str) or not isinstance(value, str) or not value:
            continue
        if not (
            _SENSITIVE_ENV_RE.search(key)
            or key.upper() in {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "GH_TOKEN"}
        ):
            continue
        if len(value.encode("utf-8", "surrogatepass")) > MAX_SECRET_BYTES:
            raise ValueError("inherited sensitive environment value exceeds bounded length")
        values.append(value)
        if len(values) > MAX_SECRET_COUNT:
            raise ValueError("too many inherited secrets")
    return tuple(values)


def _materialize_input(input_data: bytes | str | None) -> bytes | None:
    if input_data is None:
        return None
    if isinstance(input_data, str):
        if len(input_data) > MAX_INPUT_BYTES:
            raise ValueError("input_data exceeds bounded byte length")
        try:
            input_data = input_data.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValueError("input_data is not valid UTF-8") from exc
    elif isinstance(input_data, bytearray):
        if len(input_data) > MAX_INPUT_BYTES:
            raise ValueError("input_data exceeds bounded byte length")
        input_data = bytes(input_data)
    if not isinstance(input_data, bytes):
        raise ValueError("input_data must be bytes or string")
    if len(input_data) > MAX_INPUT_BYTES:
        raise ValueError("input_data exceeds bounded byte length")
    return input_data


def run_bounded(
    argv: Iterable[str],
    *,
    cwd: str | os.PathLike[str] | None = None,
    env: Mapping[str, str] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_bytes: int = DEFAULT_MAX_BYTES,
    head_bytes: int | None = None,
    tail_bytes: int | None = None,
    log_path: str | os.PathLike[str] | None = None,
    root: str | os.PathLike[str] | None = None,
    state_root: str | os.PathLike[str] | None = None,
    secrets: Iterable[str | bytes] = (),
    input_data: bytes | str | None = None,
) -> BoundedResult:
    """Run ``argv`` with shell disabled and return bounded, redacted output."""
    checked_argv = _materialize_argv(argv)
    timeout_value = _bounded_float(timeout, name="timeout", minimum=0.000001, maximum=MAX_TIMEOUT)
    max_output = _bounded_int(max_bytes, name="max_bytes", minimum=1, maximum=MAX_OUTPUT_BYTES)
    if head_bytes is None:
        head = DEFAULT_HEAD_BYTES
    else:
        head = _bounded_int(head_bytes, name="head_bytes", minimum=0, maximum=MAX_OUTPUT_BYTES)
    if tail_bytes is None:
        tail = DEFAULT_TAIL_BYTES
    else:
        tail = _bounded_int(tail_bytes, name="tail_bytes", minimum=0, maximum=MAX_OUTPUT_BYTES)
    if cwd is not None:
        _bounded_text(os.fspath(cwd), name="cwd", maximum_bytes=MAX_PATH_BYTES)
    if root is not None:
        _bounded_text(os.fspath(root), name="root", maximum_bytes=MAX_PATH_BYTES)
    if state_root is not None:
        _bounded_text(os.fspath(state_root), name="state_root", maximum_bytes=MAX_PATH_BYTES)
    if log_path is not None:
        _bounded_text(os.fspath(log_path), name="log_path", maximum_bytes=MAX_LOG_PATH_BYTES)
    checked_env, env_secrets = _materialize_env(env)
    checked_input = _materialize_input(input_data)
    # Validate all public bounds before setting up a child process or any
    # process-tree capability.  Environment-derived values are protected even
    # when a caller did not duplicate them in ``secrets``.
    inherited_secrets = _inherited_env_secrets() if checked_env is None else ()

    def all_secrets() -> Iterable[str | bytes]:
        yield from secrets
        yield from env_secrets
        yield from inherited_secrets

    stdout_redactor = StreamingRedactor(all_secrets())
    stderr_redactor = StreamingRedactor(stdout_redactor._secrets)
    controller = _prepare_tree_controller()
    redactors = {"stdout": stdout_redactor, "stderr": stderr_redactor}

    stdout_capture = _Capture(max_output, head, tail)
    stderr_capture = _Capture(max_output, head, tail)
    important_lines = _ImportantLines()
    events: queue.Queue[tuple[str, bytes | None]] = queue.Queue(maxsize=QUEUE_SIZE)
    readers_done = {"stdout": False, "stderr": False}
    stop_readers = threading.Event()
    timed_out = False
    output_limited = False
    cleanup_error = False
    raw_bytes_seen = 0
    proc: subprocess.Popen[bytes] | None = None
    start_error: str | None = None
    reader_threads: list[threading.Thread] = []
    input_thread: threading.Thread | None = None

    popen_kwargs: dict[str, object] = {
        "cwd": cwd,
        "env": checked_env,
        "stdin": subprocess.PIPE if checked_input is not None else subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "shell": False,
    }
    if os.name == "nt":
        popen_kwargs["creationflags"] = (
            getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
            | getattr(subprocess, "CREATE_SUSPENDED", 0x00000004)
        )
    else:
        popen_kwargs["start_new_session"] = True

    try:
        proc = subprocess.Popen(list(checked_argv), **popen_kwargs)  # type: ignore[arg-type]
    except (OSError, ValueError) as exc:
        start_error = f"could not start command: {type(exc).__name__}"

    if proc is not None:
        try:
            controller.attach(proc)  # type: ignore[attr-defined]
            if isinstance(controller, _WindowsJob):
                controller.resume(proc)
            if checked_input is not None and proc.stdin is not None:
                def write_input() -> None:
                    try:
                        proc.stdin.write(checked_input)  # type: ignore[union-attr]
                        proc.stdin.flush()  # type: ignore[union-attr]
                    except (BrokenPipeError, OSError, ValueError):
                        pass
                    finally:
                        try:
                            proc.stdin.close()  # type: ignore[union-attr]
                        except (OSError, ValueError):
                            pass

                input_thread = threading.Thread(target=write_input, daemon=True)
                input_thread.start()
        except (OSError, RuntimeError, ValueError, TypeError, ctypes.ArgumentError) as exc:
            # Assignment/setup happened after CreateProcess but before any
            # output is consumed.  Kill through the verified controller and
            # expose cleanup_error if the tree cannot be proven gone.
            cleanup_ok = _hard_terminate(proc, controller)
            try:
                proc.wait(timeout=1)
            except (OSError, subprocess.TimeoutExpired):
                cleanup_ok = False
            if proc.poll() is None:
                cleanup_ok = False
            if isinstance(controller, _WindowsJob):
                try:
                    closed = controller.close()
                except (OSError, RuntimeError, ValueError, TypeError, ctypes.ArgumentError):
                    closed = False
                if not closed:
                    cleanup_ok = False
            if not cleanup_ok:
                return BoundedResult(
                    "cleanup_error", getattr(proc, "returncode", None), True,
                    "", "", "", "", "", "", 0,
                    log_error=f"process-tree setup failed: {type(exc).__name__}",
                )
            start_error = f"could not prepare process tree: {type(exc).__name__}"
            proc = None

    if proc is not None:
        def reader(name: str, stream: object) -> None:
            try:
                while True:
                    chunk = stream.read(READ_CHUNK_BYTES)  # type: ignore[attr-defined]
                    if not chunk:
                        break
                    raw = bytes(chunk)
                    while True:
                        try:
                            events.put((name, raw), timeout=0.2)
                            break
                        except queue.Full:
                            if stop_readers.is_set():
                                return
                while True:
                    try:
                        events.put((name, None), timeout=0.2)
                        break
                    except queue.Full:
                        if stop_readers.is_set():
                            return
            except (OSError, ValueError, AttributeError):
                # Process teardown can close a pipe while the reader is active.
                pass
            finally:
                if not readers_done[name]:
                    try:
                        events.put((name, None), timeout=0.2)
                    except queue.Full:
                        pass

        for name, stream in (("stdout", proc.stdout), ("stderr", proc.stderr)):
            thread = threading.Thread(target=reader, args=(name, stream), daemon=True)
            thread.start()
            reader_threads.append(thread)

        deadline = time.monotonic() + timeout_value
        while True:
            if time.monotonic() >= deadline:
                timed_out = True
                stop_readers.set()
                if not _terminate_tree(proc, controller):
                    cleanup_error = True
                break
            if (
                isinstance(controller, _WindowsJob)
                and proc.poll() is not None
                and not getattr(controller, "_empty_verified", False)
            ):
                try:
                    verified = controller.verify_empty()
                except (OSError, RuntimeError, ValueError, TypeError, ctypes.ArgumentError):
                    verified = False
                if not verified:
                    cleanup_error = True
                else:
                    controller._empty_verified = True
            try:
                name, data = events.get(timeout=min(0.05, max(0.001, deadline - time.monotonic())))
            except queue.Empty:
                if proc.poll() is not None and all(readers_done.values()):
                    break
                continue
            if data is None:
                readers_done[name] = True
                if proc.poll() is not None and all(readers_done.values()):
                    break
                continue
            raw_bytes_seen += len(data)
            redacted = redactors[name].feed(data)
            important_lines.feed(name, redacted)
            capture = stdout_capture if name == "stdout" else stderr_capture
            remaining = max(0, max_output - stdout_capture.bytes_seen - stderr_capture.bytes_seen)
            capture.add(redacted, limit=remaining, mark_truncated=False)
            if raw_bytes_seen > max_output:
                output_limited = True
                stop_readers.set()
                if not _terminate_tree(proc, controller):
                    cleanup_error = True
                break
        if timed_out or output_limited:
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                stop_readers.set()
                if not _hard_terminate(proc, controller):
                    cleanup_error = True
                try:
                    proc.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    cleanup_error = True
        else:
            try:
                proc.wait(timeout=max(0.1, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                timed_out = True
                stop_readers.set()
                if not _terminate_tree(proc, controller):
                    cleanup_error = True
                try:
                    proc.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    if not _hard_terminate(proc, controller):
                        cleanup_error = True
                    try:
                        proc.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        cleanup_error = True
        # Give redactors a bounded opportunity to flush their final safe chunks.
        end = time.monotonic() + 1.0
        while time.monotonic() < end and not all(readers_done.values()):
            try:
                name, data = events.get(timeout=0.05)
            except queue.Empty:
                continue
            if data is None:
                readers_done[name] = True
            else:
                raw_bytes_seen += len(data)
                capture = stdout_capture if name == "stdout" else stderr_capture
                redacted = redactors[name].feed(data)
                important_lines.feed(name, redacted)
                remaining = max(0, max_output - stdout_capture.bytes_seen - stderr_capture.bytes_seen)
                capture.add(redacted, limit=remaining, mark_truncated=False)
        for name, redactor in redactors.items():
            redacted = redactor.flush()
            if redacted:
                important_lines.feed(name, redacted)
                capture = stdout_capture if name == "stdout" else stderr_capture
                remaining = max(0, max_output - stdout_capture.bytes_seen - stderr_capture.bytes_seen)
                capture.add(redacted, limit=remaining, mark_truncated=False)
        for stream in (proc.stdout, proc.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
        for thread in reader_threads:
            thread.join(timeout=0.2)
        if input_thread is not None:
            input_thread.join(timeout=0.2)
        if isinstance(controller, _PosixProcessGroup) and controller.alive():
            # A group that survived the graceful kill is a hard cleanup
            # failure unless the force path proves it gone.
            if not _hard_terminate(proc, controller):
                cleanup_error = True
            time.sleep(0.01)
            if controller.alive():
                cleanup_error = True
    if isinstance(controller, _WindowsJob):
        if not getattr(controller, "_empty_verified", False):
            try:
                verified = controller.verify_empty()
            except (OSError, RuntimeError, ValueError, TypeError, ctypes.ArgumentError):
                verified = False
            if not verified:
                cleanup_error = True
        try:
            closed = controller.close()
        except (OSError, RuntimeError, ValueError, TypeError, ctypes.ArgumentError):
            closed = False
        if not closed:
            # A successful child exit does not prove cleanup when the Job
            # Object handle could not be closed. Keep the result fail-closed.
            cleanup_error = True
    important_lines.finish()

    if start_error is not None:
        category, code = "start_error", None
    elif cleanup_error:
        category, code = "cleanup_error", getattr(proc, "returncode", None)
    elif timed_out:
        category, code = "timeout", getattr(proc, "returncode", None)
    elif output_limited:
        category, code = "output_limit", getattr(proc, "returncode", None)
    else:
        code = getattr(proc, "returncode", None)
        category = "ok" if code == 0 else "nonzero"

    combined_first = (stdout_capture.first_bytes() + stderr_capture.first_bytes())[:max_output]
    combined_last = (stdout_capture.last_bytes() + stderr_capture.last_bytes())[-max_output:]
    result = BoundedResult(
        exit_category=category,
        exit_code=code,
        truncated=(stdout_capture.truncated or stderr_capture.truncated or output_limited),
        first=_safe_text(combined_first),
        last=_safe_text(combined_last),
        stdout_first=_safe_text(stdout_capture.first_bytes()),
        stdout_last=_safe_text(stdout_capture.last_bytes()),
        stderr_first=_safe_text(stderr_capture.first_bytes()),
        stderr_last=_safe_text(stderr_capture.last_bytes()),
        bytes_seen=raw_bytes_seen,
        important_lines=important_lines.values(),
    )

    if log_path is not None:
        log_error: str | None = None
        relative: str | None = None
        try:
            checked, relative = _checked_log_path(
                log_path,
                root=Path(root) if root is not None else None,
                state_root=Path(state_root) if state_root is not None else None,
            )
            payload = _bounded_log_payload(result)
            _atomic_log(checked, payload)
        except (OSError, ValueError, TypeError) as exc:
            log_error = f"diagnostic log unavailable: {type(exc).__name__}"
            relative = None
        result = BoundedResult(
            **{
                **result.to_dict(),
                "important_lines": result.important_lines,
                "log_path": relative,
                "log_error": log_error,
            }
        )
    return result


# Short alias for callers that naturally use ``run``.
run = run_bounded


def _finite_positive_timeout(value: str) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise argparse.ArgumentTypeError(
            "timeout must be a finite positive number"
        ) from exc
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("timeout must be a finite positive number")
    return parsed


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", type=_finite_positive_timeout, default=DEFAULT_TIMEOUT)
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    parser.add_argument("--head-bytes", type=int, default=None)
    parser.add_argument("--tail-bytes", type=int, default=None)
    parser.add_argument("--log-path")
    parser.add_argument("--root")
    parser.add_argument("--state-root")
    parser.add_argument("--secret", action="append", default=[])
    parser.add_argument("command", nargs=argparse.REMAINDER)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    command = list(args.command)
    if command[:1] == ["--"]:
        command = command[1:]
    if not command:
        parser.error("a command is required after --")
    result = run_bounded(
        command,
        timeout=args.timeout,
        max_bytes=args.max_bytes,
        head_bytes=args.head_bytes,
        tail_bytes=args.tail_bytes,
        log_path=args.log_path,
        root=args.root,
        state_root=args.state_root,
        secrets=args.secret,
    )
    sys.stdout.write(json.dumps(result.to_dict(), ensure_ascii=False, sort_keys=True) + "\n")
    return 0 if result.exit_category == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
