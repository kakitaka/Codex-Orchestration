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
import json
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


# These patterns are intentionally conservative.  They cover common bearer
# and developer-token forms without trying to guess arbitrary user data.
_SK_BODY_MAX = MAX_REDACTION_MATCH_BYTES - len(b"sk-")
_GH_BODY_MAX = MAX_REDACTION_MATCH_BYTES - len(b"ghp_")
_XOX_BODY_MAX = MAX_REDACTION_MATCH_BYTES - len(b"xoxb-")
_BEARER_SPACE_MAX = 8
_BEARER_BODY_MAX = MAX_REDACTION_MATCH_BYTES - len(b"Bearer") - _BEARER_SPACE_MAX

# Keep the token forms bounded.  An unbounded ``+``/``{n,}`` pattern would
# force the streaming overlap to grow with attacker-controlled output.
_DEFAULT_SECRET_PATTERNS = (
    re.compile(rf"(?i)\b(?:sk|rk)-[A-Za-z0-9_-]{{16,{_SK_BODY_MAX}}}\b".encode("ascii")),
    re.compile(rf"\bgh[pousr]_[A-Za-z0-9_]{{20,{_GH_BODY_MAX}}}\b".encode("ascii")),
    re.compile(rf"\bxox[baprs]-[A-Za-z0-9-]{{16,{_XOX_BODY_MAX}}}\b".encode("ascii")),
    re.compile(rf"(?i)\bBearer\s{{1,8}}[A-Za-z0-9._~+/=-]{{12,{_BEARER_BODY_MAX}}}".encode("ascii")),
)
_PARTIAL_SECRET_SUFFIX = re.compile(
    rf"(?i)(?:\b(?:sk|rk)-[A-Za-z0-9_-]{{0,{_SK_BODY_MAX}}}|"
    rf"\bgh[pousr]_[A-Za-z0-9_]{{0,{_GH_BODY_MAX}}}|"
    rf"\bxox[baprs]-[A-Za-z0-9-]{{0,{_XOX_BODY_MAX}}}|"
    rf"\bBearer\s{{1,8}}[A-Za-z0-9._~+/=-]{{0,{_BEARER_BODY_MAX}}})\Z".encode("ascii")
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
                value = value.encode("utf-8")
            if not isinstance(value, bytes):
                continue
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

    def add(self, data: bytes, *, limit: int | None = None) -> None:
        if not data:
            return
        if limit is not None and len(data) > limit:
            data = data[: max(0, limit)]
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


def _checked_log_path(log_path: str | os.PathLike[str], *, root: Path | None,
                      state_root: Path | None) -> tuple[Path, str]:
    raw = os.fspath(log_path)
    relative = Path(raw)
    if relative.is_absolute() or relative.drive:
        raise ValueError("diagnostic log path must be relative")
    if any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError("diagnostic log path contains an unsafe component")
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
    return candidate, relative.as_posix()


def _atomic_log(path: Path, payload: bytes) -> None:
    if len(payload) > MAX_LOG_BYTES:
        payload = payload[:MAX_LOG_BYTES]
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


def _terminate_tree(process: subprocess.Popen[bytes]) -> None:
    """Best-effort process-tree termination for POSIX and Windows."""
    pid = getattr(process, "pid", None)
    if not pid:
        return
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/PID", str(pid), "/T", "/F"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                shell=False,
                timeout=3,
            )
        except (OSError, subprocess.SubprocessError):
            try:
                process.kill()
            except OSError:
                pass
        return
    try:
        os.killpg(os.getpgid(pid), signal.SIGTERM)
        return
    except (OSError, ProcessLookupError):
        pass
    try:
        process.terminate()
    except OSError:
        pass


def _hard_terminate(process: subprocess.Popen[bytes]) -> None:
    if os.name != "nt":
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            return
        except (OSError, ProcessLookupError, AttributeError):
            pass
    try:
        process.kill()
    except OSError:
        pass


def run_bounded(
    argv: Sequence[str],
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
) -> BoundedResult:
    """Run ``argv`` with shell disabled and return bounded, redacted output."""
    if isinstance(argv, (str, bytes)) or not argv:
        raise ValueError("argv must be a non-empty ordered sequence")
    checked_argv = tuple(argv)
    if any(not isinstance(arg, str) or not arg for arg in checked_argv):
        raise ValueError("argv entries must be non-empty strings")
    if timeout <= 0 or max_bytes <= 0:
        raise ValueError("timeout and max_bytes must be positive")
    head = DEFAULT_HEAD_BYTES if head_bytes is None else max(0, head_bytes)
    tail = DEFAULT_TAIL_BYTES if tail_bytes is None else max(0, tail_bytes)
    # Validate and construct redactors before launching an untrusted command.
    # A one-shot iterable is consumed exactly once, and oversized values fail
    # closed instead of starting a process whose output cannot be protected.
    stdout_redactor = StreamingRedactor(secrets)
    stderr_redactor = StreamingRedactor(stdout_redactor._secrets)
    redactors = {"stdout": stdout_redactor, "stderr": stderr_redactor}

    stdout_capture = _Capture(max_bytes, head, tail)
    stderr_capture = _Capture(max_bytes, head, tail)
    important_lines = _ImportantLines()
    events: queue.Queue[tuple[str, bytes | None]] = queue.Queue(maxsize=QUEUE_SIZE)
    readers_done = {"stdout": False, "stderr": False}
    timed_out = False
    output_limited = False
    proc: subprocess.Popen[bytes] | None = None
    start_error: str | None = None
    reader_threads: list[threading.Thread] = []

    popen_kwargs: dict[str, object] = {
        "cwd": cwd,
        "env": dict(env) if env is not None else None,
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "shell": False,
    }
    if os.name == "nt":
        popen_kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        popen_kwargs["start_new_session"] = True

    try:
        proc = subprocess.Popen(list(checked_argv), **popen_kwargs)  # type: ignore[arg-type]
    except (OSError, ValueError) as exc:
        start_error = f"could not start command: {type(exc).__name__}"

    if proc is not None:
        def reader(name: str, stream: object) -> None:
            redactor = redactors[name]
            try:
                while True:
                    chunk = stream.read(READ_CHUNK_BYTES)  # type: ignore[attr-defined]
                    if not chunk:
                        break
                    redacted = redactor.feed(bytes(chunk))
                    if redacted:
                        events.put((name, redacted))
                final = redactor.flush()
                if final:
                    events.put((name, final))
            except (OSError, ValueError):
                # Process teardown can close a pipe while the reader is active.
                pass
            finally:
                try:
                    events.put((name, None), timeout=1)
                except queue.Full:
                    pass

        for name, stream in (("stdout", proc.stdout), ("stderr", proc.stderr)):
            thread = threading.Thread(target=reader, args=(name, stream), daemon=True)
            thread.start()
            reader_threads.append(thread)

        deadline = time.monotonic() + float(timeout)
        while True:
            if time.monotonic() >= deadline:
                timed_out = True
                _terminate_tree(proc)
                break
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
            important_lines.feed(name, data)
            capture = stdout_capture if name == "stdout" else stderr_capture
            remaining = max(0, max_bytes - stdout_capture.bytes_seen - stderr_capture.bytes_seen)
            capture.add(data, limit=remaining)
            if len(data) > remaining or stdout_capture.bytes_seen + stderr_capture.bytes_seen >= max_bytes:
                output_limited = True
                _terminate_tree(proc)
                break
        if timed_out or output_limited:
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                _hard_terminate(proc)
                try:
                    proc.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    pass
        else:
            try:
                proc.wait(timeout=max(0.1, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                timed_out = True
                _terminate_tree(proc)
                try:
                    proc.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    _hard_terminate(proc)
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
                important_lines.feed(name, data)
                capture = stdout_capture if name == "stdout" else stderr_capture
                remaining = max(0, max_bytes - stdout_capture.bytes_seen - stderr_capture.bytes_seen)
                capture.add(data, limit=remaining)
        for stream in (proc.stdout, proc.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
        for thread in reader_threads:
            thread.join(timeout=0.2)
    important_lines.finish()

    if start_error is not None:
        category, code = "start_error", None
    elif timed_out:
        category, code = "timeout", getattr(proc, "returncode", None)
    elif output_limited:
        category, code = "output_limit", getattr(proc, "returncode", None)
    else:
        code = getattr(proc, "returncode", None)
        category = "ok" if code == 0 else "nonzero"

    combined_first = (stdout_capture.first_bytes() + stderr_capture.first_bytes())[:max_bytes]
    combined_last = (stdout_capture.last_bytes() + stderr_capture.last_bytes())[-max_bytes:]
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
        bytes_seen=stdout_capture.bytes_seen + stderr_capture.bytes_seen,
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
            payload = json.dumps(
                result.to_dict(),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
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


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
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
