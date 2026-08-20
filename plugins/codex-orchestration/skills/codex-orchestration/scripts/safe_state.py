"""Small, local-only helpers for safely persisting JSON state.

The orchestration helpers use this module for state which is useful locally
but must never become a second source tree.  The implementation intentionally
has no dependency on the rest of the plugin.  In particular, paths are checked
before opening them and JSON is bounded before it is accepted.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import ntpath
import os
import secrets
import stat
import tempfile
import threading
import time
from typing import Any, Callable, Iterator, TypeVar


T = TypeVar("T")

DEFAULT_MAX_BYTES = 2 * 1024 * 1024
DEFAULT_MAX_DEPTH = 32
DEFAULT_MAX_ITEMS = 20_000
_REPARSE_POINT = 0x0400
_MISSING = object()
_LOCK_GUARD = threading.RLock()
_THREAD_LOCKS: dict[str, threading.RLock] = {}
_LOCK_DEPTH: dict[tuple[str, int], int] = {}


class SafeStateError(ValueError):
    """Base exception for unsafe or malformed local state."""


class UnsafePathError(SafeStateError):
    """A state path is outside its repository or crosses a link/reparse point."""


class StateCorruptError(SafeStateError):
    """A bounded state file could not be decoded as valid JSON."""


class ConcurrentUpdateError(SafeStateError):
    """An optimistic compare/update saw a different file."""


def _reparse_or_link(path: str) -> bool:
    """Inspect a path without following it."""

    try:
        stat_result = os.lstat(path)
    except FileNotFoundError:
        return False
    attributes = int(getattr(stat_result, "st_file_attributes", 0))
    return os.path.islink(path) or bool(attributes & _REPARSE_POINT)


def _absolute_root(repo_root: os.PathLike[str] | str) -> str:
    raw = os.fspath(repo_root)
    if not isinstance(raw, str) or not raw:
        raise UnsafePathError("repository root must be a non-empty path")
    root = os.path.abspath(raw)
    if not os.path.isdir(root):
        raise UnsafePathError("repository root must be an existing directory")
    if _reparse_or_link(root):
        raise UnsafePathError("repository root cannot be a link or reparse point")
    return root


def normalize_relative_path(relative_path: os.PathLike[str] | str) -> str:
    """Return a slash-normalized relative path, rejecting traversal.

    Backslashes are treated as separators even on POSIX.  This matters when a
    path originated on Windows and is later inspected by a test or a worker on
    another platform.
    """

    raw = os.fspath(relative_path)
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        raise UnsafePathError("path must be a non-empty string")
    raw = raw.replace("\\", "/")
    if raw.startswith("/") or raw.startswith("//") or ntpath.isabs(raw):
        raise UnsafePathError("absolute state paths are not allowed")
    drive, _ = ntpath.splitdrive(raw)
    if drive:
        raise UnsafePathError("drive-qualified state paths are not allowed")
    parts = raw.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise UnsafePathError("path traversal or empty path component")
    return "/".join(parts)


def _relative_from_target(root: str, target: os.PathLike[str] | str) -> str:
    raw = os.fspath(target)
    if not isinstance(raw, str):
        raise UnsafePathError("target must be a path string")
    raw_components = raw.replace("\\", "/").split("/")
    if ".." in raw_components:
        raise UnsafePathError("path traversal component is not allowed")
    # An absolute target is accepted only when it is inside the supplied root.
    if os.path.isabs(raw) or ntpath.isabs(raw) or ntpath.splitdrive(raw)[0]:
        absolute = os.path.abspath(raw)
        try:
            relative = os.path.relpath(absolute, root)
        except ValueError as exc:  # different Windows drives
            raise UnsafePathError("target is outside repository root") from exc
        if relative == os.pardir or relative.startswith(os.pardir + os.sep):
            raise UnsafePathError("target is outside repository root")
        return normalize_relative_path(relative)
    return normalize_relative_path(raw)


def _checked_components(
    root: str,
    relative_path: str,
    *,
    create_parents: bool,
) -> str:
    current = root
    parts = relative_path.split("/")
    for index, part in enumerate(parts):
        candidate = os.path.join(current, part)
        is_final = index == len(parts) - 1
        if os.path.lexists(candidate):
            if _reparse_or_link(candidate):
                raise UnsafePathError(f"link/reparse component rejected: {part}")
            if not is_final and not os.path.isdir(candidate):
                raise UnsafePathError(f"non-directory path component: {part}")
        elif not is_final and create_parents:
            try:
                os.mkdir(candidate, 0o700)
            except FileExistsError:
                pass
            if _reparse_or_link(candidate) or not os.path.isdir(candidate):
                raise UnsafePathError(f"unsafe state directory: {part}")
            with contextlib.suppress(OSError):
                os.chmod(candidate, 0o700)
        elif not is_final:
            # Existing components were checked above.  Returning the lexical
            # remainder lets a missing state file use its caller default
            # without weakening checks for links or reparse points.
            return os.path.join(current, *parts[index:])
        current = candidate
    return current


def resolve_state_path(
    repo_root: os.PathLike[str] | str,
    target: os.PathLike[str] | str,
    *,
    create_parents: bool = False,
) -> str:
    """Resolve a state path while checking every existing component.

    The returned path is lexical and is deliberately not produced with
    ``Path.resolve``: resolving links would make a dangerous path look safe.
    """

    root = _absolute_root(repo_root)
    relative = _relative_from_target(root, target)
    return _checked_components(root, relative, create_parents=create_parents)


def _stat_identity(stat_result: os.stat_result) -> tuple[int, int, int, int, int]:
    """Return stable object identity without timestamps or mutable size."""

    inode = int(stat_result.st_ino)
    device = int(stat_result.st_dev)
    # Some filesystems expose no useful inode.  ctime is a conservative
    # fallback there; false-positive rejection is safer than silent reuse.
    fallback = (
        int(getattr(stat_result, "st_ctime_ns", 0))
        if inode == 0 and device == 0
        else 0
    )
    return (
        device,
        inode,
        stat.S_IFMT(stat_result.st_mode),
        int(getattr(stat_result, "st_file_attributes", 0)),
        fallback,
    )


def _ancestor_snapshot(
    repo_root: os.PathLike[str] | str,
    path: os.PathLike[str] | str,
) -> tuple[tuple[str, tuple[int, int, int, int, int] | None], ...]:
    """Capture root-to-parent identities, including missing components."""

    root = _absolute_root(repo_root)
    absolute = os.path.abspath(os.fspath(path))
    try:
        if os.path.commonpath((root, absolute)) != root:
            raise UnsafePathError("state target is outside repository root")
    except ValueError as exc:
        raise UnsafePathError("state target is outside repository root") from exc
    parent = os.path.dirname(absolute)
    relative_parent = os.path.relpath(parent, root)
    parts = [] if relative_parent == os.curdir else relative_parent.split(os.sep)
    snapshot: list[tuple[str, tuple[int, int, int, int, int] | None]] = []
    current = root
    missing = False
    for part in [None, *parts]:
        if part is not None:
            current = os.path.join(current, part)
        if missing or not os.path.lexists(current):
            snapshot.append((current, None))
            missing = True
            continue
        if _reparse_or_link(current):
            raise UnsafePathError("state ancestor cannot be a link/reparse point")
        stat_result = os.lstat(current)
        if not stat.S_ISDIR(stat_result.st_mode):
            raise UnsafePathError("state ancestor must be a directory")
        snapshot.append((current, _stat_identity(stat_result)))
    return tuple(snapshot)


def _revalidate_ancestors(
    snapshot: tuple[tuple[str, tuple[int, int, int, int, int] | None], ...],
) -> None:
    """Fail closed if an ancestor appeared, disappeared, or was swapped."""

    for path, expected in snapshot:
        if expected is None:
            if os.path.lexists(path):
                raise UnsafePathError("state ancestor appeared during operation")
            continue
        try:
            stat_result = os.lstat(path)
        except FileNotFoundError as exc:
            raise UnsafePathError("state ancestor disappeared during operation") from exc
        if (
            _reparse_or_link(path)
            or not stat.S_ISDIR(stat_result.st_mode)
            or _stat_identity(stat_result) != expected
        ):
            raise UnsafePathError("state ancestor changed during operation")


def _validate_json_tree(
    value: Any,
    *,
    depth: int,
    max_depth: int,
    items: list[int],
    max_items: int,
) -> None:
    if depth > max_depth:
        raise StateCorruptError("JSON nesting depth exceeds bound")
    if isinstance(value, dict):
        items[0] += len(value)
        if items[0] > max_items:
            raise StateCorruptError("JSON item count exceeds bound")
        for key, child in value.items():
            if not isinstance(key, str):
                raise StateCorruptError("JSON object keys must be strings")
            _validate_json_tree(
                child,
                depth=depth + 1,
                max_depth=max_depth,
                items=items,
                max_items=max_items,
            )
    elif isinstance(value, list):
        items[0] += len(value)
        if items[0] > max_items:
            raise StateCorruptError("JSON item count exceeds bound")
        for child in value:
            _validate_json_tree(
                child,
                depth=depth + 1,
                max_depth=max_depth,
                items=items,
                max_items=max_items,
            )
    elif isinstance(value, (str, int, float, bool)) or value is None:
        return
    else:
        raise StateCorruptError(f"unsupported JSON value: {type(value).__name__}")


def _reject_constant(value: str) -> None:
    raise StateCorruptError(f"non-standard JSON number: {value}")


def validate_json_value(
    value: Any,
    *,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_items: int = DEFAULT_MAX_ITEMS,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> bytes:
    """Validate and deterministically encode a JSON value within bounds."""

    if max_depth < 0 or max_items < 0 or max_bytes <= 0:
        raise ValueError("JSON bounds must be positive where applicable")
    _validate_json_tree(
        value,
        depth=0,
        max_depth=max_depth,
        items=[0],
        max_items=max_items,
    )
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8", "strict")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise StateCorruptError("value is not valid UTF-8 JSON") from exc
    if len(encoded) > max_bytes:
        raise StateCorruptError("JSON size exceeds bound")
    return encoded


def _read_bytes_unlocked(
    path: str,
    *,
    max_bytes: int,
    ancestor_snapshot: tuple[
        tuple[str, tuple[int, int, int, int, int] | None], ...
    ]
    | None = None,
) -> bytes:
    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")
    if ancestor_snapshot is not None:
        _revalidate_ancestors(ancestor_snapshot)
    if _reparse_or_link(path):
        raise UnsafePathError("link/reparse state file rejected")
    try:
        before = os.lstat(path)
    except FileNotFoundError:
        if ancestor_snapshot is not None:
            _revalidate_ancestors(ancestor_snapshot)
        raise
    before_identity = _stat_identity(before)
    flags = os.O_RDONLY
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        raise
    try:
        if ancestor_snapshot is not None:
            _revalidate_ancestors(ancestor_snapshot)
        stat_result = os.fstat(descriptor)
        try:
            current = os.lstat(path)
        except FileNotFoundError as exc:
            raise UnsafePathError("state file disappeared during open") from exc
        if (
            _reparse_or_link(path)
            or _stat_identity(stat_result) != before_identity
            or _stat_identity(current) != _stat_identity(stat_result)
        ):
            raise UnsafePathError("state file changed during open")
        if stat_result.st_size > max_bytes:
            raise StateCorruptError("state file exceeds byte bound")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65_536, max_bytes - total + 1))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise StateCorruptError("state file exceeds byte bound")
        if ancestor_snapshot is not None:
            _revalidate_ancestors(ancestor_snapshot)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _decode_json(
    raw: bytes,
    *,
    max_depth: int,
    max_items: int,
    max_bytes: int,
) -> Any:
    if len(raw) > max_bytes:
        raise StateCorruptError("state file exceeds byte bound")
    try:
        text = raw.decode("utf-8", "strict")
        value = json.loads(text, parse_constant=_reject_constant)
    except StateCorruptError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise StateCorruptError("state file is not valid UTF-8 JSON") from exc
    _validate_json_tree(
        value,
        depth=0,
        max_depth=max_depth,
        items=[0],
        max_items=max_items,
    )
    return value


def _thread_lock(path: str) -> threading.RLock:
    with _LOCK_GUARD:
        return _THREAD_LOCKS.setdefault(path, threading.RLock())


@contextlib.contextmanager
def _file_lock(
    path: str,
    *,
    ancestor_snapshot: tuple[
        tuple[str, tuple[int, int, int, int, int] | None], ...
    ]
    | None = None,
) -> Iterator[None]:
    """Use a same-directory lock file plus a process-local lock.

    ``fcntl`` is used when available.  Windows does not expose the same API;
    the process-local lock still protects normal plugin concurrency and the
    atomic replace prevents torn files across processes.
    """

    lock = _thread_lock(path)
    with lock:
        depth_key = (path, threading.get_ident())
        with _LOCK_GUARD:
            depth = _LOCK_DEPTH.get(depth_key, 0)
            _LOCK_DEPTH[depth_key] = depth + 1
        if depth:
            try:
                # The outer invocation already owns the OS lock.  Reopening
                # the lock file on Windows would deadlock msvcrt.locking.
                if ancestor_snapshot is not None:
                    _revalidate_ancestors(ancestor_snapshot)
                yield
            finally:
                with _LOCK_GUARD:
                    if _LOCK_DEPTH.get(depth_key, 0) <= 1:
                        _LOCK_DEPTH.pop(depth_key, None)
                    else:
                        _LOCK_DEPTH[depth_key] -= 1
            return
        try:
            lock_path = path + ".lock"
            flags = os.O_CREAT | os.O_RDWR
            flags |= getattr(os, "O_BINARY", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            descriptor = None
            windows_lock = None
            try:
                if ancestor_snapshot is not None:
                    _revalidate_ancestors(ancestor_snapshot)
                if _reparse_or_link(lock_path):
                    raise UnsafePathError("lock path cannot be a link/reparse point")
                descriptor = os.open(lock_path, flags, 0o600)
                if ancestor_snapshot is not None:
                    _revalidate_ancestors(ancestor_snapshot)
                lock_stat = os.lstat(lock_path)
                if (
                    _reparse_or_link(lock_path)
                    or _stat_identity(lock_stat)
                    != _stat_identity(os.fstat(descriptor))
                ):
                    raise UnsafePathError("lock file changed during open")
                with contextlib.suppress(OSError):
                    os.chmod(lock_path, 0o600)
                try:
                    import fcntl  # type: ignore

                    fcntl.flock(descriptor, fcntl.LOCK_EX)
                except (ImportError, OSError):
                    try:
                        import msvcrt  # type: ignore

                        # msvcrt.locking requires at least one byte and locks from
                        # the current file position.
                        if os.fstat(descriptor).st_size == 0:
                            os.write(descriptor, b"\0")
                        os.lseek(descriptor, 0, os.SEEK_SET)
                        msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)
                        windows_lock = msvcrt
                    except (ImportError, OSError):
                        # Atomic replace still prevents torn files on platforms
                        # which expose neither advisory locking API.
                        windows_lock = None
                yield
            finally:
                if descriptor is not None:
                    with contextlib.suppress(Exception):
                        if windows_lock is not None:
                            windows_lock.locking(descriptor, windows_lock.LK_UNLCK, 1)
                        else:
                            import fcntl  # type: ignore

                            fcntl.flock(descriptor, fcntl.LOCK_UN)
                    with contextlib.suppress(OSError):
                        os.close(descriptor)
        finally:
            with _LOCK_GUARD:
                _LOCK_DEPTH.pop(depth_key, None)


def _fsync_directory(directory: str) -> None:
    if os.name == "nt":
        return
    try:
        descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)


def _atomic_replace(
    path: str,
    data: bytes,
    *,
    ancestor_snapshot: tuple[
        tuple[str, tuple[int, int, int, int, int] | None], ...
    ]
    | None = None,
) -> None:
    directory = os.path.dirname(path)
    if ancestor_snapshot is not None:
        _revalidate_ancestors(ancestor_snapshot)
    if not directory or not os.path.isdir(directory):
        raise UnsafePathError("state parent directory is missing")
    if _reparse_or_link(directory):
        raise UnsafePathError("state parent directory cannot be a link/reparse point")
    if _reparse_or_link(path):
        raise UnsafePathError("refusing to replace a link/reparse state file")
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{os.path.basename(path)}.", suffix=".tmp", dir=directory
    )
    try:
        if ancestor_snapshot is not None:
            _revalidate_ancestors(ancestor_snapshot)
        os.fchmod(descriptor, 0o600) if hasattr(os, "fchmod") else os.chmod(temporary, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = -1
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if _reparse_or_link(directory) or _reparse_or_link(path):
            raise UnsafePathError("state destination changed during atomic write")
        if ancestor_snapshot is not None:
            _revalidate_ancestors(ancestor_snapshot)
        os.replace(temporary, path)
        if ancestor_snapshot is not None:
            _revalidate_ancestors(ancestor_snapshot)
        with contextlib.suppress(OSError):
            os.chmod(path, 0o600)
        _fsync_directory(directory)
    except Exception:
        if descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(descriptor)
        with contextlib.suppress(OSError):
            os.unlink(temporary)
        raise


def atomic_write_bytes(
    repo_root: os.PathLike[str] | str,
    target: os.PathLike[str] | str,
    data: bytes,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> str:
    """Atomically write bounded bytes to a safe, same-directory path."""

    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if len(data) > max_bytes:
        raise StateCorruptError("state bytes exceed bound")
    root = _absolute_root(repo_root)
    path = resolve_state_path(root, target, create_parents=True)
    ancestors = _ancestor_snapshot(root, path)
    with _file_lock(path, ancestor_snapshot=ancestors):
        _atomic_replace(path, data, ancestor_snapshot=ancestors)
    return hashlib.sha256(data).hexdigest()


def read_bytes(
    repo_root: os.PathLike[str] | str,
    target: os.PathLike[str] | str,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> bytes:
    root = _absolute_root(repo_root)
    path = resolve_state_path(root, target, create_parents=False)
    ancestors = _ancestor_snapshot(root, path)
    return _read_bytes_unlocked(
        path, max_bytes=max_bytes, ancestor_snapshot=ancestors
    )


def quarantine_file(
    repo_root: os.PathLike[str] | str,
    target: os.PathLike[str] | str,
    *,
    suffix: str = "corrupt",
) -> str | None:
    """Move one corrupt file aside; never recursively delete anything."""

    root = _absolute_root(repo_root)
    path = resolve_state_path(root, target, create_parents=False)
    ancestors = _ancestor_snapshot(root, path)
    _revalidate_ancestors(ancestors)
    if not os.path.lexists(path):
        return None
    if _reparse_or_link(path):
        raise UnsafePathError("refusing to quarantine a link/reparse file")
    _revalidate_ancestors(ancestors)
    directory = os.path.dirname(path)
    for _ in range(8):
        candidate = os.path.join(
            directory,
            f"{os.path.basename(path)}.{suffix}-{time.time_ns()}-{secrets.token_hex(4)}",
        )
        if os.path.lexists(candidate):
            continue
        _revalidate_ancestors(ancestors)
        os.replace(path, candidate)
        _revalidate_ancestors(ancestors)
        with contextlib.suppress(OSError):
            os.chmod(candidate, 0o600)
        _fsync_directory(directory)
        return candidate
    raise SafeStateError("could not choose a quarantine filename")


def read_json(
    repo_root: os.PathLike[str] | str,
    target: os.PathLike[str] | str,
    *,
    default: Any = _MISSING,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_items: int = DEFAULT_MAX_ITEMS,
    quarantine_corrupt: bool = False,
) -> Any:
    """Read bounded JSON, optionally quarantining malformed state."""

    root = _absolute_root(repo_root)
    path = resolve_state_path(root, target, create_parents=False)
    ancestors = _ancestor_snapshot(root, path)
    _revalidate_ancestors(ancestors)
    if not os.path.lexists(path):
        if default is not _MISSING:
            return default
        raise FileNotFoundError(path)
    try:
        return _decode_json(
            _read_bytes_unlocked(
                path,
                max_bytes=max_bytes,
                ancestor_snapshot=ancestors,
            ),
            max_depth=max_depth,
            max_items=max_items,
            max_bytes=max_bytes,
        )
    except StateCorruptError:
        if quarantine_corrupt:
            with contextlib.suppress(OSError, UnsafePathError):
                quarantine_file(repo_root, target)
        if default is not _MISSING:
            return default
        raise


def write_json(
    repo_root: os.PathLike[str] | str,
    target: os.PathLike[str] | str,
    value: Any,
    *,
    expected_digest: str | None = None,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_items: int = DEFAULT_MAX_ITEMS,
) -> str:
    """Validate and atomically write JSON, optionally using a digest CAS."""

    encoded = validate_json_value(
        value,
        max_depth=max_depth,
        max_items=max_items,
        max_bytes=max_bytes,
    )
    root = _absolute_root(repo_root)
    path = resolve_state_path(root, target, create_parents=True)
    ancestors = _ancestor_snapshot(root, path)
    with _file_lock(path, ancestor_snapshot=ancestors):
        if expected_digest is not None:
            try:
                current = _read_bytes_unlocked(
                    path,
                    max_bytes=max_bytes,
                    ancestor_snapshot=ancestors,
                )
            except FileNotFoundError:
                current = None
            current_digest = None if current is None else hashlib.sha256(current).hexdigest()
            if current_digest != expected_digest:
                raise ConcurrentUpdateError("state digest changed before update")
        _atomic_replace(path, encoded, ancestor_snapshot=ancestors)
    return hashlib.sha256(encoded).hexdigest()


def update_json(
    repo_root: os.PathLike[str] | str,
    target: os.PathLike[str] | str,
    updater: Callable[[Any], Any],
    *,
    default: Any = None,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_items: int = DEFAULT_MAX_ITEMS,
    quarantine_corrupt: bool = True,
) -> tuple[Any, str]:
    """Read, transform, and atomically replace one state value under a lock."""

    if not callable(updater):
        raise TypeError("updater must be callable")
    root = _absolute_root(repo_root)
    path = resolve_state_path(root, target, create_parents=True)
    ancestors = _ancestor_snapshot(root, path)
    with _file_lock(path, ancestor_snapshot=ancestors):
        if os.path.lexists(path):
            try:
                current = _decode_json(
                    _read_bytes_unlocked(
                        path,
                        max_bytes=max_bytes,
                        ancestor_snapshot=ancestors,
                    ),
                    max_depth=max_depth,
                    max_items=max_items,
                    max_bytes=max_bytes,
                )
            except StateCorruptError:
                if quarantine_corrupt:
                    quarantine_file(repo_root, target)
                else:
                    raise
                current = default
        else:
            current = default
        updated = updater(current)
        encoded = validate_json_value(
            updated,
            max_depth=max_depth,
            max_items=max_items,
            max_bytes=max_bytes,
        )
        _atomic_replace(path, encoded, ancestor_snapshot=ancestors)
    return updated, hashlib.sha256(encoded).hexdigest()


# Friendly aliases used by callers which prefer verb-first names.
safe_path = resolve_state_path
load_json = read_json
save_json = write_json
safe_read_json = read_json
safe_write_json = write_json
safe_update_json = update_json


__all__ = [
    "ConcurrentUpdateError",
    "DEFAULT_MAX_BYTES",
    "DEFAULT_MAX_DEPTH",
    "DEFAULT_MAX_ITEMS",
    "SafeStateError",
    "StateCorruptError",
    "UnsafePathError",
    "atomic_write_bytes",
    "load_json",
    "normalize_relative_path",
    "quarantine_file",
    "read_bytes",
    "read_json",
    "resolve_state_path",
    "safe_path",
    "safe_read_json",
    "safe_update_json",
    "safe_write_json",
    "save_json",
    "update_json",
    "validate_json_value",
    "write_json",
]
