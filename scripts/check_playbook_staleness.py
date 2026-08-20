#!/usr/bin/env python3
"""Validate derived-only playbook metadata against current Git blob content."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PLAYBOOK_DIR = ROOT / "docs" / "codex-playbooks"
MAX_PLAYBOOK_BYTES = 256 * 1024
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_GIT_OUTPUT = 1 * 1024 * 1024
MAX_ENTRIES = 4096
MAX_FINDINGS = 100
MAX_PATH_BYTES = 4096
MAX_TRACKED_PATHS = 100_000
MAX_STRING_LIST = 4096
TOP_KEYS = {"version", "name", "entries"}
ENTRY_KEYS = {"path", "blob", "symbols", "headings", "failure_labels", "validation"}
BLOB_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")


def _contained_file(root: Path, value: str) -> Path:
    if not value or "\\" in value:
        raise ValueError("path must be a non-empty repository-relative POSIX path")
    if len(value.encode("utf-8", "surrogatepass")) > MAX_PATH_BYTES:
        raise ValueError("path exceeds bounded length")
    pure = PurePosixPath(value)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise ValueError("path escapes repository root")
    target = root.joinpath(*pure.parts)
    if target.is_symlink() or _is_reparse(target):
        raise ValueError("source path is a symlink")
    current = root
    for part in pure.parts:
        current = current / part
        if current.is_symlink() or _is_reparse(current):
            raise ValueError("source path crosses a link or reparse point")
    resolved_root = root.resolve(strict=True)
    resolved = target.resolve(strict=True)
    if resolved_root != resolved and resolved_root not in resolved.parents:
        raise ValueError("source path escapes repository root")
    if not resolved.is_file():
        raise ValueError("source path is not a regular file")
    try:
        if resolved.stat(follow_symlinks=False).st_nlink != 1:
            raise ValueError("source path is hardlinked")
    except OSError as exc:
        raise ValueError("source path metadata unavailable") from exc
    return resolved


def _is_reparse(path: Path) -> bool:
    try:
        attrs = getattr(path.stat(follow_symlinks=False), "st_file_attributes", 0)
    except OSError:
        return True
    return bool(attrs & 0x400)


def _git_root(root: Path) -> Path | None:
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--show-toplevel"],
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
    if completed.returncode or not isinstance(raw, bytes) or len(raw) > MAX_PATH_BYTES:
        return None
    try:
        value = raw.decode("utf-8", "strict").strip("\r\n")
        if not value or "\r" in value or "\n" in value:
            return None
        return Path(value).resolve(strict=True)
    except (OSError, UnicodeError, ValueError):
        return None


def _git_blob_id(root: Path, path: Path) -> str:
    relative = path.relative_to(root).as_posix()
    try:
        with path.open("rb") as handle:
            data = handle.read(MAX_SOURCE_BYTES + 1)
        if len(data) > MAX_SOURCE_BYTES:
            raise ValueError("source file exceeds byte limit")
        completed = subprocess.run(
            ["git", "-C", str(root), "hash-object", f"--path={relative}", "--stdin"],
            input=data,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            shell=False,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError("Git hash-object unavailable") from exc
    output = completed.stdout
    if completed.returncode or not isinstance(output, bytes) or len(output) > 128:
        raise ValueError("Git hash-object failed")
    value = output.decode("ascii", "strict").strip()
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", value):
        raise ValueError("Git returned an invalid blob ID")
    return value


def _blob_id(path: Path, repo_root: Path | None = None) -> str:
    """Return Git-normalized blob ID, with a non-Git fixture fallback."""
    root = repo_root.resolve(strict=True) if repo_root is not None else _git_root(path.parent)
    if root is not None:
        return _git_blob_id(root, path)
    with path.open("rb") as handle:
        data = handle.read(MAX_SOURCE_BYTES + 1)
    if len(data) > MAX_SOURCE_BYTES:
        raise ValueError("source file exceeds byte limit")
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data, usedforsecurity=False).hexdigest()


def _repo_tracking(root: Path) -> tuple[Path | None, set[str]]:
    git_root = _git_root(root)
    if git_root is None:
        return None, set()
    if git_root != root.resolve(strict=True):
        raise ValueError("repository root must be the exact Git top level")
    completed = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
        shell=False,
        timeout=5,
    )
    raw = completed.stdout
    if completed.returncode or not isinstance(raw, bytes) or len(raw) > MAX_GIT_OUTPUT:
        raise ValueError("Git tracked path discovery failed")
    tracked: set[str] = set()
    start = 0
    while start < len(raw):
        end = raw.find(b"\0", start)
        if end < 0:
            raise ValueError("Git tracked path list is not NUL terminated")
        item = raw[start:end]
        start = end + 1
        if not item:
            continue
        if len(tracked) >= MAX_TRACKED_PATHS:
            raise ValueError("Git tracked path count exceeds bound")
        name = item.decode("utf-8", "strict")
        if len(name.encode("utf-8")) > MAX_PATH_BYTES:
            raise ValueError("Git tracked path exceeds bound")
        tracked.add(name)
    return git_root, tracked


def _string_list(value: object, field: str) -> None:
    if not isinstance(value, list) or len(value) > MAX_STRING_LIST or not all(
        isinstance(item, str) and item and len(item) <= 256 for item in value
    ):
        raise ValueError(f"{field} must be a list of bounded non-empty strings")
    if value != sorted(set(value)):
        raise ValueError(f"{field} must be sorted and unique")


def validate_playbook(path: Path, repo_root: Path, *, tracked_paths: set[str] | None = None) -> list[str]:
    findings: list[str] = []
    label = path.relative_to(repo_root).as_posix()
    try:
        if path.is_symlink() or _is_reparse(path):
            raise ValueError("playbook is a symlink")
        if path.stat(follow_symlinks=False).st_nlink != 1:
            raise ValueError("playbook is hardlinked")
        if tracked_paths is not None and label not in tracked_paths:
            raise ValueError("playbook JSON is untracked")
        with path.open("rb") as handle:
            raw = handle.read(MAX_PLAYBOOK_BYTES + 1)
        if len(raw) > MAX_PLAYBOOK_BYTES:
            raise ValueError("playbook exceeds byte limit")
        payload = json.loads(raw.decode("utf-8"))
        if not isinstance(payload, dict) or set(payload) != TOP_KEYS:
            raise ValueError("playbook top-level schema mismatch")
        if payload["version"] != 1:
            raise ValueError("unsupported playbook version")
        if not isinstance(payload["name"], str) or not payload["name"]:
            raise ValueError("name must be non-empty")
        entries = payload["entries"]
        if not isinstance(entries, list) or not entries or len(entries) > MAX_ENTRIES:
            raise ValueError("entries must be a non-empty list")
        seen: set[str] = set()
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict) or set(entry) != ENTRY_KEYS:
                raise ValueError(f"entry {index} schema mismatch")
            source_name = entry["path"]
            if not isinstance(source_name, str) or source_name in seen:
                raise ValueError(f"entry {index} path invalid or duplicated")
            seen.add(source_name)
            expected = entry["blob"]
            if not isinstance(expected, str) or not BLOB_RE.fullmatch(expected):
                raise ValueError(f"entry {index} blob is invalid")
            _string_list(entry["symbols"], "symbols")
            _string_list(entry["headings"], "headings")
            _string_list(entry["failure_labels"], "failure_labels")
            if not isinstance(entry["validation"], str) or len(entry["validation"]) > 256:
                raise ValueError(f"entry {index} validation must be a bounded string")
            source_path = _contained_file(repo_root, source_name)
            if tracked_paths is not None and source_name not in tracked_paths:
                raise ValueError("source path is untracked")
            current = _blob_id(source_path, repo_root if tracked_paths is not None else None)
            if current != expected:
                if len(findings) < MAX_FINDINGS:
                    findings.append(
                        f"{label}: stale blob for {source_name}: expected {expected}, current {current}"
                    )
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        findings.append(f"{label}: {exc}")
    return findings


def check_playbooks(repo_root: Path, playbook_dir: Path) -> list[str]:
    if repo_root.is_symlink() or _is_reparse(repo_root):
        return ["repository root is a link or reparse point"]
    root = repo_root.resolve(strict=True)
    if root.is_symlink() or _is_reparse(root):
        return ["repository root is a link or reparse point"]
    try:
        git_root, tracked_paths = _repo_tracking(root)
    except (OSError, UnicodeError, ValueError) as exc:
        return [f"Git tracking check failed: {exc}"]
    try:
        directory = playbook_dir.resolve(strict=True)
    except OSError as exc:
        return [f"playbook directory unavailable: {exc}"]
    if playbook_dir.is_symlink() or _is_reparse(playbook_dir):
        return ["playbook directory is a link or reparse point"]
    if root != directory and root not in directory.parents:
        return ["playbook directory escapes repository root"]
    if not directory.is_dir():
        return ["playbook directory is not a directory"]
    current = root
    try:
        relative_parts = directory.relative_to(root).parts
    except ValueError:
        return ["playbook directory escapes repository root"]
    for part in relative_parts:
        current = current / part
        if current.is_symlink() or _is_reparse(current):
            return ["playbook directory is a link or reparse point"]
    findings: list[str] = []
    files: list[Path] = []
    try:
        for candidate in directory.iterdir():
            if candidate.suffix.lower() == ".json":
                if len(files) >= MAX_ENTRIES:
                    return ["playbook JSON file count exceeds bound"]
                files.append(candidate)
    except OSError as exc:
        return [f"playbook directory unavailable: {exc}"]
    files.sort(key=lambda item: item.name)
    if not files:
        return ["no playbook JSON files found"]
    for path in files:
        findings.extend(validate_playbook(path, root, tracked_paths=tracked_paths if git_root else None))
        if len(findings) >= MAX_FINDINGS:
            break
    return sorted(findings)[:MAX_FINDINGS]


def parse_args(arguments: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    parser.add_argument("--playbook-dir", type=Path)
    return parser.parse_args(arguments)


def main(arguments: list[str] | None = None) -> int:
    args = parse_args(arguments)
    root = args.repo_root
    directory = args.playbook_dir or root / "docs" / "codex-playbooks"
    try:
        findings = check_playbooks(root, directory)
    except OSError as exc:
        findings = [f"playbook check failed: {exc}"]
    if findings:
        for finding in findings[:100]:
            print(f"FAIL: {finding}", file=sys.stderr)
        if len(findings) > 100:
            print(f"FAIL: {len(findings) - 100} additional findings omitted", file=sys.stderr)
        return 1
    print("PASS: playbook blobs current")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
