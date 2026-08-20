#!/usr/bin/env python3
"""Validate derived-only playbook metadata against current Git blob content."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PLAYBOOK_DIR = ROOT / "docs" / "codex-playbooks"
MAX_PLAYBOOK_BYTES = 256 * 1024
TOP_KEYS = {"version", "name", "entries"}
ENTRY_KEYS = {"path", "blob", "symbols", "headings", "failure_labels", "validation"}
BLOB_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")


def _contained_file(root: Path, value: str) -> Path:
    if not value or "\\" in value:
        raise ValueError("path must be a non-empty repository-relative POSIX path")
    pure = PurePosixPath(value)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise ValueError("path escapes repository root")
    target = root.joinpath(*pure.parts)
    if target.is_symlink():
        raise ValueError("source path is a symlink")
    resolved_root = root.resolve(strict=True)
    resolved = target.resolve(strict=True)
    if resolved_root != resolved and resolved_root not in resolved.parents:
        raise ValueError("source path escapes repository root")
    if not resolved.is_file():
        raise ValueError("source path is not a regular file")
    return resolved


def _blob_id(path: Path) -> str:
    data = path.read_bytes()
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data, usedforsecurity=False).hexdigest()


def _string_list(value: object, field: str) -> None:
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item and len(item) <= 256 for item in value
    ):
        raise ValueError(f"{field} must be a list of bounded non-empty strings")
    if value != sorted(set(value)):
        raise ValueError(f"{field} must be sorted and unique")


def validate_playbook(path: Path, repo_root: Path) -> list[str]:
    findings: list[str] = []
    label = path.relative_to(repo_root).as_posix()
    try:
        if path.is_symlink():
            raise ValueError("playbook is a symlink")
        raw = path.read_bytes()
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
        if not isinstance(entries, list) or not entries:
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
            current = _blob_id(_contained_file(repo_root, source_name))
            if current != expected:
                findings.append(
                    f"{label}: stale blob for {source_name}: expected {expected}, current {current}"
                )
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        findings.append(f"{label}: {exc}")
    return findings


def check_playbooks(repo_root: Path, playbook_dir: Path) -> list[str]:
    root = repo_root.resolve(strict=True)
    directory = playbook_dir.resolve(strict=True)
    if root != directory and root not in directory.parents:
        return ["playbook directory escapes repository root"]
    findings: list[str] = []
    files = sorted(directory.glob("*.json"), key=lambda item: item.name)
    if not files:
        return ["no playbook JSON files found"]
    for path in files:
        findings.extend(validate_playbook(path, root))
    return sorted(findings)


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
