#!/usr/bin/env python3
"""Validate release metadata and monotonic distributable identity."""

from __future__ import annotations

import argparse
import ast
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
from typing import Callable, NamedTuple


CHANGELOG_VERSION_RE = re.compile(
    r"^##\s+([^\s]+)\s+—\s+(.+)$", re.MULTILINE
)
MANIFEST_PATH = "plugins/codex-orchestration/.codex-plugin/plugin.json"
MCP_PATH = "plugins/codex-orchestration/.mcp.json"
SKILLS_ROOT = "plugins/codex-orchestration/skills"
LIFECYCLE_PATH = "tests/plugin_lifecycle_smoke.py"
ROUTING_PATH = (
    "plugins/codex-orchestration/skills/codex-orchestration/scripts/"
    "configure_native_routing.py"
)
CHANGELOG_PATH = "CHANGELOG.md"
GIT_TIMEOUT_SECONDS = 15
MAX_GIT_OUTPUT = 1_000_000
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_PATH_BYTES = 4096


class ReleaseCheckError(RuntimeError):
    """Release metadata, Git history, or version precedence is invalid."""


class SemVer(NamedTuple):
    major: int
    minor: int
    patch: int
    prerelease: tuple[str, ...] = ()
    build: tuple[str, ...] = ()

    @classmethod
    def parse(cls, value: str) -> "SemVer":
        if not isinstance(value, str):
            raise ReleaseCheckError(f"version is not a string: {value!r}")
        match = re.fullmatch(
            r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
            r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
            r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?",
            value,
        )
        if match is None:
            raise ReleaseCheckError(f"invalid SemVer 2 version: {value!r}")
        prerelease = tuple(match.group(4).split(".")) if match.group(4) else ()
        for identifier in prerelease:
            if identifier.isdigit() and len(identifier) > 1 and identifier.startswith("0"):
                raise ReleaseCheckError(
                    f"numeric prerelease identifier has a leading zero: {value!r}"
                )
        build = tuple(match.group(5).split(".")) if match.group(5) else ()
        return cls(
            int(match.group(1)),
            int(match.group(2)),
            int(match.group(3)),
            prerelease,
            build,
        )

    def _compare_prerelease(self, other: "SemVer") -> int:
        if not self.prerelease and not other.prerelease:
            return 0
        if not self.prerelease:
            return 1
        if not other.prerelease:
            return -1
        for left, right in zip(self.prerelease, other.prerelease):
            if left == right:
                continue
            left_numeric = left.isdigit()
            right_numeric = right.isdigit()
            if left_numeric and right_numeric:
                return -1 if int(left) < int(right) else 1
            if left_numeric != right_numeric:
                return -1 if left_numeric else 1
            return -1 if left < right else 1
        if len(self.prerelease) == len(other.prerelease):
            return 0
        return -1 if len(self.prerelease) < len(other.prerelease) else 1

    def compare(self, other: "SemVer") -> int:
        left_core = (self.major, self.minor, self.patch)
        right_core = (other.major, other.minor, other.patch)
        if left_core != right_core:
            return -1 if left_core < right_core else 1
        return self._compare_prerelease(other)


def compare_semver(left: str, right: str) -> int:
    """Return negative, zero, or positive using SemVer 2 precedence."""
    return SemVer.parse(left).compare(SemVer.parse(right))


def _bounded(value: str) -> str:
    if len(value) <= MAX_GIT_OUTPUT:
        return value
    return value[:MAX_GIT_OUTPUT] + "\n...[output truncated]"


def _git(root: Path, arguments: list[str], *, binary: bool = False) -> str | bytes:
    command = ["git", *arguments]
    try:
        result = subprocess.run(
            command,
            cwd=root,
            capture_output=True,
            text=False,
            check=False,
            timeout=GIT_TIMEOUT_SECONDS,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ReleaseCheckError(f"could not run {command!r}: {exc}") from exc
    if result.returncode != 0:
        stderr = result.stderr
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")
        detail = _bounded(stderr.strip()) or "no diagnostic output"
        raise ReleaseCheckError(f"Git command failed: {command!r}: {detail}")
    output = result.stdout
    if len(output) > MAX_GIT_OUTPUT:
        raise ReleaseCheckError(f"Git command returned excessive output: {command!r}")
    if binary:
        return output
    try:
        return output.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise ReleaseCheckError(
            f"Git command returned non-UTF-8 text: {command!r}"
        ) from exc


def _repository_top(root: Path) -> Path:
    root = root.resolve(strict=True)
    output = _git(root, ["rev-parse", "--show-toplevel"])
    assert isinstance(output, str)
    if len(output.encode("utf-8")) > MAX_PATH_BYTES:
        raise ReleaseCheckError("repository top-level path exceeds bound")
    try:
        top = Path(output.strip()).resolve(strict=True)
    except (OSError, ValueError) as exc:
        raise ReleaseCheckError("Git returned an invalid repository top-level path") from exc
    if top != root:
        raise ReleaseCheckError("repository root must be the exact Git top level")
    return top


def _object_width(root: Path) -> int:
    output = _git(root, ["rev-parse", "--show-object-format"])
    assert isinstance(output, str)
    value = output.strip()
    if value == "sha1":
        return 40
    if value == "sha256":
        return 64
    # Unit callers may stub a single Git response; infer the legacy width
    # only when the stub itself is a valid object-shaped response.
    if re.fullmatch(r"[0-9a-fA-F]{40}(?:\n[0-9a-fA-F]{40})*", value):
        return 40
    if re.fullmatch(r"[0-9a-fA-F]{64}(?:\n[0-9a-fA-F]{64})*", value):
        return 64
    raise ReleaseCheckError("unsupported Git object format")


def _require_clean_tree(root: Path) -> None:
    output = _git(root, ["status", "--porcelain=v1", "-z"], binary=True)
    assert isinstance(output, bytes)
    if output:
        raise ReleaseCheckError("--require-tag requires a clean Git tree")


def verify_tag_signature(root: Path, tag_name: str) -> None:
    """Require ``git tag -v`` success; tests may mock this boundary."""
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), "tag", "-v", tag_name],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            shell=False,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ReleaseCheckError("signed tag verification could not run") from exc
    stdout = completed.stdout if isinstance(completed.stdout, bytes) else b""
    stderr = completed.stderr if isinstance(completed.stderr, bytes) else b""
    if len(stdout) > MAX_GIT_OUTPUT or len(stderr) > MAX_GIT_OUTPUT:
        raise ReleaseCheckError("signed tag verification output exceeds bound")
    if completed.returncode != 0:
        raise ReleaseCheckError("tag signature verification failed")


def _require_signed_annotated_tag(root: Path, tag_name: str, head_commit: str) -> None:
    _require_clean_tree(root)
    try:
        tag_object = _git(root, ["rev-parse", "--verify", f"{tag_name}^{{tag}}"])
    except ReleaseCheckError as exc:
        raise ReleaseCheckError(f"{head_commit} is not tagged with {tag_name}") from exc
    assert isinstance(tag_object, str)
    width = _object_width(root)
    if not re.fullmatch(rf"[0-9a-f]{{{width}}}", tag_object.strip().lower()):
        raise ReleaseCheckError("tag did not resolve to one exact tag object")
    kind = _git(root, ["cat-file", "-t", tag_object.strip()])
    assert isinstance(kind, str)
    if kind.strip() != "tag":
        raise ReleaseCheckError("release tag must be annotated")
    target = resolve_commit(root, f"{tag_name}^{{commit}}", label="tag target")
    if target != head_commit:
        raise ReleaseCheckError("release tag does not point exactly at HEAD")
    verify_tag_signature(root, tag_name)


def _tags_pointing_at(root: Path, commit: str) -> list[str]:
    output = _git(root, ["tag", "--points-at", commit])
    assert isinstance(output, str)
    tags = [line for line in output.splitlines() if line]
    if len(tags) > 256 or any(len(tag.encode("utf-8")) > 256 for tag in tags):
        raise ReleaseCheckError("tag list exceeds bound")
    return tags


def _release_tag_from_names(tags: list[str]) -> str:
    candidates = [tag for tag in tags if tag.startswith("v")]
    valid = []
    for tag in candidates:
        try:
            SemVer.parse(tag[1:])
        except ReleaseCheckError:
            continue
        valid.append(tag)
    if len(valid) != 1:
        raise ReleaseCheckError("exactly one SemVer release tag must point at HEAD")
    return valid[0]


def _release_tag_for_head(root: Path, head_commit: str) -> str:
    return _release_tag_from_names(_tags_pointing_at(root, head_commit))


def resolve_commit(
    root: Path, ref: str, *, label: str, require_exact: bool = False
) -> str:
    if not isinstance(ref, str) or not ref or "\x00" in ref or ref.startswith("-"):
        raise ReleaseCheckError(f"{label} ref must be a non-empty string")
    output = _git(root, ["rev-parse", "--verify", f"{ref}^{{commit}}"])
    assert isinstance(output, str)
    lines = output.splitlines()
    width = _object_width(root)
    if len(lines) != 1 or not re.fullmatch(rf"[0-9a-fA-F]{{{width}}}", lines[0]):
        raise ReleaseCheckError(f"{label} ref did not resolve to one exact commit: {ref!r}")
    resolved = lines[0].lower()
    if require_exact and resolved != ref:
        raise ReleaseCheckError(
            f"{label} must be the exact lowercase commit object ID, not a moving ref"
        )
    return resolved


def find_merge_base(root: Path, base_commit: str, head_commit: str) -> str:
    output = _git(root, ["merge-base", "--all", base_commit, head_commit])
    assert isinstance(output, str)
    lines = [line for line in output.splitlines() if line]
    width = _object_width(root)
    if len(lines) != 1 or not re.fullmatch(rf"[0-9a-fA-F]{{{width}}}", lines[0]):
        raise ReleaseCheckError(
            "base and head must have exactly one merge base; history may be missing or ambiguous"
        )
    return lines[0].lower()


def require_complete_history(root: Path) -> None:
    output = _git(root, ["rev-parse", "--is-shallow-repository"])
    assert isinstance(output, str)
    value = output.strip()
    if value not in {"true", "false"}:
        raise ReleaseCheckError("Git returned an invalid shallow-repository state")
    if value == "true":
        raise ReleaseCheckError(
            "release identity requires complete Git history; shallow repositories fail closed"
        )


def _parse_name_status(output: bytes) -> list[tuple[str, tuple[str, ...]]]:
    try:
        fields = output.decode("utf-8").split("\x00")
    except UnicodeDecodeError as exc:
        raise ReleaseCheckError("Git diff contains a non-UTF-8 path") from exc
    if fields and fields[-1] == "":
        fields.pop()
    changes: list[tuple[str, tuple[str, ...]]] = []
    index = 0
    while index < len(fields):
        status = fields[index]
        index += 1
        kind = status[:1]
        if kind not in {"A", "C", "D", "M", "R", "T", "U", "X", "B"}:
            raise ReleaseCheckError(f"unrecognized Git diff status: {status!r}")
        path_count = 2 if kind in {"R", "C"} else 1
        if index + path_count > len(fields):
            raise ReleaseCheckError("malformed NUL-delimited Git diff output")
        paths = tuple(fields[index : index + path_count])
        index += path_count
        if any(not path or "\x00" in path for path in paths):
            raise ReleaseCheckError("Git diff contains an invalid empty path")
        changes.append((status, paths))
    return changes


def _diff_changes(root: Path, start: str, end: str | None) -> list[tuple[str, tuple[str, ...]]]:
    arguments = [
        "diff",
        "--name-status",
        "-z",
        "--find-renames",
        "--find-copies",
        "--diff-filter=ACDMRTUXB",
        start,
    ]
    if end is not None:
        arguments.append(end)
    arguments.append("--")
    output = _git(root, arguments, binary=True)
    assert isinstance(output, bytes)
    changes = _parse_name_status(output)
    if end is None:
        untracked = _git(
            root,
            ["ls-files", "--others", "--exclude-standard", "-z"],
            binary=True,
        )
        assert isinstance(untracked, bytes)
        try:
            paths = untracked.decode("utf-8").split("\x00")
        except UnicodeDecodeError as exc:
            raise ReleaseCheckError("Git returned a non-UTF-8 untracked path") from exc
        changes.extend(("A", (path,)) for path in paths if path)
    return changes


def is_distributable_path(path: str) -> bool:
    normalized = PurePosixPath(path).as_posix()
    return (
        normalized in {MANIFEST_PATH, MCP_PATH}
        or normalized == SKILLS_ROOT
        or normalized.startswith(SKILLS_ROOT + "/")
    )


def payload_changed(changes: list[tuple[str, tuple[str, ...]]]) -> bool:
    return any(is_distributable_path(path) for _status, paths in changes for path in paths)


def _disk_reader(root: Path) -> Callable[[str], str]:
    def read(path: str) -> str:
        pure = PurePosixPath(path)
        if pure.is_absolute() or ".." in pure.parts or "\\" in path:
            raise ReleaseCheckError(f"release metadata path escapes repository: {path}")
        target = root.joinpath(*pure.parts)
        current = root
        for part in pure.parts:
            current = current / part
            try:
                current_stat = current.stat(follow_symlinks=False)
            except OSError as exc:
                raise ReleaseCheckError(
                    f"release metadata path is unavailable: {path}"
                ) from exc
            if stat.S_ISLNK(current_stat.st_mode) or bool(
                getattr(current_stat, "st_file_attributes", 0) & 0x400
            ):
                raise ReleaseCheckError(
                    f"release metadata path crosses a link or reparse point: {path}"
                )
        try:
            target_stat = target.stat(follow_symlinks=False)
            resolved = target.resolve(strict=True)
        except OSError as exc:
            raise ReleaseCheckError(
                f"release metadata path is unavailable: {path}"
            ) from exc
        if (
            not stat.S_ISREG(target_stat.st_mode)
            or target_stat.st_nlink != 1
            or resolved != target.absolute()
        ):
            raise ReleaseCheckError(f"release metadata path is not a regular file: {path}")
        with target.open("rb") as handle:
            opened = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or (opened.st_dev, opened.st_ino)
                != (target_stat.st_dev, target_stat.st_ino)
            ):
                raise ReleaseCheckError(
                    f"release metadata path changed while opening: {path}"
                )
            raw = handle.read(MAX_FILE_BYTES + 1)
            after_read = os.fstat(handle.fileno())
            try:
                after = target.stat(follow_symlinks=False)
            except OSError as exc:
                raise ReleaseCheckError(
                    f"release metadata path changed while reading: {path}"
                ) from exc
            if (
                after_read.st_nlink != 1
                or (after_read.st_dev, after_read.st_ino)
                != (after.st_dev, after.st_ino)
            ):
                raise ReleaseCheckError(
                    f"release metadata path changed while reading: {path}"
                )
        if len(raw) > MAX_FILE_BYTES:
            raise ReleaseCheckError(f"release metadata path exceeds bound: {path}")
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ReleaseCheckError(f"release metadata is not UTF-8: {path}") from exc

    return read


def _commit_reader(root: Path, commit: str) -> Callable[[str], str]:
    def read(path: str) -> str:
        output = _git(root, ["show", f"{commit}:{path}"])
        assert isinstance(output, str)
        return output

    return read


def _literal_assignments(source: str, name: str, path: str) -> list[str]:
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError as exc:
        raise ReleaseCheckError(f"could not parse {path}: {exc}") from exc
    values: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if any(isinstance(target, ast.Name) and target.id == name for target in targets):
            value = node.value
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                values.append(value.value)
            else:
                raise ReleaseCheckError(f"{path} {name} must be a string literal")
    return values


def _client_versions(source: str) -> list[str]:
    try:
        tree = ast.parse(source, filename=ROUTING_PATH)
    except SyntaxError as exc:
        raise ReleaseCheckError(f"could not parse {ROUTING_PATH}: {exc}") from exc
    versions: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        pairs = {
            key.value: value
            for key, value in zip(node.keys, node.values)
            if isinstance(key, ast.Constant) and isinstance(key.value, str)
        }
        client_info = pairs.get("clientInfo")
        if not isinstance(client_info, ast.Dict):
            continue
        client_pairs = {
            key.value: value
            for key, value in zip(client_info.keys, client_info.values)
            if isinstance(key, ast.Constant) and isinstance(key.value, str)
        }
        version = client_pairs.get("version")
        if isinstance(version, ast.Constant) and isinstance(version.value, str):
            versions.append(version.value)
        else:
            raise ReleaseCheckError(f"{ROUTING_PATH} clientInfo version must be a string literal")
    return versions


def _manifest_version(reader: Callable[[str], str]) -> str:
    try:
        manifest = json.loads(reader(MANIFEST_PATH))
    except json.JSONDecodeError as exc:
        raise ReleaseCheckError(f"manifest is not valid JSON: {exc}") from exc
    version = manifest.get("version") if isinstance(manifest, dict) else None
    if not isinstance(version, str):
        raise ReleaseCheckError(f"manifest version is not a string: {version!r}")
    SemVer.parse(version)
    return version


def _metadata_check(
    reader: Callable[[str], str],
    *,
    root: Path,
    require_tag: bool,
    tag_commit: str,
) -> str:
    version = _manifest_version(reader)
    changelog = reader(CHANGELOG_PATH)
    match = CHANGELOG_VERSION_RE.search(changelog)
    if match is None:
        raise ReleaseCheckError("changelog has no version heading")
    SemVer.parse(match.group(1))
    if match.group(1) != version:
        raise ReleaseCheckError(
            f"manifest version {version} does not match latest changelog {match.group(1)}"
        )

    lifecycle_versions = _literal_assignments(
        reader(LIFECYCLE_PATH), "NEW_VERSION", LIFECYCLE_PATH
    )
    if lifecycle_versions != [version]:
        raise ReleaseCheckError(
            f"lifecycle NEW_VERSION must occur once and equal the manifest: {lifecycle_versions!r}"
        )
    routing_versions = _client_versions(reader(ROUTING_PATH))
    if routing_versions != [version]:
        raise ReleaseCheckError(
            f"routing clientInfo version must occur once and equal the manifest: {routing_versions!r}"
        )

    if require_tag and match.group(2).strip().lower() == "unreleased":
        raise ReleaseCheckError("tagged release still says Unreleased in CHANGELOG.md")
    return version


def run_check(root: Path, require_tag: bool) -> str:
    """Preserved compatibility API: validate checkout release metadata."""
    root = _repository_top(root)
    head_commit = resolve_commit(root, "HEAD", label="HEAD")
    disk_reader = _disk_reader(root)
    if not require_tag:
        return _metadata_check(disk_reader, root=root, require_tag=False, tag_commit=head_commit)
    # Locate the tag first.  Once a tag exists, every metadata read comes from
    # the immutable tagged commit; dirty disk bytes cannot influence the
    # candidate version or changelog decision.
    tag_names = _tags_pointing_at(root, head_commit)
    if not tag_names:
        raise ReleaseCheckError(f"{head_commit} is not tagged")
    tag_name = _release_tag_from_names(tag_names)
    _require_signed_annotated_tag(root, tag_name, head_commit)
    return _metadata_check(
        _commit_reader(root, head_commit),
        root=root,
        require_tag=True,
        tag_commit=head_commit,
    )


def validate_release_identity(
    root: Path,
    *,
    base_sha: str,
    head_sha: str | None,
    require_tag: bool = False,
    require_exact_shas: bool = False,
) -> str:
    """Validate payload changes and candidate version against an immutable base."""
    root = _repository_top(root)
    require_complete_history(root)
    base_commit = resolve_commit(
        root, base_sha, label="base", require_exact=require_exact_shas
    )
    if head_sha is None:
        if require_exact_shas:
            raise ReleaseCheckError("exact-SHA validation requires an explicit head SHA")
        head_commit = resolve_commit(root, "HEAD", label="HEAD")
    else:
        head_commit = resolve_commit(
            root, head_sha, label="head", require_exact=require_exact_shas
        )
    merge_base = find_merge_base(root, base_commit, head_commit)
    changes = _diff_changes(root, merge_base, head_commit if head_sha is not None else None)
    if require_tag:
        tag_name = _release_tag_for_head(root, head_commit)
        _require_signed_annotated_tag(root, tag_name, head_commit)
        # A tag gate reads metadata from the immutable tagged commit, never
        # from dirty checkout bytes.
        current_version = _metadata_check(
            _commit_reader(root, head_commit),
            root=root,
            require_tag=True,
            tag_commit=head_commit,
        )
    else:
        candidate_reader = (
            _disk_reader(root) if head_sha is None else _commit_reader(root, head_commit)
        )
        current_version = _metadata_check(
            candidate_reader,
            root=root,
            require_tag=False,
            tag_commit=head_commit,
        )
    if payload_changed(changes):
        base_version = _manifest_version(_commit_reader(root, base_commit))
        if compare_semver(current_version, base_version) <= 0:
            raise ReleaseCheckError(
                "distributable payload changed but candidate version "
                f"{current_version} is not greater than immutable base version {base_version}"
            )
    return current_version


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--require-tag", action="store_true")
    parser.add_argument("--base-sha")
    parser.add_argument("--head-sha")
    parser.add_argument("--require-exact-shas", action="store_true")
    args = parser.parse_args()
    if args.head_sha and not args.base_sha:
        parser.error("--head-sha requires --base-sha")
    if args.require_exact_shas and (not args.base_sha or not args.head_sha):
        parser.error("--require-exact-shas requires --base-sha and --head-sha")
    try:
        if args.base_sha:
            version = validate_release_identity(
                args.repo_root,
                base_sha=args.base_sha,
                head_sha=args.head_sha,
                require_tag=args.require_tag,
                require_exact_shas=args.require_exact_shas,
            )
        else:
            version = run_check(args.repo_root, args.require_tag)
    except (OSError, UnicodeError, ReleaseCheckError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"Release metadata and identity are valid for {version}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
