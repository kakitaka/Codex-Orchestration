#!/usr/bin/env python3
"""Deterministic no-model context and tooling benchmark.

The benchmark deliberately measures bytes and fixed local fixtures. It never
contacts a provider and never treats an unavailable live usage counter as zero.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile
import time
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
SKILL_REL = "plugins/codex-orchestration/skills/codex-orchestration"
SKILL_ROOT = ROOT / PurePosixPath(SKILL_REL)
BASELINE_COMMIT = "ee43f3a522460888fa7c4174f53e9e5b4980267c"
# Public compatibility constants; collect() verifies these values from the
# baseline commit object instead of trusting the constants.
BASELINE_CORE_BYTES = 56_463
BASELINE_CORE_LINES = 707
BASELINE_SKILL_MARKDOWN_BYTES = 98_030
BASELINE_AGENTS_BYTES = 732
BASELINE_AGENTS_LINES = 7
MAX_GIT_OUTPUT = 8 * 1024 * 1024
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 16 * 1024 * 1024
MAX_PATHS = 100_000
MAX_TASKS = 8
REQUIRED_TASK_NAMES = (
    "setup_status_routing",
    "small_implementation_packet",
    "duplicate_packet_wave",
    "unchanged_symbol_heading_lookup",
    "deterministic_validation_pass",
    "repeated_failure_hint",
    "bounded_noisy_tool_output",
    "exact_and_mismatched_session_lane",
)
HELPER_RELATIVE = (
    f"{SKILL_REL}/scripts/task_packet.py",
    f"{SKILL_REL}/scripts/validation_cache.py",
    f"{SKILL_REL}/scripts/bounded_run.py",
)

if str(SKILL_ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(SKILL_ROOT / "scripts"))
from bounded_run import run_bounded  # noqa: E402
from context_index import ContextIndex  # noqa: E402
from session_telemetry import SessionLaneManager  # noqa: E402
from task_packet import DuplicatePacketRegistry, build_task_packet  # noqa: E402
from token_profiles import resolve_route  # noqa: E402
from validation_cache import ValidationCache, make_validation_key  # noqa: E402


class BenchmarkError(RuntimeError):
    """The benchmark cannot establish one safe immutable Git scope."""


def _run_git(repo_root: Path, arguments: list[str], *, binary: bool = False) -> bytes | str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repo_root), *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            shell=False,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise BenchmarkError(f"Git command unavailable: {arguments!r}") from exc
    stdout = completed.stdout
    stderr = completed.stderr
    if not isinstance(stdout, bytes) or not isinstance(stderr, bytes):
        raise BenchmarkError("Git command did not return bounded bytes")
    if len(stdout) > MAX_GIT_OUTPUT or len(stderr) > MAX_GIT_OUTPUT:
        raise BenchmarkError("Git command output exceeds bound")
    if completed.returncode != 0:
        raise BenchmarkError(f"Git command failed: {arguments!r}")
    if binary:
        return stdout
    try:
        return stdout.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise BenchmarkError("Git command returned non-UTF-8 output") from exc


def _repo_scope(
    repo_root: Path, *, require_clean: bool
) -> tuple[Path, str, set[str]]:
    if repo_root.is_symlink() or bool(getattr(repo_root.stat(follow_symlinks=False), "st_file_attributes", 0) & 0x400):
        raise BenchmarkError("benchmark root is a link or reparse point")
    root = repo_root.resolve(strict=True)
    top_text = _run_git(root, ["rev-parse", "--show-toplevel"])
    assert isinstance(top_text, str)
    top = Path(top_text.strip()).resolve(strict=True)
    if top != root:
        raise BenchmarkError("benchmark root must be the exact Git top level")
    object_format = _run_git(root, ["rev-parse", "--show-object-format"])
    assert isinstance(object_format, str)
    object_format = object_format.strip()
    if object_format not in {"sha1", "sha256"}:
        raise BenchmarkError("unsupported Git object format")
    head = _run_git(root, ["rev-parse", "--verify", "HEAD^{commit}"])
    assert isinstance(head, str)
    width = 40 if object_format == "sha1" else 64
    head = head.strip().lower()
    if not re.fullmatch(rf"[0-9a-f]{{{width}}}", head):
        raise BenchmarkError("HEAD is not one exact object ID")
    if require_clean:
        dirty = _run_git(
            root,
            ["status", "--porcelain=v1", "-z", "--untracked-files=all"],
            binary=True,
        )
        assert isinstance(dirty, bytes)
        if dirty:
            raise BenchmarkError("benchmark requires a clean exact-HEAD checkout")
    raw = _run_git(root, ["ls-files", "-z"], binary=True)
    assert isinstance(raw, bytes)
    tracked: set[str] = set()
    start = 0
    while start < len(raw):
        end = raw.find(b"\0", start)
        if end < 0:
            raise BenchmarkError("tracked path list is not NUL terminated")
        item = raw[start:end]
        start = end + 1
        if not item:
            continue
        if len(tracked) >= MAX_PATHS:
            raise BenchmarkError("tracked path count exceeds bound")
        try:
            name = item.decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise BenchmarkError("tracked path is not UTF-8") from exc
        pure = PurePosixPath(name)
        if pure.is_absolute() or ".." in pure.parts or "\\" in name:
            raise BenchmarkError("tracked path is unsafe")
        tracked.add(name)
    untracked = _run_git(root, ["ls-files", "--others", "--exclude-standard", "-z"], binary=True)
    assert isinstance(untracked, bytes)
    if untracked:
        raise BenchmarkError("untracked files make the measured checkout mixed")
    return root, head, tracked


def _safe_current_path(root: Path, relative: str, tracked: set[str]) -> Path:
    if relative not in tracked:
        raise BenchmarkError(f"measured path is not tracked: {relative}")
    path = root.joinpath(*PurePosixPath(relative).parts)
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise BenchmarkError(f"measured path is unavailable: {relative}") from exc
    if path.is_symlink() or resolved != path.absolute() or not path.is_file() or path.stat(follow_symlinks=False).st_nlink != 1:
        raise BenchmarkError(f"measured path is not a regular non-link file: {relative}")
    attrs = getattr(path.stat(follow_symlinks=False), "st_file_attributes", 0)
    if attrs & 0x400:
        raise BenchmarkError(f"measured path is a reparse point: {relative}")
    return path


def _read_bounded(path: Path) -> bytes:
    with path.open("rb") as handle:
        raw = handle.read(MAX_FILE_BYTES + 1)
    if len(raw) > MAX_FILE_BYTES:
        raise BenchmarkError(f"measured file exceeds bound: {path}")
    return raw


def _baseline_blob(repo_root: Path, relative: str, *, object_width: int) -> bytes:
    value = _run_git(repo_root, ["cat-file", "blob", f"{BASELINE_COMMIT}:{relative}"], binary=True)
    assert isinstance(value, bytes)
    if len(value) > MAX_FILE_BYTES:
        raise BenchmarkError(f"baseline file exceeds bound: {relative}")
    commit = _run_git(repo_root, ["rev-parse", "--verify", f"{BASELINE_COMMIT}^{{commit}}"])
    assert isinstance(commit, str)
    if not re.fullmatch(rf"[0-9a-f]{{{object_width}}}", commit.strip().lower()):
        raise BenchmarkError("baseline commit object ID does not match hash format")
    return value


def _size(raw: bytes) -> dict[str, int]:
    return {
        "bytes": len(raw),
        "estimated_tokens_bytes_div_4": (len(raw) + 3) // 4,
        "lines": len(raw.decode("utf-8", "strict").splitlines()),
    }


def _task(
    name: str,
    before: int,
    after_paths: Iterable[Path],
    *,
    success: bool,
    test_result: str,
    detail: str = "",
) -> dict[str, object]:
    after = 0
    for path in after_paths:
        raw = _read_bounded(path)
        after += len(raw)
        if after > MAX_TOTAL_BYTES:
            raise BenchmarkError("fixture context exceeds bound")
    reduction = 0.0 if before == 0 else (before - after) / before
    return {
        "name": name,
        "before_context_bytes": before,
        "after_context_bytes": after,
        "before_estimated_tokens_bytes_div_4": (before + 3) // 4,
        "after_estimated_tokens_bytes_div_4": (after + 3) // 4,
        "estimated_context_reduction_ratio": round(reduction, 6),
        "success": bool(success),
        "test_result": test_result,
        "detail": detail,
        "live_usage": {
            "input_tokens": None,
            "cached_input_tokens": None,
            "uncached_input_tokens": None,
            "output_tokens": None,
            "reasoning_output_tokens": None,
            "cache_hit_ratio": None,
            "status": "NOT_MEASURED",
        },
    }


def _packet_fixture() -> tuple[bytes, object]:
    packet = build_task_packet(
        role="implementation-worker",
        static_rules=["Do not spawn descendants.", "fork_turns=none"],
        goal="Update one owned helper without repository-wide exploration.",
        base_revision="baseline",
        files_allowed=["scripts/example.py", "tests/test_example.py"],
        files_forbidden=[".codex-state"],
        known_facts=["The helper is deterministic."],
        constraints=["Preserve unrelated work."],
        acceptance_criteria=["Focused test passes."],
        validation="python -m unittest tests.test_example",
        output_contract="Changed files and test result only.",
    )
    return packet.canonical_bytes, packet


def _fixture_results(
    core: Path,
    references: list[Path],
    helper: Path,
    before_context: int,
) -> list[dict[str, object]]:
    packet_bytes, packet = _packet_fixture()
    registry = DuplicatePacketRegistry()
    first = registry.register(packet)
    duplicate = registry.is_duplicate(packet)
    setup_route = resolve_route(profile="balanced") == {
        "model": "gpt-5.6-terra",
        "effort": "medium",
    }
    with tempfile.TemporaryDirectory(prefix="codex-token-benchmark-") as temporary:
        fixture_root = Path(temporary)
        context_root = fixture_root / "context"
        context_root.mkdir()
        source = context_root / "routing_fixture.py"
        source.write_text(
            "# Routing status\nimport os\n\ndef routing_status():\n    return os.name\n",
            encoding="utf-8",
        )
        with ContextIndex(context_root) as index:
            indexed = index.index_file("routing_fixture.py")
            matches = index.query("routing_status")
            symbol_lookup = indexed["symbol_count"] >= 1 and any(
                item["path"] == "routing_fixture.py" for item in matches
            )

        cache_root = fixture_root / "validation"
        cache_root.mkdir()
        identity = {
            "source_blob_ids": {"src/example.py": "a" * 64},
            "lock_hashes": {"requirements.lock": "b" * 64},
            "dependency_hashes": {"dependency": "c" * 64},
            "test_hashes": {"tests/test_example.py": "d" * 64},
            "config_hashes": {"pyproject.toml": "e" * 64},
            "env_allowlist": {"PYTHONHASHSEED": "0"},
            "executable_digest": "f" * 64,
        }
        passed_key = make_validation_key(
            ["python", "-m", "unittest", "tests.test_example"], **identity
        )
        failed_key = make_validation_key(
            ["python", "-m", "unittest", "tests.test_example", "--known-failure"],
            **identity,
        )
        cache = ValidationCache(cache_root)
        cache.record_result(
            passed_key,
            status="passed",
            exit_category="success",
            exit_code=0,
            deterministic=True,
            complete=True,
        )
        validation_pass = cache.lookup_advisory(passed_key) is not None
        cache.record_result(
            failed_key,
            status="failed",
            exit_category="nonzero",
            exit_code=1,
            deterministic=True,
            complete=True,
        )
        failure_hint = cache.failure_hint(failed_key, advisory=True) is not None

        bounded = run_bounded(
            [sys.executable, "-c", "print('x' * 100000)"],
            timeout=5,
            max_bytes=1024,
            head_bytes=256,
            tail_bytes=256,
        )
        bounded_output = (
            bounded.exit_category == "output_limit"
            and bounded.truncated
            and len(bounded.stdout_first.encode("utf-8")) <= 256
            and len(bounded.stdout_last.encode("utf-8")) <= 256
        )

        lane_root = fixture_root / "lanes"
        lane_root.mkdir()
        lane_context = {
            "repo_relative": ".",
            "worktree_relative": ".",
            "branch": "main",
            "model": "gpt-5.6-luna",
            "effort": "medium",
            "cwd_relative": ".",
            "sandbox": "workspace-write",
            "approval": "never",
            "tool_profile": "default",
        }
        expires = int(time.time()) + 60
        lanes = SessionLaneManager(
            lane_root, resume_enabled=True, host_capability=True
        )
        first_lane = lanes.get_or_create(
            lane_context,
            caller_capability="benchmark-caller",
            resume_id="benchmark-session",
            task_packet_hash=packet.sha256,
            resume_expires_at=expires,
        )
        exact = lanes.resume(
            first_lane["lane_id"],
            lane_context,
            caller_capability="benchmark-caller",
            resume_id="benchmark-session",
            task_packet_hash=packet.sha256,
            resume_expires_at=expires,
        )
        mismatch = lanes.resume(
            first_lane["lane_id"],
            dict(lane_context, model="gpt-5.6-terra"),
            caller_capability="benchmark-caller",
            resume_id="benchmark-session",
            task_packet_hash=packet.sha256,
            resume_expires_at=expires,
        )
        lane = (
            exact.get("resume_id") == "benchmark-session"
            and mismatch["lane_id"] != first_lane["lane_id"]
            and "resume_id" not in mismatch
        )
    checks = (
        ("setup_status_routing", setup_route, "PASS" if setup_route else "FAIL", "adaptive route resolution"),
        ("small_implementation_packet", bool(packet_bytes), "PASS" if packet_bytes else "FAIL", "canonical packet"),
        ("duplicate_packet_wave", bool(first.accepted and duplicate), "PASS" if first.accepted and duplicate else "FAIL", "duplicate registry"),
        ("unchanged_symbol_heading_lookup", symbol_lookup, "PASS" if symbol_lookup else "FAIL", "SQLite metadata lookup"),
        ("deterministic_validation_pass", validation_pass, "PASS" if validation_pass else "FAIL", "advisory validation cache"),
        ("repeated_failure_hint", failure_hint, "PASS" if failure_hint else "FAIL", "failure hint lookup"),
        ("bounded_noisy_tool_output", bounded_output, "PASS" if bounded_output else "FAIL", "bounded process output"),
        ("exact_and_mismatched_session_lane", lane, "PASS" if lane else "FAIL", "capability-bound resume"),
    )
    paths = [references[0], helper, helper, references[1], helper, helper, core, references[2]]
    return [
        _task(
            name,
            before_context,
            [paths[index]],
            success=ok,
            test_result=result,
            detail=detail,
        )
        for index, (name, ok, result, detail) in enumerate(checks)
    ]


def collect(
    repo_root: Path = ROOT, *, require_clean: bool = True
) -> dict[str, object]:
    root, head, tracked = _repo_scope(repo_root, require_clean=require_clean)
    object_format = _run_git(root, ["rev-parse", "--show-object-format"])
    assert isinstance(object_format, str)
    width = 40 if object_format.strip() == "sha1" else 64
    baseline_core_raw = _baseline_blob(root, f"{SKILL_REL}/SKILL.md", object_width=width)
    baseline_agents_raw = _baseline_blob(root, "AGENTS.md", object_width=width)
    core = _safe_current_path(root, f"{SKILL_REL}/SKILL.md", tracked)
    agents = _safe_current_path(root, "AGENTS.md", tracked)
    refs = [
        _safe_current_path(root, f"{SKILL_REL}/references/{name}", tracked)
        for name in (
            "native-lifecycle.md",
            "planner-advisor-workflow.md",
            "delegation.md",
            "external-models.md",
            "invocation-and-routing.md",
        )
    ]
    helpers = [_safe_current_path(root, path, tracked) for path in HELPER_RELATIVE]
    markdown_names = sorted(
        path for path in tracked if path.startswith(SKILL_REL + "/") and path.endswith(".md")
    )
    markdown_paths = [_safe_current_path(root, name, tracked) for name in markdown_names]
    normal_paths = [path for path in markdown_paths if path.name != "compatibility-contract.md"]
    packet_bytes, _packet = _packet_fixture()
    baseline_tree = _run_git(root, ["ls-tree", "-r", "--name-only", BASELINE_COMMIT, "--", SKILL_REL])
    assert isinstance(baseline_tree, str)
    baseline_markdown = sum(
        len(_baseline_blob(root, name, object_width=width))
        for name in baseline_tree.splitlines()
        if name.endswith(".md")
    )
    before_always_loaded = len(baseline_core_raw) + len(baseline_agents_raw)
    after_always_loaded = len(_read_bounded(core)) + len(_read_bounded(agents))
    tasks = _fixture_results(core, refs, helpers[0], len(baseline_core_raw))
    return {
        "schema": 2,
        "baseline_commit": BASELINE_COMMIT,
        "measurement_kind": "deterministic_bytes_and_bytes_div_4_estimate",
        "paid_model_calls": 0,
        "git_scope": {
            "top_level": ".",
            "head_commit": head,
            "object_format": object_format.strip(),
            "tracked": True,
            "immutable_baseline": True,
            "clean_exact_head": require_clean,
        },
        "core_skill": {"before": _size(baseline_core_raw), "after": _size(_read_bounded(core))},
        "skill_markdown": {
            "before_bytes": baseline_markdown,
            "after_all_bytes": sum(len(_read_bounded(path)) for path in markdown_paths),
            "after_normal_route_bytes": sum(len(_read_bounded(path)) for path in normal_paths),
            "compatibility_archive_loaded_by_default": False,
        },
        "agents_context": {"before": _size(baseline_agents_raw), "after": _size(_read_bounded(agents))},
        "always_loaded_context": {
            "before_bytes": before_always_loaded,
            "after_bytes": after_always_loaded,
            "estimated_reduction_ratio": round(
                (before_always_loaded - after_always_loaded) / before_always_loaded, 6
            ),
        },
        "task_packet_fixture": {
            "bytes": len(packet_bytes),
            "estimated_tokens_bytes_div_4": (len(packet_bytes) + 3) // 4,
            "sha256": hashlib.sha256(packet_bytes).hexdigest(),
        },
        "helpers": {path.relative_to(root).as_posix(): len(_read_bounded(path)) for path in helpers},
        "fixed_tasks": tasks,
    }


def parse_args(arguments: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    parser.add_argument("--pretty", action="store_true")
    return parser.parse_args(arguments)


def main(arguments: list[str] | None = None) -> int:
    args = parse_args(arguments)
    try:
        payload = collect(args.repo_root)
        tasks = payload["fixed_tasks"]
        if len(tasks) != MAX_TASKS or tuple(task["name"] for task in tasks) != REQUIRED_TASK_NAMES:
            raise BenchmarkError("fixed fixture inventory is incomplete")
        if not all(task.get("success") and task.get("test_result") == "PASS" for task in tasks):
            raise BenchmarkError("one or more deterministic fixtures failed")
    except (BenchmarkError, OSError, UnicodeError, ValueError, SyntaxError) as exc:
        print(f"FAIL: benchmark unavailable: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            payload,
            ensure_ascii=False,
            indent=2 if args.pretty else None,
            sort_keys=True,
            separators=None if args.pretty else (",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
