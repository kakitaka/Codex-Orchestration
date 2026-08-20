#!/usr/bin/env python3
"""Deterministic, no-model token-regression scanner.

The scanner reports small, actionable findings rather than attempting to
estimate model usage.  It intentionally ignores this repository's long
implementation specification and test fixtures so examples of a violation do
not become violations themselves.
"""

from __future__ import annotations

import argparse
import ast
from dataclasses import dataclass
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import subprocess
import sys
from typing import Iterable, Sequence
from urllib.parse import unquote


MAX_SKILL_BYTES = 12 * 1024
MAX_SKILL_LINES = 350
MAX_AGENTS_BYTES = 16 * 1024
MAX_AGENTS_LINES = 500
MAX_FILE_BYTES = 2 * 1024 * 1024
DEFAULT_MAX_FINDINGS = 200
MAX_TRACKED_PATH_BYTES = 8 * 1024 * 1024
MAX_TOPLEVEL_PATH_BYTES = 64 * 1024
_PROMPT_MAX_DEFAULT_RE = re.compile(
    r"(?i)(?:\bdefault(?:s|ed)?(?:\s+to)?\s+|"
    r"\b(?:model_)?reasoning_effort\b\s*[:=]\s*)[`\"']?(?:max|xhigh)\b"
)
_SECRET_LITERAL_RE = re.compile(
    r"(?:-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|\bAKIA[0-9A-Z]{16}\b|"
    r"\b(?:gh[pousr]|github_pat_)[A-Za-z0-9_-]{20,}\b|"
    r"\b(?:sk|rk)-[A-Za-z0-9_-]{20,}\b)"
)

_IMPLEMENTATION_SPEC = "CODEX_TOKEN_EFFICIENCY_IMPLEMENTATION.md"
_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    ".venv",
    "venv",
    "node_modules",
}
_TEXT_SUFFIXES = {
    ".md",
    ".markdown",
    ".py",
    ".json",
    ".toml",
    ".yaml",
    ".yml",
    ".ini",
    ".cfg",
    ".txt",
    ".sh",
    ".ps1",
    ".bat",
    ".cmd",
}
_SOURCE_SUFFIXES = {".py", ".json", ".toml", ".yaml", ".yml", ".ini", ".cfg", ".sh", ".ps1", ".bat", ".cmd"}


@dataclass(frozen=True, order=True)
class Finding:
    code: str
    path: str
    line: int
    message: str

    def as_dict(self) -> dict[str, object]:
        return {"code": self.code, "path": self.path, "line": self.line, "message": self.message}

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: {self.code}: {self.message}"


class GitTrackingUnavailable(RuntimeError):
    """A Git worktree could not provide its authoritative tracked path set."""


def _relative(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def _git_tracked_paths(root: Path) -> set[str]:
    """Return the authoritative Git-tracked paths or fail closed."""

    try:
        top = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--show-toplevel"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )
        raw_top = top.stdout
        if not isinstance(raw_top, bytes) or len(raw_top) > MAX_TOPLEVEL_PATH_BYTES:
            raise ValueError("repository top-level path exceeds bound")
        top_text = raw_top.decode("utf-8", "strict").rstrip("\r\n")
        if not top_text or "\r" in top_text or "\n" in top_text:
            raise ValueError("invalid repository top-level path")
        top_path = Path(top_text).resolve(strict=True)
        if os.path.normcase(str(top_path)) != os.path.normcase(str(root.resolve())):
            raise ValueError("token lint root is not the repository top level")
        completed = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )
        raw = completed.stdout
        if not isinstance(raw, bytes) or len(raw) > MAX_TRACKED_PATH_BYTES:
            raise ValueError("tracked path list exceeds bound")
        return {item for item in raw.decode("utf-8", "strict").split("\0") if item}
    except (OSError, subprocess.SubprocessError, UnicodeDecodeError, ValueError):
        # A failed or non-Git root has no safe filesystem fallback: arbitrary
        # local files may hold private state unrelated to repository content.
        raise GitTrackingUnavailable("git ls-files unavailable")


def _tracked_regular_file(
    root: Path, path: Path, tracked_paths: set[str]
) -> bool:
    """Check one tracked file without following a link/reparse escape."""

    try:
        relative_name = path.relative_to(root).as_posix()
    except ValueError:
        return False
    if relative_name not in tracked_paths:
        return False
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        return False
    expected = Path(os.path.abspath(path))
    if os.path.normcase(str(resolved)) != os.path.normcase(str(expected)):
        return False
    return path.is_file() and not path.is_symlink()


def _classify_tracked_files(
    root: Path, tracked_paths: set[str]
) -> tuple[list[Path], list[str]]:
    """Partition Git-index paths into safe regular files and unsafe entries."""

    regular: list[Path] = []
    unsafe: list[str] = []
    for relative_name in sorted(tracked_paths):
        pure = PurePosixPath(relative_name)
        if pure.is_absolute() or not pure.parts or ".." in pure.parts:
            unsafe.append("<invalid-git-path>")
            continue
        path = root.joinpath(*pure.parts)
        if not _tracked_regular_file(root, path, tracked_paths):
            unsafe.append(relative_name)
            continue
        if any(part in _SKIP_DIRS for part in pure.parts[:-1]):
            continue
        regular.append(path)
    return regular, unsafe


def _is_spec(path: Path) -> bool:
    return path.name == _IMPLEMENTATION_SPEC


def _is_fixture(path: Path, root: Path) -> bool:
    relative_parts = {part.lower() for part in path.relative_to(root).parts}
    return "tests" in relative_parts or "fixtures" in relative_parts or path.name.startswith("test_")


def _read(path: Path) -> tuple[str, int] | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if len(data) > MAX_FILE_BYTES:
        return None
    return data.decode("utf-8", errors="replace"), len(data)


def _line_at(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _add(findings: list[Finding], code: str, root: Path, path: Path, line: int, message: str) -> None:
    findings.append(Finding(code, _relative(root, path), max(1, line), message))


def _check_budgets(findings: list[Finding], root: Path, path: Path, text: str, size: int) -> None:
    if path.name == "AGENTS.md":
        if size > MAX_AGENTS_BYTES:
            _add(findings, "AGENTS_BYTES", root, path, 1, f"AGENTS.md is {size} bytes; limit is {MAX_AGENTS_BYTES}")
        lines = len(text.splitlines())
        if lines > MAX_AGENTS_LINES:
            _add(findings, "AGENTS_LINES", root, path, MAX_AGENTS_LINES + 1, f"AGENTS.md has {lines} lines; limit is {MAX_AGENTS_LINES}")
    if path.name == "SKILL.md":
        if size > MAX_SKILL_BYTES:
            _add(findings, "SKILL_BYTES", root, path, 1, f"core SKILL.md is {size} bytes; limit is {MAX_SKILL_BYTES}")
        lines = len(text.splitlines())
        if lines > MAX_SKILL_LINES:
            _add(findings, "SKILL_LINES", root, path, MAX_SKILL_LINES + 1, f"core SKILL.md has {lines} lines; limit is {MAX_SKILL_LINES}")
    if path.name in {"AGENTS.md", "SKILL.md"}:
        match = _PROMPT_MAX_DEFAULT_RE.search(text)
        if match:
            _add(
                findings,
                "ACCIDENTAL_MAX_DEFAULT",
                root,
                path,
                _line_at(text, match.start()),
                "always-loaded prompt makes max/xhigh a default",
            )


_MD_LINK_RE = re.compile(r"!?(?:\[[^\]]*\])\(([^)]+)\)")


def _check_links(
    findings: list[Finding],
    root: Path,
    path: Path,
    text: str,
    tracked_paths: set[str],
) -> None:
    if _is_spec(path):
        return
    in_fence = False
    for index, line in enumerate(text.splitlines(), 1):
        if line.strip().startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        for match in _MD_LINK_RE.finditer(line):
            target = match.group(1).strip().strip("<>")
            target = unquote(target.split("#", 1)[0].split("?", 1)[0])
            if not target or target.startswith(("http://", "https://", "mailto:", "data:")):
                continue
            if re.match(r"^[A-Za-z]:[\\/]", target) or target.startswith(("/", "\\")):
                _add(findings, "BROKEN_REFERENCE", root, path, index, "reference link is absolute")
                continue
            source_parent = PurePosixPath(path.relative_to(root).as_posix()).parent
            normalized = posixpath.normpath(
                (source_parent / target.replace("\\", "/")).as_posix()
            )
            if normalized == "." or normalized == ".." or normalized.startswith("../"):
                exists_in_index = False
            else:
                prefix = normalized.rstrip("/") + "/"
                exists_in_index = normalized in tracked_paths or any(
                    item.startswith(prefix) for item in tracked_paths
                )
            if not exists_in_index:
                _add(
                    findings,
                    "BROKEN_REFERENCE",
                    root,
                    path,
                    index,
                    "reference link target is not tracked",
                )


def _check_secret_literals(
    findings: list[Finding], root: Path, path: Path, text: str
) -> None:
    if _is_spec(path) or _is_fixture(path, root) or path.name in {
        "bounded_run.py",
        "task_packet.py",
        "token_lint.py",
    }:
        return
    match = _SECRET_LITERAL_RE.search(text)
    if match:
        _add(
            findings,
            "SECRET_LITERAL",
            root,
            path,
            _line_at(text, match.start()),
            "credential-like literal must not be committed",
        )


def _paragraphs(text: str) -> Iterable[tuple[int, str]]:
    start = 1
    block: list[str] = []
    in_fence = False
    for index, line in enumerate(text.splitlines(), 1):
        if line.strip().startswith("```"):
            in_fence = not in_fence
        if not line.strip() and not in_fence:
            if block:
                yield start, " ".join(block)
                block = []
            start = index + 1
        else:
            if not block:
                start = index
            if not in_fence:
                block.append(line.strip())
    if block:
        yield start, " ".join(block)


def _check_duplicate_blocks(findings: list[Finding], root: Path, documents: list[tuple[Path, str]]) -> None:
    blocks: dict[str, list[tuple[Path, int]]] = {}
    for path, text in documents:
        if _is_spec(path) or _is_fixture(path, root):
            continue
        for line, block in _paragraphs(text):
            normalized = re.sub(r"\s+", " ", block).strip()
            if len(normalized) < 240:
                continue
            blocks.setdefault(normalized, []).append((path, line))
    for normalized, occurrences in sorted(blocks.items(), key=lambda item: item[0]):
        unique = sorted(set(occurrences), key=lambda item: (_relative(root, item[0]), item[1]))
        if len(unique) < 2:
            continue
        for path, line in unique[1:]:
            _add(findings, "DUPLICATE_PROMPT_BLOCK", root, path, line, "large stable prompt block is repeated")


def _max_allowed(path: Path, root: Path) -> bool:
    relative = path.relative_to(root).as_posix().lower()
    if path.suffix.lower() == ".md" or path.name.lower() in {"agents.md", "readme.md", "changelog.md"}:
        return True
    if relative.startswith("tests/") or relative.startswith("docs/"):
        return True
    # Exact repository-required worker/profile route; arbitrary runtime files
    # remain subject to the regression check.
    return relative == "plugins/codex-orchestration/skills/codex-orchestration/scripts/token_profiles.py"


_MAX_RE = re.compile(
    r"(?ix)(?:(?:\b(?:model_reasoning_effort|reasoning_effort|effort|service_tier)\b|\b[A-Za-z_][A-Za-z0-9_]*effort\b)\s*[:=]\s*|"
    r"--(?:reasoning-)?effort\s+|\b(?:default|value)\s*[:=]\s*)[\"']?(max|xhigh)\b"
)
_FORK_ALL_RE = re.compile(r"(?i)\bfork_turns?\b\s*[=:]\s*[\"']all[\"']")
_FIXED_WORKER_RE = re.compile(
    r"(?i)\b(?:max_(?:concurrent_)?workers?|worker_(?:count_)?limit|concurrency_limit)\b\s*[:=]\s*\d+"
)
_PACKET_NAME_RE = re.compile(r"(?i)(?:packet|prompt)")
_TIME_SOURCE_RE = re.compile(r"(?i)\b(?:datetime(?:\.datetime)?\.(?:now|utcnow)|time\.(?:time|time_ns)|uuid\.(?:uuid1|uuid4)|uuid[14])\s*\(")
_USER_PATH_RE = re.compile(
    r'''(?i)(?:["'](?:[A-Z]:[\\/]Users[\\/]|/home/[^"']+)|\b(?:Path\.(?:home|cwd)|os\.(?:environ|getcwd)|getenv)\b)'''
)


def _check_source_rules(findings: list[Finding], root: Path, path: Path, text: str) -> None:
    if _is_spec(path) or _is_fixture(path, root) or path.name == "token_lint.py":
        return
    if path.suffix.lower() not in _SOURCE_SUFFIXES:
        return
    for index, line in enumerate(text.splitlines(), 1):
        if not _max_allowed(path, root) and _MAX_RE.search(line):
            _add(findings, "ACCIDENTAL_MAX_DEFAULT", root, path, index, "max/xhigh is used as a runtime default; keep high effort opt-in")
        if not _max_allowed(path, root) and _FORK_ALL_RE.search(line) and "Never use fork_turns" not in line:
            _add(findings, "FORK_TURNS_ALL", root, path, index, "runtime prompt/config must use fork_turns=none, not all")
        if _FIXED_WORKER_RE.search(line):
            _add(findings, "FIXED_WORKER_LIMIT", root, path, index, "worker concurrency must be governed by packet/wave budgets, not a fixed count")
    if _PACKET_NAME_RE.search(path.stem) or "TASK_PACKET" in text:
        if _TIME_SOURCE_RE.search(text):
            _add(findings, "DYNAMIC_PACKET_SOURCE", root, path, _line_at(text, _TIME_SOURCE_RE.search(text).start()), "stable packet/prompt builder reads a timestamp or UUID source")
        user_match = _USER_PATH_RE.search(text)
        if user_match and not (path.name == "task_packet.py" and "Path.cwd() / root" in text):
            _add(findings, "USER_PATH_IN_PACKET", root, path, _line_at(text, user_match.start()), "stable packet/prompt builder reads an absolute user path or ambient identity")


_PYTEST_VERBOSE_RE = re.compile(r"(?i)\bpytest\b[^\n]*-vv\b")
_RECURSIVE_LIST_RE = re.compile(
    r"(?ix)(?:\bls\s+-R\b|\bfind\s+\.\s+|\b(?:Get-ChildItem|gci)\b[^\n]*-Recurse|"
    r"(?:^\s*tree(?:\s+[-/]|\s*$)|[\"']tree[\"']|(?:^|[;&|])\s*tree(?:\s+[-/A-Za-z.]|\s*$)))"
)


def _check_noisy_defaults(findings: list[Finding], root: Path, path: Path, text: str) -> None:
    if _is_spec(path) or _is_fixture(path, root) or path.name in {"token_lint.py", "token_hook.py"} or _max_allowed(path, root):
        return
    if path.suffix.lower() not in _SOURCE_SUFFIXES:
        return
    for index, line in enumerate(text.splitlines(), 1):
        command_context = (
            line.lstrip().startswith(("pytest ", "python -m pytest", "git ", "find ", "ls ", "tree"))
            or any(token in line for token in ("subprocess.", "Popen(", "run(", "os.system", "shell_command"))
        )
        if command_context and _PYTEST_VERBOSE_RE.search(line):
            _add(findings, "NOISY_PYTEST", root, path, index, "pytest -vv default produces unbounded verbose output")
        if command_context and _RECURSIVE_LIST_RE.search(line):
            _add(findings, "RECURSIVE_LISTING", root, path, index, "recursive listing default can flood tool output")
        git = re.search(r"(?i)\bgit\s+(diff|log)\b([^\n]*)", line)
        if command_context and git and not re.search(r"(?i)(?:--stat\b|--name(?:-only|-status)\b|--oneline\b|-n\s*\d+|--max-count(?:=|\s+)\d+|\s--\s+\S+)", git.group(2)):
            _add(findings, "UNBOUNDED_GIT_OUTPUT", root, path, index, f"git {git.group(1).lower()} lacks a count, summary, or target path")
        if re.search(r"(?i)(?:print\s*\(|stdout\.(?:write|writelines)\s*\()[^\n]*json\.dumps\([^\n]*(?:indent\s*=|\b(?:data|records|history|output|results|huge|large)\b)", line):
            _add(findings, "HUGE_JSON_OUTPUT", root, path, index, "JSON output should be bounded or summarized")


def _check_artifacts(
    findings: list[Finding], root: Path, path: Path, tracked_paths: set[str] | None = None
) -> None:
    if _is_spec(path) or _is_fixture(path, root) or path.name == ".gitignore":
        return
    relative = path.relative_to(root).parts
    lowered = [part.lower() for part in relative]
    name = path.name.lower()
    relative_name = path.relative_to(root).as_posix()
    if tracked_paths is not None and relative_name not in tracked_paths:
        return
    in_codex_state = ".codex-state" in lowered
    if in_codex_state:
        _add(findings, "COMMITTED_CODEX_STATE", root, path, 1, "generated .codex-state must not be committed")
    if path.suffix.lower() == ".log" or (
        path.suffix.lower() == ".jsonl"
        and any(token in name or token in lowered for token in ("telemetry", "conversation", "transcript", "raw", "session"))
    ):
        _add(findings, "RAW_TELEMETRY_ARTIFACT", root, path, 1, "raw telemetry, log, or conversation artifact must not be committed")
    elif any(token in name for token in ("conversation", "transcript", "raw-output", "raw_output")):
        _add(findings, "RAW_CONVERSATION_ARTIFACT", root, path, 1, "raw conversation/tool output must not be committed")


def _check_mcp(findings: list[Finding], root: Path, path: Path, text: str) -> None:
    if _is_spec(path) or _is_fixture(path, root):
        return
    if path.name == ".mcp.json" or path.suffix.lower() in _SOURCE_SUFFIXES:
        for index, line in enumerate(text.splitlines(), 1):
            if re.search(r"(?i)[\"'](?:include_all_tools|all_tools|expose_all_tools)[\"']\s*:\s*true", line):
                _add(findings, "BROAD_MCP_DEFAULT", root, path, index, "MCP config exposes all tools by default")
            if re.search(r"(?i)[\"']tools[\"']\s*:\s*\[\s*[\"']\*[\"']\s*\]", line):
                _add(findings, "BROAD_MCP_DEFAULT", root, path, index, "MCP config uses a wildcard tool set")


EXPECTED_PACKET_KEYS = (
    "VERSION",
    "ROLE",
    "STATIC_RULES",
    "GOAL",
    "BASE_REVISION",
    "FILES_ALLOWED",
    "FILES_FORBIDDEN",
    "KNOWN_FACTS",
    "CONSTRAINTS",
    "ACCEPTANCE_CRITERIA",
    "VALIDATION",
    "OUTPUT_CONTRACT",
)
REQUIRED_HELPERS = {
    "bounded_run.py",
    "context_index.py",
    "safe_state.py",
    "session_telemetry.py",
    "task_packet.py",
    "token_hook.py",
    "token_profiles.py",
    "validation_cache.py",
}


def _literal_assignment(path: Path, name: str) -> tuple[object, int] | None:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, SyntaxError):
        return None
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if not any(isinstance(target, ast.Name) and target.id == name for target in targets):
            continue
        try:
            return ast.literal_eval(node.value), node.lineno
        except (TypeError, ValueError):
            return None
    return None


def _check_repository_contracts(
    findings: list[Finding], root: Path, tracked_paths: set[str]
) -> None:
    skill_root = root / "plugins/codex-orchestration/skills/codex-orchestration"
    manifest = root / "plugins/codex-orchestration/.codex-plugin/plugin.json"
    if not _tracked_regular_file(root, manifest, tracked_paths):
        return
    scripts = skill_root / "scripts"
    for name in sorted(REQUIRED_HELPERS):
        target = scripts / name
        if not _tracked_regular_file(root, target, tracked_paths):
            _add(findings, "PACKAGE_OMISSION", root, manifest, 1, f"required helper missing: {name}")
    packet_path = scripts / "task_packet.py"
    assignment = (
        _literal_assignment(packet_path, "PACKET_KEYS")
        if _tracked_regular_file(root, packet_path, tracked_paths)
        else None
    )
    if assignment is None or assignment[0] != EXPECTED_PACKET_KEYS:
        line = 1 if assignment is None else assignment[1]
        _add(findings, "TASK_PACKET_ORDER", root, packet_path, line, "TASK_PACKET_V1 fields do not match the stable canonical order")
    profiles_path = scripts / "token_profiles.py"
    profiles_tracked = _tracked_regular_file(root, profiles_path, tracked_paths)
    names = _literal_assignment(profiles_path, "PROFILE_NAMES") if profiles_tracked else None
    default = _literal_assignment(profiles_path, "DEFAULT_PROFILE") if profiles_tracked else None
    if names is None or names[0] != ("legacy", "lean", "balanced", "quality"):
        _add(findings, "PROFILE_SCHEMA", root, profiles_path, 1 if names is None else names[1], "token profile names changed")
    if default is None or default[0] != "legacy":
        _add(findings, "PROFILE_SCHEMA", root, profiles_path, 1 if default is None else default[1], "implicit profile migration is forbidden")
    routing_path = scripts / "configure_native_routing.py"
    routing_tracked = _tracked_regular_file(root, routing_path, tracked_paths)
    profile_schema = (
        _literal_assignment(routing_path, "PROFILE_STATE_SCHEMA")
        if routing_tracked
        else None
    )
    if profile_schema is None or profile_schema[0] != 6:
        _add(findings, "PROFILE_SCHEMA", root, routing_path, 1 if profile_schema is None else profile_schema[1], "profile state schema must remain explicit version 6")
    advisor_limit = (
        _literal_assignment(routing_path, "ADVISOR_REVIEW_LIMIT")
        if routing_tracked
        else None
    )
    if routing_tracked:
        try:
            routing_text = routing_path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            routing_text = ""
    else:
        routing_text = ""
    if advisor_limit is None or advisor_limit[0] != 8 or "profile.advisor_loops" not in routing_text:
        _add(
            findings,
            "ADVISOR_LIMIT",
            root,
            routing_path,
            1 if advisor_limit is None else advisor_limit[1],
            "legacy and profile Advisor limits must remain explicit and bounded",
        )


def scan(root: str | Path, *, max_findings: int = DEFAULT_MAX_FINDINGS) -> list[Finding]:
    """Scan root and return deterministic findings, capped at max_findings."""
    base = Path(root).resolve()
    if not base.exists() or not base.is_dir():
        raise ValueError(f"root is not a directory: {root}")
    findings: list[Finding] = []
    documents: list[tuple[Path, str]] = []
    try:
        tracked_paths = _git_tracked_paths(base)
    except GitTrackingUnavailable:
        if max_findings <= 0:
            return []
        return [
            Finding(
                "GIT_TRACKING_UNAVAILABLE",
                ".git",
                1,
                "tracked file discovery failed; token lint did not scan filesystem fallbacks",
            )
        ]
    regular_files, unsafe_paths = _classify_tracked_files(base, tracked_paths)
    for relative_name in unsafe_paths:
        findings.append(
            Finding(
                "UNSAFE_TRACKED_PATH",
                relative_name,
                1,
                "Git-index entry is missing, non-regular, or escapes through a link/reparse point",
            )
        )
    for path in regular_files:
        if path.name == _IMPLEMENTATION_SPEC:
            # Still inspect its presence as an artifact only if it is not the
            # named implementation specification; all content rules exclude it.
            continue
        read = _read(path)
        if read is not None:
            text, size = read
            if path.suffix.lower() in _TEXT_SUFFIXES:
                documents.append((path, text))
                _check_budgets(findings, base, path, text, size)
                if path.suffix.lower() in {".md", ".markdown"}:
                    _check_links(findings, base, path, text, tracked_paths)
                _check_secret_literals(findings, base, path, text)
                _check_source_rules(findings, base, path, text)
                _check_noisy_defaults(findings, base, path, text)
                _check_mcp(findings, base, path, text)
        _check_artifacts(findings, base, path, tracked_paths)
    _check_duplicate_blocks(findings, base, documents)
    _check_repository_contracts(findings, base, tracked_paths)
    # Path/line order matches ordinary linter output and is independent of
    # filesystem traversal order.
    findings.sort(key=lambda finding: (finding.path, finding.line, finding.code, finding.message))
    if max_findings < 0:
        raise ValueError("max_findings must not be negative")
    return findings[:max_findings]


def lint(root: str | Path, *, max_findings: int = DEFAULT_MAX_FINDINGS) -> list[Finding]:
    return scan(root, max_findings=max_findings)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--max-findings", type=int, default=DEFAULT_MAX_FINDINGS)
    parser.add_argument("--json", action="store_true", dest="as_json")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    # Ask for one extra item so JSON output can accurately state truncation.
    collected = scan(args.root, max_findings=args.max_findings + 1 if args.max_findings >= 0 else args.max_findings)
    truncated = len(collected) > args.max_findings if args.max_findings >= 0 else False
    findings = collected[:args.max_findings]
    if args.as_json:
        payload = {
            "findings": [finding.as_dict() for finding in findings],
            "truncated": truncated,
        }
        sys.stdout.write(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
    else:
        for finding in findings:
            sys.stdout.write(str(finding) + "\n")
        if not findings:
            sys.stdout.write("token_lint: clean\n")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
