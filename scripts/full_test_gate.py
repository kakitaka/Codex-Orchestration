#!/usr/bin/env python3
"""Run the full unittest suite with a narrow native-Windows differential gate."""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import date
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import NamedTuple


HELPER_SCRIPTS = Path(__file__).resolve().parents[1] / "plugins/codex-orchestration/skills/codex-orchestration/scripts"
if str(HELPER_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(HELPER_SCRIPTS))
from bounded_run import run_bounded  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BASELINE = ROOT / "tests" / "baselines" / "windows-ee43f3a.json"
MAX_CAPTURE_BYTES = 4_000_000
MAX_REPORT_FAILURES = 100
BASELINE_TEST_COUNT = 384
WINDOWS_BASELINE_SHA256 = "b585913e579a681ed8d9b696231787f32be976a23bdb7198dec14a33e349308a"
TOP_KEYS = {"schema", "commit", "platform", "rationale", "owner", "expires", "entries"}
ENTRY_KEYS = {"kind", "node", "signature", "occurrences"}
BLOCK_RE = re.compile(
    r"={70}\r?\n(?P<kind>FAIL|ERROR): (?P<header>[^\r\n]+)\r?\n"
    r"-{70}\r?\n(?P<body>.*?)(?=(?:\r?\n={70}\r?\n)|\Z)",
    re.DOTALL,
)
NODE_RE = re.compile(r"\(((?:tests?\.)?[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+){2,})\)")
EXCEPTION_RE = re.compile(r"^(?:[A-Za-z_][\w.]*?(?:Error|Exception)):\s*.*$")
TEST_COUNT_RE = re.compile(r"\bRan\s+(\d+)\s+tests?\b")
WINDOWS_TEMP_RE = re.compile(
    r"(?i)(?:[A-Z]:)?/[^\s:'\"]*?/AppData/Local/Temp/(?:tmp|codex-)[^\s:'\"]*"
)


class Failure(NamedTuple):
    kind: str
    node: str
    signature: str


def _normalize(value: str, repo_root: Path) -> str:
    normalized = value.replace("\\", "/")
    root_text = str(repo_root.resolve()).replace("\\", "/")
    normalized = normalized.replace(root_text, "<REPO>")
    normalized = WINDOWS_TEMP_RE.sub("<TMP>", normalized)
    normalized = re.sub(r"0x[0-9a-fA-F]+", "<HEX>", normalized)
    return " ".join(normalized.split())[:1000]


def parse_failures(output: str, repo_root: Path) -> list[Failure]:
    failures: list[Failure] = []
    for match in BLOCK_RE.finditer(output):
        header = match.group("header")
        node_match = NODE_RE.search(header)
        node = node_match.group(1) if node_match else header
        body_lines = [line.strip() for line in match.group("body").splitlines()]
        signatures = [line for line in body_lines if EXCEPTION_RE.fullmatch(line)]
        signature = signatures[-1] if signatures else next(
            (line for line in reversed(body_lines) if line),
            "missing failure signature",
        )
        failures.append(
            Failure(
                match.group("kind"),
                _normalize(node, repo_root),
                _normalize(signature, repo_root),
            )
        )
    return sorted(failures)


def parse_test_count(output: str) -> int | None:
    matches = TEST_COUNT_RE.findall(output)
    return int(matches[-1]) if matches else None


def load_baseline(
    path: Path,
    *,
    today: date,
    expected_sha256: str | None = None,
) -> Counter[Failure]:
    raw = path.read_bytes()
    if len(raw) > 256 * 1024:
        raise ValueError("baseline exceeds byte limit")
    if (
        expected_sha256 is not None
        and hashlib.sha256(raw).hexdigest() != expected_sha256
    ):
        raise ValueError("baseline content differs from the bound base-commit allowlist")
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict) or set(payload) != TOP_KEYS:
        raise ValueError("baseline top-level schema mismatch")
    if payload["schema"] != 1 or payload["platform"] != "win32":
        raise ValueError("unsupported baseline schema or platform")
    if payload["commit"] != "ee43f3a522460888fa7c4174f53e9e5b4980267c":
        raise ValueError("baseline is not bound to the specification commit")
    if not all(
        isinstance(payload[key], str) and payload[key]
        for key in ("rationale", "owner", "expires")
    ):
        raise ValueError("baseline rationale, owner, and expiry are required")
    try:
        expiry = date.fromisoformat(payload["expires"])
    except ValueError as exc:
        raise ValueError("baseline expiry is invalid") from exc
    if today > expiry:
        raise ValueError("baseline expired")
    entries = payload["entries"]
    if not isinstance(entries, list) or not entries:
        raise ValueError("baseline entries must be non-empty")
    failures: Counter[Failure] = Counter()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or set(entry) != ENTRY_KEYS:
            raise ValueError(f"baseline entry {index} schema mismatch")
        if entry["kind"] not in {"FAIL", "ERROR"}:
            raise ValueError(f"baseline entry {index} kind invalid")
        if not all(
            isinstance(entry[key], str) and 0 < len(entry[key]) <= 1000
            for key in ("node", "signature")
        ):
            raise ValueError(f"baseline entry {index} values invalid")
        occurrences = entry["occurrences"]
        if not isinstance(occurrences, int) or isinstance(occurrences, bool):
            raise ValueError(f"baseline entry {index} occurrences invalid")
        if not 1 <= occurrences <= 100:
            raise ValueError(f"baseline entry {index} occurrences invalid")
        node = entry["node"]
        if "token_" in node or "playbook" in node or "full_test_gate" in node:
            raise ValueError("baseline cannot exempt token-efficiency tests")
        failure = Failure(entry["kind"], node, entry["signature"])
        if failure in failures:
            raise ValueError("baseline contains a duplicate entry")
        failures[failure] = occurrences
    return failures


def compare_failures(
    actual: Counter[Failure], expected: Counter[Failure]
) -> tuple[list[Failure], list[Failure]]:
    return sorted((actual - expected).elements()), sorted((expected - actual).elements())


def _format(failure: Failure) -> str:
    return f"{failure.kind} {failure.node}: {failure.signature}"


def run_gate(repo_root: Path, baseline_path: Path, *, platform: str) -> int:
    environment = os.environ.copy()
    environment.setdefault("PYTHONUTF8", "1")
    environment.setdefault("PYTHONIOENCODING", "utf-8")
    try:
        completed = run_bounded(
            [sys.executable, "-m", "unittest", "discover", "-s", "tests"],
            cwd=repo_root,
            env=environment,
            timeout=900,
            max_bytes=MAX_CAPTURE_BYTES,
            head_bytes=MAX_CAPTURE_BYTES - 1,
            tail_bytes=1,
        )
    except (OSError, TypeError, ValueError) as exc:
        print(
            f"FAIL: full tests could not start bounded runner: {type(exc).__name__}",
            file=sys.stderr,
        )
        return 1
    if completed.exit_category in {"start_error", "timeout", "output_limit"}:
        print(
            f"FAIL: full tests ended with {completed.exit_category}", file=sys.stderr
        )
        return 1
    output = completed.stdout_first + "\n" + completed.stderr_first
    actual = Counter(parse_failures(output, repo_root))
    test_count = parse_test_count(output)
    if test_count is None:
        print("FAIL: unittest output omitted the test count", file=sys.stderr)
        return 1
    if test_count < BASELINE_TEST_COUNT:
        print(
            f"FAIL: unittest discovered only {test_count} tests; "
            f"baseline is {BASELINE_TEST_COUNT}",
            file=sys.stderr,
        )
        return 1
    if completed.exit_code == 0:
        if actual:
            print("FAIL: unittest returned success with parsed failures", file=sys.stderr)
            return 1
        print(f"PASS: full unittest suite ({test_count} tests)")
        return 0
    if platform != "win32":
        for failure in sorted(actual)[:MAX_REPORT_FAILURES]:
            print(f"FAIL: {_format(failure)}", file=sys.stderr)
        if not actual:
            print("FAIL: unittest failed without a parseable failure", file=sys.stderr)
        return 1
    if not actual:
        print("FAIL: unittest failed without a parseable failure", file=sys.stderr)
        return 1
    try:
        expected = load_baseline(
            baseline_path,
            today=date.today(),
            expected_sha256=WINDOWS_BASELINE_SHA256,
        )
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        print(f"FAIL: invalid Windows baseline: {exc}", file=sys.stderr)
        return 1
    unexpected, resolved = compare_failures(actual, expected)
    if unexpected:
        for failure in unexpected[:MAX_REPORT_FAILURES]:
            print(f"FAIL: unexpected {_format(failure)}", file=sys.stderr)
        if not actual:
            print("FAIL: unittest failed without a parseable failure", file=sys.stderr)
        return 1
    print(
        "PASS: full suite failures are a subset of the native-Windows baseline "
        f"({test_count} tests, {sum(actual.values())} matched, {len(resolved)} resolved)"
    )
    return 0


def parse_args(arguments: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    return parser.parse_args(arguments)


def main(arguments: list[str] | None = None) -> int:
    args = parse_args(arguments)
    return run_gate(args.repo_root.resolve(), args.baseline.resolve(), platform=sys.platform)


if __name__ == "__main__":
    raise SystemExit(main())
