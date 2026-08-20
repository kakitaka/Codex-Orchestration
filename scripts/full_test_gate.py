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
MAX_TEST_IDS = 10_000
MAX_INVENTORY_BYTES = 256 * 1024
TEST_INVENTORY_PATH = ROOT / "tests" / "test_inventory.json"
WINDOWS_BASELINE_SHA256 = "b585913e579a681ed8d9b696231787f32be976a23bdb7198dec14a33e349308a"
# These pre-existing native-routing failures are part of the immutable specification
# baseline.  Keep the general protected-test rule intact while allowing only
# this exact, content-bound legacy set to remain in that baseline.
LEGACY_BASELINE_NODE_PREFIXES = ("test_native_routing.NativeRoutingTests.",)
LEGACY_BASELINE_NODES = {
    "test_configure_orchestration.ConfigureOrchestrationTests.test_atomic_update_preserves_security_metadata",
}
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
TEST_ID_RE = re.compile(
    r"^(?P<id>test_[A-Za-z0-9_]+\s+\([^\r\n]+\))\s+\.\.\."
)
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
    if not isinstance(output, str) or len(output.encode("utf-8", "replace")) > MAX_CAPTURE_BYTES:
        raise ValueError("test output exceeds parse bound")
    failures: list[Failure] = []
    for index, match in enumerate(BLOCK_RE.finditer(output)):
        if index >= MAX_TEST_IDS:
            raise ValueError("failure block count exceeds bound")
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
    if not isinstance(output, str) or len(output.encode("utf-8", "replace")) > MAX_CAPTURE_BYTES:
        return None
    matches = TEST_COUNT_RE.findall(output)
    return int(matches[-1]) if matches else None


def discover_test_ids(output: str) -> tuple[str, ...]:
    """Extract the exact unittest IDs from verbose output, with hard bounds."""
    if not isinstance(output, str) or len(output.encode("utf-8", "replace")) > MAX_CAPTURE_BYTES:
        raise ValueError("test output exceeds inventory parse bound")
    found: list[str] = []
    seen: set[str] = set()
    for line in output.splitlines():
        match = TEST_ID_RE.match(line)
        if match is None:
            continue
        test_id = match.group("id")
        if test_id in seen:
            raise ValueError(f"duplicate discovered test ID: {test_id}")
        if len(found) >= MAX_TEST_IDS:
            raise ValueError("discovered test ID count exceeds bound")
        seen.add(test_id)
        found.append(test_id)
    return tuple(sorted(found))


def classify_test_id(test_id: str) -> str:
    lowered = test_id.lower()
    if any(token in lowered for token in (
        "token", "bounded_run", "playbook", "full_test_gate", "preflight",
        "release_check", "packaging", "plugin_lifecycle", "task_packet",
        "validation_cache", "safe_state", "context_index", "session_telemetry",
        "token_hook", "token_profiles", "token_budget", "efficiency",
        "external_credentials", "native_routing", "routing_state",
    )):
        return "protected-tooling-security"
    if "security" in lowered or "credential" in lowered or "secret" in lowered:
        return "protected-tooling-security"
    return "ordinary"


def _read_bounded(path: Path, limit: int, label: str) -> bytes:
    with path.open("rb") as handle:
        raw = handle.read(limit + 1)
    if len(raw) > limit:
        raise ValueError(f"{label} exceeds byte limit")
    return raw


def load_test_inventory(path: Path) -> tuple[tuple[str, ...], dict[str, str]]:
    raw = _read_bounded(path, MAX_INVENTORY_BYTES, "test inventory")
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict) or set(payload) != {"schema", "test_ids", "protected"}:
        raise ValueError("test inventory schema mismatch")
    if payload["schema"] != 1:
        raise ValueError("unsupported test inventory schema")
    ids = payload["test_ids"]
    if not isinstance(ids, list) or len(ids) > MAX_TEST_IDS or any(
        not isinstance(item, str) or not item or len(item) > 512 for item in ids
    ) or ids != sorted(set(ids)):
        raise ValueError("test inventory IDs must be sorted and unique")
    protected = payload["protected"]
    if not isinstance(protected, dict) or len(protected) > MAX_TEST_IDS:
        raise ValueError("test inventory protected classification is malformed")
    if any(
        not isinstance(key, str) or key not in ids or value != "protected-tooling-security"
        for key, value in protected.items()
    ):
        raise ValueError("test inventory protected classification is malformed")
    return tuple(ids), dict(protected)


def compare_test_inventory(
    actual_ids: tuple[str, ...], expected_ids: tuple[str, ...], expected_protected: dict[str, str]
) -> tuple[list[str], list[str], list[str]]:
    actual = set(actual_ids)
    expected = set(expected_ids)
    unexpected = sorted(actual - expected)
    missing = sorted(expected - actual)
    classification = sorted(
        test_id
        for test_id in expected & actual
        if classify_test_id(test_id) != expected_protected.get(test_id, "ordinary")
    )
    return unexpected, missing, classification


def load_baseline(
    path: Path,
    *,
    today: date,
    expected_sha256: str | None = None,
) -> Counter[Failure]:
    raw = _read_bounded(path, 256 * 1024, "baseline")
    content_digest = hashlib.sha256(raw).hexdigest()
    if (
        expected_sha256 is not None
        and content_digest != expected_sha256
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
        legacy_node = (
            expected_sha256 == WINDOWS_BASELINE_SHA256
            and content_digest == WINDOWS_BASELINE_SHA256
            and (
                node in LEGACY_BASELINE_NODES
                or any(node.startswith(prefix) for prefix in LEGACY_BASELINE_NODE_PREFIXES)
            )
        )
        if classify_test_id(node) != "ordinary" and not legacy_node:
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


def run_gate(
    repo_root: Path,
    baseline_path: Path,
    *,
    platform: str,
    inventory_path: Path = TEST_INVENTORY_PATH,
) -> int:
    environment = os.environ.copy()
    environment.setdefault("PYTHONUTF8", "1")
    environment.setdefault("PYTHONIOENCODING", "utf-8")
    try:
        completed = run_bounded(
            [sys.executable, "-m", "unittest", "discover", "-v", "-s", "tests"],
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
    if completed.exit_category in {"start_error", "timeout", "output_limit", "cleanup_error"}:
        print(
            f"FAIL: full tests ended with {completed.exit_category}", file=sys.stderr
        )
        return 1
    output = completed.stdout_first + "\n" + completed.stderr_first
    try:
        actual = Counter(parse_failures(output, repo_root))
        actual_ids = discover_test_ids(output)
        expected_ids, protected = load_test_inventory(inventory_path.resolve())
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        print(f"FAIL: exact test inventory unavailable: {exc}", file=sys.stderr)
        return 1
    unexpected_ids, missing_ids, classification = compare_test_inventory(
        actual_ids, expected_ids, protected
    )
    if unexpected_ids or missing_ids or classification:
        if unexpected_ids:
            print(f"FAIL: unexpected test IDs: {unexpected_ids[:MAX_REPORT_FAILURES]}", file=sys.stderr)
        if missing_ids:
            print(f"FAIL: missing test IDs: {missing_ids[:MAX_REPORT_FAILURES]}", file=sys.stderr)
        if classification:
            print(f"FAIL: protected test classification drift: {classification[:MAX_REPORT_FAILURES]}", file=sys.stderr)
        return 1
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
    parser.add_argument("--inventory", type=Path, default=TEST_INVENTORY_PATH)
    return parser.parse_args(arguments)


def main(arguments: list[str] | None = None) -> int:
    args = parse_args(arguments)
    return run_gate(
        args.repo_root.resolve(),
        args.baseline.resolve(),
        platform=sys.platform,
        inventory_path=args.inventory.resolve(),
    )


if __name__ == "__main__":
    raise SystemExit(main())
