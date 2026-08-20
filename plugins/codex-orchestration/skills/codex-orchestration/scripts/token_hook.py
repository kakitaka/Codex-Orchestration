#!/usr/bin/env python3
"""Opt-in, fail-open Codex hook guard for noisy tool requests.

Only response shapes supported by the Codex 0.147 hook contract are emitted:
``systemMessage`` for a non-blocking PreToolUse warning and
``hookSpecificOutput.additionalContext`` for UserPromptSubmit. The helper never
rewrites a command and never treats PostToolUse as an output-replacement channel.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
import threading
from typing import Any, Mapping, Sequence, TextIO

from bounded_run import run_bounded


MAX_INPUT_BYTES = 64 * 1024
MAX_INPUT_SECONDS = 2.0
MAX_REASON_CHARS = 500
MAX_CONTEXT_CHARS = 400
MIN_CODEX_HOOK_VERSION = (0, 147, 0)
PROBE_TIMEOUT_SECONDS = 2.0
_PRE_REQUIRED = frozenset(
    {
        "cwd",
        "hook_event_name",
        "model",
        "permission_mode",
        "session_id",
        "tool_input",
        "tool_name",
        "tool_use_id",
        "transcript_path",
        "turn_id",
    }
)
_PROMPT_REQUIRED = frozenset(
    {
        "cwd",
        "hook_event_name",
        "model",
        "permission_mode",
        "prompt",
        "session_id",
        "transcript_path",
        "turn_id",
    }
)
_OPTIONAL_HOOK_FIELDS = frozenset({"agent_id", "agent_type"})
_HOOK_EVENTS = frozenset({"PreToolUse", "UserPromptSubmit"})

_RECURSIVE_RE = re.compile(
    r"(?ix)(?:\bfind\s+\.(?:\s|$)|\b(?:find|tree)\b[^\n]*\s(?:-|/)(?:r|R)\b|"
    r"\b(?:ls|dir|gci|Get-ChildItem)\b[^\n]*(?:\s-R\b|--recursive|/s\b|-Recurse\b)|"
    r"\brg\b[^\n]*--files[^\n]*(?:\s[.*/]|$))"
)
_VERBOSE_TEST_RE = re.compile(
    r"(?ix)(?:pytest|py\.test|tox|npm\s+(?:test|run\s+test)|cargo\s+test|"
    r"go\s+test|mvn\s+test)[^\n]*(?:-vv\b|--verbose\b|-vvvv\b)"
)
_VERBOSE_BUILD_RE = re.compile(
    r"(?ix)(?:cargo\s+build|cmake\s+--build|make\b|ninja\b|npm\s+run\s+build|"
    r"gradle\b)[^\n]*(?:-vv\b|--verbose\b|\sV=1\b)"
)
_UNBOUNDED_GIT_RE = re.compile(
    r"(?ix)\bgit\s+(diff|log)\b(?P<args>[^\n]*)"
)
_NOISY_LOG_RE = re.compile(r"(?ix)\b(?:cat|type|Get-Content)\b[^\n]*(?:\.log\b|log[/\\])")


def _read_bounded(stream: Any, limit: int = MAX_INPUT_BYTES, timeout: float = MAX_INPUT_SECONDS) -> bytes:
    """Read at most limit+1 bytes from a text or binary stream."""
    reader = getattr(stream, "buffer", stream)
    result: list[Any] = []
    error: list[BaseException] = []

    def read_once() -> None:
        try:
            result.append(reader.read(limit + 1))
        except BaseException as exc:  # surfaced below without blocking the hook
            error.append(exc)

    thread = threading.Thread(target=read_once, daemon=True)
    thread.start()
    thread.join(timeout=max(0.01, timeout))
    if thread.is_alive():
        raise TimeoutError("bounded stdin read timed out")
    if error:
        raise error[0]
    data = result[0] if result else b""
    if isinstance(data, str):
        data = data.encode("utf-8", errors="replace")
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("stdin did not return bytes")
    return bytes(data)


def _emit(value: Mapping[str, Any], output: TextIO) -> None:
    # Compact sorted JSON makes stdout machine-readable and deterministic.
    output.write(json.dumps(dict(value), ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    output.write("\n")


def _diagnostic(message: str, diagnostics: TextIO) -> None:
    safe = " ".join(str(message).split())[:300]
    diagnostics.write(f"token_hook: {safe}\n")


def _validate_nested_tool_input(value: Any, *, depth: int = 0, items: list[int] | None = None) -> None:
    if items is None:
        items = [0]
    if depth > 12:
        raise ValueError("tool input nesting exceeds bound")
    if isinstance(value, Mapping):
        items[0] += len(value)
        if items[0] > 512:
            raise ValueError("tool input item bound exceeded")
        for key, child in value.items():
            if not isinstance(key, str) or len(key) > 512:
                raise ValueError("tool input key is malformed")
            _validate_nested_tool_input(child, depth=depth + 1, items=items)
    elif isinstance(value, (list, tuple)):
        items[0] += len(value)
        if items[0] > 512:
            raise ValueError("tool input item bound exceeded")
        for child in value:
            _validate_nested_tool_input(child, depth=depth + 1, items=items)
    elif isinstance(value, (str, int, float, bool)) or value is None:
        if isinstance(value, str) and len(value) > 16 * 1024:
            raise ValueError("tool input string bound exceeded")
        if isinstance(value, int) and not isinstance(value, bool):
            raise ValueError("tool input integer is unsupported")
        if isinstance(value, float) and not value.is_integer():
            raise ValueError("tool input number is malformed")
    else:
        raise ValueError("tool input value is malformed")


def _official_event(payload: Mapping[str, Any]) -> str | None:
    if "hook_event_name" not in payload:
        return None
    event = payload.get("hook_event_name")
    if not isinstance(event, str) or event not in _HOOK_EVENTS:
        return None
    required = _PRE_REQUIRED if event == "PreToolUse" else _PROMPT_REQUIRED
    if not required <= set(payload) <= required | _OPTIONAL_HOOK_FIELDS:
        return None
    if event == "PreToolUse":
        if not isinstance(payload.get("tool_input"), Mapping):
            return None
        try:
            _validate_nested_tool_input(payload["tool_input"])
        except (TypeError, ValueError, RecursionError):
            return None
    fields = required - {"tool_input"}
    for field in fields:
        value = payload.get(field)
        if not isinstance(value, str) or not value or len(value) > 32 * 1024:
            return None
        if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
            return None
    if event == "UserPromptSubmit":
        prompt = payload.get("prompt")
        if not isinstance(prompt, str) or len(prompt) > 32 * 1024:
            return None
    for field in _OPTIONAL_HOOK_FIELDS & set(payload):
        value = payload[field]
        if not isinstance(value, str) or len(value) > 1024:
            return None
    return event


def _parse_version(text: str) -> tuple[int, int, int] | None:
    match = re.fullmatch(r"\s*(?:codex-cli\s+)?(\d+)\.(\d+)(?:\.(\d+))?\s*", text)
    if not match:
        return None
    return (
        int(match.group(1)),
        int(match.group(2)),
        int(match.group(3) or 0),
    )


def probe_host_capability(executable: str | None = None) -> bool:
    """Bounded, read-only probe for the current Codex hooks capability."""

    binary = executable or os.environ.get("CODEX_BIN") or "codex"
    if not isinstance(binary, str) or not binary or len(binary) > 512:
        return False
    try:
        with tempfile.TemporaryDirectory(prefix="codex-hook-probe-") as probe_home:
            env = os.environ.copy()
            env["CODEX_HOME"] = probe_home
            version_result = run_bounded(
                [binary, "--version"],
                env=env,
                timeout=PROBE_TIMEOUT_SECONDS,
                max_bytes=8 * 1024,
                head_bytes=4 * 1024,
                tail_bytes=4 * 1024,
            )
            if version_result.exit_category != "ok":
                return False
            version = _parse_version(version_result.stdout_first or "")
            if version is None or version < MIN_CODEX_HOOK_VERSION:
                return False
            feature_result = run_bounded(
                [binary, "features", "list"],
                env=env,
                timeout=PROBE_TIMEOUT_SECONDS,
                max_bytes=8 * 1024,
                head_bytes=4 * 1024,
                tail_bytes=4 * 1024,
            )
    except (OSError, ValueError):
        return False
    if feature_result.exit_category != "ok":
        return False
    feature_output = (
        feature_result.stdout_first + "\n" + feature_result.stdout_last
    )
    lines = [
        " ".join(line.strip().split()).lower()
        for line in feature_output.splitlines()
    ]
    if any(
        re.fullmatch(
            r"(?:hooks|codex_hooks|hook_events)(?:\s*=\s*|\s+)"
            r"(?:(?:stable|under[- ]development|experimental)\s+)?(?:true|enabled)",
            line,
        )
        for line in lines
    ):
        return True
    for line in feature_output.splitlines():
        try:
            value = json.loads(line)
        except (TypeError, json.JSONDecodeError):
            continue
        if isinstance(value, Mapping):
            if value.get("hooks") is True or value.get("hooks_enabled") is True:
                return True
            features = value.get("features")
            if isinstance(features, Mapping) and features.get("hooks") is True:
                return True
    return False


def _event(payload: Mapping[str, Any]) -> str:
    for key in ("event", "hook_event_name", "event_name", "type"):
        value = payload.get(key)
        if isinstance(value, str):
            value = value.strip()
            aliases = {
                "pretooluse": "PreToolUse",
                "pre_tool_use": "PreToolUse",
                "userpromptsubmit": "UserPromptSubmit",
                "user_prompt_submit": "UserPromptSubmit",
                "posttooluse": "PostToolUse",
                "post_tool_use": "PostToolUse",
            }
            return aliases.get(value.lower(), value)
    return ""


def _command(payload: Mapping[str, Any]) -> str | None:
    tool_input: Any = payload.get("tool_input", payload.get("input"))
    if not isinstance(tool_input, Mapping):
        tool_input = payload
    for key in ("command", "cmd", "shell_command"):
        value = tool_input.get(key)
        if isinstance(value, str):
            return value
        if isinstance(value, (list, tuple)) and all(isinstance(item, str) for item in value):
            # Joining is for inspection only; no rewritten value is returned.
            return " ".join(value)
    return None


def _high_confidence_finding(command: str) -> tuple[str, str] | None:
    normalized = command.strip()
    if not normalized:
        return None
    if _RECURSIVE_RE.search(normalized):
        return "warn", "recursive repository listing may produce unbounded output; target a path or bound the listing"
    if _VERBOSE_TEST_RE.search(normalized):
        return "warn", "verbose test output is noisy; use the narrow test target without -vv/--verbose"
    if _VERBOSE_BUILD_RE.search(normalized):
        return "warn", "verbose build output is noisy; use the narrow target without -vv/--verbose"
    match = _UNBOUNDED_GIT_RE.search(normalized)
    if match:
        args = match.group("args")
        bounded = re.search(
            r"(?ix)(?:--stat\b|--name-only\b|--name-status\b|--oneline\b|-n\s*\d+|"
            r"--max-count(?:=|\s+)\d+|-\d+\b|\s--\s+\S+)",
            args,
        )
        if not bounded:
            return "warn", f"unbounded git {match.group(1).lower()} may flood context; add a count, summary, or target path"
    if _NOISY_LOG_RE.search(normalized):
        return "warn", "full log output is noisy; select a bounded tail or targeted range"
    return None


def process_payload(
    payload: Mapping[str, Any],
    *,
    enabled: bool = True,
    host_capable: bool | None = None,
    diagnostics: TextIO | None = None,
) -> dict[str, Any]:
    """Return one supported hook response, or an empty fail-open response."""
    diagnostics = diagnostics or sys.stderr
    if not isinstance(payload, Mapping):
        return {}
    if host_capable is None:
        host_capable = "hook_event_name" not in payload
    if (
        type(enabled) is not bool
        or not enabled
        or type(host_capable) is not bool
        or not host_capable
    ):
        return {}
    official_event = _official_event(payload)
    if "hook_event_name" in payload:
        if official_event is None:
            _diagnostic("malformed official hook input; manual fallback", diagnostics)
            return {}
        event = official_event
    else:
        # Compatibility for callers that use the pre-0.147 helper API. The
        # live CLI always validates official schemas before dispatch.
        event = _event(payload)
    if event == "PreToolUse":
        command = _command(payload)
        if command is None:
            _diagnostic("PreToolUse command shape is unsupported; manual review required", diagnostics)
            return {}
        finding = _high_confidence_finding(command)
        if finding is None:
            return {}
        _decision, reason = finding
        return {"systemMessage": reason[:MAX_REASON_CHARS]}
    if event == "UserPromptSubmit":
        # This is deliberately a short static hint.  It does not echo or index
        # the user's prompt, and it is opt-in through the CLI/env gate.
        return {
            "hookSpecificOutput": {
                "hookEventName": "UserPromptSubmit",
                "additionalContext": (
                    "Keep tool output bounded: target paths, avoid recursive listings and "
                    "verbose tests, and summarize large logs."
                )[:MAX_CONTEXT_CHARS],
            }
        }
    if event == "PostToolUse":
        _diagnostic("PostToolUse output replacement is unsupported; inspect output manually", diagnostics)
        return {}
    if event:
        # Event names originate in untrusted hook JSON.  Never echo an
        # unsupported value into diagnostics where it could disclose a token.
        _diagnostic("unsupported hook event; manual fallback", diagnostics)
    else:
        _diagnostic("missing or unsupported hook event; manual fallback", diagnostics)
    return {}


def _parse_input(data: bytes) -> Mapping[str, Any] | None:
    if len(data) > MAX_INPUT_BYTES:
        return None
    try:
        parsed = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, MemoryError, ValueError):
        return None
    return parsed if isinstance(parsed, Mapping) else None


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--enable", "--opt-in", "--enabled",
        action="store_true",
        help="enable the opt-in guard (without this switch it emits an empty response)",
    )
    parser.add_argument(
        "--codex-bin",
        default=None,
        help="Codex executable used for the bounded live capability probe",
    )
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    stdin: Any = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    args = _build_parser().parse_args(argv)
    stdin = sys.stdin if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    stderr = sys.stderr if stderr is None else stderr
    try:
        raw = _read_bounded(stdin)
    except (OSError, TypeError, ValueError, TimeoutError) as exc:
        _diagnostic(f"input unavailable ({type(exc).__name__}); manual fallback", stderr)
        _emit({}, stdout)
        return 0
    payload = _parse_input(raw)
    if payload is None:
        if len(raw) > MAX_INPUT_BYTES:
            _diagnostic("input exceeds bounded size; manual fallback", stderr)
        else:
            _diagnostic("malformed or unsupported JSON input; manual fallback", stderr)
        _emit({}, stdout)
        return 0
    host_capable = False
    if args.enable:
        # Legacy helper payloads are retained for local/manual callers. Only
        # the official 0.147 envelope may claim a live host capability.
        host_capable = (
            True
            if "hook_event_name" not in payload
            else probe_host_capability(args.codex_bin)
        )
        if "hook_event_name" in payload and not host_capable:
            _diagnostic("Codex hook capability unavailable; manual fallback", stderr)
    _emit(
        process_payload(
            payload,
            enabled=args.enable,
            host_capable=host_capable,
            diagnostics=stderr,
        ),
        stdout,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
