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
import re
import sys
import threading
from typing import Any, Mapping, Sequence, TextIO


MAX_INPUT_BYTES = 64 * 1024
MAX_INPUT_SECONDS = 2.0
MAX_REASON_CHARS = 500
MAX_CONTEXT_CHARS = 400

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
    diagnostics: TextIO | None = None,
) -> dict[str, Any]:
    """Return one supported hook response, or an empty fail-open response."""
    diagnostics = diagnostics or sys.stderr
    if not enabled:
        return {}
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
        _diagnostic(f"unsupported hook event {event!r}; manual fallback", diagnostics)
    else:
        _diagnostic("missing or unsupported hook event; manual fallback", diagnostics)
    return {}


def _parse_input(data: bytes) -> Mapping[str, Any] | None:
    if len(data) > MAX_INPUT_BYTES:
        return None
    try:
        parsed = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, MemoryError):
        return None
    return parsed if isinstance(parsed, Mapping) else None


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--enable", "--opt-in", "--enabled",
        action="store_true",
        help="enable the opt-in guard (without this switch it emits an empty response)",
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
    _emit(process_payload(payload, enabled=args.enable, diagnostics=stderr), stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
