#!/usr/bin/env python3
"""Read existing Codex session counters into a privacy-safe aggregate.

This helper is deliberately passive: it makes no network or model calls, writes
no state, and emits no session IDs, paths, prompts, source, or tool output.
It sums event-level ``last_token_usage`` only; cumulative counters are never
summed because doing so would double-count a session.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import math
from pathlib import Path
import re
import sys
from typing import Any, Iterable


UTC = timezone.utc
WEEKLY_WINDOW_MINUTES = 10_080
MAX_PERIOD_DAYS = 32
MAX_FILES = 4_096
MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_LINE_CHARS = 4 * 1024 * 1024
MAX_TOKEN_COUNT = 10**12
MAX_METADATA_DEPTH = 8
MODEL_RE = re.compile(
    r"(?i)(?:gpt-[0-9]{1,2}(?:\.[0-9]{1,2}){0,2}"
    r"(?:-(?:luna|terra|sol|codex))?|o[1-9](?:-(?:mini|pro))?|"
    r"codex-mini-latest)"
)
EFFORTS = {"minimal", "low", "medium", "high", "xhigh", "max", "ultra"}

# Composition is compared by usage-event share.  A ten percentage-point
# absolute difference is the largest change still treated as a like-for-like
# observation.  This is deliberately fixed and visible in the report docs so
# a later caller cannot silently tune the comparison to its result.
MIX_TOLERANCE = 0.10
ROOT_OR_LEGACY = "root_or_legacy"
WORKER = "worker"
ROOT_WORKER_CLASSES = (ROOT_OR_LEGACY, WORKER)
TASK_FAMILIES = (
    "implementation",
    "research",
    "audit",
    "validation",
    "documentation",
    "configuration",
    "operations",
    "testing",
    "other",
)
_TASK_FAMILY_ALIASES = {
    "implementation": "implementation",
    "implementation-worker": "implementation",
    "impl": "implementation",
    "build": "implementation",
    "coding": "implementation",
    "research": "research",
    "research-worker": "research",
    "audit": "audit",
    "review": "audit",
    "validation": "validation",
    "verification": "validation",
    "testing": "testing",
    "test": "testing",
    "documentation": "documentation",
    "docs": "documentation",
    "configuration": "configuration",
    "config": "configuration",
    "operations": "operations",
    "operation": "operations",
}
_WORKER_MARKERS = {
    "worker",
    "execution-worker",
    "implementation-worker",
    "verification-worker",
    "research-worker",
    "subagent",
    "child",
    "executor",
}
_ROOT_MARKERS = {
    "root",
    "root-or-legacy",
    "root_or_legacy",
    "legacy",
    "orchestrator",
    "main",
    "parent",
}


class PassiveUsageError(ValueError):
    """The local log scope cannot be measured safely."""


@dataclass(frozen=True)
class Period:
    start: datetime
    end: datetime

    @property
    def duration_seconds(self) -> float:
        return (self.end - self.start).total_seconds()

    def contains(self, moment: datetime) -> bool:
        return self.start <= moment < self.end


@dataclass
class ScanStats:
    files_seen: int = 0
    files_read: int = 0
    unreadable_files: int = 0
    oversized_files: int = 0
    lines_seen: int = 0
    malformed_lines: int = 0
    oversized_lines: int = 0
    out_of_period_records: int = 0
    invalid_timestamps: int = 0
    invalid_usage_events: int = 0
    rate_observations: int = 0

    def as_dict(self) -> dict[str, int]:
        return {
            "files_seen": self.files_seen,
            "files_read": self.files_read,
            "unreadable_files": self.unreadable_files,
            "oversized_files": self.oversized_files,
            "lines_seen": self.lines_seen,
            "malformed_lines": self.malformed_lines,
            "oversized_lines": self.oversized_lines,
            "out_of_period_records": self.out_of_period_records,
            "invalid_timestamps": self.invalid_timestamps,
            "invalid_usage_events": self.invalid_usage_events,
            "rate_observations": self.rate_observations,
        }


@dataclass
class UsageTotals:
    usage_events: int = 0
    paired_input_events: int = 0
    unpaired_input_events: int = 0
    output_events: int = 0
    reasoning_output_events: int = 0
    cache_write_events: int = 0
    input_tokens: int = 0
    cached_input_tokens: int = 0
    output_tokens: int = 0
    reasoning_output_tokens: int = 0
    cache_write_input_tokens: int = 0

    def add(self, usage: Mapping[str, Any]) -> bool:
        input_tokens = _token_count(usage.get("input_tokens"))
        cached_input_tokens = _token_count(usage.get("cached_input_tokens"))
        output_tokens = _token_count(usage.get("output_tokens"))
        reasoning_output_tokens = _token_count(usage.get("reasoning_output_tokens"))
        cache_write_input_tokens = _token_count(usage.get("cache_write_input_tokens"))
        values = (
            input_tokens,
            cached_input_tokens,
            output_tokens,
            reasoning_output_tokens,
            cache_write_input_tokens,
        )
        if not any(value is not None for value in values):
            return False
        self.usage_events += 1
        if input_tokens is not None and cached_input_tokens is not None:
            if cached_input_tokens > input_tokens:
                self.unpaired_input_events += 1
            else:
                self.paired_input_events += 1
                self.input_tokens += input_tokens
                self.cached_input_tokens += cached_input_tokens
        elif input_tokens is not None or cached_input_tokens is not None:
            self.unpaired_input_events += 1
        if output_tokens is not None:
            self.output_events += 1
            self.output_tokens += output_tokens
        if reasoning_output_tokens is not None:
            self.reasoning_output_events += 1
            self.reasoning_output_tokens += reasoning_output_tokens
        if cache_write_input_tokens is not None:
            self.cache_write_events += 1
            self.cache_write_input_tokens += cache_write_input_tokens
        return True

    def as_dict(self, period: Period) -> dict[str, Any]:
        has_input = self.paired_input_events > 0
        has_output = self.output_events > 0
        has_reasoning = self.reasoning_output_events > 0
        has_cache_write = self.cache_write_events > 0
        input_tokens = self.input_tokens if has_input else None
        cached_input_tokens = self.cached_input_tokens if has_input else None
        uncached_input_tokens = (
            self.input_tokens - self.cached_input_tokens if has_input else None
        )
        cache_hit_ratio = (
            _round(self.cached_input_tokens / self.input_tokens)
            if has_input and self.input_tokens > 0
            else None
        )
        return {
            "status": "MEASURED" if self.usage_events else "NOT_MEASURED",
            "usage_events": self.usage_events,
            "paired_input_events": self.paired_input_events,
            "unpaired_input_events": self.unpaired_input_events,
            "input_tokens": input_tokens,
            "cached_input_tokens": cached_input_tokens,
            "uncached_input_tokens": uncached_input_tokens,
            "cache_write_input_tokens": (
                self.cache_write_input_tokens if has_cache_write else None
            ),
            "output_tokens": self.output_tokens if has_output else None,
            "reasoning_output_tokens": (
                self.reasoning_output_tokens if has_reasoning else None
            ),
            "cache_hit_ratio": cache_hit_ratio,
            "rates_per_usage_event": {
                "input_tokens": _per_usage_event(input_tokens, self.usage_events),
                "uncached_input_tokens": _per_usage_event(
                    uncached_input_tokens, self.usage_events
                ),
            },
            "rates_per_hour": {
                "usage_events": _per_hour(self.usage_events, period),
                "input_tokens": _per_hour(input_tokens, period),
                "uncached_input_tokens": _per_hour(uncached_input_tokens, period),
                "output_tokens": _per_hour(
                    self.output_tokens if has_output else None, period
                ),
            },
        }


@dataclass(frozen=True)
class RateObservation:
    timestamp: datetime
    reset_bucket: int
    used_percent: float


def _parse_instant(value: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        result = datetime.fromisoformat(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timestamp must be ISO-8601 with timezone") from exc
    if result.tzinfo is None:
        raise argparse.ArgumentTypeError("timestamp must include timezone")
    return result.astimezone(UTC)


def _log_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return _parse_instant(value)
    except argparse.ArgumentTypeError:
        return None


def _format_instant(moment: datetime) -> str:
    return moment.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _token_count(value: Any) -> int | None:
    if type(value) is int and 0 <= value <= MAX_TOKEN_COUNT:
        return value
    return None


def _number(value: Any, *, lower: float, upper: float) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    result = float(value)
    if not math.isfinite(result) or not lower <= result <= upper:
        return None
    return result


def _mapping(value: Any) -> Mapping[str, Any] | None:
    return value if isinstance(value, Mapping) else None


def _safe_model(value: Any) -> str:
    if isinstance(value, str) and MODEL_RE.fullmatch(value):
        return value
    return "unknown"


def _safe_effort(value: Any) -> str:
    return value if isinstance(value, str) and value in EFFORTS else "unknown"


def _safe_marker(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    # Metadata is used only as a bounded classifier.  Never preserve the raw
    # value, including when it is malformed or contains user task text.
    return value.strip().lower()[:128]


def _role_from_mapping(
    payload: Mapping[str, Any], *, _depth: int = 0
) -> str | None:
    """Classify explicit role metadata; absent/malformed means legacy root."""

    if _depth >= MAX_METADATA_DEPTH:
        return None
    supplied = False
    for key in ("is_worker", "worker", "worker_mode", "is_subagent"):
        supplied = supplied or key in payload
        value = payload.get(key)
        if type(value) is bool:
            return WORKER if value else ROOT_OR_LEGACY
    for key in (
        "root_worker",
        "root_or_worker",
        "agent_role",
        "execution_role",
        "task_role",
        "worker_role",
        "lane_role",
        "thread_role",
        "role_kind",
        "agent_kind",
        "agent_type",
        "thread_source",
        "role",
    ):
        supplied = supplied or key in payload
        marker = _safe_marker(payload.get(key))
        if marker in _WORKER_MARKERS or marker.endswith("-worker"):
            return WORKER
        if marker in _ROOT_MARKERS:
            return ROOT_OR_LEGACY
    source = _mapping(payload.get("source"))
    if source is not None and "subagent" in source:
        # Session metadata represents thread source as a tagged mapping.  Key
        # presence is sufficient; never inspect or export its nested payload.
        return WORKER
    for key in ("agent", "worker_metadata", "metadata"):
        nested = _mapping(payload.get(key))
        if nested is not None:
            role = _role_from_mapping(nested, _depth=_depth + 1)
            if role is not None:
                return role
    return ROOT_OR_LEGACY if supplied else None


def _task_family_value(value: Any) -> str | None:
    marker = _safe_marker(value)
    if not marker:
        return None
    return _TASK_FAMILY_ALIASES.get(marker)


def _task_family_from_mapping(
    payload: Mapping[str, Any], *, _depth: int = 0
) -> str | None:
    """Read only fixed task-family metadata and discard all raw task labels."""

    if _depth > 3:
        return "other"
    for key in (
        "task_family",
        "task_packet_family",
        "task_kind",
        "task_type",
        "family",
        "task_family_name",
    ):
        family = _task_family_value(payload.get(key))
        if family is not None:
            return family
        if key in payload and payload.get(key) is not None:
            # An explicitly supplied but unknown family is still a measured
            # event in the bounded ``other`` bucket.
            return "other"
    for key in ("task", "task_packet", "packet"):
        nested = _mapping(payload.get(key))
        if nested is None:
            if key in payload and payload.get(key) is not None:
                return "other"
            continue
        family = _task_family_from_mapping(nested, _depth=_depth + 1)
        if family is not None:
            return family
    return None


def _metadata_update(
    payload: Mapping[str, Any], role: str, task_family: str
) -> tuple[str, str]:
    role_value = _role_from_mapping(payload)
    family_value = _task_family_from_mapping(payload)
    if role_value is not None:
        role = role_value
    if family_value is not None:
        task_family = family_value
    return role, task_family


def _round(value: float) -> float:
    return round(value, 6)


def _per_hour(value: int | None, period: Period) -> float | None:
    if value is None or period.duration_seconds <= 0:
        return None
    return _round(value * 3600 / period.duration_seconds)


def _per_usage_event(value: int | None, usage_events: int) -> float | None:
    """Return a token average without treating missing counters as zero."""

    if value is None or usage_events <= 0:
        return None
    return _round(value / usage_events)


def _is_link_or_reparse(path: Path) -> bool:
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError:
        return True
    return path.is_symlink() or bool(attributes & 0x400)


def _session_files(root: Path, period: Period) -> list[Path]:
    if _is_link_or_reparse(root):
        raise PassiveUsageError("sessions root is a link or reparse point")
    try:
        resolved_root = root.resolve(strict=True)
    except OSError as exc:
        raise PassiveUsageError("sessions root is unavailable") from exc
    if not resolved_root.is_dir():
        raise PassiveUsageError("sessions root is not a directory")
    first_day = (period.start - timedelta(days=1)).date()
    last_day = (period.end + timedelta(days=1)).date()
    if (last_day - first_day).days + 1 > MAX_PERIOD_DAYS:
        raise PassiveUsageError("measurement period exceeds 32 days")
    files: list[Path] = []
    day = first_day
    while day <= last_day:
        directory = resolved_root / f"{day.year:04d}" / f"{day.month:02d}" / f"{day.day:02d}"
        if directory.exists() and directory.is_dir() and not _is_link_or_reparse(directory):
            for path in sorted(directory.glob("*.jsonl")):
                if _is_link_or_reparse(path) or not path.is_file():
                    continue
                try:
                    resolved = path.resolve(strict=True)
                    resolved.relative_to(resolved_root)
                except (OSError, ValueError):
                    continue
                files.append(resolved)
                if len(files) > MAX_FILES:
                    raise PassiveUsageError("session file bound exceeded")
        day += timedelta(days=1)
    return files


def _weekly_observation(
    payload: Mapping[str, Any], timestamp: datetime
) -> RateObservation | None:
    limits = _mapping(payload.get("rate_limits"))
    primary = _mapping(limits.get("primary")) if limits else None
    if primary is None:
        return None
    window = primary.get("window_minutes")
    reset = _number(primary.get("resets_at"), lower=0, upper=4_102_444_800)
    used_percent = _number(primary.get("used_percent"), lower=0, upper=100)
    if type(window) is not int or window != WEEKLY_WINDOW_MINUTES:
        return None
    if reset is None or used_percent is None:
        return None
    return RateObservation(
        timestamp=timestamp,
        reset_bucket=int(round(reset / 60) * 60),
        used_percent=used_percent,
    )


def _weekly_summary(observations: Iterable[RateObservation]) -> dict[str, Any]:
    grouped: dict[int, list[RateObservation]] = defaultdict(list)
    for observation in observations:
        grouped[observation.reset_bucket].append(observation)
    windows: list[dict[str, Any]] = []
    for reset_bucket in sorted(grouped):
        samples = sorted(
            grouped[reset_bucket], key=lambda item: (item.timestamp, item.used_percent)
        )
        first = samples[0]
        high_water = first
        high_water_count = 1
        for sample in samples[1:]:
            if sample.used_percent > high_water.used_percent:
                high_water = sample
                high_water_count += 1
        delta = high_water.used_percent - first.used_percent
        elapsed_seconds = (high_water.timestamp - first.timestamp).total_seconds()
        measured = delta > 0 and elapsed_seconds > 0
        used_percent_per_hour = _round(delta * 3600 / elapsed_seconds) if measured else None
        windows.append(
            {
                "status": "MEASURED" if measured else "NOT_MEASURED",
                "reset_at": _format_instant(datetime.fromtimestamp(reset_bucket, UTC)),
                "observations": len(samples),
                "high_water_observations": high_water_count,
                "first_observed_at": _format_instant(first.timestamp),
                "last_high_water_at": _format_instant(high_water.timestamp),
                "first_used_percent": _round(first.used_percent),
                "last_used_percent": _round(high_water.used_percent),
                "used_percent_delta": _round(delta),
                "elapsed_seconds": int(elapsed_seconds),
                "used_percent_per_hour": used_percent_per_hour,
                "minutes_per_percentage_point": (
                    _round(60 / used_percent_per_hour)
                    if used_percent_per_hour not in {None, 0}
                    else None
                ),
            }
        )
    return {
        "status": "MEASURED" if any(item["status"] == "MEASURED" for item in windows) else "NOT_MEASURED",
        "windows": windows,
    }


def _period_from_datetimes(start: datetime, end: datetime) -> Period:
    if start.tzinfo is None or end.tzinfo is None:
        raise PassiveUsageError("period timestamps require timezone")
    period = Period(start.astimezone(UTC), end.astimezone(UTC))
    if period.duration_seconds <= 0:
        raise PassiveUsageError("period end must follow start")
    return period


def _group_rows(
    grouped: Mapping[tuple[str, ...], UsageTotals], period: Period, labels: tuple[str, ...]
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for key, usage in sorted(grouped.items()):
        rows.append(
            {
                **dict(zip(labels, key)),
                **usage.as_dict(period),
            }
        )
    return rows


def _shares(counts: Mapping[str, int]) -> dict[str, float]:
    total = sum(counts.values())
    if total <= 0:
        return {}
    return {
        label: _round(count / total)
        for label, count in sorted(counts.items())
        if count > 0
    }


def _mix_from_rows(rows: Iterable[Mapping[str, Any]], label: str) -> dict[str, float]:
    counts: dict[str, int] = defaultdict(int)
    for row in rows:
        value = row.get(label)
        events = row.get("usage_events")
        if isinstance(value, str) and type(events) is int and events > 0:
            counts[value] += events
    return _shares(counts)


def collect(sessions_root: Path, *, start: datetime, end: datetime) -> dict[str, Any]:
    """Aggregate one explicit period from session JSONL without writing anything."""

    period = _period_from_datetimes(start, end)
    stats = ScanStats()
    total = UsageTotals()
    by_model_effort: dict[tuple[str, str], UsageTotals] = {}
    by_root_worker: dict[tuple[str], UsageTotals] = {}
    by_task_family: dict[tuple[str], UsageTotals] = {}
    weekly_observations: list[RateObservation] = []
    for path in _session_files(sessions_root, period):
        stats.files_seen += 1
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                stats.oversized_files += 1
                continue
            handle = path.open("r", encoding="utf-8", errors="strict")
        except (OSError, UnicodeError):
            stats.unreadable_files += 1
            continue
        model = "unknown"
        effort = "unknown"
        root_worker = ROOT_OR_LEGACY
        task_family = "other"
        with handle:
            stats.files_read += 1
            for line in handle:
                stats.lines_seen += 1
                if len(line) > MAX_LINE_CHARS:
                    stats.oversized_lines += 1
                    continue
                try:
                    entry = json.loads(line)
                except (json.JSONDecodeError, RecursionError):
                    stats.malformed_lines += 1
                    continue
                if not isinstance(entry, Mapping):
                    stats.malformed_lines += 1
                    continue
                payload = _mapping(entry.get("payload"))
                if payload is None:
                    continue
                if entry.get("type") == "turn_context":
                    if "model" in payload:
                        model = _safe_model(payload.get("model"))
                    if "effort" in payload:
                        effort = _safe_effort(payload.get("effort"))
                # Metadata is intentionally read only from structured
                # turn/session/event payloads; response/tool content is never
                # inspected for classification.
                if entry.get("type") in {"turn_context", "session_meta", "event_msg"}:
                    root_worker, task_family = _metadata_update(
                        payload, root_worker, task_family
                    )
                    for metadata_key in ("metadata", "agent", "worker_metadata"):
                        metadata = _mapping(payload.get(metadata_key))
                        if metadata is not None:
                            root_worker, task_family = _metadata_update(
                                metadata, root_worker, task_family
                            )
                timestamp = _log_timestamp(entry.get("timestamp"))
                if timestamp is None:
                    stats.invalid_timestamps += 1
                    continue
                if not period.contains(timestamp):
                    stats.out_of_period_records += 1
                    continue
                info = _mapping(payload.get("info"))
                usage = _mapping(info.get("last_token_usage")) if info else None
                if usage is not None:
                    if total.add(usage):
                        by_model_effort.setdefault((model, effort), UsageTotals()).add(
                            usage
                        )
                        by_root_worker.setdefault((root_worker,), UsageTotals()).add(
                            usage
                        )
                        by_task_family.setdefault((task_family,), UsageTotals()).add(
                            usage
                        )
                    else:
                        stats.invalid_usage_events += 1
                observation = _weekly_observation(payload, timestamp)
                if observation is not None:
                    weekly_observations.append(observation)
                    stats.rate_observations += 1
    model_effort_rows = _group_rows(
        by_model_effort, period, ("model", "effort")
    )
    root_worker_rows = _group_rows(by_root_worker, period, ("root_worker",))
    task_family_rows = _group_rows(by_task_family, period, ("task_family",))
    usage = total.as_dict(period)
    usage.update(
        {
            "by_model_effort": model_effort_rows,
            "by_root_worker": root_worker_rows,
            "by_task_family": task_family_rows,
            "mix": {
                "model": _mix_from_rows(model_effort_rows, "model"),
                "effort": _mix_from_rows(model_effort_rows, "effort"),
                "root_worker": _mix_from_rows(root_worker_rows, "root_worker"),
                "task_family": _mix_from_rows(task_family_rows, "task_family"),
            },
        }
    )
    return {
        "schema": 1,
        "measurement_kind": "passive_local_session_log_aggregate",
        "network_calls": 0,
        "model_calls": 0,
        "raw_log_exported": False,
        "period": {
            "start": _format_instant(period.start),
            "end": _format_instant(period.end),
            "duration_seconds": int(period.duration_seconds),
        },
        "scan": stats.as_dict(),
        "usage": usage,
        "weekly_limit": _weekly_summary(weekly_observations),
    }


def _metric_change(baseline: Any, candidate: Any) -> dict[str, Any]:
    if not isinstance(baseline, (int, float)) or not isinstance(candidate, (int, float)):
        return {
            "status": "NOT_MEASURED",
            "baseline": baseline if isinstance(baseline, (int, float)) else None,
            "candidate": candidate if isinstance(candidate, (int, float)) else None,
            "absolute_change": None,
            "relative_change": None,
        }
    absolute_change = candidate - baseline
    return {
        "status": "MEASURED",
        "baseline": baseline,
        "candidate": candidate,
        "absolute_change": _round(absolute_change),
        "relative_change": _round(absolute_change / baseline) if baseline != 0 else None,
    }


def _reset_bucket(value: Any) -> int | None:
    if isinstance(value, str):
        timestamp = _log_timestamp(value)
        return None if timestamp is None else int(timestamp.timestamp() // 60 * 60)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    if not math.isfinite(number) or number < 0:
        return None
    return int(round(number / 60) * 60)


def _one_weekly_rate(report: Mapping[str, Any]) -> tuple[float, int] | None:
    weekly_limit = _mapping(report.get("weekly_limit"))
    windows = weekly_limit.get("windows") if weekly_limit else None
    if not isinstance(windows, list) or len(windows) != 1:
        return None
    item = windows[0]
    if not isinstance(item, Mapping) or item.get("status") != "MEASURED":
        return None
    value = item.get("used_percent_per_hour")
    bucket = _reset_bucket(item.get("reset_at", item.get("reset_bucket")))
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or bucket is None
    ):
        return None
    return float(value), bucket


def _normalise_mix(value: Any, *, allowed: set[str] | None = None) -> dict[str, float] | None:
    if not isinstance(value, Mapping):
        return None
    weights: dict[str, float] = {}
    for label, weight in value.items():
        if not isinstance(label, str) or (allowed is not None and label not in allowed):
            return None
        if isinstance(weight, bool) or not isinstance(weight, (int, float)):
            return None
        number = float(weight)
        if not math.isfinite(number) or number < 0:
            return None
        weights[label] = number
    total = sum(weights.values())
    if total <= 0:
        return None
    return {label: weight / total for label, weight in weights.items() if weight > 0}


def _report_mix(
    usage: Mapping[str, Any], dimension: str, *, allowed: set[str] | None = None
) -> dict[str, float] | None:
    mix = _mapping(usage.get("mix"))
    if mix is not None and dimension in mix:
        return _normalise_mix(mix.get(dimension), allowed=allowed)
    rows = usage.get(
        {
            "model": "by_model_effort",
            "effort": "by_model_effort",
            "model_effort": "by_model_effort",
            "root_worker": "by_root_worker",
            "task_family": "by_task_family",
        }.get(dimension, "")
    )
    if not isinstance(rows, list):
        return None
    counts: dict[str, int] = defaultdict(int)
    for row in rows:
        if not isinstance(row, Mapping):
            return None
        events = row.get("usage_events")
        if type(events) is not int or events < 0:
            return None
        if dimension == "model_effort":
            model = row.get("model")
            effort = row.get("effort")
            if not isinstance(model, str) or not isinstance(effort, str):
                return None
            item = f"{model}\x1f{effort}"
        else:
            label = "root_worker" if dimension == "root_worker" else dimension
            item = row.get(label)
            if not isinstance(item, str):
                return None
            if allowed is not None and item not in allowed:
                return None
        counts[item] += events
    return _normalise_mix(counts)


def _mix_reason(
    baseline_usage: Mapping[str, Any],
    candidate_usage: Mapping[str, Any],
    dimension: str,
    code: str,
    *,
    allowed: set[str] | None = None,
    uninformative: set[str] | None = None,
) -> str | None:
    baseline_mix = _report_mix(baseline_usage, dimension, allowed=allowed)
    candidate_mix = _report_mix(candidate_usage, dimension, allowed=allowed)
    if baseline_mix is None or candidate_mix is None:
        return f"MISSING_{code}"
    if uninformative is not None and (
        set(baseline_mix) & uninformative
        or set(candidate_mix) & uninformative
    ):
        return f"MISSING_{code}"
    labels = set(baseline_mix) | set(candidate_mix)
    if any(
        abs(baseline_mix.get(label, 0.0) - candidate_mix.get(label, 0.0))
        > MIX_TOLERANCE
        for label in labels
    ):
        return f"{code}_MISMATCH"
    return None


def _weekly_comparison_metric(
    baseline: Mapping[str, Any], candidate: Mapping[str, Any]
) -> dict[str, Any]:
    baseline_rate = _one_weekly_rate(baseline)
    candidate_rate = _one_weekly_rate(candidate)
    if baseline_rate is None or candidate_rate is None:
        return _metric_change(None, None)
    if baseline_rate[1] != candidate_rate[1]:
        return _metric_change(None, None)
    return _metric_change(baseline_rate[0], candidate_rate[0])


def compare(baseline: Mapping[str, Any], candidate: Mapping[str, Any]) -> dict[str, Any]:
    """Compare two reports; values remain observational, not causal proof."""

    baseline_usage = _mapping(baseline.get("usage")) or {}
    candidate_usage = _mapping(candidate.get("usage")) or {}
    baseline_rates = _mapping(baseline_usage.get("rates_per_hour")) or {}
    candidate_rates = _mapping(candidate_usage.get("rates_per_hour")) or {}
    reasons = [
        reason
        for reason in (
            _mix_reason(
                baseline_usage,
                candidate_usage,
                "model",
                "MODEL_MIX",
                uninformative={"unknown"},
            ),
            _mix_reason(
                baseline_usage,
                candidate_usage,
                "effort",
                "EFFORT_MIX",
                uninformative={"unknown"},
            ),
            _mix_reason(
                baseline_usage,
                candidate_usage,
                "model_effort",
                "MODEL_EFFORT_MIX",
            ),
            _mix_reason(
                baseline_usage,
                candidate_usage,
                "root_worker",
                "ROOT_WORKER_MIX",
                allowed=set(ROOT_WORKER_CLASSES),
            ),
            _mix_reason(
                baseline_usage,
                candidate_usage,
                "task_family",
                "TASK_FAMILY_MIX",
                allowed=set(TASK_FAMILIES),
                uninformative={"other"},
            ),
        )
        if reason is not None
    ]
    baseline_per_event = _mapping(
        baseline_usage.get("rates_per_usage_event")
    ) or {}
    candidate_per_event = _mapping(
        candidate_usage.get("rates_per_usage_event")
    ) or {}
    if reasons:
        metrics = {
            name: _metric_change(None, None)
            for name in (
                "usage_events_per_hour",
                "input_tokens_per_usage_event",
                "uncached_input_tokens_per_usage_event",
                "uncached_input_tokens_per_hour",
                "output_tokens_per_hour",
                "cache_hit_ratio",
                "weekly_used_percent_per_hour",
            )
        }
    else:
        metrics = {
            "usage_events_per_hour": _metric_change(
                baseline_rates.get("usage_events"),
                candidate_rates.get("usage_events"),
            ),
            "input_tokens_per_usage_event": _metric_change(
                baseline_per_event.get("input_tokens"),
                candidate_per_event.get("input_tokens"),
            ),
            "uncached_input_tokens_per_usage_event": _metric_change(
                baseline_per_event.get("uncached_input_tokens"),
                candidate_per_event.get("uncached_input_tokens"),
            ),
            "uncached_input_tokens_per_hour": _metric_change(
                baseline_rates.get("uncached_input_tokens"),
                candidate_rates.get("uncached_input_tokens"),
            ),
            "output_tokens_per_hour": _metric_change(
                baseline_rates.get("output_tokens"),
                candidate_rates.get("output_tokens"),
            ),
            "cache_hit_ratio": _metric_change(
                baseline_usage.get("cache_hit_ratio"),
                candidate_usage.get("cache_hit_ratio"),
            ),
            "weekly_used_percent_per_hour": _weekly_comparison_metric(
                baseline, candidate
            ),
        }
    comparison: dict[str, Any] = {
        "status": "COMPARABLE" if not reasons else "NOT_COMPARABLE",
        "reason_codes": reasons,
        "metrics": metrics,
        "notes": [
            "Quota percentage and raw token counters are different measures.",
            "Composition is compared by usage-event share with a fixed 10 percentage-point tolerance.",
        ],
    }
    return {
        "schema": 1,
        "measurement_kind": "passive_local_session_log_comparison",
        "network_calls": 0,
        "model_calls": 0,
        "raw_log_exported": False,
        "interpretation": "OBSERVATIONAL_ONLY",
        "baseline": baseline,
        "candidate": candidate,
        "comparison": comparison,
    }


def parse_args(arguments: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Aggregate existing Codex session counters without network calls or writes."
    )
    parser.add_argument("--sessions-root", required=True, type=Path)
    parser.add_argument("--start", required=True, type=_parse_instant)
    parser.add_argument("--end", required=True, type=_parse_instant)
    parser.add_argument("--baseline-start", type=_parse_instant)
    parser.add_argument("--baseline-end", type=_parse_instant)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args(arguments)
    if (args.baseline_start is None) != (args.baseline_end is None):
        parser.error("--baseline-start and --baseline-end must be supplied together")
    return args


def main(arguments: list[str] | None = None) -> int:
    args = parse_args(arguments)
    try:
        candidate = collect(args.sessions_root, start=args.start, end=args.end)
        payload: Mapping[str, Any] = candidate
        if args.baseline_start is not None:
            baseline = collect(
                args.sessions_root, start=args.baseline_start, end=args.baseline_end
            )
            payload = compare(baseline, candidate)
    except (OSError, PassiveUsageError, UnicodeError, ValueError) as exc:
        print(
            f"FAIL: passive usage report unavailable: {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
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
