"""Deterministic hard-budget decisions and remediation hints.

This helper keeps the hard-limit failure contract separate from the packet
builder.  A hard rejection never truncates executable work silently.  It
returns one stable remediation sequence so a root can reduce evidence or split
the work before trying again.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Iterable, Mapping
import unicodedata


REMEDIATION_DEDUPLICATE = "deduplicate repeated evidence"
REMEDIATION_SNIPPETS = (
    "replace full source/logs with bounded relevant snippets"
)
REMEDIATION_SPLIT = "split into independent packets"

# This tuple is the public, ordered contract.  Keep human-readable values here
# rather than deriving them from a set or a mapping; rejected decisions must be
# identical across Python versions and input ordering.
HARD_BUDGET_REMEDIATION: tuple[str, ...] = (
    REMEDIATION_DEDUPLICATE,
    REMEDIATION_SNIPPETS,
    REMEDIATION_SPLIT,
)
HARD_BUDGET_REMEDIATION_SEQUENCE = HARD_BUDGET_REMEDIATION
HARD_BUDGET_REMEDIATION_STEPS = HARD_BUDGET_REMEDIATION
REMEDIATION_SEQUENCE = HARD_BUDGET_REMEDIATION
REMEDIATION_STEPS = HARD_BUDGET_REMEDIATION


class TokenBudgetError(ValueError):
    """Malformed token-budget input."""


def _non_negative_int(value: Any, name: str, *, allow_none: bool = False) -> int | None:
    if value is None and allow_none:
        return None
    if type(value) is not int or value < 0:
        raise TokenBudgetError(f"{name} must be a non-negative integer")
    return value


def _canonical_text(value: Any) -> str:
    if type(value) is not str:
        raise TokenBudgetError("evidence items must be strings")
    # Whitespace-only differences are repeated evidence for budgeting purposes;
    # normalize them before hashing/deduplication, without retaining raw logs.
    return unicodedata.normalize("NFC", value.replace("\r\n", "\n").replace("\r", "\n")).strip()


def _evidence_items(evidence: Any) -> list[str]:
    if isinstance(evidence, str):
        values = evidence.splitlines() or [evidence]
    elif isinstance(evidence, Mapping):
        values = []
        for key in sorted(evidence, key=lambda item: str(item)):
            value = evidence[key]
            if isinstance(value, str):
                values.extend(value.splitlines() or [value])
            elif isinstance(value, Iterable):
                values.extend(value)
            else:
                values.append(str(value))
    else:
        if evidence is None:
            values = []
        else:
            try:
                values = list(evidence)
            except TypeError as exc:
                raise TokenBudgetError("evidence must be text or an iterable") from exc
    normalized = [_canonical_text(item) for item in values]
    return [item for item in normalized if item]


def deduplicate_repeated_evidence(evidence: Any) -> tuple[str, ...]:
    """Return sorted unique evidence, normalizing line-ending/whitespace noise."""

    return tuple(sorted(set(_evidence_items(evidence))))


# Short failure terms are useful when callers supply complete source or logs.
# They are only a deterministic ranking aid; callers can provide their own
# terms to avoid making a semantic claim about arbitrary text.
_DEFAULT_RELEVANCE_TERMS = (
    "error",
    "exception",
    "traceback",
    "failed",
    "failure",
    "assert",
    "reject",
    "budget",
    "warning",
)


def bounded_relevant_snippets(
    evidence: Any,
    *,
    max_chars: int = 2_000,
    max_snippets: int = 8,
    relevant_terms: Iterable[str] = _DEFAULT_RELEVANCE_TERMS,
) -> tuple[str, ...]:
    """Select deterministic, bounded snippets from source/log evidence.

    Full input is never returned once the bound is reached.  Ranking keeps
    relevant failure lines first and lexical ordering breaks ties, so the same
    evidence produces the same snippets regardless of input order.
    """

    _non_negative_int(max_chars, "max_chars")
    _non_negative_int(max_snippets, "max_snippets")
    if max_chars == 0 or max_snippets == 0:
        return ()
    terms = tuple(
        sorted(
            {
                _canonical_text(term).lower()
                for term in relevant_terms
                if _canonical_text(term)
            }
        )
    )
    unique = deduplicate_repeated_evidence(evidence)
    ranked = sorted(
        unique,
        key=lambda item: (
            -sum(1 for term in terms if term in item.lower()),
            item,
        ),
    )
    selected: list[str] = []
    used = 0
    for item in ranked:
        if len(selected) >= max_snippets or used >= max_chars:
            break
        remaining = max_chars - used
        # A separator is not counted as content, but account for it so the
        # serialized snippet list remains within the advertised bound.
        room = remaining if not selected else remaining - 1
        if room <= 0:
            break
        snippet = item[:room]
        if not snippet:
            continue
        selected.append(snippet)
        used += len(snippet) + (1 if len(selected) > 1 else 0)
    return tuple(selected)


def split_independent_packets(
    evidence: Any,
    *,
    max_items: int | None = None,
    max_chars: int | None = None,
    packet_count: int | None = None,
) -> tuple[tuple[str, ...], ...]:
    """Split bounded evidence into deterministic, non-overlapping packets.

    At least one bound is required when more than one item is supplied.  The
    function does not duplicate or reorder an already bounded snippet list.
    """

    max_items = _non_negative_int(max_items, "max_items", allow_none=True)
    max_chars = _non_negative_int(max_chars, "max_chars", allow_none=True)
    packet_count = _non_negative_int(packet_count, "packet_count", allow_none=True)
    values = list(deduplicate_repeated_evidence(evidence))
    if not values:
        return ()
    if max_items is None and max_chars is None and packet_count is None:
        return (tuple(values),)
    if max_items == 0 or max_chars == 0 or packet_count == 0:
        raise TokenBudgetError("packet split bound must be positive")

    # A packet count is a cap, not a fixed worker count.  The remaining values
    # are assigned left-to-right while honoring item/character bounds.
    packets: list[tuple[str, ...]] = []
    current: list[str] = []
    current_chars = 0
    for value in values:
        if max_chars is not None and len(value) > max_chars:
            raise TokenBudgetError("one evidence item exceeds the packet character bound")
        separator = 1 if current else 0
        would_exceed_items = max_items is not None and len(current) >= max_items
        would_exceed_chars = (
            max_chars is not None and current and current_chars + separator + len(value) > max_chars
        )
        if current and (would_exceed_items or would_exceed_chars):
            packets.append(tuple(current))
            current = []
            current_chars = 0
            separator = 0
        current.append(value)
        current_chars += separator + len(value)
    if current:
        packets.append(tuple(current))

    if packet_count is not None and len(packets) > packet_count:
        # Merging would violate a character/item bound.  Do not convert a
        # caller's packet-count preference into an unsafe oversized packet.
        raise TokenBudgetError("packet count cannot satisfy the split bounds")
    return tuple(tuple(packet) for packet in packets)


def remediation_text(sequence: Iterable[str] = HARD_BUDGET_REMEDIATION) -> str:
    """Render the ordered remediation sequence with the canonical arrow."""

    values = tuple(sequence)
    if values != HARD_BUDGET_REMEDIATION:
        raise TokenBudgetError("unsupported hard-budget remediation sequence")
    return " -> ".join(values)


@dataclass(frozen=True)
class HardBudgetDecision:
    """Stable allow/reject result for one packet or wave budget check."""

    accepted: bool
    hard_exceeded: bool
    estimated_tokens: int
    hard_tokens: int | None
    used_tokens: int = 0
    reason: str | None = None
    remediation: tuple[str, ...] = ()
    kind: str = "packet"

    @property
    def rejected(self) -> bool:
        return not self.accepted

    @property
    def blocking(self) -> bool:
        return not self.accepted

    @property
    def remediation_steps(self) -> tuple[str, ...]:
        return self.remediation

    @property
    def remediation_sequence(self) -> tuple[str, ...]:
        return self.remediation

    @property
    def decision(self) -> str:
        return "accepted" if self.accepted else "rejected"

    @property
    def message(self) -> str:
        if self.accepted:
            return "accepted"
        if self.hard_exceeded:
            return f"hard budget rejected: {remediation_text(self.remediation)}"
        return self.reason or "rejected"

    def to_dict(self) -> dict[str, Any]:
        """Return fixed-order JSON-compatible diagnostics without evidence."""

        return {
            "decision": self.decision,
            "accepted": self.accepted,
            "hard_exceeded": self.hard_exceeded,
            "estimated_tokens": self.estimated_tokens,
            "hard_tokens": self.hard_tokens,
            "used_tokens": self.used_tokens,
            "reason": self.reason,
            "remediation": list(self.remediation),
            "kind": self.kind,
        }

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            self.to_dict(),
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]


def evaluate_hard_budget(
    estimated_tokens: int,
    hard_tokens: int | None,
    *,
    used_tokens: int = 0,
    kind: str = "packet",
) -> HardBudgetDecision:
    """Reject only hard-limit overflow and attach the exact remediation steps."""

    estimated_tokens = _non_negative_int(estimated_tokens, "estimated_tokens")
    hard_tokens = _non_negative_int(hard_tokens, "hard_tokens", allow_none=True)
    used_tokens = _non_negative_int(used_tokens, "used_tokens")
    if type(kind) is not str or not kind.strip():
        raise TokenBudgetError("kind must be a non-empty string")
    projected = used_tokens + estimated_tokens
    exceeded = hard_tokens is not None and projected > hard_tokens
    if exceeded:
        return HardBudgetDecision(
            accepted=False,
            hard_exceeded=True,
            estimated_tokens=estimated_tokens,
            hard_tokens=hard_tokens,
            used_tokens=used_tokens,
            reason="hard budget exceeded",
            remediation=HARD_BUDGET_REMEDIATION,
            kind=kind.strip(),
        )
    return HardBudgetDecision(
        accepted=True,
        hard_exceeded=False,
        estimated_tokens=estimated_tokens,
        hard_tokens=hard_tokens,
        used_tokens=used_tokens,
        kind=kind.strip(),
    )


def hard_budget_decision(*args: Any, **kwargs: Any) -> HardBudgetDecision:
    return evaluate_hard_budget(*args, **kwargs)


def check_budget(*args: Any, **kwargs: Any) -> HardBudgetDecision:
    return evaluate_hard_budget(*args, **kwargs)


def rejected_decision(
    estimated_tokens: int,
    hard_tokens: int,
    *,
    used_tokens: int = 0,
    kind: str = "packet",
) -> HardBudgetDecision:
    """Compatibility spelling for callers that only create rejection paths."""

    decision = evaluate_hard_budget(
        estimated_tokens,
        hard_tokens,
        used_tokens=used_tokens,
        kind=kind,
    )
    if not decision.rejected:
        raise TokenBudgetError("requested rejected decision does not exceed hard budget")
    return decision


def reject_hard_budget(
    estimated_tokens: int,
    hard_tokens: int,
    *,
    used_tokens: int = 0,
    kind: str = "packet",
) -> HardBudgetDecision:
    return rejected_decision(
        estimated_tokens,
        hard_tokens,
        used_tokens=used_tokens,
        kind=kind,
    )


def remediate_hard_budget(
    evidence: Any,
    *,
    max_chars: int = 2_000,
    max_snippets: int = 8,
    max_items_per_packet: int | None = None,
    packet_count: int | None = None,
) -> dict[str, Any]:
    """Apply the three remediation stages and return a stable summary."""

    deduplicated = deduplicate_repeated_evidence(evidence)
    snippets = bounded_relevant_snippets(
        deduplicated,
        max_chars=max_chars,
        max_snippets=max_snippets,
    )
    packets = split_independent_packets(
        snippets,
        max_items=max_items_per_packet,
        packet_count=packet_count,
    )
    return {
        "steps": list(HARD_BUDGET_REMEDIATION),
        "deduplicated_evidence": list(deduplicated),
        "bounded_relevant_snippets": list(snippets),
        "independent_packets": [list(packet) for packet in packets],
    }


# Compatibility aliases for concise callers and earlier audit vocabulary.
dedupe_repeated_evidence = deduplicate_repeated_evidence
replace_with_bounded_snippets = bounded_relevant_snippets
split_into_independent_packets = split_independent_packets
apply_hard_budget_remediation = remediate_hard_budget
hard_budget_rejection = reject_hard_budget


__all__ = [
    "HARD_BUDGET_REMEDIATION",
    "HARD_BUDGET_REMEDIATION_SEQUENCE",
    "HARD_BUDGET_REMEDIATION_STEPS",
    "REMEDIATION_DEDUPLICATE",
    "REMEDIATION_SEQUENCE",
    "REMEDIATION_STEPS",
    "REMEDIATION_SNIPPETS",
    "REMEDIATION_SPLIT",
    "HardBudgetDecision",
    "TokenBudgetError",
    "apply_hard_budget_remediation",
    "bounded_relevant_snippets",
    "check_budget",
    "dedupe_repeated_evidence",
    "deduplicate_repeated_evidence",
    "evaluate_hard_budget",
    "hard_budget_decision",
    "remediate_hard_budget",
    "remediation_text",
    "reject_hard_budget",
    "rejected_decision",
    "replace_with_bounded_snippets",
    "split_independent_packets",
    "split_into_independent_packets",
    "hard_budget_rejection",
]
