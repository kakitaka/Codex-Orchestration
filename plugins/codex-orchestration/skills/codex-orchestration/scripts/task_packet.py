"""Deterministic ``TASK_PACKET_V1`` construction and bounded wave accounting.

Packets are intentionally plain data.  The canonical bytes are produced before
the optional envelope so a packet hash never depends on a timestamp, UUID,
working directory, or process-specific metadata.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import posixpath
import re
import stat
from types import MappingProxyType
import unicodedata
from typing import Any, Iterable, Mapping
from collections.abc import Mapping as ABCMapping

try:
    from token_profiles import TokenProfile, get_profile
except ImportError:  # pragma: no cover - package-style import fallback
    from .token_profiles import TokenProfile, get_profile
try:
    from token_budget import HARD_BUDGET_REMEDIATION
except ImportError:  # pragma: no cover - package-style import fallback
    from .token_budget import HARD_BUDGET_REMEDIATION


PACKET_VERSION = "TASK_PACKET_V1"
VERSION = PACKET_VERSION
PACKET_KEYS = (
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
CANONICAL_PACKET_KEYS = PACKET_KEYS


class TaskPacketError(ValueError):
    """Base class for malformed, unsafe, or oversized task packets."""


class PacketSchemaError(TaskPacketError):
    pass


class PacketPathError(TaskPacketError):
    pass


class PacketSecretError(TaskPacketError):
    """Secret-like input was rejected without echoing the sensitive value."""

    def __init__(self, field: str, category: str) -> None:
        self.field = field
        self.category = category
        super().__init__(f"secret-like material rejected: field={field} category={category}")


SecretLikeError = PacketSecretError


class DuplicatePacketError(TaskPacketError):
    def __init__(self, packet_hash: str) -> None:
        self.packet_hash = packet_hash
        super().__init__("duplicate task packet hash rejected")


class BudgetExceeded(TaskPacketError):
    def __init__(self, kind: str) -> None:
        self.kind = kind
        super().__init__(f"wave budget {kind} limit exceeded")


class PathContainmentError(PacketPathError):
    pass


_FIELD_ALIASES = {
    "version": "VERSION",
    "role": "ROLE",
    "static_rules": "STATIC_RULES",
    "goal": "GOAL",
    "base_revision": "BASE_REVISION",
    "files_allowed": "FILES_ALLOWED",
    "files_forbidden": "FILES_FORBIDDEN",
    "known_facts": "KNOWN_FACTS",
    "constraints": "CONSTRAINTS",
    "acceptance_criteria": "ACCEPTANCE_CRITERIA",
    "validation": "VALIDATION",
    "validation_command": "VALIDATION",
    "output_contract": "OUTPUT_CONTRACT",
    "expected_output": "OUTPUT_CONTRACT",
}

_STATIC_UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b"
)
_STATIC_TIME_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?\b"
)
_STATIC_ABSOLUTE_RE = re.compile(
    r"(?:"
    r"\b[A-Za-z]:[\\/]"
    r"|(?<![A-Za-z0-9:])[/\\]{2,}[^\s'\"`]*"
    r"|(?<![A-Za-z0-9:])\\\\[^\\/\s]+[\\/][^\\/\s]+"
    r"|(?<![A-Za-z0-9:])//[^/\s]+/[^/\s]+"
    r"|(?<![A-Za-z0-9/.])/(?!/)(?:[^\s/'\"`][^\s'\"`]*)?"
    r"|(?<![A-Za-z0-9\\/.])\\(?!\\)(?:[^\s\\/'\"`][^\s'\"`]*)?"
    r"|(?<![A-Za-z0-9_])-[A-Za-z0-9][/\\]{2,}[^\s'\"`]*"
    r"|(?<![A-Za-z0-9_])-[A-Za-z0-9]/(?!/)"
    r"(?:[^\s/'\"`][^\s'\"`]*)?"
    r"|(?<![A-Za-z0-9_])-[A-Za-z0-9]\\(?!\\)"
    r"(?:[^\s\\/'\"`][^\s'\"`]*)?"
    r")",
    re.IGNORECASE,
)


def _nfc_lf(value: str) -> str:
    if type(value) is not str:
        raise PacketSchemaError("packet text fields must be strings")
    # Normalize line endings before NFC so a combining character spanning a
    # source boundary receives the same canonical treatment on every platform.
    return unicodedata.normalize("NFC", value.replace("\r\n", "\n").replace("\r", "\n"))


def _is_reparse_point(path: Path) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise PacketPathError("could not inspect packet path") from exc
    if stat.S_ISLNK(info.st_mode):
        return True
    # st_file_attributes is available on Windows and may be exposed by test
    # doubles on other platforms.  Avoid importing Windows-only ctypes.
    attributes = getattr(info, "st_file_attributes", 0)
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _root_path(repo_root: str | os.PathLike[str]) -> Path:
    root = Path(repo_root).expanduser()
    if not root.is_absolute():
        root = Path.cwd() / root
    try:
        root = root.absolute()
    except OSError as exc:
        raise PacketPathError("could not resolve repository root") from exc
    if _is_reparse_point(root):
        raise PacketPathError("repository root is a symlink or reparse point")
    if not root.exists() or not root.is_dir():
        raise PacketPathError("repository root is not an existing directory")
    return root


def _relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _reject_reparse_components(candidate: Path, root: Path) -> None:
    current = candidate
    components: list[Path] = []
    while True:
        components.append(current)
        if current == root:
            break
        parent = current.parent
        if parent == current or not _relative_to(parent, root):
            break
        current = parent
    for component in reversed(components):
        if _is_reparse_point(component):
            raise PacketPathError("packet path contains a symlink or reparse point")


def normalize_repo_path(
    value: str | os.PathLike[str],
    *,
    repo_root: str | os.PathLike[str] | None = None,
) -> str:
    """Normalize one repo-relative path and reject traversal/absolute paths."""

    if isinstance(value, os.PathLike):
        value = os.fspath(value)
    if type(value) is not str:
        raise PacketPathError("packet paths must be strings")
    text = _nfc_lf(value).replace("\\", "/")
    if not text or "\n" in text or "\x00" in text:
        raise PacketPathError("packet path is empty or contains a control character")
    # PurePosixPath does not recognize a Windows drive on POSIX, so check both
    # spellings explicitly before any normalization.
    if text.startswith("/") or text.startswith("//") or re.match(r"^[A-Za-z]:($|/)", text):
        raise PacketPathError("packet paths must be repository-relative")
    pieces = text.split("/")
    if any(piece in {"", ".", ".."} for piece in pieces):
        raise PathContainmentError("packet path contains an invalid traversal component")
    normalized = posixpath.normpath("/".join(pieces))
    if normalized in {"", ".", ".."} or normalized.startswith("../"):
        raise PathContainmentError("packet path escapes the repository")
    if repo_root is not None:
        root = _root_path(repo_root)
        candidate = root.joinpath(*normalized.split("/"))
        try:
            resolved = candidate.resolve(strict=False)
        except OSError as exc:
            raise PacketPathError("could not resolve packet path") from exc
        resolved_root = root.resolve(strict=False)
        if not _relative_to(resolved, resolved_root):
            raise PathContainmentError("packet path escapes the repository")
        _reject_reparse_components(candidate, root)
    return normalized


def _iter_values(value: Any, field: str) -> Iterable[Any]:
    if isinstance(value, (str, bytes, bytearray)) or value is None:
        raise PacketSchemaError(f"{field} must be a list")
    if not isinstance(value, Iterable):
        raise PacketSchemaError(f"{field} must be a list")
    return value


# Patterns are intentionally conservative.  The packet builder rejects a
# suspicious field instead of attempting lossy redaction into executable work.
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private_key", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\b(?:gh[pousr]|github_pat_)[A-Za-z0-9_\-]{12,}\b")),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9][A-Za-z0-9_-]{19,}\b")),
    ("bearer_token", re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{16,}\b", re.I)),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("credential_assignment", re.compile(r"\b(?:api[_-]?key|secret|password|token|credential)\s*[:=]\s*[^\s,;]+", re.I)),
)


def _secret_category(value: str) -> str | None:
    for category, pattern in _SECRET_PATTERNS:
        if pattern.search(value):
            return category
    return None


def _reject_secrets(value: Any, field: str) -> None:
    if isinstance(value, str):
        category = _secret_category(value)
        if category:
            raise PacketSecretError(field, category)
        return
    if isinstance(value, Mapping):
        for nested_key, nested_value in value.items():
            _reject_secrets(nested_value, field)
    elif isinstance(value, Iterable) and not isinstance(value, (bytes, bytearray)):
        for nested_value in value:
            _reject_secrets(nested_value, field)


def _reject_unstable_static(value: Any, field: str) -> None:
    """Keep the cacheable prefix free of per-run identifiers and local paths."""

    values = [value] if isinstance(value, str) else value
    for item in values:
        if not isinstance(item, str):
            raise PacketSchemaError(f"{field} must contain text")
        if _STATIC_UUID_RE.search(item):
            raise PacketSchemaError(f"{field} contains an unstable UUID")
        if _STATIC_TIME_RE.search(item):
            raise PacketSchemaError(f"{field} contains an unstable timestamp")
        if _STATIC_ABSOLUTE_RE.search(item):
            raise PacketSchemaError(f"{field} contains a user-specific absolute path")


def _reject_user_absolute_paths(value: Any, field: str) -> None:
    """Reject local absolute paths from every serialized text field."""

    values = value if isinstance(value, (list, tuple)) else (value,)
    for item in values:
        if isinstance(item, str) and _STATIC_ABSOLUTE_RE.search(item):
            raise PacketSchemaError(
                f"{field} contains a user-specific absolute path"
            )


def _normalize_text_list(value: Any, field: str) -> list[str]:
    normalized: set[str] = set()
    for item in _iter_values(value, field):
        normalized.add(_nfc_lf(item))
    return sorted(normalized)


def _normalize_path_list(
    value: Any,
    field: str,
    *,
    repo_root: str | os.PathLike[str] | None,
) -> list[str]:
    normalized: set[str] = set()
    for item in _iter_values(value, field):
        normalized.add(normalize_repo_path(item, repo_root=repo_root))
    return sorted(normalized)


def _mapping_value(source: Mapping[str, Any], field: str, default: Any) -> Any:
    if field in source:
        return source[field]
    alias = field.lower()
    if alias in source:
        return source[alias]
    # Permit the natural snake_case alias for fixed uppercase keys.
    return source.get(_FIELD_ALIASES.get(alias, alias), default)


def _coerce_source(
    packet: Mapping[str, Any] | None,
    *,
    role: str | None,
    static_rules: Any,
    goal: str | None,
    base_revision: str | None,
    files_allowed: Any,
    files_forbidden: Any,
    known_facts: Any,
    constraints: Any,
    acceptance_criteria: Any,
    validation: str | None,
    output_contract: str | None,
) -> dict[str, Any]:
    if packet is not None:
        if not isinstance(packet, Mapping):
            raise PacketSchemaError("packet source must be an object")
        unknown = set(packet) - set(PACKET_KEYS) - set(_FIELD_ALIASES)
        if unknown:
            raise PacketSchemaError("packet contains unsupported fields")
        return {
            "VERSION": _mapping_value(packet, "VERSION", PACKET_VERSION),
            "ROLE": _mapping_value(packet, "ROLE", role),
            "STATIC_RULES": _mapping_value(packet, "STATIC_RULES", static_rules),
            "GOAL": _mapping_value(packet, "GOAL", goal),
            "BASE_REVISION": _mapping_value(packet, "BASE_REVISION", base_revision),
            "FILES_ALLOWED": _mapping_value(packet, "FILES_ALLOWED", files_allowed),
            "FILES_FORBIDDEN": _mapping_value(packet, "FILES_FORBIDDEN", files_forbidden),
            "KNOWN_FACTS": _mapping_value(packet, "KNOWN_FACTS", known_facts),
            "CONSTRAINTS": _mapping_value(packet, "CONSTRAINTS", constraints),
            "ACCEPTANCE_CRITERIA": _mapping_value(packet, "ACCEPTANCE_CRITERIA", acceptance_criteria),
            "VALIDATION": _mapping_value(packet, "VALIDATION", _mapping_value(packet, "VALIDATION_COMMAND", validation)),
            "OUTPUT_CONTRACT": _mapping_value(packet, "OUTPUT_CONTRACT", _mapping_value(packet, "EXPECTED_OUTPUT", output_contract)),
        }
    return {
        "VERSION": PACKET_VERSION,
        "ROLE": role,
        "STATIC_RULES": static_rules,
        "GOAL": goal,
        "BASE_REVISION": base_revision,
        "FILES_ALLOWED": files_allowed,
        "FILES_FORBIDDEN": files_forbidden,
        "KNOWN_FACTS": known_facts,
        "CONSTRAINTS": constraints,
        "ACCEPTANCE_CRITERIA": acceptance_criteria,
        "VALIDATION": validation,
        "OUTPUT_CONTRACT": output_contract,
    }


def _build_payload(
    source: Mapping[str, Any],
    *,
    repo_root: str | os.PathLike[str] | None,
) -> dict[str, Any]:
    version = _nfc_lf(source["VERSION"])
    if version != PACKET_VERSION:
        raise PacketSchemaError("packet VERSION is unsupported")
    if source["ROLE"] is None or source["GOAL"] is None:
        raise PacketSchemaError("packet ROLE and GOAL are required")
    role = _nfc_lf(source["ROLE"])
    goal = _nfc_lf(source["GOAL"])
    if not role.strip() or not goal.strip():
        raise PacketSchemaError("packet ROLE and GOAL must be non-empty")
    base_revision = _nfc_lf(source["BASE_REVISION"] or "")
    validation = _nfc_lf(source["VALIDATION"] or "")
    output_contract = _nfc_lf(source["OUTPUT_CONTRACT"] or "")
    static_rules = _normalize_text_list(source["STATIC_RULES"] or (), "STATIC_RULES")
    _reject_unstable_static(role, "ROLE")
    _reject_unstable_static(static_rules, "STATIC_RULES")
    payload = {
        "VERSION": PACKET_VERSION,
        "ROLE": role,
        "STATIC_RULES": static_rules,
        "GOAL": goal,
        "BASE_REVISION": base_revision,
        "FILES_ALLOWED": _normalize_path_list(
            source["FILES_ALLOWED"] if source["FILES_ALLOWED"] is not None else (),
            "FILES_ALLOWED",
            repo_root=repo_root,
        ),
        "FILES_FORBIDDEN": _normalize_path_list(
            source["FILES_FORBIDDEN"] if source["FILES_FORBIDDEN"] is not None else (),
            "FILES_FORBIDDEN",
            repo_root=repo_root,
        ),
        "KNOWN_FACTS": _normalize_text_list(
            source["KNOWN_FACTS"] if source["KNOWN_FACTS"] is not None else (),
            "KNOWN_FACTS",
        ),
        "CONSTRAINTS": _normalize_text_list(
            source["CONSTRAINTS"] if source["CONSTRAINTS"] is not None else (),
            "CONSTRAINTS",
        ),
        "ACCEPTANCE_CRITERIA": _normalize_text_list(
            source["ACCEPTANCE_CRITERIA"]
            if source["ACCEPTANCE_CRITERIA"] is not None
            else (),
            "ACCEPTANCE_CRITERIA",
        ),
        "VALIDATION": validation,
        "OUTPUT_CONTRACT": output_contract,
    }
    for field, value in payload.items():
        _reject_secrets(value, field)
        _reject_user_absolute_paths(value, field)
    return payload


def canonical_json_bytes(payload: Mapping[str, Any]) -> bytes:
    """Serialize a validated fixed-order payload exactly once."""

    if tuple(payload) != PACKET_KEYS:
        raise PacketSchemaError("packet keys are not in TASK_PACKET_V1 order")
    data = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=False,
    ).encode("utf-8")
    if data.startswith(b"\xef\xbb\xbf") or data.endswith(b"\n"):
        raise PacketSchemaError("canonical packet bytes have an invalid BOM or LF")
    return data


@dataclass(frozen=True)
class TaskPacket(ABCMapping[str, Any]):
    payload: Mapping[str, Any]
    canonical_bytes: bytes
    sha256: str

    def __post_init__(self) -> None:
        immutable = {
            key: tuple(value) if isinstance(value, list) else value
            for key, value in self.payload.items()
        }
        object.__setattr__(self, "payload", MappingProxyType(immutable))

    @property
    def packet_hash(self) -> str:
        return self.sha256

    @property
    def hash(self) -> str:
        return self.sha256

    @property
    def digest(self) -> str:
        return self.sha256

    @property
    def canonical(self) -> bytes:
        return self.canonical_bytes

    def to_dict(self) -> dict[str, Any]:
        return {
            key: list(value) if isinstance(value, tuple) else value
            for key, value in self.payload.items()
        }

    def as_dict(self) -> dict[str, Any]:
        return self.to_dict()

    def envelope(self) -> dict[str, Any]:
        return {
            "VERSION": PACKET_VERSION,
            "SHA256": self.sha256,
            "PACKET": self.to_dict(),
        }

    def to_envelope(self) -> dict[str, Any]:
        return self.envelope()

    @classmethod
    def from_mapping(
        cls,
        packet: Mapping[str, Any],
        *,
        repo_root: str | os.PathLike[str] | None = None,
    ) -> "TaskPacket":
        return build_task_packet(packet, repo_root=repo_root)

    def __getitem__(self, key: str) -> Any:
        return self.payload[key]

    def __iter__(self):
        return iter(self.payload)

    def __len__(self) -> int:
        return len(self.payload)

    def keys(self):
        return self.payload.keys()

    def items(self):
        return self.payload.items()

    def values(self):
        return self.payload.values()


def build_task_packet(
    packet: Mapping[str, Any] | str | None = None,
    files_allowed: Any = (),
    files_forbidden: Any = (),
    known_facts: Any = (),
    acceptance_criteria: Any = (),
    validation_command: str | None = "",
    expected_output: str | None = "",
    *,
    role: str | None = "implementation-worker",
    static_rules: Any = ("fork_turns=none", "Do not spawn descendants."),
    goal: str | None = None,
    base_revision: str | None = "",
    constraints: Any = (),
    validation: str | None = None,
    output_contract: str | None = None,
    repo_root: str | os.PathLike[str] | None = None,
) -> TaskPacket:
    """Build one normalized packet and hash its canonical bytes.

    A mapping may be supplied as the first argument.  For convenience a goal
    string may also be supplied positionally; keyword form remains preferred in
    code that needs to be explicit about ownership.
    """

    source_mapping: Mapping[str, Any] | None
    if isinstance(packet, Mapping):
        source_mapping = packet
    elif packet is None:
        source_mapping = None
    else:
        if goal is not None:
            raise PacketSchemaError("goal was provided twice")
        goal = packet
        source_mapping = None
    source = _coerce_source(
        source_mapping,
        role=role,
        static_rules=static_rules,
        goal=goal,
        base_revision=base_revision,
        files_allowed=files_allowed,
        files_forbidden=files_forbidden,
        known_facts=known_facts,
        constraints=constraints,
        acceptance_criteria=acceptance_criteria,
        validation=validation_command if validation is None else validation,
        output_contract=expected_output if output_contract is None else output_contract,
    )
    payload = _build_payload(source, repo_root=repo_root)
    data = canonical_json_bytes(payload)
    digest = hashlib.sha256(data).hexdigest()
    return TaskPacket(payload=payload, canonical_bytes=data, sha256=digest)


def build_packet(*args: Any, **kwargs: Any) -> TaskPacket:
    return build_task_packet(*args, **kwargs)


def create_task_packet(*args: Any, **kwargs: Any) -> TaskPacket:
    return build_task_packet(*args, **kwargs)


make_task_packet = build_task_packet
normalize_packet = build_task_packet


def canonical_bytes(packet: TaskPacket | Mapping[str, Any], **kwargs: Any) -> bytes:
    if isinstance(packet, TaskPacket):
        return packet.canonical_bytes
    return build_task_packet(packet, **kwargs).canonical_bytes


def packet_hash(packet: TaskPacket | Mapping[str, Any], **kwargs: Any) -> str:
    if isinstance(packet, TaskPacket):
        return packet.sha256
    return build_task_packet(packet, **kwargs).sha256


hash_packet = packet_hash
serialize_packet = canonical_bytes
canonicalize_packet = canonical_bytes


def estimate_tokens(packet: TaskPacket | bytes | str, *, chars_per_token: int = 4) -> int:
    if type(chars_per_token) is not int or chars_per_token <= 0:
        raise TaskPacketError("chars_per_token must be a positive integer")
    if isinstance(packet, TaskPacket):
        size = len(packet.canonical_bytes)
    elif isinstance(packet, bytes):
        size = len(packet)
    elif isinstance(packet, str):
        size = len(packet.encode("utf-8"))
    else:
        raise TaskPacketError("token estimation requires a packet, bytes, or text")
    return max(1, (size + chars_per_token - 1) // chars_per_token)


@dataclass(frozen=True)
class DuplicateDecision:
    packet_hash: str
    duplicate: bool
    accepted: bool

    def __bool__(self) -> bool:
        return self.accepted

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)


class DuplicatePacketRegistry:
    """Content-addressed packet registry; it never limits worker concurrency."""

    def __init__(self, hashes: Iterable[str] = ()) -> None:
        self._hashes: set[str] = set()
        for value in hashes:
            self._hashes.add(self._coerce_hash(value))

    @staticmethod
    def _coerce_hash(packet: TaskPacket | str | bytes) -> str:
        if isinstance(packet, TaskPacket):
            return packet.sha256
        if isinstance(packet, bytes):
            return hashlib.sha256(packet).hexdigest()
        if isinstance(packet, str) and re.fullmatch(r"[0-9a-fA-F]{64}", packet):
            return packet.lower()
        raise TaskPacketError("packet registry requires a TaskPacket or SHA256 hash")

    @property
    def hashes(self) -> frozenset[str]:
        return frozenset(self._hashes)

    def is_duplicate(self, packet: TaskPacket | str | bytes) -> bool:
        return self._coerce_hash(packet) in self._hashes

    def seen(self, packet: TaskPacket | str | bytes) -> bool:
        return self.is_duplicate(packet)

    def check(self, packet: TaskPacket | str | bytes) -> DuplicateDecision:
        digest = self._coerce_hash(packet)
        duplicate = digest in self._hashes
        return DuplicateDecision(digest, duplicate, not duplicate)

    def register(
        self,
        packet: TaskPacket | str | bytes,
        *,
        reject_duplicate: bool = False,
    ) -> DuplicateDecision:
        decision = self.check(packet)
        if decision.duplicate:
            if reject_duplicate:
                raise DuplicatePacketError(decision.packet_hash)
            return decision
        self._hashes.add(decision.packet_hash)
        return decision

    add = register

    def reserve(self, packet: TaskPacket | str | bytes) -> DuplicateDecision:
        return self.register(packet, reject_duplicate=True)

    def reject_duplicate(self, packet: TaskPacket | str | bytes) -> DuplicateDecision:
        return self.reserve(packet)

    def clear(self) -> None:
        self._hashes.clear()


PacketDeduplicator = DuplicatePacketRegistry


@dataclass(frozen=True)
class BudgetDecision:
    accepted: bool
    blocking: bool
    soft_exceeded: bool
    hard_exceeded: bool
    duplicate: bool
    packet_hash: str | None
    added_tokens: int
    added_cost: float
    used_tokens: int
    used_cost: float
    reason: str | None = None
    remediation: tuple[str, ...] = ()

    @property
    def allowed(self) -> bool:
        return self.accepted

    @property
    def approval_allowed(self) -> bool:
        return self.accepted and not self.blocking

    def __bool__(self) -> bool:
        return self.accepted

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)


class WaveBudget:
    """Account tokens/cost for one wave without imposing a worker-count cap."""

    def __init__(
        self,
        profile: str | TokenProfile | None = None,
        *,
        soft_tokens: int | None = None,
        hard_tokens: int | None = None,
        soft_cost: float | None = None,
        hard_cost: float | None = None,
        duplicate_registry: DuplicatePacketRegistry | None = None,
    ) -> None:
        selected = get_profile(profile)
        self.soft_tokens = (
            selected.wave_soft_tokens if soft_tokens is None else soft_tokens
        )
        self.hard_tokens = (
            selected.wave_hard_tokens if hard_tokens is None else hard_tokens
        )
        self.soft_cost = soft_cost
        self.hard_cost = hard_cost
        self._validate_limit(self.soft_tokens, "soft_tokens")
        self._validate_limit(self.hard_tokens, "hard_tokens")
        self._validate_limit(self.soft_cost, "soft_cost", allow_float=True)
        self._validate_limit(self.hard_cost, "hard_cost", allow_float=True)
        if (
            self.soft_tokens is not None
            and self.hard_tokens is not None
            and self.soft_tokens > self.hard_tokens
        ):
            raise TaskPacketError("soft token budget cannot exceed hard token budget")
        if (
            self.soft_cost is not None
            and self.hard_cost is not None
            and self.soft_cost > self.hard_cost
        ):
            raise TaskPacketError("soft cost budget cannot exceed hard cost budget")
        self.used_tokens = 0
        self.used_cost = 0.0
        self.duplicate_registry = duplicate_registry or DuplicatePacketRegistry()
        self.last_decision: BudgetDecision | None = None

    @classmethod
    def from_profile(cls, profile: str | TokenProfile) -> "WaveBudget":
        return cls(profile)

    @staticmethod
    def _validate_limit(value: Any, name: str, *, allow_float: bool = False) -> None:
        if value is None:
            return
        if allow_float:
            if type(value) not in {int, float} or not math.isfinite(float(value)) or value < 0:
                raise TaskPacketError(f"{name} must be a finite non-negative number")
        elif type(value) is not int or value < 0:
            raise TaskPacketError(f"{name} must be a non-negative integer")

    def _amounts(
        self,
        packet_or_tokens: TaskPacket | int,
        estimated_tokens: int | None,
        cost: float,
    ) -> tuple[int, float, str | None]:
        if isinstance(packet_or_tokens, TaskPacket):
            tokens = estimate_tokens(packet_or_tokens) if estimated_tokens is None else estimated_tokens
            digest = packet_or_tokens.sha256
        else:
            tokens = packet_or_tokens if estimated_tokens is None else estimated_tokens
            digest = None
        self._validate_limit(tokens, "estimated_tokens")
        self._validate_limit(cost, "cost", allow_float=True)
        return tokens, float(cost), digest

    def consume(
        self,
        packet_or_tokens: TaskPacket | int,
        estimated_tokens: int | None = None,
        *,
        cost: float = 0.0,
        packet_hash_value: str | None = None,
        packet_hash: str | None = None,
    ) -> BudgetDecision:
        tokens, amount, digest = self._amounts(packet_or_tokens, estimated_tokens, cost)
        digest = packet_hash or packet_hash_value or digest
        duplicate = False
        if digest is not None:
            duplicate = self.duplicate_registry.is_duplicate(digest)
        projected_tokens = self.used_tokens + tokens
        projected_cost = self.used_cost + amount
        hard_exceeded = (
            self.hard_tokens is not None and projected_tokens > self.hard_tokens
        ) or (self.hard_cost is not None and projected_cost > self.hard_cost)
        soft_exceeded = (
            self.soft_tokens is not None and projected_tokens > self.soft_tokens
        ) or (self.soft_cost is not None and projected_cost > self.soft_cost)
        if duplicate:
            decision = BudgetDecision(
                False,
                True,
                soft_exceeded,
                False,
                True,
                digest,
                0,
                0.0,
                self.used_tokens,
                self.used_cost,
                "duplicate packet hash",
            )
        elif hard_exceeded:
            decision = BudgetDecision(
                False,
                True,
                soft_exceeded,
                True,
                False,
                digest,
                0,
                0.0,
                self.used_tokens,
                self.used_cost,
                "hard budget exhausted",
                HARD_BUDGET_REMEDIATION,
            )
        else:
            if digest is not None:
                self.duplicate_registry.register(digest)
            self.used_tokens = projected_tokens
            self.used_cost = projected_cost
            decision = BudgetDecision(
                True,
                soft_exceeded,
                soft_exceeded,
                False,
                False,
                digest,
                tokens,
                amount,
                self.used_tokens,
                self.used_cost,
                "soft budget exceeded" if soft_exceeded else None,
            )
        self.last_decision = decision
        return decision

    def reserve(self, *args: Any, **kwargs: Any) -> BudgetDecision:
        decision = self.consume(*args, **kwargs)
        if decision.hard_exceeded:
            raise BudgetExceeded("hard")
        if decision.duplicate:
            raise DuplicatePacketError(decision.packet_hash or "")
        return decision

    record = consume
    add = consume
    account = consume

    @property
    def soft_exhausted(self) -> bool:
        return bool(self.last_decision and self.last_decision.soft_exceeded)

    @property
    def soft_signal(self) -> bool:
        return self.soft_exhausted

    @property
    def hard_exhausted(self) -> bool:
        return bool(self.last_decision and self.last_decision.hard_exceeded)

    @property
    def hard_rejected(self) -> bool:
        return self.hard_exhausted

    @property
    def tokens(self) -> int:
        return self.used_tokens

    @property
    def cost(self) -> float:
        return self.used_cost

    def approval_allowed(self) -> bool:
        return not self.soft_exhausted and not self.hard_exhausted

    def can_release_executor(self) -> bool:
        # Any exhausted budget is a non-approval.  Executor release is owned by
        # the root and is never inferred from a worker-count setting.
        return self.approval_allowed()

    def snapshot(self) -> dict[str, Any]:
        return {
            "used_tokens": self.used_tokens,
            "used_cost": self.used_cost,
            "soft_tokens": self.soft_tokens,
            "hard_tokens": self.hard_tokens,
            "soft_cost": self.soft_cost,
            "hard_cost": self.hard_cost,
            "packet_hashes": sorted(self.duplicate_registry.hashes),
        }


TokenBudget = WaveBudget
WaveTokenBudget = WaveBudget


class PacketBudget(WaveBudget):
    """Same accounting contract using a profile's per-packet limits."""

    def __init__(
        self,
        profile: str | TokenProfile | None = None,
        *,
        soft_tokens: int | None = None,
        hard_tokens: int | None = None,
        soft_cost: float | None = None,
        hard_cost: float | None = None,
        duplicate_registry: DuplicatePacketRegistry | None = None,
    ) -> None:
        selected = get_profile(profile)
        super().__init__(
            None,
            soft_tokens=(
                selected.packet_soft_tokens if soft_tokens is None else soft_tokens
            ),
            hard_tokens=(
                selected.packet_hard_tokens if hard_tokens is None else hard_tokens
            ),
            soft_cost=soft_cost,
            hard_cost=hard_cost,
            duplicate_registry=duplicate_registry,
        )


PacketTokenBudget = PacketBudget


def wave_budget(profile: str | TokenProfile | None = None, **kwargs: Any) -> WaveBudget:
    return WaveBudget(profile, **kwargs)


def packet_budget(profile: str | TokenProfile | None = None, **kwargs: Any) -> PacketBudget:
    return PacketBudget(profile, **kwargs)


__all__ = [
    "BudgetDecision",
    "BudgetExceeded",
    "CANONICAL_PACKET_KEYS",
    "DuplicateDecision",
    "DuplicatePacketError",
    "DuplicatePacketRegistry",
    "PACKET_KEYS",
    "PACKET_VERSION",
    "PacketDeduplicator",
    "PacketBudget",
    "PacketPathError",
    "PacketSchemaError",
    "PacketSecretError",
    "PacketTokenBudget",
    "PathContainmentError",
    "SecretLikeError",
    "TaskPacket",
    "TaskPacketError",
    "TokenBudget",
    "VERSION",
    "WaveBudget",
    "WaveTokenBudget",
    "build_packet",
    "build_task_packet",
    "canonical_bytes",
    "canonicalize_packet",
    "canonical_json_bytes",
    "create_task_packet",
    "estimate_tokens",
    "hash_packet",
    "make_task_packet",
    "normalize_packet",
    "normalize_repo_path",
    "packet_hash",
    "packet_budget",
    "serialize_packet",
    "wave_budget",
]
