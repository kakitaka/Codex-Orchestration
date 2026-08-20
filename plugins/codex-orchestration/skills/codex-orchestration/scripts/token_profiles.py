"""Backward-compatible token profiles and route recommendations.

The profile module is deliberately small and dependency free.  A profile is a
set of advisory limits; it never rewrites an explicitly selected model or
reasoning effort.  The ``legacy`` profile represents the pre-profile contract
and is therefore the default when no profile was requested.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
import re
from typing import Any, Mapping


PROFILE_NAMES = ("legacy", "lean", "balanced", "quality")
DEFAULT_PROFILE = "legacy"


class TokenProfileError(ValueError):
    """Raised when a profile or route recommendation is invalid."""


@dataclass(frozen=True)
class TokenProfile:
    """One bounded token profile.

    ``None`` budgets mean that the legacy path has no newly introduced budget
    gate.  This is intentional: selecting no profile must preserve the old
    routing behavior byte-for-byte at the state-contract level.
    """

    name: str
    advisor_loops: int
    packet_soft_tokens: int | None
    packet_hard_tokens: int | None
    wave_soft_tokens: int | None
    wave_hard_tokens: int | None

    def __post_init__(self) -> None:
        if type(self.name) is not str or self.name not in PROFILE_NAMES:
            raise TokenProfileError("invalid token profile name")
        if type(self.advisor_loops) is not int or not 1 <= self.advisor_loops <= 128:
            raise TokenProfileError("invalid advisor loop limit")
        values = (
            ("packet_soft_tokens", self.packet_soft_tokens),
            ("packet_hard_tokens", self.packet_hard_tokens),
            ("wave_soft_tokens", self.wave_soft_tokens),
            ("wave_hard_tokens", self.wave_hard_tokens),
        )
        for label, value in values:
            if value is not None and (
                type(value) is not int or value < 0 or value > 10**12
            ):
                raise TokenProfileError(f"invalid {label}")
        for soft, hard in (
            (self.packet_soft_tokens, self.packet_hard_tokens),
            (self.wave_soft_tokens, self.wave_hard_tokens),
        ):
            if soft is not None and hard is not None and soft > hard:
                raise TokenProfileError("soft token budget cannot exceed hard budget")

    @property
    def advisor_review_limit(self) -> int:
        return self.advisor_loops

    @property
    def advisor_loop_limit(self) -> int:
        return self.advisor_loops

    @property
    def advisor_limit(self) -> int:
        return self.advisor_loops

    @property
    def packet_soft_budget(self) -> int | None:
        return self.packet_soft_tokens

    @property
    def packet_hard_budget(self) -> int | None:
        return self.packet_hard_tokens

    @property
    def packet_soft(self) -> int | None:
        return self.packet_soft_tokens

    @property
    def packet_soft_limit(self) -> int | None:
        return self.packet_soft_tokens

    @property
    def packet_hard(self) -> int | None:
        return self.packet_hard_tokens

    @property
    def packet_hard_limit(self) -> int | None:
        return self.packet_hard_tokens

    @property
    def wave_soft_budget(self) -> int | None:
        return self.wave_soft_tokens

    @property
    def wave_hard_budget(self) -> int | None:
        return self.wave_hard_tokens

    @property
    def wave_soft(self) -> int | None:
        return self.wave_soft_tokens

    @property
    def wave_soft_limit(self) -> int | None:
        return self.wave_soft_tokens

    @property
    def wave_hard(self) -> int | None:
        return self.wave_hard_tokens

    @property
    def wave_hard_limit(self) -> int | None:
        return self.wave_hard_tokens

    @property
    def legacy_compatible(self) -> bool:
        return self.name == "legacy"

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "advisor_loops": self.advisor_loops,
            "packet_soft_tokens": self.packet_soft_tokens,
            "packet_hard_tokens": self.packet_hard_tokens,
            "wave_soft_tokens": self.wave_soft_tokens,
            "wave_hard_tokens": self.wave_hard_tokens,
        }

    def __getitem__(self, key: str) -> Any:
        aliases = {
            "advisor_limit": "advisor_loops",
            "advisor_loop_limit": "advisor_loops",
            "advisor_max_rounds": "advisor_loops",
            "advisor_reviews": "advisor_loops",
            "packet_soft": "packet_soft_tokens",
            "packet_hard": "packet_hard_tokens",
            "packet_soft_budget": "packet_soft_tokens",
            "packet_hard_budget": "packet_hard_tokens",
            "wave_soft": "wave_soft_tokens",
            "wave_hard": "wave_hard_tokens",
            "wave_soft_budget": "wave_soft_tokens",
            "wave_hard_budget": "wave_hard_tokens",
        }
        return self.as_dict()[aliases.get(key, key)]

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default


_PROFILE_VALUES = MappingProxyType({
    "legacy": TokenProfile("legacy", 8, None, None, None, None),
    "lean": TokenProfile("lean", 1, 3_000, 6_000, 12_000, 20_000),
    "balanced": TokenProfile("balanced", 2, 5_000, 9_000, 24_000, 36_000),
    "quality": TokenProfile("quality", 4, 8_000, 14_000, 48_000, 72_000),
})

# Public aliases make the schema easy to consume from small scripts without
# requiring callers to know the private implementation name.
TOKEN_PROFILES: Mapping[str, TokenProfile] = _PROFILE_VALUES
PROFILES: Mapping[str, TokenProfile] = _PROFILE_VALUES
PROFILE_DEFINITIONS: Mapping[str, TokenProfile] = _PROFILE_VALUES
LEGACY_PROFILE = _PROFILE_VALUES["legacy"]
LEAN_PROFILE = _PROFILE_VALUES["lean"]
BALANCED_PROFILE = _PROFILE_VALUES["balanced"]
QUALITY_PROFILE = _PROFILE_VALUES["quality"]


def normalize_profile_name(value: str | TokenProfile | None) -> str:
    """Return a canonical profile name, defaulting to ``legacy``."""

    if value is None:
        return DEFAULT_PROFILE
    if isinstance(value, TokenProfile):
        value = value.name
    if type(value) is not str:
        raise TokenProfileError("token profile must be a string")
    name = value.strip().lower()
    if name not in _PROFILE_VALUES:
        choices = ", ".join(PROFILE_NAMES)
        raise TokenProfileError(f"unknown token profile {value!r}; choose {choices}")
    return name


def get_profile(value: str | TokenProfile | None = None) -> TokenProfile:
    """Resolve a profile without changing any caller-owned value."""

    return _PROFILE_VALUES[normalize_profile_name(value)]


def get_token_profile(value: str | TokenProfile | None = None) -> TokenProfile:
    return get_profile(value)


def resolve_profile(value: str | TokenProfile | None = None) -> TokenProfile:
    return get_profile(value)


def profile_for(value: str | TokenProfile | None = None) -> TokenProfile:
    return get_profile(value)


def profile_names() -> tuple[str, ...]:
    return PROFILE_NAMES


def advisor_loop_limit(profile: str | TokenProfile | None = None) -> int:
    return get_profile(profile).advisor_loops


def profile_budgets(profile: str | TokenProfile | None = None) -> dict[str, int | None]:
    selected = get_profile(profile)
    return {
        "packet_soft_tokens": selected.packet_soft_tokens,
        "packet_hard_tokens": selected.packet_hard_tokens,
        "wave_soft_tokens": selected.wave_soft_tokens,
        "wave_hard_tokens": selected.wave_hard_tokens,
    }


# The ladder is deliberately monotonic.  ``max`` is only an escalation step;
# ordinary recommendations stop at the effort appropriate to the profile.
RECOMMENDATION_LADDER: tuple[Mapping[str, str], ...] = (
    MappingProxyType({"model": "gpt-5.6-luna", "effort": "medium"}),
    MappingProxyType({"model": "gpt-5.6-terra", "effort": "medium"}),
    MappingProxyType({"model": "gpt-5.6-terra", "effort": "high"}),
    MappingProxyType({"model": "gpt-5.6-sol", "effort": "high"}),
    MappingProxyType({"model": "gpt-5.6-sol", "effort": "max"}),
)

# Review-facing roles need a stronger default than a normal Executor.  This is
# still only a recommendation: an explicit user route and an applicable
# repository requirement are resolved before it.
REVIEW_ROLE_NAMES = frozenset({"auditor", "advisor", "reviewer"})
REVIEW_ROLE_FLOOR = MappingProxyType({"model": "gpt-5.6-sol", "effort": "high"})
_SUPPORTED_EFFORTS = frozenset(
    {"low", "medium", "high", "xhigh", "max", "ultra"}
)
_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+/@-]{0,199}$")


def _worker_requires_luna_max(worker_requirement: Any) -> bool:
    return _worker_requirement_route(worker_requirement) is not None


def _worker_requirement_route(worker_requirement: Any) -> dict[str, str] | None:
    """Return the concrete route carried by the supported Luna requirement.

    ``worker_requirement`` is an AGENTS-level requirement, not a profile
    recommendation. Only an exact structured mapping can elevate a route;
    prose and compatibility strings are informational input.
    """

    if isinstance(worker_requirement, str):
        return None
    if not isinstance(worker_requirement, Mapping):
        return None
    keys = set(worker_requirement)
    if keys not in (
        {"model", "effort"},
        {"model", "reasoning_effort"},
        {"model", "model_reasoning_effort"},
    ):
        raise TokenProfileError("worker requirement has unsupported fields")
    effort_key = (
        "effort"
        if "effort" in worker_requirement
        else (
            "reasoning_effort"
            if "reasoning_effort" in worker_requirement
            else "model_reasoning_effort"
        )
    )
    model = worker_requirement.get("model")
    effort = worker_requirement.get(effort_key)
    if model != "gpt-5.6-luna" or effort != "max":
        raise TokenProfileError("worker requirement must be gpt-5.6-luna@max")
    return {"model": "gpt-5.6-luna", "effort": "max"}


def _route_value(route: Any, key: str) -> str | None:
    if isinstance(route, Mapping):
        value = route.get(key)
    else:
        value = getattr(route, key, None)
    return value if isinstance(value, str) and value else None


def _validate_route_value(value: Any, key: str, source: str) -> str:
    if type(value) is not str or not value.strip():
        raise TokenProfileError(f"{source} {key} must be a non-empty string")
    value = value.strip()
    if key == "effort" and value not in _SUPPORTED_EFFORTS:
        raise TokenProfileError(f"{source} effort is unsupported")
    if key == "model" and _MODEL_RE.fullmatch(value) is None:
        raise TokenProfileError(f"{source} model is malformed")
    return value


def _extract_route(route: Any, source: str) -> dict[str, str]:
    if route is None:
        return {}
    if not isinstance(route, Mapping):
        raise TokenProfileError(f"{source} route must be an object")
    result: dict[str, str] = {}
    for key in ("model", "effort"):
        if key in route:
            result[key] = _validate_route_value(route[key], key, source)
    unknown = set(route) - {"model", "effort"}
    if unknown:
        raise TokenProfileError(f"{source} route contains unsupported fields")
    return result


def _recommendation_index(
    profile: TokenProfile,
    escalation: int,
    *,
    seat: str = "executor",
) -> int:
    if type(escalation) is not int or escalation < 0:
        raise TokenProfileError("escalation must be a non-negative integer")
    # lean starts at Luna, balanced at Terra, quality at Sol.  Legacy keeps the
    # historical Luna route as the least surprising advisory fallback.
    start = {"legacy": 0, "lean": 0, "balanced": 1, "quality": 3}[profile.name]
    if isinstance(seat, str) and seat.strip().lower() in REVIEW_ROLE_NAMES:
        start = max(start, 3)
    return min(start + escalation, len(RECOMMENDATION_LADDER) - 1)


def recommend_route(
    profile: str | TokenProfile | None = None,
    *,
    seat: str = "executor",
    escalation: int = 0,
    worker_requirement: Any = None,
) -> dict[str, str]:
    """Return a recommendation only; it never mutates a configured route."""

    selected = get_profile(profile)
    worker_route = _worker_requirement_route(worker_requirement)
    if worker_route is not None:
        return dict(worker_route)
    index = _recommendation_index(selected, escalation, seat=seat)
    recommendation = dict(RECOMMENDATION_LADDER[index])
    if (
        isinstance(seat, str)
        and seat.strip().lower() in REVIEW_ROLE_NAMES
        and escalation == 0
    ):
        # Keep this explicit so a future ladder/profile edit cannot make a
        # default review recommendation weaker than Sol High.
        recommendation = dict(REVIEW_ROLE_FLOOR)
    return recommendation


def recommend_model_effort(
    profile: str | TokenProfile | None = None,
    *,
    seat: str = "executor",
    escalation: int = 0,
    worker_requirement: Any = None,
) -> dict[str, str]:
    return recommend_route(
        profile,
        seat=seat,
        escalation=escalation,
        worker_requirement=worker_requirement,
    )


def _first_route_value(
    key: str,
    explicit: Any,
    agents: Any,
    configured: Any,
) -> tuple[str | None, str | None]:
    for source, value in (
        ("explicit", explicit),
        ("agents", agents),
        ("configured", configured),
    ):
        result = _route_value(value, key) if key in {"model", "effort"} else None
        if result is None and isinstance(value, str):
            result = value
        if result is not None:
            return result, source
    return None, None


def _effective_agents_route(agents: Any, worker_requirement: Any) -> Any:
    """Merge an AGENTS-level worker requirement over a generic AGENTS route."""

    worker_route = _worker_requirement_route(worker_requirement)
    if worker_route is None:
        return agents
    if isinstance(agents, Mapping):
        merged = dict(agents)
        merged.update(worker_route)
        return merged
    return worker_route


def resolve_route(
    *,
    profile: str | TokenProfile | None = None,
    seat: str = "executor",
    explicit_model: str | None = None,
    explicit_effort: str | None = None,
    agents_model: str | None = None,
    agents_effort: str | None = None,
    configured_model: str | None = None,
    configured_effort: str | None = None,
    worker_requirement: Any = None,
    explicit: Mapping[str, Any] | None = None,
    agents: Mapping[str, Any] | None = None,
    configured: Mapping[str, Any] | None = None,
) -> dict[str, str]:
    """Resolve model and effort using the documented precedence.

    Explicit user values win independently for model and effort.  AGENTS rules
    then win over the saved configured route, followed by the profile's
    recommendation.  The returned mapping is a new value and does not mutate
    any input route.
    """

    explicit_values = _extract_route(explicit, "explicit")
    agents_values = _extract_route(agents, "agents")
    configured_values = _extract_route(configured, "configured")
    if explicit_model is not None:
        explicit_model = _validate_route_value(explicit_model, "model", "explicit")
    if explicit_effort is not None:
        explicit_effort = _validate_route_value(explicit_effort, "effort", "explicit")
    if agents_model is not None:
        agents_model = _validate_route_value(agents_model, "model", "agents")
    if agents_effort is not None:
        agents_effort = _validate_route_value(agents_effort, "effort", "agents")
    if configured_model is not None:
        configured_model = _validate_route_value(configured_model, "model", "configured")
    if configured_effort is not None:
        configured_effort = _validate_route_value(configured_effort, "effort", "configured")
    for source, values, model_value, effort_value in (
        ("explicit", explicit_values, explicit_model, explicit_effort),
        ("agents", agents_values, agents_model, agents_effort),
        ("configured", configured_values, configured_model, configured_effort),
    ):
        if (
            model_value is not None
            and "model" in values
            and values["model"] != model_value
        ) or (
            effort_value is not None
            and "effort" in values
            and values["effort"] != effort_value
        ):
            raise TokenProfileError(f"conflicting {source} route forms")
    explicit_model = explicit_values.get("model", explicit_model)
    explicit_effort = explicit_values.get("effort", explicit_effort)
    agents_model = agents_values.get("model", agents_model)
    agents_effort = agents_values.get("effort", agents_effort)
    configured_model = configured_values.get("model", configured_model)
    configured_effort = configured_values.get("effort", configured_effort)
    effective_agents = _effective_agents_route(agents, worker_requirement)
    recommendation = recommend_route(
        profile,
        seat=seat,
        worker_requirement=worker_requirement,
    )
    model, _ = _first_route_value(
        "model", explicit_model, _route_value(effective_agents, "model") or agents_model, configured_model
    )
    effort, _ = _first_route_value(
        "effort", explicit_effort, _route_value(effective_agents, "effort") or agents_effort, configured_effort
    )
    if model is None:
        model = recommendation["model"]
    if effort is None:
        effort = recommendation["effort"]
    if not isinstance(model, str) or not isinstance(effort, str):
        raise TokenProfileError("resolved route is missing model or effort")
    return {"model": model, "effort": effort}


def resolve_route_with_source(**kwargs: Any) -> dict[str, str]:
    """Resolve a route and include provenance for diagnostics."""

    # Keep the public route shape compact while allowing callers that need an
    # audit explanation to request the source explicitly.
    worker_requirement = kwargs.get("worker_requirement")
    explicit = kwargs.get("explicit")
    agents = kwargs.get("agents")
    configured = kwargs.get("configured")
    explicit_values = _extract_route(explicit, "explicit")
    agents_values = _extract_route(agents, "agents")
    configured_values = _extract_route(configured, "configured")
    explicit_model = explicit_values.get("model", kwargs.get("explicit_model"))
    explicit_effort = explicit_values.get("effort", kwargs.get("explicit_effort"))
    effective_agents = _effective_agents_route(agents, worker_requirement)
    agents_model = _route_value(effective_agents, "model") or agents_values.get(
        "model", kwargs.get("agents_model")
    )
    agents_effort = _route_value(effective_agents, "effort") or agents_values.get(
        "effort", kwargs.get("agents_effort")
    )
    configured_model = configured_values.get("model", kwargs.get("configured_model"))
    configured_effort = configured_values.get("effort", kwargs.get("configured_effort"))
    resolved = resolve_route(**kwargs)
    _, model_source = _first_route_value(
        "model", explicit_model, agents_model, configured_model
    )
    _, effort_source = _first_route_value(
        "effort", explicit_effort, agents_effort, configured_effort
    )
    fallback_source = (
        "agents" if _worker_requirement_route(worker_requirement) is not None else "profile"
    )
    model_source = model_source or fallback_source
    effort_source = effort_source or fallback_source
    return {
        "model": resolved["model"],
        "effort": resolved["effort"],
        "model_source": model_source,
        "effort_source": effort_source,
        "source": model_source if model_source == effort_source else f"{model_source}+{effort_source}",
    }


def resolve_model_effort(*args: Any, **kwargs: Any) -> dict[str, str]:
    """Compatibility alias for callers that use a model/effort name."""

    if args:
        if len(args) > 3:
            raise TypeError("resolve_model_effort accepts at most three positional values")
        for name, value in zip(("explicit", "agents", "configured"), args):
            kwargs.setdefault(name, value)
    return resolve_route(**kwargs)


__all__ = [
    "DEFAULT_PROFILE",
    "BALANCED_PROFILE",
    "LEAN_PROFILE",
    "LEGACY_PROFILE",
    "PROFILE_NAMES",
    "PROFILES",
    "PROFILE_DEFINITIONS",
    "QUALITY_PROFILE",
    "RECOMMENDATION_LADDER",
    "TOKEN_PROFILES",
    "TokenProfile",
    "TokenProfileError",
    "advisor_loop_limit",
    "get_profile",
    "get_token_profile",
    "normalize_profile_name",
    "profile_budgets",
    "profile_for",
    "profile_names",
    "resolve_profile",
    "recommend_model_effort",
    "recommend_route",
    "resolve_model_effort",
    "resolve_route",
    "resolve_route_with_source",
]
