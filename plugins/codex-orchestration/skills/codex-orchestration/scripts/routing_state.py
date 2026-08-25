#!/usr/bin/env python3
"""Fail-closed validation for persisted Codex-Orchestration routing state.

This module deliberately depends only on the Python standard library so every
packaged entry point can import the same contract validator.
"""

from __future__ import annotations

import re
from typing import Any

try:
    from token_profiles import PROFILE_NAMES
except ImportError:  # pragma: no cover - package-style import fallback
    from .token_profiles import PROFILE_NAMES


MANAGED_MARKER = "[codex-orchestration managed-policy v1]"
ROUTING_TOOL_NAMESPACE = "agents"
NATIVE_MODEL_OVERRIDE_FIELD = "expose_spawn_agent_model_overrides"
FABLE_MODEL = "claude-fable-5"
FABLE_EFFORTS = frozenset({"low", "medium", "high", "xhigh", "max"})
OPUS_MODEL = "claude-opus-5"
OPUS_EFFORTS = frozenset({"low", "medium", "high", "xhigh", "max"})
TERRA_LUNA_SOL_ESCALATION_PRESET = "terra-luna-sol-escalation"
TERRA_LUNA_SOL_ESCALATION_ROOT_MODEL = "gpt-5.6-terra"
TERRA_LUNA_SOL_ESCALATION_ROOT_EFFORT = "medium"
TERRA_LUNA_SOL_ESCALATION_EXECUTOR_MODEL = "gpt-5.6-luna"
TERRA_LUNA_SOL_ESCALATION_EXECUTOR_EFFORT = "max"
TERRA_LUNA_SOL_ESCALATION_ADVISOR_MODEL = "gpt-5.6-sol"
TERRA_LUNA_SOL_ESCALATION_ADVISOR_EFFORT = "max"
TERRA_LUNA_SOL_ESCALATION_MULTI_AGENT_ENABLED = True
TERRA_LUNA_SOL_ESCALATION_SUBAGENT_ENABLED = True
FABLE_SERVERS = frozenset(
    {
        "fable-advisor-python3",
        "fable-advisor-python",
        "fable-advisor-py",
    }
)

_SCHEMA_POLICY_PAIRS = {
    1: 1,
    2: 2,
    3: 3,
    4: 4,
    5: 5,
    6: 6,
    7: 7,
    8: 8,
}
_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+/@-]{0,199}$")
_AGENT_RE = re.compile(r"^[a-z][a-z0-9_]{0,62}$")
_EFFORT_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
_BASE_TOP_LEVEL_KEYS = frozenset(
    {
        "schema",
        "policy_version",
        "managed_by",
        "config_file",
        "executor",
        "advisor",
        "managed",
        "previous",
        "scalar_origin",
        "managed_feature",
    }
)
_BASE_MANAGED_KEYS = frozenset({"mode", "usage", "metadata", "namespace"})
_BASE_PREVIOUS_KEYS = frozenset({"mode", "usage", "metadata", "namespace"})


class RoutingStateError(ValueError):
    """The persisted value is not one exact supported routing-state contract."""


def _require(condition: bool, detail: str) -> None:
    if not condition:
        raise RoutingStateError(detail)


def _has_marker_first_line(value: Any) -> bool:
    if type(value) is not str:
        return False
    first_line, separator, body = value.partition("\n")
    return first_line == MANAGED_MARKER and separator == "\n" and bool(body.strip())


def _validate_snapshot(value: Any, expected_type: type) -> None:
    _require(type(value) is dict, "restore snapshot must be an object")
    known = value.get("known")
    present = value.get("present")
    _require(type(known) is bool, "snapshot known must be boolean")
    _require(type(present) is bool, "snapshot present must be boolean")

    if not known:
        _require(
            not present and set(value) == {"known", "present"},
            "unknown snapshot must be exactly absent",
        )
    elif not present:
        _require(
            set(value) == {"known", "present"},
            "absent snapshot has unexpected fields",
        )
    else:
        _require(
            set(value) == {"known", "present", "value"},
            "present snapshot has the wrong shape",
        )
        _require(
            type(value["value"]) is expected_type,
            "present snapshot has the wrong value type",
        )


def _validate_route(route: Any, *, seat: str, schema: int) -> str:
    _require(type(route) is dict, f"{seat} route must be an object")
    kind = route.get("kind")
    _require(type(kind) is str, f"{seat} route kind must be a string")

    if kind == "model":
        _require(
            set(route) == {"kind", "model", "effort"},
            f"{seat} model route has the wrong shape",
        )
        _require(
            type(route["model"]) is str and _MODEL_RE.fullmatch(route["model"]) is not None,
            f"{seat} model route has an invalid model",
        )
        _require(
            route["model"] not in {FABLE_MODEL, OPUS_MODEL},
            f"{seat} model route uses a reserved Claude model",
        )
        _require(
            type(route["effort"]) is str
            and _EFFORT_RE.fullmatch(route["effort"]) is not None,
            f"{seat} model route has an invalid effort",
        )
    elif kind == "agent":
        _require(
            set(route) == {"kind", "agent"},
            f"{seat} agent route has the wrong shape",
        )
        _require(
            type(route["agent"]) is str and _AGENT_RE.fullmatch(route["agent"]) is not None,
            f"{seat} agent route has an invalid name",
        )
    elif kind == "fable":
        _require(
            seat in {"planner", "advisor"} and schema >= 2,
            f"{seat} cannot use Fable in schema {schema}",
        )
        _require(
            set(route) == {"kind", "model", "effort", "server"},
            f"{seat} Fable route has the wrong shape",
        )
        _require(route["model"] == FABLE_MODEL, "Fable model is not pinned")
        _require(
            type(route["effort"]) is str and route["effort"] in FABLE_EFFORTS,
            "Fable effort is unsupported",
        )
        _require(
            type(route["server"]) is str and route["server"] in FABLE_SERVERS,
            "Fable server is unsupported",
        )
    elif kind == "claude_subscription":
        _require(
            seat in {"planner", "advisor"} and schema >= 5,
            f"{seat} cannot use a Claude subscription route in schema {schema}",
        )
        _require(
            set(route) == {"kind", "model", "effort", "server"},
            f"{seat} Claude subscription route has the wrong shape",
        )
        _require(route["model"] == OPUS_MODEL, "Claude subscription model is not pinned")
        _require(
            type(route["effort"]) is str and route["effort"] in OPUS_EFFORTS,
            "Claude Opus 5 effort is unsupported",
        )
        _require(
            type(route["server"]) is str and route["server"] in FABLE_SERVERS,
            "Claude subscription server is unsupported",
        )
    else:
        raise RoutingStateError(f"{seat} route kind is unsupported")
    return kind


def _validate_route_separation(planner: Any, advisor: Any) -> None:
    if planner is None or advisor is None:
        return
    planner_kind = planner["kind"]
    advisor_kind = advisor["kind"]
    subscription_kinds = {"fable", "claude_subscription"}
    same_route = (
        planner_kind == advisor_kind == "model"
        and planner["model"] == advisor["model"]
    ) or (
        planner_kind == advisor_kind == "agent"
        and planner["agent"] == advisor["agent"]
    ) or (
        planner_kind in subscription_kinds and advisor_kind in subscription_kinds
    )
    _require(not same_route, "Planner and Advisor routes are not independent")


def _validate_preset(
    preset: Any,
    executor: dict[str, Any],
    planner: Any,
    advisor: Any,
    designer: Any,
) -> None:
    """Validate the only persisted preset without making it a model ACL."""

    _require(
        preset is None or type(preset) is str,
        "preset must be null or a supported preset name",
    )
    if preset is None:
        return
    _require(
        preset == TERRA_LUNA_SOL_ESCALATION_PRESET,
        "preset is unsupported",
    )
    _require(
        executor
        == {
            "kind": "model",
            "model": TERRA_LUNA_SOL_ESCALATION_EXECUTOR_MODEL,
            "effort": TERRA_LUNA_SOL_ESCALATION_EXECUTOR_EFFORT,
        },
        "preset executor route is forged",
    )
    _require(planner is None, "preset cannot persist a Planner route")
    _require(advisor is None, "preset cannot persist an Advisor route")
    _require(designer is None, "preset cannot persist a Designer route")


def _validate_preset_subagent_state(
    managed_subagent: Any,
    previous_subagent: Any,
) -> None:
    """Validate the exact profile-only controls that make Luna spawnable."""

    _require(
        type(managed_subagent) is dict
        and set(managed_subagent)
        == {"feature_enabled", "agents_enabled", "model", "effort"},
        "preset subagent managed state has the wrong shape",
    )
    _require(
        managed_subagent["feature_enabled"]
        is TERRA_LUNA_SOL_ESCALATION_MULTI_AGENT_ENABLED,
        "preset multi-agent feature setting is forged",
    )
    _require(
        managed_subagent["agents_enabled"]
        is TERRA_LUNA_SOL_ESCALATION_SUBAGENT_ENABLED,
        "preset agents enabled setting is forged",
    )
    _require(
        managed_subagent["model"] == TERRA_LUNA_SOL_ESCALATION_EXECUTOR_MODEL,
        "preset subagent model is forged",
    )
    _require(
        managed_subagent["effort"] == TERRA_LUNA_SOL_ESCALATION_EXECUTOR_EFFORT,
        "preset subagent effort is forged",
    )
    _require(
        type(previous_subagent) is dict
        and set(previous_subagent)
        == {
            "feature_enabled",
            "agents_enabled",
            "model",
            "effort",
            "agents_table_was_absent",
        },
        "preset subagent restore state has the wrong shape",
    )
    _require(
        type(previous_subagent["agents_table_was_absent"]) is bool,
        "preset agents table ownership marker is invalid",
    )
    for key, expected_type in (
        ("feature_enabled", bool),
        ("agents_enabled", bool),
        ("model", str),
        ("effort", str),
    ):
        saved = previous_subagent[key]
        _validate_snapshot(saved, expected_type)
        _require(saved["known"] is True, "preset snapshot must be explicit")
    if previous_subagent["agents_table_was_absent"]:
        for key in ("agents_enabled", "model", "effort"):
            _require(
                previous_subagent[key] == {"known": True, "present": False},
                "absent agents table must have absent profile-control snapshots",
            )


def _validate_scalar_conversion(state: dict[str, Any], managed: dict[str, Any]) -> None:
    scalar_origin = state["scalar_origin"]
    managed_feature = state["managed_feature"]
    if scalar_origin is None:
        _require(managed_feature is None, "null scalar origin requires null managed feature")
        return

    _require(type(scalar_origin) is bool, "scalar origin must be null or boolean")
    _require(type(managed_feature) is dict, "scalar conversion must save a table")
    expected_feature_keys = {
        "enabled",
        "hide_spawn_agent_metadata",
        "tool_namespace",
        "multi_agent_mode_hint_text",
        "usage_hint_text",
    }
    if "model_overrides" in managed:
        expected_feature_keys.add(NATIVE_MODEL_OVERRIDE_FIELD)
    _require(
        set(managed_feature) == expected_feature_keys,
        "managed scalar conversion table has the wrong shape",
    )
    _require(
        type(managed_feature["enabled"]) is bool
        and managed_feature["enabled"] is scalar_origin,
        "managed scalar conversion enabled value is forged",
    )
    _require(
        type(managed_feature["hide_spawn_agent_metadata"]) is bool
        and managed_feature["hide_spawn_agent_metadata"] is False,
        "managed scalar conversion metadata value is forged",
    )
    _require(
        type(managed_feature["tool_namespace"]) is str
        and managed_feature["tool_namespace"] == ROUTING_TOOL_NAMESPACE,
        "managed scalar conversion namespace is forged",
    )
    _require(
        type(managed_feature["multi_agent_mode_hint_text"]) is str
        and managed_feature["multi_agent_mode_hint_text"] == managed["mode"],
        "managed scalar conversion mode is forged",
    )
    _require(
        type(managed_feature["usage_hint_text"]) is str
        and managed_feature["usage_hint_text"] == managed["usage"],
        "managed scalar conversion usage is forged",
    )
    if "model_overrides" in managed:
        _require(
            managed_feature[NATIVE_MODEL_OVERRIDE_FIELD] is True,
            "managed scalar conversion model override is forged",
        )


def _validate_token_profile(value: Any) -> None:
    _require(
        type(value) is str and value in PROFILE_NAMES,
        "token profile is unsupported",
    )


def validate_routing_state(value: Any) -> dict[str, Any]:
    """Validate one exact, complete persisted routing-state schema.

    Schemas 1 through 5 retain their historical shapes.  Schema 6 is a
    deliberately disambiguated compatibility boundary: the token-profile and
    preset variants have mutually exclusive top-level fields.  Schema 8 is
    the combined current shape and always carries both nullable fields.
    Unknown keys and future extensions are rejected intentionally.
    """

    _require(type(value) is dict, "routing state must be an object")
    schema = value.get("schema")
    policy_version = value.get("policy_version")
    _require(
        type(schema) is int and schema in _SCHEMA_POLICY_PAIRS,
        "schema must be an exact supported integer",
    )
    _require(
        type(policy_version) is int
        and policy_version == _SCHEMA_POLICY_PAIRS[schema],
        "policy version does not match schema",
    )

    has_token_profile = "token_profile" in value
    has_preset = "preset" in value
    if schema == 6:
        _require(
            has_token_profile != has_preset,
            "schema 6 must select exactly one top-level variant",
        )

    expected_top = set(_BASE_TOP_LEVEL_KEYS)
    if schema >= 3:
        expected_top.add("planner")
    if schema >= 4:
        expected_top.add("designer")
    if schema == 6:
        expected_top.add("token_profile" if has_token_profile else "preset")
    elif schema == 7:
        expected_top.add("preset")
    elif schema == 8:
        expected_top.update({"token_profile", "preset"})
    _require(set(value) == expected_top, "top-level state shape is unsupported")
    _require(value["managed_by"] == "codex-orchestration", "state owner is invalid")
    _require(
        type(value["config_file"]) is str
        and bool(value["config_file"])
        and "\x00" not in value["config_file"],
        "config path is invalid",
    )

    if schema == 6 and has_token_profile:
        _validate_token_profile(value["token_profile"])
    elif schema == 8 and value["token_profile"] is not None:
        _validate_token_profile(value["token_profile"])

    _validate_route(value["executor"], seat="executor", schema=schema)
    planner = value.get("planner")
    advisor = value["advisor"]
    designer = value.get("designer")
    if planner is not None:
        _validate_route(planner, seat="planner", schema=schema)
    if advisor is not None:
        _validate_route(advisor, seat="advisor", schema=schema)
    if designer is not None:
        designer_kind = _validate_route(designer, seat="designer", schema=schema)
        _require(
            designer_kind == "model",
            "persistent Designer must use a direct model route",
        )
    _validate_route_separation(planner, advisor)

    preset = None
    if schema == 6 and has_preset:
        preset = value["preset"]
    elif schema in {7, 8}:
        preset = value["preset"]
    if schema in {6, 7, 8} and (schema != 6 or has_preset):
        _validate_preset(preset, value["executor"], planner, advisor, designer)

    managed = value["managed"]
    previous = value["previous"]
    _require(type(managed) is dict, "managed state must be an object")
    _require(type(previous) is dict, "previous state must be an object")
    managed_has_mcp = "mcp" in managed
    previous_has_mcp = "mcp" in previous
    managed_has_overrides = "model_overrides" in managed
    previous_has_overrides = "model_overrides" in previous
    managed_has_subagent = "subagent" in managed
    previous_has_subagent = "subagent" in previous
    _require(managed_has_mcp == previous_has_mcp, "MCP state and restore data must pair")
    _require(
        managed_has_overrides == previous_has_overrides,
        "model override state and restore data must pair",
    )
    _require(
        managed_has_subagent == previous_has_subagent,
        "preset subagent state and restore data must pair",
    )
    if preset is not None:
        _require(
            not managed_has_mcp,
            "preset cannot persist MCP state",
        )
        _require(
            not managed_has_overrides,
            "preset cannot persist model override state",
        )
    _require(not managed_has_mcp or schema >= 2, "schema 1 cannot contain MCP state")

    token_variant_schema6 = schema == 6 and has_token_profile
    overrides_allowed = schema == 5 or token_variant_schema6 or schema == 8
    _require(
        not managed_has_overrides or overrides_allowed,
        "schema does not permit model override state",
    )

    preset_subagent_allowed = schema in {7, 8} and preset == TERRA_LUNA_SOL_ESCALATION_PRESET
    _require(
        not managed_has_subagent or preset_subagent_allowed,
        "subagent controls are reserved for a persisted preset",
    )
    _require(
        not preset_subagent_allowed or managed_has_subagent,
        "persisted preset must manage Luna subagent controls",
    )

    expected_managed = set(_BASE_MANAGED_KEYS)
    expected_previous = set(_BASE_PREVIOUS_KEYS)
    if managed_has_mcp:
        expected_managed.add("mcp")
        expected_previous.add("mcp")
    if managed_has_overrides:
        expected_managed.add("model_overrides")
        expected_previous.add("model_overrides")
    if managed_has_subagent:
        expected_managed.add("subagent")
        expected_previous.add("subagent")
    _require(set(managed) == expected_managed, "managed state has the wrong shape")
    _require(set(previous) == expected_previous, "restore state has the wrong shape")
    _require(_has_marker_first_line(managed["mode"]), "managed mode marker is invalid")
    _require(_has_marker_first_line(managed["usage"]), "managed usage marker is invalid")
    _require(managed["metadata"] is False, "managed metadata must be false")
    _require(
        managed["namespace"] == ROUTING_TOOL_NAMESPACE,
        "managed namespace is invalid",
    )
    if managed_has_overrides:
        _require(
            managed["model_overrides"] is True,
            "managed model override must be true",
        )

    for key, expected_type in (
        ("mode", str),
        ("usage", str),
        ("metadata", bool),
        ("namespace", str),
    ):
        _validate_snapshot(previous[key], expected_type)
    if managed_has_overrides:
        _validate_snapshot(previous["model_overrides"], bool)
    if managed_has_subagent:
        _validate_preset_subagent_state(managed["subagent"], previous["subagent"])

    subscription_routes = [
        route
        for route in (planner, advisor)
        if type(route) is dict
        and route.get("kind") in {"fable", "claude_subscription"}
    ]
    _require(
        len(subscription_routes) <= 1,
        "more than one Claude subscription seat is configured",
    )
    if managed_has_mcp:
        managed_mcp = managed["mcp"]
        previous_mcp = previous["mcp"]
        _require(type(managed_mcp) is dict and bool(managed_mcp), "MCP state is empty")
        _require(type(previous_mcp) is dict, "MCP restore state must be an object")
        _require(
            set(managed_mcp) == set(previous_mcp)
            and set(managed_mcp).issubset(FABLE_SERVERS),
            "MCP state has unsupported or unpaired servers",
        )
        _require(
            all(type(enabled) is bool for enabled in managed_mcp.values()),
            "MCP enabled values must be booleans",
        )
        for saved in previous_mcp.values():
            _validate_snapshot(saved, bool)
        true_servers = [server for server, enabled in managed_mcp.items() if enabled]
    else:
        true_servers = []

    if subscription_routes:
        selected_server = subscription_routes[0]["server"]
        _require(
            true_servers == [selected_server],
            "MCP state must enable exactly the selected Claude launcher",
        )
    else:
        _require(
            not true_servers,
            "MCP state enables a launcher without a Claude subscription seat",
        )

    _validate_scalar_conversion(value, managed)
    return value
