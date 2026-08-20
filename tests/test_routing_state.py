from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import sys
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = (
    REPO_ROOT
    / "plugins"
    / "codex-orchestration"
    / "skills"
    / "codex-orchestration"
    / "scripts"
)
sys.path.insert(0, str(SCRIPTS))

import routing_state as STATE  # noqa: E402


def snapshot(value: object = None, *, present: bool = False) -> dict[str, object]:
    saved: dict[str, object] = {"known": True, "present": present}
    if present:
        saved["value"] = value
    return saved


def fable_route(server: str = "fable-advisor-python3") -> dict[str, str]:
    return {
        "kind": "fable",
        "model": STATE.FABLE_MODEL,
        "effort": "high",
        "server": server,
    }


def opus_route(server: str = "fable-advisor-python3") -> dict[str, str]:
    return {
        "kind": "claude_subscription",
        "model": STATE.OPUS_MODEL,
        "effort": "xhigh",
        "server": server,
    }


def genuine_state(schema: int) -> dict[str, object]:
    managed: dict[str, object] = {
        "mode": f"{STATE.MANAGED_MARKER}\nmode body",
        "usage": f"{STATE.MANAGED_MARKER}\nusage body",
        "metadata": False,
        "namespace": STATE.ROUTING_TOOL_NAMESPACE,
    }
    previous: dict[str, object] = {
        "mode": snapshot(),
        "usage": snapshot("prior usage", present=True),
        "metadata": snapshot(True, present=True),
        "namespace": {"known": False, "present": False},
    }
    state: dict[str, object] = {
        "schema": schema,
        "policy_version": schema,
        "managed_by": "codex-orchestration",
        "config_file": "/tmp/codex/config.toml",
        "executor": {"kind": "model", "model": "gpt-5.6-luna", "effort": "xhigh"},
        "advisor": {"kind": "agent", "agent": "independent_advisor"},
        "managed": managed,
        "previous": previous,
        "scalar_origin": None,
        "managed_feature": None,
    }
    if schema == 2:
        state["advisor"] = fable_route()
    if schema >= 3:
        state["planner"] = fable_route()
    if schema >= 4:
        state["designer"] = {
            "kind": "model",
            "model": "gpt-designer",
            "effort": "high",
        }
    if schema in (6, 7):
        state["preset"] = None
    if schema == 8:
        state["token_profile"] = None
        state["preset"] = None
    if schema >= 2:
        managed["mcp"] = {
            "fable-advisor-python3": True,
            "fable-advisor-python": False,
        }
        previous["mcp"] = {
            "fable-advisor-python3": snapshot(),
            "fable-advisor-python": snapshot(False, present=True),
        }
    return state


def configured_preset_state(schema: int) -> dict[str, object]:
    state = genuine_state(schema)
    state["preset"] = STATE.TERRA_LUNA_SOL_ESCALATION_PRESET
    state["executor"] = {
        "kind": "model",
        "model": STATE.TERRA_LUNA_SOL_ESCALATION_EXECUTOR_MODEL,
        "effort": STATE.TERRA_LUNA_SOL_ESCALATION_EXECUTOR_EFFORT,
    }
    state["planner"] = None
    state["advisor"] = None
    state["designer"] = None
    state["managed"].pop("mcp", None)
    state["previous"].pop("mcp", None)
    state["managed"]["subagent"] = {
        "feature_enabled": True,
        "agents_enabled": True,
        "model": STATE.TERRA_LUNA_SOL_ESCALATION_EXECUTOR_MODEL,
        "effort": STATE.TERRA_LUNA_SOL_ESCALATION_EXECUTOR_EFFORT,
    }
    state["previous"]["subagent"] = {
        "feature_enabled": snapshot(False, present=True),
        "agents_enabled": snapshot(),
        "model": snapshot(),
        "effort": snapshot(),
        "agents_table_was_absent": True,
    }
    return state


class RoutingStateTests(unittest.TestCase):
    def test_genuine_schemas_one_through_eight_are_accepted(self) -> None:
        for schema in (1, 2, 3, 4, 5, 6, 7, 8):
            with self.subTest(schema=schema):
                state = genuine_state(schema)
                self.assertIs(STATE.validate_routing_state(state), state)

    def test_scalar_conversion_and_retained_disabled_mcp_are_accepted(self) -> None:
        state = genuine_state(3)
        state["planner"] = {"kind": "model", "model": "gpt-planner", "effort": "high"}
        managed = state["managed"]
        managed["mcp"] = {server: False for server in managed["mcp"]}
        state["scalar_origin"] = True
        state["managed_feature"] = {
            "enabled": True,
            "hide_spawn_agent_metadata": False,
            "tool_namespace": STATE.ROUTING_TOOL_NAMESPACE,
            "multi_agent_mode_hint_text": managed["mode"],
            "usage_hint_text": managed["usage"],
        }
        self.assertIs(STATE.validate_routing_state(state), state)

    def test_model_override_state_is_paired_typed_and_scalar_complete(self) -> None:
        state = genuine_state(5)
        state["managed"]["model_overrides"] = True
        state["previous"]["model_overrides"] = snapshot(False, present=True)
        self.assertIs(STATE.validate_routing_state(state), state)

        for label, mutate in (
            ("missing restore", lambda value: value["previous"].pop("model_overrides")),
            ("false managed", lambda value: value["managed"].update(model_overrides=False)),
            ("wrong restore", lambda value: value["previous"].update(model_overrides=snapshot(0, present=True))),
        ):
            with self.subTest(label=label):
                invalid = deepcopy(state)
                mutate(invalid)
                with self.assertRaises(STATE.RoutingStateError):
                    STATE.validate_routing_state(invalid)

        scalar = deepcopy(state)
        scalar["scalar_origin"] = True
        scalar["managed_feature"] = {
            "enabled": True,
            "hide_spawn_agent_metadata": False,
            "tool_namespace": STATE.ROUTING_TOOL_NAMESPACE,
            "multi_agent_mode_hint_text": scalar["managed"]["mode"],
            "usage_hint_text": scalar["managed"]["usage"],
            STATE.NATIVE_MODEL_OVERRIDE_FIELD: True,
        }
        self.assertIs(STATE.validate_routing_state(scalar), scalar)
        scalar["managed_feature"][STATE.NATIVE_MODEL_OVERRIDE_FIELD] = False
        with self.assertRaises(STATE.RoutingStateError):
            STATE.validate_routing_state(scalar)

        legacy = genuine_state(4)
        legacy["managed"]["model_overrides"] = True
        legacy["previous"]["model_overrides"] = snapshot()
        with self.assertRaises(STATE.RoutingStateError):
            STATE.validate_routing_state(legacy)

    def test_full_negative_invariant_matrix_fails_closed(self) -> None:
        baseline = genuine_state(7)

        def schema(value: object):
            return lambda state: state.__setitem__("schema", value)

        def policy(value: object):
            return lambda state: state.__setitem__("policy_version", value)

        mutations = [
            *( (f"schema {value!r}", schema(value)) for value in (True, 1.0, "7", None, 0, 8) ),
            *( (f"policy {value!r}", policy(value)) for value in (True, 7.0, "7", None, 0, 8, 3) ),
            ("missing top key", lambda state: state.pop("managed_by")),
            ("extra top key", lambda state: state.__setitem__("future", True)),
            ("wrong owner", lambda state: state.__setitem__("managed_by", "other")),
            ("empty config path", lambda state: state.__setitem__("config_file", "")),
            ("missing preset", lambda state: state.pop("preset")),
            ("preset boolean", lambda state: state.__setitem__("preset", True)),
            ("preset unknown", lambda state: state.__setitem__("preset", "future")),
            ("missing managed key", lambda state: state["managed"].pop("metadata")),
            ("extra managed key", lambda state: state["managed"].update(future=True)),
            ("missing previous key", lambda state: state["previous"].pop("mode")),
            ("extra previous key", lambda state: state["previous"].update(future=True)),
            ("unmarked mode", lambda state: state["managed"].update(mode="mode")),
            ("marker prefix", lambda state: state["managed"].update(mode=f"{STATE.MANAGED_MARKER} forged\nbody")),
            ("marker only", lambda state: state["managed"].update(mode=STATE.MANAGED_MARKER)),
            ("empty marker body", lambda state: state["managed"].update(mode=f"{STATE.MANAGED_MARKER}\n  ")),
            ("wrong metadata", lambda state: state["managed"].update(metadata=0)),
            ("wrong namespace", lambda state: state["managed"].update(namespace="other")),
            ("snapshot non-object", lambda state: state["previous"].update(mode=None)),
            ("snapshot known non-bool", lambda state: state["previous"].update(mode={"known": 1, "present": False})),
            ("snapshot present non-bool", lambda state: state["previous"].update(mode={"known": True, "present": 0})),
            ("snapshot unknown present", lambda state: state["previous"].update(mode={"known": False, "present": True, "value": "x"})),
            ("snapshot absent extra", lambda state: state["previous"].update(mode={"known": True, "present": False, "value": "x"})),
            ("snapshot present missing value", lambda state: state["previous"].update(mode={"known": True, "present": True})),
            ("snapshot wrong value type", lambda state: state["previous"].update(metadata={"known": True, "present": True, "value": 1})),
            ("executor null", lambda state: state.__setitem__("executor", None)),
            ("executor Fable", lambda state: state.__setitem__("executor", fable_route())),
            ("designer Fable", lambda state: state.__setitem__("designer", fable_route())),
            ("designer agent", lambda state: state.__setitem__("designer", {"kind": "agent", "agent": "designer_agent"})),
            ("model route missing effort", lambda state: state["executor"].pop("effort")),
            ("model route extra key", lambda state: state["executor"].update(future=True)),
            ("model route bad model", lambda state: state["executor"].update(model="bad model")),
            ("model route bad effort", lambda state: state["executor"].update(effort="bad effort")),
            ("agent route bad name", lambda state: state.__setitem__("executor", {"kind": "agent", "agent": "Bad-Agent"})),
            ("Fable wrong model", lambda state: state["planner"].update(model="claude-other")),
            ("Fable wrong effort", lambda state: state["planner"].update(effort="ultra")),
            ("Fable wrong server", lambda state: state["planner"].update(server="future-server")),
            ("Fable extra route key", lambda state: state["planner"].update(future=True)),
            ("same direct model", lambda state: state.update(planner={"kind": "model", "model": "same", "effort": "high"}, advisor={"kind": "model", "model": "same", "effort": "low"})),
            ("same agent", lambda state: state.update(planner={"kind": "agent", "agent": "same_agent"}, advisor={"kind": "agent", "agent": "same_agent"})),
            ("two Fable seats", lambda state: state.__setitem__("advisor", fable_route())),
            ("managed MCP missing pair", lambda state: state["previous"].pop("mcp")),
            ("previous MCP missing pair", lambda state: state["managed"].pop("mcp")),
            ("empty MCP", lambda state: (state["managed"].update(mcp={}), state["previous"].update(mcp={}))),
            ("unsupported MCP key", lambda state: (state["managed"]["mcp"].update(future=False), state["previous"]["mcp"].update(future=snapshot()))),
            ("unpaired MCP key", lambda state: state["previous"]["mcp"].pop("fable-advisor-python")),
            ("MCP value integer", lambda state: state["managed"]["mcp"].update({"fable-advisor-python": 0})),
            ("MCP snapshot wrong type", lambda state: state["previous"]["mcp"].update({"fable-advisor-python": snapshot(0, present=True)})),
            ("selected launcher disabled", lambda state: state["managed"]["mcp"].update({"fable-advisor-python3": False})),
            ("two launchers enabled", lambda state: state["managed"]["mcp"].update({"fable-advisor-python": True})),
            ("launcher without Fable", lambda state: state.__setitem__("planner", {"kind": "model", "model": "planner", "effort": "high"})),
            ("scalar origin integer", lambda state: state.__setitem__("scalar_origin", 1)),
            ("null scalar forged table", lambda state: state.__setitem__("managed_feature", {})),
            ("boolean scalar missing table", lambda state: state.update(scalar_origin=False, managed_feature=None)),
            ("scalar enabled integer", lambda state: state.update(scalar_origin=True, managed_feature={"enabled": 1, "hide_spawn_agent_metadata": False, "tool_namespace": "agents", "multi_agent_mode_hint_text": state["managed"]["mode"], "usage_hint_text": state["managed"]["usage"]})),
            ("scalar enabled float", lambda state: state.update(scalar_origin=True, managed_feature={"enabled": 1.0, "hide_spawn_agent_metadata": False, "tool_namespace": "agents", "multi_agent_mode_hint_text": state["managed"]["mode"], "usage_hint_text": state["managed"]["usage"]})),
            ("scalar metadata integer", lambda state: state.update(scalar_origin=True, managed_feature={"enabled": True, "hide_spawn_agent_metadata": 0, "tool_namespace": "agents", "multi_agent_mode_hint_text": state["managed"]["mode"], "usage_hint_text": state["managed"]["usage"]})),
            ("scalar table extra key", lambda state: state.update(scalar_origin=True, managed_feature={"enabled": True, "hide_spawn_agent_metadata": False, "tool_namespace": "agents", "multi_agent_mode_hint_text": state["managed"]["mode"], "usage_hint_text": state["managed"]["usage"], "future": True})),
            ("legacy future Planner field", lambda state: (state.update(schema=2, policy_version=2), state.__setitem__("planner", None))),
            ("legacy future Designer field", lambda state: (state.update(schema=3, policy_version=3), state.__setitem__("designer", None))),
            ("future nested snapshot field", lambda state: state["previous"]["mode"].update(future=True)),
        ]

        for label, mutate in mutations:
            with self.subTest(label=label):
                state = deepcopy(baseline)
                mutate(state)
                with self.assertRaises(STATE.RoutingStateError):
                    STATE.validate_routing_state(state)

    def test_schema_five_opus_route_is_sealed_and_exclusive(self) -> None:
        state = genuine_state(5)
        state["planner"] = opus_route()
        self.assertIs(STATE.validate_routing_state(state), state)

        mutations = {
            "Fable cross encoded": lambda value: value["planner"].update(
                model=STATE.FABLE_MODEL
            ),
            "wrong effort": lambda value: value["planner"].update(effort="ultra"),
            "wrong server": lambda value: value["planner"].update(server="future"),
            "extra key": lambda value: value["planner"].update(future=True),
            "executor Opus": lambda value: value.update(executor=opus_route()),
            "designer Opus": lambda value: value.update(designer=opus_route()),
            "mixed subscription seats": lambda value: value.update(
                advisor=fable_route()
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                invalid = deepcopy(state)
                mutate(invalid)
                with self.assertRaises(STATE.RoutingStateError):
                    STATE.validate_routing_state(invalid)

        legacy = genuine_state(4)
        legacy["planner"] = opus_route()
        with self.assertRaises(STATE.RoutingStateError):
            STATE.validate_routing_state(legacy)

    def test_schema_six_preset_route_is_sealed(self) -> None:
        state = genuine_state(6)
        state["preset"] = STATE.TERRA_LUNA_SOL_ESCALATION_PRESET
        state["executor"] = {
            "kind": "model",
            "model": STATE.TERRA_LUNA_SOL_ESCALATION_EXECUTOR_MODEL,
            "effort": STATE.TERRA_LUNA_SOL_ESCALATION_EXECUTOR_EFFORT,
        }
        state["planner"] = None
        state["advisor"] = None
        state["designer"] = None
        state["managed"].pop("mcp")
        state["previous"].pop("mcp")
        self.assertIs(STATE.validate_routing_state(state), state)

        mutations = {
            "wrong executor effort": lambda value: value["executor"].update(
                effort="high"
            ),
            "planner route": lambda value: value.update(
                planner={"kind": "model", "model": "gpt-planner", "effort": "high"}
            ),
            "advisor route": lambda value: value.update(
                advisor={"kind": "model", "model": "gpt-advisor", "effort": "high"}
            ),
            "designer route": lambda value: value.update(
                designer={"kind": "model", "model": "gpt-designer", "effort": "high"}
            ),
            "disabled MCP ownership": lambda value: value.update(
                managed={
                    **value["managed"],
                    "mcp": {
                        "fable-advisor-python3": False,
                    },
                },
                previous={
                    **value["previous"],
                    "mcp": {
                        "fable-advisor-python3": snapshot(),
                    },
                },
            ),
            "model override ownership": lambda value: value.update(
                managed={**value["managed"], "model_overrides": True},
                previous={
                    **value["previous"],
                    "model_overrides": snapshot(),
                },
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                invalid = deepcopy(state)
                mutate(invalid)
                with self.assertRaises(STATE.RoutingStateError):
                    STATE.validate_routing_state(invalid)

    def test_schema_seven_preset_subagent_route_is_sealed(self) -> None:
        state = genuine_state(7)
        state["preset"] = STATE.TERRA_LUNA_SOL_ESCALATION_PRESET
        state["executor"] = {
            "kind": "model",
            "model": STATE.TERRA_LUNA_SOL_ESCALATION_EXECUTOR_MODEL,
            "effort": STATE.TERRA_LUNA_SOL_ESCALATION_EXECUTOR_EFFORT,
        }
        state["planner"] = None
        state["advisor"] = None
        state["designer"] = None
        state["managed"].pop("mcp")
        state["previous"].pop("mcp")
        state["managed"]["subagent"] = {
            "feature_enabled": True,
            "agents_enabled": True,
            "model": STATE.TERRA_LUNA_SOL_ESCALATION_EXECUTOR_MODEL,
            "effort": STATE.TERRA_LUNA_SOL_ESCALATION_EXECUTOR_EFFORT,
        }
        state["previous"]["subagent"] = {
            "feature_enabled": snapshot(False, present=True),
            "agents_enabled": snapshot(),
            "model": snapshot(),
            "effort": snapshot(),
            "agents_table_was_absent": True,
        }
        self.assertIs(STATE.validate_routing_state(state), state)

        mutations = {
            "missing subagent managed": lambda value: value["managed"].pop(
                "subagent"
            ),
            "missing subagent restore": lambda value: value["previous"].pop(
                "subagent"
            ),
            "wrong feature value": lambda value: value["managed"]["subagent"].update(
                feature_enabled=False
            ),
            "wrong agents value": lambda value: value["managed"]["subagent"].update(
                agents_enabled=False
            ),
            "wrong default model": lambda value: value["managed"]["subagent"].update(
                model="gpt-5.6-terra"
            ),
            "wrong default effort": lambda value: value["managed"]["subagent"].update(
                effort="high"
            ),
            "unknown subagent field": lambda value: value["managed"]["subagent"].update(
                future=True
            ),
            "unknown restore field": lambda value: value["previous"]["subagent"].update(
                future=True
            ),
            "table ownership wrong type": lambda value: value["previous"][
                "subagent"
            ].update(agents_table_was_absent=1),
            "absent table had agent enabled": lambda value: value["previous"][
                "subagent"
            ].update(agents_enabled=snapshot(False, present=True)),
            "disabled MCP ownership": lambda value: value.update(
                managed={
                    **value["managed"],
                    "mcp": {
                        "fable-advisor-python3": False,
                    },
                },
                previous={
                    **value["previous"],
                    "mcp": {
                        "fable-advisor-python3": snapshot(),
                    },
                },
            ),
            "model override ownership": lambda value: value.update(
                managed={**value["managed"], "model_overrides": True},
                previous={
                    **value["previous"],
                    "model_overrides": snapshot(),
                },
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                invalid = deepcopy(state)
                mutate(invalid)
                with self.assertRaises(STATE.RoutingStateError):
                    STATE.validate_routing_state(invalid)

    def test_schema_six_variants_are_disambiguated_and_cross_features_rejected(self) -> None:
        token = genuine_state(5)
        token.update(schema=6, policy_version=6, token_profile="balanced")
        self.assertIs(STATE.validate_routing_state(token), token)

        token_with_overrides = deepcopy(token)
        token_with_overrides["managed"]["model_overrides"] = True
        token_with_overrides["previous"]["model_overrides"] = snapshot(
            False, present=True
        )
        self.assertIs(STATE.validate_routing_state(token_with_overrides), token_with_overrides)

        preset = genuine_state(6)
        preset["preset"] = STATE.TERRA_LUNA_SOL_ESCALATION_PRESET
        preset["executor"] = {
            "kind": "model",
            "model": STATE.TERRA_LUNA_SOL_ESCALATION_EXECUTOR_MODEL,
            "effort": STATE.TERRA_LUNA_SOL_ESCALATION_EXECUTOR_EFFORT,
        }
        preset["planner"] = None
        preset["advisor"] = None
        preset["designer"] = None
        preset["managed"].pop("mcp")
        preset["previous"].pop("mcp")
        self.assertIs(STATE.validate_routing_state(preset), preset)

        neither = genuine_state(5)
        neither.update(schema=6, policy_version=6)
        with self.assertRaises(STATE.RoutingStateError):
            STATE.validate_routing_state(neither)

        both = deepcopy(token)
        both["preset"] = None
        with self.assertRaises(STATE.RoutingStateError):
            STATE.validate_routing_state(both)

        token_with_subagent = deepcopy(token)
        token_with_subagent["managed"]["subagent"] = {}
        token_with_subagent["previous"]["subagent"] = {}
        with self.assertRaises(STATE.RoutingStateError):
            STATE.validate_routing_state(token_with_subagent)

        preset_with_profile = deepcopy(preset)
        preset_with_profile["token_profile"] = "lean"
        with self.assertRaises(STATE.RoutingStateError):
            STATE.validate_routing_state(preset_with_profile)

        preset_with_overrides = deepcopy(preset)
        preset_with_overrides["managed"]["model_overrides"] = True
        preset_with_overrides["previous"]["model_overrides"] = snapshot()
        with self.assertRaises(STATE.RoutingStateError):
            STATE.validate_routing_state(preset_with_overrides)

    def test_schema_seven_rejects_token_profile_and_model_overrides(self) -> None:
        token = genuine_state(7)
        token["token_profile"] = "balanced"
        with self.assertRaises(STATE.RoutingStateError):
            STATE.validate_routing_state(token)

        overrides = genuine_state(7)
        overrides["managed"]["model_overrides"] = True
        overrides["previous"]["model_overrides"] = snapshot()
        with self.assertRaises(STATE.RoutingStateError):
            STATE.validate_routing_state(overrides)

    def test_schema_eight_combines_nullable_profile_preset_and_paired_controls(self) -> None:
        state = genuine_state(8)
        self.assertIs(STATE.validate_routing_state(state), state)

        profiled = deepcopy(state)
        profiled["token_profile"] = "quality"
        self.assertIs(STATE.validate_routing_state(profiled), profiled)

        overrides = deepcopy(profiled)
        overrides["managed"]["model_overrides"] = True
        overrides["previous"]["model_overrides"] = snapshot(False, present=True)
        overrides["scalar_origin"] = True
        overrides["managed_feature"] = {
            "enabled": True,
            "hide_spawn_agent_metadata": False,
            "tool_namespace": STATE.ROUTING_TOOL_NAMESPACE,
            "multi_agent_mode_hint_text": overrides["managed"]["mode"],
            "usage_hint_text": overrides["managed"]["usage"],
            STATE.NATIVE_MODEL_OVERRIDE_FIELD: True,
        }
        self.assertIs(STATE.validate_routing_state(overrides), overrides)

        preset = configured_preset_state(8)
        self.assertIs(STATE.validate_routing_state(preset), preset)

        preset["token_profile"] = "lean"
        self.assertIs(STATE.validate_routing_state(preset), preset)

        preset_with_overrides = deepcopy(preset)
        preset_with_overrides["managed"]["model_overrides"] = True
        preset_with_overrides["previous"]["model_overrides"] = snapshot(
            False, present=True
        )
        with self.assertRaises(STATE.RoutingStateError):
            STATE.validate_routing_state(preset_with_overrides)

        preset_with_mcp = deepcopy(preset)
        preset_with_mcp["managed"]["mcp"] = {
            "fable-advisor-python3": False,
        }
        preset_with_mcp["previous"]["mcp"] = {
            "fable-advisor-python3": snapshot(),
        }
        with self.assertRaises(STATE.RoutingStateError):
            STATE.validate_routing_state(preset_with_mcp)

        missing_subagent = deepcopy(configured_preset_state(8))
        missing_subagent["managed"].pop("subagent")
        missing_subagent["previous"].pop("subagent")
        with self.assertRaises(STATE.RoutingStateError):
            STATE.validate_routing_state(missing_subagent)

        nonpreset_subagent = genuine_state(8)
        nonpreset_subagent["managed"]["subagent"] = {}
        nonpreset_subagent["previous"]["subagent"] = {}
        with self.assertRaises(STATE.RoutingStateError):
            STATE.validate_routing_state(nonpreset_subagent)

        invalid_profiles = ("", "future", 1, True)
        for profile in invalid_profiles:
            with self.subTest(profile=profile):
                invalid = deepcopy(state)
                invalid["token_profile"] = profile
                with self.assertRaises(STATE.RoutingStateError):
                    STATE.validate_routing_state(invalid)

    def test_schema_eight_shape_type_and_unknown_field_rejections(self) -> None:
        baseline = genuine_state(8)
        mutations = (
            lambda state: state.pop("token_profile"),
            lambda state: state.pop("preset"),
            lambda state: state.update(future=True),
            lambda state: state["managed"].update(future=True),
            lambda state: state["previous"].update(future=True),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                invalid = deepcopy(baseline)
                mutate(invalid)
                with self.assertRaises(STATE.RoutingStateError):
                    STATE.validate_routing_state(invalid)

        for field in ("schema", "policy_version"):
            for invalid_value in (True, 8.0, "8", None, 7, 9):
                with self.subTest(field=field, value=invalid_value):
                    invalid = deepcopy(baseline)
                    invalid[field] = invalid_value
                    with self.assertRaises(STATE.RoutingStateError):
                        STATE.validate_routing_state(invalid)

    def test_reserved_claude_models_cannot_use_generic_model_routes(self) -> None:
        seats_by_schema = {
            1: ("executor", "advisor"),
            2: ("executor", "advisor"),
            3: ("executor", "planner", "advisor"),
            4: ("executor", "planner", "advisor", "designer"),
            5: ("executor", "planner", "advisor", "designer"),
            6: ("executor", "planner", "advisor", "designer"),
            7: ("executor", "planner", "advisor", "designer"),
            8: ("executor", "planner", "advisor", "designer"),
        }
        for schema, seats in seats_by_schema.items():
            for seat in seats:
                for model in (STATE.FABLE_MODEL, STATE.OPUS_MODEL):
                    with self.subTest(schema=schema, seat=seat, model=model):
                        invalid = genuine_state(schema)
                        invalid[seat] = {
                            "kind": "model",
                            "model": model,
                            "effort": "high",
                        }
                        if not any(
                            isinstance(invalid.get(candidate), dict)
                            and invalid[candidate].get("kind")
                            in {"fable", "claude_subscription"}
                            for candidate in ("planner", "advisor")
                        ):
                            for server in invalid["managed"].get("mcp", {}):
                                invalid["managed"]["mcp"][server] = False
                        with self.assertRaises(STATE.RoutingStateError):
                            STATE.validate_routing_state(invalid)

        for sealed, generic in (
            (fable_route(), STATE.OPUS_MODEL),
            (opus_route(), STATE.FABLE_MODEL),
        ):
            for sealed_seat, generic_seat in (
                ("planner", "advisor"),
                ("advisor", "planner"),
            ):
                with self.subTest(
                    sealed_model=sealed["model"],
                    sealed_seat=sealed_seat,
                    generic_model=generic,
                    generic_seat=generic_seat,
                ):
                    invalid = genuine_state(5)
                    invalid[sealed_seat] = deepcopy(sealed)
                    invalid[generic_seat] = {
                        "kind": "model",
                        "model": generic,
                        "effort": "high",
                    }
                    with self.assertRaises(STATE.RoutingStateError):
                        STATE.validate_routing_state(invalid)

    def test_legacy_schemas_reject_future_surfaces(self) -> None:
        scenarios = []
        schema_one = genuine_state(1)
        schema_one["planner"] = None
        scenarios.append(("schema 1 planner", schema_one))
        schema_one = genuine_state(1)
        schema_one["advisor"] = fable_route()
        scenarios.append(("schema 1 Fable", schema_one))
        schema_one = genuine_state(1)
        schema_one["managed"]["mcp"] = {"fable-advisor-python3": False}
        schema_one["previous"]["mcp"] = {"fable-advisor-python3": snapshot()}
        scenarios.append(("schema 1 MCP", schema_one))
        schema_two = genuine_state(2)
        schema_two["planner"] = None
        scenarios.append(("schema 2 planner", schema_two))
        for schema in (1, 2, 3):
            legacy = genuine_state(schema)
            legacy["designer"] = None
            scenarios.append((f"schema {schema} designer", legacy))
        for schema in (1, 2, 3, 4, 5):
            legacy = genuine_state(schema)
            legacy["preset"] = None
            scenarios.append((f"schema {schema} preset", legacy))
        for schema in (1, 2, 3, 4, 5, 6):
            legacy = genuine_state(schema)
            legacy["managed"]["subagent"] = {}
            legacy["previous"]["subagent"] = {}
            scenarios.append((f"schema {schema} subagent", legacy))

        for label, state in scenarios:
            with self.subTest(label=label), self.assertRaises(STATE.RoutingStateError):
                STATE.validate_routing_state(state)

    def test_schema_six_persists_one_valid_token_profile(self) -> None:
        state = genuine_state(5)
        state["schema"] = 6
        state["policy_version"] = 6
        state["token_profile"] = "balanced"
        self.assertIs(STATE.validate_routing_state(state), state)

        for profile in (None, "", "future", 1, True):
            with self.subTest(profile=profile):
                invalid = deepcopy(state)
                invalid["token_profile"] = profile
                with self.assertRaises(STATE.RoutingStateError):
                    STATE.validate_routing_state(invalid)

    def test_schema_six_requires_profile_and_legacy_schemas_reject_it(self) -> None:
        state = genuine_state(5)
        state["schema"] = 6
        state["policy_version"] = 6
        with self.assertRaises(STATE.RoutingStateError):
            STATE.validate_routing_state(state)

        legacy = genuine_state(5)
        legacy["token_profile"] = "lean"
        with self.assertRaises(STATE.RoutingStateError):
            STATE.validate_routing_state(legacy)


if __name__ == "__main__":
    unittest.main()
