"""Tests Red Team campaign engine — interpolation, registry, end-to-end.

Tests unitaires (pas de marker integration) : utilisent uniquement le moteur
in-memory + actions mockees, donc tournables sans Postgres/Redis.
"""

from __future__ import annotations

import asyncio

import pytest

from apps.api.pentest.campaign import actions
from apps.api.pentest.campaign.engine import (
    CampaignEngine,
    _eval_when,
    _interpolate,
    _resolve_path,
)
from apps.api.pentest.campaign.loader import (
    list_builtin_scenarios,
    load_builtin,
    parse_scenario,
)
from apps.api.pentest.campaign.models import CampaignStatus, Scenario, Stage, StageStatus


# ──────────────────────────────────────────────────────────────────────────
# Interpolation
# ──────────────────────────────────────────────────────────────────────────


def test_resolve_path_dotted():
    ctx = {"recon": {"open_ports": [22, 80, 443]}, "target": "x.com"}
    assert _resolve_path(ctx, "target") == "x.com"
    assert _resolve_path(ctx, "recon.open_ports") == [22, 80, 443]
    assert _resolve_path(ctx, "recon.open_ports.0") == 22
    assert _resolve_path(ctx, "missing.path") is None


def test_interpolate_string_substitution():
    ctx = {"target": "demo.lab", "stage1": {"port": 8080}}
    assert _interpolate("http://{{target}}", ctx) == "http://demo.lab"
    assert _interpolate("port-{{stage1.port}}-end", ctx) == "port-8080-end"


def test_interpolate_returns_object_when_full_placeholder():
    ctx = {"recon": {"ports": [22, 80]}}
    assert _interpolate("{{recon.ports}}", ctx) == [22, 80]


def test_interpolate_dict_and_list_recursive():
    ctx = {"target": "x.com", "scope": ["x.com", "y.com"]}
    args = {"url": "https://{{target}}/api", "scope": "{{scope}}", "nested": [{"k": "{{target}}"}]}
    out = _interpolate(args, ctx)
    assert out["url"] == "https://x.com/api"
    assert out["scope"] == ["x.com", "y.com"]
    assert out["nested"][0]["k"] == "x.com"


def test_eval_when_safe():
    ctx = {"scan": {"open_ports": [22, 80]}}
    assert _eval_when("80 in {{scan.open_ports}}", ctx) is True
    assert _eval_when("443 in {{scan.open_ports}}", ctx) is False
    assert _eval_when("len({{scan.open_ports}}) > 1", ctx) is True


def test_eval_when_blocks_imports():
    ctx = {}
    # __import__ ne doit pas etre disponible (sandbox)
    assert _eval_when("__import__('os')", ctx) is False


# ──────────────────────────────────────────────────────────────────────────
# Action registry
# ──────────────────────────────────────────────────────────────────────────


def test_action_registry_has_core_families():
    names = set(actions.list_actions())
    # Au moins une action par famille
    assert any(n.startswith("recon.") for n in names)
    assert any(n.startswith("exploit.") for n in names)
    assert any(n.startswith("c2.") for n in names)
    assert any(n.startswith("exfil.") for n in names)
    assert "wait" in names
    assert "detection.check" in names
    assert "http.call" in names


def test_register_decorator_adds_action():
    @actions.register("test.echo")
    async def _echo(args, ctx):
        return {"echoed": args.get("msg")}

    fn = actions.get_action("test.echo")
    assert fn is not None
    out = asyncio.run(fn({"msg": "hi"}, {}))
    assert out == {"echoed": "hi"}


# ──────────────────────────────────────────────────────────────────────────
# Engine — execution end-to-end avec actions mockees
# ──────────────────────────────────────────────────────────────────────────


def _build_test_scenario() -> Scenario:
    """Scenario minimal : 3 etapes mockees pour eviter dependances reseau."""

    @actions.register("test.set_value")
    async def _set(args, ctx):
        return {"value": args.get("v"), "list": [1, 2, 3]}

    @actions.register("test.consume")
    async def _consume(args, ctx):
        return {"got": args.get("input"), "doubled": args.get("input", 0) * 2}

    @actions.register("test.failing")
    async def _fail(args, ctx):
        raise RuntimeError("boom")

    return Scenario(
        name="unit-test",
        description="test scenario",
        target="test.local",
        scope=["test.local"],
        stages=[
            Stage(id="s1", name="set", action="test.set_value", args={"v": 42}),
            Stage(
                id="s2",
                name="consume",
                action="test.consume",
                args={"input": "{{s1.value}}"},
            ),
            Stage(
                id="s3",
                name="conditional",
                action="test.consume",
                args={"input": 999},
                when="{{s1.value}} == 42",
            ),
            Stage(
                id="s4",
                name="skipped",
                action="test.consume",
                args={"input": 0},
                when="{{s1.value}} == 0",
            ),
        ],
    )


def test_campaign_runs_end_to_end():
    sc = _build_test_scenario()
    eng = CampaignEngine(sc)
    state = asyncio.run(eng.run())

    assert state.status == CampaignStatus.COMPLETED
    assert state.progress == 100.0
    assert len(state.stages) == 4

    s1 = state.by_stage("s1")
    assert s1 and s1.status == StageStatus.SUCCESS
    assert s1.output["value"] == 42

    s2 = state.by_stage("s2")
    assert s2 and s2.status == StageStatus.SUCCESS
    assert s2.output["got"] == 42  # interpolation dynamique
    assert s2.output["doubled"] == 84

    s3 = state.by_stage("s3")
    assert s3 and s3.status == StageStatus.SUCCESS

    s4 = state.by_stage("s4")
    assert s4 and s4.status == StageStatus.SKIPPED


def test_campaign_halts_on_failure_when_continue_on_error_false():
    @actions.register("test.boom")
    async def _b(args, ctx):
        raise RuntimeError("kaboom")

    sc = Scenario(
        name="fail-fast",
        target="test.local",
        stages=[
            Stage(id="ok", name="ok", action="test.set_value", args={"v": 1}),
            Stage(id="bad", name="bad", action="test.boom", args={}),
            Stage(id="never", name="never", action="test.set_value", args={"v": 2}),
        ],
    )
    eng = CampaignEngine(sc)
    state = asyncio.run(eng.run())

    assert state.status == CampaignStatus.FAILED
    assert state.by_stage("ok").status == StageStatus.SUCCESS
    assert state.by_stage("bad").status == StageStatus.FAILED
    assert state.by_stage("never").status == StageStatus.PENDING


def test_campaign_continues_when_continue_on_error_true():
    sc = Scenario(
        name="fail-soft",
        target="test.local",
        stages=[
            Stage(id="bad", name="bad", action="test.boom", args={}, continue_on_error=True),
            Stage(id="after", name="after", action="test.set_value", args={"v": 7}),
        ],
    )
    eng = CampaignEngine(sc)
    state = asyncio.run(eng.run())

    assert state.by_stage("bad").status == StageStatus.FAILED
    assert state.by_stage("after").status == StageStatus.SUCCESS
    assert state.status == CampaignStatus.FAILED  # une etape failed = campaign failed


def test_unknown_action_marks_failure():
    sc = Scenario(
        name="unknown",
        target="test.local",
        stages=[Stage(id="x", name="x", action="does.not.exist", args={}, continue_on_error=True)],
    )
    eng = CampaignEngine(sc)
    state = asyncio.run(eng.run())
    assert state.by_stage("x").status == StageStatus.FAILED
    assert "unknown action" in state.by_stage("x").error.lower()


def test_timeline_emits_events():
    sc = _build_test_scenario()
    eng = CampaignEngine(sc)
    asyncio.run(eng.run())

    kinds = [e.kind for e in eng.state.timeline]
    assert "start" in kinds
    assert "success" in kinds
    assert "skip" in kinds
    assert "finish" in kinds


# ──────────────────────────────────────────────────────────────────────────
# Loader / scenarios YAML
# ──────────────────────────────────────────────────────────────────────────


def test_builtin_scenarios_listed():
    items = list_builtin_scenarios()
    names = {i.get("name") for i in items if "name" in i}
    assert "quick-recon" in names
    assert "apt29-emulation" in names
    assert "ransomware-emulation" in names


def test_load_builtin_scenario_parses_clean():
    sc = load_builtin("quick-recon")
    assert sc.name == "quick-recon"
    assert len(sc.stages) >= 3
    assert all(st.action.split(".")[0] in {"recon", "detection", "exploit", "c2", "exfil", "post", "implant", "wait", "http"}
               for st in sc.stages)


def test_parse_scenario_validates_required_fields():
    with pytest.raises(Exception):
        parse_scenario({"name": "incomplete"})  # target manquant
