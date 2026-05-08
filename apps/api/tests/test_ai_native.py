"""Tests : Vague 14 — LLM client, triage, RAG, rule generators (mode stub)."""

from __future__ import annotations

import os

# Forcer le mode stub pour tous les tests (pas de clé API en CI)
os.environ.pop("ANTHROPIC_API_KEY", None)
os.environ.pop("OPENAI_API_KEY", None)

from apps.api.ai.llm_client import call_llm, llm_status, parse_json_response
from apps.api.ai.rag import RagDoc, rag_search, rag_summary
from apps.api.ai.rule_generator import (
    RuleSeed,
    build_sigma_rule,
    build_yara_rule,
    render_sigma_yaml,
)
from apps.api.ai.triage import TriageInput, triage_input

# ── LLM client ────────────────────────────────────────────────────────


def test_llm_status_returns_provider_info():
    s = llm_status()
    assert s["default_provider"] in ("anthropic", "openai", "ollama", "stub")
    assert "anthropic_available" in s
    assert "openai_available" in s
    assert "ollama_available" in s


def test_call_llm_stub_returns_valid_json():
    r = call_llm("hello", system="be brief", prefer="stub")
    assert r.provider == "stub"
    parsed = parse_json_response(r.text)
    assert parsed is not None
    assert parsed["verdict"] == "needs_review"


def test_parse_json_strips_markdown_fences():
    text = "Here is the result:\n```json\n{\"a\": 1}\n```\nThanks"
    assert parse_json_response(text) == {"a": 1}


def test_parse_json_handles_nested_braces():
    text = '{"outer": {"inner": "value"}, "list": [1, 2, 3]}'
    assert parse_json_response(text) == {"outer": {"inner": "value"}, "list": [1, 2, 3]}


def test_parse_json_returns_none_on_invalid():
    assert parse_json_response("just text, no json here") is None


def test_parse_json_handles_braces_in_strings():
    text = '{"msg": "this { has } braces"}'
    assert parse_json_response(text) == {"msg": "this { has } braces"}


# ── Triage ────────────────────────────────────────────────────────────


def test_triage_input_returns_required_fields():
    t = TriageInput(kind="event", title="brute force ssh", severity="high",
                    src_ip="1.2.3.4", username="admin", event_type="auth_failure",
                    message="Failed password")
    r = triage_input(t, prefer="stub")
    assert "triage" in r and "llm" in r and "raw_text" in r
    for field in ("verdict", "confidence", "severity", "summary", "recommended_actions",
                  "mitre_techniques", "iocs", "root_cause_hypothesis", "tags"):
        assert field in r["triage"]


def test_triage_llm_metadata_populated():
    t = TriageInput(kind="event", title="test")
    r = triage_input(t, prefer="stub")
    assert r["llm"]["provider"] == "stub"
    assert "usage" in r["llm"]


# ── RAG ───────────────────────────────────────────────────────────────


def _make_docs() -> list[RagDoc]:
    return [
        RagDoc(id="e1", kind="event", text="ssh brute force admin failed login attempt", metadata={}),
        RagDoc(id="e2", kind="event", text="dns query suspicious newly registered domain", metadata={}),
        RagDoc(id="e3", kind="event", text="powershell encoded command execution suspicious", metadata={}),
        RagDoc(id="e4", kind="incident", text="ssh brute force campaign multiple targets observed", metadata={}),
        RagDoc(id="e5", kind="event", text="lateral movement smb session multiple hosts", metadata={}),
    ]


def test_rag_search_finds_relevant_docs():
    docs = _make_docs()
    results = rag_search("ssh brute force attack", docs, top_k=3)
    assert len(results) >= 1
    top_ids = [r["id"] for r in results]
    assert "e1" in top_ids or "e4" in top_ids


def test_rag_search_respects_top_k():
    docs = _make_docs()
    results = rag_search("query that matches multiple docs ssh brute powershell dns", docs, top_k=2, min_score=0.0)
    assert len(results) <= 2


def test_rag_search_min_score_filters():
    docs = _make_docs()
    results = rag_search("ssh", docs, top_k=10, min_score=0.99)
    # Avec un seuil ridiculement haut, aucun résultat
    assert results == []


def test_rag_search_empty_corpus():
    assert rag_search("anything", [], top_k=5) == []


def test_rag_search_empty_query():
    assert rag_search("", _make_docs(), top_k=5) == []


def test_rag_summary_counts_by_kind():
    s = rag_summary(_make_docs())
    assert s["corpus_size"] == 5
    assert s["by_kind"]["event"] == 4
    assert s["by_kind"]["incident"] == 1
    assert s["approx_token_count"] > 0


# ── Rule generator ────────────────────────────────────────────────────


def test_sigma_rule_has_required_fields():
    seed = RuleSeed(title="Test rule", severity="high", event_type="auth_failure",
                    src_ip="10.0.0.1", username="alice")
    rule = build_sigma_rule(seed)
    for field in ("title", "id", "status", "description", "logsource", "detection", "level"):
        assert field in rule
    assert rule["level"] == "high"
    assert rule["detection"]["selection"]["EventType"] == "auth_failure"
    assert rule["detection"]["selection"]["SourceIp"] == "10.0.0.1"


def test_sigma_rule_keywords_extracted_from_message():
    seed = RuleSeed(title="t", message="powershell EncodedCommand bypass execution policy unrestricted")
    rule = build_sigma_rule(seed)
    assert "keywords" in rule["detection"]
    assert len(rule["detection"]["keywords"]) > 0


def test_sigma_rule_minimal_seed_does_not_crash():
    rule = build_sigma_rule(RuleSeed(title="Minimal"))
    assert "detection" in rule
    assert "selection" in rule["detection"]


def test_sigma_yaml_renders_valid_yaml():
    import yaml
    rule = build_sigma_rule(RuleSeed(title="t", severity="medium", event_type="login"))
    text = render_sigma_yaml(rule)
    parsed = yaml.safe_load(text)
    assert parsed["title"] == "t"
    assert parsed["level"] == "medium"


def test_sigma_mitre_tags_normalized():
    seed = RuleSeed(title="t", mitre_techniques=["T1110.003", "T1059.001"])
    rule = build_sigma_rule(seed)
    assert "attack.t1110_003" in rule["tags"]
    assert "attack.t1059_001" in rule["tags"]


def test_yara_rule_starts_with_rule_keyword():
    seed = RuleSeed(title="MyDetection", severity="high", src_ip="1.2.3.4",
                    message="malicious payload encoded base64")
    text = build_yara_rule(seed)
    assert text.startswith("rule AutoGen_")
    assert "$ip_src" in text
    assert "1.2.3.4" in text
    assert "condition:" in text


def test_yara_rule_with_minimal_seed():
    text = build_yara_rule(RuleSeed(title="Minimal"))
    assert "rule AutoGen_" in text
    assert "$placeholder" in text  # fallback


def test_yara_rule_includes_mitre_meta():
    seed = RuleSeed(title="t", mitre_techniques=["T1059"])
    text = build_yara_rule(seed)
    assert "T1059" in text
