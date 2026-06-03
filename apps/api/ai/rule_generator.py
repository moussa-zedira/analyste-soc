"""Générateurs Sigma + Yara à partir d'un event/incident.

Mode "template" : déterministe, sans LLM. Construit la règle depuis les
champs structurés de l'event (event_type, src_ip, username, message-tokens).

Mode "llm" : prompt un LLM pour enrichir la règle (titre/desc/MITRE).
Le rendu YAML reste produit côté Python pour garantir la validité syntaxique.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from dataclasses import dataclass, field
from typing import Any

import yaml

from apps.api.ai.llm_client import LlmResponse, call_llm, parse_json_response

SIGMA_LEVEL_BY_SEVERITY = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "informational",
}


@dataclass
class RuleSeed:
    title: str
    severity: str | None = None
    event_type: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    username: str | None = None
    message: str | None = None
    raw: str | None = None
    mitre_techniques: list[str] = field(default_factory=list)
    description: str | None = None
    references: list[str] = field(default_factory=list)


def _slugify(s: str, max_len: int = 60) -> str:
    s = re.sub(r"[^A-Za-z0-9]+", "_", s).strip("_").lower()
    return s[:max_len] or "rule"


def _short_hash(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="replace")).hexdigest()[:8]


def _extract_keywords(message: str | None, limit: int = 5) -> list[str]:
    """Extrait des keywords distinctifs (mots > 3 chars, pas stopwords basiques)."""
    if not message:
        return []
    stop = {
        "the",
        "and",
        "for",
        "with",
        "from",
        "this",
        "that",
        "user",
        "host",
        "name",
        "time",
        "type",
        "data",
        "info",
        "error",
    }
    tokens = re.findall(r"[A-Za-z][A-Za-z0-9_./-]{3,}", message)
    seen: list[str] = []
    for t in tokens:
        tl = t.lower()
        if tl in stop or t in seen:
            continue
        seen.append(t)
        if len(seen) >= limit:
            break
    return seen


def build_sigma_rule(seed: RuleSeed) -> dict[str, Any]:
    """Construit une règle Sigma (dict prêt à dumper en YAML)."""
    detection: dict[str, Any] = {}
    selection: dict[str, Any] = {}

    if seed.event_type:
        selection["EventType"] = seed.event_type
    if seed.src_ip:
        selection["SourceIp"] = seed.src_ip
    if seed.dst_ip:
        selection["DestinationIp"] = seed.dst_ip
    if seed.username:
        selection["User"] = seed.username

    keywords = _extract_keywords(seed.message)
    if keywords:
        detection["keywords"] = keywords

    if not selection and not keywords:
        # Évite une règle vide qui matchera tout
        selection["EventType"] = seed.event_type or "*"

    if selection:
        detection["selection"] = selection

    cond = " and ".join(k for k in ("selection", "keywords") if k in detection)
    detection["condition"] = cond or "selection"

    rule_id = str(
        uuid.UUID(
            int=int(_short_hash(seed.title) + _short_hash(seed.message or seed.title), 16)
            & ((1 << 128) - 1)
        )
    )

    rule: dict[str, Any] = {
        "title": seed.title[:120],
        "id": rule_id,
        "status": "experimental",
        "description": seed.description
        or f"Auto-generated rule from event of type '{seed.event_type or 'unknown'}'",
        "references": seed.references,
        "author": "analyste-soc auto-generator",
        "date": "2026/04/17",
        "tags": [f"attack.{t.lower().replace('.', '_')}" for t in seed.mitre_techniques],
        "logsource": {
            "category": "security",
            "product": "analyste_soc",
        },
        "detection": detection,
        "falsepositives": ["Legitimate administrative activity", "Automated scanners"],
        "level": SIGMA_LEVEL_BY_SEVERITY.get((seed.severity or "medium").lower(), "medium"),
    }
    return rule


def build_yara_rule(seed: RuleSeed) -> str:
    """Construit une règle Yara textuelle (string-based)."""
    name = f"AutoGen_{_slugify(seed.title, 40)}_{_short_hash(seed.title)}"
    strings: list[tuple[str, str]] = []

    if seed.message:
        # Extrait sous-strings significatives (tokens longs)
        for i, kw in enumerate(_extract_keywords(seed.message, limit=8)):
            if len(kw) >= 4:
                strings.append((f"$s{i}", kw))
    if seed.src_ip:
        strings.append(("$ip_src", seed.src_ip))
    if seed.dst_ip:
        strings.append(("$ip_dst", seed.dst_ip))
    if seed.username:
        strings.append(("$user", seed.username))

    if not strings:
        # Yara a besoin d'au moins une string ou condition triviale
        strings.append(("$placeholder", seed.title[:40].replace('"', "_")))

    str_lines = "\n        ".join(f'{name} = "{val}"' for name, val in strings)
    " or ".join(name for name, _ in strings)

    meta_lines = [
        f'description = "{(seed.description or "Auto-generated rule")[:120]}"',
        f'severity = "{seed.severity or "medium"}"',
        'author = "analyste-soc auto-generator"',
        'date = "2026-04-17"',
    ]
    if seed.mitre_techniques:
        meta_lines.append(f'mitre = "{",".join(seed.mitre_techniques)}"')

    meta_block = "\n        ".join(meta_lines)

    return f"""rule {name}
{{
    meta:
        {meta_block}

    strings:
        {str_lines}

    condition:
        any of them
}}
"""


# ── LLM enrichment ────────────────────────────────────────────────────


LLM_ENRICH_SYSTEM = """You are a detection engineer. Given a security event, you suggest:
1. A concise rule title (max 80 chars)
2. A description (1-2 sentences)
3. MITRE ATT&CK technique IDs (e.g. T1059.001)
4. Severity (critical|high|medium|low|info)

Output strictly a JSON object with fields: title, description, mitre_techniques (list), severity.
"""


def enrich_seed_with_llm(
    seed: RuleSeed, prefer: str | None = None
) -> tuple[RuleSeed, dict[str, Any]]:
    """Enrichit le seed via LLM. Retourne (seed_modifié, métadonnées_llm)."""
    prompt = (
        f"Event details:\n"
        f"- type: {seed.event_type}\n"
        f"- severity: {seed.severity}\n"
        f"- src_ip: {seed.src_ip}\n"
        f"- username: {seed.username}\n"
        f"- message: {seed.message or '(none)'}\n\n"
        f"Provide enrichment JSON now."
    )
    resp: LlmResponse = call_llm(prompt, system=LLM_ENRICH_SYSTEM, max_tokens=512, prefer=prefer)
    parsed = parse_json_response(resp.text) or {}

    if isinstance(parsed.get("title"), str) and parsed["title"].strip():
        seed.title = parsed["title"].strip()
    if isinstance(parsed.get("description"), str):
        seed.description = parsed["description"].strip()
    if isinstance(parsed.get("mitre_techniques"), list):
        seed.mitre_techniques = [str(t) for t in parsed["mitre_techniques"] if t]
    if isinstance(parsed.get("severity"), str):
        seed.severity = parsed["severity"].strip().lower()

    return seed, {
        "provider": resp.provider,
        "model": resp.model,
        "usage": resp.usage,
        "raw_text": resp.text,
    }


def render_sigma_yaml(rule: dict[str, Any]) -> str:
    return yaml.dump(rule, sort_keys=False, allow_unicode=True, default_flow_style=False)
