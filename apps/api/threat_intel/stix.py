"""STIX 2.1 Object Support — creation, parsing, validation, conversion.

Supporte tous les SDO/SRO du standard STIX 2.1 et la conversion bidirectionnelle
entre le format interne IOC et STIX 2.1.
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import UTC, datetime
from typing import Any

# ---------------------------------------------------------------------------
# STIX 2.1 SDO / SRO type registry
# ---------------------------------------------------------------------------

SDO_TYPES = {
    "attack-pattern",
    "campaign",
    "course-of-action",
    "grouping",
    "identity",
    "indicator",
    "infrastructure",
    "intrusion-set",
    "location",
    "malware",
    "malware-analysis",
    "note",
    "observed-data",
    "opinion",
    "report",
    "threat-actor",
    "tool",
    "vulnerability",
}

SRO_TYPES = {"relationship", "sighting"}

SCO_TYPES = {
    "artifact",
    "autonomous-system",
    "directory",
    "domain-name",
    "email-addr",
    "email-message",
    "file",
    "ipv4-addr",
    "ipv6-addr",
    "mac-addr",
    "mutex",
    "network-traffic",
    "process",
    "software",
    "url",
    "user-account",
    "windows-registry-key",
    "x509-certificate",
}

ALL_STIX_TYPES = (
    SDO_TYPES | SRO_TYPES | SCO_TYPES | {"bundle", "language-content", "marking-definition"}
)

# ---------------------------------------------------------------------------
# TLP Marking definitions (STIX 2.1)
# ---------------------------------------------------------------------------

TLP_MARKINGS = {
    "WHITE": {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp",
        "name": "TLP:WHITE",
        "definition": {"tlp": "white"},
    },
    "GREEN": {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp",
        "name": "TLP:GREEN",
        "definition": {"tlp": "green"},
    },
    "AMBER": {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp",
        "name": "TLP:AMBER",
        "definition": {"tlp": "amber"},
    },
    "AMBER+STRICT": {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--826578e1-40a3-4b87-8e6b-0f39e5bcd987",
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp",
        "name": "TLP:AMBER+STRICT",
        "definition": {"tlp": "amber+strict"},
    },
    "RED": {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp",
        "name": "TLP:RED",
        "definition": {"tlp": "red"},
    },
}

# ---------------------------------------------------------------------------
# Deterministic STIX ID generation
# ---------------------------------------------------------------------------


def generate_stix_id(stix_type: str, *args: str) -> str:
    """Generate a deterministic STIX 2.1 ID using UUIDv5.

    Uses the STIX namespace UUID with the type + contributing properties.
    """
    STIX_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
    seed = f"{stix_type}--{'|'.join(args)}"
    deterministic_uuid = uuid.uuid5(STIX_NAMESPACE, seed)
    return f"{stix_type}--{deterministic_uuid}"


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


# ---------------------------------------------------------------------------
# IOC type -> STIX pattern mapping
# ---------------------------------------------------------------------------

_IOC_TYPE_TO_PATTERN: dict[str, str] = {
    "ip": "[ipv4-addr:value = '{value}']",
    "ipv4": "[ipv4-addr:value = '{value}']",
    "ipv6": "[ipv6-addr:value = '{value}']",
    "domain": "[domain-name:value = '{value}']",
    "url": "[url:value = '{value}']",
    "hash_md5": "[file:hashes.MD5 = '{value}']",
    "hash_sha1": "[file:hashes.'SHA-1' = '{value}']",
    "hash_sha256": "[file:hashes.'SHA-256' = '{value}']",
    "email": "[email-addr:value = '{value}']",
    "filename": "[file:name = '{value}']",
    "mutex": "[mutex:name = '{value}']",
    "registry_key": "[windows-registry-key:key = '{value}']",
    "user_agent": "[network-traffic:extensions.'http-request-ext'.request_header.'User-Agent' = '{value}']",
    "cidr": "[ipv4-addr:value = '{value}']",
    "asn": "[autonomous-system:number = {value}]",
    "cve": "[vulnerability:name = '{value}']",
    "ja3": "[network-traffic:extensions.'ja3-ext'.ja3_hash = '{value}']",
}

_PATTERN_TO_IOC_TYPE: list[tuple[str, str]] = [
    (r"\[ipv4-addr:value\s*=\s*'([^']+)'\]", "ip"),
    (r"\[ipv6-addr:value\s*=\s*'([^']+)'\]", "ip"),
    (r"\[domain-name:value\s*=\s*'([^']+)'\]", "domain"),
    (r"\[url:value\s*=\s*'([^']+)'\]", "url"),
    (r"\[file:hashes\.MD5\s*=\s*'([^']+)'\]", "hash_md5"),
    (r"\[file:hashes\.'SHA-1'\s*=\s*'([^']+)'\]", "hash_sha1"),
    (r"\[file:hashes\.'SHA-256'\s*=\s*'([^']+)'\]", "hash_sha256"),
    (r"\[email-addr:value\s*=\s*'([^']+)'\]", "email"),
    (r"\[file:name\s*=\s*'([^']+)'\]", "filename"),
    (r"\[mutex:name\s*=\s*'([^']+)'\]", "mutex"),
    (r"\[windows-registry-key:key\s*=\s*'([^']+)'\]", "registry_key"),
    (r"\[autonomous-system:number\s*=\s*(\d+)\]", "asn"),
    (r"\[vulnerability:name\s*=\s*'([^']+)'\]", "cve"),
]


# ---------------------------------------------------------------------------
# STIX Pattern validation
# ---------------------------------------------------------------------------

_STIX_PATTERN_RE = re.compile(
    r"^\[("
    r"[a-z0-9\-]+(?:\.[a-z0-9\-_']+)*"
    r"\s*(=|!=|>|<|>=|<=|LIKE|MATCHES|ISSUBSET|ISSUPERSET|IN)\s*"
    r"('[^']*'|\d+(?:\.\d+)?|\[.*?\])"
    r"(\s+(AND|OR)\s+"
    r"[a-z0-9\-]+(?:\.[a-z0-9\-_']+)*"
    r"\s*(=|!=|>|<|>=|<=|LIKE|MATCHES|ISSUBSET|ISSUPERSET|IN)\s*"
    r"('[^']*'|\d+(?:\.\d+)?|\[.*?\])"
    r")*"
    r")\]$",
    re.IGNORECASE,
)


def validate_stix_pattern(pattern: str) -> bool:
    """Basic validation of a STIX 2.1 pattern expression."""
    if not pattern or not pattern.startswith("[") or not pattern.endswith("]"):
        return False
    # Accept multi-observation patterns (joined by OR at bracket level)
    parts = re.split(r"\]\s+OR\s+\[", pattern[1:-1])
    for part in parts:
        test = f"[{part}]"
        if not _STIX_PATTERN_RE.match(test):
            return False
    return True


# ---------------------------------------------------------------------------
# SDO / SRO factory helpers
# ---------------------------------------------------------------------------


def make_indicator(
    pattern: str,
    name: str | None = None,
    description: str | None = None,
    valid_from: str | None = None,
    valid_until: str | None = None,
    confidence: int | None = None,
    labels: list[str] | None = None,
    tlp: str | None = None,
    kill_chain_phases: list[dict] | None = None,
    external_references: list[dict] | None = None,
) -> dict[str, Any]:
    """Create a STIX 2.1 Indicator SDO."""
    now = _now_iso()
    obj: dict[str, Any] = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": generate_stix_id("indicator", pattern),
        "created": now,
        "modified": now,
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": valid_from or now,
    }
    if name:
        obj["name"] = name
    if description:
        obj["description"] = description
    if valid_until:
        obj["valid_until"] = valid_until
    if confidence is not None:
        obj["confidence"] = confidence
    if labels:
        obj["labels"] = labels
    if kill_chain_phases:
        obj["kill_chain_phases"] = kill_chain_phases
    if external_references:
        obj["external_references"] = external_references
    if tlp and tlp.upper() in TLP_MARKINGS:
        obj["object_marking_refs"] = [TLP_MARKINGS[tlp.upper()]["id"]]
    return obj


def make_sdo(
    sdo_type: str,
    name: str,
    description: str | None = None,
    extra: dict | None = None,
    tlp: str | None = None,
) -> dict[str, Any]:
    """Generic factory for any STIX 2.1 SDO."""
    if sdo_type not in SDO_TYPES:
        raise ValueError(f"Unknown SDO type: {sdo_type}")
    now = _now_iso()
    obj: dict[str, Any] = {
        "type": sdo_type,
        "spec_version": "2.1",
        "id": generate_stix_id(sdo_type, name),
        "created": now,
        "modified": now,
        "name": name,
    }
    if description:
        obj["description"] = description
    if extra:
        obj.update(extra)
    if tlp and tlp.upper() in TLP_MARKINGS:
        obj["object_marking_refs"] = [TLP_MARKINGS[tlp.upper()]["id"]]
    return obj


def make_relationship(
    source_ref: str,
    relationship_type: str,
    target_ref: str,
    description: str | None = None,
    confidence: int | None = None,
) -> dict[str, Any]:
    """Create a STIX 2.1 Relationship SRO."""
    now = _now_iso()
    obj: dict[str, Any] = {
        "type": "relationship",
        "spec_version": "2.1",
        "id": generate_stix_id("relationship", source_ref, relationship_type, target_ref),
        "created": now,
        "modified": now,
        "relationship_type": relationship_type,
        "source_ref": source_ref,
        "target_ref": target_ref,
    }
    if description:
        obj["description"] = description
    if confidence is not None:
        obj["confidence"] = confidence
    return obj


def make_sighting(
    sighting_of_ref: str,
    where_sighted_refs: list[str] | None = None,
    count: int | None = None,
    first_seen: str | None = None,
    last_seen: str | None = None,
) -> dict[str, Any]:
    """Create a STIX 2.1 Sighting SRO."""
    now = _now_iso()
    obj: dict[str, Any] = {
        "type": "sighting",
        "spec_version": "2.1",
        "id": generate_stix_id("sighting", sighting_of_ref, now),
        "created": now,
        "modified": now,
        "sighting_of_ref": sighting_of_ref,
    }
    if where_sighted_refs:
        obj["where_sighted_refs"] = where_sighted_refs
    if count is not None:
        obj["count"] = count
    if first_seen:
        obj["first_seen"] = first_seen
    if last_seen:
        obj["last_seen"] = last_seen
    return obj


def make_bundle(objects: list[dict]) -> dict[str, Any]:
    """Create a STIX 2.1 Bundle."""
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }


def parse_bundle(data: dict | str) -> list[dict]:
    """Parse a STIX 2.1 Bundle and return the list of objects."""
    if isinstance(data, str):
        data = json.loads(data)
    if not isinstance(data, dict):
        raise ValueError("Invalid STIX bundle: expected a JSON object")
    if data.get("type") != "bundle":
        # Might be a single object
        if data.get("type") in ALL_STIX_TYPES:
            return [data]
        raise ValueError("Invalid STIX data: not a bundle and not a known STIX type")
    return data.get("objects", [])


# ---------------------------------------------------------------------------
# Conversion: Internal IOC <-> STIX 2.1
# ---------------------------------------------------------------------------


def ioc_to_stix(ioc_dict: dict) -> dict[str, Any]:
    """Convert an internal IOC dict to a STIX 2.1 Indicator."""
    ioc_type = ioc_dict.get("type", "ip")
    value = ioc_dict.get("value", "")
    pattern_tpl = _IOC_TYPE_TO_PATTERN.get(ioc_type)
    if not pattern_tpl:
        pattern_tpl = "[artifact:payload_bin = '{value}']"

    if ioc_type == "asn":
        pattern = pattern_tpl.replace("{value}", str(value))
    else:
        pattern = pattern_tpl.replace("{value}", value)

    tags = ioc_dict.get("tags", [])
    if isinstance(tags, str):
        try:
            tags = json.loads(tags)
        except Exception:
            tags = [tags] if tags else []

    mitre = ioc_dict.get("mitre_techniques", [])
    if isinstance(mitre, str):
        try:
            mitre = json.loads(mitre)
        except Exception:
            mitre = [mitre] if mitre else []

    kill_chain_phases = None
    kcp = ioc_dict.get("kill_chain_phase")
    if kcp:
        kill_chain_phases = [
            {"kill_chain_name": "lockheed-martin-cyber-kill-chain", "phase_name": kcp}
        ]

    external_refs = None
    if mitre:
        external_refs = [{"source_name": "mitre-attack", "external_id": t} for t in mitre]

    first_seen = ioc_dict.get("first_seen")
    if isinstance(first_seen, datetime):
        first_seen = first_seen.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    expiry = ioc_dict.get("expiry")
    valid_until = None
    if isinstance(expiry, datetime):
        valid_until = expiry.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    elif isinstance(expiry, str) and expiry:
        valid_until = expiry

    indicator = make_indicator(
        pattern=pattern,
        name=f"{ioc_type}:{value}",
        description=f"IOC {ioc_type} from source {ioc_dict.get('source', 'unknown')}",
        valid_from=first_seen,
        valid_until=valid_until,
        confidence=ioc_dict.get("confidence"),
        labels=tags or None,
        tlp=ioc_dict.get("tlp"),
        kill_chain_phases=kill_chain_phases,
        external_references=external_refs,
    )

    # Preserve stix_id if it was already set
    if ioc_dict.get("stix_id"):
        indicator["id"] = ioc_dict["stix_id"]

    return indicator


def stix_to_ioc(stix_obj: dict) -> dict | None:
    """Convert a STIX 2.1 Indicator to internal IOC dict.

    Returns None if the object is not an indicator or pattern is not parseable.
    """
    if stix_obj.get("type") != "indicator":
        return None

    pattern = stix_obj.get("pattern", "")
    ioc_type = None
    value = None

    for regex, typ in _PATTERN_TO_IOC_TYPE:
        m = re.search(regex, pattern, re.IGNORECASE)
        if m:
            ioc_type = typ
            value = m.group(1)
            break

    if not ioc_type or not value:
        return None

    # Extract TLP from marking refs
    tlp = "AMBER"
    marking_refs = stix_obj.get("object_marking_refs", [])
    tlp_id_map = {v["id"]: k for k, v in TLP_MARKINGS.items()}
    for ref in marking_refs:
        if ref in tlp_id_map:
            tlp = tlp_id_map[ref]
            break

    # Kill chain
    kill_chain_phase = None
    kcps = stix_obj.get("kill_chain_phases", [])
    if kcps:
        kill_chain_phase = kcps[0].get("phase_name")

    # MITRE techniques from external_references
    mitre = []
    for ref in stix_obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            eid = ref.get("external_id")
            if eid:
                mitre.append(eid)

    first_seen = stix_obj.get("valid_from")
    expiry = stix_obj.get("valid_until")

    return {
        "type": ioc_type,
        "value": value,
        "state": "active",
        "confidence": stix_obj.get("confidence", 50),
        "tlp": tlp,
        "source": "stix_import",
        "tags": stix_obj.get("labels", []),
        "mitre_techniques": mitre,
        "kill_chain_phase": kill_chain_phase,
        "stix_id": stix_obj.get("id"),
        "first_seen": first_seen,
        "expiry": expiry,
    }


def stix_objects_to_iocs(objects: list[dict]) -> list[dict]:
    """Convert a list of STIX objects to internal IOC dicts, filtering non-indicators."""
    results = []
    for obj in objects:
        ioc = stix_to_ioc(obj)
        if ioc:
            results.append(ioc)
    return results


def serialize_bundle(bundle: dict) -> str:
    """Serialize a STIX bundle to JSON string."""
    return json.dumps(bundle, indent=2, default=str)


def deserialize_bundle(raw: str) -> dict:
    """Deserialize a JSON string to a STIX bundle dict."""
    return json.loads(raw)
