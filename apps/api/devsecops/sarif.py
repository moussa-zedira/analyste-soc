"""SARIF 2.1.0 Output Generator — GitHub Code Scanning & VS Code compatible."""

from __future__ import annotations

import json
from typing import Any

_SEVERITY_TO_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

_SEVERITY_TO_SARIF_RANK = {
    "critical": 9.5,
    "high": 8.0,
    "medium": 5.0,
    "low": 3.0,
    "info": 1.0,
}


def generate_sarif(
    findings: list[dict],
    tool_name: str = "DevSecOps Scanner",
    tool_version: str = "1.0.0",
    tool_uri: str = "https://github.com/analyste-soc/devsecops",
) -> dict[str, Any]:
    """Generate a SARIF 2.1.0 JSON report from scan findings.

    Compatible with:
    - GitHub Code Scanning (Advanced Security)
    - VS Code SARIF Viewer extension
    - Azure DevOps
    - Any SARIF 2.1.0 consumer
    """
    # Deduplicate rules
    rules_map: dict[str, dict] = {}
    results: list[dict] = []

    for _idx, finding in enumerate(findings):
        rule_id = _make_rule_id(finding)

        if rule_id not in rules_map:
            rules_map[rule_id] = {
                "id": rule_id,
                "name": finding.get("title", "Unknown"),
                "shortDescription": {"text": finding.get("title", "Unknown")},
                "fullDescription": {"text": finding.get("description", finding.get("title", ""))},
                "helpUri": f"https://cwe.mitre.org/data/definitions/{_extract_cwe_num(finding.get('cwe_id', ''))}.html"
                if finding.get("cwe_id")
                else "",
                "help": {
                    "text": finding.get("remediation", "No remediation provided."),
                    "markdown": f"**Remediation:** {finding.get('remediation', 'N/A')}",
                },
                "defaultConfiguration": {
                    "level": _SEVERITY_TO_SARIF_LEVEL.get(
                        finding.get("severity", "info"), "note"
                    ),
                },
                "properties": {
                    "security-severity": str(
                        _SEVERITY_TO_SARIF_RANK.get(finding.get("severity", "info"), 1.0)
                    ),
                    "tags": [finding.get("scan_type", "security"), "security"],
                },
            }

        # Build result
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "ruleIndex": list(rules_map.keys()).index(rule_id),
            "level": _SEVERITY_TO_SARIF_LEVEL.get(
                finding.get("severity", "info"), "note"
            ),
            "message": {
                "text": finding.get("description", finding.get("title", "")),
            },
        }

        # Location
        file_path = finding.get("file_path", "")
        line_number = finding.get("line_number", 0)
        if file_path and not file_path.startswith("http"):
            location: dict[str, Any] = {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": file_path.replace("\\", "/"),
                        "uriBaseId": "%SRCROOT%",
                    },
                }
            }
            if line_number and line_number > 0:
                location["physicalLocation"]["region"] = {
                    "startLine": line_number,
                    "startColumn": 1,
                }
            result["locations"] = [location]

        # Code snippet as code flow
        snippet = finding.get("code_snippet", "")
        if snippet:
            result["relatedLocations"] = [
                {
                    "id": 0,
                    "message": {"text": "Code context"},
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": file_path.replace("\\", "/") if file_path else "unknown",
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": max(1, line_number - 2) if line_number else 1,
                            "snippet": {"text": snippet},
                        },
                    },
                }
            ]

        # CWE tag
        if finding.get("cwe_id"):
            result["taxa"] = [
                {
                    "id": finding["cwe_id"],
                    "toolComponent": {"name": "CWE", "index": 0},
                }
            ]

        # Fingerprint for deduplication
        fp_data = f"{rule_id}:{file_path}:{line_number}"
        import hashlib

        result["fingerprints"] = {
            "primaryLocationLineHash": hashlib.sha256(fp_data.encode()).hexdigest()[:16],
        }

        results.append(result)

    sarif: dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "informationUri": tool_uri,
                        "rules": list(rules_map.values()),
                    },
                },
                "results": results,
                "taxonomies": [
                    {
                        "name": "CWE",
                        "version": "4.13",
                        "informationUri": "https://cwe.mitre.org/",
                        "organization": "MITRE",
                        "shortDescription": {"text": "Common Weakness Enumeration"},
                    }
                ],
            }
        ],
    }

    return sarif


def sarif_to_json(sarif: dict) -> str:
    """Serialize SARIF dict to formatted JSON string."""
    return json.dumps(sarif, indent=2, ensure_ascii=False)


def _make_rule_id(finding: dict) -> str:
    """Create a stable rule ID from finding attributes."""
    scan_type = finding.get("scan_type", "generic")
    cwe = finding.get("cwe_id", "")
    title = finding.get("title", "unknown").lower().replace(" ", "-")[:40]
    if cwe:
        return f"{scan_type}/{cwe}/{title}"
    return f"{scan_type}/{title}"


def _extract_cwe_num(cwe_id: str) -> str:
    """Extract numeric CWE ID from 'CWE-XXX' format."""
    if cwe_id and "-" in cwe_id:
        return cwe_id.split("-", 1)[1]
    return cwe_id or "0"
