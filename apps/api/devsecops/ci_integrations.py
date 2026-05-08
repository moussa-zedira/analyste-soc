"""CI/CD Pipeline Integration — generate configs, receive webhooks, quality gates."""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from typing import Any

import structlog

logger = logging.getLogger(__name__)
slog = structlog.get_logger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# PIPELINE CONFIG GENERATORS
# ═══════════════════════════════════════════════════════════════════════════════


def generate_github_actions(
    api_url: str = "http://localhost:8000",
    scan_types: list[str] | None = None,
    quality_gate_id: int | None = None,
    branch: str = "main",
) -> str:
    """Generate a GitHub Actions workflow YAML for security scanning."""
    scans = scan_types or ["sast", "sca", "secrets"]
    scan_steps = ""

    for scan in scans:
        scan_steps += f"""
      - name: Run {scan.upper()} scan
        run: |
          RESULT=$(curl -s -X POST {api_url}/api/devsecops/scan/{scan} \\
            -H "Authorization: Bearer ${{{{ secrets.DEVSECOPS_TOKEN }}}}" \\
            -H "Content-Type: application/json" \\
            -d '{{"path": "${{{{ github.workspace }}}}"}}')
          echo "$RESULT" >> $GITHUB_STEP_SUMMARY
          RUN_ID=$(echo "$RESULT" | jq -r '.run_id')
          echo "run_id_{scan}=$RUN_ID" >> $GITHUB_OUTPUT
        id: {scan}_scan
"""

    qg_step = ""
    if quality_gate_id:
        qg_step = f"""
      - name: Check quality gate
        run: |
          GATE=$(curl -s {api_url}/api/devsecops/quality-gates/{quality_gate_id} \\
            -H "Authorization: Bearer ${{{{ secrets.DEVSECOPS_TOKEN }}}}")
          PASSED=$(echo "$GATE" | jq -r '.passed')
          if [ "$PASSED" != "true" ]; then
            echo "Quality gate FAILED"
            exit 1
          fi
"""

    return f"""name: DevSecOps Security Scan
on:
  push:
    branches: [{branch}]
  pull_request:
    branches: [{branch}]

permissions:
  security-events: write
  contents: read

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0
{scan_steps}
      - name: Upload SARIF results
        if: always()
        run: |
          for scan in {' '.join(scans)}; do
            RUN_ID=$(echo "${{{{ steps.${{scan}}_scan.outputs.run_id_${{scan}} }}}}")
            if [ -n "$RUN_ID" ]; then
              curl -s {api_url}/api/devsecops/runs/$RUN_ID/sarif \\
                -H "Authorization: Bearer ${{{{ secrets.DEVSECOPS_TOKEN }}}}" \\
                -o "${{scan}}-results.sarif"
            fi
          done

      - name: Upload SARIF to GitHub
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: .
          category: devsecops
{qg_step}
"""


def generate_gitlab_ci(
    api_url: str = "http://localhost:8000",
    scan_types: list[str] | None = None,
    quality_gate_id: int | None = None,
) -> str:
    """Generate a GitLab CI pipeline YAML for security scanning."""
    scans = scan_types or ["sast", "sca", "secrets"]
    stages = " ".join(scans) + " report"

    jobs = ""
    for scan in scans:
        jobs += f"""
{scan}-scan:
  stage: {scan}
  image: python:3.12-slim
  script:
    - |
      RESULT=$(curl -s -X POST {api_url}/api/devsecops/scan/{scan} \\
        -H "Authorization: Bearer $DEVSECOPS_TOKEN" \\
        -H "Content-Type: application/json" \\
        -d '{{"path": "$CI_PROJECT_DIR"}}')
      RUN_ID=$(echo "$RESULT" | jq -r '.run_id')
      curl -s {api_url}/api/devsecops/runs/$RUN_ID/sarif \\
        -H "Authorization: Bearer $DEVSECOPS_TOKEN" \\
        -o gl-{scan}-report.json
  artifacts:
    reports:
      sast: gl-{scan}-report.json
    when: always
"""

    qg_job = ""
    if quality_gate_id:
        qg_job = f"""
quality-gate:
  stage: report
  script:
    - |
      GATE=$(curl -s {api_url}/api/devsecops/quality-gates/{quality_gate_id} \\
        -H "Authorization: Bearer $DEVSECOPS_TOKEN")
      PASSED=$(echo "$GATE" | jq -r '.passed')
      if [ "$PASSED" != "true" ]; then
        echo "Quality gate FAILED"
        exit 1
      fi
"""

    return f"""stages:
  - {stages}

variables:
  DEVSECOPS_TOKEN: $DEVSECOPS_TOKEN
{jobs}{qg_job}"""


def generate_jenkins_pipeline(
    api_url: str = "http://localhost:8000",
    scan_types: list[str] | None = None,
    quality_gate_id: int | None = None,
) -> str:
    """Generate a Jenkins pipeline (Groovy) for security scanning."""
    scans = scan_types or ["sast", "sca", "secrets"]

    scan_stages = ""
    for scan in scans:
        scan_stages += f"""
                stage('{scan.upper()} Scan') {{
                    steps {{
                        script {{
                            def result = sh(
                                script: \"\"\"curl -s -X POST {api_url}/api/devsecops/scan/{scan} \\\\
                                    -H "Authorization: Bearer ${{DEVSECOPS_TOKEN}}" \\\\
                                    -H "Content-Type: application/json" \\\\
                                    -d '{{"path": "${{WORKSPACE}}"}}'
                                \"\"\",
                                returnStdout: true
                            ).trim()
                            def json = readJSON text: result
                            env.RUN_ID_{scan.upper()} = json.run_id
                        }}
                    }}
                }}
"""

    qg_stage = ""
    if quality_gate_id:
        qg_stage = f"""
                stage('Quality Gate') {{
                    steps {{
                        script {{
                            def gate = sh(
                                script: 'curl -s {api_url}/api/devsecops/quality-gates/{quality_gate_id} -H "Authorization: Bearer ${{DEVSECOPS_TOKEN}}"',
                                returnStdout: true
                            ).trim()
                            def json = readJSON text: gate
                            if (!json.passed) {{
                                error "Quality gate FAILED"
                            }}
                        }}
                    }}
                }}
"""

    return f"""pipeline {{
    agent any

    environment {{
        DEVSECOPS_TOKEN = credentials('devsecops-token')
    }}

    stages {{
{scan_stages}{qg_stage}
    }}

    post {{
        always {{
            archiveArtifacts artifacts: '*-results.sarif', allowEmptyArchive: true
        }}
    }}
}}
"""


def generate_azure_devops(
    api_url: str = "http://localhost:8000",
    scan_types: list[str] | None = None,
    quality_gate_id: int | None = None,
) -> str:
    """Generate an Azure DevOps pipeline YAML."""
    scans = scan_types or ["sast", "sca", "secrets"]

    steps = ""
    for scan in scans:
        steps += f"""
  - script: |
      RESULT=$(curl -s -X POST {api_url}/api/devsecops/scan/{scan} \\
        -H "Authorization: Bearer $(DEVSECOPS_TOKEN)" \\
        -H "Content-Type: application/json" \\
        -d '{{"path": "$(Build.SourcesDirectory)"}}')
      echo "##vso[task.setvariable variable=RUN_ID_{scan.upper()}]$(echo $RESULT | jq -r '.run_id')"
    displayName: '{scan.upper()} Scan'
"""

    qg_step = ""
    if quality_gate_id:
        qg_step = f"""
  - script: |
      GATE=$(curl -s {api_url}/api/devsecops/quality-gates/{quality_gate_id} \\
        -H "Authorization: Bearer $(DEVSECOPS_TOKEN)")
      PASSED=$(echo $GATE | jq -r '.passed')
      if [ "$PASSED" != "true" ]; then
        echo "##vso[task.logissue type=error]Quality gate FAILED"
        exit 1
      fi
    displayName: 'Quality Gate Check'
"""

    return f"""trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

variables:
  - name: DEVSECOPS_TOKEN
    value: $(devsecops-token)

steps:
  - checkout: self
    fetchDepth: 0
{steps}{qg_step}"""


def generate_circleci(
    api_url: str = "http://localhost:8000",
    scan_types: list[str] | None = None,
    quality_gate_id: int | None = None,
) -> str:
    """Generate a CircleCI config YAML."""
    scans = scan_types or ["sast", "sca", "secrets"]

    scan_steps = ""
    for scan in scans:
        scan_steps += f"""
          - run:
              name: {scan.upper()} Scan
              command: |
                RESULT=$(curl -s -X POST {api_url}/api/devsecops/scan/{scan} \\
                  -H "Authorization: Bearer $DEVSECOPS_TOKEN" \\
                  -H "Content-Type: application/json" \\
                  -d '{{"path": "~/project"}}')
                echo "$RESULT"
"""

    qg_step = ""
    if quality_gate_id:
        qg_step = f"""
          - run:
              name: Quality Gate
              command: |
                GATE=$(curl -s {api_url}/api/devsecops/quality-gates/{quality_gate_id} \\
                  -H "Authorization: Bearer $DEVSECOPS_TOKEN")
                PASSED=$(echo $GATE | jq -r '.passed')
                if [ "$PASSED" != "true" ]; then
                  echo "Quality gate FAILED"
                  exit 1
                fi
"""

    return f"""version: 2.1

jobs:
  security-scan:
    docker:
      - image: cimg/python:3.12
    steps:
      - checkout
{scan_steps}{qg_step}
      - store_artifacts:
          path: ./scan-results

workflows:
  security:
    jobs:
      - security-scan
"""


# Map CI platform names to generators
CI_GENERATORS: dict[str, Any] = {
    "github": generate_github_actions,
    "gitlab": generate_gitlab_ci,
    "jenkins": generate_jenkins_pipeline,
    "azure": generate_azure_devops,
    "circleci": generate_circleci,
}


# ═══════════════════════════════════════════════════════════════════════════════
# QUALITY GATE EVALUATION
# ═══════════════════════════════════════════════════════════════════════════════


def evaluate_quality_gate(
    gate_config: dict,
    findings: list[dict],
) -> dict[str, Any]:
    """Evaluate findings against a quality gate and return pass/fail with details."""
    severity_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    has_secrets = False

    for f in findings:
        sev = f.get("severity", "info").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        if f.get("scan_type") == "secrets":
            has_secrets = True

    passed = True
    reasons: list[str] = []

    max_critical = gate_config.get("max_critical", 0)
    if severity_counts["critical"] > max_critical:
        passed = False
        reasons.append(f"Critical findings: {severity_counts['critical']} > max {max_critical}")

    max_high = gate_config.get("max_high", 5)
    if severity_counts["high"] > max_high:
        passed = False
        reasons.append(f"High findings: {severity_counts['high']} > max {max_high}")

    max_medium = gate_config.get("max_medium")
    if max_medium is not None and severity_counts["medium"] > max_medium:
        passed = False
        reasons.append(f"Medium findings: {severity_counts['medium']} > max {max_medium}")

    no_secrets = gate_config.get("no_secrets", True)
    if no_secrets and has_secrets:
        passed = False
        reasons.append("Secrets detected in code (no_secrets policy)")

    return {
        "passed": passed,
        "severity_counts": severity_counts,
        "reasons": reasons,
        "total_findings": len(findings),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# EXPORT FORMATS
# ═══════════════════════════════════════════════════════════════════════════════


def to_junit_xml(findings: list[dict], run_id: int | str = "0") -> str:
    """Convert findings to JUnit XML format for CI/CD integration."""
    testsuite = ET.Element("testsuite", {
        "name": f"DevSecOps Scan Run {run_id}",
        "tests": str(len(findings)),
        "failures": str(sum(1 for f in findings if f.get("severity") in ("critical", "high"))),
        "errors": "0",
    })

    for f in findings:
        tc = ET.SubElement(testsuite, "testcase", {
            "name": f.get("title", "Unknown"),
            "classname": f.get("scan_type", "devsecops"),
        })

        if f.get("severity") in ("critical", "high"):
            failure = ET.SubElement(tc, "failure", {
                "message": f.get("title", ""),
                "type": f.get("severity", "high"),
            })
            failure.text = (
                f"Severity: {f.get('severity')}\n"
                f"CWE: {f.get('cwe_id', 'N/A')}\n"
                f"File: {f.get('file_path', 'N/A')}:{f.get('line_number', '')}\n"
                f"Description: {f.get('description', '')}\n"
                f"Remediation: {f.get('remediation', '')}"
            )
        elif f.get("severity") == "medium":
            system_out = ET.SubElement(tc, "system-out")
            system_out.text = f"[WARN] {f.get('description', '')}"

    return ET.tostring(testsuite, encoding="unicode", xml_declaration=True)
