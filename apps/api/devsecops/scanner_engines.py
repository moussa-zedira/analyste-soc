"""DevSecOps native binary engines.

Wrappers around real security scanners (Semgrep, Bandit, Safety, Trivy, Gitleaks,
Checkov, Hadolint). Each engine:

  * checks if the binary is available via ``shutil.which``
  * spawns the tool with ``asyncio.create_subprocess_exec`` (JSON / SARIF output)
  * parses stdout (or a tempfile when output > 10 MB)
  * returns ``list[dict]`` ready for ``_persist_run`` (keys: ``title``, ``severity``,
    ``scan_type``, ``description``, ``cwe_id``, ``file``, ``line``, ``code_snippet``,
    ``remediation``)

If the binary is missing, the engine returns ``None`` so the caller can fall back
to the in-process regex scanner.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

import structlog

slog = structlog.get_logger(__name__)

DEFAULT_TIMEOUT = 300  # seconds, per scan
MAX_INLINE_OUTPUT = 10 * 1024 * 1024  # 10 MB → spill to tempfile


# ═══════════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════════


def _have(binary: str) -> str | None:
    """Return absolute path to ``binary`` if available, else ``None``."""
    return shutil.which(binary)


def _normalize_severity(value: Any) -> str:
    """Map various scanner severities to {critical, high, medium, low, info}."""
    if value is None:
        return "low"
    s = str(value).strip().lower()
    if s in ("critical", "crit"):
        return "critical"
    if s in ("high", "error", "err"):
        return "high"
    if s in ("medium", "moderate", "warning", "warn"):
        return "medium"
    if s in ("low", "minor"):
        return "low"
    if s in ("info", "informational", "note", "unknown", "negligible"):
        return "info"
    return "low"


async def _run(
    cmd: list[str],
    *,
    cwd: str | None = None,
    timeout: int = DEFAULT_TIMEOUT,
    env: dict[str, str] | None = None,
) -> tuple[int, bytes, bytes]:
    """Execute ``cmd``, capturing stdout/stderr (spilling stdout to a tempfile if huge).

    Returns ``(returncode, stdout_bytes, stderr_bytes)``.
    """
    full_env = os.environ.copy()
    if env:
        full_env.update(env)

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        cwd=cwd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=full_env,
    )

    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        try:
            await proc.wait()
        except Exception:
            pass
        slog.warning("devsecops_engine_timeout", cmd=cmd[0], timeout=timeout)
        return 124, b"", b"timeout"

    if len(stdout) > MAX_INLINE_OUTPUT:
        # Spill very large outputs through a tempfile (kept on disk briefly)
        with tempfile.NamedTemporaryFile(delete=False, prefix="devsecops_", suffix=".json") as fh:
            fh.write(stdout)
            slog.warning("devsecops_engine_output_huge", cmd=cmd[0], size=len(stdout), path=fh.name)

    return proc.returncode or 0, stdout, stderr


def _f(
    *,
    title: str,
    severity: str,
    scan_type: str,
    description: str = "",
    cwe_id: str = "",
    file: str = "",
    line: int = 0,
    code_snippet: str = "",
    remediation: str = "",
    raw: dict | None = None,
) -> dict:
    """Build a finding dict aligned with both ``ScanFindingResult.to_dict()`` and
    the keys read by ``apps.api.routes.devsecops._persist_run`` (``file``, ``line``)."""
    return {
        "title": title,
        "severity": _normalize_severity(severity),
        "scan_type": scan_type,
        "description": description or "",
        "cwe_id": cwe_id or "",
        # Expose both shapes for downstream compatibility
        "file": file or "",
        "file_path": file or "",
        "line": int(line or 0),
        "line_number": int(line or 0),
        "code_snippet": code_snippet or "",
        "remediation": remediation or "",
        "raw_data": raw or {},
    }


def _safe_json_loads(data: bytes) -> Any:
    try:
        return json.loads(data.decode("utf-8", errors="ignore"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# SAST — Semgrep + Bandit
# ═══════════════════════════════════════════════════════════════════════════════


async def semgrep_scan(target: str) -> list[dict] | None:
    """Run ``semgrep --config=auto --json --quiet`` on ``target``."""
    if not _have("semgrep"):
        return None
    slog.info("scan_engine_used", engine="semgrep", target=target)

    cmd = [
        "semgrep",
        "--config=auto",
        "--json",
        "--quiet",
        "--no-git-ignore",
        "--metrics=off",
        "--timeout", "120",
        target,
    ]
    rc, stdout, stderr = await _run(cmd)
    if rc not in (0, 1):  # 0 = clean, 1 = findings; >1 = error
        slog.warning("semgrep_failed", rc=rc, stderr=stderr[:300].decode(errors="ignore"))
        return None

    data = _safe_json_loads(stdout)
    if not data:
        return []

    findings: list[dict] = []
    for r in data.get("results", []):
        extra = r.get("extra", {}) or {}
        meta = extra.get("metadata", {}) or {}
        cwe_raw = meta.get("cwe") or meta.get("cwe_id") or ""
        if isinstance(cwe_raw, list):
            cwe_raw = cwe_raw[0] if cwe_raw else ""
        cwe = ""
        if isinstance(cwe_raw, str) and "CWE" in cwe_raw.upper():
            cwe = cwe_raw.split(":")[0].strip()

        findings.append(_f(
            title=r.get("check_id", "semgrep finding"),
            severity=extra.get("severity", "medium"),
            scan_type="sast",
            description=extra.get("message") or meta.get("shortDescription", ""),
            cwe_id=cwe,
            file=r.get("path", ""),
            line=(r.get("start") or {}).get("line", 0),
            code_snippet=(extra.get("lines") or "")[:1000],
            remediation=meta.get("fix") or extra.get("fix") or "",
            raw={"engine": "semgrep", "rule": r.get("check_id")},
        ))
    return findings


async def bandit_scan(target: str) -> list[dict] | None:
    """Run ``bandit -r <target> -f json`` for Python."""
    if not _have("bandit"):
        return None
    slog.info("scan_engine_used", engine="bandit", target=target)

    cmd = ["bandit", "-r", target, "-f", "json", "-q"]
    rc, stdout, stderr = await _run(cmd)
    # Bandit returns non-zero when findings exist; we still want to parse stdout.
    data = _safe_json_loads(stdout)
    if not data:
        if rc != 0:
            slog.warning("bandit_failed", rc=rc, stderr=stderr[:300].decode(errors="ignore"))
        return [] if rc in (0, 1) else None

    findings: list[dict] = []
    for r in data.get("results", []):
        cwe_node = r.get("issue_cwe") or {}
        cwe_id = cwe_node.get("id") if isinstance(cwe_node, dict) else None
        cwe = f"CWE-{cwe_id}" if cwe_id else ""
        findings.append(_f(
            title=r.get("test_name") or r.get("test_id", "bandit finding"),
            severity=r.get("issue_severity", "medium"),
            scan_type="sast",
            description=r.get("issue_text", ""),
            cwe_id=cwe,
            file=r.get("filename", ""),
            line=r.get("line_number", 0),
            code_snippet=(r.get("code") or "")[:1000],
            remediation=r.get("more_info", ""),
            raw={"engine": "bandit", "test_id": r.get("test_id")},
        ))
    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# Secrets — Gitleaks
# ═══════════════════════════════════════════════════════════════════════════════


async def gitleaks_scan(target: str) -> list[dict] | None:
    """Run ``gitleaks detect`` against ``target`` (filesystem mode by default)."""
    if not _have("gitleaks"):
        return None
    slog.info("scan_engine_used", engine="gitleaks", target=target)

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as fh:
        report_path = fh.name

    try:
        cmd = [
            "gitleaks", "detect",
            f"--source={target}",
            "--no-git",
            "--report-format=json",
            f"--report-path={report_path}",
            "--exit-code=0",
            "--redact",
        ]
        rc, _, stderr = await _run(cmd)
        if rc not in (0, 1):
            slog.warning("gitleaks_failed", rc=rc, stderr=stderr[:300].decode(errors="ignore"))
            return None

        try:
            with open(report_path, "rb") as f:
                data = _safe_json_loads(f.read())
        except FileNotFoundError:
            data = []

        if not data:
            return []

        findings: list[dict] = []
        for r in data:
            findings.append(_f(
                title=f"Secret leak: {r.get('RuleID') or r.get('Description', 'unknown')}",
                severity="critical",
                scan_type="secrets",
                description=r.get("Description", "Secret detected by Gitleaks"),
                cwe_id="CWE-798",
                file=r.get("File", ""),
                line=r.get("StartLine", 0),
                code_snippet=(r.get("Match") or r.get("Secret") or "")[:300],
                remediation="Rotate the credential immediately and remove it from the repository (also from git history if pushed).",
                raw={"engine": "gitleaks", "rule": r.get("RuleID")},
            ))
        return findings
    finally:
        try:
            os.unlink(report_path)
        except OSError:
            pass


# ═══════════════════════════════════════════════════════════════════════════════
# SCA — Safety (Python requirements)
# ═══════════════════════════════════════════════════════════════════════════════


async def safety_scan(target: str) -> list[dict] | None:
    """Run ``safety check`` against the requirements file(s) under ``target``.

    Accepts either a path to a requirements*.txt file or a directory containing one.
    """
    if not _have("safety"):
        return None

    target_path = Path(target)
    req_files: list[Path] = []
    if target_path.is_file() and target_path.name.startswith("requirements"):
        req_files = [target_path]
    elif target_path.is_dir():
        req_files = sorted(target_path.rglob("requirements*.txt"))
    if not req_files:
        return []

    slog.info("scan_engine_used", engine="safety", files=len(req_files))

    findings: list[dict] = []
    for req in req_files:
        cmd = ["safety", "check", "--json", "--file", str(req)]
        rc, stdout, stderr = await _run(cmd)
        # Safety exits 64 when vulnerabilities found
        if rc not in (0, 64, 1):
            slog.warning("safety_failed", rc=rc, file=str(req), stderr=stderr[:300].decode(errors="ignore"))
            continue

        data = _safe_json_loads(stdout)
        if not data:
            continue

        # Safety v3 returns dict with vulnerabilities; older returns list
        vulns = []
        if isinstance(data, dict):
            vulns = data.get("vulnerabilities") or data.get("affected_packages") or []
        elif isinstance(data, list):
            vulns = data

        for v in vulns:
            if isinstance(v, list):
                # Legacy schema: [package, affected, installed, description, vuln_id, cve, severity]
                pkg = v[0] if len(v) > 0 else "?"
                installed = v[2] if len(v) > 2 else ""
                desc = v[3] if len(v) > 3 else ""
                vuln_id = v[4] if len(v) > 4 else ""
                sev = v[6] if len(v) > 6 else "high"
            else:
                pkg = v.get("package_name") or v.get("package") or "?"
                installed = v.get("analyzed_version") or v.get("installed_version") or ""
                desc = v.get("advisory") or v.get("description") or ""
                vuln_id = v.get("vulnerability_id") or v.get("CVE") or ""
                sev = v.get("severity") or "high"

            findings.append(_f(
                title=f"Vulnerable dependency: {pkg}@{installed}",
                severity=sev,
                scan_type="sca",
                description=f"{vuln_id}: {desc}",
                cwe_id="CWE-1395",
                file=str(req),
                code_snippet=f"{pkg}=={installed}",
                remediation=f"Upgrade {pkg} to a non-vulnerable version. See {vuln_id}.",
                raw={"engine": "safety", "vuln_id": vuln_id},
            ))
    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# Container / Filesystem — Trivy
# ═══════════════════════════════════════════════════════════════════════════════


def _looks_like_image_ref(target: str) -> bool:
    """Cheap heuristic to detect ``image[:tag]`` vs filesystem path."""
    if os.sep in target or target.startswith(("./", "../", "/")):
        return False
    if Path(target).exists():
        return False
    return ":" in target or "/" in target


async def trivy_scan(target: str) -> list[dict] | None:
    """Run ``trivy fs`` on a directory, or ``trivy image`` on an image reference."""
    if not _have("trivy"):
        return None

    mode = "image" if _looks_like_image_ref(target) else "fs"
    slog.info("scan_engine_used", engine="trivy", mode=mode, target=target)

    cmd = [
        "trivy", mode,
        "--format", "json",
        "--severity", "MEDIUM,HIGH,CRITICAL",
        "--quiet",
        "--no-progress",
        "--scanners", "vuln,misconfig,secret",
        target,
    ]
    rc, stdout, stderr = await _run(cmd)
    if rc != 0:
        slog.warning("trivy_failed", rc=rc, stderr=stderr[:300].decode(errors="ignore"))
        return None

    data = _safe_json_loads(stdout)
    if not data:
        return []

    findings: list[dict] = []
    for result in data.get("Results", []) or []:
        target_file = result.get("Target", "")
        # Vulnerabilities
        for v in result.get("Vulnerabilities", []) or []:
            findings.append(_f(
                title=f"{v.get('VulnerabilityID', 'CVE')} in {v.get('PkgName', '?')}",
                severity=v.get("Severity", "MEDIUM"),
                scan_type="container",
                description=v.get("Title") or v.get("Description", "")[:500],
                cwe_id=(v.get("CweIDs") or [""])[0],
                file=target_file,
                code_snippet=f"{v.get('PkgName','?')} {v.get('InstalledVersion','')} → fixed: {v.get('FixedVersion','-')}",
                remediation=f"Upgrade {v.get('PkgName','?')} to {v.get('FixedVersion','a patched version')}." if v.get("FixedVersion") else "Apply vendor patch.",
                raw={"engine": "trivy", "id": v.get("VulnerabilityID")},
            ))
        # Misconfigurations (Dockerfile, k8s, terraform)
        for m in result.get("Misconfigurations", []) or []:
            cause = m.get("CauseMetadata", {}) or {}
            findings.append(_f(
                title=f"{m.get('ID','MISCONF')}: {m.get('Title','Misconfiguration')}",
                severity=m.get("Severity", "MEDIUM"),
                scan_type="container",
                description=m.get("Description", ""),
                cwe_id="",
                file=target_file,
                line=cause.get("StartLine", 0),
                code_snippet=(cause.get("Code", {}) or {}).get("Lines", [{}])[0].get("Content", "") if cause.get("Code") else "",
                remediation=m.get("Resolution", ""),
                raw={"engine": "trivy", "id": m.get("ID")},
            ))
        # Secrets in image layers / fs
        for s in result.get("Secrets", []) or []:
            findings.append(_f(
                title=f"Secret: {s.get('Title') or s.get('RuleID', 'leaked credential')}",
                severity=s.get("Severity", "CRITICAL"),
                scan_type="secrets",
                description=s.get("Match", ""),
                cwe_id="CWE-798",
                file=target_file,
                line=s.get("StartLine", 0),
                code_snippet=(s.get("Match") or "")[:300],
                remediation="Rotate the secret and rebuild without it.",
                raw={"engine": "trivy", "rule": s.get("RuleID")},
            ))
    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# IaC — Checkov
# ═══════════════════════════════════════════════════════════════════════════════


async def checkov_scan(target: str) -> list[dict] | None:
    """Run ``checkov -d <target> -o json --quiet``."""
    if not _have("checkov"):
        return None
    slog.info("scan_engine_used", engine="checkov", target=target)

    target_path = Path(target)
    arg = "-f" if target_path.is_file() else "-d"
    cmd = [
        "checkov",
        arg, target,
        "-o", "json",
        "--quiet",
        "--compact",
        "--soft-fail",
    ]
    rc, stdout, stderr = await _run(cmd)
    if rc not in (0, 1, 2):
        slog.warning("checkov_failed", rc=rc, stderr=stderr[:300].decode(errors="ignore"))
        return None

    data = _safe_json_loads(stdout)
    if not data:
        return []

    # Checkov returns either a list of frameworks or a single dict
    blocks = data if isinstance(data, list) else [data]

    sev_from_check_id = {  # Checkov often omits severity → infer from framework
        "CKV_AWS": "high", "CKV_GCP": "high", "CKV_AZURE": "high",
        "CKV_K8S": "medium", "CKV_DOCKER": "medium", "CKV2": "medium",
    }

    findings: list[dict] = []
    for block in blocks:
        results = (block.get("results") or {}).get("failed_checks", []) if isinstance(block, dict) else []
        for c in results:
            check_id = c.get("check_id", "")
            sev = c.get("severity") or next(
                (v for k, v in sev_from_check_id.items() if check_id.startswith(k)),
                "medium",
            )
            file_line = c.get("file_line_range") or [0, 0]
            findings.append(_f(
                title=f"{check_id}: {c.get('check_name', 'IaC misconfiguration')}",
                severity=sev,
                scan_type="iac",
                description=c.get("check_name", ""),
                cwe_id="",
                file=c.get("file_path", "") or c.get("repo_file_path", ""),
                line=file_line[0] if file_line else 0,
                code_snippet="\n".join(
                    line if isinstance(line, str) else (line[1] if isinstance(line, list) and len(line) > 1 else str(line))
                    for line in (c.get("code_block") or [])[:10]
                )[:1000],
                remediation=c.get("guideline", "") or "Review and fix per Checkov guideline.",
                raw={"engine": "checkov", "check_id": check_id},
            ))
    return findings
