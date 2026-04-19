#!/usr/bin/env python3
"""Pipeline A — Audit Web Externe Complet (CLI).

Enchaine: subdomain enum -> full_recon pipeline -> vuln_scan pipeline ->
optional report generation. Stream les events SSE du pipeline en live.

Exemples:
    python scripts/audit_web.py example.com
    python scripts/audit_web.py example.com --no-subdomain --report
    python scripts/audit_web.py example.com --client "ACME" --tester "Moussa"
    API_KEY=xxx python scripts/audit_web.py target.tld --api http://localhost:8000

Variables d'env:
    API_KEY        clé X-API-Key (sinon --key)
    API_BASE       base URL (sinon --api, defaut http://localhost:8000)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Iterator

import httpx


def log(msg: str, level: str = "info") -> None:
    color = {"info": "\033[36m", "ok": "\033[32m", "warn": "\033[33m", "err": "\033[31m"}.get(level, "")
    reset = "\033[0m" if color else ""
    ts = time.strftime("%H:%M:%S")
    print(f"{color}[{ts}] {msg}{reset}", flush=True)


def http(client: httpx.Client, method: str, path: str, **kwargs) -> httpx.Response:
    r = client.request(method, path, **kwargs)
    if r.status_code >= 400:
        log(f"HTTP {r.status_code} {method} {path}: {r.text[:200]}", "err")
        r.raise_for_status()
    return r


def subdomain_enum(client: httpx.Client, domain: str) -> list[str]:
    log(f"Subdomain enum: {domain}")
    r = http(client, "POST", "/pentest/subdomain/quick", json={"domain": domain, "resolve": True})
    data = r.json()
    subs = data.get("subdomains") or data.get("results") or []
    if isinstance(subs, list) and subs and isinstance(subs[0], dict):
        subs = [s.get("subdomain") or s.get("name") or s.get("domain") for s in subs if s]
    subs = [s for s in subs if s]
    log(f"  -> {len(subs)} sous-domaines trouves", "ok" if subs else "warn")
    return subs


def stream_pipeline(client: httpx.Client, pipeline_id: str) -> Iterator[tuple[str, dict]]:
    """Yield (event_type, data) tuples from the SSE stream."""
    with client.stream("GET", f"/pentest/pipelines/{pipeline_id}/stream", timeout=None) as r:
        event_type = "message"
        for line in r.iter_lines():
            if not line:
                event_type = "message"
                continue
            if line.startswith("event:"):
                event_type = line.split(":", 1)[1].strip()
            elif line.startswith("data:"):
                payload = line.split(":", 1)[1].strip()
                try:
                    data = json.loads(payload)
                except json.JSONDecodeError:
                    data = {"raw": payload}
                yield event_type, data
                if event_type in ("pipeline_complete", "pipeline_error"):
                    return


_presets_cache: dict[str, list[dict]] | None = None


def _load_presets(client: httpx.Client) -> dict[str, list[dict]]:
    global _presets_cache
    if _presets_cache is None:
        r = http(client, "GET", "/pentest/pipelines/presets")
        data = r.json()
        _presets_cache = {name: info.get("steps", []) for name, info in data.items()}
    return _presets_cache


def run_pipeline(client: httpx.Client, preset: str, target: str) -> dict:
    log(f"Pipeline {preset} sur {target}")
    presets = _load_presets(client)
    steps = presets.get(preset, [])
    if not steps:
        log(f"  preset '{preset}' inconnu (dispos: {list(presets)})", "err")
        return {"status": "error"}
    r = http(
        client,
        "POST",
        "/pentest/pipelines/start",
        json={"name": preset, "target": target, "steps": steps},
    )
    pid = r.json()["pipeline_id"]
    log(f"  pipeline_id={pid}")

    findings_total = 0
    for evt, data in stream_pipeline(client, pid):
        if evt == "step_start":
            log(f"  [{data.get('step')}/{data.get('total')}] {data.get('module_id')}...")
        elif evt == "step_complete":
            f = data.get("findings", 0)
            findings_total += f if isinstance(f, int) else 0
            dur = (data.get("duration_ms") or 0) / 1000
            log(f"  [+] {data.get('module_id')}: {f} findings ({dur:.1f}s)", "ok" if f else "info")
        elif evt == "step_error":
            log(f"  [-] {data.get('module_id')}: {data.get('error')}", "err")
        elif evt == "pipeline_complete":
            dur = (data.get("duration_ms") or 0) / 1000
            log(
                f"  Pipeline OK: {data.get('completed')}/{data.get('total_steps')} steps, "
                f"{data.get('total_findings', findings_total)} findings, {dur:.1f}s",
                "ok",
            )
            return {"pipeline_id": pid, "status": "ok", "findings": data.get("total_findings", findings_total)}
        elif evt == "pipeline_error":
            log(f"  Pipeline ERR: {data.get('error')}", "err")
            return {"pipeline_id": pid, "status": "error"}
    return {"pipeline_id": pid, "status": "unknown", "findings": findings_total}


def generate_report(client: httpx.Client, *, title: str, client_name: str, tester: str, scope: list[str], scan_ids: list[str]) -> None:
    log("Generation rapport")
    body = {
        "title": title,
        "client": client_name,
        "tester": tester,
        "scope": scope,
        "scan_ids": scan_ids,
    }
    try:
        r = http(client, "POST", "/pentest/report/generate", json=body)
        data = r.json()
        rid = data.get("report_id") or data.get("id")
        log(f"  rapport genere: id={rid}", "ok")
    except httpx.HTTPStatusError as e:
        log(f"  rapport KO: {e.response.text[:200]}", "warn")


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit web externe complet via pipeline platform")
    parser.add_argument("target", help="Domaine cible (ex: example.com)")
    parser.add_argument("--api", default=os.environ.get("API_BASE", "http://localhost:8000"))
    parser.add_argument("--key", default=os.environ.get("API_KEY", ""))
    parser.add_argument("--no-subdomain", action="store_true", help="Skip subdomain enum")
    parser.add_argument("--max-subs", type=int, default=5, help="Limite sous-domaines a scanner (defaut: 5)")
    parser.add_argument("--scheme", default="https", choices=["http", "https"])
    parser.add_argument("--report", action="store_true", help="Generer rapport en fin")
    parser.add_argument("--client", default="Internal", help="Nom client pour le rapport")
    parser.add_argument("--tester", default="Red Team Operator")
    parser.add_argument("--vuln-only", action="store_true", help="Skip full_recon, vuln_scan seul")
    parser.add_argument("--recon-only", action="store_true", help="Skip vuln_scan, full_recon seul")
    args = parser.parse_args()

    if not args.key:
        print("ERROR: API_KEY missing (--key ou env API_KEY)", file=sys.stderr)
        return 2

    headers = {"X-API-Key": args.key, "Content-Type": "application/json"}
    with httpx.Client(base_url=args.api, headers=headers, timeout=30.0) as client:
        log(f"Audit web: {args.target} (api={args.api})", "info")

        targets: list[str] = []
        if args.no_subdomain:
            targets = [args.target]
        else:
            try:
                subs = subdomain_enum(client, args.target)
                targets = [args.target] + subs[: args.max_subs]
                # dedup
                seen = set()
                targets = [t for t in targets if not (t in seen or seen.add(t))]
            except Exception as e:
                log(f"Subdomain enum echec ({e}); on continue avec la cible seule", "warn")
                targets = [args.target]

        log(f"Cibles a scanner: {len(targets)} -> {targets}", "info")

        scan_ids: list[str] = []
        for t in targets:
            url = t if t.startswith("http") else f"{args.scheme}://{t}"
            try:
                if not args.vuln_only:
                    res = run_pipeline(client, "full_recon", url)
                    if res.get("pipeline_id"):
                        scan_ids.append(res["pipeline_id"])
                if not args.recon_only:
                    res = run_pipeline(client, "vuln_scan", url)
                    if res.get("pipeline_id"):
                        scan_ids.append(res["pipeline_id"])
            except httpx.HTTPError as e:
                log(f"Pipeline echec sur {url}: {e}", "err")

        if args.report and scan_ids:
            generate_report(
                client,
                title=f"Audit Web Externe - {args.target}",
                client_name=args.client,
                tester=args.tester,
                scope=targets,
                scan_ids=scan_ids,
            )

        log(f"Termine. {len(scan_ids)} pipelines executes.", "ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
