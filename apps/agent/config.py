"""Configuration partagée pour l'agent de surveillance réseau."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

# Load .env: agent-local first, then project root as fallback
_agent_dir = Path(__file__).resolve().parent
load_dotenv(_agent_dir / ".env")
load_dotenv(_agent_dir.parent.parent / ".env")

API_BASE_URL: str = os.getenv("API_BASE_URL", "http://127.0.0.1:8000")
API_KEY: str = os.getenv("API_KEY", "")
if not API_KEY:
    raise RuntimeError(
        "API_KEY env var is required for the monitoring agent. "
        "Set it to match the backend's API_KEY value."
    )

HEADERS: dict[str, str] = {
    "X-API-Key": API_KEY,
    "Content-Type": "application/json",
}

EVENTS_URL: str = f"{API_BASE_URL}/events"
RULES_RUN_URL: str = f"{API_BASE_URL}/rules/run"
ANOMALY_RUN_URL: str = f"{API_BASE_URL}/anomaly/run"
