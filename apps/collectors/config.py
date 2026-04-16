"""Configuration partagee des collecteurs."""

from __future__ import annotations

import os


API_BASE_URL = os.getenv("API_BASE_URL", "http://127.0.0.1:8000")
API_KEY = os.getenv("API_KEY", "")
if not API_KEY:
    raise RuntimeError(
        "API_KEY env var is required for the syslog collector. "
        "Set it to match the backend's API_KEY value."
    )

SYSLOG_UDP_PORT = int(os.getenv("SYSLOG_UDP_PORT", "514"))
SYSLOG_TCP_PORT = int(os.getenv("SYSLOG_TCP_PORT", "1514"))

BATCH_SIZE = int(os.getenv("BATCH_SIZE", "50"))
FLUSH_INTERVAL = float(os.getenv("FLUSH_INTERVAL", "2.0"))

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
