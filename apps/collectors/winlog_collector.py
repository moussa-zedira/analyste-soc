"""Collecteur Windows Event Log — lit les journaux systeme Windows en temps reel."""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path

from apps.collectors.api_client import send_batch
from apps.collectors.normalizer import NormalizedEvent
from apps.collectors.winlog_ids import WINLOG_EVENT_MAP

logger = logging.getLogger(__name__)

BOOKMARK_DIR = Path.home() / ".cyberdef"
BOOKMARK_FILE = BOOKMARK_DIR / "winlog_bookmarks.json"

CHANNELS = ["Security", "System", "Application"]
POLL_INTERVAL = 5  # seconds


def _load_bookmarks() -> dict[str, int]:
    """Charge les bookmarks de lecture depuis le fichier JSON."""
    if BOOKMARK_FILE.exists():
        try:
            return json.loads(BOOKMARK_FILE.read_text())
        except Exception:
            logger.warning("Failed to load bookmarks, starting fresh")
    return {}


def _save_bookmarks(bookmarks: dict[str, int]) -> None:
    """Sauvegarde les bookmarks."""
    BOOKMARK_DIR.mkdir(parents=True, exist_ok=True)
    BOOKMARK_FILE.write_text(json.dumps(bookmarks, indent=2))


def _event_to_normalized(event_id: int, channel: str, computer: str,
                         message: str, src_ip: str | None,
                         username: str | None) -> NormalizedEvent:
    """Convertit un event Windows en NormalizedEvent."""
    mapping = WINLOG_EVENT_MAP.get(event_id)
    if mapping:
        event_type, severity, desc = mapping
    else:
        event_type = f"winlog.{event_id}"
        severity = "low"
        desc = message or f"Windows Event {event_id}"

    return NormalizedEvent(
        source=f"winlog:{computer}/{channel}",
        event_type=event_type,
        severity=severity,
        src_ip=src_ip,
        username=username,
        message=desc if not message else message[:500],
        raw=json.dumps({
            "event_id": event_id,
            "channel": channel,
            "computer": computer,
        }),
    )


def collect_windows_logs() -> None:
    """Boucle principale de collecte des logs Windows via win32evtlog."""
    try:
        import win32evtlog
        import win32evtlogutil
    except ImportError:
        logger.error(
            "pywin32 not available. Install with: pip install pywin32\n"
            "This collector only works on Windows."
        )
        return

    bookmarks = _load_bookmarks()
    computer = os.environ.get("COMPUTERNAME", "localhost")
    logger.info("Starting Windows Event Log collector on %s", computer)
    logger.info("Monitoring channels: %s", CHANNELS)

    while True:
        batch: list[NormalizedEvent] = []

        for channel in CHANNELS:
            try:
                hand = win32evtlog.OpenEventLog(None, channel)
                flags = (
                    win32evtlog.EVENTLOG_FORWARDS_READ
                    | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                )

                last_record = bookmarks.get(channel, 0)
                win32evtlog.GetNumberOfEventLogRecords(hand)

                while True:
                    events = win32evtlog.ReadEventLog(hand, flags, 0)
                    if not events:
                        break

                    for event in events:
                        record_num = event.RecordNumber
                        if record_num <= last_record:
                            continue

                        event_id = event.EventID & 0xFFFF
                        message = ""
                        try:
                            message = win32evtlogutil.FormatMessage(event, channel)
                        except Exception:
                            message = str(event.StringInserts or "")

                        # Extract username from string inserts
                        username = None
                        src_ip = None
                        if event.StringInserts:
                            inserts = list(event.StringInserts)
                            # Common patterns for security events
                            if len(inserts) > 5:
                                username = inserts[5] if inserts[5] != "-" else None
                            if len(inserts) > 19:
                                ip_val = inserts[19]
                                if ip_val and ip_val != "-" and "." in ip_val:
                                    src_ip = ip_val

                        normalized = _event_to_normalized(
                            event_id, channel, computer,
                            message[:500], src_ip, username,
                        )
                        batch.append(normalized)
                        bookmarks[channel] = record_num

                win32evtlog.CloseEventLog(hand)

            except Exception:
                logger.exception("Error reading channel %s", channel)

        if batch:
            count = send_batch(batch)
            logger.info("Sent %d/%d Windows events", count, len(batch))
            _save_bookmarks(bookmarks)

        time.sleep(POLL_INTERVAL)


def main() -> None:
    """Point d'entree du collecteur Windows."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    collect_windows_logs()


if __name__ == "__main__":
    main()
