"""File watcher — surveille des fichiers de log et envoie les nouvelles lignes a l'API."""

from __future__ import annotations

import glob as globmod
import json
import logging
import os
import time
from pathlib import Path

from apps.collectors.api_client import send_batch
from apps.collectors.normalizer import NormalizedEvent, init_parsers, parse_line

logger = logging.getLogger(__name__)

OFFSET_DIR = Path.home() / ".cyberdef"
OFFSET_FILE = OFFSET_DIR / "filewatcher_offsets.json"
POLL_INTERVAL = 2  # seconds

# Auto-detect format hints by filename
_FORMAT_HINTS: dict[str, str] = {
    "auth.log": "auth",
    "secure": "auth",
    "syslog": "syslog",
    "messages": "syslog",
    "access.log": "apache",
    "access_log": "apache",
    "error.log": "syslog",
    "error_log": "syslog",
}


def _load_offsets() -> dict[str, dict]:
    if OFFSET_FILE.exists():
        try:
            return json.loads(OFFSET_FILE.read_text())
        except Exception:
            logger.warning("Failed to load offsets, starting fresh")
    return {}


def _save_offsets(offsets: dict[str, dict]) -> None:
    OFFSET_DIR.mkdir(parents=True, exist_ok=True)
    OFFSET_FILE.write_text(json.dumps(offsets, indent=2))


def _detect_rotation(filepath: str, saved: dict) -> bool:
    """Detecte si un fichier a subi une rotation (taille reduite ou inode change)."""
    try:
        stat = os.stat(filepath)
        current_size = stat.st_size
        current_inode = stat.st_ino

        saved_size = saved.get("size", 0)
        saved_inode = saved.get("inode", 0)

        if current_inode != saved_inode and saved_inode != 0:
            return True
        if current_size < saved_size:
            return True
    except OSError:
        pass
    return False


def watch_files(patterns: list[str]) -> None:
    """Surveille les fichiers correspondant aux patterns glob."""
    init_parsers()
    offsets = _load_offsets()
    logger.info("File watcher started, monitoring: %s", patterns)

    while True:
        batch: list[NormalizedEvent] = []
        files_found: set[str] = set()

        for pattern in patterns:
            for filepath in globmod.glob(pattern, recursive=True):
                filepath = os.path.abspath(filepath)
                files_found.add(filepath)

                if not os.path.isfile(filepath):
                    continue

                saved = offsets.get(filepath, {"offset": 0, "size": 0, "inode": 0})

                # Check for rotation
                if _detect_rotation(filepath, saved):
                    logger.info("Log rotation detected for %s, resetting offset", filepath)
                    saved = {"offset": 0, "size": 0, "inode": 0}

                try:
                    stat = os.stat(filepath)
                    current_size = stat.st_size

                    if current_size <= saved.get("offset", 0):
                        offsets[filepath] = {
                            "offset": saved.get("offset", 0),
                            "size": current_size,
                            "inode": stat.st_ino,
                        }
                        continue

                    with open(filepath, "r", errors="replace") as f:
                        f.seek(saved.get("offset", 0))
                        new_lines = f.readlines()
                        new_offset = f.tell()

                    for line in new_lines:
                        line = line.strip()
                        if not line:
                            continue
                        event = parse_line(line)
                        if event:
                            batch.append(event)

                    offsets[filepath] = {
                        "offset": new_offset,
                        "size": current_size,
                        "inode": stat.st_ino,
                    }

                except Exception:
                    logger.exception("Error reading %s", filepath)

        if batch:
            count = send_batch(batch)
            logger.info("Sent %d/%d events from file watcher", count, len(batch))
            _save_offsets(offsets)

        time.sleep(POLL_INTERVAL)


def main() -> None:
    """Point d'entree du file watcher."""
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    patterns = sys.argv[1:] if len(sys.argv) > 1 else ["/var/log/auth.log", "/var/log/syslog"]
    watch_files(patterns)


if __name__ == "__main__":
    main()
