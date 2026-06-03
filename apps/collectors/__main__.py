"""Point d'entree CLI pour les collecteurs."""

from __future__ import annotations

import argparse
import logging
import sys


def main() -> None:
    parser = argparse.ArgumentParser(description="CyberDef Log Collectors")
    sub = parser.add_subparsers(dest="command")

    # Syslog receiver
    sub.add_parser("syslog", help="Start syslog UDP/TCP receiver")

    # Windows Event Log collector
    sub.add_parser("winlog", help="Start Windows Event Log collector")

    # File watcher
    fw = sub.add_parser("filewatcher", help="Start file watcher")
    fw.add_argument("patterns", nargs="*", default=["/var/log/auth.log", "/var/log/syslog"])

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if args.command == "syslog":
        from apps.collectors.syslog_receiver import main as syslog_main

        syslog_main()
    elif args.command == "winlog":
        from apps.collectors.winlog_collector import main as winlog_main

        winlog_main()
    elif args.command == "filewatcher":
        from apps.collectors.file_watcher import main as fw_main

        sys.argv = [sys.argv[0]] + args.patterns
        fw_main()
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
