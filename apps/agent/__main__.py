"""Point d'entrée CLI : python -m apps.agent [sniffer|simulator]"""

from __future__ import annotations

import argparse


def main() -> None:
    """Parse les arguments et lance le mode sniffer ou simulateur."""
    parser = argparse.ArgumentParser(description="Cyber Defense Network Monitor")
    parser.add_argument(
        "mode",
        choices=["sniffer", "simulator", "sim"],
        help="sniffer = real capture (admin), simulator/sim = fake events",
    )
    parser.add_argument(
        "--eps",
        type=float,
        default=2,
        help="Events per second for simulator (default: 2)",
    )
    parser.add_argument(
        "--interface",
        type=str,
        default=None,
        help="Network interface for sniffer (default: all)",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=None,
        help="Duration in seconds (default: forever)",
    )
    args = parser.parse_args()

    if args.mode == "sniffer":
        from apps.agent.sniffer import run

        run(interface=args.interface)
    else:
        from apps.agent.simulator import run

        run(eps=args.eps, duration=args.duration)


if __name__ == "__main__":
    main()
