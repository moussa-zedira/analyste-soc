"""Real network traffic sniffer that maps packets to security events."""

from __future__ import annotations

import threading
import time
from collections import defaultdict

from apps.agent.api_client import post_event, trigger_rules

try:
    from scapy.all import DNS, DNSQR, IP, TCP, sniff  # type: ignore[import-untyped]
except ImportError:
    sniff = None  # handled in run()

# ---------------------------------------------------------------------------
# Detection thresholds
# ---------------------------------------------------------------------------

SCAN_THRESHOLD = 15  # distinct ports from same IP = port scan
VOLUME_THRESHOLD = 5_000_000  # 5 MB from single IP = data exfil
TRACKER_WINDOW = 60  # seconds before resetting trackers

SUSPICIOUS_TLDS = [".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".buzz", ".ru"]
SUSPICIOUS_WORDS = ["malware", "c2", "exfil", "phishing", "darkweb", "botnet"]

# ---------------------------------------------------------------------------
# In-memory trackers (single-threaded — scapy callback is sequential)
# ---------------------------------------------------------------------------

syn_tracker: dict[str, set[int]] = defaultdict(set)
volume_tracker: dict[str, int] = defaultdict(int)
rst_tracker: dict[str, int] = defaultdict(int)
_tracker_reset_time: float = time.time()

stats = {"events_sent": 0, "errors": 0}


def _reset_trackers_if_needed() -> None:
    global _tracker_reset_time
    if time.time() - _tracker_reset_time > TRACKER_WINDOW:
        syn_tracker.clear()
        volume_tracker.clear()
        rst_tracker.clear()
        _tracker_reset_time = time.time()


def _send_event(
    event_type: str,
    severity: str,
    src_ip: str,
    dst_ip: str,
    message: str = "",
    username: str | None = None,
    raw: dict | None = None,
) -> None:
    result = post_event(
        {
            "source": "sniffer",
            "event_type": event_type,
            "severity": severity,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "username": username,
            "message": message,
            "raw": raw,
        }
    )
    if result:
        stats["events_sent"] += 1
        print(f"[SNIFFER] {event_type} | {src_ip} -> {dst_ip} | {message[:60]}")
    else:
        stats["errors"] += 1


# ---------------------------------------------------------------------------
# Packet callback
# ---------------------------------------------------------------------------


def _packet_callback(pkt) -> None:  # type: ignore[no-untyped-def]
    _reset_trackers_if_needed()

    if not pkt.haslayer(IP):
        return

    src_ip: str = pkt[IP].src
    dst_ip: str = pkt[IP].dst

    # 1) DNS anomaly
    if pkt.haslayer(DNSQR):
        qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
        if any(tld in qname for tld in SUSPICIOUS_TLDS) or any(
            w in qname.lower() for w in SUSPICIOUS_WORDS
        ):
            _send_event(
                "dns_anomaly",
                "high",
                src_ip,
                dst_ip,
                message=f"Suspicious DNS query: {qname}",
                raw={"query": qname},
            )
        return

    if not pkt.haslayer(TCP):
        return

    tcp = pkt[TCP]

    # 2) SYN scan detection
    if tcp.flags == 0x02:  # SYN only
        syn_tracker[src_ip].add(tcp.dport)
        if len(syn_tracker[src_ip]) >= SCAN_THRESHOLD:
            ports = sorted(syn_tracker[src_ip])[:20]
            _send_event(
                "port_scan",
                "high",
                src_ip,
                dst_ip,
                message=f"Port scan: {len(syn_tracker[src_ip])} ports probed",
                raw={"ports_sample": ports},
            )
            syn_tracker[src_ip].clear()
        return

    # 3) RST detection (blocked/refused)
    if tcp.flags & 0x04:
        rst_tracker[src_ip] += 1
        if rst_tracker[src_ip] % 10 == 0:
            _send_event(
                "blocked_connection",
                "low",
                src_ip,
                dst_ip,
                message=f"Connection refused/reset ({rst_tracker[src_ip]} RSTs)",
            )

    # 4) Volume tracking
    payload_len = len(pkt[IP].payload)
    volume_tracker[src_ip] += payload_len
    if volume_tracker[src_ip] >= VOLUME_THRESHOLD:
        mb = volume_tracker[src_ip] / 1_000_000
        _send_event(
            "data_exfil",
            "high",
            src_ip,
            dst_ip,
            message=f"High outbound volume: {mb:.1f} MB in {TRACKER_WINDOW}s",
        )
        volume_tracker[src_ip] = 0


# ---------------------------------------------------------------------------
# Background rules trigger
# ---------------------------------------------------------------------------


def _rules_loop(interval: int = 30) -> None:
    while True:
        time.sleep(interval)
        trigger_rules()


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def run(interface: str | None = None) -> None:
    """Start capturing. Requires admin/elevated privileges + Npcap."""
    if sniff is None:
        print("[ERROR] scapy is not installed.")
        print("        Install it with: pip install scapy")
        print("        Also install Npcap: https://npcap.com/")
        return

    print("[SNIFFER] Starting real network capture...")
    print(
        f"[SNIFFER] Thresholds: scan={SCAN_THRESHOLD} ports, "
        f"exfil={VOLUME_THRESHOLD / 1e6:.0f} MB, window={TRACKER_WINDOW}s"
    )
    print("[SNIFFER] Ctrl+C to stop\n")

    threading.Thread(target=_rules_loop, args=(30,), daemon=True).start()
    print("[SNIFFER] Rules trigger thread started (every 30s)")

    kwargs: dict = {"prn": _packet_callback, "store": 0}
    if interface:
        kwargs["iface"] = interface

    try:
        sniff(**kwargs)
    except PermissionError:
        print("[ERROR] Requires admin/elevated privileges. Run as Administrator.")
    except KeyboardInterrupt:
        print(
            f"\n[SNIFFER] Stopped. "
            f"Events: {stats['events_sent']}, Errors: {stats['errors']}"
        )
