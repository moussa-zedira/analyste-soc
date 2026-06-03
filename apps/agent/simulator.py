"""Simulateur réaliste d'événements de sécurité pour le tableau de bord."""

from __future__ import annotations

import random
import threading
import time

from apps.agent.api_client import post_event, trigger_anomaly, trigger_rules

# ---------------------------------------------------------------------------
# Pools for realistic data
# ---------------------------------------------------------------------------

ATTACKER_IPS = [f"203.0.113.{i}" for i in range(1, 20)]
INTERNAL_IPS = [f"10.0.1.{i}" for i in range(10, 50)]
DNS_SERVERS = ["8.8.8.8", "1.1.1.1"]

USERNAMES = [
    "admin",
    "root",
    "administrator",
    "jsmith",
    "svc_backup",
    "test",
    "deploy",
    "guest",
    "sa",
    "postgres",
]

SUSPICIOUS_DOMAINS = [
    "malware-c2.xyz",
    "exfil-data.top",
    "phishing-kit.tk",
    "darkweb-proxy.ml",
    "cryptominer.buzz",
    "botnet-ctrl.ga",
    "ransom-payment.cf",
    "stealer-panel.ru",
]

SCAN_PORTS = [22, 23, 25, 80, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443]

DEFAULT_EPS = 3
BURST_INTERVAL = 45  # seconds between attack bursts

stats: dict[str, int] = {"total": 0}

# ---------------------------------------------------------------------------
# Event generators
# ---------------------------------------------------------------------------


def generate_auth_success() -> dict:
    """Génère un événement d'authentification réussie."""
    return {
        "source": "simulator",
        "event_type": "auth.success",
        "severity": "low",
        "src_ip": random.choice(INTERNAL_IPS),
        "dst_ip": random.choice(INTERNAL_IPS),
        "username": random.choice(USERNAMES[:5]),
        "message": f"Successful login via {random.choice(['SSH', 'RDP', 'HTTP'])}",
        "raw": {
            "protocol": random.choice(["ssh", "rdp", "http"]),
            "port": random.choice([22, 3389, 443]),
        },
    }


def generate_auth_fail() -> dict:
    """Génère un événement d'échec d'authentification."""
    return {
        "source": "simulator",
        "event_type": "auth.fail",
        "severity": "medium",
        "src_ip": random.choice(ATTACKER_IPS),
        "dst_ip": random.choice(INTERNAL_IPS),
        "username": random.choice(USERNAMES),
        "message": f"Failed login attempt via {random.choice(['SSH', 'RDP', 'HTTP'])}",
        "raw": {
            "protocol": random.choice(["ssh", "rdp", "http"]),
            "port": random.choice([22, 3389, 443]),
        },
    }


def generate_brute_force_burst(count: int = 12) -> list[dict]:
    """Rafale d'auth.fail depuis la même IP -> déclenche la règle bruteforce.v1."""
    attacker = random.choice(ATTACKER_IPS)
    target = random.choice(INTERNAL_IPS)
    return [
        {
            "source": "simulator",
            "event_type": "auth.fail",
            "severity": "medium",
            "src_ip": attacker,
            "dst_ip": target,
            "username": random.choice(USERNAMES),
            "message": f"Failed SSH login from {attacker}",
            "raw": {"protocol": "ssh", "port": 22},
        }
        for _ in range(count)
    ]


def generate_conn_attempt() -> dict:
    """Génère un événement de tentative de connexion."""
    return {
        "source": "simulator",
        "event_type": "conn.attempt",
        "severity": "low",
        "src_ip": random.choice(ATTACKER_IPS),
        "dst_ip": random.choice(INTERNAL_IPS),
        "message": f"Connection attempt on port {random.choice(SCAN_PORTS)}",
        "raw": {"port": random.choice(SCAN_PORTS), "protocol": "tcp"},
    }


def generate_port_scan_burst(count: int = 55) -> list[dict]:
    """Rafale de conn.attempt depuis la même IP -> déclenche la règle portscan.v1."""
    attacker = random.choice(ATTACKER_IPS)
    return [
        {
            "source": "simulator",
            "event_type": "conn.attempt",
            "severity": "low",
            "src_ip": attacker,
            "dst_ip": random.choice(INTERNAL_IPS),
            "message": f"Connection attempt on port {port}",
            "raw": {"port": port, "protocol": "tcp"},
        }
        for port in random.choices(SCAN_PORTS, k=count)
    ]


def generate_dns_anomaly() -> dict:
    """Génère un événement d'anomalie DNS vers un domaine suspect."""
    domain = random.choice(SUSPICIOUS_DOMAINS)
    return {
        "source": "simulator",
        "event_type": "dns_anomaly",
        "severity": "high",
        "src_ip": random.choice(INTERNAL_IPS),
        "dst_ip": random.choice(DNS_SERVERS),
        "message": f"DNS query to suspicious domain: {domain}",
        "raw": {"domain": domain},
    }


def generate_blocked_connection() -> dict:
    """Génère un événement de connexion bloquée par le pare-feu."""
    return {
        "source": "simulator",
        "event_type": "blocked_connection",
        "severity": "low",
        "src_ip": random.choice(ATTACKER_IPS),
        "dst_ip": random.choice(INTERNAL_IPS),
        "message": "Connection blocked by firewall",
        "raw": {"port": random.choice(SCAN_PORTS), "action": "DROP"},
    }


def generate_data_exfil() -> dict:
    """Génère un événement d'exfiltration de données volumineuse."""
    mb = round(random.uniform(5.0, 50.0), 1)
    return {
        "source": "simulator",
        "event_type": "data_exfil",
        "severity": "high",
        "src_ip": random.choice(INTERNAL_IPS),
        "dst_ip": random.choice(ATTACKER_IPS),
        "message": f"Large outbound data transfer: {mb} MB",
        "raw": {
            "bytes": int(mb * 1_000_000),
            "duration_seconds": random.randint(10, 120),
        },
    }


# Weighted generators: (function, weight)
_GENERATORS = [
    (generate_auth_success, 15),
    (generate_auth_fail, 25),
    (generate_conn_attempt, 15),
    (generate_dns_anomaly, 15),
    (generate_blocked_connection, 20),
    (generate_data_exfil, 10),
]


def _pick_generator():
    """Sélectionne un générateur d'événements selon les poids définis."""
    funcs, weights = zip(*_GENERATORS, strict=False)
    return random.choices(funcs, weights=weights, k=1)[0]


# ---------------------------------------------------------------------------
# Background rules trigger
# ---------------------------------------------------------------------------


def _rules_loop(interval: int = 30) -> None:
    """Boucle d'arrière-plan déclenchant règles et détection d'anomalies."""
    while True:
        time.sleep(interval)
        trigger_rules()
        trigger_anomaly()


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def _send_and_count(event_data: dict) -> None:
    """Envoie un événement et incrémente les compteurs de statistiques."""
    result = post_event(event_data)
    if result:
        stats["total"] += 1
        stats.setdefault(event_data["event_type"], 0)
        stats[event_data["event_type"]] = stats.get(event_data["event_type"], 0) + 1


def run(eps: float = DEFAULT_EPS, duration: int | None = None) -> None:
    """Lance le simulateur. *eps* = événements par seconde."""
    print(f"[SIMULATOR] Starting at ~{eps} events/sec")
    print(f"[SIMULATOR] Attack bursts every ~{BURST_INTERVAL}s")
    print("[SIMULATOR] Rules evaluated every ~30s")
    print("[SIMULATOR] Ctrl+C to stop\n")

    threading.Thread(target=_rules_loop, args=(30,), daemon=True).start()

    delay = 1.0 / eps
    start = time.time()
    last_burst = start
    burst_type = 0  # alternate between brute force and port scan

    try:
        while True:
            if duration and (time.time() - start) > duration:
                break

            # Periodic attack bursts (alternate types)
            if time.time() - last_burst >= BURST_INTERVAL:
                if burst_type % 2 == 0:
                    print("[SIMULATOR] >>> Brute force burst <<<")
                    for ev in generate_brute_force_burst(12):
                        _send_and_count(ev)
                        time.sleep(0.05)
                else:
                    print("[SIMULATOR] >>> Port scan burst <<<")
                    for ev in generate_port_scan_burst(55):
                        _send_and_count(ev)
                        time.sleep(0.02)
                burst_type += 1
                last_burst = time.time()

            # Normal event
            gen = _pick_generator()
            event_data = gen()
            _send_and_count(event_data)

            if stats["total"] % 20 == 0 and stats["total"] > 0:
                breakdown = " | ".join(f"{k}: {v}" for k, v in stats.items() if k != "total")
                print(f"[SIMULATOR] Total: {stats['total']} | {breakdown}")

            time.sleep(delay)

    except KeyboardInterrupt:
        print(f"\n[SIMULATOR] Stopped. Total: {stats['total']}")
