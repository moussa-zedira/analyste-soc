"""Catalogue des frameworks de conformite.

Chaque framework mappe ses controles vers des CAPABILITIES internes que la
plateforme documente :

  detection.brute_force, detection.malware, detection.exfil,
  detection.lateral, mitre.coverage, audit.immutable, audit.user_actions,
  encryption.tls, secrets.vault, vuln.scan, ioc.feeds, sigma.rules,
  uba.profiling, case_mgmt.sla, backup.dr, incident.playbook

Ce mapping permet de generer des rapports de couverture sans dependre
d'une norme externe non commitable (chaque framework officiel a des
licences specifiques — on garde ici un sous-ensemble representatif).
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Control:
    """Un controle de conformite : id officiel, libelle, capabilities requises."""

    id: str
    title: str
    description: str
    capabilities: list[str] = field(default_factory=list)
    mandatory: bool = True


@dataclass
class Framework:
    """Un framework de conformite avec son inventaire de controles."""

    id: str
    name: str
    version: str
    url: str
    description: str
    controls: list[Control] = field(default_factory=list)


# ──────────────────────────────────────────────────────────────────────
# NIS2 (UE 2022/2555) — sous-ensemble axe sur la gestion des risques cyber
# ──────────────────────────────────────────────────────────────────────

NIS2 = Framework(
    id="nis2",
    name="NIS2 Directive (EU 2022/2555)",
    version="2022",
    url="https://eur-lex.europa.eu/eli/dir/2022/2555/oj",
    description="Directive UE sur la securite des reseaux et systemes d'information",
    controls=[
        Control(
            "nis2.21.2.a",
            "Risk analysis & ISMS",
            "Politique d'analyse des risques + systeme de management",
            ["sigma.rules", "mitre.coverage", "uba.profiling"],
        ),
        Control(
            "nis2.21.2.b",
            "Incident handling",
            "Capacite de gerer les incidents (detection, reponse, recovery)",
            ["case_mgmt.sla", "incident.playbook", "detection.brute_force"],
        ),
        Control(
            "nis2.21.2.c",
            "Business continuity & DR",
            "Continuite d'activite + plans de reprise",
            ["backup.dr"],
        ),
        Control(
            "nis2.21.2.d",
            "Supply chain security",
            "Securite chaine d'approvisionnement (incl. SBOM)",
            ["vuln.scan", "ioc.feeds"],
        ),
        Control(
            "nis2.21.2.e",
            "Network security & vuln mgmt",
            "Securite des reseaux + acquisition + gestion des vulns",
            ["vuln.scan", "detection.lateral", "encryption.tls"],
        ),
        Control(
            "nis2.21.2.f",
            "Effectiveness assessment",
            "Politique d'evaluation des mesures de securite",
            ["mitre.coverage", "audit.immutable"],
        ),
        Control(
            "nis2.21.2.g",
            "Cyber hygiene & training",
            "Bonnes pratiques + formation",
            ["audit.user_actions"],
            mandatory=False,
        ),
        Control(
            "nis2.21.2.h",
            "Cryptography",
            "Politique d'utilisation cryptographique + chiffrement",
            ["encryption.tls", "secrets.vault"],
        ),
        Control(
            "nis2.21.2.i",
            "HR security & access control",
            "Securite RH + controle d'acces",
            ["audit.user_actions"],
        ),
        Control(
            "nis2.21.2.j",
            "MFA & secure comms",
            "Authentification multi-facteur + comms securisees",
            ["encryption.tls"],
        ),
    ],
)


# ──────────────────────────────────────────────────────────────────────
# DORA (UE 2022/2554) — secteur financier
# ──────────────────────────────────────────────────────────────────────

DORA = Framework(
    id="dora",
    name="DORA — Digital Operational Resilience Act",
    version="2022",
    url="https://eur-lex.europa.eu/eli/reg/2022/2554/oj",
    description="Resilience operationnelle numerique du secteur financier UE",
    controls=[
        Control(
            "dora.art5",
            "ICT risk management framework",
            "Cadre de gestion des risques TIC",
            ["sigma.rules", "mitre.coverage", "uba.profiling"],
        ),
        Control(
            "dora.art9",
            "Detection of anomalous activities",
            "Mecanismes de detection des activites anormales",
            ["uba.profiling", "detection.brute_force", "detection.exfil"],
        ),
        Control(
            "dora.art11",
            "Response & recovery",
            "Reponse et recuperation",
            ["incident.playbook", "case_mgmt.sla", "backup.dr"],
        ),
        Control(
            "dora.art13",
            "Learning & evolving",
            "Apprentissage des incidents passes",
            ["audit.immutable", "case_mgmt.sla"],
        ),
        Control(
            "dora.art17",
            "Incident classification & reporting",
            "Classification + reporting des incidents",
            ["case_mgmt.sla", "audit.immutable"],
        ),
        Control(
            "dora.art24",
            "Threat-led penetration testing (TLPT)",
            "Tests d'intrusion bases sur les menaces",
            ["mitre.coverage", "ioc.feeds"],
        ),
        Control(
            "dora.art28",
            "Third-party risk",
            "Gestion des risques tiers (incl. CVE supply-chain)",
            ["vuln.scan", "ioc.feeds"],
        ),
    ],
)


# ──────────────────────────────────────────────────────────────────────
# PCI-DSS v4.0 — controles representatifs
# ──────────────────────────────────────────────────────────────────────

PCI_DSS = Framework(
    id="pci-dss",
    name="PCI-DSS v4.0",
    version="4.0",
    url="https://www.pcisecuritystandards.org/",
    description="Payment Card Industry Data Security Standard",
    controls=[
        Control(
            "pci.req1",
            "Network security controls",
            "Pare-feu et segmentation reseau",
            ["detection.lateral"],
        ),
        Control(
            "pci.req2",
            "Secure configuration",
            "Configuration securisee (pas de defaults)",
            ["vuln.scan"],
        ),
        Control(
            "pci.req3",
            "Protect stored account data",
            "Protection des donnees de compte (chiffrement at rest)",
            ["encryption.tls", "secrets.vault"],
        ),
        Control("pci.req4", "Encrypt transmissions", "Chiffrement en transit", ["encryption.tls"]),
        Control(
            "pci.req5",
            "Anti-malware",
            "Protection contre les malwares",
            ["detection.malware", "ioc.feeds"],
        ),
        Control(
            "pci.req6",
            "Vulnerability management",
            "Developpement securise + patch mgmt",
            ["vuln.scan"],
        ),
        Control(
            "pci.req7",
            "Restrict access",
            "Restriction des acces (need-to-know)",
            ["audit.user_actions"],
        ),
        Control(
            "pci.req8",
            "Identify users",
            "Identification + authent forte",
            ["audit.user_actions", "uba.profiling"],
        ),
        Control(
            "pci.req10",
            "Log & monitor",
            "Journalisation + monitoring de tous les acces",
            ["sigma.rules", "audit.immutable", "uba.profiling"],
        ),
        Control(
            "pci.req11",
            "Test security",
            "Tester regulierement la securite (pentests)",
            ["vuln.scan", "mitre.coverage"],
        ),
        Control(
            "pci.req12",
            "Information security policy",
            "Politique de securite de l'information",
            ["incident.playbook", "case_mgmt.sla"],
        ),
    ],
)


# ──────────────────────────────────────────────────────────────────────
# ISO/IEC 27001:2022 — controles Annex A representatifs
# ──────────────────────────────────────────────────────────────────────

ISO_27001 = Framework(
    id="iso-27001",
    name="ISO/IEC 27001:2022",
    version="2022",
    url="https://www.iso.org/standard/27001",
    description="Systeme de management de la securite de l'information",
    controls=[
        Control(
            "iso.a5.7",
            "Threat intelligence",
            "Veille sur les menaces",
            ["ioc.feeds", "mitre.coverage"],
        ),
        Control(
            "iso.a5.24",
            "Information security incident management",
            "Planification de la gestion des incidents",
            ["incident.playbook", "case_mgmt.sla"],
        ),
        Control("iso.a5.30", "ICT readiness for BC", "Continuite TIC", ["backup.dr"]),
        Control(
            "iso.a8.7",
            "Protection against malware",
            "Protection contre les malwares",
            ["detection.malware", "ioc.feeds"],
        ),
        Control(
            "iso.a8.8",
            "Management of technical vulnerabilities",
            "Gestion des vulns techniques",
            ["vuln.scan"],
        ),
        Control("iso.a8.15", "Logging", "Journalisation", ["sigma.rules", "audit.immutable"]),
        Control(
            "iso.a8.16",
            "Monitoring activities",
            "Surveillance des activites",
            ["uba.profiling", "detection.brute_force"],
        ),
        Control(
            "iso.a8.24", "Use of cryptography", "Cryptographie", ["encryption.tls", "secrets.vault"]
        ),
    ],
)


# ──────────────────────────────────────────────────────────────────────
# NIST Cybersecurity Framework 2.0
# ──────────────────────────────────────────────────────────────────────

NIST_CSF = Framework(
    id="nist-csf",
    name="NIST Cybersecurity Framework 2.0",
    version="2.0",
    url="https://www.nist.gov/cyberframework",
    description="Framework de cyber-securite NIST (Govern, Identify, Protect, Detect, Respond, Recover)",
    controls=[
        Control("csf.id.am", "Asset Management", "Inventaire des assets", ["vuln.scan"]),
        Control(
            "csf.id.ra",
            "Risk Assessment",
            "Evaluation des risques",
            ["mitre.coverage", "vuln.scan"],
        ),
        Control(
            "csf.pr.aa",
            "Identity Mgmt & Access Control",
            "Gestion identite + controle acces",
            ["audit.user_actions"],
        ),
        Control(
            "csf.pr.ds",
            "Data Security",
            "Protection des donnees",
            ["encryption.tls", "secrets.vault"],
        ),
        Control(
            "csf.de.ae",
            "Anomalies & Events",
            "Detection des anomalies",
            ["uba.profiling", "sigma.rules"],
        ),
        Control(
            "csf.de.cm",
            "Continuous Monitoring",
            "Monitoring continu",
            ["sigma.rules", "audit.immutable"],
        ),
        Control(
            "csf.rs.an", "Analysis", "Analyse des incidents", ["case_mgmt.sla", "mitre.coverage"]
        ),
        Control("csf.rs.mi", "Mitigation", "Confinement + eradication", ["incident.playbook"]),
        Control("csf.rc.rp", "Recovery Planning", "Planning de recuperation", ["backup.dr"]),
    ],
)


# ──────────────────────────────────────────────────────────────────────

ALL_FRAMEWORKS: dict[str, Framework] = {f.id: f for f in [NIS2, DORA, PCI_DSS, ISO_27001, NIST_CSF]}


def list_frameworks() -> list[dict]:
    return [
        {
            "id": f.id,
            "name": f.name,
            "version": f.version,
            "url": f.url,
            "description": f.description,
            "controls_count": len(f.controls),
        }
        for f in ALL_FRAMEWORKS.values()
    ]


def get_framework(fid: str) -> Framework | None:
    return ALL_FRAMEWORKS.get(fid)
