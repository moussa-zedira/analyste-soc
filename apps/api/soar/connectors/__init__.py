"""SOAR connectors package — real integrations with security tools.

Each connector exposes a client class that wraps API calls to a specific vendor.
All connectors share the abstract `Connector` base class (see `base.py`) which
provides `configured` property, `available()` async check and common logging.

Available connectors:
- IPTablesConnector        (iptables)
- LDAPConnector            (ldap_ad)
- AWSConnector             (aws_iam)
- DefenderConnector        (ms_defender)
- FalconConnector          (crowdstrike)
- PanoramaConnector        (palo_alto)
"""

from apps.api.soar.connectors.aws_iam import AWSConnector
from apps.api.soar.connectors.base import Connector
from apps.api.soar.connectors.crowdstrike import FalconConnector
from apps.api.soar.connectors.iptables import IPTablesConnector
from apps.api.soar.connectors.ldap_ad import LDAPConnector
from apps.api.soar.connectors.ms_defender import DefenderConnector
from apps.api.soar.connectors.palo_alto import PanoramaConnector

__all__ = [
    "Connector",
    "IPTablesConnector",
    "LDAPConnector",
    "AWSConnector",
    "DefenderConnector",
    "FalconConnector",
    "PanoramaConnector",
    "list_connectors",
]


def list_connectors() -> list[Connector]:
    """Instancie tous les connectors disponibles (diagnostic)."""
    return [
        IPTablesConnector(),
        LDAPConnector(),
        AWSConnector(),
        DefenderConnector(),
        FalconConnector(),
        PanoramaConnector(),
    ]
