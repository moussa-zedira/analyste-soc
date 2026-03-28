"""Pipeline de normalisation — registre de parsers et format unifie."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Protocol

logger = logging.getLogger(__name__)


@dataclass
class NormalizedEvent:
    """Format unifie d'un evenement de securite."""

    source: str
    event_type: str
    severity: str = "low"
    src_ip: str | None = None
    dst_ip: str | None = None
    username: str | None = None
    message: str | None = None
    raw: str | None = None


class Parser(Protocol):
    """Interface pour les parsers de log."""

    name: str

    def can_parse(self, line: str) -> bool:
        """Retourne True si le parser reconnait cette ligne."""
        ...

    def parse(self, line: str) -> NormalizedEvent | None:
        """Parse la ligne et retourne un NormalizedEvent ou None."""
        ...


_registry: list[Parser] = []


def register(parser: Parser) -> None:
    """Enregistre un parser dans le pipeline."""
    _registry.append(parser)
    logger.debug("Parser registered: %s", parser.name)


def parse_line(line: str) -> NormalizedEvent | None:
    """Essaie chaque parser enregistre et retourne le premier resultat."""
    for parser in _registry:
        try:
            if parser.can_parse(line):
                result = parser.parse(line)
                if result is not None:
                    return result
        except Exception:
            logger.exception("Parser %s failed on line", parser.name)
    return None


def init_parsers() -> None:
    """Charge et enregistre tous les parsers disponibles."""
    from apps.collectors.parsers.syslog_rfc3164 import Rfc3164Parser
    from apps.collectors.parsers.syslog_rfc5424 import Rfc5424Parser
    from apps.collectors.parsers.cef import CefParser
    from apps.collectors.parsers.json_log import JsonLogParser
    from apps.collectors.parsers.windows_xml import WindowsXmlParser
    from apps.collectors.parsers.apache_combined import ApacheCombinedParser
    from apps.collectors.parsers.auth_log import AuthLogParser

    for cls in [
        Rfc3164Parser,
        Rfc5424Parser,
        CefParser,
        JsonLogParser,
        WindowsXmlParser,
        ApacheCombinedParser,
        AuthLogParser,
    ]:
        register(cls())
