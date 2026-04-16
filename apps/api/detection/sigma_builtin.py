"""Pack SIGMA built-in : regles seedees au demarrage si elles n'existent pas.

Chaque regle est ecrite en YAML standard SIGMA pour rester compatible avec
l'ecosysteme Sigma (sigmac, conversion natives Splunk/Elastic).
"""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from apps.api.detection.sigma_engine import import_sigma_rule
from apps.api.models.sigma_rule import SigmaRule

logger = logging.getLogger(__name__)


BUILTIN_SIGMA_RULES: list[str] = [
    """
title: Brute Force Multiple Auth Failures
id: 1f7c8a01-aa01-4be0-9c2c-1f1f8ea11001
description: Detecte de multiples echecs d'authentification consecutifs (potentiel brute-force).
status: stable
author: cyberdef
level: high
logsource:
  category: authentication
detection:
  selection:
    event_type: auth.fail
  condition: selection
""".strip(),
    """
title: Successful Login After Multiple Failures
id: 1f7c8a01-aa02-4be0-9c2c-1f1f8ea11002
description: Login reussi apres une serie d'echecs (possible compromission d'identifiants).
status: experimental
author: cyberdef
level: high
logsource:
  category: authentication
detection:
  selection:
    event_type: auth.success
  keywords:
    - 'after failures'
    - 'previous failed'
  condition: selection and keywords
""".strip(),
    """
title: Suspicious PowerShell Encoded Command
id: 2a4d4501-bb03-4be0-9c2c-1f1f8ea11003
description: Detection des commandes PowerShell encodees en Base64 (technique d'evasion T1059.001).
status: stable
author: cyberdef
level: high
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Message:
      - '*-EncodedCommand*'
      - '*-enc *'
      - '*FromBase64String*'
  condition: selection
""".strip(),
    """
title: Privilege Escalation via sudo
id: 3b8e5601-cc04-4be0-9c2c-1f1f8ea11004
description: Tentative d'elevation de privileges via sudo / setuid (T1548).
status: stable
author: cyberdef
level: medium
logsource:
  product: linux
detection:
  selection:
    event_type: priv.escalation
  condition: selection
""".strip(),
    """
title: Web Server Forbidden Burst
id: 4c1f6701-dd05-4be0-9c2c-1f1f8ea11005
description: Forte volumetrie de 403 Forbidden (potentiel scan d'enumeration).
status: experimental
author: cyberdef
level: medium
logsource:
  category: webserver
detection:
  selection:
    event_type: web.forbidden
  condition: selection
""".strip(),
    """
title: Network Service Discovery (port scan)
id: 5d2a7801-ee06-4be0-9c2c-1f1f8ea11006
description: Pattern de scan reseau (T1046).
status: stable
author: cyberdef
level: medium
logsource:
  category: ids
detection:
  selection:
    Message:
      - '*portscan*'
      - '*port scan*'
      - '*nmap*'
      - '*masscan*'
  condition: selection
""".strip(),
    """
title: Suspicious Account Creation
id: 6e3b8901-ff07-4be0-9c2c-1f1f8ea11007
description: Creation de compte (T1136) — a correler avec une activite admin recente.
status: stable
author: cyberdef
level: medium
logsource:
  product: windows
detection:
  selection:
    event_type: account.created
  condition: selection
""".strip(),
    """
title: Disable Defenses Indicator
id: 7f4ca001-aa08-4be0-9c2c-1f1f8ea11008
description: Tentative de desactivation des defenses (T1562) — antivirus, EDR, audit.
status: experimental
author: cyberdef
level: high
logsource:
  product: windows
detection:
  selection:
    Message:
      - '*Set-MpPreference*'
      - '*DisableRealtimeMonitoring*'
      - '*Stop-Service*WinDefend*'
      - '*sc stop SecurityHealthService*'
  condition: selection
""".strip(),
]


def seed_builtin_sigma(db: Session) -> int:
    """Importe les regles SIGMA built-in si elles n'existent pas deja.

    Retourne le nombre de regles nouvellement creees.
    """
    created = 0
    existing_titles = {
        name for (name,) in db.query(SigmaRule.name).all()
    }
    for yaml_content in BUILTIN_SIGMA_RULES:
        try:
            import yaml as _yaml
            parsed = _yaml.safe_load(yaml_content)
            title = (parsed or {}).get("title", "")
        except Exception:  # noqa: BLE001
            title = ""
        if not title or title in existing_titles:
            continue
        try:
            import_sigma_rule(yaml_content, db)
            created += 1
        except Exception:
            logger.exception("Failed to seed sigma rule %s", title)
    if created:
        logger.info("Seeded %d built-in SIGMA rules", created)
    return created
