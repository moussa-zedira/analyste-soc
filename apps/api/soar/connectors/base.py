"""Base class for SOAR connectors."""

from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)


class Connector:
    """Classe abstraite pour tous les connectors SOAR.

    Chaque connector concret doit :
      - definir `name` (str) et `required_env` (liste de variables d'env)
      - implementer `available()` async : retourne True si le service repond
      - implementer les methodes metier (block_ip, disable_user, etc.)
    """

    name: str = "base"
    required_env: list[str] = []

    def __init__(self) -> None:
        self._env = {k: os.getenv(k, "") for k in self.required_env}

    @property
    def configured(self) -> bool:
        """Retourne True si toutes les variables d'env requises sont presentes."""
        if not self.required_env:
            return True
        return all(self._env.get(k) for k in self.required_env)

    def env(self, key: str, default: str = "") -> str:
        """Helper pour lire une env var au runtime (re-lecture a chaque appel)."""
        return os.getenv(key, default) or default

    async def available(self) -> bool:
        """Ping le service distant. Override dans les sous-classes."""
        return self.configured

    def info(self) -> dict[str, Any]:
        """Diagnostic snapshot (pour la route /soar/connectors)."""
        return {
            "name": self.name,
            "configured": self.configured,
            "required_env": self.required_env,
            "missing_env": [k for k in self.required_env if not self._env.get(k)],
        }

    def _log(self, level: str, msg: str, **kw: Any) -> None:
        extra = " ".join(f"{k}={v}" for k, v in kw.items())
        getattr(logger, level)("[connector:%s] %s %s", self.name, msg, extra)
