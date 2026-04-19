"""Test critique IOC : list_iocs() doit retourner un tuple (items, total).

Regression recente : list_iocs() avait ete modifie pour ne retourner qu'une
liste, cassant toutes les routes qui faisaient `items, total = list_iocs(...)`
et affichaient une pagination. Ce test verrouille le contrat.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration


def test_list_iocs_returns_tuple_items_total(db_session):
    """list_iocs(db) renvoie (list[IOC], int) — contrat de pagination."""
    from apps.api.threat_intel.ioc_manager import create_ioc, list_iocs

    # Cree 3 IOCs pour avoir une base non-vide
    create_ioc(db_session, "ip", "10.0.0.1", source="test")
    create_ioc(db_session, "ip", "10.0.0.2", source="test")
    create_ioc(db_session, "domain", "evil.test", source="test")

    result = list_iocs(db_session, limit=10)

    # Contrat : tuple de longueur 2
    assert isinstance(result, tuple), f"list_iocs doit retourner un tuple, recu {type(result)}"
    assert len(result) == 2, f"tuple doit avoir 2 elements (items, total), recu {len(result)}"

    items, total = result
    assert isinstance(items, list), "items doit etre une list"
    assert isinstance(total, int), "total doit etre un int"
    assert total >= 3, f"total doit inclure les 3 IOCs crees, recu {total}"
    assert len(items) >= 3
    # Chaque item est bien un IOC avec le champ value
    assert all(hasattr(it, "value") for it in items)

    # Filtre type=ip : total recalcule correctement
    ip_items, ip_total = list_iocs(db_session, ioc_type="ip", limit=10)
    assert ip_total >= 2
    assert all(it.type == "ip" for it in ip_items)
