"""Tests du systeme de detection et de triage — classification, liste blanche, seuil, anomalies, MITRE."""

from __future__ import annotations

import os
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Stub les modules optionnels qui ne sont pas installes dans l'env de test.
# IMPORTANT : on ne stube QUE si le vrai module n'est pas installe. Sinon,
# on corromprait ``sys.modules['redis']`` pour toute la session pytest,
# et ``limits`` (via slowapi) verrait ``__version__ == "0.0.0"`` au
# prochain import de ``apps.api.main`` (rate_limiter), ce qui casse
# ~40 tests en cascade (ConfigurationError: min version 3.0).
# ---------------------------------------------------------------------------

for _mod in ("redis", "redis.asyncio"):
    if _mod in sys.modules:
        # Module deja importe (vrai ou stub precedent) : on n'y touche pas.
        continue
    try:
        __import__(_mod)
    except ImportError:
        sys.modules[_mod] = MagicMock()

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

TEST_API_KEY = "test-key-detection"


@pytest.fixture(autouse=True)
def _set_env():
    """Injecte les variables d'environnement necessaires pour les tests."""
    old_key = os.environ.get("API_KEY")
    old_env = os.environ.get("ENV")
    os.environ["API_KEY"] = TEST_API_KEY
    os.environ["ENV"] = "dev"

    from apps.api.config import get_settings
    get_settings.cache_clear()

    yield

    if old_key is None:
        os.environ.pop("API_KEY", None)
    else:
        os.environ["API_KEY"] = old_key
    if old_env is None:
        os.environ.pop("ENV", None)
    else:
        os.environ["ENV"] = old_env
    get_settings.cache_clear()


def _make_event(**kwargs) -> SimpleNamespace:
    """Cree un faux evenement avec des valeurs par defaut sensibles."""
    defaults = {
        "event_type": "auth.fail",
        "src_ip": "10.0.0.1",
        "username": "admin",
        "severity": "medium",
    }
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def _make_whitelist_entry(entry_type: str, value: str, enabled: bool = True) -> SimpleNamespace:
    """Cree une fausse entree de liste blanche."""
    return SimpleNamespace(entry_type=entry_type, value=value, enabled=enabled)


# ===========================================================================
# Triage — classification
# ===========================================================================


class TestClassifyEvent:
    """Tests de la fonction classify_event."""

    def test_classify_event_malicious(self):
        """Verifie qu'un evenement auth.fail est classifie comme malveillant."""
        from apps.api.detection.triage import classify_event

        event = _make_event(event_type="auth.fail")
        assert classify_event(event) == "malicious"

    def test_classify_event_benign(self):
        """Verifie qu'un evenement auth.success est classifie comme benin."""
        from apps.api.detection.triage import classify_event

        event = _make_event(event_type="auth.success")
        assert classify_event(event) == "benign"

    def test_classify_event_suspicious(self):
        """Verifie qu'un evenement dns_anomaly est classifie comme suspect."""
        from apps.api.detection.triage import classify_event

        event = _make_event(event_type="dns_anomaly")
        assert classify_event(event) == "suspicious"

    def test_classify_event_default(self):
        """Verifie qu'un type d'evenement inconnu retourne 'suspicious' par defaut."""
        from apps.api.detection.triage import classify_event

        event = _make_event(event_type="unknown.event.type")
        assert classify_event(event) == "suspicious"


# ===========================================================================
# Triage — liste blanche
# ===========================================================================


class TestWhitelist:
    """Tests de la fonction _is_whitelisted."""

    def test_is_whitelisted_ip(self):
        """Verifie qu'une IP figurant dans la liste blanche est detectee."""
        from apps.api.detection.triage import _is_whitelisted

        event = _make_event(src_ip="192.168.1.100")
        whitelist = [_make_whitelist_entry("ip", "192.168.1.100")]
        assert _is_whitelisted(event, whitelist) is True

    def test_is_whitelisted_ip_range(self):
        """Verifie qu'une IP dans une plage CIDR de la liste blanche est detectee."""
        from apps.api.detection.triage import _is_whitelisted

        event = _make_event(src_ip="10.0.0.42")
        whitelist = [_make_whitelist_entry("ip_range", "10.0.0.0/24")]
        assert _is_whitelisted(event, whitelist) is True

    def test_is_not_whitelisted(self):
        """Verifie qu'une IP absente de la liste blanche n'est pas filtree."""
        from apps.api.detection.triage import _is_whitelisted

        event = _make_event(src_ip="203.0.113.5")
        whitelist = [
            _make_whitelist_entry("ip", "192.168.1.100"),
            _make_whitelist_entry("ip_range", "10.0.0.0/24"),
        ]
        assert _is_whitelisted(event, whitelist) is False


# ===========================================================================
# Triage — seuil de severite
# ===========================================================================


class TestBelowThreshold:
    """Tests de la fonction _below_threshold."""

    def test_below_threshold(self):
        """Verifie qu'un evenement de faible severite est en dessous du seuil medium."""
        from apps.api.detection.triage import _below_threshold

        event = _make_event(severity="low")
        # Le seuil par defaut est 'medium' (valeur 1), 'low' vaut 0 => en dessous
        assert _below_threshold(event) is True


# ===========================================================================
# Anomalie — fonctions mathematiques pures
# ===========================================================================


class TestWelfordUpdate:
    """Tests de l'algorithme de Welford pour la mise a jour incrementale."""

    def test_welford_update(self):
        """Verifie la moyenne et la variance apres plusieurs mises a jour."""
        from apps.api.detection.anomaly import _welford_update

        count, mean, variance = 0, 0.0, 0.0

        values = [10.0, 20.0, 30.0]
        for v in values:
            count, mean, variance = _welford_update(count, mean, variance, v)

        assert count == 3
        assert mean == pytest.approx(20.0)
        # Variance de Welford (somme des carres des ecarts) = 200.0
        # Ecart-type echantillon = sqrt(200 / 2) = 10.0
        assert variance == pytest.approx(200.0)


class TestStddev:
    """Tests du calcul de l'ecart-type."""

    def test_stddev_basic(self):
        """Verifie l'ecart-type pour des valeurs connues."""
        from apps.api.detection.anomaly import _stddev

        # variance=200.0 avec count=3 => stddev = sqrt(200/2) = 10.0
        result = _stddev(200.0, 3)
        assert result == pytest.approx(10.0)


class TestZScore:
    """Tests du calcul du z-score."""

    def test_z_score_basic(self):
        """Verifie le z-score pour une valeur, une moyenne et un ecart-type connus."""
        from apps.api.detection.anomaly import _z_score

        # (40 - 20) / 10 = 2.0
        result = _z_score(40.0, 20.0, 10.0)
        assert result == pytest.approx(2.0)

    def test_z_score_zero_stddev(self):
        """Verifie que le z-score retourne 0 lorsque l'ecart-type est nul."""
        from apps.api.detection.anomaly import _z_score

        result = _z_score(42.0, 20.0, 0.0)
        assert result == 0.0


# ===========================================================================
# MITRE ATT&CK
# ===========================================================================


class TestMitre:
    """Tests du registre de correspondance MITRE ATT&CK."""

    def test_get_techniques_for_rule(self):
        """Verifie que la regle bruteforce.v1 retourne les techniques MITRE attendues."""
        from apps.api.detection.mitre import get_techniques_for_rule

        techniques = get_techniques_for_rule("bruteforce.v1")
        assert len(techniques) >= 1
        ids = {t.id for t in techniques}
        assert "T1110" in ids
        assert "T1110.001" in ids

    def test_get_techniques_unknown_rule(self):
        """Verifie qu'une regle inconnue retourne une liste vide."""
        from apps.api.detection.mitre import get_techniques_for_rule

        techniques = get_techniques_for_rule("nonexistent.rule.v99")
        assert techniques == []
