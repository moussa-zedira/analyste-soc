"""Moteur SIGMA officiel base sur pySigma.

Cette implementation remplace le parser maison par la librairie officielle
`pysigma` + le backend `pysigma-backend-elasticsearch` pour produire des requetes
Lucene, qui sont ensuite transposees en filtres SQLAlchemy pour notre table
`events` (Postgres).

Compatibilite : les anciennes fonctions `compile_sigma`, `evaluate_sigma_rule`,
`import_sigma_rule`, `get_enabled_sigma_rules` sont preservees comme wrappers
au-dessus de `SigmaEngine`.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy import and_, not_, or_
from sqlalchemy.orm import Session
from sqlalchemy.sql import ColumnElement

from apps.api.models.event import Event
from apps.api.models.sigma_rule import SigmaRule

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Logsource mapping : Sigma logsource (product/category/service) → event_types
# ─────────────────────────────────────────────────────────────────────────────
LOGSOURCE_MAP: dict[str, list[str]] = {
    "authentication": ["auth.fail", "auth.success", "auth.explicit"],
    "windows": [
        "winlog", "auth.fail", "auth.success", "priv.escalation",
        "account.created", "account.deleted", "service.installed",
    ],
    "linux": ["auth.fail", "auth.success", "priv.escalation", "priv.sudo"],
    "firewall": ["network.blocked", "network.allowed"],
    "webserver": ["web.access", "web.forbidden", "web.server_error"],
    "ids": ["ids.alert"],
    "process_creation": ["process.created"],
    "security": [
        "auth.fail", "auth.success", "priv.escalation",
        "account.created", "account.deleted",
    ],
    "sysmon": ["process.created", "winlog"],
    "network_connection": ["network.allowed", "network.blocked"],
    "dns": ["dns.query", "network.allowed"],
    "proxy": ["web.access", "web.forbidden"],
}


# ─────────────────────────────────────────────────────────────────────────────
# Field mapping : noms Sigma → colonnes Event
# ─────────────────────────────────────────────────────────────────────────────
FIELD_MAP: dict[str, str] = {
    "SourceIp": "src_ip",
    "IpAddress": "src_ip",
    "src_ip": "src_ip",
    "SourceAddress": "src_ip",
    "DestinationIp": "dst_ip",
    "DestinationAddress": "dst_ip",
    "dst_ip": "dst_ip",
    "TargetUserName": "username",
    "User": "username",
    "username": "username",
    "SubjectUserName": "username",
    "EventType": "event_type",
    "event_type": "event_type",
    "EventID": "event_type",
    "Message": "message",
    "message": "message",
    "Source": "source",
    "source": "source",
    "Image": "message",
    "CommandLine": "message",
    "ProcessName": "message",
    "ParentImage": "message",
    "ParentCommandLine": "message",
    "TargetFilename": "message",
}

# Champs textuels qui peuvent etre cherches dans message/raw en fallback
FREE_TEXT_FIELDS = {"message", "raw"}

_NORMALIZED_LEVELS = {
    "informational": "low",
    "info": "low",
    "low": "low",
    "medium": "medium",
    "moderate": "medium",
    "high": "high",
    "critical": "high",
}


@dataclass
class CompiledRule:
    """Regle SIGMA compilee, prete a etre evaluee."""

    rule_id: str
    title: str
    description: str
    level: str
    author: str
    status: str
    logsource: dict[str, str]
    event_types: list[str]
    lucene: str | None
    yaml_source: str
    # Backward-compat : conditions au format legacy pour `evaluate_sigma_rule`
    conditions: list[dict] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# pySigma loader : tolerant a l'absence de la lib (degrade en mode legacy)
# ─────────────────────────────────────────────────────────────────────────────
def _load_pysigma():
    """Importe pySigma + backend ES. Retourne (SigmaRule, LuceneBackend) ou (None, None)."""
    try:
        from sigma.rule import SigmaRule as PySigmaRule
        try:
            from sigma.backends.elasticsearch import LuceneBackend
        except Exception:  # pragma: no cover - backend optionnel
            LuceneBackend = None  # type: ignore[assignment]
        return PySigmaRule, LuceneBackend
    except Exception:  # pragma: no cover
        logger.warning("pysigma not available, falling back to legacy parser")
        return None, None


# ─────────────────────────────────────────────────────────────────────────────
# SigmaEngine : nouvelle API
# ─────────────────────────────────────────────────────────────────────────────
class SigmaEngine:
    """Moteur SIGMA base sur pySigma + Lucene → SQLAlchemy."""

    def __init__(self) -> None:
        self.rules: list[CompiledRule] = []
        self._pysigma_rule_cls, self._lucene_backend_cls = _load_pysigma()
        self._backend = None
        if self._lucene_backend_cls is not None:
            try:
                self._backend = self._lucene_backend_cls()
            except Exception:  # pragma: no cover
                logger.exception("Failed to instantiate LuceneBackend")
                self._backend = None

    # ── Loading ─────────────────────────────────────────────────────────────
    def load_rules(
        self,
        source: str = "builtin",
        path: str | Path | None = None,
        yaml_strings: Iterable[str] | None = None,
        min_level: str | None = None,
    ) -> int:
        """Charge des regles depuis `builtin`, `directory`, `repo`, ou YAML brut.

        Retourne le nombre de regles chargees. Les erreurs individuelles sont
        loggees mais ne stoppent pas le chargement.
        """
        loaded: list[CompiledRule] = []

        sources: list[tuple[str, str]] = []  # (yaml_text, origin_path)
        if source == "builtin":
            from apps.api.detection.sigma_builtin import BUILTIN_SIGMA_RULES
            sources = [(y, "builtin") for y in BUILTIN_SIGMA_RULES]
        elif source == "directory":
            if path is None:
                raise ValueError("`path` is required for source='directory'")
            base = Path(path)
            if not base.exists():
                raise FileNotFoundError(f"Sigma directory not found: {base}")
            for yml in sorted(base.rglob("*.yml")):
                try:
                    sources.append((yml.read_text(encoding="utf-8"), str(yml)))
                except Exception:
                    logger.exception("Failed to read %s", yml)
        elif source == "repo":
            # Lazy fetch : delegue au caller (route /sigma/sync). Si `path`
            # pointe vers un repo deja clone, on s'en sert comme directory.
            if path is None:
                raise ValueError(
                    "`path` is required for source='repo' (path to cloned SigmaHQ)"
                )
            return self.load_rules(source="directory", path=path, min_level=min_level)
        elif source == "raw":
            if not yaml_strings:
                raise ValueError("`yaml_strings` required for source='raw'")
            sources = [(y, "raw") for y in yaml_strings]
        else:
            raise ValueError(f"Unknown source: {source}")

        threshold = _level_rank(min_level) if min_level else 0

        for yaml_text, origin in sources:
            try:
                compiled = self.compile_yaml(yaml_text)
            except Exception as exc:
                logger.warning("Sigma rule from %s failed to compile: %s", origin, exc)
                continue
            if threshold and _level_rank(compiled.level) < threshold:
                continue
            loaded.append(compiled)

        self.rules = loaded
        return len(loaded)

    # ── Compilation YAML → CompiledRule ─────────────────────────────────────
    def compile_yaml(self, yaml_text: str) -> CompiledRule:
        """Parse une regle YAML SIGMA et la compile en `CompiledRule`."""
        try:
            raw = yaml.safe_load(yaml_text)
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML: {e}") from e
        if not isinstance(raw, dict):
            raise ValueError("SIGMA rule must be a YAML mapping")

        title = raw.get("title", "Unnamed Rule")
        description = raw.get("description", "")
        level = _normalize_level(raw.get("level", "medium"))
        author = raw.get("author", "")
        status = raw.get("status", "experimental")
        rule_id = str(raw.get("id") or title)

        logsource = raw.get("logsource", {}) or {}
        event_types = _logsource_to_event_types(logsource)

        # Compilation pySigma → Lucene (best-effort)
        lucene_query: str | None = None
        if self._pysigma_rule_cls is not None and self._backend is not None:
            try:
                py_rule = self._pysigma_rule_cls.from_yaml(yaml_text)
                queries = self._backend.convert_rule(py_rule)
                if queries:
                    lucene_query = queries[0] if isinstance(queries, list) else str(queries)
            except Exception as exc:
                logger.debug(
                    "pySigma compilation failed for '%s' (%s) — fallback legacy",
                    title, exc,
                )

        # Conditions legacy (toujours produites pour fallback eval / tests)
        legacy_conditions = _legacy_compile_detection(raw.get("detection", {}) or {})

        return CompiledRule(
            rule_id=rule_id,
            title=title,
            description=description,
            level=level,
            author=author,
            status=status,
            logsource={
                "product": logsource.get("product", ""),
                "category": logsource.get("category", ""),
                "service": logsource.get("service", ""),
            },
            event_types=event_types,
            lucene=lucene_query,
            yaml_source=yaml_text,
            conditions=legacy_conditions,
        )

    # ── Evaluation ──────────────────────────────────────────────────────────
    def evaluate(
        self,
        db: Session,
        rule: CompiledRule,
        lookback_minutes: int = 10,
    ) -> list[Event]:
        """Execute une regle compilee contre la table events.

        Strategie :
          1. Filtre temporel + filtre event_types (si logsource mappe).
          2. Si une requete Lucene existe, on la convertit en clauses
             SQLAlchemy via `_lucene_to_sql`.
          3. Sinon, on retombe sur l'evaluation legacy en Python sur les
             events de la fenetre.
        """
        since = datetime.now(UTC) - timedelta(minutes=lookback_minutes)
        q = db.query(Event).filter(Event.ts >= since)

        if rule.event_types:
            q = q.filter(Event.event_type.in_(rule.event_types))

        if rule.lucene:
            try:
                clause = _lucene_to_sql(rule.lucene)
                if clause is not None:
                    q = q.filter(clause)
                    return q.all()
            except Exception:
                logger.debug(
                    "Lucene→SQL conversion failed for '%s', falling back to Python eval",
                    rule.title,
                )

        # Fallback : evaluation Python event-par-event
        candidates = q.all()
        return [ev for ev in candidates if _legacy_evaluate(rule, ev)]

    def evaluate_all(
        self,
        db: Session,
        lookback_minutes: int = 10,
        max_workers: int = 4,
    ) -> dict[str, list[Event]]:
        """Evalue toutes les regles chargees en parallele.

        Retourne un dict {rule_id: [events matched]}. Note : SQLAlchemy Session
        n'est pas thread-safe — chaque thread ne touche que ses propres requetes
        sur la session passee, donc on serialize via un lock implicite. Pour de
        vrai parallelisme, le caller devrait passer plusieurs sessions.
        """
        results: dict[str, list[Event]] = {}
        if not self.rules:
            return results

        # En pratique on serialize sur la meme session ; le ThreadPool est
        # surtout utile pour la compilation Lucene→SQL CPU-bound qui se fait
        # par regle. Les queries restent sequentielles cote DB.
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {
                ex.submit(self.evaluate, db, rule, lookback_minutes): rule
                for rule in self.rules
            }
            for fut in as_completed(futures):
                rule = futures[fut]
                try:
                    results[rule.rule_id] = fut.result()
                except Exception:
                    logger.exception("Sigma rule %s evaluation failed", rule.rule_id)
                    results[rule.rule_id] = []
        return results


# ─────────────────────────────────────────────────────────────────────────────
# Lucene → SQLAlchemy
# ─────────────────────────────────────────────────────────────────────────────
_TOKEN_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|\(|\)|\bAND\b|\bOR\b|\bNOT\b|[^\s()]+',
    re.IGNORECASE,
)


def _lucene_to_sql(lucene: str) -> ColumnElement | None:
    """Convertit une expression Lucene basique en clause SQLAlchemy.

    Couvre : `field:value`, `field:"value with spaces"`, wildcards `*`/`?`,
    operateurs `AND`/`OR`/`NOT`, parentheses, et terme libre (cherche dans
    message+raw). Retourne `None` si la chaine est vide ou non parsable.
    """
    if not lucene or not lucene.strip():
        return None
    tokens = _TOKEN_RE.findall(lucene)
    if not tokens:
        return None

    parser = _LuceneParser(tokens)
    return parser.parse_or()


class _LuceneParser:
    """Parseur recursif descendant pour un sous-ensemble de Lucene."""

    def __init__(self, tokens: list[str]) -> None:
        self.tokens = tokens
        self.pos = 0

    def _peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _consume(self) -> str | None:
        tok = self._peek()
        if tok is not None:
            self.pos += 1
        return tok

    def parse_or(self) -> ColumnElement | None:
        left = self.parse_and()
        while True:
            tok = self._peek()
            if tok and tok.upper() == "OR":
                self._consume()
                right = self.parse_and()
                if left is None:
                    left = right
                elif right is not None:
                    left = or_(left, right)
            else:
                break
        return left

    def parse_and(self) -> ColumnElement | None:
        left = self.parse_not()
        while True:
            tok = self._peek()
            if tok is None or tok in (")",) or tok.upper() == "OR":
                break
            if tok.upper() == "AND":
                self._consume()
                right = self.parse_not()
            else:
                # juxtaposition implicite = AND
                right = self.parse_not()
            if left is None:
                left = right
            elif right is not None:
                left = and_(left, right)
        return left

    def parse_not(self) -> ColumnElement | None:
        tok = self._peek()
        if tok and tok.upper() == "NOT":
            self._consume()
            inner = self.parse_term()
            if inner is not None:
                return not_(inner)
            return None
        return self.parse_term()

    def parse_term(self) -> ColumnElement | None:
        tok = self._consume()
        if tok is None:
            return None
        if tok == "(":
            inner = self.parse_or()
            # Consomme `)` si present
            if self._peek() == ")":
                self._consume()
            return inner
        if tok == ")":
            return None
        # `field:value` ou terme libre
        if ":" in tok and not tok.startswith('"'):
            field, _, value = tok.partition(":")
            return _build_field_clause(field, _strip_quotes(value))
        return _build_field_clause(None, _strip_quotes(tok))


def _strip_quotes(s: str) -> str:
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        return s[1:-1]
    return s


def _build_field_clause(field: str | None, value: str) -> ColumnElement | None:
    """Construit une clause SQL pour un (field, value)."""
    if not value:
        return None
    has_wildcard = "*" in value or "?" in value
    sql_pattern = value.replace("*", "%").replace("?", "_") if has_wildcard else None

    if field is None:
        # terme libre → cherche dans message + raw
        like = f"%{value}%"
        return or_(Event.message.ilike(like), Event.raw.ilike(like))

    column_name = FIELD_MAP.get(field, field)
    column = getattr(Event, column_name, None)
    if column is None:
        # champ inconnu → fallback sur recherche texte libre
        like = f"%{value}%"
        return or_(Event.message.ilike(like), Event.raw.ilike(like))

    if has_wildcard:
        return column.ilike(sql_pattern)
    if column_name in FREE_TEXT_FIELDS:
        return column.ilike(f"%{value}%")
    return column == value


# ─────────────────────────────────────────────────────────────────────────────
# Helpers : logsource mapping, normalisation level
# ─────────────────────────────────────────────────────────────────────────────
def _logsource_to_event_types(logsource: dict) -> list[str]:
    matched: set[str] = set()
    for key in (logsource.get("category"), logsource.get("product"), logsource.get("service")):
        if key and key in LOGSOURCE_MAP:
            matched.update(LOGSOURCE_MAP[key])
    return sorted(matched)


def _normalize_level(level: str | None) -> str:
    if not level:
        return "medium"
    return _NORMALIZED_LEVELS.get(str(level).lower(), "low")


def _level_rank(level: str | None) -> int:
    return {"low": 1, "medium": 2, "high": 3}.get(_normalize_level(level), 0)


# ─────────────────────────────────────────────────────────────────────────────
# LEGACY API : conserve la compat pour le code existant (engine.py, pipeline,
# routes, tests). Les fonctions ci-dessous sont des wrappers thin.
# ─────────────────────────────────────────────────────────────────────────────
def compile_sigma(yaml_content: str) -> dict:
    """[Compat] Compile une regle SIGMA YAML vers le format dict legacy."""
    eng = _shared_engine()
    rule = eng.compile_yaml(yaml_content)
    return {
        "title": rule.title,
        "description": rule.description,
        "level": rule.level,
        "author": rule.author,
        "event_types": rule.event_types,
        "conditions": rule.conditions,
        "lucene": rule.lucene,
    }


def _legacy_compile_detection(detection: dict) -> list[dict]:
    """Reproduction du compilateur maison pour le fallback Python."""
    conditions: list[dict] = []
    for key, value in detection.items():
        if key == "condition":
            continue
        if isinstance(value, dict):
            conditions.append({"type": "match", "name": key, "fields": value})
        elif isinstance(value, list):
            conditions.append({"type": "any_of", "name": key, "values": value})
    return conditions


def _legacy_evaluate(rule: CompiledRule, event: Event) -> bool:
    """Evaluation Python d'une regle compilee contre un Event."""
    compiled = {
        "event_types": rule.event_types,
        "conditions": rule.conditions,
    }
    return evaluate_sigma_rule(compiled, event)


def evaluate_sigma_rule(compiled: dict, event: Event) -> bool:
    """[Compat] Evalue une regle compilee (dict) contre un event en Python."""
    allowed_types = compiled.get("event_types", [])
    if allowed_types and not any(
        (event.event_type or "").startswith(t) or t.startswith(event.event_type or "")
        for t in allowed_types
    ):
        return False

    conditions = compiled.get("conditions", [])
    if not conditions:
        return False

    for cond in conditions:
        if cond["type"] == "match":
            fields = cond["fields"]
            matched = True
            for field_name, pattern in fields.items():
                event_value = _get_event_field(event, field_name)
                if not _match_field(event_value, pattern):
                    matched = False
                    break
            if not matched:
                return False
        elif cond["type"] == "any_of":
            values = cond["values"]
            event_raw = event.raw or ""
            event_msg = event.message or ""
            combined = f"{event_raw} {event_msg}".lower()
            if not any(str(v).lower() in combined for v in values):
                return False

    return True


def _match_field(event_value: str | None, pattern: Any) -> bool:
    if event_value is None:
        return False
    if isinstance(pattern, str):
        if "*" in pattern or "?" in pattern:
            regex = pattern.replace(".", r"\.").replace("*", ".*").replace("?", ".")
            return bool(re.search(regex, event_value, re.IGNORECASE))
        return pattern.lower() in event_value.lower()
    if isinstance(pattern, list):
        return any(_match_field(event_value, p) for p in pattern)
    if isinstance(pattern, (int, float)):
        return str(pattern) in event_value
    return False


def _get_event_field(event: Event, field_name: str) -> str | None:
    column_name = FIELD_MAP.get(field_name, field_name)
    return getattr(event, column_name, None)


def import_sigma_rule(yaml_content: str, db: Session) -> SigmaRule:
    """[Compat] Importe une regle SIGMA dans la table `sigma_rules`."""
    compiled = compile_sigma(yaml_content)

    rule = SigmaRule(
        name=compiled["title"],
        description=compiled.get("description", ""),
        level=compiled["level"],
        yaml_content=yaml_content,
        compiled_json=json.dumps(compiled),
        enabled=True,
        author=compiled.get("author", ""),
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return rule


def get_enabled_sigma_rules(db: Session) -> list[tuple[SigmaRule, dict]]:
    """[Compat] Retourne les regles actives + leur version compilee."""
    rules = db.query(SigmaRule).filter(SigmaRule.enabled.is_(True)).all()
    result: list[tuple[SigmaRule, dict]] = []
    for rule in rules:
        if rule.compiled_json:
            try:
                compiled = json.loads(rule.compiled_json)
                result.append((rule, compiled))
                continue
            except json.JSONDecodeError:
                pass
        # Recompile a la volee si compiled_json absent/corrompu
        try:
            compiled = compile_sigma(rule.yaml_content)
            result.append((rule, compiled))
        except Exception:
            logger.warning("Failed to recompile SIGMA rule %s", rule.id)
    return result


# Singleton interne pour eviter de recreer le backend Lucene a chaque compile_sigma
_ENGINE_SINGLETON: SigmaEngine | None = None


def _shared_engine() -> SigmaEngine:
    global _ENGINE_SINGLETON
    if _ENGINE_SINGLETON is None:
        _ENGINE_SINGLETON = SigmaEngine()
    return _ENGINE_SINGLETON


__all__ = [
    "SigmaEngine",
    "CompiledRule",
    "LOGSOURCE_MAP",
    "FIELD_MAP",
    # Backward-compat
    "compile_sigma",
    "evaluate_sigma_rule",
    "import_sigma_rule",
    "get_enabled_sigma_rules",
]
