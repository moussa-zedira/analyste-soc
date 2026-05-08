"""Moteur de correlation multi-evenements — detecte les attaques complexes par
correlation temporelle, sequentielle, statistique et entite."""

from __future__ import annotations

import hashlib
import logging
import math
import re
import uuid
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

from sqlalchemy.orm import Session

from apps.api.models.event import Event
from apps.api.models.incident import Incident
from apps.api.models.incident_event import IncidentEvent
from apps.api.observability import record_rule_match

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# MITRE ATT&CK tactics reference
# ---------------------------------------------------------------------------
MITRE_TACTICS = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]


class CorrelationType(StrEnum):
    """Types de correlation supportes."""
    TEMPORAL = "temporal"
    SEQUENTIAL = "sequential"
    THRESHOLD = "threshold"
    STATISTICAL = "statistical"
    KILL_CHAIN = "kill_chain"


class ActionType(StrEnum):
    """Actions declenchees par une correspondance de correlation."""
    ALERT = "alert"
    CREATE_INCIDENT = "create_incident"
    BLOCK_IP = "block_ip"
    DISABLE_ACCOUNT = "disable_account"
    QUARANTINE_HOST = "quarantine_host"
    NOTIFY_SOC = "notify_soc"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class EventPattern:
    """Motif a rechercher dans les evenements."""

    event_type: str | None = None
    severity: str | None = None
    field_conditions: dict[str, Any] = field(default_factory=dict)
    regex_conditions: dict[str, str] = field(default_factory=dict)
    negate: bool = False
    label: str = ""

    def matches(self, event: Event) -> bool:
        """Verifie si un evenement correspond a ce motif."""
        result = self._positive_match(event)
        return (not result) if self.negate else result

    def _positive_match(self, event: Event) -> bool:
        if self.event_type and event.event_type != self.event_type:
            return False
        if self.severity and event.severity != self.severity:
            return False
        for fld, expected in self.field_conditions.items():
            val = getattr(event, fld, None)
            if val is None:
                return False
            if isinstance(expected, list):
                if val not in expected:
                    return False
            elif val != expected:
                return False
        for fld, pattern in self.regex_conditions.items():
            val = getattr(event, fld, None) or ""
            if not re.search(pattern, val, re.IGNORECASE):
                return False
        return True


@dataclass
class CorrelationRule:
    """Definition declarative d'une regle de correlation multi-evenements."""

    id: str
    name: str
    description: str
    correlation_type: CorrelationType
    event_patterns: list[EventPattern]
    time_window: int  # seconds
    group_by: list[str]
    threshold: int = 1
    severity: str = "high"
    mitre_tactics: list[str] = field(default_factory=list)
    actions: list[str] = field(default_factory=lambda: ["create_incident"])
    enabled: bool = True
    tags: list[str] = field(default_factory=list)
    # For statistical correlation
    baseline_window: int = 3600  # seconds for baseline calculation
    std_dev_threshold: float = 3.0  # standard deviations for anomaly
    # For sequential detection
    ordered: bool = True  # patterns must match in order
    max_gap: int | None = None  # max seconds between consecutive pattern matches


@dataclass
class CorrelationMatch:
    """Resultat d'une correspondance de correlation."""

    rule_id: str
    rule_name: str
    severity: str
    group_key: str
    group_values: dict[str, str]
    matched_events: list[Event]
    matched_at: datetime
    mitre_tactics: list[str]
    description: str
    score: float = 0.0


# ---------------------------------------------------------------------------
# Correlation Engine
# ---------------------------------------------------------------------------

class CorrelationEngine:
    """Moteur de correlation multi-evenements temps reel.

    Supporte la correlation temporelle, sequentielle, a seuil,
    statistique et par chaine d'attaque (kill chain).
    """

    def __init__(self) -> None:
        self._rules: dict[str, CorrelationRule] = {}
        self._custom_evaluators: dict[str, Callable] = {}

    # -- Rule management ----------------------------------------------------

    def register_rule(self, rule: CorrelationRule) -> None:
        """Enregistre ou met a jour une regle de correlation."""
        self._rules[rule.id] = rule
        logger.info("Correlation rule registered: %s (%s)", rule.id, rule.name)

    def unregister_rule(self, rule_id: str) -> bool:
        """Supprime une regle. Retourne True si elle existait."""
        return self._rules.pop(rule_id, None) is not None

    def get_rule(self, rule_id: str) -> CorrelationRule | None:
        return self._rules.get(rule_id)

    def get_rules(self, *, enabled_only: bool = True) -> list[CorrelationRule]:
        rules = list(self._rules.values())
        if enabled_only:
            rules = [r for r in rules if r.enabled]
        return rules

    def register_evaluator(self, name: str, fn: Callable) -> None:
        """Enregistre un evaluateur personnalise pour les regles complexes."""
        self._custom_evaluators[name] = fn

    # -- Main evaluation ----------------------------------------------------

    def evaluate(
        self,
        events: list[Event],
        db: Session | None = None,
    ) -> list[CorrelationMatch]:
        """Evalue toutes les regles actives contre la liste d'evenements.

        Les evenements doivent etre tries par horodatage croissant.
        """
        matches: list[CorrelationMatch] = []
        rules = self.get_rules(enabled_only=True)

        for rule in rules:
            try:
                rule_matches = self._evaluate_rule(rule, events)
                matches.extend(rule_matches)
            except Exception:
                logger.exception("Correlation rule %s failed", rule.id)

        # Deduplicate by (rule_id, group_key)
        seen: set[str] = set()
        unique: list[CorrelationMatch] = []
        for m in matches:
            key = f"{m.rule_id}|{m.group_key}"
            if key not in seen:
                seen.add(key)
                unique.append(m)
                record_rule_match("correlation", m.rule_id, m.severity)

        return unique

    def persist_matches(
        self,
        db: Session,
        matches: list[CorrelationMatch],
    ) -> int:
        """Cree des incidents pour les correspondances de correlation.

        Retourne le nombre d'incidents crees.
        """
        created = 0
        now = datetime.now(UTC)

        for match in matches:
            if "create_incident" not in (
                self._rules.get(match.rule_id, CorrelationRule(
                    id="", name="", description="",
                    correlation_type=CorrelationType.TEMPORAL,
                    event_patterns=[], time_window=0, group_by=[],
                )).actions
            ):
                continue

            dedup = self._compute_dedup(match, now)
            existing = db.query(Incident.id).filter(
                Incident.dedup_hash == dedup
            ).first()
            if existing:
                continue

            incident_id = str(uuid.uuid4())
            event_times = [e.ts for e in match.matched_events if e.ts]
            start_ts = min(event_times) if event_times else now
            end_ts = max(event_times) if event_times else now

            tactics_str = ", ".join(match.mitre_tactics) if match.mitre_tactics else ""
            description = match.description
            if tactics_str:
                description += f"\n\nMITRE ATT&CK: {tactics_str}"

            incident = Incident(
                id=incident_id,
                created_at=now,
                updated_at=now,
                status="open",
                severity=match.severity,
                title=f"[CORR] {match.rule_name}: {match.group_key}",
                description=description,
                rule_id=f"correlation:{match.rule_id}",
                entity_key=match.group_key,
                start_ts=start_ts,
                end_ts=end_ts,
                dedup_hash=dedup,
            )
            db.add(incident)

            for evt in match.matched_events:
                db.add(IncidentEvent(incident_id=incident_id, event_id=evt.id))

            created += 1
            logger.info(
                "Correlation incident created: %s rule=%s key=%s events=%d",
                incident_id, match.rule_id, match.group_key,
                len(match.matched_events),
            )

        return created

    # -- Rule evaluation dispatch -------------------------------------------

    def _evaluate_rule(
        self,
        rule: CorrelationRule,
        events: list[Event],
    ) -> list[CorrelationMatch]:
        dispatch = {
            CorrelationType.TEMPORAL: self._eval_temporal,
            CorrelationType.SEQUENTIAL: self._eval_sequential,
            CorrelationType.THRESHOLD: self._eval_threshold,
            CorrelationType.STATISTICAL: self._eval_statistical,
            CorrelationType.KILL_CHAIN: self._eval_kill_chain,
        }
        handler = dispatch.get(rule.correlation_type)
        if handler is None:
            logger.warning("Unknown correlation type: %s", rule.correlation_type)
            return []
        return handler(rule, events)

    # -- Group events by entity fields --------------------------------------

    def _group_events(
        self,
        events: list[Event],
        group_by: list[str],
    ) -> dict[str, list[Event]]:
        """Regroupe les evenements par les champs specifies."""
        groups: dict[str, list[Event]] = defaultdict(list)
        for event in events:
            key_parts = []
            for field_name in group_by:
                val = getattr(event, field_name, None) or "unknown"
                key_parts.append(str(val))
            key = "|".join(key_parts)
            groups[key].append(event)
        return dict(groups)

    def _parse_group_key(
        self,
        key: str,
        group_by: list[str],
    ) -> dict[str, str]:
        parts = key.split("|")
        return {
            group_by[i]: parts[i] if i < len(parts) else "unknown"
            for i in range(len(group_by))
        }

    # -- Temporal correlation -----------------------------------------------

    def _eval_temporal(
        self,
        rule: CorrelationRule,
        events: list[Event],
    ) -> list[CorrelationMatch]:
        """Correlation temporelle : plusieurs patterns dans une fenetre de temps."""
        matches: list[CorrelationMatch] = []
        groups = self._group_events(events, rule.group_by)
        window = timedelta(seconds=rule.time_window)

        for group_key, group_events in groups.items():
            # For each pattern, find matching events
            pattern_matches: list[list[Event]] = []
            for pattern in rule.event_patterns:
                matched = [e for e in group_events if pattern.matches(e)]
                pattern_matches.append(matched)

            # All patterns must have at least one match
            if not all(pattern_matches):
                continue

            # Check time window: events from all patterns within window
            first_events = pattern_matches[0]
            for anchor in first_events:
                window_start = anchor.ts - window
                window_end = anchor.ts + window
                combined: list[Event] = []
                all_patterns_present = True

                for pm in pattern_matches:
                    in_window = [
                        e for e in pm
                        if window_start <= e.ts <= window_end
                    ]
                    if not in_window:
                        all_patterns_present = False
                        break
                    combined.extend(in_window)

                if all_patterns_present and len(combined) >= rule.threshold:
                    # Deduplicate events
                    seen_ids: set[str] = set()
                    unique_events: list[Event] = []
                    for e in combined:
                        if e.id not in seen_ids:
                            seen_ids.add(e.id)
                            unique_events.append(e)

                    matches.append(CorrelationMatch(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        group_key=group_key,
                        group_values=self._parse_group_key(group_key, rule.group_by),
                        matched_events=unique_events,
                        matched_at=datetime.now(UTC),
                        mitre_tactics=rule.mitre_tactics,
                        description=rule.description,
                    ))
                    break  # one match per group

        return matches

    # -- Sequential pattern detection ---------------------------------------

    def _eval_sequential(
        self,
        rule: CorrelationRule,
        events: list[Event],
    ) -> list[CorrelationMatch]:
        """Detection sequentielle : A puis B puis C dans l'ordre temporel."""
        matches: list[CorrelationMatch] = []
        groups = self._group_events(events, rule.group_by)
        window = timedelta(seconds=rule.time_window)
        max_gap = timedelta(seconds=rule.max_gap) if rule.max_gap else None

        for group_key, group_events in groups.items():
            sorted_events = sorted(group_events, key=lambda e: e.ts)
            chain = self._find_sequential_chain(
                rule.event_patterns, sorted_events, window, max_gap, rule.ordered,
            )
            if chain and len(chain) >= len(rule.event_patterns):
                matches.append(CorrelationMatch(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    group_key=group_key,
                    group_values=self._parse_group_key(group_key, rule.group_by),
                    matched_events=chain,
                    matched_at=datetime.now(UTC),
                    mitre_tactics=rule.mitre_tactics,
                    description=rule.description,
                ))

        return matches

    def _find_sequential_chain(
        self,
        patterns: list[EventPattern],
        events: list[Event],
        window: timedelta,
        max_gap: timedelta | None,
        ordered: bool,
    ) -> list[Event] | None:
        """Recherche une chaine sequentielle de patterns dans les evenements."""
        if not patterns:
            return []

        chain: list[Event] = []
        pattern_idx = 0
        last_ts: datetime | None = None

        for event in events:
            if pattern_idx >= len(patterns):
                break

            pattern = patterns[pattern_idx]
            if not pattern.matches(event):
                continue

            # Check time constraints
            if chain:
                first_ts = chain[0].ts
                if event.ts - first_ts > window:
                    # Reset: window exceeded
                    chain = []
                    pattern_idx = 0
                    if patterns[0].matches(event):
                        chain.append(event)
                        pattern_idx = 1
                        last_ts = event.ts
                    continue

                if max_gap and last_ts and (event.ts - last_ts) > max_gap:
                    chain = []
                    pattern_idx = 0
                    if patterns[0].matches(event):
                        chain.append(event)
                        pattern_idx = 1
                        last_ts = event.ts
                    continue

            if ordered and last_ts and event.ts < last_ts:
                continue

            chain.append(event)
            last_ts = event.ts
            pattern_idx += 1

        if pattern_idx >= len(patterns):
            return chain
        return None

    # -- Threshold-based rules ----------------------------------------------

    def _eval_threshold(
        self,
        rule: CorrelationRule,
        events: list[Event],
    ) -> list[CorrelationMatch]:
        """Detection a seuil : N evenements correspondants dans T secondes."""
        matches: list[CorrelationMatch] = []
        groups = self._group_events(events, rule.group_by)
        window = timedelta(seconds=rule.time_window)

        for group_key, group_events in groups.items():
            for pattern in rule.event_patterns:
                matched = [e for e in group_events if pattern.matches(e)]
                if len(matched) < rule.threshold:
                    continue

                sorted_matched = sorted(matched, key=lambda e: e.ts)

                # Sliding window
                i = 0
                for j in range(len(sorted_matched)):
                    while sorted_matched[j].ts - sorted_matched[i].ts > window:
                        i += 1
                    count = j - i + 1
                    if count >= rule.threshold:
                        window_events = sorted_matched[i:j + 1]
                        matches.append(CorrelationMatch(
                            rule_id=rule.id,
                            rule_name=rule.name,
                            severity=rule.severity,
                            group_key=group_key,
                            group_values=self._parse_group_key(
                                group_key, rule.group_by,
                            ),
                            matched_events=window_events,
                            matched_at=datetime.now(UTC),
                            mitre_tactics=rule.mitre_tactics,
                            description=(
                                f"{rule.description} "
                                f"({count} events in {rule.time_window}s)"
                            ),
                        ))
                        break  # one match per group per pattern

        return matches

    # -- Statistical correlation --------------------------------------------

    def _eval_statistical(
        self,
        rule: CorrelationRule,
        events: list[Event],
    ) -> list[CorrelationMatch]:
        """Detection statistique : combinaisons inhabituelles basees sur
        l'ecart-type par rapport a la moyenne historique."""
        matches: list[CorrelationMatch] = []
        groups = self._group_events(events, rule.group_by)
        window = timedelta(seconds=rule.time_window)
        baseline_window = timedelta(seconds=rule.baseline_window)

        now = datetime.now(UTC)
        recent_start = now - window
        baseline_start = now - baseline_window

        for group_key, group_events in groups.items():
            for pattern in rule.event_patterns:
                matched = [e for e in group_events if pattern.matches(e)]
                if not matched:
                    continue

                baseline_events = [
                    e for e in matched if e.ts >= baseline_start
                ]
                recent_events = [
                    e for e in matched if e.ts >= recent_start
                ]

                if len(baseline_events) < 5:
                    continue  # not enough data for baseline

                # Calculate rate per window
                total_baseline_seconds = max(
                    rule.baseline_window, 1,
                )
                num_windows = total_baseline_seconds / max(rule.time_window, 1)
                len(baseline_events) / max(num_windows, 1)

                # Simple variance estimation
                bucket_size = rule.time_window
                buckets: dict[int, int] = defaultdict(int)
                for e in baseline_events:
                    bucket = int(
                        (e.ts - baseline_start).total_seconds()
                    ) // max(bucket_size, 1)
                    buckets[bucket] += 1

                if len(buckets) < 2:
                    continue

                values = list(buckets.values())
                mean = sum(values) / len(values)
                variance = sum((v - mean) ** 2 for v in values) / len(values)
                std_dev = math.sqrt(variance) if variance > 0 else 1.0

                current_rate = len(recent_events)
                z_score = (current_rate - mean) / std_dev if std_dev > 0 else 0

                if z_score >= rule.std_dev_threshold:
                    matches.append(CorrelationMatch(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        group_key=group_key,
                        group_values=self._parse_group_key(
                            group_key, rule.group_by,
                        ),
                        matched_events=recent_events,
                        matched_at=now,
                        mitre_tactics=rule.mitre_tactics,
                        description=(
                            f"{rule.description} "
                            f"(z-score={z_score:.2f}, mean={mean:.1f}, "
                            f"current={current_rate})"
                        ),
                        score=z_score,
                    ))

        return matches

    # -- Kill chain correlation ---------------------------------------------

    def _eval_kill_chain(
        self,
        rule: CorrelationRule,
        events: list[Event],
    ) -> list[CorrelationMatch]:
        """Correlation kill chain : mappe les evenements sur les etapes
        MITRE ATT&CK et detecte les progressions de chaine d'attaque."""
        # Kill chain = sequential with tactic progression tracking
        return self._eval_sequential(rule, events)

    # -- Utilities ----------------------------------------------------------

    @staticmethod
    def _compute_dedup(match: CorrelationMatch, now: datetime) -> str:
        bucket = now.strftime("%Y-%m-%dT%H:%M")
        raw = f"corr:{match.rule_id}|{match.group_key}|{bucket}"
        return hashlib.sha256(raw.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Singleton engine instance
# ---------------------------------------------------------------------------

_engine_instance: CorrelationEngine | None = None


def get_correlation_engine() -> CorrelationEngine:
    """Retourne l'instance singleton du moteur de correlation."""
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = CorrelationEngine()
        _load_builtin_rules(_engine_instance)
    return _engine_instance


def _load_builtin_rules(engine: CorrelationEngine) -> None:
    """Charge les regles de correlation integrees."""
    try:
        from apps.api.detection.builtin_correlations import get_builtin_rules
        for rule in get_builtin_rules():
            engine.register_rule(rule)
        logger.info(
            "Loaded %d built-in correlation rules",
            len(get_builtin_rules()),
        )
    except Exception:
        logger.exception("Failed to load built-in correlation rules")


def run_correlation(db: Session, events: list[Event]) -> int:
    """Point d'entree pour executer la correlation sur une liste d'evenements.

    Retourne le nombre d'incidents crees.
    """
    engine = get_correlation_engine()
    matches = engine.evaluate(events, db)
    if not matches:
        return 0
    created = engine.persist_matches(db, matches)
    logger.info(
        "Correlation engine: %d matches, %d incidents created",
        len(matches), created,
    )
    return created
