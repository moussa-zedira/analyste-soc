"""Evaluateur de regles — detection par fenetre glissante."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime

from apps.api.detection.rules import Rule
from apps.api.models.event import Event


@dataclass(frozen=True, slots=True)
class RuleMatch:
    """Resultat du declenchement d'une regle sur un groupe d'evenements."""

    rule_id: str
    group_key: str
    group_values: dict[str, str]
    event_ids: list[str]
    start_ts: datetime
    end_ts: datetime
    count: int


def evaluate_rule(rule: Rule, events: list[Event]) -> list[RuleMatch]:
    """Evalue une regle sur une liste d'evenements.

    Filtre par event_type, regroupe par les champs group_by de la regle,
    puis applique une fenetre glissante a deux pointeurs par groupe.
    """
    filtered = [e for e in events if e.event_type == rule.event_type]
    if not filtered:
        return []

    groups: dict[str, list[Event]] = defaultdict(list)
    for ev in filtered:
        key_parts: list[str] = []
        skip = False
        for field_name in rule.group_by:
            value = getattr(ev, field_name, None)
            if value is None:
                skip = True
                break
            key_parts.append(f"{field_name}:{value}")
        if skip:
            continue
        groups["|".join(key_parts)].append(ev)

    matches: list[RuleMatch] = []

    for group_key, group_events in groups.items():
        sorted_events = sorted(group_events, key=lambda e: e.ts)
        group_matches = _sliding_window(rule, group_key, sorted_events)
        matches.extend(group_matches)

    return matches


def _sliding_window(rule: Rule, group_key: str, events: list[Event]) -> list[RuleMatch]:
    """Fenetre glissante a deux pointeurs sur les evenements tries pour un groupe."""
    matches: list[RuleMatch] = []
    left = 0

    for right in range(len(events)):
        while events[right].ts - events[left].ts > rule.time_window:
            left += 1

        window_size = right - left + 1
        if window_size < rule.threshold_count:
            continue

        window_events = events[left : right + 1]

        group_values: dict[str, str] = {}
        for field_name in rule.group_by:
            group_values[field_name] = getattr(window_events[0], field_name, "")

        matches.append(
            RuleMatch(
                rule_id=rule.id,
                group_key=group_key,
                group_values=group_values,
                event_ids=[e.id for e in window_events],
                start_ts=window_events[0].ts,
                end_ts=window_events[-1].ts,
                count=window_size,
            )
        )

        left = right + 1

    return matches
