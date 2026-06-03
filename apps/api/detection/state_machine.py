"""Machine a etats finis pour la detection stateful — suit la progression
d'attaque a travers des etats avec transitions temporelles et expiration."""

from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any

from apps.api.models.event import Event

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# State Machine definitions
# ---------------------------------------------------------------------------


class TransitionResult(StrEnum):
    """Resultat d'une tentative de transition."""

    ADVANCED = "advanced"
    COMPLETED = "completed"
    NO_MATCH = "no_match"
    EXPIRED = "expired"


@dataclass
class StateDefinition:
    """Definition d'un etat dans la machine a etats."""

    name: str
    description: str = ""
    is_initial: bool = False
    is_final: bool = False
    timeout: int = 3600  # seconds before auto-expire
    mitre_tactic: str = ""


@dataclass
class TransitionDefinition:
    """Definition d'une transition entre deux etats."""

    from_state: str
    to_state: str
    event_type: str
    conditions: dict[str, Any] = field(default_factory=dict)
    regex_conditions: dict[str, str] = field(default_factory=dict)
    max_delay: int | None = None  # max seconds between events for this transition


@dataclass
class StateMachineDefinition:
    """Definition complete d'une machine a etats de detection."""

    id: str
    name: str
    description: str
    states: list[StateDefinition]
    transitions: list[TransitionDefinition]
    group_by: list[str]
    severity: str = "high"
    mitre_tactics: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    enabled: bool = True


@dataclass
class ActiveState:
    """Instance active d'une machine a etats en cours d'evaluation."""

    instance_id: str
    machine_id: str
    current_state: str
    group_key: str
    group_values: dict[str, str]
    entered_at: float  # timestamp
    last_transition: float  # timestamp
    matched_event_ids: list[str] = field(default_factory=list)
    history: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> ActiveState:
        return cls(**data)


# ---------------------------------------------------------------------------
# Redis-backed state storage
# ---------------------------------------------------------------------------

REDIS_PREFIX = "siem:fsm:"
STATE_TTL = 7200  # 2 hours default


class StateStore:
    """Stockage des etats actifs avec Redis (repli en memoire si indisponible)."""

    def __init__(self) -> None:
        self._memory_store: dict[str, dict[str, ActiveState]] = {}
        self._redis = None
        self._redis_checked = False

    def _get_redis(self):
        if self._redis_checked:
            return self._redis
        self._redis_checked = True
        try:
            from apps.api.cache import get_redis_client

            self._redis = get_redis_client()
        except Exception:
            self._redis = None
        return self._redis

    def get_active_states(self, machine_id: str) -> list[ActiveState]:
        """Recupere tous les etats actifs pour une machine donnee."""
        r = self._get_redis()
        if r is not None:
            return self._redis_get_states(r, machine_id)
        return list(self._memory_store.get(machine_id, {}).values())

    def get_state(self, machine_id: str, group_key: str) -> ActiveState | None:
        """Recupere un etat actif specifique."""
        r = self._get_redis()
        if r is not None:
            return self._redis_get_state(r, machine_id, group_key)
        return self._memory_store.get(machine_id, {}).get(group_key)

    def save_state(self, state: ActiveState, ttl: int = STATE_TTL) -> None:
        """Persiste un etat actif."""
        r = self._get_redis()
        if r is not None:
            self._redis_save_state(r, state, ttl)
        else:
            if state.machine_id not in self._memory_store:
                self._memory_store[state.machine_id] = {}
            self._memory_store[state.machine_id][state.group_key] = state

    def remove_state(self, machine_id: str, group_key: str) -> None:
        """Supprime un etat actif."""
        r = self._get_redis()
        if r is not None:
            self._redis_remove_state(r, machine_id, group_key)
        else:
            if machine_id in self._memory_store:
                self._memory_store[machine_id].pop(group_key, None)

    def get_all_active(self) -> list[ActiveState]:
        """Recupere tous les etats actifs de toutes les machines."""
        r = self._get_redis()
        if r is not None:
            return self._redis_get_all(r)
        result = []
        for states in self._memory_store.values():
            result.extend(states.values())
        return result

    def cleanup_expired(
        self,
        machines: dict[str, StateMachineDefinition],
    ) -> int:
        """Supprime les etats expires. Retourne le nombre supprime."""
        now = time.time()
        removed = 0
        all_states = self.get_all_active()

        for state in all_states:
            machine = machines.get(state.machine_id)
            if machine is None:
                self.remove_state(state.machine_id, state.group_key)
                removed += 1
                continue

            state_def = None
            for s in machine.states:
                if s.name == state.current_state:
                    state_def = s
                    break

            timeout = state_def.timeout if state_def else STATE_TTL
            if now - state.last_transition > timeout:
                self.remove_state(state.machine_id, state.group_key)
                removed += 1

        return removed

    # -- Redis helpers ------------------------------------------------------

    def _redis_key(self, machine_id: str, group_key: str) -> str:
        return f"{REDIS_PREFIX}{machine_id}:{group_key}"

    def _redis_index_key(self, machine_id: str) -> str:
        return f"{REDIS_PREFIX}index:{machine_id}"

    def _redis_save_state(self, r, state: ActiveState, ttl: int) -> None:
        try:
            key = self._redis_key(state.machine_id, state.group_key)
            r.setex(key, ttl, json.dumps(state.to_dict(), default=str))
            r.sadd(self._redis_index_key(state.machine_id), state.group_key)
            r.expire(self._redis_index_key(state.machine_id), ttl)
        except Exception:
            logger.debug("Redis save state failed, using memory")
            if state.machine_id not in self._memory_store:
                self._memory_store[state.machine_id] = {}
            self._memory_store[state.machine_id][state.group_key] = state

    def _redis_get_state(self, r, machine_id: str, group_key: str) -> ActiveState | None:
        try:
            key = self._redis_key(machine_id, group_key)
            raw = r.get(key)
            if raw:
                return ActiveState.from_dict(json.loads(raw))
        except Exception:
            logger.debug("Redis get state failed")
        return self._memory_store.get(machine_id, {}).get(group_key)

    def _redis_get_states(self, r, machine_id: str) -> list[ActiveState]:
        try:
            index_key = self._redis_index_key(machine_id)
            members = r.smembers(index_key)
            states = []
            for group_key in members:
                state = self._redis_get_state(r, machine_id, group_key)
                if state:
                    states.append(state)
            return states
        except Exception:
            return list(self._memory_store.get(machine_id, {}).values())

    def _redis_remove_state(self, r, machine_id: str, group_key: str) -> None:
        try:
            r.delete(self._redis_key(machine_id, group_key))
            r.srem(self._redis_index_key(machine_id), group_key)
        except Exception:
            logger.debug("state_machine: ignored exception", exc_info=True)
        if machine_id in self._memory_store:
            self._memory_store[machine_id].pop(group_key, None)

    def _redis_get_all(self, r) -> list[ActiveState]:
        try:
            keys = r.keys(f"{REDIS_PREFIX}index:*")
            states = []
            for idx_key in keys:
                machine_id = idx_key.replace(f"{REDIS_PREFIX}index:", "")
                states.extend(self._redis_get_states(r, machine_id))
            return states
        except Exception:
            result = []
            for vals in self._memory_store.values():
                result.extend(vals.values())
            return result


# ---------------------------------------------------------------------------
# State Machine Engine
# ---------------------------------------------------------------------------


class StateMachineEngine:
    """Moteur de machines a etats pour la detection stateful.

    Suit la progression d'attaque a travers des etats avec transitions
    basees sur les evenements, timeouts et expiration automatique.
    """

    def __init__(self, store: StateStore | None = None) -> None:
        self._machines: dict[str, StateMachineDefinition] = {}
        self._store = store or StateStore()

    def register_machine(self, machine: StateMachineDefinition) -> None:
        self._machines[machine.id] = machine
        logger.info("State machine registered: %s", machine.id)

    def unregister_machine(self, machine_id: str) -> bool:
        return self._machines.pop(machine_id, None) is not None

    def get_machines(self, *, enabled_only: bool = True) -> list[StateMachineDefinition]:
        machines = list(self._machines.values())
        if enabled_only:
            machines = [m for m in machines if m.enabled]
        return machines

    def get_active_states(self) -> list[ActiveState]:
        return self._store.get_all_active()

    def get_machine_states(self, machine_id: str) -> list[ActiveState]:
        return self._store.get_active_states(machine_id)

    def process_event(self, event: Event) -> list[dict]:
        """Traite un evenement a travers toutes les machines actives.

        Retourne une liste de completions (machines ayant atteint l'etat final).
        """
        completions: list[dict] = []
        now = time.time()

        for machine in self.get_machines(enabled_only=True):
            group_key = self._build_group_key(machine, event)
            if group_key is None:
                continue

            state = self._store.get_state(machine.id, group_key)

            if state is None:
                # Try to start a new state machine instance
                result = self._try_initial_transition(machine, event, group_key, now)
                if result:
                    self._store.save_state(result)
            else:
                # Try to advance existing state
                transition_result, new_state = self._try_advance(
                    machine,
                    state,
                    event,
                    now,
                )
                if transition_result == TransitionResult.COMPLETED:
                    completions.append(
                        {
                            "machine_id": machine.id,
                            "machine_name": machine.name,
                            "severity": machine.severity,
                            "group_key": group_key,
                            "group_values": state.group_values,
                            "event_ids": state.matched_event_ids,
                            "mitre_tactics": machine.mitre_tactics,
                            "history": state.history,
                        }
                    )
                    self._store.remove_state(machine.id, group_key)
                elif transition_result == TransitionResult.ADVANCED:
                    if new_state:
                        self._store.save_state(new_state)
                elif transition_result == TransitionResult.EXPIRED:
                    self._store.remove_state(machine.id, group_key)

        return completions

    def process_events(self, events: list[Event]) -> list[dict]:
        """Traite une liste d'evenements (tries par horodatage)."""
        all_completions: list[dict] = []
        for event in events:
            completions = self.process_event(event)
            all_completions.extend(completions)
        return all_completions

    def cleanup(self) -> int:
        """Supprime les etats expires."""
        return self._store.cleanup_expired(self._machines)

    # -- Internal -----------------------------------------------------------

    def _build_group_key(
        self,
        machine: StateMachineDefinition,
        event: Event,
    ) -> str | None:
        parts = []
        for field_name in machine.group_by:
            val = getattr(event, field_name, None)
            if val is None:
                return None
            parts.append(str(val))
        return "|".join(parts)

    def _parse_group_key(
        self,
        machine: StateMachineDefinition,
        key: str,
    ) -> dict[str, str]:
        parts = key.split("|")
        return {
            machine.group_by[i]: parts[i] if i < len(parts) else "unknown"
            for i in range(len(machine.group_by))
        }

    def _try_initial_transition(
        self,
        machine: StateMachineDefinition,
        event: Event,
        group_key: str,
        now: float,
    ) -> ActiveState | None:
        """Tente de demarrer une nouvelle instance de machine a etats."""
        initial_states = [s for s in machine.states if s.is_initial]
        if not initial_states:
            return None

        initial = initial_states[0]

        for transition in machine.transitions:
            if transition.from_state != initial.name:
                continue
            if not self._event_matches_transition(event, transition):
                continue

            state = ActiveState(
                instance_id=str(uuid.uuid4()),
                machine_id=machine.id,
                current_state=transition.to_state,
                group_key=group_key,
                group_values=self._parse_group_key(machine, group_key),
                entered_at=now,
                last_transition=now,
                matched_event_ids=[event.id],
                history=[
                    {
                        "from": initial.name,
                        "to": transition.to_state,
                        "event_type": event.event_type,
                        "event_id": event.id,
                        "timestamp": now,
                    }
                ],
            )
            return state

        return None

    def _try_advance(
        self,
        machine: StateMachineDefinition,
        state: ActiveState,
        event: Event,
        now: float,
    ) -> tuple[TransitionResult, ActiveState | None]:
        """Tente de faire progresser un etat actif."""
        # Check if current state has expired
        current_state_def = None
        for s in machine.states:
            if s.name == state.current_state:
                current_state_def = s
                break

        if current_state_def:
            timeout = current_state_def.timeout
            if now - state.last_transition > timeout:
                return TransitionResult.EXPIRED, None

        for transition in machine.transitions:
            if transition.from_state != state.current_state:
                continue
            if not self._event_matches_transition(event, transition):
                continue
            if transition.max_delay is not None:
                if now - state.last_transition > transition.max_delay:
                    continue

            # Advance
            state.current_state = transition.to_state
            state.last_transition = now
            state.matched_event_ids.append(event.id)
            state.history.append(
                {
                    "from": transition.from_state,
                    "to": transition.to_state,
                    "event_type": event.event_type,
                    "event_id": event.id,
                    "timestamp": now,
                }
            )

            # Check if final state
            for s in machine.states:
                if s.name == transition.to_state and s.is_final:
                    return TransitionResult.COMPLETED, state

            return TransitionResult.ADVANCED, state

        return TransitionResult.NO_MATCH, None

    @staticmethod
    def _event_matches_transition(
        event: Event,
        transition: TransitionDefinition,
    ) -> bool:
        """Verifie si un evenement correspond aux conditions de transition."""
        if transition.event_type and event.event_type != transition.event_type:
            return False

        import re as re_mod

        for fld, expected in transition.conditions.items():
            val = getattr(event, fld, None)
            if val is None or val != expected:
                return False

        for fld, pattern in transition.regex_conditions.items():
            val = getattr(event, fld, None) or ""
            if not re_mod.search(pattern, val, re_mod.IGNORECASE):
                return False

        return True


# ---------------------------------------------------------------------------
# Built-in state machines
# ---------------------------------------------------------------------------


def get_builtin_machines() -> list[StateMachineDefinition]:
    """Retourne les machines a etats integrees."""
    return [
        # Full kill chain tracker
        StateMachineDefinition(
            id="fsm-killchain",
            name="Kill Chain Progression Tracker",
            description=(
                "Tracks attacker progression through the cyber kill chain "
                "from reconnaissance to impact."
            ),
            states=[
                StateDefinition(
                    name="idle",
                    is_initial=True,
                    timeout=0,
                    description="Waiting for initial reconnaissance",
                ),
                StateDefinition(
                    name="recon",
                    timeout=7200,
                    mitre_tactic="reconnaissance",
                    description="Reconnaissance activity detected",
                ),
                StateDefinition(
                    name="weaponize",
                    timeout=3600,
                    mitre_tactic="resource-development",
                    description="Weaponization indicators found",
                ),
                StateDefinition(
                    name="deliver",
                    timeout=3600,
                    mitre_tactic="initial-access",
                    description="Delivery mechanism used",
                ),
                StateDefinition(
                    name="exploit",
                    timeout=1800,
                    mitre_tactic="execution",
                    description="Exploitation occurred",
                ),
                StateDefinition(
                    name="install",
                    timeout=3600,
                    mitre_tactic="persistence",
                    description="Persistence installed",
                ),
                StateDefinition(
                    name="c2",
                    timeout=3600,
                    mitre_tactic="command-and-control",
                    description="C2 channel established",
                ),
                StateDefinition(
                    name="actions",
                    timeout=3600,
                    is_final=True,
                    mitre_tactic="exfiltration",
                    description="Actions on objectives detected",
                ),
            ],
            transitions=[
                TransitionDefinition("idle", "recon", "conn.attempt"),
                TransitionDefinition("idle", "recon", "dns.query"),
                TransitionDefinition("recon", "deliver", "email.phishing_click"),
                TransitionDefinition("recon", "deliver", "web.attack"),
                TransitionDefinition("recon", "exploit", "exploit.attempt"),
                TransitionDefinition("deliver", "exploit", "exploit.attempt"),
                TransitionDefinition("deliver", "exploit", "file.download"),
                TransitionDefinition("exploit", "install", "file.modify"),
                TransitionDefinition("exploit", "install", "process.exec"),
                TransitionDefinition("install", "c2", "conn.outbound"),
                TransitionDefinition("c2", "actions", "data.exfiltration"),
                TransitionDefinition("c2", "actions", "data.transfer"),
                TransitionDefinition("c2", "actions", "file.archive"),
            ],
            group_by=["src_ip"],
            severity="critical",
            mitre_tactics=[
                "reconnaissance",
                "initial-access",
                "execution",
                "persistence",
                "command-and-control",
                "exfiltration",
            ],
            tags=["kill-chain", "apt", "full-attack"],
        ),
        # Account takeover state machine
        StateMachineDefinition(
            id="fsm-account-takeover",
            name="Account Takeover Progression",
            description="Tracks account takeover from enumeration to abuse.",
            states=[
                StateDefinition(
                    name="idle",
                    is_initial=True,
                    timeout=0,
                ),
                StateDefinition(
                    name="enum",
                    timeout=1800,
                    description="Account enumeration detected",
                ),
                StateDefinition(
                    name="brute",
                    timeout=600,
                    description="Brute force in progress",
                ),
                StateDefinition(
                    name="compromised",
                    timeout=3600,
                    description="Account compromised",
                ),
                StateDefinition(
                    name="abuse",
                    timeout=3600,
                    is_final=True,
                    description="Account being abused",
                ),
            ],
            transitions=[
                TransitionDefinition("idle", "enum", "auth.enum"),
                TransitionDefinition("idle", "brute", "auth.fail"),
                TransitionDefinition("enum", "brute", "auth.fail"),
                TransitionDefinition("brute", "brute", "auth.fail"),
                TransitionDefinition("brute", "compromised", "auth.success"),
                TransitionDefinition("compromised", "abuse", "priv.escalation"),
                TransitionDefinition("compromised", "abuse", "data.access"),
                TransitionDefinition("compromised", "abuse", "lateral.movement"),
            ],
            group_by=["src_ip"],
            severity="critical",
            mitre_tactics=[
                "credential-access",
                "initial-access",
                "privilege-escalation",
            ],
            tags=["account-takeover", "credential-attack"],
        ),
        # Ransomware progression
        StateMachineDefinition(
            id="fsm-ransomware",
            name="Ransomware Attack Progression",
            description="Tracks ransomware from initial access to encryption.",
            states=[
                StateDefinition(name="idle", is_initial=True, timeout=0),
                StateDefinition(name="access", timeout=3600),
                StateDefinition(name="discovery", timeout=1800),
                StateDefinition(name="lateral", timeout=3600),
                StateDefinition(name="staging", timeout=1800),
                StateDefinition(name="encryption", timeout=600, is_final=True),
            ],
            transitions=[
                TransitionDefinition("idle", "access", "exploit.attempt"),
                TransitionDefinition("idle", "access", "auth.success"),
                TransitionDefinition(
                    "access",
                    "discovery",
                    "process.exec",
                    regex_conditions={"message": r"(net\s|whoami|ipconfig|systeminfo)"},
                ),
                TransitionDefinition("discovery", "lateral", "lateral.movement"),
                TransitionDefinition("discovery", "lateral", "conn.rdp"),
                TransitionDefinition("lateral", "staging", "file.archive"),
                TransitionDefinition("lateral", "staging", "data.transfer"),
                TransitionDefinition(
                    "staging",
                    "encryption",
                    "file.modify",
                    regex_conditions={"message": r"\.(encrypted|locked|crypt)"},
                ),
            ],
            group_by=["src_ip"],
            severity="critical",
            mitre_tactics=[
                "initial-access",
                "discovery",
                "lateral-movement",
                "collection",
                "impact",
            ],
            tags=["ransomware", "encryption", "full-attack"],
        ),
    ]


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_engine_instance: StateMachineEngine | None = None


def get_state_machine_engine() -> StateMachineEngine:
    """Retourne l'instance singleton du moteur de machines a etats."""
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = StateMachineEngine()
        for machine in get_builtin_machines():
            _engine_instance.register_machine(machine)
        logger.info(
            "State machine engine initialized with %d machines",
            len(get_builtin_machines()),
        )
    return _engine_instance
