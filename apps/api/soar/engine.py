"""SOAR Playbook Engine — execute des playbooks YAML avec steps sequentiels/paralleles,
conditions, interpolation de variables, rollback et audit trail complet."""

from __future__ import annotations

import asyncio
import logging
import re
import time
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from apps.api.models.soar import Playbook, PlaybookExecution, PlaybookStepResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Variable interpolation
# ---------------------------------------------------------------------------

_VAR_RE = re.compile(r"\{\{\s*([a-zA-Z0-9_.\[\]]+)\s*\}\}")


def _resolve_var(path: str, variables: dict[str, Any]) -> Any:
    """Resolve a dotted variable path like 'steps.lookup.result.score'."""
    parts = path.replace("[", ".").replace("]", "").split(".")
    current: Any = variables
    for part in parts:
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, (list, tuple)):
            try:
                current = current[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            return None
        if current is None:
            return None
    return current


def interpolate(value: Any, variables: dict[str, Any]) -> Any:
    """Recursively interpolate {{ var }} placeholders in a value."""
    if isinstance(value, str):
        # If the entire string is one variable reference, return the raw value
        m = _VAR_RE.fullmatch(value)
        if m:
            return _resolve_var(m.group(1), variables)
        # Otherwise do string substitution
        def _replacer(match: re.Match) -> str:
            resolved = _resolve_var(match.group(1), variables)
            return str(resolved) if resolved is not None else match.group(0)
        return _VAR_RE.sub(_replacer, value)
    if isinstance(value, dict):
        return {k: interpolate(v, variables) for k, v in value.items()}
    if isinstance(value, list):
        return [interpolate(item, variables) for item in value]
    return value


# ---------------------------------------------------------------------------
# Condition evaluation
# ---------------------------------------------------------------------------

_OP_MAP = {
    "eq": lambda a, b: a == b,
    "ne": lambda a, b: a != b,
    "gt": lambda a, b: float(a) > float(b),
    "gte": lambda a, b: float(a) >= float(b),
    "lt": lambda a, b: float(a) < float(b),
    "lte": lambda a, b: float(a) <= float(b),
    "contains": lambda a, b: b in str(a),
    "not_contains": lambda a, b: b not in str(a),
    "in": lambda a, b: a in b,
    "not_in": lambda a, b: a not in b,
    "exists": lambda a, _: a is not None,
    "not_exists": lambda a, _: a is None,
    "matches": lambda a, b: bool(re.search(b, str(a))),
    "starts_with": lambda a, b: str(a).startswith(str(b)),
    "ends_with": lambda a, b: str(a).endswith(str(b)),
}


def evaluate_condition(condition: dict, variables: dict[str, Any]) -> bool:
    """Evaluate a condition dict: {field, operator, value} or {all/any: [...]}."""
    if "all" in condition:
        return all(evaluate_condition(c, variables) for c in condition["all"])
    if "any" in condition:
        return any(evaluate_condition(c, variables) for c in condition["any"])

    field = condition.get("field", "")
    operator = condition.get("operator", "eq")
    expected = interpolate(condition.get("value"), variables)

    actual = _resolve_var(field, variables)
    op_fn = _OP_MAP.get(operator)
    if op_fn is None:
        logger.warning("Unknown condition operator: %s", operator)
        return False
    try:
        return op_fn(actual, expected)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Playbook validation
# ---------------------------------------------------------------------------

VALID_TRIGGER_TYPES = {
    "manual", "on_incident", "on_alert", "on_threshold", "scheduled", "webhook",
}


def validate_playbook_definition(definition: dict) -> list[str]:
    """Return a list of validation errors (empty = valid)."""
    errors: list[str] = []
    if "steps" not in definition:
        errors.append("Playbook must have a 'steps' key")
        return errors
    steps = definition["steps"]
    if not isinstance(steps, list) or len(steps) == 0:
        errors.append("'steps' must be a non-empty list")
        return errors
    seen_names: set[str] = set()
    for i, step in enumerate(steps):
        name = step.get("name", "")
        if not name:
            errors.append(f"Step {i} missing 'name'")
        elif name in seen_names:
            errors.append(f"Duplicate step name: {name}")
        seen_names.add(name)
        if "action" not in step and "parallel" not in step:
            errors.append(f"Step '{name}' must have 'action' or 'parallel'")
    return errors


# ---------------------------------------------------------------------------
# Playbook Engine
# ---------------------------------------------------------------------------

class PlaybookEngine:
    """Execute un playbook step-by-step avec audit trail."""

    def __init__(self, db: Session, dry_run: bool = False):
        self.db = db
        self.dry_run = dry_run
        self._cancelled = False

    # -- public API ---------------------------------------------------------

    async def execute(
        self,
        playbook: Playbook,
        input_data: dict[str, Any] | None = None,
        trigger: str = "manual",
        created_by: str = "system",
        incident_id: str | None = None,
    ) -> PlaybookExecution:
        """Run a full playbook and return the execution record."""
        now = datetime.now(UTC)
        execution = PlaybookExecution(
            id=str(uuid.uuid4()),
            playbook_id=playbook.id,
            playbook_name=playbook.name,
            status="running",
            trigger=trigger,
            input_data=input_data or {},
            variables={},
            dry_run=self.dry_run,
            started_at=now,
            created_at=now,
            created_by=created_by,
            incident_id=incident_id,
        )
        self.db.add(execution)
        self.db.commit()

        # Publish status to Redis
        _publish_status(execution.id, "running")

        variables: dict[str, Any] = {
            "input": input_data or {},
            "playbook": {"id": playbook.id, "name": playbook.name},
            "execution": {"id": execution.id},
            "steps": {},
        }

        definition = playbook.definition
        steps = definition.get("steps", [])
        rollback_stack: list[dict] = []
        t0 = time.monotonic()

        try:
            for idx, step_def in enumerate(steps):
                if self._cancelled:
                    execution.status = "cancelled"
                    break

                if "parallel" in step_def:
                    results = await self._execute_parallel(
                        execution.id, idx, step_def, variables,
                    )
                    for name, res in results.items():
                        variables["steps"][name] = res
                else:
                    result = await self._execute_step(
                        execution.id, idx, step_def, variables,
                    )
                    step_name = step_def.get("name", f"step_{idx}")
                    variables["steps"][step_name] = result

                    if step_def.get("rollback"):
                        rollback_stack.append(step_def["rollback"])

                    # Stop on failure unless continue_on_error
                    if (
                        isinstance(result, dict)
                        and result.get("status") == "error"
                        and not step_def.get("continue_on_error", False)
                    ):
                        execution.status = "failed"
                        execution.error = result.get("error", "Step failed")
                        # Rollback
                        if rollback_stack and definition.get("rollback_on_failure", True):
                            await self._run_rollback(
                                execution.id, rollback_stack, variables,
                            )
                        break
            else:
                if execution.status == "running":
                    execution.status = "completed"

        except Exception as exc:
            execution.status = "failed"
            execution.error = str(exc)
            logger.exception("Playbook execution %s failed", execution.id)
            if rollback_stack and definition.get("rollback_on_failure", True):
                await self._run_rollback(execution.id, rollback_stack, variables)

        elapsed = (time.monotonic() - t0) * 1000
        execution.duration_ms = round(elapsed, 2)
        execution.finished_at = datetime.now(UTC)
        execution.variables = _safe_json(variables)
        execution.result = {
            "steps_executed": len(variables.get("steps", {})),
            "status": execution.status,
        }
        self.db.commit()

        _publish_status(execution.id, execution.status)
        return execution

    def cancel(self) -> None:
        self._cancelled = True

    # -- step execution -----------------------------------------------------

    async def _execute_step(
        self,
        execution_id: str,
        idx: int,
        step_def: dict,
        variables: dict[str, Any],
    ) -> dict[str, Any]:
        """Execute a single step and record the result."""
        from apps.api.soar.actions import get_action

        step_name = step_def.get("name", f"step_{idx}")
        action_name = step_def.get("action", "")
        params = interpolate(step_def.get("params", {}), variables)
        timeout_s = step_def.get("timeout", 300)

        # Condition check
        condition = step_def.get("condition")
        if condition and not evaluate_condition(condition, variables):
            step_result = PlaybookStepResult(
                id=str(uuid.uuid4()),
                execution_id=execution_id,
                step_name=step_name,
                step_index=idx,
                action=action_name,
                status="skipped",
                skipped=True,
                skip_reason="Condition not met",
                started_at=datetime.now(UTC),
                finished_at=datetime.now(UTC),
                duration_ms=0,
            )
            self.db.add(step_result)
            self.db.commit()
            return {"status": "skipped", "reason": "Condition not met"}

        t0 = time.monotonic()
        now = datetime.now(UTC)

        step_record = PlaybookStepResult(
            id=str(uuid.uuid4()),
            execution_id=execution_id,
            step_name=step_name,
            step_index=idx,
            action=action_name,
            status="running",
            input_params=_safe_json(params),
            started_at=now,
        )
        self.db.add(step_record)
        self.db.commit()

        if self.dry_run:
            output = {"status": "dry_run", "action": action_name, "params": params}
            step_record.status = "dry_run"
            step_record.output = output
            step_record.finished_at = datetime.now(UTC)
            step_record.duration_ms = round((time.monotonic() - t0) * 1000, 2)
            self.db.commit()
            return output

        action_fn = get_action(action_name)
        if action_fn is None:
            output = {"status": "error", "error": f"Unknown action: {action_name}"}
            step_record.status = "error"
            step_record.error = output["error"]
            step_record.finished_at = datetime.now(UTC)
            step_record.duration_ms = round((time.monotonic() - t0) * 1000, 2)
            self.db.commit()
            return output

        try:
            if asyncio.iscoroutinefunction(action_fn):
                output = await asyncio.wait_for(
                    action_fn(params, variables, self.db),
                    timeout=timeout_s,
                )
            else:
                output = await asyncio.wait_for(
                    asyncio.to_thread(action_fn, params, variables, self.db),
                    timeout=timeout_s,
                )
            if not isinstance(output, dict):
                output = {"result": output}
            output.setdefault("status", "success")
            step_record.status = "success"
            step_record.output = _safe_json(output)
        except TimeoutError:
            output = {"status": "error", "error": f"Timeout after {timeout_s}s"}
            step_record.status = "timeout"
            step_record.error = output["error"]
        except Exception as exc:
            output = {"status": "error", "error": str(exc)}
            step_record.status = "error"
            step_record.error = str(exc)
            logger.exception("Step %s failed", step_name)

        step_record.finished_at = datetime.now(UTC)
        step_record.duration_ms = round((time.monotonic() - t0) * 1000, 2)
        self.db.commit()
        return output

    async def _execute_parallel(
        self,
        execution_id: str,
        base_idx: int,
        step_def: dict,
        variables: dict[str, Any],
    ) -> dict[str, dict]:
        """Execute multiple steps in parallel."""
        parallel_steps = step_def.get("parallel", [])
        tasks = []
        for i, sub_step in enumerate(parallel_steps):
            tasks.append(
                self._execute_step(execution_id, base_idx * 100 + i, sub_step, variables)
            )
        results_list = await asyncio.gather(*tasks, return_exceptions=True)
        merged: dict[str, dict] = {}
        for sub_step, result in zip(parallel_steps, results_list, strict=False):
            name = sub_step.get("name", f"parallel_{base_idx}_{id(sub_step)}")
            if isinstance(result, Exception):
                merged[name] = {"status": "error", "error": str(result)}
            else:
                merged[name] = result
        return merged

    async def _run_rollback(
        self,
        execution_id: str,
        rollback_stack: list[dict],
        variables: dict[str, Any],
    ) -> None:
        """Execute rollback steps in reverse order."""
        logger.info("Running rollback for execution %s (%d steps)", execution_id, len(rollback_stack))
        for i, rb_def in enumerate(reversed(rollback_stack)):
            rb_step = {
                "name": f"rollback_{i}",
                "action": rb_def.get("action", ""),
                "params": rb_def.get("params", {}),
                "continue_on_error": True,
            }
            await self._execute_step(execution_id, 9000 + i, rb_step, variables)


# ---------------------------------------------------------------------------
# Trigger matching
# ---------------------------------------------------------------------------

def match_triggers(
    db: Session,
    trigger_type: str,
    context: dict[str, Any],
) -> list[Playbook]:
    """Return enabled playbooks whose trigger matches the given context."""
    playbooks = (
        db.query(Playbook)
        .filter(Playbook.enabled.is_(True), Playbook.trigger_type == trigger_type)
        .all()
    )
    matched: list[Playbook] = []
    for pb in playbooks:
        cfg = pb.trigger_config or {}
        if trigger_type == "on_incident":
            severity_filter = cfg.get("severity")
            if severity_filter and context.get("severity") not in severity_filter:
                continue
        elif trigger_type == "on_alert":
            rule_filter = cfg.get("rule_ids")
            if rule_filter and context.get("rule_id") not in rule_filter:
                continue
        elif trigger_type == "on_threshold":
            metric = cfg.get("metric")
            threshold = cfg.get("threshold", 0)
            if context.get("metric") != metric:
                continue
            if context.get("value", 0) < threshold:
                continue
        matched.append(pb)
    return matched


async def fire_triggers(
    db: Session,
    trigger_type: str,
    context: dict[str, Any],
) -> list[PlaybookExecution]:
    """Find and execute all matching playbooks for a trigger event."""
    playbooks = match_triggers(db, trigger_type, context)
    executions: list[PlaybookExecution] = []
    for pb in playbooks:
        engine = PlaybookEngine(db)
        execution = await engine.execute(
            pb,
            input_data=context,
            trigger=trigger_type,
        )
        executions.append(execution)
    return executions


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_json(obj: Any) -> Any:
    """Make an object JSON-safe for storage."""
    if isinstance(obj, dict):
        return {k: _safe_json(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_safe_json(item) for item in obj]
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    return str(obj)


def _publish_status(execution_id: str, status: str) -> None:
    """Publish execution status to Redis for real-time updates."""
    try:
        from apps.api.cache import get_redis_client
        r = get_redis_client()
        if r is not None:
            import json
            r.publish(
                "soar:executions",
                json.dumps({"execution_id": execution_id, "status": status}),
            )
            r.set(
                f"soar:execution:{execution_id}:status",
                status,
                ex=3600,
            )
    except Exception:
        logger.debug("engine: ignored exception", exc_info=True)
