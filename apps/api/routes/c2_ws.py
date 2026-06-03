"""WebSocket Operator Console (V4.4).

Deux endpoints :
 - ``/ws/redteam/c2/events`` : stream global des events (new/dead session,
   new beacon, etc.).
 - ``/ws/redteam/c2/sessions/{id}/terminal`` : terminal interactif sur
   une session Sliver, avec engagement guard avant chaque exec.

Le client passe son JWT access via le query param ``?token=...`` car les
WebSockets ne portent pas naturellement les cookies cross-origin/path.
On reutilise le meme JWT que celui pose dans le cookie ``cd_access`` —
c'est la route Next ``/api/auth/ws-token`` qui l'expose au navigateur.
"""

from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect, status
from jose import JWTError

from apps.api.auth import decode_token
from apps.api.db.session import SessionLocal
from apps.api.models.user import User
from apps.api.pentest.c2_sliver import client as sliver_client
from apps.api.pentest.c2_sliver.events import (
    EVENT_COMMAND_RESULT,
    publish_event,
    redteam_broadcaster,
)

logger = logging.getLogger("apps.api.pentest.c2_sliver.ws")

router = APIRouter(prefix="/ws/redteam/c2", tags=["Red Team WebSocket"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _auth_ws(ws: WebSocket, token: str) -> str | None:
    """Decode JWT et retourne user_id, sinon ferme la WS et retourne None."""
    if not token:
        await ws.close(code=status.WS_1008_POLICY_VIOLATION, reason="missing token")
        return None
    try:
        payload = decode_token(token)
    except JWTError:
        await ws.close(code=status.WS_1008_POLICY_VIOLATION, reason="invalid token")
        return None
    except Exception:
        logger.exception("ws_auth_unexpected_error")
        await ws.close(code=status.WS_1011_INTERNAL_ERROR)
        return None
    if payload.get("type") != "access":
        await ws.close(code=status.WS_1008_POLICY_VIOLATION, reason="wrong token type")
        return None
    user_id = payload.get("sub")
    if not user_id:
        await ws.close(code=status.WS_1008_POLICY_VIOLATION, reason="no sub")
        return None

    # Verifie que le user existe et est actif
    db = SessionLocal()
    try:
        user = db.get(User, user_id)
        if user is None or not user.is_active:
            await ws.close(code=status.WS_1008_POLICY_VIOLATION, reason="user inactive")
            return None
    finally:
        db.close()
    return user_id


async def _heartbeat(ws: WebSocket, interval: int = 30) -> None:
    """Envoie ``{type: 'ping'}`` toutes les N secondes pour garder la WS active."""
    try:
        while True:
            await asyncio.sleep(interval)
            try:
                await ws.send_json({"type": "ping"})
            except Exception:
                return
    except asyncio.CancelledError:
        return


# ---------------------------------------------------------------------------
# /ws/redteam/c2/events — stream global
# ---------------------------------------------------------------------------


@router.websocket("/events")
async def ws_events(ws: WebSocket, token: str = Query(default="")) -> None:
    """Stream tous les events C2 au client (new beacon, dead session, etc.)."""
    await ws.accept()
    user_id = await _auth_ws(ws, token)
    if user_id is None:
        return

    queue = redteam_broadcaster.subscribe()
    hb_task = asyncio.create_task(_heartbeat(ws))
    try:
        await ws.send_json({"type": "ready"})
        while True:
            data = await queue.get()
            try:
                await ws.send_text(data)
            except Exception:
                break
    except WebSocketDisconnect:
        pass
    except Exception:
        logger.exception("ws_events_error")
    finally:
        hb_task.cancel()
        redteam_broadcaster.unsubscribe(queue)


# ---------------------------------------------------------------------------
# /ws/redteam/c2/sessions/{id}/terminal — terminal interactif
# ---------------------------------------------------------------------------


@router.websocket("/sessions/{session_id}/terminal")
async def ws_terminal(
    ws: WebSocket,
    session_id: str,
    token: str = Query(default=""),
    engagement_id: str = Query(default=""),
) -> None:
    """Terminal interactif sur une session Sliver.

    Protocole client -> serveur :  ``{"command": "whoami", "timeout": 30}``
    Protocole serveur -> client :
      - ``{"type":"ready", "session_id":"..."}``
      - ``{"type":"exec_start", "command":"..."}``
      - ``{"type":"exec_result", "command":"...", "output":"...", "status":"done"}``
      - ``{"type":"exec_error", "command":"...", "detail":"..."}``
      - ``{"type":"error", "detail":"...", "code":...}``
      - ``{"type":"ping"}``
    """
    await ws.accept()
    user_id = await _auth_ws(ws, token)
    if user_id is None:
        return

    if not engagement_id:
        await ws.send_json({"type": "error", "code": 400, "detail": "engagement_id required"})
        await ws.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    # Engagement guard : refus immediat si l'engagement n'autorise pas
    db = SessionLocal()
    try:
        try:
            from apps.api.pentest.engagement.guard import assert_engagement_allows

            await assert_engagement_allows(db, engagement_id, target=session_id)
        except ImportError:
            pass  # V4.3b absent -> on accepte
        except Exception as e:
            detail = getattr(e, "detail", str(e))
            code = getattr(e, "status_code", 403)
            await ws.send_json({"type": "error", "code": code, "detail": detail})
            await ws.close(code=status.WS_1008_POLICY_VIOLATION)
            return
    finally:
        db.close()

    hb_task = asyncio.create_task(_heartbeat(ws))
    try:
        await ws.send_json({"type": "ready", "session_id": session_id})
        while True:
            try:
                msg = await ws.receive_json()
            except WebSocketDisconnect:
                break
            except Exception:
                # message malforme — on demande au client de reessayer
                try:
                    await ws.send_json({"type": "exec_error", "detail": "invalid message"})
                except Exception:
                    break
                continue

            if not isinstance(msg, dict):
                continue
            cmd = (msg.get("command") or "").strip()
            if not cmd:
                continue
            timeout = int(msg.get("timeout") or 30)
            if timeout < 1:
                timeout = 30
            if timeout > 600:
                timeout = 600

            # Re-check guard a chaque commande (kill switch peut se declencher
            # en cours de session)
            db = SessionLocal()
            try:
                try:
                    from apps.api.pentest.engagement.guard import (
                        assert_engagement_allows,
                    )

                    await assert_engagement_allows(db, engagement_id, target=session_id)
                except ImportError:
                    pass
                except Exception as e:
                    detail = getattr(e, "detail", str(e))
                    code = getattr(e, "status_code", 403)
                    await ws.send_json(
                        {"type": "exec_error", "command": cmd, "detail": detail, "code": code}
                    )
                    continue
            finally:
                db.close()

            await ws.send_json({"type": "exec_start", "command": cmd})
            try:
                result = await sliver_client.execute_command(session_id, cmd, timeout=timeout)
            except RuntimeError as e:
                await ws.send_json(
                    {
                        "type": "exec_error",
                        "command": cmd,
                        "detail": f"Sliver unavailable: {e}",
                        "code": 503,
                    }
                )
                continue
            except Exception as e:  # noqa: BLE001
                logger.exception("ws_terminal_exec_failed")
                await ws.send_json(
                    {"type": "exec_error", "command": cmd, "detail": str(e), "code": 502}
                )
                continue

            output = (result.get("stdout") or "") + (
                ("\n" + result.get("stderr", "")) if result.get("stderr") else ""
            )
            payload = {
                "type": "exec_result",
                "command": cmd,
                "output": output,
                "status": "done",
                "exit_status": result.get("status"),
                "duration_ms": result.get("duration_ms"),
            }
            try:
                await ws.send_json(payload)
            except Exception:
                break

            # Publish sur le broadcaster pour les autres clients connectes
            try:
                publish_event(
                    EVENT_COMMAND_RESULT,
                    {
                        "session_id": session_id,
                        "engagement_id": engagement_id,
                        "command": cmd,
                        "exit_status": result.get("status"),
                        "user_id": user_id,
                    },
                )
            except Exception:
                logger.debug("c2_ws: ignored exception", exc_info=True)
    except WebSocketDisconnect:
        pass
    except Exception:
        logger.exception("ws_terminal_loop_error")
    finally:
        hb_task.cancel()


__all__ = ["router"]
