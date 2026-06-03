"""Point de terminaison WebSocket pour le streaming d'evenements en temps reel."""

from __future__ import annotations

import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from apps.api.broadcast import broadcaster

logger = logging.getLogger(__name__)

router = APIRouter()


@router.websocket("/ws/live")
async def websocket_live(ws: WebSocket) -> None:
    """Diffuser les evenements et incidents en temps reel aux clients connectes."""
    await ws.accept()
    queue = broadcaster.subscribe()
    try:
        while True:
            data = await queue.get()
            await ws.send_text(data)
    except WebSocketDisconnect:
        logger.info("WebSocket client disconnected")
    except Exception:
        logger.exception("WebSocket error")
    finally:
        broadcaster.unsubscribe(queue)
