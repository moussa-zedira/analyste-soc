"""Event broadcaster — Redis pub/sub with in-memory fallback."""

from __future__ import annotations

import asyncio
import json
import logging
import threading

from apps.api.cache import get_redis_client

logger = logging.getLogger(__name__)

CHANNEL = "siem:live"


class Broadcaster:
    """Pub/sub broadcaster. Uses Redis if available, else in-memory queues."""

    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue[str]] = set()
        self._redis_listener_started = False

    def subscribe(self) -> asyncio.Queue[str]:
        queue: asyncio.Queue[str] = asyncio.Queue(maxsize=100)
        self._subscribers.add(queue)
        self._start_redis_listener()
        return queue

    def unsubscribe(self, queue: asyncio.Queue[str]) -> None:
        self._subscribers.discard(queue)

    def publish(self, message: dict) -> None:
        """Publish a message. Tries Redis first, falls back to local dispatch."""
        data = json.dumps(message)
        r = get_redis_client()
        if r is not None:
            try:
                r.publish(CHANNEL, data)
                return
            except Exception:
                logger.debug("Redis publish failed, using local dispatch")
        self._dispatch_local(data)

    def _dispatch_local(self, data: str) -> None:
        """Dispatch a message to all local subscribers."""
        for queue in self._subscribers.copy():
            try:
                queue.put_nowait(data)
            except asyncio.QueueFull:
                logger.warning("Dropping message for slow WebSocket client")

    def _start_redis_listener(self) -> None:
        """Start a background thread listening on Redis pub/sub."""
        if self._redis_listener_started:
            return
        r = get_redis_client()
        if r is None:
            return
        self._redis_listener_started = True
        thread = threading.Thread(target=self._redis_listen, daemon=True)
        thread.start()

    def _redis_listen(self) -> None:
        """Subscribe to Redis channel and forward messages to local queues."""
        try:
            r = get_redis_client()
            if r is None:
                return
            pubsub = r.pubsub()
            pubsub.subscribe(CHANNEL)
            for message in pubsub.listen():
                if message["type"] == "message":
                    self._dispatch_local(message["data"])
        except Exception:
            logger.exception("Redis listener crashed")
            self._redis_listener_started = False


broadcaster = Broadcaster()
