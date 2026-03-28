"""Serveur syslog asyncio — recoit les logs UDP/TCP et les envoie a l'API."""

from __future__ import annotations

import asyncio
import logging
import time
from collections import deque

from apps.collectors.config import (
    BATCH_SIZE,
    FLUSH_INTERVAL,
    SYSLOG_TCP_PORT,
    SYSLOG_UDP_PORT,
)
from apps.collectors.normalizer import NormalizedEvent, init_parsers, parse_line
from apps.collectors.api_client import send_batch

logger = logging.getLogger(__name__)

_queue: deque[NormalizedEvent] = deque()


class SyslogUDPProtocol(asyncio.DatagramProtocol):
    """Protocole UDP pour la reception de messages syslog."""

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            line = data.decode("utf-8", errors="replace").strip()
            if line:
                event = parse_line(line)
                if event:
                    _queue.append(event)
                    logger.debug("UDP event queued from %s", addr[0])
        except Exception:
            logger.exception("Error processing UDP datagram")


class SyslogTCPHandler:
    """Handler TCP pour les connexions syslog persistantes."""

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        addr = writer.get_extra_info("peername")
        logger.info("TCP connection from %s", addr)
        try:
            while True:
                data = await reader.readline()
                if not data:
                    break
                line = data.decode("utf-8", errors="replace").strip()
                if line:
                    event = parse_line(line)
                    if event:
                        _queue.append(event)
        except asyncio.CancelledError:
            pass
        except Exception:
            logger.exception("Error handling TCP connection from %s", addr)
        finally:
            writer.close()


async def _flush_loop() -> None:
    """Boucle de flush periodique — envoie les events en batch a l'API."""
    while True:
        await asyncio.sleep(FLUSH_INTERVAL)
        if not _queue:
            continue

        batch: list[NormalizedEvent] = []
        while _queue and len(batch) < BATCH_SIZE:
            batch.append(_queue.popleft())

        if batch:
            count = send_batch(batch)
            logger.info("Flushed %d/%d events to API", count, len(batch))


async def run_server() -> None:
    """Demarre le serveur syslog UDP + TCP + flush loop."""
    init_parsers()
    logger.info("Parsers initialized")

    loop = asyncio.get_event_loop()

    # UDP server
    transport, _ = await loop.create_datagram_endpoint(
        SyslogUDPProtocol,
        local_addr=("0.0.0.0", SYSLOG_UDP_PORT),
    )
    logger.info("Syslog UDP listening on :%d", SYSLOG_UDP_PORT)

    # TCP server
    tcp_handler = SyslogTCPHandler()
    tcp_server = await asyncio.start_server(
        tcp_handler.handle,
        "0.0.0.0",
        SYSLOG_TCP_PORT,
    )
    logger.info("Syslog TCP listening on :%d", SYSLOG_TCP_PORT)

    # Flush loop
    flush_task = asyncio.create_task(_flush_loop())

    try:
        await asyncio.gather(
            tcp_server.serve_forever(),
            flush_task,
        )
    finally:
        transport.close()
        tcp_server.close()


def main() -> None:
    """Point d'entree du serveur syslog."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    logger.info("Starting syslog receiver...")
    asyncio.run(run_server())


if __name__ == "__main__":
    main()
