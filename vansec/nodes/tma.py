#!/usr/bin/env python3
"""
vansec/nodes/tma.py — TMA (Traffic Management Agency) verifier node.
Handles Phase 2 of the VANSEC protocol.
"""

from __future__ import annotations

import socket
import time
from typing import Tuple

import config
from vansec.network import channel
from vansec.network.simulator import NetworkSimulator
from vansec.protocol.phases import phase2_tma_verify


class TMA:
    def __init__(
        self,
        host: str = config.TMA_HOST,
        port: int = config.TMA_PORT,
        simulator: NetworkSimulator | None = None,
        quiet: bool = False,
    ):
        self.host = host
        self.port = port
        self.sim = simulator or NetworkSimulator()
        self.quiet = quiet
        self.priv_key = config.TMA_PRIV_KEY
        self.identity = config.TMA_IDENTITY
        self.PK_g = config.PK_G
        # Vehicle public key for signature verification
        # In a real VANET this would be a PKI lookup via sender_id;
        # here we use the pre-shared key from config.
        self.vehicle_pub_key = config.VEHICLE_PUB_KEY

    def start(self) -> None:
        if not self.quiet:
            print(f"\n{'='*72}\n[TMA] Listening on {self.host}:{self.port}\n{'='*72}")
        channel.listen_and_serve(
            handler=self._handle_connection,
            host=self.host, port=self.port,
            quiet=self.quiet,
        )

    def _handle_connection(self, conn: socket.socket, addr: Tuple[str, int]) -> None:
        conn.settimeout(config.SOCKET_TIMEOUT)
        start_wall = time.time()
        try:
            packet = channel.recv_message(conn)
            if not self.quiet:
                print(f"[TMA] Packet from {addr}")

            result = phase2_tma_verify(
                packet=packet,
                tma_priv_key=self.priv_key,
                tma_identity=self.identity,
                PK_g=self.PK_g,
                max_age_sec=config.TIMESTAMP_MAX_AGE_SEC,
                vehicle_pub_key=self.vehicle_pub_key,   # NEW: for sig verification
            )

            if not self.quiet:
                print(f"[TMA] sig={result.signature_ok} s1={result.s1_ok} "
                      f"sigma2={result.sigma2_ok} fresh={result.freshness_ok}  "
                      f"({time.time()-start_wall:.4f}s)")

            if result.all_ok:
                channel.send_message(conn, "Ack: Message delivered and verified")
            else:
                channel.send_message(conn, {
                    "status": "verification_failed",
                    "signature_ok": result.signature_ok,
                    "s1_ok": result.s1_ok,
                    "sigma2_ok": result.sigma2_ok,
                    "freshness_ok": result.freshness_ok,
                    "error": result.error,
                })
        except Exception as e:
            if not self.quiet:
                print(f"[TMA] Error: {e}")
            try:
                channel.send_message(conn, {"status": "error", "detail": str(e)})
            except Exception:
                pass
