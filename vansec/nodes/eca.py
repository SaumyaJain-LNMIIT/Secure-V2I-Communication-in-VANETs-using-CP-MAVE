#!/usr/bin/env python3
"""
vansec/nodes/eca.py — ECA (Enterprise Certificate Authority) server node.
Handles Phase 1 of the VANSEC protocol.
"""

from __future__ import annotations

import socket
import time
from typing import Tuple

import config
from vansec.network import channel
from vansec.network.simulator import NetworkSimulator
from vansec.protocol.phases import (
    phase1_eca_challenge,
    phase1_eca_verify_and_sign,
)


class ECA:
    def __init__(
        self,
        host: str = config.ECA_HOST,
        port: int = config.ECA_PORT,
        simulator: NetworkSimulator | None = None,
        quiet: bool = False,
    ):
        self.host = host
        self.port = port
        self.sim = simulator or NetworkSimulator()
        self.quiet = quiet
        self.priv_key = config.ECA_PRIV_KEY
        self.pub_key = config.ECA_PUB_KEY
        self.sigma = config.ECA_SIGMA
        self.vehicle_pub_key = config.VEHICLE_PUB_KEY
        self.tma_pub_key = config.TMA_PUB_KEY

    def start(self) -> None:
        if not self.quiet:
            print(f"\n{'='*72}\n[ECA] Listening on {self.host}:{self.port}\n{'='*72}")
        channel.listen_and_serve(
            handler=self._handle_connection,
            host=self.host, port=self.port,
            quiet=self.quiet,
        )

    def _handle_connection(self, conn: socket.socket, addr: Tuple[str, int]) -> None:
        start_wall = time.time()
        conn.settimeout(config.SOCKET_TIMEOUT)
        try:
            identity_msg = channel.recv_message(conn)
            if not self.quiet:
                print(f"[ECA] Vehicle session from {addr}")

            challenge, nonce_plain = phase1_eca_challenge(
                identity_msg=identity_msg,
                eca_priv_key=self.priv_key,
                vehicle_pub_key=self.vehicle_pub_key,
                tma_pub_key=self.tma_pub_key,
            )
            channel.send_message(conn, challenge)

            response = channel.recv_message(conn)

            auth_token = phase1_eca_verify_and_sign(
                response=response,
                nonce_plaintext=nonce_plain,
                eca_key_point=challenge.eca_key_point,
                iv=challenge.iv,
                sender_id=identity_msg.sender_id,
                receiver_id=identity_msg.receiver_id,
                eca_sigma=self.sigma,
                eca_priv_key=self.priv_key,
                eca_pub_key=self.pub_key,
            )
            channel.send_message(conn, auth_token)
            if not self.quiet:
                print(f"[ECA] Session done in {time.time()-start_wall:.4f}s")

        except ValueError as ve:
            if not self.quiet:
                print(f"[ECA] Auth FAILED: {ve}")
            try: channel.send_message(conn, {"error": str(ve)})
            except Exception: pass
        except Exception as e:
            if not self.quiet:
                print(f"[ECA] Error: {e}")
            try: channel.send_message(conn, {"error": str(e)})
            except Exception: pass
