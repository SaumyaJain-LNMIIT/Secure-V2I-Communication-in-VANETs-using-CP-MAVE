#!/usr/bin/env python3
"""
vansec/nodes/vehicle.py — Vehicle (OBU) node.
Orchestrates: Phase 1 (authenticate with ECA), Phase 2 (send message to TMA).
"""

from __future__ import annotations

import time
from typing import Dict, Any, Optional

from ecdsa import curves

import config
from vansec.crypto.primitives import Hash
from vansec.network import channel
from vansec.network.simulator import NetworkSimulator
from vansec.protocol.phases import (
    rand_scalar,
    phase1_vehicle_init,
    phase1_vehicle_respond,
    phase1_vehicle_verify_token,
    phase2_vehicle_build_packet,
)

_q = curves.NIST256p.order


class Vehicle:
    def __init__(
        self,
        vehicle_id: int = config.VEHICLE_IDENTITY,
        priv_key: int = config.VEHICLE_PRIV_KEY,
        simulator: NetworkSimulator | None = None,
    ):
        self.identity = vehicle_id
        self.priv_key = priv_key
        self.sim = simulator

        self.eca_pub_key = config.ECA_PUB_KEY
        self.tma_pub_key = config.TMA_PUB_KEY
        self.tma_identity = config.TMA_IDENTITY
        self.PK_g = config.PK_G
        self.ECA_C_i = config.ECA_C_I
        self.ECA_Y_i = config.ECA_Y_I

    def _send(self, sock, msg, sender: str, receiver: str) -> None:
        if self.sim is not None:
            channel.attach_simulator(self.sim, sender=sender, receiver=receiver)
        try:
            channel.send_message(sock, msg)
        finally:
            if self.sim is not None:
                channel.detach_simulator()

    def run_protocol(
        self,
        eca_host: str = config.ECA_HOST,
        eca_port: int = config.ECA_PORT,
        tma_host: str = config.TMA_HOST,
        tma_port: int = config.TMA_PORT,
        msg_to_send: Optional[int] = None,
    ) -> Dict[str, Any]:
        if msg_to_send is None:
            msg_to_send = rand_scalar()

        result: Dict[str, Any] = {
            "phase1_time": None, "phase2_time": None, "status": "OK",
        }

        # ── Phase 1: authenticate with ECA ──────────────────────────
        try:
            p1_start = time.perf_counter()
            sock_eca = channel.connect(eca_host, eca_port)
            try:
                identity_msg = phase1_vehicle_init(self.identity, self.tma_identity)
                self._send(sock_eca, identity_msg, "Vehicle", "ECA")
                challenge = channel.recv_message(sock_eca)
                response, r1, A = phase1_vehicle_respond(
                    challenge, self.priv_key, self.eca_pub_key
                )
                self._send(sock_eca, response, "Vehicle", "ECA")
                auth_token = channel.recv_message(sock_eca)
            finally:
                sock_eca.close()

            I_p = Hash(self.tma_identity, auth_token.start_time,
                       response.expiry_period) % _q
            token_ok = phase1_vehicle_verify_token(
                token=auth_token, I_p=I_p, PK_g=self.PK_g,
                ECA_C_i=self.ECA_C_i, ECA_Y_i=self.ECA_Y_i,
                B=auth_token.B_point, eca_pub_key=self.eca_pub_key,
            )
            p1_end = time.perf_counter()
            result["phase1_time"] = p1_end - p1_start

            if not token_ok:
                result["status"] = "VERIFY_FAIL_PHASE1"
                print("[VEHICLE] sigma_t verification FAILED")
                return result
            print(f"[VEHICLE] Phase 1 OK ({result['phase1_time']:.4f}s)")

        except ConnectionError as e:
            result["status"] = f"PACKET_LOSS_PHASE1: {e}"
            print(f"[VEHICLE] Phase 1 packet lost: {e}")
            return result
        except Exception as e:
            result["status"] = f"ERROR_PHASE1: {e}"
            print(f"[VEHICLE] Phase 1 error: {e}")
            return result

        # ── Phase 2: send signed message to TMA ─────────────────────
        try:
            p2_start = time.perf_counter()
            packet = phase2_vehicle_build_packet(
                sigma_t=auth_token.sigma_t, r1=r1, I_p=I_p,
                B=auth_token.B_point, A=A,
                start_time=auth_token.start_time,
                expiry_period=response.expiry_period,
                iv=challenge.iv, msg_to_send=msg_to_send,
                tma_pub_key=self.tma_pub_key, PK_g=self.PK_g,
                ECA_C_i=self.ECA_C_i, ECA_Y_i=self.ECA_Y_i,
                ECA_pub_key=self.eca_pub_key,
                vehicle_id=self.identity,          # NEW: bind sender identity
                vehicle_priv_key=self.priv_key,    # NEW: sign the packet
            )
            sock_tma = channel.connect(tma_host, tma_port)
            try:
                self._send(sock_tma, packet, "Vehicle", "TMA")
                tma_reply = channel.recv_message(sock_tma)
            finally:
                sock_tma.close()

            p2_end = time.perf_counter()
            result["phase2_time"] = p2_end - p2_start
            print(f"[VEHICLE] Phase 2 OK ({result['phase2_time']:.4f}s)")
            print(f"[VEHICLE] TMA reply: {tma_reply}")

        except ConnectionError as e:
            result["status"] = f"PACKET_LOSS_PHASE2: {e}"
            print(f"[VEHICLE] Phase 2 packet lost: {e}")
        except Exception as e:
            result["status"] = f"ERROR_PHASE2: {e}"
            print(f"[VEHICLE] Phase 2 error: {e}")

        return result
