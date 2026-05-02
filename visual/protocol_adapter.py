#!/usr/bin/env python3
"""
visual/protocol_adapter.py — Bridge between real VANSEC protocol and visual events.

Calls the **real** phase1_*/phase2_* functions from vansec.protocol.phases
and translates results into VisualEvent timelines.
"""

from __future__ import annotations

import copy
import os
import time
from typing import List

from ecdsa import curves

import config
from vansec.crypto.primitives import Hash, generate_timestamp, _point_x, _point_y
from vansec.crypto.keys import generate_keypair
from vansec.protocol.phases import (
    rand_scalar,
    phase1_vehicle_init,
    phase1_eca_challenge,
    phase1_vehicle_respond,
    phase1_eca_verify_and_sign,
    phase1_vehicle_verify_token,
    phase2_vehicle_build_packet,
    phase2_tma_verify,
)

from visual.constants import (
    PACKET_VALID, PACKET_MALICIOUS, PACKET_AUTH, PACKET_TOKEN,
    SUCCESS_COLOR, FAIL_COLOR, WARNING_COLOR,
    ECA_X, TMA_X, SCENE_W,
)
from visual.events import (
    VisualEvent, ev_status, ev_log, ev_vehicle_move, ev_packet,
    ev_auth_ok, ev_auth_fail, ev_token, ev_banner, ev_metric,
    ev_attacker_appear, ev_attacker_hide, ev_dos_burst, ev_wait,
    ev_scene_reset,
)

_q = curves.NIST256p.order
_G = curves.NIST256p.generator


class ProtocolAdapter:
    """
    Runs real VANSEC protocol functions and produces VisualEvent timelines.
    """

    # ── Internal: full legitimate protocol (no sockets) ─────────────
    @staticmethod
    def _run_legit():
        """Mirrors experiments/attacks.py _run_legitimate_protocol()."""
        identity_msg = phase1_vehicle_init(config.VEHICLE_IDENTITY,
                                           config.TMA_IDENTITY)
        challenge, nonce_plain = phase1_eca_challenge(
            identity_msg, config.ECA_PRIV_KEY,
            config.VEHICLE_PUB_KEY, config.TMA_PUB_KEY,
        )
        response, r1, A = phase1_vehicle_respond(
            challenge, config.VEHICLE_PRIV_KEY, config.ECA_PUB_KEY,
        )
        auth_token = phase1_eca_verify_and_sign(
            response, nonce_plain, challenge.eca_key_point, challenge.iv,
            identity_msg.sender_id, identity_msg.receiver_id,
            config.ECA_SIGMA, config.ECA_PRIV_KEY, config.ECA_PUB_KEY,
        )
        I_p = Hash(config.TMA_IDENTITY, auth_token.start_time,
                    response.expiry_period) % _q
        msg = rand_scalar()
        packet = phase2_vehicle_build_packet(
            auth_token.sigma_t, r1, I_p, auth_token.B_point, A,
            auth_token.start_time, response.expiry_period, challenge.iv,
            msg, config.TMA_PUB_KEY, config.PK_G,
            config.ECA_C_I, config.ECA_Y_I, config.ECA_PUB_KEY,
            vehicle_id=config.VEHICLE_IDENTITY,
            vehicle_priv_key=config.VEHICLE_PRIV_KEY,
        )
        return packet, auth_token, I_p, response.expiry_period

    @staticmethod
    def _verify(packet, max_age=5.0):
        return phase2_tma_verify(
            packet, config.TMA_PRIV_KEY, config.TMA_IDENTITY, config.PK_G,
            max_age_sec=max_age,
            vehicle_pub_key=config.VEHICLE_PUB_KEY,
        )

    # ================================================================
    # Normal mode
    # ================================================================
    def build_normal_events(self) -> List[VisualEvent]:
        """Legitimate vehicle authenticates and sends a secure message."""
        packet, auth_token, I_p, _ = self._run_legit()
        result = self._verify(packet)
        latency = 0.0  # we don't have sockets, so approximate
        events: List[VisualEvent] = []

        # -- Phase 1: Vehicle → ECA authentication --
        events.append(ev_status("Phase 1 — Vehicle Authentication"))
        events.append(ev_log("Vehicle initiating authentication with ECA…"))
        events.append(ev_vehicle_move(ECA_X - 40, delay=200))
        events.append(ev_wait(800))

        events.append(ev_log("Sending identity + nonce request"))
        events.append(ev_packet("Vehicle", "ECA", PACKET_AUTH,
                                "Identity Request", delay=300))
        events.append(ev_wait(1000))

        events.append(ev_log("ECA: nonce challenge (AES-128-CBC encrypted)"))
        events.append(ev_packet("ECA", "Vehicle", PACKET_AUTH,
                                "Nonce Challenge", delay=200))
        events.append(ev_wait(800))

        events.append(ev_log("Vehicle: decrypting nonce, incrementing, responding"))
        events.append(ev_packet("Vehicle", "ECA", PACKET_AUTH,
                                "Nonce Response", delay=200))
        events.append(ev_wait(800))

        events.append(ev_log("ECA: verifying nonce → issuing auth token (σ_t)"))
        events.append(ev_token("ECA", "Vehicle", delay=200))
        events.append(ev_auth_ok("Vehicle", delay=800))
        events.append(ev_banner("✓ PHASE 1 COMPLETE — TOKEN RECEIVED",
                                SUCCESS_COLOR, delay=200, duration=2000))
        events.append(ev_wait(1200))

        # -- Phase 2: Vehicle → TMA secure message --
        events.append(ev_status("Phase 2 — Secure Message Delivery"))
        events.append(ev_log("Vehicle building Phase 2 packet (ECDSA signed)"))
        events.append(ev_vehicle_move(TMA_X - 40, delay=200))
        events.append(ev_wait(1000))

        events.append(ev_log("Sending encrypted message + signature to TMA"))
        events.append(ev_packet("Vehicle", "TMA", PACKET_VALID,
                                "Encrypted Msg", delay=300))
        events.append(ev_wait(1000))

        if result.all_ok:
            events.append(ev_log("TMA: ECDSA ✓ | s1 ✓ | σ2 ✓ | Freshness ✓"))
            events.append(ev_auth_ok("TMA", delay=200))
            events.append(ev_banner("✓ MESSAGE ACCEPTED — ALL CHECKS PASSED",
                                    SUCCESS_COLOR, delay=300, duration=2500))
            events.append(ev_metric("accepted", 1, delay=100))
        else:
            events.append(ev_log(f"TMA: verification failed — {result.error}"))
            events.append(ev_auth_fail("TMA", "Verification Failed", delay=200))
            events.append(ev_banner("✗ VERIFICATION FAILED", FAIL_COLOR,
                                    delay=300, duration=2500))
            events.append(ev_metric("rejected", 1, delay=100))

        events.append(ev_wait(800))
        return events

    # ================================================================
    # Replay Attack
    # ================================================================
    def build_replay_events(self) -> List[VisualEvent]:
        packet, *_ = self._run_legit()
        replayed = copy.deepcopy(packet)
        replayed.timestamp = int((time.time() - 60) * 1000)
        result = phase2_tma_verify(
            replayed, config.TMA_PRIV_KEY, config.TMA_IDENTITY, config.PK_G,
            max_age_sec=5.0, vehicle_pub_key=None,
        )
        detected = not result.freshness_ok

        events: List[VisualEvent] = []
        events.append(ev_status("Attack Mode — Replay Attack"))
        events.append(ev_log("Legitimate vehicle completes authentication…"))
        events.append(ev_vehicle_move(ECA_X - 40, delay=200))
        events.append(ev_wait(600))
        events.append(ev_packet("Vehicle", "ECA", PACKET_AUTH,
                                "Auth Request", delay=200))
        events.append(ev_wait(600))
        events.append(ev_token("ECA", "Vehicle", delay=200))
        events.append(ev_auth_ok("Vehicle", delay=600))
        events.append(ev_wait(600))

        events.append(ev_vehicle_move(TMA_X - 40, delay=200))
        events.append(ev_wait(600))
        events.append(ev_packet("Vehicle", "TMA", PACKET_VALID,
                                "Encrypted Msg", delay=200))
        events.append(ev_auth_ok("TMA", delay=800))
        events.append(ev_metric("accepted", 1, delay=100))
        events.append(ev_wait(800))

        # -- Attacker replays the old packet --
        events.append(ev_attacker_appear(delay=200))
        events.append(ev_log("⚠ Attacker captured the packet…"))
        events.append(ev_wait(800))
        events.append(ev_log("Attacker replaying stale packet (60 s old)"))
        events.append(ev_packet("Attacker", "TMA", PACKET_MALICIOUS,
                                "Replayed Packet", delay=300))
        events.append(ev_wait(1000))

        if detected:
            events.append(ev_log("TMA: timestamp stale → REPLAY DETECTED"))
            events.append(ev_auth_fail("TMA", "STALE", delay=200))
            events.append(ev_banner("⚠ REPLAY DETECTED\nTimestamp exceeds 5 s window",
                                    FAIL_COLOR, delay=300, duration=2500))
            events.append(ev_metric("rejected", 1, delay=100))
            events.append(ev_metric("attacks", 1, delay=50))
        else:
            events.append(ev_log("TMA: replay NOT detected (unexpected)"))
            events.append(ev_auth_ok("TMA", delay=200))

        events.append(ev_wait(600))
        events.append(ev_attacker_hide(delay=200))
        return events

    # ================================================================
    # Tamper Attack
    # ================================================================
    def build_tamper_events(self) -> List[VisualEvent]:
        packet, *_ = self._run_legit()
        tampered = copy.deepcopy(packet)
        enc = bytearray(tampered.enc_msg)
        if enc:
            enc[0] ^= 0xFF
        tampered.enc_msg = bytes(enc)
        result = self._verify(tampered, max_age=30.0)
        detected = not result.signature_ok

        events: List[VisualEvent] = []
        events.append(ev_status("Attack Mode — Tamper Attack"))
        events.append(ev_log("Legitimate vehicle sends encrypted message…"))
        events.append(ev_vehicle_move(TMA_X - 40, delay=200))
        events.append(ev_wait(600))
        events.append(ev_packet("Vehicle", "TMA", PACKET_VALID,
                                "Encrypted Msg", delay=200))
        events.append(ev_wait(400))

        events.append(ev_attacker_appear(delay=200))
        events.append(ev_log("⚠ Attacker intercepts and modifies ciphertext"))
        events.append(ev_wait(800))
        events.append(ev_packet("Attacker", "TMA", PACKET_MALICIOUS,
                                "Tampered Packet", delay=300))
        events.append(ev_wait(1000))

        if detected:
            events.append(ev_log("TMA: ECDSA signature INVALID → TAMPER DETECTED"))
            events.append(ev_auth_fail("TMA", "SIG FAIL", delay=200))
            events.append(ev_banner("⚠ SIGNATURE FAILED\nCiphertext integrity violated",
                                    FAIL_COLOR, delay=300, duration=2500))
            events.append(ev_metric("rejected", 1, delay=100))
            events.append(ev_metric("attacks", 1, delay=50))
        else:
            events.append(ev_log("TMA: tamper NOT detected (unexpected)"))

        events.append(ev_wait(600))
        events.append(ev_attacker_hide(delay=200))
        return events

    # ================================================================
    # Impersonation Attack
    # ================================================================
    def build_impersonation_events(self) -> List[VisualEvent]:
        packet, *_ = self._run_legit()
        forged = copy.deepcopy(packet)
        forged.sender_id = config.VEHICLE_IDENTITY + 1
        result = self._verify(forged, max_age=30.0)
        detected = not result.signature_ok

        events: List[VisualEvent] = []
        events.append(ev_status("Attack Mode — Impersonation Attack"))
        events.append(ev_attacker_appear(delay=200))
        events.append(ev_log("Attacker forging sender identity…"))
        events.append(ev_wait(800))
        events.append(ev_log("Sending packet with spoofed Vehicle ID"))
        events.append(ev_packet("Attacker", "TMA", PACKET_MALICIOUS,
                                "Forged Identity", delay=300))
        events.append(ev_wait(1000))

        if detected:
            events.append(ev_log("TMA: sender_id ≠ signed identity → IMPERSONATION DETECTED"))
            events.append(ev_auth_fail("TMA", "IDENTITY", delay=200))
            events.append(ev_banner("⚠ AUTHENTICATION FAILED\nSender identity mismatch",
                                    FAIL_COLOR, delay=300, duration=2500))
            events.append(ev_metric("rejected", 1, delay=100))
            events.append(ev_metric("attacks", 1, delay=50))
        else:
            events.append(ev_log("TMA: impersonation NOT detected (unexpected)"))

        events.append(ev_wait(600))
        events.append(ev_attacker_hide(delay=200))
        return events

    # ================================================================
    # DoS Flood Attack
    # ================================================================
    def build_dos_events(self, flood_count: int = 12) -> List[VisualEvent]:
        # Pre-compute: build legitimate + flood packets using real functions
        legit_packet, *_ = self._run_legit()
        legit_result = self._verify(legit_packet)

        rejected = 0
        for _ in range(flood_count):
            forged, *_ = self._run_legit()
            forged.vehicle_sig = os.urandom(64)
            r = self._verify(forged, max_age=30.0)
            if not r.all_ok:
                rejected += 1

        post_packet, *_ = self._run_legit()
        post_result = self._verify(post_packet)

        events: List[VisualEvent] = []
        events.append(ev_status("Attack Mode — DoS Flood Attack"))
        events.append(ev_log("Baseline: legitimate packet accepted"))
        events.append(ev_vehicle_move(TMA_X - 40, delay=200))
        events.append(ev_wait(600))
        events.append(ev_packet("Vehicle", "TMA", PACKET_VALID,
                                "Legit Packet", delay=200))
        events.append(ev_auth_ok("TMA", delay=800))
        events.append(ev_metric("accepted", 1, delay=100))
        events.append(ev_wait(600))

        # Flood
        events.append(ev_attacker_appear(delay=200))
        events.append(ev_log(f"⚠ Attacker flooding TMA with {flood_count} forged packets…"))
        events.append(ev_wait(600))
        events.append(ev_dos_burst(flood_count, delay=200))
        events.append(ev_wait(2500))  # let the burst animation play

        events.append(ev_log(f"TMA rejected {rejected}/{flood_count} flood packets"))
        events.append(ev_metric("rejected", rejected, delay=100))
        events.append(ev_metric("attacks", flood_count, delay=50))
        events.append(ev_banner(f"⚠ DoS FLOOD: {rejected}/{flood_count} REJECTED\nTMA remains operational",
                                WARNING_COLOR if rejected == flood_count else FAIL_COLOR,
                                delay=300, duration=2500))
        events.append(ev_wait(800))

        # Post-flood
        events.append(ev_log("Post-flood: testing legitimate packet…"))
        events.append(ev_packet("Vehicle", "TMA", PACKET_VALID,
                                "Post-Flood Msg", delay=300))
        events.append(ev_wait(1000))
        if post_result.all_ok:
            events.append(ev_log("TMA: post-flood verification ✓ — system survived"))
            events.append(ev_auth_ok("TMA", delay=200))
            events.append(ev_banner("✓ SYSTEM SURVIVED DoS FLOOD",
                                    SUCCESS_COLOR, delay=300, duration=2500))
            events.append(ev_metric("accepted", 1, delay=100))
        else:
            events.append(ev_log("TMA: post-flood FAILED (unexpected)"))

        events.append(ev_wait(600))
        events.append(ev_attacker_hide(delay=200))
        return events
