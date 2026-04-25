#!/usr/bin/env python3
"""
experiments/attacks.py — Simulated attack scenarios for VANSEC.
Demonstrates detection of: replay, tamper, and impersonation attacks.
"""

from __future__ import annotations

import os
import sys
import time
import copy
from typing import Dict, List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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

_q = curves.NIST256p.order
_G = curves.NIST256p.generator

__all__ = ["run_all_attacks"]


def _print_banner(title: str) -> None:
    print(f"\n{'='*72}\n  [ATTACK] {title}\n{'='*72}")


def _run_legitimate_protocol():
    """Full legitimate protocol run (no sockets). Returns all intermediate state."""
    identity_msg = phase1_vehicle_init(config.VEHICLE_IDENTITY, config.TMA_IDENTITY)
    challenge, nonce_plain = phase1_eca_challenge(
        identity_msg, config.ECA_PRIV_KEY, config.VEHICLE_PUB_KEY, config.TMA_PUB_KEY,
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


def _verify(packet, max_age=5.0):
    return phase2_tma_verify(
        packet, config.TMA_PRIV_KEY, config.TMA_IDENTITY, config.PK_G,
        max_age_sec=max_age,
        vehicle_pub_key=config.VEHICLE_PUB_KEY,
    )


def test_replay_attack() -> Dict[str, str]:
    _print_banner("Replay Attack")
    packet, *_ = _run_legitimate_protocol()

    fresh = _verify(packet)
    print(f"  Fresh: all_ok={fresh.all_ok}  sig={fresh.signature_ok}")

    # Reuse same packet with a stale timestamp (attacker cannot re-sign without private key)
    replayed = copy.deepcopy(packet)
    replayed.timestamp = int((time.time() - 60) * 1000)
    # Signature now covers the old timestamp — TMA will detect BOTH sig failure AND staleness.
    # To isolate freshness, simulate an attacker who can re-sign (has no key), so
    # we just test the freshness path. We set vehicle_pub_key=None to skip sig check.
    replay = phase2_tma_verify(
        replayed, config.TMA_PRIV_KEY, config.TMA_IDENTITY, config.PK_G,
        max_age_sec=5.0, vehicle_pub_key=None,  # test freshness in isolation
    )
    detected = not replay.freshness_ok
    print(f"  Replayed: freshness_ok={replay.freshness_ok}  DETECTED={detected}")
    return {
        "type": "Replay Attack",
        "expected": "Rejected (stale timestamp)",
        "actual": "Rejected" if detected else "NOT Rejected",
        "detected": "YES" if detected else "NO",
    }


def test_tamper_attack() -> Dict[str, str]:
    _print_banner("Tamper Attack (ciphertext)")
    packet, *_ = _run_legitimate_protocol()

    tampered = copy.deepcopy(packet)
    enc = bytearray(tampered.enc_msg)
    if enc:
        enc[0] ^= 0xFF
    tampered.enc_msg = bytes(enc)
    # Signature now invalid: covers original enc_msg, not the tampered one
    result = _verify(tampered, max_age=30.0)
    detected = not result.signature_ok
    print(f"  Ciphertext tampered: sig_ok={result.signature_ok}  DETECTED={detected}")
    return {
        "type": "Tamper Attack (ciphertext)",
        "expected": "Rejected (signature fail)",
        "actual": "Rejected" if detected else "NOT Rejected",
        "detected": "YES" if detected else "NO",
    }


def test_tamper_sigma_attack() -> Dict[str, str]:
    _print_banner("Tamper Attack (sigma2)")
    packet, *_ = _run_legitimate_protocol()

    tampered = copy.deepcopy(packet)
    tampered.sigma2 = (tampered.sigma2 + 1) % _q
    # Signature covers sigma2 — will fail signature check
    result = _verify(tampered, max_age=30.0)
    detected = not result.signature_ok or not result.sigma2_ok
    print(f"  sigma2 modified: sig_ok={result.signature_ok}  sigma2_ok={result.sigma2_ok}  DETECTED={detected}")
    return {
        "type": "Tamper Attack (sigma2)",
        "expected": "Rejected (signature fail)",
        "actual": "Rejected" if detected else "NOT Rejected",
        "detected": "YES" if detected else "NO",
    }


def test_impersonation_attack() -> Dict[str, str]:
    _print_banner("Impersonation Attack")
    # Attacker steals a valid packet but cannot re-sign it (no private key).
    # They modify the sender_id to claim a different identity.
    packet, *_ = _run_legitimate_protocol()

    forged = copy.deepcopy(packet)
    forged.sender_id = config.VEHICLE_IDENTITY + 1  # wrong identity
    # vehicle_sig still covers original sender_id → signature mismatch
    result = _verify(forged, max_age=30.0)
    detected = not result.signature_ok
    print(f"  Impersonated sender_id: sig_ok={result.signature_ok}  DETECTED={detected}")
    return {
        "type": "Impersonation Attack",
        "expected": "Rejected (signature fail)",
        "actual": "Rejected" if detected else "NOT Rejected",
        "detected": "YES" if detected else "NO",
    }


def run_all_attacks() -> List[Dict[str, str]]:
    _print_banner("Running All Attack Simulations")
    results = [
        test_replay_attack(),
        test_tamper_attack(),
        test_tamper_sigma_attack(),
        test_impersonation_attack(),
    ]
    print(f"\n{'-'*72}\n  ATTACK SUMMARY\n{'-'*72}")
    for r in results:
        icon = "YES" if r["detected"] == "YES" else "NO "
        print(f"  [{icon}] {r['type']:40s} → {r['actual']}")
    return results


if __name__ == "__main__":
    run_all_attacks()
