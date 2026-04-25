#!/usr/bin/env python3
"""tests/test_protocol.py — Full protocol round-trip tests (no sockets)."""

import os, sys, copy
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ecdsa import curves

import config
from vansec.crypto.primitives import Hash
from vansec.protocol.phases import (
    rand_scalar,
    phase1_vehicle_init, phase1_eca_challenge,
    phase1_vehicle_respond, phase1_eca_verify_and_sign,
    phase1_vehicle_verify_token,
    phase2_vehicle_build_packet, phase2_tma_verify,
)

_q = curves.NIST256p.order


def _run_p1():
    """Shared helper: run Phase 1 and return all state needed for Phase 2."""
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
    return auth_token, r1, A, I_p, response, challenge


def _build_packet(auth_token, r1, A, I_p, response, challenge, msg=None):
    return phase2_vehicle_build_packet(
        auth_token.sigma_t, r1, I_p, auth_token.B_point, A,
        auth_token.start_time, response.expiry_period, challenge.iv,
        msg if msg is not None else rand_scalar(),
        config.TMA_PUB_KEY, config.PK_G,
        config.ECA_C_I, config.ECA_Y_I, config.ECA_PUB_KEY,
        vehicle_id=config.VEHICLE_IDENTITY,
        vehicle_priv_key=config.VEHICLE_PRIV_KEY,
    )


def _verify(packet, max_age=5.0):
    return phase2_tma_verify(
        packet, config.TMA_PRIV_KEY, config.TMA_IDENTITY, config.PK_G,
        max_age_sec=max_age,
        vehicle_pub_key=config.VEHICLE_PUB_KEY,
    )


def test_full_protocol_roundtrip():
    auth_token, r1, A, I_p, response, challenge = _run_p1()
    token_ok = phase1_vehicle_verify_token(
        auth_token, I_p, config.PK_G, config.ECA_C_I,
        config.ECA_Y_I, auth_token.B_point, config.ECA_PUB_KEY,
    )
    assert token_ok, "Phase 1 sigma_t verification FAILED"
    print("[PASS] Phase 1: sigma_t OK")

    msg = rand_scalar()
    packet = _build_packet(auth_token, r1, A, I_p, response, challenge, msg)

    result = _verify(packet)
    assert result.signature_ok, f"signature_ok FAILED: {result.error}"
    assert result.s1_ok, "s1 FAILED"
    assert result.sigma2_ok, "sigma2 FAILED"
    assert result.freshness_ok, "freshness FAILED"
    assert result.decrypted_msg == msg, f"msg mismatch: {result.decrypted_msg} != {msg}"
    assert result.all_ok, f"all_ok FAILED: {result}"
    print("[PASS] Phase 2: signature, s1, sigma2, freshness, decrypt all OK")


def test_nonce_mismatch_detected():
    identity_msg = phase1_vehicle_init(config.VEHICLE_IDENTITY, config.TMA_IDENTITY)
    challenge, nonce_plain = phase1_eca_challenge(
        identity_msg, config.ECA_PRIV_KEY, config.VEHICLE_PUB_KEY, config.TMA_PUB_KEY,
    )
    response, _, _ = phase1_vehicle_respond(
        challenge, config.VEHICLE_PRIV_KEY, config.ECA_PUB_KEY,
    )
    try:
        phase1_eca_verify_and_sign(
            response, nonce_plain + 999, challenge.eca_key_point, challenge.iv,
            identity_msg.sender_id, identity_msg.receiver_id,
            config.ECA_SIGMA, config.ECA_PRIV_KEY, config.ECA_PUB_KEY,
        )
        raise AssertionError("Should have raised ValueError")
    except ValueError:
        pass
    print("[PASS] Nonce mismatch correctly detected")


def test_ciphertext_tamper_detected():
    """Mutating enc_msg must invalidate the packet signature."""
    auth_token, r1, A, I_p, response, challenge = _run_p1()
    packet = _build_packet(auth_token, r1, A, I_p, response, challenge)

    tampered = copy.deepcopy(packet)
    enc = bytearray(tampered.enc_msg)
    enc[0] ^= 0xFF
    tampered.enc_msg = bytes(enc)

    result = _verify(tampered, max_age=30.0)
    assert not result.signature_ok, "Ciphertext tamper should fail signature check"
    assert not result.all_ok
    print("[PASS] Ciphertext tamper correctly detected via signature failure")


def test_sender_id_tamper_detected():
    """Changing sender_id without recomputing signature must be detected."""
    auth_token, r1, A, I_p, response, challenge = _run_p1()
    packet = _build_packet(auth_token, r1, A, I_p, response, challenge)

    forged = copy.deepcopy(packet)
    forged.sender_id = config.VEHICLE_IDENTITY + 1  # fake identity

    result = _verify(forged, max_age=30.0)
    assert not result.signature_ok, "Sender-id tamper should fail signature check"
    assert not result.all_ok
    print("[PASS] Sender-id tamper (impersonation) correctly detected via signature failure")


def test_sigma2_tamper_detected():
    """Modifying sigma2 must invalidate the packet signature."""
    auth_token, r1, A, I_p, response, challenge = _run_p1()
    packet = _build_packet(auth_token, r1, A, I_p, response, challenge)

    tampered = copy.deepcopy(packet)
    tampered.sigma2 = (tampered.sigma2 + 1) % _q

    result = _verify(tampered, max_age=30.0)
    assert not result.signature_ok, "sigma2 tamper should fail signature check"
    assert not result.all_ok
    print("[PASS] sigma2 tamper correctly detected via signature failure")


def test_multiple_runs_consistent():
    for i in range(5):
        auth_token, r1, A, I_p, response, challenge = _run_p1()
        packet = _build_packet(auth_token, r1, A, I_p, response, challenge)
        result = _verify(packet)
        assert result.all_ok, f"Run {i+1} failed: {result}"
    print("[PASS] 5 consecutive runs all OK")


if __name__ == "__main__":
    test_full_protocol_roundtrip()
    test_nonce_mismatch_detected()
    test_ciphertext_tamper_detected()
    test_sender_id_tamper_detected()
    test_sigma2_tamper_detected()
    test_multiple_runs_consistent()
    print("\n✅ All protocol tests passed!")
