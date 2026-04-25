#!/usr/bin/env python3
"""
vansec/protocol/phases.py — Pure-function protocol logic for Phase 1 and Phase 2.

Transport-independent: no sockets, no time.sleep(), no printing.
"""

from __future__ import annotations

import hashlib
import os
import struct
from typing import Tuple

from ecdsa import SigningKey, VerifyingKey, NIST256p, BadSignatureError, curves

from vansec.crypto.primitives import (
    Hash,
    AES_Enc_using_Key,
    AES_Dec_using_Key,
    generate_nonce,
    generate_iv,
    compute_shared_secret,
    generate_timestamp,
    verify_freshness,
    _point_x, _point_y,
)
from vansec.protocol.messages import (
    IdentityMsg,
    NonceChallenge,
    NonceResponse,
    AuthToken,
    Phase2Packet,
    VerifyResult,
)

_CURVE = curves.NIST256p
_G = _CURVE.generator
_q = _CURVE.order

__all__ = [
    "rand_scalar",
    "phase1_vehicle_init",
    "phase1_eca_challenge",
    "phase1_vehicle_respond",
    "phase1_eca_verify_and_sign",
    "phase1_vehicle_verify_token",
    "phase2_vehicle_build_packet",
    "phase2_tma_verify",
]


def rand_scalar() -> int:
    """Random scalar in Z_q."""
    return int.from_bytes(os.urandom(32), "big") % _q


# ===================================================================
# PHASE 1 — Vehicle Authentication (Vehicle ↔ ECA)
# ===================================================================

def phase1_vehicle_init(vehicle_id: int, tma_id: int) -> IdentityMsg:
    return IdentityMsg(sender_id=vehicle_id, receiver_id=tma_id)


def phase1_eca_challenge(
    identity_msg: IdentityMsg,
    eca_priv_key: int,
    vehicle_pub_key,
    tma_pub_key,
) -> Tuple[NonceChallenge, int]:
    nonce = rand_scalar()
    iv = generate_iv()
    eca_key_point = compute_shared_secret(eca_priv_key, vehicle_pub_key)
    enc_nonce, _ = AES_Enc_using_Key(eca_key_point, iv, nonce)

    challenge = NonceChallenge(
        iv=iv,
        enc_nonce=enc_nonce,
        tma_pub_key=tma_pub_key,
        eca_key_point=eca_key_point,
    )
    return challenge, nonce


def phase1_vehicle_respond(
    challenge: NonceChallenge,
    vehicle_priv_key: int,
    eca_pub_key,
) -> Tuple[NonceResponse, int, object]:
    vehicle_key = compute_shared_secret(vehicle_priv_key, eca_pub_key)

    nonce_raw, _ = AES_Dec_using_Key(vehicle_key, challenge.iv, challenge.enc_nonce)
    if isinstance(nonce_raw, int):
        nonce_decrypted = nonce_raw
    else:
        nonce_decrypted = int.from_bytes(nonce_raw, "big")

    nonce_incremented = (nonce_decrypted + 1) % _q
    expiry_period = rand_scalar()
    enc_nonce_inc, _ = AES_Enc_using_Key(vehicle_key, challenge.iv, nonce_incremented)

    r1 = rand_scalar()
    A = r1 * _G

    response = NonceResponse(
        A_point=A,
        expiry_period=expiry_period,
        enc_nonce_inc=enc_nonce_inc,
    )
    return response, r1, A


def phase1_eca_verify_and_sign(
    response: NonceResponse,
    nonce_plaintext: int,
    eca_key_point,
    iv: bytes,
    sender_id: int,
    receiver_id: int,
    eca_sigma: int,
    eca_priv_key: int,
    eca_pub_key,
) -> AuthToken:
    received_inc, _ = AES_Dec_using_Key(eca_key_point, iv, response.enc_nonce_inc)
    expected_inc = (nonce_plaintext + 1) % _q

    if received_inc != expected_inc:
        raise ValueError(
            f"Nonce mismatch: expected {expected_inc}, got {received_inc}"
        )

    hash_sigma_a = Hash(eca_sigma) % _q
    h_tr = Hash(sender_id, receiver_id, hash_sigma_a,
                _point_x(response.A_point), _point_y(response.A_point)) % _q
    B = h_tr * eca_pub_key

    start_time = rand_scalar()
    I_p = Hash(receiver_id, start_time, response.expiry_period) % _q
    sigma_t = (I_p * eca_sigma + h_tr * eca_priv_key + eca_priv_key) % _q

    return AuthToken(sigma_t=sigma_t, B_point=B, start_time=start_time)


def phase1_vehicle_verify_token(
    token: AuthToken,
    I_p: int,
    PK_g,
    ECA_C_i,
    ECA_Y_i,
    B,
    eca_pub_key,
) -> bool:
    lhs = token.sigma_t * _G
    rhs = I_p * PK_g + I_p * ECA_C_i + I_p * ECA_Y_i + B + eca_pub_key
    return lhs == rhs


# ===================================================================
# PHASE 2 — Signature helpers
# ===================================================================

def _int_to_bytes32(n: int) -> bytes:
    """Encode a non-negative integer as exactly 32 big-endian bytes."""
    return n.to_bytes(32, "big")


def _point_to_bytes64(pt) -> bytes:
    """Encode an EC point as 64 bytes (x‖y, each 32 bytes)."""
    return _int_to_bytes32(_point_x(pt)) + _int_to_bytes32(_point_y(pt))


def _packet_signing_bytes(packet: Phase2Packet) -> bytes:
    """
    Canonical byte string over Phase 2 critical fields (used for signature).

    Covers everything an attacker could tamper with:
    sender_id, all EC points, s1, sigma2, iv, enc_msg, timestamp.
    Note: start_time / expiry_period are large scalars (mod q), not Unix ts.
    """
    parts: list[bytes] = [
        _int_to_bytes32(packet.sender_id),
        _point_to_bytes64(packet.A),
        _point_to_bytes64(packet.P1),
        _point_to_bytes64(packet.P2),
        _point_to_bytes64(packet.P3),
        _point_to_bytes64(packet.P4),
        _point_to_bytes64(packet.P5),
        _point_to_bytes64(packet.T1),
        _int_to_bytes32(packet.start_time),      # scalar mod q → 32 bytes
        _int_to_bytes32(packet.expiry_period),   # scalar mod q → 32 bytes
        _int_to_bytes32(packet.s1),
        _int_to_bytes32(packet.sigma2),
        packet.iv,               # 16 bytes
        packet.enc_msg,          # variable length
        struct.pack(">Q", packet.timestamp & 0xFFFFFFFFFFFFFFFF),  # Unix ms → 8 bytes
    ]
    return b"".join(parts)



def _sign_packet(packet: Phase2Packet, vehicle_priv_key: int) -> bytes:
    """
    Sign *packet* with the vehicle's ECDSA private key (NIST P-256).

    Uses SigningKey.from_secret_exponent so the raw integer scalar is
    passed directly without byte conversion.
    Returns a 64-byte (r‖s) signature.
    """
    sk = SigningKey.from_secret_exponent(vehicle_priv_key, curve=NIST256p,
                                         hashfunc=hashlib.sha256)
    data = _packet_signing_bytes(packet)
    return sk.sign(data)


def _verify_sig(packet: Phase2Packet, vehicle_pub_key) -> bool:
    """
    Verify *packet.vehicle_sig* against the canonical data bytes.
    *vehicle_pub_key* is the ecdsa ellipticcurve.Point stored in config.
    Returns True if valid, False otherwise.
    """
    try:
        vk = VerifyingKey.from_public_point(vehicle_pub_key, curve=NIST256p,
                                            hashfunc=hashlib.sha256)
        data = _packet_signing_bytes(packet)
        return vk.verify(packet.vehicle_sig, data)
    except (BadSignatureError, Exception):
        return False


# ===================================================================
# PHASE 2 — Message Transmission (Vehicle → TMA)
# ===================================================================

def phase2_vehicle_build_packet(
    sigma_t: int,
    r1: int,
    I_p: int,
    B,
    A,
    start_time: int,
    expiry_period: int,
    iv: bytes,
    msg_to_send: int,
    tma_pub_key,
    PK_g,
    ECA_C_i,
    ECA_Y_i,
    ECA_pub_key,
    vehicle_id: int = 0,
    vehicle_priv_key: int = 0,
) -> Phase2Packet:
    r2 = rand_scalar()
    r3 = rand_scalar()

    P1 = r2 * PK_g
    P2 = r2 * ECA_C_i
    P3 = r2 * ECA_Y_i
    P4 = r2 * ECA_pub_key
    P5 = r2 * B
    T1 = r3 * PK_g

    I_c = Hash(
        _point_x(A), _point_y(A),
        _point_x(P1), _point_y(P1), _point_x(P2), _point_y(P2),
        _point_x(P3), _point_y(P3), _point_x(P4), _point_y(P4),
        _point_x(P5), _point_y(P5), _point_x(T1), _point_y(T1),
    ) % _q

    sigma2 = (r2 * sigma_t + I_c * r1) % _q
    s1 = (r3 + I_c * r2) % _q

    vehicle_key_for_msg = r1 * tma_pub_key
    enc_msg, _ = AES_Enc_using_Key(vehicle_key_for_msg, iv, msg_to_send)
    timestamp = generate_timestamp()

    packet = Phase2Packet(
        A=A, P1=P1, P2=P2, P3=P3, P4=P4, P5=P5, T1=T1,
        start_time=start_time,
        expiry_period=expiry_period,
        s1=s1, sigma2=sigma2,
        iv=iv, enc_msg=enc_msg,
        timestamp=timestamp,
        sender_id=vehicle_id,
        vehicle_sig=b"",
    )

    # Sign over all critical fields (including enc_msg and sender_id)
    if vehicle_priv_key != 0:
        packet.vehicle_sig = _sign_packet(packet, vehicle_priv_key)

    return packet


def phase2_tma_verify(
    packet: Phase2Packet,
    tma_priv_key: int,
    tma_identity: int,
    PK_g,
    max_age_sec: float = 5.0,
    vehicle_pub_key=None,
) -> VerifyResult:

    # ── 0. Signature check (first — cheapest rejection) ──────────────
    if vehicle_pub_key is not None and len(packet.vehicle_sig) > 0:
        sig_ok = _verify_sig(packet, vehicle_pub_key)
        if not sig_ok:
            return VerifyResult(
                s1_ok=False, sigma2_ok=False, freshness_ok=False,
                signature_ok=False,
                error="SIGNATURE_FAIL",
            )
    else:
        sig_ok = True  # no key provided → skip (backward compat)

    # ── 1. Freshness / replay protection ─────────────────────────────
    freshness_ok = verify_freshness(packet.timestamp, max_age_sec)

    # ── 2. Decrypt ───────────────────────────────────────────────────
    TMA_key = tma_priv_key * packet.A
    try:
        msg_decrypted, _ = AES_Dec_using_Key(TMA_key, packet.iv, packet.enc_msg)
        dec_error = None
    except Exception as e:
        msg_decrypted = None
        dec_error = str(e)

    if dec_error:
        return VerifyResult(
            s1_ok=False, sigma2_ok=False, freshness_ok=freshness_ok,
            signature_ok=sig_ok,
            error=f"Decryption failed: {dec_error}",
        )

    # ── 3. s1 and sigma2 checks ──────────────────────────────────────
    I_c = Hash(
        _point_x(packet.A), _point_y(packet.A),
        _point_x(packet.P1), _point_y(packet.P1),
        _point_x(packet.P2), _point_y(packet.P2),
        _point_x(packet.P3), _point_y(packet.P3),
        _point_x(packet.P4), _point_y(packet.P4),
        _point_x(packet.P5), _point_y(packet.P5),
        _point_x(packet.T1), _point_y(packet.T1),
    ) % _q

    I_p = Hash(tma_identity, packet.start_time, packet.expiry_period) % _q

    s1_ok = (packet.s1 * PK_g) == (packet.T1 + I_c * packet.P1)

    lhs_sig2 = (packet.sigma2 % _q) * _G
    rhs_sig2 = (
        (I_p % _q) * (packet.P1 + packet.P2 + packet.P3)
        + packet.P4
        + packet.P5
        + (I_c % _q) * packet.A
    )
    sigma2_ok = (lhs_sig2 == rhs_sig2)

    return VerifyResult(
        s1_ok=s1_ok, sigma2_ok=sigma2_ok, freshness_ok=freshness_ok,
        signature_ok=sig_ok,
        decrypted_msg=msg_decrypted if isinstance(msg_decrypted, int) else None,
    )
