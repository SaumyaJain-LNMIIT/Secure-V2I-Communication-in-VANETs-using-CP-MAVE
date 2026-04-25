#!/usr/bin/env python3
"""
vansec/protocol/messages.py — Structured message types for the VANSEC protocol.
"""

from __future__ import annotations

import pickle
from dataclasses import dataclass, field
from typing import Optional

__all__ = [
    "IdentityMsg",
    "NonceChallenge",
    "NonceResponse",
    "AuthToken",
    "Phase2Packet",
    "VerifyResult",
    "serialize",
    "deserialize",
]


# ===================================================================
# Phase 1 messages (Vehicle ↔ ECA)
# ===================================================================

@dataclass
class IdentityMsg:
    sender_id: int
    receiver_id: int


@dataclass
class NonceChallenge:
    iv: bytes
    enc_nonce: bytes
    tma_pub_key: object  # EC Point
    eca_key_point: object  # shared secret point


@dataclass
class NonceResponse:
    A_point: object  # ephemeral public key r₁·G
    expiry_period: int
    enc_nonce_inc: bytes


@dataclass
class AuthToken:
    sigma_t: int
    B_point: object  # EC Point
    start_time: int


# ===================================================================
# Phase 2 messages (Vehicle → TMA)
# ===================================================================

@dataclass
class Phase2Packet:
    A: object
    P1: object
    P2: object
    P3: object
    P4: object
    P5: object
    T1: object
    start_time: int
    expiry_period: int
    s1: int
    sigma2: int
    iv: bytes
    enc_msg: bytes
    timestamp: int          # Unix ms — replay protection
    sender_id: int = 0      # vehicle identity scalar
    vehicle_sig: bytes = field(default_factory=bytes)  # ECDSA signature over packet fields


@dataclass
class VerifyResult:
    s1_ok: bool
    sigma2_ok: bool
    freshness_ok: bool
    signature_ok: bool = True          # NEW: per-packet ECDSA signature check
    decrypted_msg: Optional[int] = None
    error: Optional[str] = None

    @property
    def all_ok(self) -> bool:
        return self.signature_ok and self.s1_ok and self.sigma2_ok and self.freshness_ok


# ===================================================================
# Serialization helpers
# ===================================================================

def serialize(msg) -> bytes:
    return pickle.dumps(msg)


def deserialize(data: bytes):
    return pickle.loads(data)
