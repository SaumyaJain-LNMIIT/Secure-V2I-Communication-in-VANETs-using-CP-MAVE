#!/usr/bin/env python3
from __future__ import annotations

import os
from typing import Tuple, List

from ecdsa import ellipticcurve, curves

from vansec.crypto.primitives import generate_nonce

# Curve setup (equivalent to P256)
curve = curves.NIST256p
G = curve.generator
q = curve.order

Point = ellipticcurve.Point

__all__ = [
    "generate_keypair",
    "generate_identity",
    "Registration_With_KGC",
    "register_eca",
    "KeyStore",
]

# ===================================================================
# Key pair & identity generation
# ===================================================================

def generate_keypair() -> Tuple[int, Point]:
    priv = int.from_bytes(os.urandom(32), "big") % q
    if priv == 0:
        priv = 1
    pub = priv * G
    return priv, pub


def generate_identity() -> int:
    return int.from_bytes(os.urandom(32), "big") % q


# ===================================================================
# KGC Registration
# ===================================================================

def Registration_With_KGC(KGC_priv_key: int) -> Tuple[Point, int, Point]:
    h_j_i = generate_nonce()
    y_j_i = generate_nonce()

    Y_j_i = (y_j_i % q) * G
    C_j_i = ((h_j_i * y_j_i) % q) * G

    sigma_j_i = (KGC_priv_key + (h_j_i * y_j_i) + y_j_i) % q

    return C_j_i, sigma_j_i, Y_j_i


def _point_sum(points: List[Point]) -> Point:
    if not points:
        raise ValueError("Need at least one Point")
    total = points[0]
    for p in points[1:]:
        total = total + p
    return total


def register_eca(
    kgc_keys: List[Tuple[int, Point]],
) -> Tuple[int, Point, Point, Point]:

    C_list, sigma_list, Y_list, pub_list = [], [], [], []

    for priv, pub in kgc_keys:
        C_i, sigma, Y_i = Registration_With_KGC(priv)
        C_list.append(C_i)
        sigma_list.append(sigma % q)
        Y_list.append(Y_i)
        pub_list.append(pub)

    ECA_sigma = sum(sigma_list) % q
    ECA_C_i = _point_sum(C_list)
    ECA_Y_i = _point_sum(Y_list)
    PK_g = _point_sum(pub_list)

    return ECA_sigma, ECA_C_i, ECA_Y_i, PK_g


# ===================================================================
# Convenience holder
# ===================================================================

class KeyStore:
    def __init__(
        self,
        identity: int,
        priv_key: int,
        pub_key: Point,
        role: str = "unknown",
    ):
        self.identity = identity
        self.priv_key = priv_key
        self.pub_key = pub_key
        self.role = role

    def __repr__(self) -> str:
        return f"KeyStore(role={self.role!r}, id=...{str(self.identity)[-8:]})"