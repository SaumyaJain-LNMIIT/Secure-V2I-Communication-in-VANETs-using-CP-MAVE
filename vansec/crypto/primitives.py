#!/usr/bin/env python3
"""
vansec/crypto/primitives.py — Core cryptographic primitives for VANSEC.

Provides:
  - Hash(*args)             → SHA-384, returns int mod q
  - AES_Enc_using_Key()     → AES-128-CBC encrypt via ECC shared secret
  - AES_Dec_using_Key()     → AES-128-CBC decrypt via ECC shared secret
  - generate_nonce()        → random scalar mod q
  - generate_iv()           → 16-byte random IV
  - compute_shared_secret() → ECDH shared secret point
  - generate_timestamp()    → current Unix timestamp as int
  - verify_freshness()      → replay protection check
"""

import os
import time
import hashlib
from typing import Tuple, Union

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from ecdsa import curves, ellipticcurve

# Curve constants
_CURVE = curves.NIST256p
_G = _CURVE.generator
_q = _CURVE.order
Point = ellipticcurve.PointJacobi  # ecdsa uses PointJacobi internally

__all__ = [
    "Hash",
    "AES_Enc_using_Key",
    "AES_Dec_using_Key",
    "generate_nonce",
    "generate_iv",
    "compute_shared_secret",
    "generate_timestamp",
    "verify_freshness",
]

# Fixed byte length for P-256 coordinates
_COORD_BYTES = 32
_AES_BLOCK = AES.block_size  # 16


# ===================================================================
# Internal helpers
# ===================================================================

def _to_bytes_fixed_int(x: int, length: int = _COORD_BYTES) -> bytes:
    """Encode integer *x* to fixed-length big-endian bytes."""
    if x < 0:
        raise ValueError("Only non-negative integers supported.")
    return x.to_bytes(length, byteorder="big")


def _point_x(point) -> int:
    """Get x coordinate from an ecdsa Point (handles both API styles)."""
    if callable(getattr(point, 'x', None)):
        return point.x()
    return point.x


def _point_y(point) -> int:
    """Get y coordinate from an ecdsa Point (handles both API styles)."""
    if callable(getattr(point, 'y', None)):
        return point.y()
    return point.y


def _point_to_bytes(point) -> bytes:
    """Return x||y fixed-length encoding (each coordinate 32 bytes)."""
    return (
        _to_bytes_fixed_int(_point_x(point), _COORD_BYTES)
        + _to_bytes_fixed_int(_point_y(point), _COORD_BYTES)
    )


# ===================================================================
# Cryptographic Hash
# ===================================================================

def Hash(*args) -> int:
    """
    Deterministic SHA-384 hash over variable arguments.
    Returns the hash value **mod q**.
    """
    h = hashlib.sha384()
    data = b""
    for arg in args:
        if isinstance(arg, int):
            data += _to_bytes_fixed_int(arg, _COORD_BYTES)
        elif isinstance(arg, bytes):
            data += arg
        elif isinstance(arg, str):
            data += arg.encode("utf-8")
        elif hasattr(arg, 'x') and hasattr(arg, 'y'):
            # EC point
            data += _point_to_bytes(arg)
        else:
            data += str(arg).encode("utf-8")
    h.update(data)
    return int.from_bytes(h.digest(), byteorder="big") % _q


# ===================================================================
# AES-128-CBC Encryption / Decryption (key from ECC point)
# ===================================================================

def _derive_aes_key(point) -> bytes:
    """Derive a 16-byte AES key from an EC point via SHA-256(x || y)."""
    return hashlib.sha256(_point_to_bytes(point)).digest()[:16]


def AES_Enc_using_Key(
    key_point,
    iv: bytes,
    msg: Union[int, str, bytes],
) -> Tuple[bytes, object]:
    """
    AES-128-CBC encrypt.

    Parameters
    ----------
    key_point : EC Point
        ECC shared-secret point used to derive the AES key.
    iv : bytes
        16-byte initialisation vector.
    msg : int | str | bytes
        Plaintext (integers are encoded as 32-byte big-endian).

    Returns
    -------
    (ciphertext, key_point)
    """
    if not isinstance(iv, (bytes, bytearray)) or len(iv) != _AES_BLOCK:
        raise ValueError("iv must be 16 bytes")

    aes_key = _derive_aes_key(key_point)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)

    if isinstance(msg, int):
        msg_bytes = _to_bytes_fixed_int(msg, _COORD_BYTES)
    elif isinstance(msg, bytes):
        msg_bytes = msg
    else:
        msg_bytes = str(msg).encode("utf-8")

    ciphertext = cipher.encrypt(pad(msg_bytes, _AES_BLOCK))
    return ciphertext, key_point


def AES_Dec_using_Key(
    key_point,
    iv: bytes,
    enc_msg: bytes,
) -> Tuple[Union[int, bytes, str], object]:
    """
    AES-128-CBC decrypt.

    Returns
    -------
    (plaintext_or_int, key_point)
        If the decrypted data is exactly 32 bytes it is returned as an ``int``.
    """
    if not isinstance(iv, (bytes, bytearray)) or len(iv) != _AES_BLOCK:
        raise ValueError("iv must be 16 bytes")

    aes_key = _derive_aes_key(key_point)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)

    plain_padded = cipher.decrypt(enc_msg)
    try:
        plain = unpad(plain_padded, _AES_BLOCK)
    except ValueError:
        raise ValueError("Invalid padding or corrupted ciphertext")

    if len(plain) == _COORD_BYTES:
        try:
            return int.from_bytes(plain, "big"), key_point
        except Exception:
            return plain, key_point
    else:
        try:
            return plain.decode("utf-8"), key_point
        except Exception:
            return plain, key_point


# ===================================================================
# Utility functions
# ===================================================================

def generate_nonce() -> int:
    """Random scalar modulo q."""
    return int.from_bytes(os.urandom(32), "big") % _q


def generate_iv() -> bytes:
    """16-byte random IV for AES-CBC."""
    return os.urandom(_AES_BLOCK)


def compute_shared_secret(priv: int, pub) -> object:
    """ECDH shared secret: ``priv * pub``."""
    return priv * pub


# ===================================================================
# Timestamp / Replay protection
# ===================================================================

def generate_timestamp() -> int:
    """Current Unix timestamp in **milliseconds** (integer)."""
    return int(time.time() * 1000)


def verify_freshness(timestamp_ms: int, max_age_sec: float = 5.0) -> bool:
    """
    Return ``True`` if *timestamp_ms* is within *max_age_sec* of now.
    Used by TMA to reject replayed Phase-2 packets.
    """
    now_ms = int(time.time() * 1000)
    age_ms = now_ms - timestamp_ms
    return 0 <= age_ms <= max_age_sec * 1000
