#!/usr/bin/env python3
"""tests/test_primitives.py — Unit tests for vansec.crypto.primitives."""

import os, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ecdsa import curves
from vansec.crypto.keys import generate_keypair
from vansec.crypto.primitives import (
    Hash, AES_Enc_using_Key, AES_Dec_using_Key,
    generate_nonce, generate_iv, compute_shared_secret,
    generate_timestamp, verify_freshness,
)

_q = curves.NIST256p.order


def test_hash_determinism():
    h1 = Hash(42, 123, "hello")
    h2 = Hash(42, 123, "hello")
    assert h1 == h2, f"Hash not deterministic: {h1} != {h2}"
    print("[PASS] test_hash_determinism")

def test_hash_different_inputs():
    assert Hash(1, 2, 3) != Hash(1, 2, 4), "Hash collision"
    print("[PASS] test_hash_different_inputs")

def test_hash_mod_q():
    for i in range(50):
        h = Hash(i, i * 7, "test")
        assert 0 <= h < _q, f"Hash out of range: {h}"
    print("[PASS] test_hash_mod_q")

def test_aes_roundtrip_int():
    priv, pub = generate_keypair()
    priv2, pub2 = generate_keypair()
    shared = compute_shared_secret(priv, pub2)
    iv = generate_iv()
    original = 123456789012345678901234567890
    ct, _ = AES_Enc_using_Key(shared, iv, original)
    pt, _ = AES_Dec_using_Key(shared, iv, ct)
    assert pt == original, f"AES roundtrip failed: {pt} != {original}"
    print("[PASS] test_aes_roundtrip_int")

def test_aes_roundtrip_nonce():
    priv, pub = generate_keypair()
    shared = priv * pub
    iv = generate_iv()
    nonce = generate_nonce()
    ct, _ = AES_Enc_using_Key(shared, iv, nonce)
    pt, _ = AES_Dec_using_Key(shared, iv, ct)
    assert pt == nonce, f"Nonce roundtrip failed"
    print("[PASS] test_aes_roundtrip_nonce")

def test_nonce_uniqueness():
    nonces = {generate_nonce() for _ in range(100)}
    assert len(nonces) == 100, f"Only {len(nonces)} unique nonces"
    print("[PASS] test_nonce_uniqueness")

def test_iv_length():
    assert len(generate_iv()) == 16
    print("[PASS] test_iv_length")

def test_shared_secret_commutativity():
    priv1, pub1 = generate_keypair()
    priv2, pub2 = generate_keypair()
    assert compute_shared_secret(priv1, pub2) == compute_shared_secret(priv2, pub1)
    print("[PASS] test_shared_secret_commutativity")

def test_timestamp_freshness():
    ts = generate_timestamp()
    assert verify_freshness(ts, 5.0), "Fresh ts not fresh"
    old_ts = int((time.time() - 60) * 1000)
    assert not verify_freshness(old_ts, 5.0), "Old ts is fresh"
    print("[PASS] test_timestamp_freshness")


if __name__ == "__main__":
    test_hash_determinism()
    test_hash_different_inputs()
    test_hash_mod_q()
    test_aes_roundtrip_int()
    test_aes_roundtrip_nonce()
    test_nonce_uniqueness()
    test_iv_length()
    test_shared_secret_commutativity()
    test_timestamp_freshness()
    print("\n✅ All primitive tests passed!")
