# VANSEC — VANET Data Integrity & Confidentiality

A Python-based simulation framework for **data integrity and confidentiality** in Vehicular Ad-hoc Networks (VANETs), implemented using **AES-128-CBC encryption** and **ECDSA digital signatures** on NIST P-256.

Based on the **CP-MAVE** protocol, refactored into a modular, experiment-ready academic project.

---

## Security Properties

| Property | Mechanism | Where |
|---|---|---|
| **Confidentiality** | AES-128-CBC; key derived via ECDH shared secret (vehicle · TMA) | `phases.py` `AES_Enc_using_Key` |
| **Data Integrity** | ECDSA signature over all Phase 2 packet fields (enc_msg, σ₂, s₁, IV, timestamp, sender_id) | `phases.py` `_sign_packet / _verify_sig` |
| **Authentication** | Nonce challenge-response (Phase 1) + ECA-issued session token σ_t | `phases.py` Phase 1 functions |
| **Non-repudiation** | Vehicle signs each packet with its NIST P-256 private key; TMA verifies with vehicle public key | `SigningKey.from_string` / `VerifyingKey.from_public_point` |
| **Replay Protection** | Millisecond-precision Unix timestamp in every Phase 2 packet; TMA rejects packets older than 5 s | `phases.py` `verify_freshness` |

### How the requirement is met

> *"Develop a scheme to ensure data integrity and confidentiality in VANET using encryption and digital signatures."*

- **Confidentiality** — the message is encrypted with AES-128-CBC before transmission. The AES key is derived from an ECDH shared secret, so only the intended TMA can decrypt.
- **Integrity / Digital Signature** — after building the Phase 2 packet, the vehicle signs the full packet (including ciphertext, sender identity, and all protocol fields) with its ECDSA private key. TMA verifies this signature before decrypting. Any bit-flip in the ciphertext or any field substitution is detected immediately.
- **Replay Protection** — the timestamp inside the signed payload is checked within a configurable freshness window. A replayed packet is rejected even if the signature is valid.

---

## Architecture

```
Vehicle (OBU)  ──Phase 1──▶  ECA (Certificate Authority)
     │                            │
     │◀── auth token (σ_t) ──────┘
     │
     │  Phase 2 packet (signed + encrypted)
     │    └─ sender_id, enc_msg (AES-CBC), ECDSA vehicle_sig, σ₂, s₁, timestamp
     │
     └──── Phase 2 ─────────▶  TMA (Traffic Management Agency)
                                     │
                                     ├─ 1. verify ECDSA vehicle_sig
                                     ├─ 2. check timestamp freshness
                                     ├─ 3. decrypt AES ciphertext
                                     └─ 4. verify σ₂ and s₁
```

---

## Project Structure

```
VANSEC/
├── config.py                    # Centralized keys, ports, simulation params
├── main.py                      # CLI entry point
├── requirements.txt
├── vansec/
│   ├── crypto/
│   │   ├── primitives.py        # Hash (SHA-384), AES-128-CBC, nonce, IV, ECDH
│   │   └── keys.py              # Key generation (NIST P-256), KGC registration
│   ├── protocol/
│   │   ├── messages.py          # Typed message dataclasses (Phase2Packet has vehicle_sig)
│   │   └── phases.py            # Phase 1 & Phase 2 logic + ECDSA sign/verify helpers
│   ├── network/
│   │   ├── simulator.py         # VANET channel simulator (delay, loss, jitter)
│   │   └── channel.py           # TCP transport + NetworkSimulator integration
│   ├── nodes/
│   │   ├── vehicle.py           # Vehicle OBU — signs and encrypts Phase 2 packet
│   │   ├── eca.py               # ECA server — Phase 1 challenge/response
│   │   └── tma.py               # TMA verifier — checks signature then decrypts
│   └── metrics/
│       ├── collector.py         # Metrics collection & CSV export
│       └── plotter.py           # matplotlib graph generation
├── experiments/
│   ├── runner.py                # Experiment orchestrator (5 experiment types)
│   └── attacks.py               # Attack simulations (all 4 detected)
├── tests/
│   ├── test_primitives.py       # Crypto unit tests (9 tests)
│   └── test_protocol.py         # Protocol round-trip + security tests (7 tests)
└── results/                     # Auto-generated output
    ├── csv/
    └── plots/
```

---

## Setup

```bash
pip install -r requirements.txt
```

`requirements.txt`:
```
ecdsa
pycryptodome
matplotlib
```

---

## Usage

```bash
# Run all experiments
python main.py

# Specific modes
python main.py --mode single     # Single-vehicle (20 runs)
python main.py --mode multi      # Multi-vehicle (5 vehicles × 5 runs)
python main.py --mode crypto     # Cryptographic overhead benchmark
python main.py --mode attacks    # Security attack simulations
```

---

## Running Tests

```bash
python tests/test_primitives.py   # 9/9 crypto primitive tests
python tests/test_protocol.py     # 7/7 protocol + security tests
python experiments/attacks.py     # 4/4 attack simulations (all detected)
```

### Security test coverage

| Test | Verifies |
|---|---|
| `test_full_protocol_roundtrip` | Legitimate packet accepted: sig✓, s1✓, σ₂✓, freshness✓, decrypt✓ |
| `test_ciphertext_tamper_detected` | Bit-flip in `enc_msg` → signature fail → rejected |
| `test_sender_id_tamper_detected` | Forged `sender_id` without re-signing → signature fail → rejected |
| `test_sigma2_tamper_detected` | Modified `σ₂` → signature fail → rejected |
| `test_nonce_mismatch_detected` | Wrong nonce in Phase 1 → ValueError |
| `test_multiple_runs_consistent` | 5 consecutive full runs all succeed |

---

## Running with Sockets (3 terminals)

```bash
# Terminal 1
python -c "from vansec.nodes.eca import ECA; ECA().start()"
# Terminal 2
python -c "from vansec.nodes.tma import TMA; TMA().start()"
# Terminal 3
python main.py --mode single --runs 10
```

---

## Experiments

| # | Experiment | Purpose |
|---|---|---|
| 1 | Single Vehicle | Baseline latency (Phase 1 + Phase 2) |
| 2 | Multi-Vehicle | Scalability with multiple vehicles |
| 3 | Scalability Sweep | Latency vs. vehicle count [1, 5, 10, 20] |
| 4 | Loss Rate Sweep | PDR, latency, jitter under [0–30%] packet loss |
| 5 | Crypto Benchmark | Per-operation overhead (Hash, AES, ECC keygen, scalar mul) |
| 6 | Attack Detection | Replay, ciphertext tamper, σ₂ tamper, impersonation — all rejected |

---

## Technology Stack

| Library | Role |
|---|---|
| **ecdsa** (pure Python, NIST P-256) | ECDH key agreement, ECDSA signing & verification |
| **PyCryptodome** | AES-128-CBC encryption / decryption |
| **matplotlib** | Graph generation |
| **TCP sockets** | Inter-node communication |

---

## Credits

Based on the CP-MAVE protocol: *Conditional Privacy-preserving Message Authentication protocol for VANET Emergency message exchange*.
