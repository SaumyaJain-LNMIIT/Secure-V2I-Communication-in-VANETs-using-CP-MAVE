#!/usr/bin/env python3
"""
config.py — Centralized configuration for the VANSEC project.

All ECC keys, identities, network parameters, and simulation settings
live here. Every other module imports from this single source of truth.
"""
from ecdsa import curves, ellipticcurve

# Wrapper for NIST P-256 curve constants
class P256Wrapper:
    def __init__(self):
        self.curve = curves.NIST256p
        self.G = self.curve.generator
        self.q = self.curve.order

P256 = P256Wrapper()
Point = ellipticcurve.Point

# ===================================================================
# ECC Curve
# ===================================================================
CURVE = P256

# ===================================================================
# Entity Identities (random scalars on P-256)
# ===================================================================
VEHICLE_IDENTITY = (
    6330614295947393657856040725909354215571545936334951160496604125994438196162
)
ECA_IDENTITY = (
    13385647806998004153020035149177702292929509406886890249193697053202672561527
)
TMA_IDENTITY = (
    8169104755805935683608881213542562938956147541291769502712984486856835317573
)

# ===================================================================
# ECC Private Keys
# ===================================================================
VEHICLE_PRIV_KEY = (
    62718740499567001559645896635471998470595369862886026081752443059900420476791
)
ECA_PRIV_KEY = (
    27035679567817885497930140100479440063071582958031951165314744143627511123473
)
TMA_PRIV_KEY = (
    3822204222889312141452796624401703944169653051092257917058141841645549240302
)

# ===================================================================
# ECC Public Keys (precomputed points on P-256)
# ===================================================================
VEHICLE_PUB_KEY = Point(
    P256.curve.curve,
    0xF81CC47E2CAF24468DDF86AB9279C14BAE235A07C5C2F960A1BA395FFC14D2B6,
    0xD8D7DAB908578B5AA9F87118662117587BD44F38B8D67EB0E9B4439F04F8A723
)
ECA_PUB_KEY = Point(
    P256.curve.curve,
    0x6AADBCCB88AD8839C21E7A3754E42F7281EEB2B75A07358F6889EEF9030C1793,
    0x869E40C7C429FA96DDC6AD3576224FF5BD95C55A68224A0D1F734E4786443AF5
)
TMA_PUB_KEY = Point(
    P256.curve.curve,
    0x6880BBBB54C1A66F3618249D550FA629EC31EECE9A3BE989E6093AC1B790DBB2,
    0xA315167D2F09B9A27B0FE53FC96B47EEA13BC8DEAEA8C50CABDE9428E8683D03
)

# ===================================================================
# ECA Registration Credentials (from KGC registration)
# ===================================================================
ECA_SIGMA = (
    25106535378440752376581550080743121753402285117385170558988665032551770271000
)
ECA_C_I = Point(P256.curve.curve,
    0xB617E0900B2D6304A11D7A99E27E7498483B6563B47C1EE06DD2DC73E62408FB,
    0x90DCBF5075F41420FC7A51B078DFBE2A1B401D6D431E7DF45072A8134186CAE6
)
ECA_Y_I = Point(P256.curve.curve,
    0x3DDA16E64B2FDE142872B07E2A28271AC3B014425E15575CAA405BDFB6052B94,
    0xC797BB1D4A12FEDC152C3B2AEDB1F34A12537B6B5EC388502BDC2825565D2D
)
PK_G = Point(P256.curve.curve,
    0x6D1973E8554C68424FC51542FF8B0FE6A84BD7C88F2E2F19F4D0712A13604D55,
    0xE64E6122CE7A70E26F7496510EA93FB5730A9894448D1A6B4BD15DA8C08CFDC0
)

# ===================================================================
# Network Configuration
# ===================================================================
ECA_HOST = "127.0.0.1"
ECA_PORT = 8001

TMA_HOST = "127.0.0.1"
TMA_PORT = 8002

SOCKET_TIMEOUT = 10.0       # seconds
RECV_BUFFER = 65536          # bytes

# ===================================================================
# Network Simulation Parameters
# ===================================================================
# Delay ranges (in seconds)
PROPAGATION_DELAY_MIN = 0.001
PROPAGATION_DELAY_MAX = 0.010

PROCESSING_DELAY_MIN = 0.001
PROCESSING_DELAY_MAX = 0.005

QUEUING_DELAY_MIN = 0.0005
QUEUING_DELAY_MAX = 0.003

# Channel characteristics
BANDWIDTH_BPS = 6_000_000   # 6 Mbps (IEEE 802.11p typical)
PACKET_LOSS_RATE = 0.05     # 5% default loss

# ===================================================================
# Replay Protection
# ===================================================================
TIMESTAMP_MAX_AGE_SEC = 5.0  # packets older than this are rejected

# ===================================================================
# Experiment Defaults
# ===================================================================
DEFAULT_NUM_RUNS = 20
DEFAULT_NUM_VEHICLES = 5
DEFAULT_RUNS_PER_VEHICLE = 5

# ===================================================================
# Output Paths
# ===================================================================
RESULTS_DIR = "results"
CSV_DIR = "results/csv"
PLOTS_DIR = "results/plots"
