#!/usr/bin/env python3
"""
vansec/network/channel.py — TCP socket transport with NetworkSimulator integration.

Provides length-prefixed send/recv helpers and a simple server loop.
A NetworkSimulator can be attached module-wide so that all send_message
calls automatically go through the simulator (delay + packet loss).

Simulator integration
---------------------
    from vansec.network import channel
    from vansec.network.simulator import NetworkSimulator

    sim = NetworkSimulator(loss_rate=0.05)
    channel.attach_simulator(sim, sender="Vehicle", receiver="ECA")
    channel.send_message(sock, my_msg)   # delay applied, may raise on loss
    channel.detach_simulator()
"""

from __future__ import annotations

import socket
import struct
import pickle
import time
from typing import Any, Callable, Optional, Tuple

import config

__all__ = [
    "send_message",
    "recv_message",
    "connect",
    "listen_and_serve",
    "attach_simulator",
    "detach_simulator",
]

# 4-byte unsigned-int header for message length
_HEADER_FMT = "!I"
_HEADER_SIZE = struct.calcsize(_HEADER_FMT)

# Module-level simulator state (None = bypass simulation)
_active_sim = None
_sim_sender: str = "unknown"
_sim_receiver: str = "unknown"


# ===================================================================
# Simulator attachment API
# ===================================================================

def attach_simulator(sim, sender: str = "Vehicle", receiver: str = "Server") -> None:
    """
    Register *sim* as the active NetworkSimulator for this module.

    All subsequent ``send_message`` calls will route through
    ``sim.transmit()``, applying realistic delay and packet loss.

    Parameters
    ----------
    sim : NetworkSimulator
        The simulator instance to use.
    sender : str
        Label logged as the packet sender (e.g. ``"Vehicle"``).
    receiver : str
        Label logged as the packet receiver (e.g. ``"ECA"``).
    """
    global _active_sim, _sim_sender, _sim_receiver
    _active_sim = sim
    _sim_sender = sender
    _sim_receiver = receiver


def detach_simulator() -> None:
    """Remove the active simulator; subsequent sends are un-simulated."""
    global _active_sim
    _active_sim = None


# ===================================================================
# Send / receive with length prefix
# ===================================================================

def send_message(sock: socket.socket, msg: Any) -> int:
    """
    Serialize *msg* with pickle, pass through the simulator (if attached),
    prepend a 4-byte length header, and send over *sock*.

    If the simulator drops the packet a ``ConnectionError`` is raised so
    that the caller (Vehicle / ECA / TMA) can treat it like a real loss.

    Returns the total number of bytes sent (header + payload).
    """
    payload = pickle.dumps(msg)

    if _active_sim is not None:
        # Run through the simulator: computes delays, models packet loss
        result, _delay, _log = _active_sim.transmit(
            msg, _sim_sender, _sim_receiver
        )
        # `time.sleep` already called inside transmit() for non-lost packets
        if result is None:
            # Packet was lost — signal to the caller
            raise ConnectionError(
                f"[SIMULATOR] Packet dropped ({_sim_sender} → {_sim_receiver})"
            )
        # Use the simulator's serialized bytes so size accounting is consistent
        payload = result

    header = struct.pack(_HEADER_FMT, len(payload))
    sock.sendall(header + payload)
    return _HEADER_SIZE + len(payload)


def recv_message(sock: socket.socket) -> Any:
    """
    Receive a length-prefixed message and deserialize it.

    Returns the deserialized Python object.

    Raises
    ------
    ConnectionError
        If the peer closed the connection before sending a full message.
    """
    header_data = _recv_exactly(sock, _HEADER_SIZE)
    if not header_data:
        raise ConnectionError("Peer closed connection (no header)")
    (payload_len,) = struct.unpack(_HEADER_FMT, header_data)
    payload = _recv_exactly(sock, payload_len)
    if not payload:
        raise ConnectionError("Peer closed connection (incomplete payload)")
    return pickle.loads(payload)


def _recv_exactly(sock: socket.socket, n: int) -> Optional[bytes]:
    """Read exactly *n* bytes from *sock*; return ``None`` on EOF."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


# ===================================================================
# Connection helpers
# ===================================================================

def connect(
    host: str = config.ECA_HOST,
    port: int = config.ECA_PORT,
    timeout: float = config.SOCKET_TIMEOUT,
) -> socket.socket:
    """Create a TCP client socket and connect to (*host*, *port*)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((host, port))
    return sock


def listen_and_serve(
    handler: Callable[[socket.socket, Tuple[str, int]], None],
    host: str = "127.0.0.1",
    port: int = 8001,
    backlog: int = 8,
) -> None:
    """
    Bind a TCP server to (*host*, *port*) and call *handler(conn, addr)*
    for each accepted connection.

    Runs until ``KeyboardInterrupt``.
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(backlog)
    print(f"[CHANNEL] Listening on {host}:{port} ...")

    try:
        while True:
            conn, addr = srv.accept()
            try:
                handler(conn, addr)
            except Exception as exc:
                print(f"[CHANNEL] Error handling {addr}: {exc}")
            finally:
                conn.close()
    except KeyboardInterrupt:
        print("\n[CHANNEL] Server shutting down.")
    finally:
        srv.close()
