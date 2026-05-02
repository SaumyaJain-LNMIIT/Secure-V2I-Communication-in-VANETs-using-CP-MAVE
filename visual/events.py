#!/usr/bin/env python3
"""
visual/events.py — Lightweight event objects that drive the visual engine.

The ProtocolAdapter produces a timeline of these events; the Renderer
consumes them sequentially to animate the simulation.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional, Tuple

from visual.constants import (
    PACKET_VALID, PACKET_MALICIOUS, PACKET_AUTH, PACKET_TOKEN,
    SUCCESS_COLOR, FAIL_COLOR,
)


@dataclass
class VisualEvent:
    """Single visual event on the simulation timeline."""
    event_type: str          # see EVENT_* constants below
    source: str = ""         # "Vehicle", "ECA", "TMA", "Attacker"
    target: str = ""
    color: Tuple[int, int, int] = PACKET_VALID
    label: str = ""
    delay_ms: int = 0        # milliseconds to wait *before* this event fires
    duration_ms: int = 0     # how long the event's animation lasts
    extra: dict = field(default_factory=dict)


# ── Event type constants ────────────────────────────────────────────
EVENT_STATUS       = "STATUS_UPDATE"
EVENT_LOG          = "LOG_MESSAGE"
EVENT_VEHICLE_MOVE = "VEHICLE_MOVE"       # extra: {"target_x": int}
EVENT_PACKET_SEND  = "PACKET_SEND"
EVENT_AUTH_OK      = "AUTH_SUCCESS"
EVENT_AUTH_FAIL    = "AUTH_FAIL"
EVENT_TOKEN        = "TOKEN_ISSUED"
EVENT_BANNER       = "BANNER"             # extra: {"text": str}
EVENT_METRIC       = "METRIC_UPDATE"      # extra: {"field": str, "delta": int}
EVENT_ATTACKER_APPEAR = "ATTACKER_APPEAR"
EVENT_ATTACKER_HIDE   = "ATTACKER_HIDE"
EVENT_DOS_BURST    = "DOS_BURST"          # extra: {"count": int}
EVENT_WAIT         = "WAIT"               # pure delay
EVENT_SCENE_RESET  = "SCENE_RESET"


# ── Convenience builders ────────────────────────────────────────────

def ev_status(text: str, delay: int = 0) -> VisualEvent:
    return VisualEvent(EVENT_STATUS, label=text, delay_ms=delay)

def ev_log(text: str, delay: int = 0) -> VisualEvent:
    return VisualEvent(EVENT_LOG, label=text, delay_ms=delay)

def ev_vehicle_move(target_x: int, delay: int = 0) -> VisualEvent:
    return VisualEvent(EVENT_VEHICLE_MOVE, delay_ms=delay,
                       extra={"target_x": target_x})

def ev_packet(src: str, tgt: str, color, label: str, delay: int = 0) -> VisualEvent:
    return VisualEvent(EVENT_PACKET_SEND, source=src, target=tgt,
                       color=color, label=label, delay_ms=delay)

def ev_auth_ok(target: str, delay: int = 0) -> VisualEvent:
    return VisualEvent(EVENT_AUTH_OK, target=target, color=SUCCESS_COLOR,
                       delay_ms=delay)

def ev_auth_fail(target: str, label: str = "", delay: int = 0) -> VisualEvent:
    return VisualEvent(EVENT_AUTH_FAIL, target=target, color=FAIL_COLOR,
                       label=label, delay_ms=delay)

def ev_token(src: str, tgt: str, delay: int = 0) -> VisualEvent:
    return VisualEvent(EVENT_TOKEN, source=src, target=tgt,
                       color=PACKET_TOKEN, label="Auth Token", delay_ms=delay)

def ev_banner(text: str, color=SUCCESS_COLOR, delay: int = 0,
              duration: int = 2500) -> VisualEvent:
    return VisualEvent(EVENT_BANNER, color=color, label=text,
                       delay_ms=delay, duration_ms=duration,
                       extra={"text": text})

def ev_metric(field_name: str, delta: int = 1, delay: int = 0) -> VisualEvent:
    return VisualEvent(EVENT_METRIC, delay_ms=delay,
                       extra={"field": field_name, "delta": delta})

def ev_attacker_appear(delay: int = 0) -> VisualEvent:
    return VisualEvent(EVENT_ATTACKER_APPEAR, delay_ms=delay)

def ev_attacker_hide(delay: int = 0) -> VisualEvent:
    return VisualEvent(EVENT_ATTACKER_HIDE, delay_ms=delay)

def ev_dos_burst(count: int = 10, delay: int = 0) -> VisualEvent:
    return VisualEvent(EVENT_DOS_BURST, delay_ms=delay,
                       extra={"count": count})

def ev_wait(ms: int) -> VisualEvent:
    return VisualEvent(EVENT_WAIT, delay_ms=ms)

def ev_scene_reset(delay: int = 0) -> VisualEvent:
    return VisualEvent(EVENT_SCENE_RESET, delay_ms=delay)
