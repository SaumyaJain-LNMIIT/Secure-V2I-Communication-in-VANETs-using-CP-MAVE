#!/usr/bin/env python3
"""
visual/renderer.py — Main Pygame rendering engine for VANSEC visualization.

Consumes VisualEvent timelines and animates the simulation scene.
"""

from __future__ import annotations

import math
from typing import List, Optional

import pygame

from visual.constants import (
    WINDOW_W, WINDOW_H, FPS, TITLE,
    BG_COLOR, ROAD_COLOR, ROAD_SHOULDER, ROAD_EDGE, LANE_MARKING,
    ROAD_Y, ROAD_H, ROAD_TOP, ROAD_BOT, LANE_DASH_W, LANE_DASH_H, LANE_GAP,
    SCENE_W, STATUS_BAR_H, EVENT_LOG_H,
    VEHICLE_START_X, VEHICLE_Y, VEHICLE_W, VEHICLE_H,
    ECA_X, ECA_Y, ECA_W, ECA_H,
    TMA_X, TMA_Y, TMA_W, TMA_H,
    ATTACKER_X, ATTACKER_Y, ATTACKER_W, ATTACKER_H,
    VEHICLE_COLOR, ECA_COLOR, TMA_COLOR, ATTACKER_COLOR,
    PACKET_VALID, PACKET_MALICIOUS, PACKET_AUTH, PACKET_TOKEN,
    SUCCESS_COLOR, FAIL_COLOR, WARNING_COLOR,
    TEXT_PRIMARY, TEXT_SECONDARY, PANEL_BG,
    FONT_FAMILY, FONT_FALLBACK,
    FONT_SIZE_TITLE, FONT_SIZE_LABEL, FONT_SIZE_SMALL,
    FONT_SIZE_BANNER, FONT_SIZE_METRIC, FONT_SIZE_LOG,
    VEHICLE_DRIVE_SPEED,
)
from visual.events import (
    VisualEvent,
    EVENT_STATUS, EVENT_LOG, EVENT_VEHICLE_MOVE, EVENT_PACKET_SEND,
    EVENT_AUTH_OK, EVENT_AUTH_FAIL, EVENT_TOKEN, EVENT_BANNER,
    EVENT_METRIC, EVENT_ATTACKER_APPEAR, EVENT_ATTACKER_HIDE,
    EVENT_DOS_BURST, EVENT_WAIT, EVENT_SCENE_RESET,
)
from visual.entities import (
    VehicleSprite, BuildingSprite, PacketSprite,
    DosBurstManager, BannerOverlay,
)
from visual.ui_panels import StatusBar, MetricsPanel, EventLog


def _try_font(name: str, size: int) -> pygame.font.Font:
    try:
        return pygame.font.SysFont(name, size)
    except Exception:
        return pygame.font.SysFont(FONT_FALLBACK, size)


class Renderer:
    """
    The main visual engine. Receives event lists, processes them, draws the scene.
    """

    def __init__(self):
        self.screen: Optional[pygame.Surface] = None
        self.clock: Optional[pygame.time.Clock] = None
        self.fullscreen = False
        self.running = True
        self.paused = False

        # Fonts (initialized in init_display)
        self.font_title = None
        self.font_label = None
        self.font_small = None
        self.font_banner = None
        self.font_metric = None
        self.font_log = None

        # Scene entities
        self.vehicle = VehicleSprite(VEHICLE_START_X, VEHICLE_Y,
                                     VEHICLE_COLOR, "Vehicle")
        self.eca = BuildingSprite(ECA_X, ECA_Y, ECA_W, ECA_H,
                                  ECA_COLOR, "ECA", "Auth Authority")
        self.tma = BuildingSprite(TMA_X, TMA_Y, TMA_W, TMA_H,
                                  TMA_COLOR, "TMA", "Msg Authority")
        self.attacker = VehicleSprite(ATTACKER_X, ATTACKER_Y,
                                      ATTACKER_COLOR, "Attacker")
        self.attacker.visible = False

        # Active animations
        self.packets: List[PacketSprite] = []
        self.dos_burst: Optional[DosBurstManager] = None
        self.banner = BannerOverlay()

        # UI
        self.status_bar = StatusBar()
        self.metrics = MetricsPanel()
        self.event_log = EventLog()

        # Event timeline
        self.events: List[VisualEvent] = []
        self.event_idx = 0
        self.event_timer = 0.0    # seconds since last event fired

        # Road animation offset for dashes
        self._road_offset = 0.0

        # Connection lines animation
        self._conn_alpha = 0.0
        self._conn_src = (0, 0)
        self._conn_dst = (0, 0)

    # ================================================================
    # Initialization
    # ================================================================

    def init_display(self):
        pygame.init()
        pygame.display.set_caption(TITLE)
        self.screen = pygame.display.set_mode((WINDOW_W, WINDOW_H))
        self.clock = pygame.time.Clock()

        self.font_title = _try_font(FONT_FAMILY, FONT_SIZE_TITLE)
        self.font_label = _try_font(FONT_FAMILY, FONT_SIZE_LABEL)
        self.font_small = _try_font(FONT_FAMILY, FONT_SIZE_SMALL)
        self.font_banner = _try_font(FONT_FAMILY, FONT_SIZE_BANNER)
        self.font_metric = _try_font(FONT_FAMILY, FONT_SIZE_METRIC)
        self.font_log = _try_font(FONT_FAMILY, FONT_SIZE_LOG)

    def toggle_fullscreen(self):
        self.fullscreen = not self.fullscreen
        if self.fullscreen:
            self.screen = pygame.display.set_mode((0, 0), pygame.FULLSCREEN)
        else:
            self.screen = pygame.display.set_mode((WINDOW_W, WINDOW_H))

    # ================================================================
    # Scene Reset
    # ================================================================

    def reset_scene(self):
        """Reset all entities to initial positions."""
        self.vehicle.x = VEHICLE_START_X
        self.vehicle.target_x = VEHICLE_START_X
        self.vehicle.visible = True
        self.vehicle.pulse = 0
        self.attacker.visible = False
        self.attacker.x = ATTACKER_X
        self.attacker.pulse = 0
        self.eca.pulse = 0
        self.tma.pulse = 0
        self.packets.clear()
        self.dos_burst = None
        self.banner.active = False
        self.event_log.clear()

    def full_reset(self):
        """Full reset including metrics."""
        self.reset_scene()
        self.metrics.reset()
        self.events.clear()
        self.event_idx = 0
        self.event_timer = 0.0

    # ================================================================
    # Load event timeline
    # ================================================================

    def load_events(self, events: List[VisualEvent]):
        self.events = events
        self.event_idx = 0
        self.event_timer = 0.0

    # ================================================================
    # Entity position lookups
    # ================================================================

    def _entity_center(self, name: str):
        name = name.lower()
        if name == "vehicle":
            return self.vehicle.center
        elif name == "eca":
            return self.eca.center
        elif name == "tma":
            return self.tma.center
        elif name == "attacker":
            return self.attacker.center
        return (SCENE_W // 2, ROAD_Y)

    # ================================================================
    # Process one event
    # ================================================================

    def _fire_event(self, ev: VisualEvent):
        et = ev.event_type

        if et == EVENT_STATUS:
            self.status_bar.status_text = ev.label

        elif et == EVENT_LOG:
            self.event_log.add(ev.label)

        elif et == EVENT_VEHICLE_MOVE:
            self.vehicle.target_x = ev.extra.get("target_x", self.vehicle.x)

        elif et == EVENT_PACKET_SEND:
            src = self._entity_center(ev.source)
            dst = self._entity_center(ev.target)
            p = PacketSprite(src, dst, ev.color, ev.label)
            self.packets.append(p)

        elif et == EVENT_AUTH_OK:
            target = ev.target.lower()
            if target == "vehicle":
                self.vehicle.trigger_pulse(SUCCESS_COLOR)
            elif target == "eca":
                self.eca.trigger_pulse(SUCCESS_COLOR)
            elif target == "tma":
                self.tma.trigger_pulse(SUCCESS_COLOR)

        elif et == EVENT_AUTH_FAIL:
            target = ev.target.lower()
            if target == "tma":
                self.tma.trigger_pulse(FAIL_COLOR)
            elif target == "eca":
                self.eca.trigger_pulse(FAIL_COLOR)

        elif et == EVENT_TOKEN:
            src = self._entity_center(ev.source)
            dst = self._entity_center(ev.target)
            p = PacketSprite(src, dst, PACKET_TOKEN, ev.label)
            self.packets.append(p)

        elif et == EVENT_BANNER:
            text = ev.extra.get("text", ev.label)
            dur = ev.duration_ms if ev.duration_ms > 0 else 2500
            self.banner.show(text, ev.color, dur)

        elif et == EVENT_METRIC:
            field = ev.extra.get("field", "")
            delta = ev.extra.get("delta", 1)
            if field == "accepted":
                self.metrics.accepted += delta
            elif field == "rejected":
                self.metrics.rejected += delta
            elif field == "attacks":
                self.metrics.attacks += delta

        elif et == EVENT_ATTACKER_APPEAR:
            self.attacker.visible = True

        elif et == EVENT_ATTACKER_HIDE:
            self.attacker.visible = False

        elif et == EVENT_DOS_BURST:
            count = ev.extra.get("count", 10)
            src = self._entity_center("attacker")
            dst = self._entity_center("tma")
            self.dos_burst = DosBurstManager(src, dst, count)

        elif et == EVENT_SCENE_RESET:
            self.reset_scene()

        elif et == EVENT_WAIT:
            pass  # delay is handled by the timer

    # ================================================================
    # Update loop
    # ================================================================

    def update(self, dt: float):
        if self.paused:
            return

        # Process event timeline
        if self.event_idx < len(self.events):
            self.event_timer += dt * 1000  # convert to ms
            ev = self.events[self.event_idx]
            if self.event_timer >= ev.delay_ms:
                self._fire_event(ev)
                self.event_timer = 0.0
                self.event_idx += 1

        # Update entities
        self.vehicle.update(dt)
        self.attacker.update(dt)
        self.eca.update(dt)
        self.tma.update(dt)
        self.banner.update(dt)

        # Update packets
        for p in self.packets:
            p.update(dt)
        self.packets = [p for p in self.packets if p.alive or p.progress < 1.05]
        # Clean up finished packets
        self.packets = [p for p in self.packets if p.alive]

        # DoS burst
        if self.dos_burst is not None:
            self.dos_burst.update(dt)
            if not self.dos_burst.active:
                self.dos_burst = None

        # Road dash animation
        self._road_offset = (self._road_offset + dt * 30) % (LANE_DASH_W + LANE_GAP)

    # ================================================================
    # Draw
    # ================================================================

    def draw(self):
        self.screen.fill(BG_COLOR)

        # Road
        self._draw_road()

        # Connection lines (decorative)
        self._draw_connection_lines()

        # Entities
        self.eca.draw(self.screen, self.font_label, self.font_small)
        self.tma.draw(self.screen, self.font_label, self.font_small)
        self.vehicle.draw(self.screen, self.font_small)
        if self.attacker.visible:
            self.attacker.draw(self.screen, self.font_small)

        # Packets
        for p in self.packets:
            p.draw(self.screen, self.font_small)

        # DoS burst
        if self.dos_burst is not None:
            self.dos_burst.draw(self.screen, self.font_small)

        # Banner overlay
        self.banner.draw(self.screen, self.font_banner, SCENE_W, WINDOW_H)

        # UI panels (drawn on top)
        self.status_bar.draw(self.screen, self.font_title, self.font_small)
        self.metrics.draw(self.screen, self.font_label, self.font_metric,
                          self.font_small)
        self.event_log.draw(self.screen, self.font_log)

        # Pause indicator
        if self.paused:
            self._draw_pause_overlay()

        pygame.display.flip()

    # ── Road ────────────────────────────────────────────────────────

    def _draw_road(self):
        # Road shoulders
        pygame.draw.rect(self.screen, ROAD_SHOULDER,
                         (0, ROAD_TOP - 6, SCENE_W, ROAD_H + 12))
        # Road surface
        pygame.draw.rect(self.screen, ROAD_COLOR,
                         (0, ROAD_TOP, SCENE_W, ROAD_H))
        # Edge lines
        pygame.draw.line(self.screen, ROAD_EDGE,
                         (0, ROAD_TOP), (SCENE_W, ROAD_TOP), 2)
        pygame.draw.line(self.screen, ROAD_EDGE,
                         (0, ROAD_BOT), (SCENE_W, ROAD_BOT), 2)

        # Center dashes
        dash_y = ROAD_Y
        x = -self._road_offset
        dash_surf = pygame.Surface((LANE_DASH_W, LANE_DASH_H), pygame.SRCALPHA)
        dash_surf.fill((255, 255, 255, 50))
        while x < SCENE_W:
            self.screen.blit(dash_surf, (int(x), dash_y - 1))
            x += LANE_DASH_W + LANE_GAP

    # ── Decorative connection lines ─────────────────────────────────

    def _draw_connection_lines(self):
        """Draw subtle dashed lines from ECA/TMA down to the road."""
        for entity in [self.eca, self.tma]:
            if not entity.visible:
                continue
            cx = int(entity.x + entity.w / 2)
            ey = int(entity.y + entity.h)
            ry = ROAD_TOP

            # Dashed vertical line
            y = ey
            while y < ry:
                seg_end = min(y + 6, ry)
                line_surf = pygame.Surface((2, seg_end - y), pygame.SRCALPHA)
                line_surf.fill((*entity.color, 40))
                self.screen.blit(line_surf, (cx - 1, y))
                y += 12

    # ── Pause overlay ───────────────────────────────────────────────

    def _draw_pause_overlay(self):
        overlay = pygame.Surface((SCENE_W, WINDOW_H), pygame.SRCALPHA)
        overlay.fill((0, 0, 0, 100))
        self.screen.blit(overlay, (0, 0))
        txt = self.font_banner.render("PAUSED", True, TEXT_PRIMARY)
        x = (SCENE_W - txt.get_width()) // 2
        y = (WINDOW_H - txt.get_height()) // 2
        self.screen.blit(txt, (x, y))
        hint = self.font_small.render("Press SPACE to resume", True, TEXT_SECONDARY)
        self.screen.blit(hint, ((SCENE_W - hint.get_width()) // 2, y + 50))

    # ================================================================
    # Timeline status
    # ================================================================

    @property
    def timeline_done(self) -> bool:
        return self.event_idx >= len(self.events) and not self.banner.active

    @property
    def timeline_progress(self) -> float:
        if not self.events:
            return 1.0
        return self.event_idx / len(self.events)
