#!/usr/bin/env python3
"""
visual/entities.py — Pygame drawable entities: vehicles, buildings, packets.
"""

from __future__ import annotations

import math
from typing import List, Optional, Tuple

import pygame

from visual.constants import (
    VEHICLE_COLOR, ECA_COLOR, TMA_COLOR, ATTACKER_COLOR,
    PACKET_VALID, PACKET_MALICIOUS, PACKET_AUTH, PACKET_TOKEN,
    TEXT_PRIMARY, TEXT_SECONDARY, PANEL_BG, PANEL_BORDER,
    PACKET_RADIUS, PACKET_TRAIL_COUNT, PACKET_SPEED,
    VEHICLE_W, VEHICLE_H,
    SUCCESS_COLOR, FAIL_COLOR,
    BANNER_DURATION_MS, BANNER_FADE_MS,
)


def _lerp(a: float, b: float, t: float) -> float:
    return a + (b - a) * min(max(t, 0.0), 1.0)


def _ease_out(t: float) -> float:
    return 1 - (1 - t) ** 3


def _draw_rounded_rect(surface, color, rect, radius=10, border=0, border_color=None):
    """Draw a rounded rectangle with optional border."""
    r = pygame.Rect(rect)
    if border > 0 and border_color:
        pygame.draw.rect(surface, border_color, r, border_radius=radius)
        inner = r.inflate(-border * 2, -border * 2)
        pygame.draw.rect(surface, color, inner, border_radius=max(radius - border, 2))
    else:
        pygame.draw.rect(surface, color, r, border_radius=radius)


def _glow_surface(w: int, h: int, color: Tuple[int, int, int], alpha: int = 40,
                  radius: int = 8) -> pygame.Surface:
    """Create a soft glow surface."""
    s = pygame.Surface((w + radius * 2, h + radius * 2), pygame.SRCALPHA)
    for i in range(radius, 0, -1):
        a = int(alpha * (i / radius))
        c = (*color, a)
        r = pygame.Rect(radius - i, radius - i, w + i * 2, h + i * 2)
        pygame.draw.rect(s, c, r, border_radius=i + 4)
    return s


# ===================================================================
# Vehicle Sprite
# ===================================================================

class VehicleSprite:
    def __init__(self, x: float, y: float, color=VEHICLE_COLOR, label: str = "Vehicle"):
        self.x = x
        self.y = y
        self.target_x = x
        self.color = color
        self.label = label
        self.w = VEHICLE_W
        self.h = VEHICLE_H
        self.pulse = 0.0           # 0..1 for glow effect
        self.pulse_color = SUCCESS_COLOR
        self.visible = True

    @property
    def center(self) -> Tuple[float, float]:
        return (self.x + self.w / 2, self.y + self.h / 2)

    def move_toward(self, speed: float = 2.5):
        if abs(self.x - self.target_x) > 1:
            direction = 1 if self.target_x > self.x else -1
            self.x += direction * speed

    def trigger_pulse(self, color=SUCCESS_COLOR):
        self.pulse = 1.0
        self.pulse_color = color

    def update(self, dt: float):
        self.move_toward()
        if self.pulse > 0:
            self.pulse = max(0, self.pulse - dt * 2)

    def draw(self, surface: pygame.Surface, font_small: pygame.font.Font):
        if not self.visible:
            return
        # Glow
        if self.pulse > 0:
            glow = _glow_surface(self.w, self.h, self.pulse_color,
                                  int(50 * self.pulse), 12)
            surface.blit(glow, (self.x - 12, self.y - 12))

        # Car body
        body_rect = (self.x, self.y, self.w, self.h)
        _draw_rounded_rect(surface, self.color, body_rect, radius=8)

        # Windshield
        ws_rect = (self.x + self.w - 22, self.y + 4, 18, self.h - 8)
        darker = tuple(max(0, c - 60) for c in self.color)
        _draw_rounded_rect(surface, darker, ws_rect, radius=4)

        # Wheels
        wheel_color = (40, 40, 50)
        pygame.draw.circle(surface, wheel_color,
                           (int(self.x + 14), int(self.y + self.h)), 6)
        pygame.draw.circle(surface, wheel_color,
                           (int(self.x + self.w - 14), int(self.y + self.h)), 6)

        # Label
        label_surf = font_small.render(self.label, True, TEXT_PRIMARY)
        lx = self.x + (self.w - label_surf.get_width()) / 2
        ly = self.y - 20
        surface.blit(label_surf, (lx, ly))


# ===================================================================
# Building Sprite (ECA / TMA)
# ===================================================================

class BuildingSprite:
    def __init__(self, x: float, y: float, w: float, h: float,
                 color: Tuple[int, int, int], label: str, sublabel: str = ""):
        self.x = x
        self.y = y
        self.w = w
        self.h = h
        self.color = color
        self.label = label
        self.sublabel = sublabel
        self.pulse = 0.0
        self.pulse_color = SUCCESS_COLOR
        self.visible = True

    @property
    def center(self) -> Tuple[float, float]:
        return (self.x + self.w / 2, self.y + self.h / 2)

    def trigger_pulse(self, color=SUCCESS_COLOR):
        self.pulse = 1.0
        self.pulse_color = color

    def update(self, dt: float):
        if self.pulse > 0:
            self.pulse = max(0, self.pulse - dt * 1.8)

    def draw(self, surface: pygame.Surface, font_label: pygame.font.Font,
             font_small: pygame.font.Font):
        if not self.visible:
            return
        # Glow
        if self.pulse > 0:
            glow = _glow_surface(int(self.w), int(self.h), self.pulse_color,
                                  int(55 * self.pulse), 14)
            surface.blit(glow, (self.x - 14, self.y - 14))

        # Main body
        _draw_rounded_rect(surface, self.color,
                           (self.x, self.y, self.w, self.h),
                           radius=10, border=2,
                           border_color=tuple(min(255, c + 40) for c in self.color))

        # Icon: simple antenna / server lines
        cx = int(self.x + self.w / 2)
        cy = int(self.y + self.h / 2)
        line_col = tuple(min(255, c + 80) for c in self.color)
        for offset in (-12, 0, 12):
            pygame.draw.line(surface, line_col,
                             (cx + offset - 8, cy), (cx + offset + 8, cy), 2)

        # Label
        label_surf = font_label.render(self.label, True, TEXT_PRIMARY)
        lx = self.x + (self.w - label_surf.get_width()) / 2
        surface.blit(label_surf, (lx, self.y + self.h + 6))

        if self.sublabel:
            sub_surf = font_small.render(self.sublabel, True, TEXT_SECONDARY)
            sx = self.x + (self.w - sub_surf.get_width()) / 2
            surface.blit(sub_surf, (sx, self.y + self.h + 24))


# ===================================================================
# Packet Sprite (animated)
# ===================================================================

class PacketSprite:
    def __init__(self, start: Tuple[float, float], end: Tuple[float, float],
                 color: Tuple[int, int, int], label: str = "",
                 speed: float = PACKET_SPEED):
        self.sx, self.sy = start
        self.ex, self.ey = end
        self.color = color
        self.label = label
        self.speed = speed
        self.progress = 0.0        # 0..1
        self.alive = True
        self.trail: List[Tuple[float, float]] = []

    @property
    def pos(self) -> Tuple[float, float]:
        t = _ease_out(self.progress)
        return (_lerp(self.sx, self.ex, t), _lerp(self.sy, self.ey, t))

    def update(self, dt: float):
        if not self.alive:
            return
        dist = math.hypot(self.ex - self.sx, self.ey - self.sy)
        if dist < 1:
            self.alive = False
            return
        step = (self.speed / dist) * 60 * dt
        self.trail.append(self.pos)
        if len(self.trail) > PACKET_TRAIL_COUNT:
            self.trail.pop(0)
        self.progress += step
        if self.progress >= 1.0:
            self.progress = 1.0
            self.alive = False

    def draw(self, surface: pygame.Surface, font_small: pygame.font.Font):
        # Trail
        for i, (tx, ty) in enumerate(self.trail):
            alpha_frac = (i + 1) / (len(self.trail) + 1)
            r = max(3, int(PACKET_RADIUS * 0.5 * alpha_frac))
            trail_surf = pygame.Surface((r * 2, r * 2), pygame.SRCALPHA)
            a = int(120 * alpha_frac)
            pygame.draw.circle(trail_surf, (*self.color, a), (r, r), r)
            surface.blit(trail_surf, (tx - r, ty - r))

        # Main packet circle
        x, y = self.pos
        # Outer glow
        glow_r = PACKET_RADIUS + 6
        glow_surf = pygame.Surface((glow_r * 2, glow_r * 2), pygame.SRCALPHA)
        pygame.draw.circle(glow_surf, (*self.color, 35), (glow_r, glow_r), glow_r)
        surface.blit(glow_surf, (x - glow_r, y - glow_r))

        pygame.draw.circle(surface, self.color, (int(x), int(y)), PACKET_RADIUS)
        inner_col = tuple(min(255, c + 60) for c in self.color)
        pygame.draw.circle(surface, inner_col, (int(x), int(y)), PACKET_RADIUS - 3)

        # Label
        if self.label:
            lbl = font_small.render(self.label, True, TEXT_PRIMARY)
            surface.blit(lbl, (x - lbl.get_width() / 2, y - PACKET_RADIUS - 18))


# ===================================================================
# DoS Burst Packets (multiple rapid packets)
# ===================================================================

class DosBurstManager:
    """Manages multiple rapid red packets for DoS flood animation."""

    def __init__(self, start: Tuple[float, float], end: Tuple[float, float],
                 count: int = 12):
        self.packets: List[PacketSprite] = []
        self.pending = count
        self.start = start
        self.end = end
        self.spawn_timer = 0.0
        self.spawn_interval = 0.12   # seconds between spawns
        self.rejected_count = 0
        self.reject_markers: List[Tuple[float, float, float]] = []  # x, y, alpha

    @property
    def active(self) -> bool:
        return self.pending > 0 or any(p.alive for p in self.packets)

    def update(self, dt: float):
        self.spawn_timer += dt
        if self.pending > 0 and self.spawn_timer >= self.spawn_interval:
            self.spawn_timer = 0.0
            self.pending -= 1
            # Slightly randomized start
            import random
            ofs_y = random.randint(-20, 20)
            p = PacketSprite(
                (self.start[0], self.start[1] + ofs_y), self.end,
                PACKET_MALICIOUS, "", speed=PACKET_SPEED * 1.5
            )
            self.packets.append(p)

        for p in self.packets:
            p.update(dt)
            if not p.alive and p.progress >= 1.0:
                # Mark as rejected
                self.reject_markers.append((self.end[0], self.end[1], 1.0))
                self.rejected_count += 1
                p.progress = 2.0  # sentinel so we don't re-count

        # Fade reject markers
        self.reject_markers = [(x, y, max(0, a - dt * 1.5))
                               for x, y, a in self.reject_markers if a > 0]

    def draw(self, surface: pygame.Surface, font_small: pygame.font.Font):
        for p in self.packets:
            if p.alive:
                p.draw(surface, font_small)

        # Red X markers at TMA
        for x, y, alpha in self.reject_markers:
            if alpha > 0:
                s = pygame.Surface((24, 24), pygame.SRCALPHA)
                a = int(200 * alpha)
                col = (*FAIL_COLOR, a)
                pygame.draw.line(s, col, (4, 4), (20, 20), 3)
                pygame.draw.line(s, col, (20, 4), (4, 20), 3)
                surface.blit(s, (x - 12, y - 12 + len(self.reject_markers) % 5 * 3))


# ===================================================================
# Warning / Success Banner
# ===================================================================

class BannerOverlay:
    """Large centered text banner with colored background."""

    def __init__(self):
        self.text = ""
        self.color = SUCCESS_COLOR
        self.timer = 0.0
        self.duration = 2.5
        self.active = False

    def show(self, text: str, color: Tuple[int, int, int], duration_ms: int = 2500):
        self.text = text
        self.color = color
        self.duration = duration_ms / 1000.0
        self.timer = 0.0
        self.active = True

    def update(self, dt: float):
        if self.active:
            self.timer += dt
            if self.timer >= self.duration:
                self.active = False

    def draw(self, surface: pygame.Surface, font_banner: pygame.font.Font,
             scene_w: int, scene_h: int):
        if not self.active:
            return

        # Fade factor
        fade_in = min(1.0, self.timer / 0.3)
        fade_out = min(1.0, (self.duration - self.timer) / 0.3) if self.timer > self.duration - 0.3 else 1.0
        alpha = int(220 * fade_in * fade_out)

        # Background bar
        bar_h = 100
        bar_y = scene_h // 2 - bar_h // 2
        bg = pygame.Surface((scene_w, bar_h), pygame.SRCALPHA)
        bg.fill((*self.color[:3], int(alpha * 0.35)))
        surface.blit(bg, (0, bar_y))

        # Border lines
        border_col = (*self.color[:3], min(255, alpha))
        border_s = pygame.Surface((scene_w, 2), pygame.SRCALPHA)
        border_s.fill(border_col)
        surface.blit(border_s, (0, bar_y))
        surface.blit(border_s, (0, bar_y + bar_h - 2))

        # Text (support multi-line)
        lines = self.text.split("\n")
        total_h = len(lines) * (font_banner.get_height() + 4)
        start_y = bar_y + (bar_h - total_h) // 2
        for i, line in enumerate(lines):
            txt = font_banner.render(line, True, TEXT_PRIMARY)
            tx = (scene_w - txt.get_width()) // 2
            ty = start_y + i * (font_banner.get_height() + 4)
            # Drop shadow
            shadow = font_banner.render(line, True, (0, 0, 0))
            surface.blit(shadow, (tx + 2, ty + 2))
            surface.blit(txt, (tx, ty))
