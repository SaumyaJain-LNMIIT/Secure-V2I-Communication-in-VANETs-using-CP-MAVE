#!/usr/bin/env python3
"""
visual/ui_panels.py — HUD panels: status bar, metrics, event log, controls hint.
"""

from __future__ import annotations

import pygame
from typing import List, Tuple

from visual.constants import (
    WINDOW_W, WINDOW_H, SCENE_W, STATUS_BAR_H, EVENT_LOG_H,
    METRICS_PANEL_W, PANEL_BG, PANEL_BORDER,
    TEXT_PRIMARY, TEXT_SECONDARY, TEXT_ACCENT,
    SUCCESS_COLOR, FAIL_COLOR, WARNING_COLOR,
    FONT_SIZE_TITLE, FONT_SIZE_LABEL, FONT_SIZE_SMALL,
    FONT_SIZE_METRIC, FONT_SIZE_LOG,
)


# ===================================================================
# Status Bar (top)
# ===================================================================

class StatusBar:
    def __init__(self):
        self.mode_text = "Normal Mode"
        self.status_text = "Initializing…"
        self.fps = 0

    def update(self, fps: float):
        self.fps = int(fps)

    def draw(self, surface: pygame.Surface, font_title: pygame.font.Font,
             font_small: pygame.font.Font):
        # Background
        bar = pygame.Surface((WINDOW_W, STATUS_BAR_H), pygame.SRCALPHA)
        bar.fill((*PANEL_BG, 230))
        surface.blit(bar, (0, 0))

        # Bottom border
        pygame.draw.line(surface, PANEL_BORDER, (0, STATUS_BAR_H - 1),
                         (WINDOW_W, STATUS_BAR_H - 1), 1)

        # Left: VANSEC title
        title = font_title.render("VANSEC", True, TEXT_ACCENT)
        surface.blit(title, (16, (STATUS_BAR_H - title.get_height()) // 2))

        # Center: mode
        mode = font_title.render(self.mode_text, True, TEXT_PRIMARY)
        mx = (SCENE_W - mode.get_width()) // 2
        surface.blit(mode, (mx, (STATUS_BAR_H - mode.get_height()) // 2))

        # Status text
        if self.status_text:
            st = font_small.render(self.status_text, True, TEXT_SECONDARY)
            surface.blit(st, (mx, STATUS_BAR_H - st.get_height() - 2))

        # Right: FPS
        fps_text = font_small.render(f"{self.fps} FPS", True, TEXT_SECONDARY)
        surface.blit(fps_text, (SCENE_W - fps_text.get_width() - 12,
                                (STATUS_BAR_H - fps_text.get_height()) // 2))


# ===================================================================
# Metrics Panel (right side)
# ===================================================================

class MetricsPanel:
    def __init__(self):
        self.accepted = 0
        self.rejected = 0
        self.attacks = 0
        self.latency_ms = 0.0

    def reset(self):
        self.accepted = 0
        self.rejected = 0
        self.attacks = 0
        self.latency_ms = 0.0

    def draw(self, surface: pygame.Surface, font_label: pygame.font.Font,
             font_metric: pygame.font.Font, font_small: pygame.font.Font):
        x = SCENE_W
        y = 0
        w = METRICS_PANEL_W
        h = WINDOW_H

        # Background
        panel = pygame.Surface((w, h), pygame.SRCALPHA)
        panel.fill((*PANEL_BG, 240))
        surface.blit(panel, (x, y))

        # Left border
        pygame.draw.line(surface, PANEL_BORDER, (x, 0), (x, h), 1)

        # Title
        title = font_label.render("LIVE METRICS", True, TEXT_ACCENT)
        surface.blit(title, (x + (w - title.get_width()) // 2, 14))

        # Divider
        pygame.draw.line(surface, PANEL_BORDER, (x + 16, 40), (x + w - 16, 40), 1)

        # Metrics rows
        row_y = 56
        row_h = 60

        self._draw_metric(surface, font_metric, font_label,
                          x + 16, row_y, "Accepted", str(self.accepted),
                          SUCCESS_COLOR)
        row_y += row_h
        self._draw_metric(surface, font_metric, font_label,
                          x + 16, row_y, "Rejected", str(self.rejected),
                          FAIL_COLOR)
        row_y += row_h
        self._draw_metric(surface, font_metric, font_label,
                          x + 16, row_y, "Attacks", str(self.attacks),
                          WARNING_COLOR)
        row_y += row_h
        self._draw_metric(surface, font_metric, font_label,
                          x + 16, row_y, "Latency",
                          f"{self.latency_ms:.1f} ms", TEXT_ACCENT)

        # Divider
        row_y += row_h + 10
        pygame.draw.line(surface, PANEL_BORDER, (x + 16, row_y),
                         (x + w - 16, row_y), 1)

        # Detection rate
        row_y += 16
        total_attacks = self.rejected + self.attacks  # approximate
        if self.attacks > 0:
            rate = (self.rejected / max(1, self.rejected)) * 100
            rate_text = f"{rate:.0f}%"
        else:
            rate_text = "—"
        det_label = font_small.render("Detection Rate", True, TEXT_SECONDARY)
        surface.blit(det_label, (x + 16, row_y))
        det_val = font_label.render(rate_text, True, SUCCESS_COLOR)
        surface.blit(det_val, (x + w - 16 - det_val.get_width(), row_y))

        # Divider
        row_y += 44
        pygame.draw.line(surface, PANEL_BORDER, (x + 16, row_y),
                         (x + w - 16, row_y), 1)

        # Controls section
        row_y += 14
        ctrl_title = font_small.render("CONTROLS", True, TEXT_ACCENT)
        surface.blit(ctrl_title, (x + (w - ctrl_title.get_width()) // 2, row_y))
        row_y += 22

        controls = [
            ("1", "Normal"),
            ("2", "Replay Attack"),
            ("3", "Tamper Attack"),
            ("4", "Impersonation"),
            ("5", "DoS Flood"),
            ("SPACE", "Pause / Resume"),
            ("F", "Fullscreen"),
            ("R", "Restart"),
            ("ESC", "Exit"),
        ]
        for key, desc in controls:
            key_surf = font_small.render(key, True, TEXT_ACCENT)
            desc_surf = font_small.render(f"  {desc}", True, TEXT_SECONDARY)
            surface.blit(key_surf, (x + 16, row_y))
            surface.blit(desc_surf, (x + 16 + key_surf.get_width(), row_y))
            row_y += 18

    @staticmethod
    def _draw_metric(surface, font_metric, font_label,
                     x, y, label, value, color):
        lbl = font_metric.render(label, True, TEXT_SECONDARY)
        surface.blit(lbl, (x, y))
        val = font_label.render(value, True, color)
        surface.blit(val, (x, y + 22))


# ===================================================================
# Event Log (bottom)
# ===================================================================

class EventLog:
    MAX_LINES = 4

    def __init__(self):
        self.lines: List[str] = []

    def add(self, text: str):
        self.lines.append(text)
        if len(self.lines) > 50:
            self.lines = self.lines[-50:]

    def clear(self):
        self.lines.clear()

    def draw(self, surface: pygame.Surface, font_log: pygame.font.Font):
        y = WINDOW_H - EVENT_LOG_H
        w = SCENE_W

        # Background
        bg = pygame.Surface((w, EVENT_LOG_H), pygame.SRCALPHA)
        bg.fill((*PANEL_BG, 220))
        surface.blit(bg, (0, y))

        # Top border
        pygame.draw.line(surface, PANEL_BORDER, (0, y), (w, y), 1)

        # Show last N lines
        visible = self.lines[-self.MAX_LINES:]
        for i, line in enumerate(visible):
            # Prefix with ">" indicator
            color = TEXT_SECONDARY if i < len(visible) - 1 else TEXT_PRIMARY
            prefix = "›  " if i == len(visible) - 1 else "   "
            txt = font_log.render(f"{prefix}{line}", True, color)
            surface.blit(txt, (12, y + 6 + i * 18))
