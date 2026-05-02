#!/usr/bin/env python3
"""
visual/constants.py — Visual design tokens and layout constants.
"""

# ===================================================================
# Window
# ===================================================================
WINDOW_W = 1280
WINDOW_H = 720
FPS = 60
TITLE = "VANSEC — Vehicular Ad-hoc Network Security Simulation"

# ===================================================================
# Color Palette (Dark Premium Theme)
# ===================================================================
BG_COLOR          = (15, 14, 23)       # #0f0e17
ROAD_COLOR        = (45, 45, 61)       # #2d2d3d
ROAD_SHOULDER     = (35, 35, 50)
LANE_MARKING      = (255, 255, 255, 64)
ROAD_EDGE         = (80, 80, 110)

VEHICLE_COLOR     = (0, 212, 170)      # #00d4aa  teal
ECA_COLOR         = (78, 168, 222)     # #4ea8de  blue
TMA_COLOR         = (168, 85, 247)     # #a855f7  purple
ATTACKER_COLOR    = (239, 68, 68)      # #ef4444  red

PACKET_VALID      = (34, 197, 94)      # #22c55e  green
PACKET_MALICIOUS  = (239, 68, 68)      # #ef4444  red
PACKET_AUTH       = (59, 130, 246)     # #3b82f6  blue
PACKET_TOKEN      = (99, 179, 237)     # #63b3ed  light-blue

SUCCESS_COLOR     = (34, 197, 94)      # #22c55e
FAIL_COLOR        = (239, 68, 68)      # #ef4444
WARNING_COLOR     = (245, 158, 11)     # #f59e0b

PANEL_BG          = (26, 26, 46)       # #1a1a2e
PANEL_BORDER      = (55, 55, 85)
TEXT_PRIMARY       = (226, 232, 240)   # #e2e8f0
TEXT_SECONDARY     = (148, 163, 184)   # #94a3b8
TEXT_ACCENT        = (125, 211, 252)   # #7dd3fc

# ===================================================================
# Layout — Main Scene (left portion: 0 → SCENE_W)
# ===================================================================
METRICS_PANEL_W = 220
SCENE_W = WINDOW_W - METRICS_PANEL_W   # 1060
STATUS_BAR_H = 44
EVENT_LOG_H = 80
SCENE_Y_TOP = STATUS_BAR_H
SCENE_Y_BOT = WINDOW_H - EVENT_LOG_H

# Road geometry
ROAD_Y = 370                           # center of the main road
ROAD_H = 90                            # total road height
ROAD_TOP = ROAD_Y - ROAD_H // 2
ROAD_BOT = ROAD_Y + ROAD_H // 2
LANE_DASH_W = 40
LANE_DASH_H = 3
LANE_GAP = 30

# ===================================================================
# Entity Positions
# ===================================================================
VEHICLE_START_X = 60
VEHICLE_Y = ROAD_Y - 10
VEHICLE_W = 72
VEHICLE_H = 36

ECA_X = SCENE_W // 2 - 60
ECA_Y = ROAD_TOP - 120
ECA_W = 100
ECA_H = 60

TMA_X = SCENE_W - 160
TMA_Y = ROAD_TOP - 120
TMA_W = 100
TMA_H = 60

ATTACKER_X = 60
ATTACKER_Y = ROAD_Y + ROAD_H // 2 + 60
ATTACKER_W = 72
ATTACKER_H = 36

# ===================================================================
# Animation
# ===================================================================
PACKET_RADIUS = 10
PACKET_SPEED = 4.0             # pixels per frame base speed
PACKET_TRAIL_COUNT = 5
VEHICLE_DRIVE_SPEED = 2.5      # px / frame

BANNER_DURATION_MS = 2500
BANNER_FADE_MS = 400

# ===================================================================
# Fonts (resolved at runtime)
# ===================================================================
FONT_FAMILY = "segoeui"
FONT_FALLBACK = "arial"
FONT_SIZE_TITLE = 18
FONT_SIZE_LABEL = 15
FONT_SIZE_SMALL = 12
FONT_SIZE_BANNER = 32
FONT_SIZE_METRIC = 14
FONT_SIZE_LOG = 12

# ===================================================================
# Demo timing (milliseconds)
# ===================================================================
DEMO_PHASE_GAP = 1200          # pause between demo phases
SCENE_TRANSITION_MS = 600
