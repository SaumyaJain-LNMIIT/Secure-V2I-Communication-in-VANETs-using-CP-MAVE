#!/usr/bin/env python3
"""
visual/demo_runner.py — Entry point for the VANSEC Pygame visual simulation.

Usage
-----
    python main.py --mode visual       # via main.py
    python -m visual.demo_runner       # standalone
"""

from __future__ import annotations

import sys
import os

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pygame

from visual.renderer import Renderer
from visual.protocol_adapter import ProtocolAdapter
from visual.constants import FPS
from visual.events import ev_status, ev_wait, ev_banner, ev_scene_reset
from visual.constants import SUCCESS_COLOR, FAIL_COLOR, WARNING_COLOR


# ===================================================================
# Mode definitions
# ===================================================================

MODE_NAMES = {
    1: "Normal Mode",
    2: "Replay Attack",
    3: "Tamper Attack",
    4: "Impersonation Attack",
    5: "DoS Flood Attack",
    0: "Auto Demo",
}


class DemoRunner:
    """Manages the visual demo lifecycle and mode switching."""

    def __init__(self):
        self.renderer = Renderer()
        self.adapter = ProtocolAdapter()
        self.current_mode = 0

    def start(self, mode: str = "auto"):
        """
        Parameters
        ----------
        mode : str
            "auto"           — polished 60-90s presentation sequence
            "normal"         — interactive normal mode
            "replay"         — replay attack demo
            "tamper"         — tamper attack demo
            "impersonation"  — impersonation attack demo
            "dos"            — DoS flood attack demo
        """
        self.renderer.init_display()

        mode_map = {
            "auto": 0, "normal": 1, "replay": 2,
            "tamper": 3, "impersonation": 4, "dos": 5,
        }
        self.current_mode = mode_map.get(mode, 0)

        if self.current_mode == 0:
            self._run_auto_demo()
        else:
            self._run_single_mode(self.current_mode)

        pygame.quit()

    # ================================================================
    # Build events for a mode
    # ================================================================

    def _build_events(self, mode: int):
        if mode == 1:
            return self.adapter.build_normal_events()
        elif mode == 2:
            return self.adapter.build_replay_events()
        elif mode == 3:
            return self.adapter.build_tamper_events()
        elif mode == 4:
            return self.adapter.build_impersonation_events()
        elif mode == 5:
            return self.adapter.build_dos_events()
        return []

    # ================================================================
    # Single interactive mode
    # ================================================================

    def _run_single_mode(self, mode: int):
        self.renderer.full_reset()
        self.renderer.status_bar.mode_text = MODE_NAMES.get(mode, "Unknown")
        events = self._build_events(mode)
        self.renderer.load_events(events)
        self._main_loop(allow_switch=True)

    # ================================================================
    # Auto demo (presentation mode)
    # ================================================================

    def _run_auto_demo(self):
        """
        Polished 60-90 second sequence:
        1. Normal mode — authenticate + send message
        2. Replay attack — detected
        3. Tamper attack — detected
        4. Impersonation — detected
        5. DoS flood — survived
        6. Summary
        """
        self.renderer.full_reset()
        self.renderer.status_bar.mode_text = "Auto Demo"

        # Build combined timeline
        all_events = []

        # Intro
        all_events.append(ev_status("VANSEC — Vehicular Ad-hoc Network Security Simulation"))
        all_events.append(ev_banner("VANSEC DEMONSTRATION\nSecure V2I Communication",
                                     SUCCESS_COLOR, delay=500, duration=2500))
        all_events.append(ev_wait(3000))
        all_events.append(ev_scene_reset(delay=200))

        # Phase 1+2: Normal
        self.renderer.status_bar.mode_text = "Auto Demo — Normal"
        normal_events = self.adapter.build_normal_events()
        all_events.extend(normal_events)
        all_events.append(ev_wait(1500))
        all_events.append(ev_scene_reset(delay=200))

        # Replay Attack
        replay_events = self.adapter.build_replay_events()
        all_events.extend(replay_events)
        all_events.append(ev_wait(1500))
        all_events.append(ev_scene_reset(delay=200))

        # Tamper Attack
        tamper_events = self.adapter.build_tamper_events()
        all_events.extend(tamper_events)
        all_events.append(ev_wait(1500))
        all_events.append(ev_scene_reset(delay=200))

        # Impersonation Attack
        impersonation_events = self.adapter.build_impersonation_events()
        all_events.extend(impersonation_events)
        all_events.append(ev_wait(1500))
        all_events.append(ev_scene_reset(delay=200))

        # DoS Flood
        dos_events = self.adapter.build_dos_events()
        all_events.extend(dos_events)
        all_events.append(ev_wait(1500))

        # Summary
        all_events.append(ev_banner(
            "✓ ALL ATTACKS DETECTED\n"
            "VANSEC Security Verification Complete",
            SUCCESS_COLOR, delay=500, duration=4000
        ))
        all_events.append(ev_wait(4500))

        self.renderer.load_events(all_events)
        self._main_loop(allow_switch=True)

    # ================================================================
    # Main loop
    # ================================================================

    def _main_loop(self, allow_switch: bool = True):
        while self.renderer.running:
            dt = self.renderer.clock.tick(FPS) / 1000.0

            # Event handling
            for event in pygame.event.get():
                if event.type == pygame.QUIT:
                    self.renderer.running = False
                    return

                if event.type == pygame.KEYDOWN:
                    if event.key == pygame.K_ESCAPE:
                        self.renderer.running = False
                        return

                    if event.key == pygame.K_SPACE:
                        self.renderer.paused = not self.renderer.paused

                    if event.key == pygame.K_f:
                        self.renderer.toggle_fullscreen()

                    if event.key == pygame.K_r:
                        # Restart current mode
                        if self.current_mode == 0:
                            self.renderer.full_reset()
                            self._run_auto_demo()
                            return
                        else:
                            self._run_single_mode(self.current_mode)
                            return

                    # Mode switching (1-5)
                    if allow_switch:
                        if event.key == pygame.K_1:
                            self.current_mode = 1
                            self._run_single_mode(1)
                            return
                        elif event.key == pygame.K_2:
                            self.current_mode = 2
                            self._run_single_mode(2)
                            return
                        elif event.key == pygame.K_3:
                            self.current_mode = 3
                            self._run_single_mode(3)
                            return
                        elif event.key == pygame.K_4:
                            self.current_mode = 4
                            self._run_single_mode(4)
                            return
                        elif event.key == pygame.K_5:
                            self.current_mode = 5
                            self._run_single_mode(5)
                            return

            # Update mode text based on current scene
            if self.current_mode != 0:
                self.renderer.status_bar.mode_text = MODE_NAMES.get(
                    self.current_mode, "Unknown")

            # Update
            self.renderer.update(dt)
            self.renderer.status_bar.update(self.renderer.clock.get_fps())

            # Draw
            self.renderer.draw()


# ===================================================================
# Standalone entry point
# ===================================================================

def run_visual_demo(mode: str = "auto"):
    """Public entry point called from main.py or directly."""
    runner = DemoRunner()
    runner.start(mode)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="VANSEC Visual Simulation")
    parser.add_argument(
        "--demo-mode",
        choices=["auto", "normal", "replay", "tamper", "impersonation", "dos"],
        default="auto",
        help="Demo mode (default: auto)",
    )
    args = parser.parse_args()
    run_visual_demo(args.demo_mode)
