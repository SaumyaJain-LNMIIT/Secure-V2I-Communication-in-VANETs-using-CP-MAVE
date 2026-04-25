#!/usr/bin/env python3
"""
vansec/metrics/plotter.py — Graph generation for VANSEC experiments.

Reads CSV data or MetricsCollector objects and produces matplotlib figures
saved to the results/plots/ directory.
"""

from __future__ import annotations

import csv
import os
from typing import Dict, List, Optional

import matplotlib
matplotlib.use("Agg")  # non-interactive backend for file output
import matplotlib.pyplot as plt

import config

__all__ = ["Plotter"]

# ===================================================================
# Consistent style configuration
# ===================================================================
_COLORS = {
    "blue": "#4C72B0",
    "orange": "#DD8452",
    "green": "#55A868",
    "red": "#C44E52",
    "purple": "#8172B2",
    "teal": "#64B5CD",
}


class Plotter:
    """Generate report-ready graphs from experiment data."""

    def __init__(self, output_dir: str = config.PLOTS_DIR):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    # ───────────────────────────────────────────────
    # Shared style helper
    # ───────────────────────────────────────────────

    @staticmethod
    def _apply_style(ax) -> None:
        """Remove top/right spines and apply consistent grid."""
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        ax.grid(True, alpha=0.25, linestyle="--")

    # ───────────────────────────────────────────────
    # Graph 1: Phase latency per run
    # ───────────────────────────────────────────────

    def plot_phase_latency(
        self,
        runs_csv: str,
        filename: str = "phase_latency_per_run.png",
    ) -> str:
        """Line chart: Phase 1 & Phase 2 time vs. run number.

        Only plots SUCCESSFUL runs (non-empty phase times).
        Failed runs are not shown — plotting them as 0 ms would be
        misleading since no actual verification occurred.
        """
        runs, p1, p2 = [], [], []
        with open(runs_csv, newline="") as f:
            for row in csv.DictReader(f):
                # Skip failed runs: empty phase times mean packet loss / error
                if not row["phase1_time"] or not row["phase2_time"]:
                    continue
                runs.append(int(row["run_id"]))
                p1.append(float(row["phase1_time"]) * 1000)
                p2.append(float(row["phase2_time"]) * 1000)

        if not runs:
            return ""

        fig, ax = plt.subplots(figsize=(10, 5))
        ax.plot(runs, p1, marker="o", label="Phase 1 (auth)", linewidth=1.5, color=_COLORS["blue"])
        ax.plot(runs, p2, marker="s", label="Phase 2 (data)", linewidth=1.5, color=_COLORS["orange"])
        ax.set_xlabel("Run #")
        ax.set_ylabel("Latency (ms)")
        ax.set_title("Phase 1 & Phase 2 Latency per Run\n"
                      f"({len(runs)} successful runs, 6 Mbps channel, 5% loss)",
                      fontsize=12)
        ax.legend()
        self._apply_style(ax)
        path = os.path.join(self.output_dir, filename)
        fig.tight_layout()
        fig.savefig(path, dpi=150)
        plt.close(fig)
        return path

    # ───────────────────────────────────────────────
    # Graph 2: Avg latency vs. vehicle count
    # ───────────────────────────────────────────────

    def plot_scalability(
        self,
        vehicle_counts: List[int],
        avg_times: List[float],
        filename: str = "scalability.png",
    ) -> str:
        """Bar chart: average total time vs. number of vehicles."""
        fig, ax = plt.subplots(figsize=(8, 5))
        bars = ax.bar(
            [str(v) for v in vehicle_counts],
            [t * 1000 for t in avg_times],
            color=_COLORS["blue"],
            edgecolor="black",
        )
        ax.set_xlabel("Number of Vehicles")
        ax.set_ylabel("Avg Total Latency (ms)")
        ax.set_title("Scalability: Latency vs. Vehicle Count\n"
                      "(sequential execution, 5 runs/vehicle)",
                      fontsize=12)
        self._apply_style(ax)
        # add value labels on top of bars
        for bar, val in zip(bars, avg_times):
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 0.5,
                f"{val*1000:.1f}",
                ha="center", va="bottom", fontsize=9, fontweight="bold",
            )
        path = os.path.join(self.output_dir, filename)
        fig.tight_layout()
        fig.savefig(path, dpi=150)
        plt.close(fig)
        return path

    # ───────────────────────────────────────────────
    # Graph 3: PDR vs. loss rate
    # ───────────────────────────────────────────────

    def plot_pdr_vs_loss(
        self,
        loss_rates: List[float],
        pdr_values: List[float],
        filename: str = "pdr_vs_loss.png",
    ) -> str:
        """Line chart: PDR (%) vs. configured packet loss rate (%)."""
        x = [lr * 100 for lr in loss_rates]
        fig, ax = plt.subplots(figsize=(8, 5))
        ax.plot(x, pdr_values, marker="D", linewidth=2, color=_COLORS["orange"])
        for xi, yi in zip(x, pdr_values):
            ax.annotate(f"{yi:.1f}%", (xi, yi), textcoords="offset points",
                        xytext=(0, 10), ha="center", fontsize=9)
        ax.set_xlabel("Packet Loss Rate (%)")
        ax.set_ylabel("Packet Delivery Ratio (%)")
        ax.set_title("PDR vs. Packet Loss Rate\n"
                      "(50 runs per loss rate, Bernoulli loss model)",
                      fontsize=12)
        ax.set_ylim(0, 105)
        self._apply_style(ax)
        path = os.path.join(self.output_dir, filename)
        fig.tight_layout()
        fig.savefig(path, dpi=150)
        plt.close(fig)
        return path

    # ───────────────────────────────────────────────
    # Graph 4: Latency vs. loss rate
    # ───────────────────────────────────────────────

    def plot_latency_vs_loss(
        self,
        loss_rates: List[float],
        avg_latencies: List[float],
        filename: str = "latency_vs_loss.png",
    ) -> str:
        """Line chart: average latency (ms) vs. loss rate."""
        x = [lr * 100 for lr in loss_rates]
        y = [lat * 1000 for lat in avg_latencies]
        fig, ax = plt.subplots(figsize=(8, 5))
        ax.plot(x, y, marker="^", linewidth=2, color=_COLORS["green"])
        for xi, yi in zip(x, y):
            ax.annotate(f"{yi:.2f}", (xi, yi), textcoords="offset points",
                        xytext=(0, 10), ha="center", fontsize=9)
        ax.set_xlabel("Packet Loss Rate (%)")
        ax.set_ylabel("Avg Latency (ms)")
        ax.set_title("Average Latency vs. Packet Loss Rate\n"
                      "(delivered packets only, 50 runs per rate)",
                      fontsize=12)
        self._apply_style(ax)
        path = os.path.join(self.output_dir, filename)
        fig.tight_layout()
        fig.savefig(path, dpi=150)
        plt.close(fig)
        return path

    # ───────────────────────────────────────────────
    # Graph 5: Delay breakdown (stacked bar)
    # ───────────────────────────────────────────────

    def plot_delay_breakdown(
        self,
        network_csv: str,
        filename: str = "delay_breakdown.png",
    ) -> str:
        """Stacked bar: propagation / transmission / processing / queuing."""
        runs, prop, trans, proc, queue = [], [], [], [], []
        with open(network_csv, newline="") as f:
            for i, row in enumerate(csv.DictReader(f)):
                runs.append(i + 1)
                prop.append(float(row["propagation_delay"]) * 1000)
                trans.append(float(row["transmission_delay"]) * 1000)
                proc.append(float(row["processing_delay"]) * 1000)
                queue.append(float(row["queuing_delay"]) * 1000)

        fig, ax = plt.subplots(figsize=(12, 5))
        ax.bar(runs, prop, label="Propagation", color=_COLORS["blue"])
        ax.bar(runs, trans, bottom=prop, label="Transmission", color=_COLORS["orange"])
        bottom2 = [p + t for p, t in zip(prop, trans)]
        ax.bar(runs, proc, bottom=bottom2, label="Processing", color=_COLORS["green"])
        bottom3 = [b + p for b, p in zip(bottom2, proc)]
        ax.bar(runs, queue, bottom=bottom3, label="Queuing", color=_COLORS["red"])
        ax.set_xlabel("Transmission #")
        ax.set_ylabel("Delay (ms)")
        ax.set_title("Delay Component Breakdown per Transmission", fontsize=12)
        ax.legend()
        self._apply_style(ax)
        path = os.path.join(self.output_dir, filename)
        fig.tight_layout()
        fig.savefig(path, dpi=150)
        plt.close(fig)
        return path

    # ───────────────────────────────────────────────
    # Graph 6: Crypto overhead
    # ───────────────────────────────────────────────

    def plot_crypto_overhead(
        self,
        operations: Dict[str, float],
        filename: str = "crypto_overhead.png",
    ) -> str:
        """Bar chart: average time per cryptographic operation (μs)."""
        names = list(operations.keys())
        times_us = [v * 1e6 for v in operations.values()]

        fig, ax = plt.subplots(figsize=(10, 5))
        bars = ax.barh(names, times_us, color=_COLORS["purple"], edgecolor="black")
        ax.set_xlabel("Time (μs)")
        ax.set_title("Cryptographic Operation Overhead\n(100 iterations, NIST P-256)",
                      fontsize=12)
        self._apply_style(ax)
        for bar, val in zip(bars, times_us):
            ax.text(
                bar.get_width() + max(times_us) * 0.01,
                bar.get_y() + bar.get_height() / 2,
                f"{val:.1f} μs",
                va="center", fontsize=9,
            )
        path = os.path.join(self.output_dir, filename)
        fig.tight_layout()
        fig.savefig(path, dpi=150)
        plt.close(fig)
        return path

    # ───────────────────────────────────────────────
    # Graph 7: Throughput vs. vehicles
    # ───────────────────────────────────────────────

    def plot_throughput(
        self,
        vehicle_counts: List[int],
        throughputs: List[float],
        filename: str = "throughput.png",
    ) -> str:
        """Bar chart: throughput (Kbps) vs. vehicle count."""
        fig, ax = plt.subplots(figsize=(8, 5))
        bars = ax.bar(
            [str(v) for v in vehicle_counts],
            [t / 1000 for t in throughputs],
            color=_COLORS["teal"],
            edgecolor="black",
        )
        ax.set_xlabel("Number of Vehicles")
        ax.set_ylabel("Throughput (Kbps)")
        ax.set_title("Throughput vs. Vehicle Count\n"
                      "(aggregate delivered bits / total delivery time)",
                      fontsize=12)
        self._apply_style(ax)
        for bar, val in zip(bars, throughputs):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.5,
                    f"{val/1000:.1f}", ha="center", va="bottom", fontsize=9, fontweight="bold")
        path = os.path.join(self.output_dir, filename)
        fig.tight_layout()
        fig.savefig(path, dpi=150)
        plt.close(fig)
        return path

    # ───────────────────────────────────────────────
    # Graph 8: Jitter vs. loss rate
    # ───────────────────────────────────────────────

    def plot_jitter_vs_loss(
        self,
        loss_rates: List[float],
        jitter_values: List[float],
        filename: str = "jitter_vs_loss.png",
    ) -> str:
        """Line chart: jitter (ms) vs. loss rate."""
        x = [lr * 100 for lr in loss_rates]
        y = [j * 1000 for j in jitter_values]
        fig, ax = plt.subplots(figsize=(8, 5))
        ax.plot(x, y, marker="o", linewidth=2, color=_COLORS["red"])
        for xi, yi in zip(x, y):
            ax.annotate(f"{yi:.2f}", (xi, yi), textcoords="offset points",
                        xytext=(0, 10), ha="center", fontsize=9)
        ax.set_xlabel("Packet Loss Rate (%)")
        ax.set_ylabel("Jitter (ms)")
        ax.set_title("Jitter vs. Packet Loss Rate\n"
                      "(mean interarrival deviation, 50 runs per rate)",
                      fontsize=12)
        self._apply_style(ax)
        path = os.path.join(self.output_dir, filename)
        fig.tight_layout()
        fig.savefig(path, dpi=150)
        plt.close(fig)
        return path

    # ───────────────────────────────────────────────
    # Graph 9: Attack detection table (as figure)
    # ───────────────────────────────────────────────

    def plot_attack_results(
        self,
        attack_data: List[Dict[str, str]],
        filename: str = "attack_results.png",
    ) -> str:
        """Table rendered as a figure showing attack detection results."""
        if not attack_data:
            return ""

        cols = ["Attack Type", "Expected", "Actual", "Detected"]
        cell_text = [
            [d.get("type", ""), d.get("expected", ""), d.get("actual", ""), d.get("detected", "")]
            for d in attack_data
        ]

        fig, ax = plt.subplots(figsize=(12, 2 + 0.5 * len(attack_data)))
        ax.axis("off")
        table = ax.table(
            cellText=cell_text,
            colLabels=cols,
            cellLoc="center",
            loc="center",
        )
        table.auto_set_font_size(False)
        table.set_fontsize(10)
        table.scale(1.2, 1.6)
        # colour header row
        for j in range(len(cols)):
            table[0, j].set_facecolor(_COLORS["blue"])
            table[0, j].set_text_props(color="white", weight="bold")
        # colour data rows: green for detected, red for not
        for i, row in enumerate(attack_data):
            if row.get("detected") == "YES":
                bg = "#d4edda"  # light green
            elif row.get("detected") == "PARTIAL":
                bg = "#fff3cd"  # light yellow
            else:
                bg = "#f8d7da"  # light red
            for j in range(len(cols)):
                table[i + 1, j].set_facecolor(bg)
        ax.set_title("Security Attack Detection Results", fontsize=14, pad=20, fontweight="bold")
        path = os.path.join(self.output_dir, filename)
        fig.tight_layout()
        fig.savefig(path, dpi=150, bbox_inches="tight")
        plt.close(fig)
        return path

    # ───────────────────────────────────────────────
    # Graph 10: DoS attack impact (reframed)
    # ───────────────────────────────────────────────

    def plot_dos_impact(
        self,
        baseline_ms: float,
        avg_flood_ms: float,
        post_flood_ms: float,
        flood_count: int,
        total_flood_ms: float = 0.0,
        filename: str = "dos_impact.png",
    ) -> str:
        """Grouped bar chart: per-packet cost + total resource consumption."""
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5),
                                        gridspec_kw={"width_ratios": [3, 2]})

        # Left panel: per-packet verification time
        categories = [
            "Baseline\n(legitimate)",
            f"Flood Packet\n(forged sig)",
            "Post-Flood\n(legitimate)",
        ]
        times = [baseline_ms, avg_flood_ms, post_flood_ms]
        colors = [_COLORS["green"], _COLORS["red"], _COLORS["blue"]]
        bars = ax1.bar(categories, times, color=colors, edgecolor="black", width=0.5)
        ax1.set_ylabel("Verification Time (ms)")
        ax1.set_title("Per-Packet Verification Cost", fontsize=11)
        self._apply_style(ax1)
        for bar, val in zip(bars, times):
            ax1.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + max(times) * 0.03,
                f"{val:.2f} ms",
                ha="center", va="bottom", fontsize=10, fontweight="bold",
            )

        # Right panel: total resource consumption
        total_legit = baseline_ms  # 1 packet
        total_flood = total_flood_ms if total_flood_ms > 0 else avg_flood_ms * flood_count
        cat2 = ["1 Legitimate\nPacket", f"{flood_count} Flood\nPackets"]
        vals2 = [total_legit, total_flood]
        colors2 = [_COLORS["green"], _COLORS["red"]]
        bars2 = ax2.bar(cat2, vals2, color=colors2, edgecolor="black", width=0.5)
        ax2.set_ylabel("Total CPU Time (ms)")
        ax2.set_title("Aggregate TMA Resource Cost", fontsize=11)
        self._apply_style(ax2)
        for bar, val in zip(bars2, vals2):
            ax2.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + max(vals2) * 0.03,
                f"{val:.1f} ms",
                ha="center", va="bottom", fontsize=10, fontweight="bold",
            )

        fig.suptitle(f"DoS Flood Attack — Impact on TMA Resources\n"
                     f"({flood_count} packets with random ECDSA signatures)",
                     fontsize=13, fontweight="bold")
        path = os.path.join(self.output_dir, filename)
        fig.tight_layout()
        fig.savefig(path, dpi=150)
        plt.close(fig)
        return path
