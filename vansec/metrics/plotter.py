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


class Plotter:
    """Generate report-ready graphs from experiment data."""

    def __init__(self, output_dir: str = config.PLOTS_DIR):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    # ───────────────────────────────────────────────
    # Graph 1: Phase latency per run
    # ───────────────────────────────────────────────

    def plot_phase_latency(
        self,
        runs_csv: str,
        filename: str = "phase_latency_per_run.png",
    ) -> str:
        """Line chart: Phase 1 & Phase 2 time vs. run number."""
        runs, p1, p2 = [], [], []
        with open(runs_csv, newline="") as f:
            for row in csv.DictReader(f):
                runs.append(int(row["run_id"]))
                p1.append(float(row["phase1_time"]) * 1000 if row["phase1_time"] else 0)
                p2.append(float(row["phase2_time"]) * 1000 if row["phase2_time"] else 0)

        fig, ax = plt.subplots(figsize=(10, 5))
        ax.plot(runs, p1, marker="o", label="Phase 1 (ms)", linewidth=1.5)
        ax.plot(runs, p2, marker="s", label="Phase 2 (ms)", linewidth=1.5)
        ax.set_xlabel("Run #")
        ax.set_ylabel("Latency (ms)")
        ax.set_title("Phase 1 & Phase 2 Latency per Run")
        ax.legend()
        ax.grid(True, alpha=0.3)
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
            color="#4C72B0",
            edgecolor="black",
        )
        ax.set_xlabel("Number of Vehicles")
        ax.set_ylabel("Avg Total Latency (ms)")
        ax.set_title("Scalability: Latency vs. Vehicle Count")
        ax.grid(True, axis="y", alpha=0.3)
        # add value labels on top of bars
        for bar, val in zip(bars, avg_times):
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 0.5,
                f"{val*1000:.1f}",
                ha="center", va="bottom", fontsize=9,
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
        fig, ax = plt.subplots(figsize=(8, 5))
        ax.plot(
            [lr * 100 for lr in loss_rates],
            pdr_values,
            marker="D", linewidth=2, color="#DD8452",
        )
        ax.set_xlabel("Packet Loss Rate (%)")
        ax.set_ylabel("Packet Delivery Ratio (%)")
        ax.set_title("PDR vs. Packet Loss Rate")
        ax.set_ylim(0, 105)
        ax.grid(True, alpha=0.3)
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
        fig, ax = plt.subplots(figsize=(8, 5))
        ax.plot(
            [lr * 100 for lr in loss_rates],
            [lat * 1000 for lat in avg_latencies],
            marker="^", linewidth=2, color="#55A868",
        )
        ax.set_xlabel("Packet Loss Rate (%)")
        ax.set_ylabel("Avg Latency (ms)")
        ax.set_title("Average Latency vs. Packet Loss Rate")
        ax.grid(True, alpha=0.3)
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
        ax.bar(runs, prop, label="Propagation", color="#4C72B0")
        ax.bar(runs, trans, bottom=prop, label="Transmission", color="#DD8452")
        bottom2 = [p + t for p, t in zip(prop, trans)]
        ax.bar(runs, proc, bottom=bottom2, label="Processing", color="#55A868")
        bottom3 = [b + p for b, p in zip(bottom2, proc)]
        ax.bar(runs, queue, bottom=bottom3, label="Queuing", color="#C44E52")
        ax.set_xlabel("Transmission #")
        ax.set_ylabel("Delay (ms)")
        ax.set_title("Delay Component Breakdown per Transmission")
        ax.legend()
        ax.grid(True, axis="y", alpha=0.3)
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
        bars = ax.barh(names, times_us, color="#8172B2", edgecolor="black")
        ax.set_xlabel("Time (μs)")
        ax.set_title("Cryptographic Operation Overhead")
        ax.grid(True, axis="x", alpha=0.3)
        for bar, val in zip(bars, times_us):
            ax.text(
                bar.get_width() + max(times_us) * 0.01,
                bar.get_y() + bar.get_height() / 2,
                f"{val:.1f}",
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
        ax.bar(
            [str(v) for v in vehicle_counts],
            [t / 1000 for t in throughputs],
            color="#64B5CD",
            edgecolor="black",
        )
        ax.set_xlabel("Number of Vehicles")
        ax.set_ylabel("Throughput (Kbps)")
        ax.set_title("Throughput vs. Vehicle Count")
        ax.grid(True, axis="y", alpha=0.3)
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
        fig, ax = plt.subplots(figsize=(8, 5))
        ax.plot(
            [lr * 100 for lr in loss_rates],
            [j * 1000 for j in jitter_values],
            marker="o", linewidth=2, color="#C44E52",
        )
        ax.set_xlabel("Packet Loss Rate (%)")
        ax.set_ylabel("Jitter (ms)")
        ax.set_title("Jitter vs. Packet Loss Rate")
        ax.grid(True, alpha=0.3)
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

        fig, ax = plt.subplots(figsize=(10, 2 + 0.4 * len(attack_data)))
        ax.axis("off")
        table = ax.table(
            cellText=cell_text,
            colLabels=cols,
            cellLoc="center",
            loc="center",
        )
        table.auto_set_font_size(False)
        table.set_fontsize(11)
        table.scale(1.2, 1.5)
        # colour header row
        for j in range(len(cols)):
            table[0, j].set_facecolor("#4C72B0")
            table[0, j].set_text_props(color="white", weight="bold")
        ax.set_title("Security Attack Detection Results", fontsize=14, pad=20)
        path = os.path.join(self.output_dir, filename)
        fig.tight_layout()
        fig.savefig(path, dpi=150, bbox_inches="tight")
        plt.close(fig)
        return path
