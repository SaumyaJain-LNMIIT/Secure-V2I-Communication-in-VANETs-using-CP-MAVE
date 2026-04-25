#!/usr/bin/env python3
"""
vansec/metrics/collector.py — Metrics collection and CSV export engine.

Records per-run timing, network events, and crypto overhead.
Exports all collected data to CSV files for analysis and plotting.
"""

from __future__ import annotations

import csv
import os
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

import config

__all__ = ["MetricsCollector"]


@dataclass
class RunRecord:
    """One protocol execution record."""
    run_id: int
    vehicle_id: int
    phase1_time: Optional[float]
    phase2_time: Optional[float]
    total_time: Optional[float]
    status: str
    s1_ok: Optional[bool] = None
    sigma2_ok: Optional[bool] = None
    timestamp: float = field(default_factory=time.time)


@dataclass
class NetworkRecord:
    """One network transmission record."""
    run_id: int
    sender: str
    receiver: str
    size_bits: int
    propagation_delay: float
    transmission_delay: float
    processing_delay: float
    queuing_delay: float
    total_delay: float
    packet_lost: bool
    timestamp: float = field(default_factory=time.time)


@dataclass
class CryptoRecord:
    """One cryptographic operation timing record."""
    run_id: int
    operation: str       # e.g. "aes_encrypt", "hash", "ecc_scalar_mul"
    time_sec: float
    timestamp: float = field(default_factory=time.time)


class MetricsCollector:
    """
    Centralized metrics collection for all VANSEC experiments.

    Usage
    -----
    >>> mc = MetricsCollector()
    >>> mc.record_run(run_id=1, vehicle_id=1, phase1_time=0.12, ...)
    >>> mc.export_csv()
    """

    def __init__(self, output_dir: str = config.CSV_DIR):
        self.output_dir = output_dir
        self.runs: List[RunRecord] = []
        self.network: List[NetworkRecord] = []
        self.crypto: List[CryptoRecord] = []

    # ───────────────────────────────────────────────
    # Recording methods
    # ───────────────────────────────────────────────

    def record_run(
        self,
        run_id: int,
        vehicle_id: int,
        phase1_time: Optional[float],
        phase2_time: Optional[float],
        status: str,
        s1_ok: Optional[bool] = None,
        sigma2_ok: Optional[bool] = None,
    ) -> None:
        total = None
        if phase1_time is not None and phase2_time is not None:
            total = phase1_time + phase2_time
        self.runs.append(RunRecord(
            run_id=run_id,
            vehicle_id=vehicle_id,
            phase1_time=phase1_time,
            phase2_time=phase2_time,
            total_time=total,
            status=status,
            s1_ok=s1_ok,
            sigma2_ok=sigma2_ok,
        ))

    def record_network(
        self,
        run_id: int,
        sender: str,
        receiver: str,
        size_bits: int,
        propagation_delay: float,
        transmission_delay: float,
        processing_delay: float,
        queuing_delay: float,
        total_delay: float,
        packet_lost: bool,
    ) -> None:
        self.network.append(NetworkRecord(
            run_id=run_id,
            sender=sender,
            receiver=receiver,
            size_bits=size_bits,
            propagation_delay=propagation_delay,
            transmission_delay=transmission_delay,
            processing_delay=processing_delay,
            queuing_delay=queuing_delay,
            total_delay=total_delay,
            packet_lost=packet_lost,
        ))

    def record_crypto(
        self, run_id: int, operation: str, time_sec: float
    ) -> None:
        self.crypto.append(CryptoRecord(
            run_id=run_id, operation=operation, time_sec=time_sec
        ))

    # ───────────────────────────────────────────────
    # Export
    # ───────────────────────────────────────────────

    def export_csv(self, output_dir: Optional[str] = None) -> Dict[str, str]:
        """
        Write all collected metrics to CSV files.

        Returns a dict mapping metric name → file path.
        """
        out = output_dir or self.output_dir
        os.makedirs(out, exist_ok=True)
        paths: Dict[str, str] = {}

        if self.runs:
            p = os.path.join(out, "run_results.csv")
            self._write_csv(p, self.runs)
            paths["runs"] = p

        if self.network:
            p = os.path.join(out, "network_logs.csv")
            self._write_csv(p, self.network)
            paths["network"] = p

        if self.crypto:
            p = os.path.join(out, "crypto_overhead.csv")
            self._write_csv(p, self.crypto)
            paths["crypto"] = p

        return paths

    @staticmethod
    def _write_csv(path: str, records: list) -> None:
        if not records:
            return
        fieldnames = list(asdict(records[0]).keys())
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for rec in records:
                writer.writerow(asdict(rec))

    # ───────────────────────────────────────────────
    # Summary
    # ───────────────────────────────────────────────

    def summary(self) -> Dict[str, Any]:
        """Return aggregate statistics from collected run data."""
        ok_runs = [r for r in self.runs if r.status == "OK"]
        p1 = [r.phase1_time for r in ok_runs if r.phase1_time is not None]
        p2 = [r.phase2_time for r in ok_runs if r.phase2_time is not None]
        tot = [r.total_time for r in ok_runs if r.total_time is not None]

        def _avg(lst):
            return sum(lst) / len(lst) if lst else 0.0

        return {
            "total_runs": len(self.runs),
            "ok_runs": len(ok_runs),
            "failed_runs": len(self.runs) - len(ok_runs),
            "avg_phase1_s": round(_avg(p1), 6),
            "avg_phase2_s": round(_avg(p2), 6),
            "avg_total_s": round(_avg(tot), 6),
        }

    def reset(self) -> None:
        """Clear all collected data."""
        self.runs.clear()
        self.network.clear()
        self.crypto.clear()
