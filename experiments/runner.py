#!/usr/bin/env python3
"""
experiments/runner.py — Multi-scenario experiment orchestrator for VANSEC.
"""

from __future__ import annotations

import os
import sys
import time
import threading
from typing import Dict, List, Optional, Any

from ecdsa import curves

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config
from vansec.crypto.primitives import (
    Hash, AES_Enc_using_Key, AES_Dec_using_Key,
    generate_nonce, generate_iv, compute_shared_secret,
)
from vansec.crypto.keys import generate_keypair
from vansec.network.simulator import NetworkSimulator
from vansec.metrics.collector import MetricsCollector
from vansec.metrics.plotter import Plotter
from vansec.nodes.vehicle import Vehicle
from vansec.nodes.eca import ECA
from vansec.nodes.tma import TMA

_G = curves.NIST256p.generator


# ===================================================================
# Display helpers
# ===================================================================

def _print_banner(title: str) -> None:
    print(f"\n{'='*72}\n  {title}\n{'='*72}")


def _print_summary_box(title: str, rows: List[tuple]) -> None:
    """Print a bordered summary box with key-value rows."""
    width = 54
    print(f"\n  ┌{'─' * width}┐")
    print(f"  │  {title:<{width - 2}}│")
    print(f"  ├{'─' * width}┤")
    for label, value in rows:
        line = f"{label:<20}: {value}"
        print(f"  │  {line:<{width - 2}}│")
    print(f"  └{'─' * width}┘")


def _progress(current: int, total: int) -> None:
    """Overwrite a single progress line in the terminal."""
    bar_len = 30
    filled = int(bar_len * current / total)
    bar = "█" * filled + "░" * (bar_len - filled)
    pct = current / total * 100
    print(f"\r  Progress: {bar} {pct:5.1f}%  ({current}/{total})", end="", flush=True)


# ===================================================================
# Server management
# ===================================================================

def _start_servers(
    eca_host=config.ECA_HOST, eca_port=config.ECA_PORT,
    tma_host=config.TMA_HOST, tma_port=config.TMA_PORT,
    simulator: Optional[NetworkSimulator] = None,
    quiet: bool = True,
):
    eca = ECA(host=eca_host, port=eca_port, simulator=simulator, quiet=quiet)
    tma = TMA(host=tma_host, port=tma_port, simulator=simulator, quiet=quiet)
    t_eca = threading.Thread(target=eca.start, daemon=True)
    t_tma = threading.Thread(target=tma.start, daemon=True)
    t_eca.start()
    t_tma.start()
    time.sleep(0.3)
    return eca, tma


# ===================================================================
# Experiment 1: Single Vehicle
# ===================================================================

def run_single_vehicle(
    num_runs: int = config.DEFAULT_NUM_RUNS,
    collector: Optional[MetricsCollector] = None,
    quiet: bool = True,
) -> MetricsCollector:
    _print_banner(f"Experiment 1: Single Vehicle — {num_runs} runs")
    mc = collector or MetricsCollector()
    sim = NetworkSimulator()
    eca, tma = _start_servers(simulator=sim, quiet=quiet)
    vehicle = Vehicle(simulator=sim, quiet=quiet)

    for run_id in range(1, num_runs + 1):
        if not quiet:
            print(f"\n--- Run {run_id}/{num_runs} ---")
        else:
            _progress(run_id, num_runs)
        result = vehicle.run_protocol()
        mc.record_run(
            run_id=run_id, vehicle_id=1,
            phase1_time=result.get("phase1_time"),
            phase2_time=result.get("phase2_time"),
            status=result.get("status", "UNKNOWN"),
        )
        for log in sim.logs:
            mc.record_network(
                run_id=run_id, sender=log.sender, receiver=log.receiver,
                size_bits=log.size_bits,
                propagation_delay=log.propagation_delay,
                transmission_delay=log.transmission_delay,
                processing_delay=log.processing_delay,
                queuing_delay=log.queuing_delay,
                total_delay=log.total_delay,
                packet_lost=log.packet_lost,
            )
        sim.reset()
        time.sleep(0.05)

    if quiet:
        print()  # newline after progress bar

    s = mc.summary()
    _print_summary_box("Experiment 1: Single Vehicle", [
        ("Successful runs", f"{s['ok_runs']}/{s['total_runs']}"),
        ("Failed runs", f"{s['failed_runs']}"),
        ("Avg Phase 1", f"{s['avg_phase1_s']*1000:.2f} ms"),
        ("Avg Phase 2", f"{s['avg_phase2_s']*1000:.2f} ms"),
        ("Avg Total", f"{s['avg_total_s']*1000:.2f} ms"),
    ])
    return mc


# ===================================================================
# Experiment 2: Multi-Vehicle
# ===================================================================

def run_multi_vehicle(
    num_vehicles: int = config.DEFAULT_NUM_VEHICLES,
    runs_per_vehicle: int = config.DEFAULT_RUNS_PER_VEHICLE,
    collector: Optional[MetricsCollector] = None,
    quiet: bool = True,
) -> MetricsCollector:
    total_runs = num_vehicles * runs_per_vehicle
    _print_banner(f"Experiment 2: {num_vehicles} vehicles × {runs_per_vehicle} runs")
    mc = collector or MetricsCollector()
    sim = NetworkSimulator()
    eca, tma = _start_servers(simulator=sim, quiet=quiet)
    global_run = 0
    for vid in range(1, num_vehicles + 1):
        vehicle = Vehicle(vehicle_id=config.VEHICLE_IDENTITY + vid, simulator=sim, quiet=quiet)
        for r in range(1, runs_per_vehicle + 1):
            global_run += 1
            if quiet:
                _progress(global_run, total_runs)
            result = vehicle.run_protocol()
            mc.record_run(
                run_id=global_run, vehicle_id=vid,
                phase1_time=result.get("phase1_time"),
                phase2_time=result.get("phase2_time"),
                status=result.get("status", "UNKNOWN"),
            )
            sim.reset()
            time.sleep(0.05)

    if quiet:
        print()

    s = mc.summary()
    _print_summary_box(f"Experiment 2: {num_vehicles} Vehicles", [
        ("Successful runs", f"{s['ok_runs']}/{s['total_runs']}"),
        ("Failed runs", f"{s['failed_runs']}"),
        ("Avg Phase 1", f"{s['avg_phase1_s']*1000:.2f} ms"),
        ("Avg Phase 2", f"{s['avg_phase2_s']*1000:.2f} ms"),
        ("Avg Total", f"{s['avg_total_s']*1000:.2f} ms"),
    ])
    return mc


# ===================================================================
# Experiment 3: Scalability Sweep
# ===================================================================

def run_scalability_test(vehicle_counts=None, runs_per_vehicle=3, quiet=True):
    counts = vehicle_counts or [1, 5, 10, 20]
    _print_banner(f"Experiment 3: Scalability — {counts}")
    results = {"counts": counts, "avg_times": [], "throughputs": []}
    sim = NetworkSimulator()
    eca, tma = _start_servers(simulator=sim, quiet=quiet)
    for idx, count in enumerate(counts):
        mc = MetricsCollector()
        gid = 0
        for vid in range(1, count + 1):
            v = Vehicle(vehicle_id=config.VEHICLE_IDENTITY + vid, simulator=sim, quiet=quiet)
            for _ in range(runs_per_vehicle):
                gid += 1
                r = v.run_protocol()
                mc.record_run(gid, vid, r.get("phase1_time"), r.get("phase2_time"), r.get("status","UNKNOWN"))
                sim.reset()
                time.sleep(0.02)
        s = mc.summary()
        m = sim.get_metrics()
        results["avg_times"].append(s["avg_total_s"])
        results["throughputs"].append(m.get("Throughput (bps)", 0))
        print(f"  [{idx+1}/{len(counts)}] Vehicles={count:>3d}: avg={s['avg_total_s']*1000:.2f} ms")

    _print_summary_box("Experiment 3: Scalability", [
        (f"{c} vehicles", f"{t*1000:.2f} ms")
        for c, t in zip(counts, results["avg_times"])
    ])
    return results


# ===================================================================
# Experiment 4: Loss Rate Sweep
# ===================================================================

def run_loss_rate_sweep(loss_rates=None, num_runs=10, quiet=True):
    rates = loss_rates or [0.0, 0.05, 0.10, 0.20, 0.30]
    _print_banner(f"Experiment 4: Loss Rate Sweep — {[f'{r*100:.0f}%' for r in rates]}")
    results = {"loss_rates": rates, "pdr": [], "avg_latency": [], "jitter": []}
    for idx, rate in enumerate(rates):
        sim = NetworkSimulator(loss_rate=rate)
        eca, tma = _start_servers(
            eca_port=8001 + int(rate * 1000),
            tma_port=8002 + int(rate * 1000),
            simulator=sim,
            quiet=quiet,
        )
        time.sleep(0.2)
        vehicle = Vehicle(simulator=sim, quiet=quiet)
        for run_id in range(1, num_runs + 1):
            vehicle.run_protocol(
                eca_port=8001 + int(rate * 1000),
                tma_port=8002 + int(rate * 1000),
            )
            time.sleep(0.02)
        m = sim.get_metrics()
        results["pdr"].append(m.get("PDR (%)", 0))
        results["avg_latency"].append(m.get("Average Delay (s)", 0))
        results["jitter"].append(m.get("Jitter (s)", 0))
        print(f"  [{idx+1}/{len(rates)}] Loss={rate*100:>5.1f}%: PDR={m.get('PDR (%)',0):.1f}%")

    _print_summary_box("Experiment 4: Loss Rate Sweep", [
        (f"Loss {r*100:.0f}%", f"PDR={p:.1f}%")
        for r, p in zip(rates, results["pdr"])
    ])
    return results


# ===================================================================
# Experiment 5: Crypto Benchmark
# ===================================================================

def run_crypto_benchmark(iterations=100, collector=None, quiet=True):
    _print_banner(f"Experiment 5: Crypto Benchmark — {iterations} iterations")
    mc = collector or MetricsCollector()
    results = {
        "hash": [], "aes_encrypt": [], "aes_decrypt": [],
        "nonce_gen": [], "ecc_keygen": [], "ecc_scalar_mul": [],
        "shared_secret": [],
    }
    priv, pub = generate_keypair()
    priv2, pub2 = generate_keypair()
    iv = generate_iv()
    secret = compute_shared_secret(priv, pub2)
    for i in range(iterations):
        if quiet and (i + 1) % 10 == 0:
            _progress(i + 1, iterations)
        t = time.perf_counter()
        Hash(i, priv, pub)
        results["hash"].append(time.perf_counter() - t)
        t = time.perf_counter()
        ct, _ = AES_Enc_using_Key(secret, iv, i + 1)
        results["aes_encrypt"].append(time.perf_counter() - t)
        t = time.perf_counter()
        AES_Dec_using_Key(secret, iv, ct)
        results["aes_decrypt"].append(time.perf_counter() - t)
        t = time.perf_counter()
        generate_nonce()
        results["nonce_gen"].append(time.perf_counter() - t)
        t = time.perf_counter()
        generate_keypair()
        results["ecc_keygen"].append(time.perf_counter() - t)
        t = time.perf_counter()
        _ = priv * _G
        results["ecc_scalar_mul"].append(time.perf_counter() - t)
        t = time.perf_counter()
        compute_shared_secret(priv, pub2)
        results["shared_secret"].append(time.perf_counter() - t)

    if quiet:
        print()

    avg = {}
    rows = []
    for op, times in results.items():
        avg[op] = sum(times) / len(times)
        mc.record_crypto(run_id=0, operation=op, time_sec=avg[op])
        rows.append((op, f"{avg[op]*1e6:.2f} μs"))

    _print_summary_box("Experiment 5: Crypto Overhead", rows)
    return avg


# ===================================================================
# Run All Experiments
# ===================================================================

def run_all() -> None:
    os.makedirs(config.RESULTS_DIR, exist_ok=True)
    os.makedirs(config.CSV_DIR, exist_ok=True)
    os.makedirs(config.PLOTS_DIR, exist_ok=True)
    plotter = Plotter()

    # Experiment 1
    mc1 = run_single_vehicle(num_runs=20)
    csv_paths = mc1.export_csv(os.path.join(config.CSV_DIR, "exp1"))
    if "runs" in csv_paths:
        plotter.plot_phase_latency(csv_paths["runs"])
    if "network" in csv_paths:
        plotter.plot_delay_breakdown(csv_paths["network"])

    # Experiment 5 (crypto — quick, no servers needed)
    crypto = run_crypto_benchmark(iterations=100)
    plotter.plot_crypto_overhead(crypto)

    # Experiment 2
    mc2 = run_multi_vehicle(num_vehicles=5, runs_per_vehicle=3)
    mc2.export_csv(os.path.join(config.CSV_DIR, "exp2"))

    # Experiment 3
    scale = run_scalability_test(vehicle_counts=[1, 5, 10, 20])
    plotter.plot_scalability(scale["counts"], scale["avg_times"])
    plotter.plot_throughput(scale["counts"], scale["throughputs"])

    # Experiment 4
    loss = run_loss_rate_sweep(loss_rates=[0.0, 0.05, 0.10, 0.20, 0.30])
    plotter.plot_pdr_vs_loss(loss["loss_rates"], loss["pdr"])
    plotter.plot_latency_vs_loss(loss["loss_rates"], loss["avg_latency"])
    plotter.plot_jitter_vs_loss(loss["loss_rates"], loss["jitter"])

    # Attack simulations
    try:
        from experiments.attacks import run_all_attacks
        attack_results = run_all_attacks()
        plotter.plot_attack_results(attack_results)
        # Generate DoS-specific plot if DoS data is available
        dos = next((r for r in attack_results if r["type"] == "DoS Flood Attack"), None)
        if dos:
            plotter.plot_dos_impact(
                baseline_ms=float(dos["baseline_ms"]),
                avg_flood_ms=float(dos["avg_flood_ms"]),
                post_flood_ms=float(dos["post_flood_ms"]),
                flood_count=int(dos["flood_packets"]),
            )
    except Exception as e:
        print(f"  [WARN] Attacks skipped: {e}")

    print(f"\n{'='*72}")
    print(f"  ALL EXPERIMENTS COMPLETE")
    print(f"  CSVs  → {os.path.abspath(config.CSV_DIR)}")
    print(f"  Plots → {os.path.abspath(config.PLOTS_DIR)}")
    print(f"{'='*72}")


if __name__ == "__main__":
    run_all()
