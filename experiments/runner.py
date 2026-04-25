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


def _print_banner(title: str) -> None:
    print(f"\n{'='*72}\n  {title}\n{'='*72}")


def _start_servers(
    eca_host=config.ECA_HOST, eca_port=config.ECA_PORT,
    tma_host=config.TMA_HOST, tma_port=config.TMA_PORT,
    simulator: Optional[NetworkSimulator] = None,
):
    eca = ECA(host=eca_host, port=eca_port, simulator=simulator)
    tma = TMA(host=tma_host, port=tma_port, simulator=simulator)
    t_eca = threading.Thread(target=eca.start, daemon=True)
    t_tma = threading.Thread(target=tma.start, daemon=True)
    t_eca.start()
    t_tma.start()
    time.sleep(0.3)
    return eca, tma


def run_single_vehicle(
    num_runs: int = config.DEFAULT_NUM_RUNS,
    collector: Optional[MetricsCollector] = None,
) -> MetricsCollector:
    _print_banner(f"Experiment 1: Single Vehicle — {num_runs} runs")
    mc = collector or MetricsCollector()
    sim = NetworkSimulator()
    eca, tma = _start_servers(simulator=sim)
    vehicle = Vehicle(simulator=sim)

    for run_id in range(1, num_runs + 1):
        print(f"\n--- Run {run_id}/{num_runs} ---")
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

    s = mc.summary()
    print(f"\n[RESULT] OK: {s['ok_runs']}/{s['total_runs']}  "
          f"Avg P1: {s['avg_phase1_s']*1000:.2f}ms  Avg P2: {s['avg_phase2_s']*1000:.2f}ms")
    return mc


def run_multi_vehicle(
    num_vehicles: int = config.DEFAULT_NUM_VEHICLES,
    runs_per_vehicle: int = config.DEFAULT_RUNS_PER_VEHICLE,
    collector: Optional[MetricsCollector] = None,
) -> MetricsCollector:
    _print_banner(f"Experiment 2: {num_vehicles} vehicles × {runs_per_vehicle} runs")
    mc = collector or MetricsCollector()
    sim = NetworkSimulator()
    eca, tma = _start_servers(simulator=sim)
    global_run = 0
    for vid in range(1, num_vehicles + 1):
        vehicle = Vehicle(vehicle_id=config.VEHICLE_IDENTITY + vid, simulator=sim)
        for r in range(1, runs_per_vehicle + 1):
            global_run += 1
            result = vehicle.run_protocol()
            mc.record_run(
                run_id=global_run, vehicle_id=vid,
                phase1_time=result.get("phase1_time"),
                phase2_time=result.get("phase2_time"),
                status=result.get("status", "UNKNOWN"),
            )
            sim.reset()
            time.sleep(0.05)
    s = mc.summary()
    print(f"\n[RESULT] OK: {s['ok_runs']}/{s['total_runs']}  Avg: {s['avg_total_s']*1000:.2f}ms")
    return mc


def run_scalability_test(vehicle_counts=None, runs_per_vehicle=3):
    counts = vehicle_counts or [1, 5, 10, 20]
    _print_banner(f"Experiment 3: Scalability — {counts}")
    results = {"counts": counts, "avg_times": [], "throughputs": []}
    sim = NetworkSimulator()
    eca, tma = _start_servers(simulator=sim)
    for count in counts:
        mc = MetricsCollector()
        gid = 0
        for vid in range(1, count + 1):
            v = Vehicle(vehicle_id=config.VEHICLE_IDENTITY + vid, simulator=sim)
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
        print(f"  Vehicles={count}: avg={s['avg_total_s']*1000:.2f}ms")
    return results


def run_loss_rate_sweep(loss_rates=None, num_runs=10):
    rates = loss_rates or [0.0, 0.05, 0.10, 0.20, 0.30]
    _print_banner(f"Experiment 4: Loss Sweep — {rates}")
    results = {"loss_rates": rates, "pdr": [], "avg_latency": [], "jitter": []}
    for rate in rates:
        sim = NetworkSimulator(loss_rate=rate)
        eca, tma = _start_servers(
            eca_port=8001 + int(rate * 1000),
            tma_port=8002 + int(rate * 1000),
            simulator=sim,
        )
        time.sleep(0.2)
        vehicle = Vehicle(simulator=sim)
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
        print(f"  Loss={rate*100:.0f}%: PDR={m.get('PDR (%)',0):.1f}%")
    return results


def run_crypto_benchmark(iterations=100, collector=None):
    _print_banner(f"Experiment 5: Crypto Benchmark — {iterations} iters")
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

    avg = {}
    for op, times in results.items():
        avg[op] = sum(times) / len(times)
        mc.record_crypto(run_id=0, operation=op, time_sec=avg[op])
        print(f"  {op:20s}: {avg[op]*1e6:10.2f} μs")
    return avg


def run_all() -> None:
    os.makedirs(config.RESULTS_DIR, exist_ok=True)
    os.makedirs(config.CSV_DIR, exist_ok=True)
    os.makedirs(config.PLOTS_DIR, exist_ok=True)
    plotter = Plotter()

    mc1 = run_single_vehicle(num_runs=20)
    csv_paths = mc1.export_csv(os.path.join(config.CSV_DIR, "exp1"))
    if "runs" in csv_paths:
        plotter.plot_phase_latency(csv_paths["runs"])
    if "network" in csv_paths:
        plotter.plot_delay_breakdown(csv_paths["network"])

    crypto = run_crypto_benchmark(iterations=100)
    plotter.plot_crypto_overhead(crypto)

    mc2 = run_multi_vehicle(num_vehicles=5, runs_per_vehicle=3)
    mc2.export_csv(os.path.join(config.CSV_DIR, "exp2"))

    scale = run_scalability_test(vehicle_counts=[1, 5, 10, 20])
    plotter.plot_scalability(scale["counts"], scale["avg_times"])
    plotter.plot_throughput(scale["counts"], scale["throughputs"])

    loss = run_loss_rate_sweep(loss_rates=[0.0, 0.05, 0.10, 0.20, 0.30])
    plotter.plot_pdr_vs_loss(loss["loss_rates"], loss["pdr"])
    plotter.plot_latency_vs_loss(loss["loss_rates"], loss["avg_latency"])
    plotter.plot_jitter_vs_loss(loss["loss_rates"], loss["jitter"])

    try:
        from experiments.attacks import run_all_attacks
        attack_results = run_all_attacks()
        plotter.plot_attack_results(attack_results)
    except Exception as e:
        print(f"[WARN] Attacks skipped: {e}")

    print(f"\n{'='*72}\n  ALL EXPERIMENTS COMPLETE\n  CSVs  → {os.path.abspath(config.CSV_DIR)}")
    print(f"  Plots → {os.path.abspath(config.PLOTS_DIR)}\n{'='*72}")


if __name__ == "__main__":
    run_all()
