#!/usr/bin/env python3
"""
main.py — Entry point for the VANSEC project.

Usage
-----
  python main.py                  # Run all experiments
  python main.py --mode single    # Single-vehicle experiment only
  python main.py --mode multi     # Multi-vehicle experiment only
  python main.py --mode attacks   # Attack simulations only
  python main.py --mode crypto    # Crypto benchmark only
  python main.py --mode all       # Everything (default)
"""

import argparse
import os
import sys

# Ensure the project root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config
from experiments.runner import (
    run_single_vehicle,
    run_multi_vehicle,
    run_scalability_test,
    run_loss_rate_sweep,
    run_crypto_benchmark,
    run_all,
)
from experiments.attacks import run_all_attacks


def main():
    parser = argparse.ArgumentParser(
        description="VANSEC — VANET Data Integrity & Confidentiality"
    )
    parser.add_argument(
        "--mode",
        choices=["single", "multi", "scale", "loss", "crypto", "attacks", "all"],
        default="all",
        help="Which experiment to run (default: all)",
    )
    parser.add_argument(
        "--runs", type=int, default=config.DEFAULT_NUM_RUNS,
        help="Number of protocol runs per vehicle",
    )
    parser.add_argument(
        "--vehicles", type=int, default=config.DEFAULT_NUM_VEHICLES,
        help="Number of vehicles for multi-vehicle experiments",
    )
    args = parser.parse_args()

    # Ensure output directories exist
    os.makedirs(config.RESULTS_DIR, exist_ok=True)
    os.makedirs(config.CSV_DIR, exist_ok=True)
    os.makedirs(config.PLOTS_DIR, exist_ok=True)

    print("=" * 72)
    print("  VANSEC — VANET Data Integrity & Confidentiality")
    print("=" * 72)

    if args.mode == "all":
        run_all()

    elif args.mode == "single":
        mc = run_single_vehicle(num_runs=args.runs)
        mc.export_csv(os.path.join(config.CSV_DIR, "single"))
        print(mc.summary())

    elif args.mode == "multi":
        mc = run_multi_vehicle(
            num_vehicles=args.vehicles,
            runs_per_vehicle=args.runs,
        )
        mc.export_csv(os.path.join(config.CSV_DIR, "multi"))
        print(mc.summary())

    elif args.mode == "scale":
        results = run_scalability_test()
        print(results)

    elif args.mode == "loss":
        results = run_loss_rate_sweep()
        print(results)

    elif args.mode == "crypto":
        results = run_crypto_benchmark()
        print(results)

    elif args.mode == "attacks":
        results = run_all_attacks()
        for r in results:
            print(r)


if __name__ == "__main__":
    main()
