#!/usr/bin/env python3
"""
main.py — Entry point for the VANSEC project.

Usage
-----
  python main.py                  # Run all experiments (default)
  python main.py --interactive    # Launch interactive menu
  python main.py --mode single    # Single-vehicle experiment only
  python main.py --mode multi     # Multi-vehicle experiment only
  python main.py --mode attacks   # Attack simulations only
  python main.py --mode crypto    # Crypto benchmark only
  python main.py --mode menu      # Interactive menu (same as --interactive)
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


# ===================================================================
# Interactive Menu
# ===================================================================

def _ask_int(prompt: str, default: int) -> int:
    """Ask the user for an integer, returning *default* on empty/invalid input."""
    raw = input(f"  {prompt} [default: {default}]: ").strip()
    if not raw:
        return default
    try:
        val = int(raw)
        if val <= 0:
            print(f"  Invalid, using default: {default}")
            return default
        return val
    except ValueError:
        print(f"  Invalid, using default: {default}")
        return default


def _ask_float(prompt: str, default: float) -> float:
    """Ask the user for a float, returning *default* on empty/invalid input."""
    raw = input(f"  {prompt} [default: {default}]: ").strip()
    if not raw:
        return default
    try:
        val = float(raw)
        if val < 0:
            print(f"  Invalid, using default: {default}")
            return default
        return val
    except ValueError:
        print(f"  Invalid, using default: {default}")
        return default


def _pause() -> None:
    """Wait for user acknowledgement before returning to the menu."""
    input("\n  Press Enter to continue...")


def _print_menu() -> None:
    print(f"""
{'═' * 72}
  VANSEC — VANET Data Integrity & Confidentiality
  Interactive Experiment Console
{'═' * 72}

  [1]  Single Vehicle Experiment
  [2]  Multi-Vehicle Experiment
  [3]  Scalability Sweep
  [4]  Loss Rate Sweep
  [5]  Cryptographic Benchmark
  [6]  Attack Simulations (Replay, Tamper, Impersonation, DoS)
  [7]  Run All Experiments
  [0]  Exit
""")


def interactive_menu() -> None:
    """Menu-driven interactive mode with guided parameter input."""
    # Ensure output directories exist
    os.makedirs(config.RESULTS_DIR, exist_ok=True)
    os.makedirs(config.CSV_DIR, exist_ok=True)
    os.makedirs(config.PLOTS_DIR, exist_ok=True)

    while True:
        _print_menu()
        choice = input("  Enter choice: ").strip()

        if choice == "0":
            print("\n  Goodbye!\n")
            break

        elif choice == "1":
            runs = _ask_int("Number of runs", config.DEFAULT_NUM_RUNS)
            mc = run_single_vehicle(num_runs=runs)
            paths = mc.export_csv(os.path.join(config.CSV_DIR, "single"))
            if paths:
                print(f"\n  ✓ CSV saved → {list(paths.values())}")
            _pause()

        elif choice == "2":
            vehicles = _ask_int("Number of vehicles", config.DEFAULT_NUM_VEHICLES)
            runs = _ask_int("Runs per vehicle", config.DEFAULT_RUNS_PER_VEHICLE)
            mc = run_multi_vehicle(num_vehicles=vehicles, runs_per_vehicle=runs)
            paths = mc.export_csv(os.path.join(config.CSV_DIR, "multi"))
            if paths:
                print(f"\n  ✓ CSV saved → {list(paths.values())}")
            _pause()

        elif choice == "3":
            print("\n  Vehicle counts to test: [1, 5, 10, 20]")
            results = run_scalability_test()
            _pause()

        elif choice == "4":
            print("\n  Loss rates to test: [0%, 5%, 10%, 20%, 30%]")
            results = run_loss_rate_sweep()
            _pause()

        elif choice == "5":
            iters = _ask_int("Number of iterations", 100)
            results = run_crypto_benchmark(iterations=iters)
            _pause()

        elif choice == "6":
            results = run_all_attacks()
            _pause()

        elif choice == "7":
            print("\n  Running all experiments. This may take a few minutes...\n")
            run_all()
            _pause()

        else:
            print(f"\n  Invalid choice: '{choice}'. Please enter 0-7.")


# ===================================================================
# CLI Entry Point
# ===================================================================

def main():
    parser = argparse.ArgumentParser(
        description="VANSEC — VANET Data Integrity & Confidentiality"
    )
    parser.add_argument(
        "--mode",
        choices=["single", "multi", "scale", "loss", "crypto", "attacks", "all", "menu"],
        default="all",
        help="Which experiment to run (default: all)",
    )
    parser.add_argument(
        "--interactive", "-i", action="store_true",
        help="Launch interactive menu",
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

    # Interactive menu mode
    if args.interactive or args.mode == "menu":
        interactive_menu()
        return

    # Banner for CLI mode
    print("=" * 72)
    print("  VANSEC — VANET Data Integrity & Confidentiality")
    print("=" * 72)

    if args.mode == "all":
        run_all()

    elif args.mode == "single":
        mc = run_single_vehicle(num_runs=args.runs)
        mc.export_csv(os.path.join(config.CSV_DIR, "single"))

    elif args.mode == "multi":
        mc = run_multi_vehicle(
            num_vehicles=args.vehicles,
            runs_per_vehicle=args.runs,
        )
        mc.export_csv(os.path.join(config.CSV_DIR, "multi"))

    elif args.mode == "scale":
        results = run_scalability_test()

    elif args.mode == "loss":
        results = run_loss_rate_sweep()

    elif args.mode == "crypto":
        results = run_crypto_benchmark()

    elif args.mode == "attacks":
        results = run_all_attacks()


if __name__ == "__main__":
    main()
