"""
main.py
-------
Entry point for the AI-vs-AI Cyber Defense Simulator.

Modes:
  python3 main.py                      # run full simulation
  python3 main.py --episodes 50        # override episode count
  python3 main.py --mode visualize     # generate plots only
  python3 main.py --mode test          # single-episode smoke test
  python3 main.py --mode reset         # wipe models + metrics and start fresh
  python3 main.py --resume             # load saved models and continue training

The script validates the environment, initialises all subsystems, runs the
simulation engine, and generates visualisation plots at the end.
"""

import os
import sys
import time
import signal
import logging
import argparse
import platform
import subprocess
import json
from datetime import datetime
from typing import Optional

# ---------------------------------------------------------------------------
# Bootstrap: make sure we are running from the simulator root directory
# ---------------------------------------------------------------------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

# ---------------------------------------------------------------------------
# Imports (done after sys.path is set)
# ---------------------------------------------------------------------------
try:
    from config import (
        ATTACKER_IP, TARGET_IP, DEFENDER_IP, MONITOR_IP,
        TOTAL_EPISODES, STEPS_PER_EPISODE, STEP_DELAY_SECONDS,
        METRICS_OUTPUT_DIR, SIMULATION_LOG_FILE, LOG_LEVEL,
        MODEL_SAVE_DIR, SNORT_ALERT_FILE, IPTABLES_CHAIN,
    )
    from utils import setup_logger, ensure_dir, timestamp_now, ensure_utf8_stdout
    from simulation_engine import SimulationEngine
    from visualizer import generate_all_plots
except ImportError as e:
    print(f"[FATAL] Import error: {e}")
    print("  Make sure all .py files are in the same directory.")
    sys.exit(1)

logger = setup_logger("Main", SIMULATION_LOG_FILE, LOG_LEVEL)

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

BANNER = r"""
  ╔══════════════════════════════════════════════════════════════╗
  ║       AI-vs-AI  CYBER  DEFENSE  SIMULATOR                   ║
  ║                                                              ║
  ║   Attacker AI  ⚔  ←→  ⚔  Defender AI                       ║
  ║   Reinforcement Learning | IDS | Firewall Automation         ║
  ╚══════════════════════════════════════════════════════════════╝
"""

# ---------------------------------------------------------------------------
# Environment validator
# ---------------------------------------------------------------------------

class EnvironmentValidator:
    """
    Validates that all required system components are present before
    the simulation starts. Fails fast with clear error messages.
    """

    def __init__(self):
        self.errors:   list = []
        self.warnings: list = []

    def validate(self, strict: bool = False) -> bool:
        """
        Run all checks. Returns True if the environment is ready.
        If strict=True, any warning is also treated as a failure.
        """
        self._check_python_version()
        self._check_python_packages()
        self._check_directories()
        self._check_config_values()
        self._check_optional_system_tools()

        # Print results
        if self.warnings:
            for w in self.warnings:
                logger.warning(f"  ⚠  {w}")
        if self.errors:
            for e in self.errors:
                logger.error(f"  ✗  {e}")
            return False

        logger.info("  ✓  Environment validation passed.")
        return True

    def _check_python_version(self):
        major, minor = sys.version_info[:2]
        if major < 3 or (major == 3 and minor < 8):
            self.errors.append(
                f"Python 3.8+ required. Current: {major}.{minor}")
        else:
            logger.info(f"  Python {major}.{minor}: OK")

    def _check_python_packages(self):
        required = {
            "numpy":      "numpy",
            "pandas":     "pandas",
            "matplotlib": "matplotlib",
            "seaborn":    "seaborn",
        }
        optional = {
            "scapy":      "scapy",
            "nmap":       "python-nmap",
        }
        for mod, pkg in required.items():
            try:
                __import__(mod)
                logger.info(f"  Package '{mod}': OK")
            except ImportError:
                self.errors.append(
                    f"Required package '{mod}' not installed. "
                    f"Run: pip3 install {pkg}")

        for mod, pkg in optional.items():
            try:
                __import__(mod)
                logger.info(f"  Optional package '{mod}': OK")
            except ImportError:
                self.warnings.append(
                    f"Optional package '{mod}' not installed ({pkg}). "
                    f"Some features may use simulation mode.")

    def _check_directories(self):
        dirs = [
            METRICS_OUTPUT_DIR,
            MODEL_SAVE_DIR,
            os.path.join(METRICS_OUTPUT_DIR, "plots"),
        ]
        for d in dirs:
            try:
                ensure_dir(d)
                logger.info(f"  Directory '{d}': OK")
            except Exception as e:
                self.errors.append(f"Cannot create directory '{d}': {e}")

        # Snort alert file — create empty if missing
        alert_dir = os.path.dirname(SNORT_ALERT_FILE)
        if alert_dir:
            try:
                ensure_dir(alert_dir)
                if not os.path.exists(SNORT_ALERT_FILE):
                    open(SNORT_ALERT_FILE, "a").close()
                    logger.info(f"  Created Snort alert file: {SNORT_ALERT_FILE}")
            except PermissionError:
                self.warnings.append(
                    f"Cannot create Snort alert file at {SNORT_ALERT_FILE}. "
                    f"Simulation mode will be used for IDS alerts.")

    def _check_config_values(self):
        if TOTAL_EPISODES <= 0:
            self.errors.append("TOTAL_EPISODES must be > 0")
        if STEPS_PER_EPISODE <= 0:
            self.errors.append("STEPS_PER_EPISODE must be > 0")
        logger.info(f"  Config: {TOTAL_EPISODES} episodes × "
                    f"{STEPS_PER_EPISODE} steps = "
                    f"{TOTAL_EPISODES * STEPS_PER_EPISODE} total steps")

    def _check_optional_system_tools(self):
        tools = ["iptables", "nmap", "snort"]
        for tool in tools:
            found = _command_exists(tool)
            if found:
                logger.info(f"  System tool '{tool}': found")
            else:
                self.warnings.append(
                    f"System tool '{tool}' not found — "
                    f"simulation mode will be used for this component.")


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="AI-vs-AI Cyber Defense Simulator",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "--mode", type=str, default="simulate",
        choices=["simulate", "visualize", "test", "reset"],
        help=(
            "simulate  : run the full RL simulation (default)\n"
            "visualize : generate plots from existing metrics\n"
            "test      : run a 1-episode smoke test\n"
            "reset     : delete saved models and metrics, then simulate"
        ),
    )
    parser.add_argument(
        "--episodes", type=int, default=None,
        help="Override TOTAL_EPISODES from config.py",
    )
    parser.add_argument(
        "--steps", type=int, default=None,
        help="Override STEPS_PER_EPISODE from config.py",
    )
    parser.add_argument(
        "--resume", action="store_true",
        help="Load saved Q-table models and continue training",
    )
    parser.add_argument(
        "--no-plots", action="store_true",
        help="Skip auto-generating plots at end of simulation",
    )
    parser.add_argument(
        "--strict", action="store_true",
        help="Treat validation warnings as errors (fail fast)",
    )
    parser.add_argument(
        "--live", action="store_true",
        help=("Live mode: do not simulate attacks. The defender reacts to real Snort\n"
              "alerts from the attacker VM (run attacker_ai.py there)."),
    )
    parser.add_argument(
        "--live-step", type=float, default=None, metavar="SECONDS",
        help="Live mode: seconds per defender decision (default: LIVE_STEP_SECONDS)",
    )
    return parser


# ---------------------------------------------------------------------------
# Mode handlers
# ---------------------------------------------------------------------------

def run_simulation(args: argparse.Namespace):
    """Main simulation mode — runs all episodes."""
    import config as cfg

    # Apply CLI overrides to config module at runtime
    if args.episodes:
        cfg.TOTAL_EPISODES = args.episodes
        logger.info(f"Overriding TOTAL_EPISODES → {args.episodes}")
    if args.steps:
        cfg.STEPS_PER_EPISODE = args.steps
        logger.info(f"Overriding STEPS_PER_EPISODE → {args.steps}")
    if args.live:
        cfg.LIVE_MODE = True
        logger.info("Live mode enabled (--live): no simulated attacker.")
    if args.live_step:
        cfg.LIVE_STEP_SECONDS = args.live_step
        logger.info(f"Overriding LIVE_STEP_SECONDS → {args.live_step}")

    engine = SimulationEngine()

    # Optionally load saved models
    if args.resume:
        logger.info("--resume flag set: loading saved models...")
        try:
            engine.attacker.load_model()
            engine.defender.load_model()
            logger.info("Models loaded successfully.")
        except Exception as e:
            logger.warning(f"Could not load models: {e}. Starting fresh.")

    # Register graceful shutdown signal handlers
    def _signal_handler(sig, frame):
        logger.warning(f"\nSignal {sig} received — requesting graceful stop...")
        engine.stop()

    signal.signal(signal.SIGINT,  _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    # Run the simulation
    start_time = time.time()
    engine.run()
    elapsed = time.time() - start_time

    logger.info(f"\nSimulation finished in {elapsed:.1f}s "
                f"({elapsed/60:.1f} minutes).")

    # Auto-generate plots unless suppressed
    if not args.no_plots:
        logger.info("\nGenerating visualisation plots...")
        try:
            plot_dir = generate_all_plots(METRICS_OUTPUT_DIR)
            if plot_dir:
                logger.info(f"Plots saved to: {plot_dir}")
                _print_output_summary(plot_dir)
        except Exception as e:
            logger.error(f"Plot generation failed: {e}", exc_info=True)


def run_visualize_only(args: argparse.Namespace):
    """Visualize mode — just generate plots from existing metrics."""
    logger.info("Mode: VISUALIZE — reading existing metrics...")
    metrics_path = os.path.join(METRICS_OUTPUT_DIR, "episode_metrics.csv")
    if not os.path.exists(metrics_path):
        logger.error(
            f"No episode_metrics.csv found at {METRICS_OUTPUT_DIR}. "
            f"Run a simulation first.")
        sys.exit(1)

    plot_dir = generate_all_plots(METRICS_OUTPUT_DIR)
    if plot_dir:
        _print_output_summary(plot_dir)


def run_smoke_test(args: argparse.Namespace):
    """Test mode — 1 episode, 5 steps, verifies end-to-end pipeline."""
    import config as cfg
    logger.info("Mode: SMOKE TEST — 1 episode, 5 steps")

    cfg.TOTAL_EPISODES    = 1
    cfg.STEPS_PER_EPISODE = 5
    cfg.STEP_DELAY_SECONDS = 0.0
    cfg.ENV_RESET_BETWEEN_EPISODES = True

    engine = SimulationEngine()
    engine.run()

    # Verify metrics file was written
    metrics_path = os.path.join(METRICS_OUTPUT_DIR, "episode_metrics.csv")
    if os.path.exists(metrics_path):
        logger.info(f"✓ Metrics file written: {metrics_path}")
    else:
        logger.error("✗ Metrics file was NOT written — check for errors above.")
        sys.exit(1)

    logger.info("✓ Smoke test passed.")


def run_reset(args: argparse.Namespace):
    """Reset mode — wipe all models and metrics, then simulate fresh."""
    import shutil
    logger.warning("Mode: RESET — deleting saved models and metrics...")

    dirs_to_clean = [METRICS_OUTPUT_DIR, MODEL_SAVE_DIR]
    for d in dirs_to_clean:
        if os.path.exists(d):
            shutil.rmtree(d)
            logger.info(f"  Deleted: {d}")
        ensure_dir(d)
        logger.info(f"  Recreated: {d}")

    logger.info("Reset complete. Starting fresh simulation...")
    args.resume = False
    run_simulation(args)


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _command_exists(cmd: str) -> bool:
    """Return True if a shell command exists on PATH."""
    return subprocess.call(
        ["which", cmd],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    ) == 0


def _print_output_summary(plot_dir: str):
    """Print a final summary of all generated output files."""
    logger.info("\n" + "="*60)
    logger.info("  OUTPUT SUMMARY")
    logger.info("="*60)

    output_groups = {
        "Metrics (CSV)": [
            os.path.join(METRICS_OUTPUT_DIR, "episode_metrics.csv"),
            os.path.join(METRICS_OUTPUT_DIR, "step_metrics.csv"),
        ],
        "Metrics (JSON)": [
            os.path.join(METRICS_OUTPUT_DIR, "summary.json"),
            os.path.join(METRICS_OUTPUT_DIR, "learning_curves.json"),
            os.path.join(METRICS_OUTPUT_DIR, "raw_episodes.json"),
        ],
        "Saved Models": [
            os.path.join(MODEL_SAVE_DIR, "attacker_q_table.pkl"),
            os.path.join(MODEL_SAVE_DIR, "defender_q_table.pkl"),
        ],
        "Simulation Log": [SIMULATION_LOG_FILE],
    }

    for group, paths in output_groups.items():
        logger.info(f"\n  {group}:")
        for p in paths:
            exists = "✓" if os.path.exists(p) else "✗ (missing)"
            size   = ""
            if os.path.exists(p):
                kb = os.path.getsize(p) / 1024
                size = f" ({kb:.1f} KB)"
            logger.info(f"    {exists}  {p}{size}")

    # List plots
    if os.path.exists(plot_dir):
        plots = sorted([f for f in os.listdir(plot_dir) if f.endswith(".png")])
        logger.info(f"\n  Plots ({len(plots)} files in {plot_dir}):")
        for p in plots:
            full = os.path.join(plot_dir, p)
            kb = os.path.getsize(full) / 1024
            logger.info(f"    ✓  {p}  ({kb:.1f} KB)")

    logger.info("\n" + "="*60)


def _write_run_metadata(args: argparse.Namespace):
    """Write a JSON file recording how this run was invoked."""
    meta = {
        "timestamp":   timestamp_now(),
        "mode":        args.mode,
        "episodes":    args.episodes,
        "steps":       args.steps,
        "resume":      args.resume,
        "python":      sys.version,
        "platform":    platform.platform(),
        "cwd":         os.getcwd(),
    }
    meta_path = os.path.join(METRICS_OUTPUT_DIR, "run_metadata.json")
    try:
        ensure_dir(METRICS_OUTPUT_DIR)
        with open(meta_path, "w") as f:
            json.dump(meta, f, indent=2)
    except Exception as e:
        logger.warning(f"Could not write run metadata: {e}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ensure_utf8_stdout()
    print(BANNER)

    parser = build_arg_parser()
    args   = parser.parse_args()

    logger.info(f"AI-vs-AI Cyber Defense Simulator — {timestamp_now()}")
    live = getattr(args, "live", False) and args.mode == "simulate"
    logger.info("Mode: LIVE (real attacker, real Snort alerts)" if live
                else f"Mode: {args.mode.upper()}")
    logger.info(f"Python: {sys.version.split()[0]}  |  "
                f"Platform: {platform.system()} {platform.release()}")
    logger.info(f"Working dir: {SCRIPT_DIR}")
    logger.info(f"Network: ATK={ATTACKER_IP}  TGT={TARGET_IP}  "
                f"DEF={DEFENDER_IP}  MON={MONITOR_IP}")

    # Ensure output dirs exist
    ensure_dir(METRICS_OUTPUT_DIR)
    ensure_dir(MODEL_SAVE_DIR)

    # ── Environment validation ─────────────────────────────────────────
    logger.info("\n[Step 1/4] Validating environment...")
    validator = EnvironmentValidator()
    ok = validator.validate(strict=args.strict)
    if not ok:
        logger.error("Environment validation FAILED. Fix errors above and retry.")
        sys.exit(1)

    # ── Write run metadata ─────────────────────────────────────────────
    _write_run_metadata(args)

    # ── Dispatch to mode handler ───────────────────────────────────────
    logger.info(f"\n[Step 2/4] Dispatching mode: {args.mode}")

    mode_map = {
        "simulate":  run_simulation,
        "visualize": run_visualize_only,
        "test":      run_smoke_test,
        "reset":     run_reset,
    }
    handler = mode_map.get(args.mode)
    if handler is None:
        logger.error(f"Unknown mode: {args.mode}")
        sys.exit(1)

    logger.info("\n[Step 3/4] Starting simulation engine...\n")
    handler(args)

    logger.info("\n[Step 4/4] All done.")
    logger.info(f"Simulation complete at {timestamp_now()}")


if __name__ == "__main__":
    main()
