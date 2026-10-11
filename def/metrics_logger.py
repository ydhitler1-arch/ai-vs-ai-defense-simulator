"""
metrics_logger.py
-----------------
Full metrics recording system for the AI-vs-AI Cyber Defense Simulator.
Captures per-episode and per-step data, writes CSV logs, maintains running
statistics, and exports final summary JSON for the visualiser to consume.
"""

import os
import csv
import json
import time
import logging
import statistics
from datetime import datetime
from typing import Dict, List, Optional, Any
from collections import deque

from config import (
    METRICS_OUTPUT_DIR,
    SIMULATION_LOG_FILE,
    LOG_LEVEL,
    TOTAL_EPISODES,
)
from utils import setup_logger, timestamp_now, ensure_dir

logger = setup_logger("MetricsLogger", SIMULATION_LOG_FILE, LOG_LEVEL)


# ---------------------------------------------------------------------------
# Field definitions
# ---------------------------------------------------------------------------

EPISODE_CSV_FIELDS = [
    "episode",
    "timestamp",
    "total_steps",
    "attack_success_rate",
    "detection_accuracy",
    "false_positive_rate",
    "avg_response_time_s",
    "avg_attacker_reward",
    "avg_defender_reward",
    "total_blocks",
    "total_false_positives",
    "attacker_epsilon",
    "defender_epsilon",
    "target_compromised",
    # Rolling window stats (computed here)
    "rolling_atk_reward_10",
    "rolling_def_reward_10",
    "rolling_attack_success_10",
    "rolling_detection_acc_10",
    "cumulative_compromise_count",
    "cumulative_block_count",
]

STEP_CSV_FIELDS = [
    "episode",
    "step",
    "timestamp",
    "atk_action",
    "atk_success",
    "atk_reward",
    "def_action",
    "def_correct",
    "def_reward",
    "alert_count",
    "response_time_s",
]


# ---------------------------------------------------------------------------
# MetricsLogger
# ---------------------------------------------------------------------------

class MetricsLogger:
    """
    Records all metrics from the simulation to disk.

    Outputs:
      - metrics/episode_metrics.csv    — one row per episode
      - metrics/step_metrics.csv       — one row per step (all episodes)
      - metrics/summary.json           — final aggregated statistics
      - metrics/learning_curves.json   — reward history for plotting
      - metrics/raw_episodes.json      — full episode objects for deep analysis
    """

    def __init__(self, output_dir: str = None):
        self.output_dir = output_dir or METRICS_OUTPUT_DIR
        ensure_dir(self.output_dir)

        # File paths
        self.episode_csv_path    = os.path.join(self.output_dir, "episode_metrics.csv")
        self.step_csv_path       = os.path.join(self.output_dir, "step_metrics.csv")
        self.summary_json_path   = os.path.join(self.output_dir, "summary.json")
        self.curves_json_path    = os.path.join(self.output_dir, "learning_curves.json")
        self.raw_json_path       = os.path.join(self.output_dir, "raw_episodes.json")

        # Rolling window buffers (window=10)
        self._window = 10
        self._atk_rewards:     deque = deque(maxlen=self._window)
        self._def_rewards:     deque = deque(maxlen=self._window)
        self._atk_success:     deque = deque(maxlen=self._window)
        self._det_accuracy:    deque = deque(maxlen=self._window)

        # Cumulative counters
        self._cum_compromises: int = 0
        self._cum_blocks:      int = 0
        self._episode_count:   int = 0

        # In-memory stores for JSON export
        self._all_episodes:    List[Dict] = []
        self._learning_curves: Dict[str, List] = {
            "episodes":              [],
            "attacker_rewards":      [],
            "defender_rewards":      [],
            "attack_success_rate":   [],
            "detection_accuracy":    [],
            "false_positive_rate":   [],
            "avg_response_time_s":   [],
            "attacker_epsilon":      [],
            "defender_epsilon":      [],
            "rolling_atk_reward_10": [],
            "rolling_def_reward_10": [],
        }

        # Open CSV writers (kept open across all episodes for efficiency)
        self._episode_csv_fh  = open(self.episode_csv_path, "w", newline="")
        self._step_csv_fh     = open(self.step_csv_path,    "w", newline="")

        self._episode_writer  = csv.DictWriter(
            self._episode_csv_fh, fieldnames=EPISODE_CSV_FIELDS, extrasaction="ignore")
        self._step_writer     = csv.DictWriter(
            self._step_csv_fh,    fieldnames=STEP_CSV_FIELDS,    extrasaction="ignore")

        self._episode_writer.writeheader()
        self._step_writer.writeheader()

        # Flush to disk immediately so files are visible even mid-run
        self._episode_csv_fh.flush()
        self._step_csv_fh.flush()

        logger.info(f"MetricsLogger initialised. Output dir: {self.output_dir}")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def log_episode(self, summary: Dict[str, Any]):
        """
        Record a completed episode.
        Called once per episode by SimulationEngine._finalise_episode().
        """
        self._episode_count += 1

        # Update rolling windows
        self._atk_rewards.append(summary.get("avg_attacker_reward", 0.0))
        self._def_rewards.append(summary.get("avg_defender_reward", 0.0))
        self._atk_success.append(summary.get("attack_success_rate", 0.0))
        self._det_accuracy.append(summary.get("detection_accuracy", 0.0))

        # Update cumulative counters
        if summary.get("target_compromised", False):
            self._cum_compromises += 1
        self._cum_blocks += summary.get("total_blocks", 0)

        # Compute rolling averages
        rolling_atk  = _mean(self._atk_rewards)
        rolling_def  = _mean(self._def_rewards)
        rolling_succ = _mean(self._atk_success)
        rolling_det  = _mean(self._det_accuracy)

        # Build enriched row
        row = dict(summary)
        row["timestamp"]                = timestamp_now()
        row["rolling_atk_reward_10"]    = round(rolling_atk,  4)
        row["rolling_def_reward_10"]    = round(rolling_def,  4)
        row["rolling_attack_success_10"]= round(rolling_succ, 4)
        row["rolling_detection_acc_10"] = round(rolling_det,  4)
        row["cumulative_compromise_count"] = self._cum_compromises
        row["cumulative_block_count"]   = self._cum_blocks

        # Write CSV row
        self._episode_writer.writerow(row)
        self._episode_csv_fh.flush()

        # Update learning curve store
        ep_num = summary.get("episode", self._episode_count)
        self._learning_curves["episodes"].append(ep_num)
        self._learning_curves["attacker_rewards"].append(
            summary.get("avg_attacker_reward", 0.0))
        self._learning_curves["defender_rewards"].append(
            summary.get("avg_defender_reward", 0.0))
        self._learning_curves["attack_success_rate"].append(
            summary.get("attack_success_rate", 0.0))
        self._learning_curves["detection_accuracy"].append(
            summary.get("detection_accuracy", 0.0))
        self._learning_curves["false_positive_rate"].append(
            summary.get("false_positive_rate", 0.0))
        self._learning_curves["avg_response_time_s"].append(
            summary.get("avg_response_time_s", 0.0))
        self._learning_curves["attacker_epsilon"].append(
            summary.get("attacker_epsilon", 0.0))
        self._learning_curves["defender_epsilon"].append(
            summary.get("defender_epsilon", 0.0))
        self._learning_curves["rolling_atk_reward_10"].append(rolling_atk)
        self._learning_curves["rolling_def_reward_10"].append(rolling_def)

        # Keep raw episode data
        self._all_episodes.append(row)

        # Periodically flush JSON curves (every 5 episodes)
        if self._episode_count % 5 == 0:
            self._flush_curves_json()

        logger.debug(f"MetricsLogger: episode {ep_num} logged. "
                     f"Rolling ATK={rolling_atk:.3f} DEF={rolling_def:.3f}")

    def log_step(self, episode: int, step_data: Dict[str, Any]):
        """
        Record a single simulation step.
        Called every step by SimulationEngine._run_episode() if step-level
        logging is enabled.
        """
        row = {
            "episode":        episode,
            "step":           step_data.get("step", 0),
            "timestamp":      timestamp_now(),
            "atk_action":     step_data.get("atk_action", ""),
            "atk_success":    int(step_data.get("atk_success", False)),
            "atk_reward":     round(step_data.get("atk_reward", 0.0), 4),
            "def_action":     step_data.get("def_action", ""),
            "def_correct":    int(step_data.get("def_correct", False)),
            "def_reward":     round(step_data.get("def_reward", 0.0), 4),
            "alert_count":    step_data.get("alert_count", 0),
            "response_time_s":round(step_data.get("response_time", 0.0), 4),
        }
        self._step_writer.writerow(row)
        # Flush every 50 steps to avoid huge buffered writes
        if step_data.get("step", 0) % 50 == 0:
            self._step_csv_fh.flush()

    def get_current_stats(self) -> Dict[str, Any]:
        """Return a snapshot of current running statistics."""
        return {
            "episodes_completed":       self._episode_count,
            "cumulative_compromises":   self._cum_compromises,
            "cumulative_blocks":        self._cum_blocks,
            "rolling_atk_reward_10":   round(_mean(self._atk_rewards), 4),
            "rolling_def_reward_10":   round(_mean(self._def_rewards), 4),
            "rolling_attack_success":  round(_mean(self._atk_success), 4),
            "rolling_detection_acc":   round(_mean(self._det_accuracy), 4),
        }

    def finalise(self):
        """
        Called at simulation end. Writes summary JSON and closes file handles.
        """
        logger.info("MetricsLogger: finalising and writing summary...")

        summary = self._build_final_summary()

        # Write summary JSON
        with open(self.summary_json_path, "w") as f:
            json.dump(summary, f, indent=2)

        # Write final learning curves JSON
        self._flush_curves_json()

        # Write raw episodes JSON
        with open(self.raw_json_path, "w") as f:
            json.dump(self._all_episodes, f, indent=2)

        # Close CSV handles
        self._episode_csv_fh.close()
        self._step_csv_fh.close()

        logger.info(f"Metrics finalised. Files written to: {self.output_dir}")
        self._print_final_summary(summary)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_final_summary(self) -> Dict[str, Any]:
        """Aggregate all episode data into a final statistics summary."""
        if not self._all_episodes:
            return {"error": "No episodes recorded"}

        atk_rewards = [e.get("avg_attacker_reward", 0) for e in self._all_episodes]
        def_rewards = [e.get("avg_defender_reward", 0) for e in self._all_episodes]
        suc_rates   = [e.get("attack_success_rate", 0) for e in self._all_episodes]
        det_accs    = [e.get("detection_accuracy",  0) for e in self._all_episodes]
        fp_rates    = [e.get("false_positive_rate",  0) for e in self._all_episodes]
        resp_times  = [e.get("avg_response_time_s",  0) for e in self._all_episodes]

        # Convergence check: last 20 episodes vs first 20
        n = len(atk_rewards)
        first_20 = atk_rewards[:20]  if n >= 20 else atk_rewards
        last_20  = atk_rewards[-20:] if n >= 20 else atk_rewards
        atk_conv = _mean(last_20) - _mean(first_20)

        first_20d = def_rewards[:20]  if n >= 20 else def_rewards
        last_20d  = def_rewards[-20:] if n >= 20 else def_rewards
        def_conv = _mean(last_20d) - _mean(first_20d)

        return {
            "simulation_info": {
                "total_episodes":      self._episode_count,
                "total_compromises":   self._cum_compromises,
                "total_blocks":        self._cum_blocks,
                "generated_at":        timestamp_now(),
            },
            "attacker_stats": {
                "avg_reward":          round(_mean(atk_rewards), 4),
                "max_reward":          round(max(atk_rewards), 4),
                "min_reward":          round(min(atk_rewards), 4),
                "std_reward":          round(_std(atk_rewards), 4),
                "avg_attack_success":  round(_mean(suc_rates), 4),
                "convergence_delta":   round(atk_conv, 4),
            },
            "defender_stats": {
                "avg_reward":          round(_mean(def_rewards), 4),
                "max_reward":          round(max(def_rewards), 4),
                "min_reward":          round(min(def_rewards), 4),
                "std_reward":          round(_std(def_rewards), 4),
                "avg_detection_acc":   round(_mean(det_accs), 4),
                "avg_false_pos_rate":  round(_mean(fp_rates), 4),
                "avg_response_time_s": round(_mean(resp_times), 4),
                "convergence_delta":   round(def_conv, 4),
            },
            "overall": {
                "compromise_rate":     round(self._cum_compromises / max(self._episode_count, 1), 4),
                "block_rate_per_ep":   round(self._cum_blocks / max(self._episode_count, 1), 4),
                "defender_win_rate":   round(1.0 - _mean(suc_rates), 4),
                "attacker_win_rate":   round(_mean(suc_rates), 4),
            },
        }

    def _flush_curves_json(self):
        """Write current learning curves to JSON file."""
        try:
            with open(self.curves_json_path, "w") as f:
                json.dump(self._learning_curves, f, indent=2)
        except IOError as e:
            logger.warning(f"Could not write learning curves JSON: {e}")

    def _print_final_summary(self, summary: Dict):
        """Pretty-print the final summary to the log."""
        logger.info("\n" + "="*60)
        logger.info("  FINAL SIMULATION SUMMARY")
        logger.info("="*60)
        si = summary.get("simulation_info", {})
        logger.info(f"  Episodes completed : {si.get('total_episodes', 0)}")
        logger.info(f"  Total compromises  : {si.get('total_compromises', 0)}")
        logger.info(f"  Total blocks       : {si.get('total_blocks', 0)}")

        a = summary.get("attacker_stats", {})
        logger.info(f"\n  Attacker:")
        logger.info(f"    Avg reward       : {a.get('avg_reward', 0):.4f}")
        logger.info(f"    Avg atk success  : {a.get('avg_attack_success', 0):.2%}")
        logger.info(f"    Convergence Δ    : {a.get('convergence_delta', 0):+.4f}")

        d = summary.get("defender_stats", {})
        logger.info(f"\n  Defender:")
        logger.info(f"    Avg reward       : {d.get('avg_reward', 0):.4f}")
        logger.info(f"    Avg detection    : {d.get('avg_detection_acc', 0):.2%}")
        logger.info(f"    Avg FP rate      : {d.get('avg_false_pos_rate', 0):.2%}")
        logger.info(f"    Avg resp time    : {d.get('avg_response_time_s', 0):.3f}s")
        logger.info(f"    Convergence Δ    : {d.get('convergence_delta', 0):+.4f}")

        o = summary.get("overall", {})
        logger.info(f"\n  Overall:")
        logger.info(f"    Defender win rate: {o.get('defender_win_rate', 0):.2%}")
        logger.info(f"    Attacker win rate: {o.get('attacker_win_rate', 0):.2%}")
        logger.info("="*60)


# ---------------------------------------------------------------------------
# Statistics helpers
# ---------------------------------------------------------------------------

def _mean(values) -> float:
    vals = list(values)
    return statistics.mean(vals) if vals else 0.0


def _std(values) -> float:
    vals = list(values)
    return statistics.stdev(vals) if len(vals) > 1 else 0.0
