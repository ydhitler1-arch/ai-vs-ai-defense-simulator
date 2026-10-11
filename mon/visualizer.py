"""
visualizer.py
-------------
Full visualisation suite for the AI-vs-AI Cyber Defense Simulator.
Reads metrics produced by MetricsLogger and generates publication-quality
plots covering:
  1. Attacker & Defender learning curves (reward over episodes)
  2. Rolling-average reward comparison
  3. Attack success rate vs Detection accuracy
  4. False positive rate over episodes
  5. Average response time trend
  6. Epsilon decay curves (exploration vs exploitation)
  7. Cumulative compromise & block counts
  8. Action distribution heatmaps (attacker and defender)
  9. Win-rate summary bar chart
 10. Correlation heatmap of all key metrics
 11. Episode outcome distribution (pie chart)
 12. Combined dashboard (multi-panel figure)

All plots are saved to metrics/plots/ as high-resolution PNG files.
A combined dashboard PNG is also exported.

Usage:
    python visualizer.py                    # reads from default METRICS_OUTPUT_DIR
    python visualizer.py --dir /path/to/metrics
"""

import os
import sys
import json
import argparse
import logging
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")   # non-interactive backend — safe in all environments
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import matplotlib.ticker as mticker
from matplotlib.colors import LinearSegmentedColormap
import seaborn as sns
from typing import Dict, List, Optional, Tuple

from config import METRICS_OUTPUT_DIR, LOG_LEVEL
from utils import setup_logger, ensure_dir

logger = setup_logger("Visualizer", None, LOG_LEVEL)

# ---------------------------------------------------------------------------
# Style constants
# ---------------------------------------------------------------------------

ATTACKER_COLOR  = "#E74C3C"   # red
DEFENDER_COLOR  = "#2ECC71"   # green
NEUTRAL_COLOR   = "#3498DB"   # blue
ACCENT_COLOR    = "#F39C12"   # orange
BG_COLOR        = "#1A1A2E"   # dark navy (cybersecurity theme)
PANEL_COLOR     = "#16213E"
TEXT_COLOR      = "#EAEAEA"
GRID_COLOR      = "#2C2C54"

FONT_TITLE      = {"fontsize": 13, "fontweight": "bold", "color": TEXT_COLOR}
FONT_LABEL      = {"fontsize": 10, "color": TEXT_COLOR}
FONT_TICK       = {"labelcolor": TEXT_COLOR, "labelsize": 8}

PLOT_DIR_NAME   = "plots"
DPI             = 150


def _apply_dark_style(fig, axes_list):
    """Apply consistent dark cybersecurity theme to all axes."""
    fig.patch.set_facecolor(BG_COLOR)
    for ax in axes_list:
        ax.set_facecolor(PANEL_COLOR)
        ax.tick_params(**FONT_TICK)
        ax.xaxis.label.set_color(TEXT_COLOR)
        ax.yaxis.label.set_color(TEXT_COLOR)
        ax.title.set_color(TEXT_COLOR)
        for spine in ax.spines.values():
            spine.set_edgecolor(GRID_COLOR)
        ax.grid(True, color=GRID_COLOR, linewidth=0.5, linestyle="--", alpha=0.7)


# ---------------------------------------------------------------------------
# Data loader
# ---------------------------------------------------------------------------

class MetricsData:
    """Loads and validates all metrics files produced by MetricsLogger."""

    def __init__(self, metrics_dir: str):
        self.metrics_dir = metrics_dir
        self.plot_dir = os.path.join(metrics_dir, PLOT_DIR_NAME)
        ensure_dir(self.plot_dir)

        self.episode_df:  Optional[pd.DataFrame] = None
        self.step_df:     Optional[pd.DataFrame] = None
        self.curves:      Optional[Dict]          = None
        self.summary:     Optional[Dict]          = None
        self.raw_episodes:Optional[List]          = None

        self._load()

    def _load(self):
        ep_path    = os.path.join(self.metrics_dir, "episode_metrics.csv")
        step_path  = os.path.join(self.metrics_dir, "step_metrics.csv")
        curves_path= os.path.join(self.metrics_dir, "learning_curves.json")
        summary_path=os.path.join(self.metrics_dir, "summary.json")
        raw_path   = os.path.join(self.metrics_dir, "raw_episodes.json")

        if os.path.exists(ep_path):
            self.episode_df = pd.read_csv(ep_path)
            logger.info(f"Loaded episode CSV: {len(self.episode_df)} rows")
        else:
            logger.warning(f"Episode CSV not found: {ep_path}")

        if os.path.exists(step_path):
            self.step_df = pd.read_csv(step_path)
            logger.info(f"Loaded step CSV: {len(self.step_df)} rows")

        if os.path.exists(curves_path):
            with open(curves_path) as f:
                self.curves = json.load(f)

        if os.path.exists(summary_path):
            with open(summary_path) as f:
                self.summary = json.load(f)

        if os.path.exists(raw_path):
            with open(raw_path) as f:
                self.raw_episodes = json.load(f)

    def ready(self) -> bool:
        return self.episode_df is not None and len(self.episode_df) > 0


# ---------------------------------------------------------------------------
# Individual plot functions
# ---------------------------------------------------------------------------

def plot_learning_curves(data: MetricsData):
    """Plot 1: Raw and rolling-average reward learning curves."""
    df = data.episode_df
    fig, axes = plt.subplots(2, 1, figsize=(12, 8), sharex=True)
    _apply_dark_style(fig, axes)

    eps = df["episode"]

    # Top: raw rewards
    ax = axes[0]
    ax.plot(eps, df["avg_attacker_reward"], color=ATTACKER_COLOR,
            alpha=0.4, linewidth=1, label="Attacker (raw)")
    ax.plot(eps, df["avg_defender_reward"], color=DEFENDER_COLOR,
            alpha=0.4, linewidth=1, label="Defender (raw)")
    ax.plot(eps, df["rolling_atk_reward_10"], color=ATTACKER_COLOR,
            linewidth=2.5, label="Attacker (rolling-10)")
    ax.plot(eps, df["rolling_def_reward_10"], color=DEFENDER_COLOR,
            linewidth=2.5, label="Defender (rolling-10)")
    ax.axhline(0, color=TEXT_COLOR, linewidth=0.5, linestyle=":")
    ax.set_title("Learning Curves — Average Reward per Episode", **FONT_TITLE)
    ax.set_ylabel("Average Reward", **FONT_LABEL)
    ax.legend(facecolor=PANEL_COLOR, edgecolor=GRID_COLOR, labelcolor=TEXT_COLOR)

    # Bottom: rolling only (cleaner view)
    ax2 = axes[1]
    ax2.fill_between(eps, df["rolling_atk_reward_10"], alpha=0.3,
                     color=ATTACKER_COLOR)
    ax2.fill_between(eps, df["rolling_def_reward_10"], alpha=0.3,
                     color=DEFENDER_COLOR)
    ax2.plot(eps, df["rolling_atk_reward_10"], color=ATTACKER_COLOR,
             linewidth=2, label="Attacker rolling-10")
    ax2.plot(eps, df["rolling_def_reward_10"], color=DEFENDER_COLOR,
             linewidth=2, label="Defender rolling-10")
    ax2.set_title("Rolling-Average Reward (window=10)", **FONT_TITLE)
    ax2.set_xlabel("Episode", **FONT_LABEL)
    ax2.set_ylabel("Rolling Avg Reward", **FONT_LABEL)
    ax2.legend(facecolor=PANEL_COLOR, edgecolor=GRID_COLOR, labelcolor=TEXT_COLOR)

    plt.tight_layout()
    path = os.path.join(data.plot_dir, "01_learning_curves.png")
    plt.savefig(path, dpi=DPI, facecolor=BG_COLOR)
    plt.close()
    logger.info(f"Saved: {path}")


def plot_success_vs_detection(data: MetricsData):
    """Plot 2: Attack success rate vs detection accuracy per episode."""
    df = data.episode_df
    fig, ax = plt.subplots(figsize=(12, 5))
    _apply_dark_style(fig, [ax])

    eps = df["episode"]
    ax.plot(eps, df["attack_success_rate"] * 100, color=ATTACKER_COLOR,
            linewidth=2, label="Attack Success Rate %")
    ax.plot(eps, df["detection_accuracy"] * 100, color=DEFENDER_COLOR,
            linewidth=2, label="Detection Accuracy %")

    # Shade the gap between them
    ax.fill_between(eps,
                    df["attack_success_rate"] * 100,
                    df["detection_accuracy"] * 100,
                    where=(df["detection_accuracy"] >= df["attack_success_rate"]),
                    alpha=0.15, color=DEFENDER_COLOR, label="Defender advantage")
    ax.fill_between(eps,
                    df["attack_success_rate"] * 100,
                    df["detection_accuracy"] * 100,
                    where=(df["attack_success_rate"] > df["detection_accuracy"]),
                    alpha=0.15, color=ATTACKER_COLOR, label="Attacker advantage")

    ax.set_title("Attack Success Rate vs Detection Accuracy", **FONT_TITLE)
    ax.set_xlabel("Episode", **FONT_LABEL)
    ax.set_ylabel("Rate (%)", **FONT_LABEL)
    ax.set_ylim(0, 110)
    ax.yaxis.set_major_formatter(mticker.PercentFormatter(xmax=100))
    ax.legend(facecolor=PANEL_COLOR, edgecolor=GRID_COLOR, labelcolor=TEXT_COLOR)

    plt.tight_layout()
    path = os.path.join(data.plot_dir, "02_success_vs_detection.png")
    plt.savefig(path, dpi=DPI, facecolor=BG_COLOR)
    plt.close()
    logger.info(f"Saved: {path}")


def plot_false_positive_rate(data: MetricsData):
    """Plot 3: False positive rate trend with rolling average."""
    df = data.episode_df
    fig, ax = plt.subplots(figsize=(12, 4))
    _apply_dark_style(fig, [ax])

    eps = df["episode"]
    fp  = df["false_positive_rate"] * 100
    rolling_fp = fp.rolling(window=10, min_periods=1).mean()

    ax.bar(eps, fp, color=ACCENT_COLOR, alpha=0.5, width=0.8, label="False Positive Rate %")
    ax.plot(eps, rolling_fp, color=ACCENT_COLOR, linewidth=2.5,
            label="Rolling avg (10 ep)")

    ax.set_title("Defender False Positive Rate per Episode", **FONT_TITLE)
    ax.set_xlabel("Episode", **FONT_LABEL)
    ax.set_ylabel("False Positive Rate (%)", **FONT_LABEL)
    ax.yaxis.set_major_formatter(mticker.PercentFormatter(xmax=100))
    ax.legend(facecolor=PANEL_COLOR, edgecolor=GRID_COLOR, labelcolor=TEXT_COLOR)

    plt.tight_layout()
    path = os.path.join(data.plot_dir, "03_false_positive_rate.png")
    plt.savefig(path, dpi=DPI, facecolor=BG_COLOR)
    plt.close()
    logger.info(f"Saved: {path}")


def plot_response_time(data: MetricsData):
    """Plot 4: Average defense response time per episode."""
    df = data.episode_df
    fig, ax = plt.subplots(figsize=(12, 4))
    _apply_dark_style(fig, [ax])

    eps = df["episode"]
    rt  = df["avg_response_time_s"] * 1000   # convert to ms for readability
    rolling_rt = rt.rolling(window=10, min_periods=1).mean()

    ax.plot(eps, rt, color=NEUTRAL_COLOR, alpha=0.4, linewidth=1, label="Response time (ms)")
    ax.plot(eps, rolling_rt, color=NEUTRAL_COLOR, linewidth=2.5,
            label="Rolling avg (10 ep)")
    ax.fill_between(eps, 0, rt, color=NEUTRAL_COLOR, alpha=0.1)

    ax.set_title("Average Defense Response Time per Episode", **FONT_TITLE)
    ax.set_xlabel("Episode", **FONT_LABEL)
    ax.set_ylabel("Response Time (ms)", **FONT_LABEL)
    ax.legend(facecolor=PANEL_COLOR, edgecolor=GRID_COLOR, labelcolor=TEXT_COLOR)

    plt.tight_layout()
    path = os.path.join(data.plot_dir, "04_response_time.png")
    plt.savefig(path, dpi=DPI, facecolor=BG_COLOR)
    plt.close()
    logger.info(f"Saved: {path}")


def plot_epsilon_decay(data: MetricsData):
    """Plot 5: Epsilon decay curves for both agents."""
    df = data.episode_df
    fig, ax = plt.subplots(figsize=(12, 4))
    _apply_dark_style(fig, [ax])

    eps = df["episode"]
    ax.plot(eps, df["attacker_epsilon"], color=ATTACKER_COLOR, linewidth=2,
            label="Attacker ε (exploration rate)")
    ax.plot(eps, df["defender_epsilon"], color=DEFENDER_COLOR, linewidth=2,
            label="Defender ε (exploration rate)")

    ax.set_title("Epsilon Decay — Exploration vs Exploitation", **FONT_TITLE)
    ax.set_xlabel("Episode", **FONT_LABEL)
    ax.set_ylabel("Epsilon (ε)", **FONT_LABEL)
    ax.set_ylim(0, 1.05)
    ax.legend(facecolor=PANEL_COLOR, edgecolor=GRID_COLOR, labelcolor=TEXT_COLOR)

    # Annotate exploitation phase
    ax.axhline(0.1, color=TEXT_COLOR, linewidth=0.8, linestyle=":",
               label="Full exploitation threshold (ε=0.1)")

    plt.tight_layout()
    path = os.path.join(data.plot_dir, "05_epsilon_decay.png")
    plt.savefig(path, dpi=DPI, facecolor=BG_COLOR)
    plt.close()
    logger.info(f"Saved: {path}")


def plot_cumulative_outcomes(data: MetricsData):
    """Plot 6: Cumulative compromise count and block count."""
    df = data.episode_df
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    _apply_dark_style(fig, axes)

    eps = df["episode"]

    # Compromises
    ax1 = axes[0]
    ax1.step(eps, df["cumulative_compromise_count"], color=ATTACKER_COLOR,
             linewidth=2.5, where="post")
    ax1.fill_between(eps, df["cumulative_compromise_count"],
                     step="post", alpha=0.25, color=ATTACKER_COLOR)
    ax1.set_title("Cumulative Target Compromises", **FONT_TITLE)
    ax1.set_xlabel("Episode", **FONT_LABEL)
    ax1.set_ylabel("Cumulative Count", **FONT_LABEL)

    # Blocks
    ax2 = axes[1]
    ax2.step(eps, df["cumulative_block_count"], color=DEFENDER_COLOR,
             linewidth=2.5, where="post")
    ax2.fill_between(eps, df["cumulative_block_count"],
                     step="post", alpha=0.25, color=DEFENDER_COLOR)
    ax2.set_title("Cumulative Successful Blocks", **FONT_TITLE)
    ax2.set_xlabel("Episode", **FONT_LABEL)
    ax2.set_ylabel("Cumulative Count", **FONT_LABEL)

    plt.suptitle("Cumulative Outcomes Over All Episodes",
                 color=TEXT_COLOR, fontsize=14, fontweight="bold", y=1.02)
    plt.tight_layout()
    path = os.path.join(data.plot_dir, "06_cumulative_outcomes.png")
    plt.savefig(path, dpi=DPI, facecolor=BG_COLOR, bbox_inches="tight")
    plt.close()
    logger.info(f"Saved: {path}")


def plot_action_distributions(data: MetricsData):
    """Plot 7: Attacker and Defender action frequency distributions."""
    if data.step_df is None:
        logger.warning("Step CSV not available — skipping action distributions.")
        return

    df = data.step_df
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    _apply_dark_style(fig, axes)

    # Attacker actions
    ax1 = axes[0]
    atk_counts = df["atk_action"].value_counts()
    bars = ax1.bar(atk_counts.index, atk_counts.values,
                   color=ATTACKER_COLOR, alpha=0.85)
    ax1.bar_label(bars, fmt="%d", color=TEXT_COLOR, fontsize=9)
    ax1.set_title("Attacker Action Distribution", **FONT_TITLE)
    ax1.set_xlabel("Action", **FONT_LABEL)
    ax1.set_ylabel("Frequency", **FONT_LABEL)

    # Defender actions
    ax2 = axes[1]
    def_counts = df["def_action"].value_counts()
    bars2 = ax2.bar(def_counts.index, def_counts.values,
                    color=DEFENDER_COLOR, alpha=0.85)
    ax2.bar_label(bars2, fmt="%d", color=TEXT_COLOR, fontsize=9)
    ax2.set_title("Defender Action Distribution", **FONT_TITLE)
    ax2.set_xlabel("Action", **FONT_LABEL)
    ax2.set_ylabel("Frequency", **FONT_LABEL)

    plt.suptitle("Action Distributions (All Episodes)",
                 color=TEXT_COLOR, fontsize=14, fontweight="bold", y=1.02)
    plt.tight_layout()
    path = os.path.join(data.plot_dir, "07_action_distributions.png")
    plt.savefig(path, dpi=DPI, facecolor=BG_COLOR, bbox_inches="tight")
    plt.close()
    logger.info(f"Saved: {path}")


def plot_action_heatmap(data: MetricsData):
    """Plot 8: Action co-occurrence heatmap (attacker action vs defender action)."""
    if data.step_df is None:
        logger.warning("Step CSV not available — skipping action heatmap.")
        return

    df = data.step_df
    pivot = pd.crosstab(df["atk_action"], df["def_action"])

    fig, ax = plt.subplots(figsize=(10, 6))
    fig.patch.set_facecolor(BG_COLOR)
    ax.set_facecolor(PANEL_COLOR)

    cmap = LinearSegmentedColormap.from_list(
        "cyber", [PANEL_COLOR, DEFENDER_COLOR, ATTACKER_COLOR])
    sns.heatmap(pivot, ax=ax, cmap=cmap, annot=True, fmt="d",
                linewidths=0.5, linecolor=GRID_COLOR,
                cbar_kws={"label": "Co-occurrence Count"})

    ax.set_title("Attacker vs Defender Action Co-occurrence", **FONT_TITLE)
    ax.set_xlabel("Defender Action", **FONT_LABEL)
    ax.set_ylabel("Attacker Action", **FONT_LABEL)
    ax.tick_params(**FONT_TICK)

    plt.tight_layout()
    path = os.path.join(data.plot_dir, "08_action_heatmap.png")
    plt.savefig(path, dpi=DPI, facecolor=BG_COLOR)
    plt.close()
    logger.info(f"Saved: {path}")


def plot_win_rate_summary(data: MetricsData):
    """Plot 9: Win rate summary bar chart from final summary JSON."""
    if data.summary is None:
        logger.warning("Summary JSON not available — skipping win rate chart.")
        return

    overall = data.summary.get("overall", {})
    fig, ax = plt.subplots(figsize=(8, 5))
    _apply_dark_style(fig, [ax])

    labels = ["Attacker\nWin Rate", "Defender\nWin Rate",
              "Compromise\nRate", "Block Rate\nper Episode"]
    values = [
        overall.get("attacker_win_rate", 0) * 100,
        overall.get("defender_win_rate", 0) * 100,
        overall.get("compromise_rate",   0) * 100,
        min(overall.get("block_rate_per_ep", 0) * 10, 100),   # normalised
    ]
    colors = [ATTACKER_COLOR, DEFENDER_COLOR, ATTACKER_COLOR, DEFENDER_COLOR]

    bars = ax.bar(labels, values, color=colors, alpha=0.85)
    ax.bar_label(bars, fmt="%.1f%%", color=TEXT_COLOR, fontsize=10,
                 fontweight="bold")
    ax.set_ylim(0, 115)
    ax.set_title("Simulation Win-Rate Summary", **FONT_TITLE)
    ax.set_ylabel("Rate (%)", **FONT_LABEL)
    ax.yaxis.set_major_formatter(mticker.PercentFormatter(xmax=100))

    plt.tight_layout()
    path = os.path.join(data.plot_dir, "09_win_rate_summary.png")
    plt.savefig(path, dpi=DPI, facecolor=BG_COLOR)
    plt.close()
    logger.info(f"Saved: {path}")


def plot_metric_correlation(data: MetricsData):
    """Plot 10: Correlation heatmap of all key episode metrics."""
    df = data.episode_df
    cols = [
        "avg_attacker_reward", "avg_defender_reward",
        "attack_success_rate", "detection_accuracy",
        "false_positive_rate", "avg_response_time_s",
        "attacker_epsilon", "defender_epsilon",
        "total_blocks", "total_false_positives",
    ]
    available = [c for c in cols if c in df.columns]
    corr = df[available].corr()

    fig, ax = plt.subplots(figsize=(12, 9))
    fig.patch.set_facecolor(BG_COLOR)
    ax.set_facecolor(PANEL_COLOR)

    cmap = sns.diverging_palette(10, 130, as_cmap=True)
    mask = np.zeros_like(corr, dtype=bool)
    mask[np.triu_indices_from(mask)] = True   # show lower triangle

    sns.heatmap(corr, ax=ax, mask=mask, cmap=cmap, center=0,
                annot=True, fmt=".2f", linewidths=0.5,
                linecolor=GRID_COLOR,
                cbar_kws={"label": "Pearson r"})
    ax.set_title("Metric Correlation Heatmap", **FONT_TITLE)
    ax.tick_params(**FONT_TICK)

    plt.tight_layout()
    path = os.path.join(data.plot_dir, "10_metric_correlation.png")
    plt.savefig(path, dpi=DPI, facecolor=BG_COLOR)
    plt.close()
    logger.info(f"Saved: {path}")


def plot_episode_outcomes_pie(data: MetricsData):
    """Plot 11: Episode outcome distribution pie chart."""
    df = data.episode_df
    if "target_compromised" not in df.columns:
        logger.warning("target_compromised column not found — skipping pie chart.")
        return

    compromised    = int(df["target_compromised"].sum())
    not_compromised= len(df) - compromised

    fig, ax = plt.subplots(figsize=(7, 7))
    fig.patch.set_facecolor(BG_COLOR)
    ax.set_facecolor(BG_COLOR)

    labels = ["Target Compromised\n(Attacker wins)", "Target Defended\n(Defender wins)"]
    sizes  = [compromised, not_compromised]
    colors = [ATTACKER_COLOR, DEFENDER_COLOR]
    explode= (0.05, 0.05)

    wedges, texts, autotexts = ax.pie(
        sizes, labels=labels, colors=colors, explode=explode,
        autopct="%1.1f%%", startangle=90,
        wedgeprops={"edgecolor": BG_COLOR, "linewidth": 2},
        textprops={"color": TEXT_COLOR},
    )
    for at in autotexts:
        at.set_fontsize(12)
        at.set_fontweight("bold")

    ax.set_title("Episode Outcome Distribution", **FONT_TITLE)

    plt.tight_layout()
    path = os.path.join(data.plot_dir, "11_episode_outcomes_pie.png")
    plt.savefig(path, dpi=DPI, facecolor=BG_COLOR)
    plt.close()
    logger.info(f"Saved: {path}")


def plot_dashboard(data: MetricsData):
    """Plot 12: Combined 6-panel dashboard figure."""
    df = data.episode_df
    fig = plt.figure(figsize=(20, 14))
    fig.patch.set_facecolor(BG_COLOR)

    gs = gridspec.GridSpec(3, 3, figure=fig, hspace=0.45, wspace=0.35)

    axes = []

    # Panel 1: Learning curves
    ax1 = fig.add_subplot(gs[0, :2])
    axes.append(ax1)
    eps = df["episode"]
    ax1.plot(eps, df["rolling_atk_reward_10"], color=ATTACKER_COLOR,
             linewidth=2, label="Attacker (rolling-10)")
    ax1.plot(eps, df["rolling_def_reward_10"], color=DEFENDER_COLOR,
             linewidth=2, label="Defender (rolling-10)")
    ax1.axhline(0, color=TEXT_COLOR, linewidth=0.5, linestyle=":")
    ax1.set_title("Learning Curves (Rolling Reward)", **FONT_TITLE)
    ax1.set_ylabel("Reward", **FONT_LABEL)
    ax1.legend(facecolor=PANEL_COLOR, edgecolor=GRID_COLOR,
               labelcolor=TEXT_COLOR, fontsize=8)

    # Panel 2: Attack success vs detection
    ax2 = fig.add_subplot(gs[0, 2])
    axes.append(ax2)
    ax2.plot(eps, df["attack_success_rate"] * 100, color=ATTACKER_COLOR,
             linewidth=1.5, label="Atk success %")
    ax2.plot(eps, df["detection_accuracy"] * 100, color=DEFENDER_COLOR,
             linewidth=1.5, label="Detection %")
    ax2.set_title("Success vs Detection", **FONT_TITLE)
    ax2.set_ylabel("%", **FONT_LABEL)
    ax2.legend(facecolor=PANEL_COLOR, edgecolor=GRID_COLOR,
               labelcolor=TEXT_COLOR, fontsize=8)

    # Panel 3: False positive rate
    ax3 = fig.add_subplot(gs[1, 0])
    axes.append(ax3)
    fp_rolling = (df["false_positive_rate"] * 100).rolling(10, min_periods=1).mean()
    ax3.plot(eps, fp_rolling, color=ACCENT_COLOR, linewidth=2)
    ax3.fill_between(eps, 0, fp_rolling, color=ACCENT_COLOR, alpha=0.2)
    ax3.set_title("False Positive Rate (%)", **FONT_TITLE)
    ax3.set_ylabel("%", **FONT_LABEL)

    # Panel 4: Response time
    ax4 = fig.add_subplot(gs[1, 1])
    axes.append(ax4)
    rt_ms = df["avg_response_time_s"] * 1000
    rt_rolling = rt_ms.rolling(10, min_periods=1).mean()
    ax4.plot(eps, rt_rolling, color=NEUTRAL_COLOR, linewidth=2)
    ax4.fill_between(eps, 0, rt_rolling, color=NEUTRAL_COLOR, alpha=0.2)
    ax4.set_title("Avg Response Time (ms)", **FONT_TITLE)
    ax4.set_ylabel("ms", **FONT_LABEL)

    # Panel 5: Epsilon decay
    ax5 = fig.add_subplot(gs[1, 2])
    axes.append(ax5)
    ax5.plot(eps, df["attacker_epsilon"], color=ATTACKER_COLOR,
             linewidth=2, label="Attacker ε")
    ax5.plot(eps, df["defender_epsilon"], color=DEFENDER_COLOR,
             linewidth=2, label="Defender ε")
    ax5.set_title("Epsilon Decay", **FONT_TITLE)
    ax5.set_ylabel("ε", **FONT_LABEL)
    ax5.legend(facecolor=PANEL_COLOR, edgecolor=GRID_COLOR,
               labelcolor=TEXT_COLOR, fontsize=8)

    # Panel 6: Cumulative outcomes
    ax6 = fig.add_subplot(gs[2, :2])
    axes.append(ax6)
    ax6.step(eps, df["cumulative_compromise_count"], color=ATTACKER_COLOR,
             linewidth=2, where="post", label="Compromises")
    ax6.step(eps, df["cumulative_block_count"], color=DEFENDER_COLOR,
             linewidth=2, where="post", label="Blocks")
    ax6.set_title("Cumulative Outcomes", **FONT_TITLE)
    ax6.set_xlabel("Episode", **FONT_LABEL)
    ax6.set_ylabel("Count", **FONT_LABEL)
    ax6.legend(facecolor=PANEL_COLOR, edgecolor=GRID_COLOR,
               labelcolor=TEXT_COLOR, fontsize=8)

    # Panel 7: Pie summary
    ax7 = fig.add_subplot(gs[2, 2])
    axes.append(ax7)
    ax7.set_facecolor(BG_COLOR)
    compromised = int(df["target_compromised"].sum()) if "target_compromised" in df.columns else 0
    defended    = len(df) - compromised
    ax7.pie([compromised, defended],
            labels=["Attacker\nwins", "Defender\nwins"],
            colors=[ATTACKER_COLOR, DEFENDER_COLOR],
            autopct="%1.0f%%", startangle=90,
            wedgeprops={"edgecolor": BG_COLOR, "linewidth": 1.5},
            textprops={"color": TEXT_COLOR, "fontsize": 9})
    ax7.set_title("Win Split", **FONT_TITLE)

    _apply_dark_style(fig, axes)

    fig.suptitle("AI-vs-AI Cyber Defense Simulator — Dashboard",
                 color=TEXT_COLOR, fontsize=16, fontweight="bold", y=0.98)

    path = os.path.join(data.plot_dir, "12_dashboard.png")
    plt.savefig(path, dpi=DPI, facecolor=BG_COLOR, bbox_inches="tight")
    plt.close()
    logger.info(f"Saved dashboard: {path}")


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

PLOT_FUNCTIONS = [
    plot_learning_curves,
    plot_success_vs_detection,
    plot_false_positive_rate,
    plot_response_time,
    plot_epsilon_decay,
    plot_cumulative_outcomes,
    plot_action_distributions,
    plot_action_heatmap,
    plot_win_rate_summary,
    plot_metric_correlation,
    plot_episode_outcomes_pie,
    plot_dashboard,
]


def generate_all_plots(metrics_dir: str = None):
    """Generate all plots from metrics stored in metrics_dir."""
    mdir = metrics_dir or METRICS_OUTPUT_DIR
    logger.info(f"Generating plots from: {mdir}")

    data = MetricsData(mdir)
    if not data.ready():
        logger.error("No episode metrics found. Run the simulation first.")
        return

    for fn in PLOT_FUNCTIONS:
        try:
            fn(data)
        except Exception as e:
            logger.error(f"Plot function {fn.__name__} failed: {e}", exc_info=True)

    logger.info(f"\nAll plots saved to: {data.plot_dir}")
    return data.plot_dir


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate visualisation plots for AI-vs-AI Cyber Defense Simulator")
    parser.add_argument("--dir", type=str, default=None,
                        help="Path to metrics directory (default: from config)")
    args = parser.parse_args()

    plot_dir = generate_all_plots(args.dir)
    if plot_dir:
        print(f"\n✅ All plots generated successfully in: {plot_dir}")
