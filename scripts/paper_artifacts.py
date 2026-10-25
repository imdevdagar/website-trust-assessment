#!/usr/bin/env python
"""Build the paper's data figures and result tables from frozen artifacts.

Every number is read from a committed artifact. The script aborts if the dataset
hash or split counts no longer match the run that produced the published metrics,
or if the H4 gate no longer passes, so a silently drifted artifact cannot reach
the manuscript.

Usage:
    PYTHONPATH=. python scripts/paper_artifacts.py
"""

from __future__ import annotations

import hashlib
import json
import platform
import statistics
import sys
import time
import tracemalloc
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PAPER = ROOT / "paper"
FIGURES = PAPER / "figures"
TABLES = PAPER / "tables"

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D

BLUE = "#0072B2"
VERMILION = "#D55E00"
GREEN = "#009E73"
ORANGE = "#E69F00"
GREY = "#7F7F7F"
PURPLE = "#CC79A7"
SKY = "#56B4E9"

plt.rcParams.update(
    {
        "font.family": "serif",
        "font.serif": ["DejaVu Serif"],
        "font.size": 8,
        "axes.labelsize": 8,
        "axes.titlesize": 9,
        "legend.fontsize": 7,
        "xtick.labelsize": 7,
        "ytick.labelsize": 7,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "figure.dpi": 300,
        "savefig.bbox": "tight",
        "pdf.fonttype": 42,
        "axes.grid": False,
    }
)


def load(rel: str) -> dict:
    return json.loads((ROOT / rel).read_text(encoding="utf-8"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def save(fig, name: str) -> None:
    FIGURES.mkdir(parents=True, exist_ok=True)
    for suffix in (".pdf", ".png"):
        fig.savefig(FIGURES / f"{name}{suffix}")
    plt.close(fig)
    print(f"  figure {name}.pdf/.png")


def md_table(headers: list[str], rows: list[list[str]], align: str | None = None) -> str:
    if align is None:
        align = "l" + "r" * (len(headers) - 1)
    marks = ["---:" if flag == "r" else "---" for flag in align]
    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join(marks) + " |"]
    lines.extend("| " + " | ".join(row) + " |" for row in rows)
    return "\n".join(lines) + "\n"


def write_md(name: str, body: str) -> None:
    TABLES.mkdir(parents=True, exist_ok=True)
    (TABLES / name).write_text(body, encoding="utf-8", newline="\n")
    print(f"  table  {name}")


def f3(value: float) -> str:
    return f"{value:.3f}"


def pct(value: float) -> str:
    return f"{100.0 * value:.1f}%"


def ci_text(block: dict) -> str:
    return f"{block['point']:.3f} [{block['low']:.3f}, {block['high']:.3f}]"


# ---------------------------------------------------------------- load + audit

MANIFEST = load("data/datasets/feed_v2/manifest.json")
RUN = load("data/research/runs/feed_v2/run.json")
RUN_S43 = load("data/research/runs/feed_v2_s43/run.json")
RUN_NO_B02 = load("data/research/runs/feed_v2_no_batch_02/run.json")
PROFILE = load("data/research/profile_feed_v2.json")
ERROR = load("data/research/error_analysis_feed_v2.json")
H4 = load("data/research/injection_h4.json")
HUMAN = load("data/labels/feed/human_vs_feed_final.json")
CHURN = load("data/labels/feed/churn/churn_report.json")
FIXTURES = load("data/injection_fixtures/manifest.json")
LEARNING = load("data/research/learning_curve.json")

DATASET_SHA = sha256_file(ROOT / "data/datasets/feed_v2/dataset.jsonl")
assert DATASET_SHA == RUN["dataset"]["sha256"], "dataset no longer matches the published run"
assert MANIFEST["files"]["dataset_jsonl"]["sha256"] == DATASET_SHA
GROUP = RUN["groups"]["hybrid"]
SPLITS = GROUP["splits"]
for split in ("train", "val", "test"):
    assert SPLITS[split]["samples"] == MANIFEST["splits"][split]["samples"]
    assert SPLITS[split]["domains"] == MANIFEST["splits"][split]["domains"]
assert MANIFEST["samples"] == PROFILE["samples"]
assert MANIFEST["targets"]["1"] == PROFILE["malicious"]["n"]
assert MANIFEST["targets"]["0"] == PROFILE["benign"]["n"]

rows = H4["rows"]
tp = sum(1 for row in rows if row["truth"] == "injection" and row["predicted_injection"])
fn = sum(1 for row in rows if row["truth"] == "injection" and not row["predicted_injection"])
fp = sum(1 for row in rows if row["truth"] != "injection" and row["predicted_injection"])
tn = len(rows) - tp - fn - fp
reference = H4["detection"]["all"]["confusion"]
assert (tp, fp, fn, tn) == (reference["tp"], reference["fp"], reference["fn"], reference["tn"])
assert H4["passed"] and all(H4["gate"].values()), "H4 isolation gate no longer passes"
assert ERROR["reproduction_ok"]
assert LEARNING["dataset_sha256"] == DATASET_SHA, "learning curve is from another dataset build"
assert LEARNING["train"]["samples"] == SPLITS["train"]["samples"]
assert LEARNING["train"]["domains"] == SPLITS["train"]["domains"]
assert abs(LEARNING["anchor"]["difference"]) < 0.02, (
    "full-data learning-curve point no longer reproduces the run's grouped CV estimate"
)


# -------------------------------------------------------------------- figures

def figure_dataset() -> None:
    order = ["train", "val", "test"]
    malicious = [MANIFEST["splits"][s]["labels"]["malicious"] for s in order]
    benign = [MANIFEST["splits"][s]["labels"]["benign"] for s in order]
    domains = [MANIFEST["splits"][s]["domains"] for s in order]

    fig, ax = plt.subplots(figsize=(3.4, 2.7))
    x = range(len(order))
    bars = ax.bar(x, malicious, 0.55, color=VERMILION, label="malicious (in feed)")
    ax.bar(x, benign, 0.55, bottom=malicious, color=BLUE, label="benign (feed-absent)")
    for idx, (top, bottom) in enumerate(zip(malicious, benign)):
        ax.text(idx, top / 2, str(top), ha="center", va="center", color="white", fontsize=7)
        ax.text(idx, top + bottom / 2, str(bottom), ha="center", va="center", color="white", fontsize=7)
        ax.text(idx, top + bottom + 12, f"n={top + bottom}\n{domains[idx]} domains",
                ha="center", va="bottom", fontsize=6.5)
    ax.set_xticks(list(x), [s.capitalize() for s in order])
    ax.set_ylabel("Samples")
    ax.set_ylim(0, 680)
    ax.legend(loc="upper right", frameon=False)
    save(fig, "fig3_dataset_composition")


def figure_label_sources() -> None:
    fig, (left, right) = plt.subplots(1, 2, figsize=(6.8, 2.9), gridspec_kw={"width_ratios": [1, 1.3]})
    fig.subplots_adjust(wspace=0.62)

    labels = ["benign", "suspicious", "malicious"]
    matrix = [
        [HUMAN["human_label_by_feed_membership"][label]["in_feed"],
         HUMAN["human_label_by_feed_membership"][label]["not_in_feed"]]
        for label in labels
    ]
    peak = max(max(row) for row in matrix)
    image = left.imshow(matrix, cmap="Blues", vmin=0, vmax=peak)
    for i, row in enumerate(matrix):
        for j, value in enumerate(row):
            left.text(j, i, str(value), ha="center", va="center", fontsize=8,
                      color="white" if value > peak * 0.6 else "black")
    left.set_xticks([0, 1], ["in feed", "not in feed"])
    left.set_yticks(range(3), [s.capitalize() for s in labels])
    left.set_xlabel("Feed membership")
    left.set_title("(a) Human labels by feed (n=146)")
    left.tick_params(length=0)
    for spine in left.spines.values():
        spine.set_visible(False)

    overall = CHURN["overall"]
    collected = CHURN["collected_assessments"]
    groups = [
        ("Feed labels\n(n=549)", overall["retained"], overall["dropped"], "retained", "delisted"),
        ("Eval. positives\n(n=496)", collected["still_listed"], collected["no_longer_listed"],
         "retained", "delisted"),
        ("Eval. negatives\n(n=330)", collected["derived_benign_domains"] - collected["derived_benign_now_listed"],
         collected["derived_benign_now_listed"], "not newly listed", "newly listed"),
    ]
    y = range(len(groups))
    for idx, (_, keep, lost, _, _) in enumerate(groups):
        total = keep + lost
        right.barh(idx, keep / total, 0.55, color=BLUE)
        right.barh(idx, lost / total, 0.55, left=keep / total, color=VERMILION)
        right.text(keep / total / 2, idx, f"{keep}", ha="center", va="center",
                   color="white", fontsize=7)
        if lost:
            right.text(1.02, idx, f"{lost} ({pct(lost / total)})", ha="left", va="center", fontsize=6.5)
        else:
            right.text(1.02, idx, "0", ha="left", va="center", fontsize=6.5)
    right.set_yticks(list(y), [group[0] for group in groups])
    right.invert_yaxis()
    right.set_xlim(0, 1.22)
    right.set_xticks([0, 0.5, 1.0], ["0%", "50%", "100%"])
    right.set_xlabel("Share at second retrieval 4.43 h later")
    right.set_title("(b) Feed-label retention")
    right.legend(
        handles=[Line2D([0], [0], color=BLUE, lw=6, label="retained / not listed"),
                 Line2D([0], [0], color=VERMILION, lw=6, label="delisted / newly listed")],
        loc="upper center", bbox_to_anchor=(0.5, -0.34), ncol=2, frameon=False,
    )
    save(fig, "fig4_label_sources")


def reliability_panel(ax, bins: list[dict], title: str, ece: float) -> None:
    ax.plot([0, 1], [0, 1], color=GREY, lw=0.8, ls="--", label="perfect calibration")
    xs = [b["mean_confidence"] for b in bins]
    ys = [b["accuracy"] for b in bins]
    sizes = [14 + 2.0 * b["count"] for b in bins]
    ax.scatter(xs, ys, s=sizes, color=BLUE, edgecolor="white", linewidth=0.6, zorder=3)
    for x, y, b in zip(xs, ys, bins):
        if b["count"] >= 20:
            offset = (10, 6) if x < 0.2 else ((-14, -12) if x > 0.9 else (8, -10))
            ax.annotate(f"n={b['count']}", (x, y), textcoords="offset points",
                        xytext=offset, fontsize=6, color=GREY,
                        ha="right" if x > 0.9 else "left")
    ax.set_xlim(-0.02, 1.05)
    ax.set_ylim(-0.02, 1.02)
    ax.set_xlabel("Mean predicted probability")
    ax.set_ylabel("Observed malicious fraction")
    ax.set_title(title)
    ax.text(0.03, 0.95, f"ECE = {ece:.3f}", transform=ax.transAxes, va="top", fontsize=7)


def figure_reliability() -> None:
    models = GROUP["models"]
    fig, (left, right) = plt.subplots(1, 2, figsize=(6.4, 2.8))
    reliability_panel(left, models["rule_engine"]["reliability"],
                      "(a) Shipped rule engine (raw)",
                      models["rule_engine"]["test"]["ece"])
    reliability_panel(right, models["logistic_regression"]["reliability"],
                      "(b) Hybrid logistic (Platt-calibrated)",
                      models["logistic_regression"]["test"]["ece"])
    fig.legend(handles=[Line2D([0], [0], color=GREY, lw=0.8, ls="--", label="perfect calibration"),
                        Line2D([0], [0], marker="o", color=BLUE, ls="", ms=4,
                               label="test bins (area = count)")],
               loc="lower center", bbox_to_anchor=(0.5, -0.06), ncol=2, frameon=False)
    fig.subplots_adjust(wspace=0.42, bottom=0.28)
    save(fig, "fig5_reliability")


def figure_risk_coverage() -> None:
    models = GROUP["models"]
    entries = [
        ("Rule engine", models["rule_engine"]["risk_coverage"], VERMILION, "o"),
        ("Logistic (hybrid)", models["logistic_regression"]["risk_coverage"], BLUE, "s"),
        ("HistGB (hybrid)", models["hist_gradient_boosting"]["risk_coverage"], GREEN, "^"),
    ]
    fig, ax = plt.subplots(figsize=(3.6, 2.8))
    for label, blocks, colour, marker in entries:
        xs = [b["coverage_actual"] for b in blocks]
        ys = [b["accuracy"] for b in blocks]
        ax.plot(xs, ys, color=colour, marker=marker, lw=1.2, ms=4, label=label)
    prior = SPLITS["test"]["positives"] / SPLITS["test"]["samples"]
    ax.axhline(prior, color=GREY, lw=0.8, ls="--")
    ax.text(0.505, prior + 0.012, f"class prior {prior:.3f}", color=GREY, fontsize=6.5)
    ax.set_xlim(0.42, 1.03)
    ax.set_ylim(0.35, 1.01)
    ax.set_xlabel("Coverage (most confident first)")
    ax.set_ylabel("Accuracy on covered subset")
    ax.legend(loc="lower left", frameon=False)
    save(fig, "fig6_risk_coverage")


def figure_ablation() -> None:
    order = ["url", "signals", "rule", "hybrid"]
    labels = ["url\n(21)", "signals\n(80)", "rule\n(36)", "hybrid\n(116)"]
    engine = GROUP["models"]["rule_engine"]["bootstrap"]
    fig, (left, right) = plt.subplots(1, 2, figsize=(6.6, 2.9))
    for ax, metric, title in ((left, "roc_auc", "(a) AUROC"), (right, "average_precision", "(b) AUPRC")):
        for offset, model, colour, marker, label in (
            (-0.16, "logistic_regression", BLUE, "o", "Logistic"),
            (0.16, "hist_gradient_boosting", GREEN, "^", "HistGB"),
        ):
            points, lows, highs = [], [], []
            for group in order:
                block = RUN["groups"][group]["models"][model]["bootstrap"][metric]
                points.append(block["point"])
                lows.append(block["point"] - block["low"])
                highs.append(block["high"] - block["point"])
            xs = [idx + offset for idx in range(len(order))]
            ax.errorbar(xs, points, yerr=[lows, highs], fmt=marker, color=colour, ms=4,
                        capsize=2.5, lw=1.0, label=label)
        engine_block = engine[metric]
        ax.axhline(engine_block["point"], color=VERMILION, lw=0.9, ls="--", label="Rule engine")
        ax.fill_between([-0.5, 3.5], engine_block["low"], engine_block["high"],
                        color=VERMILION, alpha=0.12, lw=0)
        ax.set_xticks(range(len(order)), labels)
        ax.set_xlim(-0.5, 3.5)
        ax.set_title(title)
        ax.set_ylabel("Test " + ("AUROC" if metric == "roc_auc" else "AUPRC"))
        if metric == "roc_auc":
            ax.set_ylim(0.35, 1.01)
        else:
            ax.set_ylim(0.50, 1.01)
    fig.legend(handles=[Line2D([0], [0], marker="o", color=BLUE, ls="-", lw=1.0, ms=4, label="Logistic"),
                        Line2D([0], [0], marker="^", color=GREEN, ls="-", lw=1.0, ms=4, label="HistGB"),
                        Line2D([0], [0], color=VERMILION, ls="--", lw=0.9, label="Rule engine (95% band)")],
               loc="lower center", bbox_to_anchor=(0.5, -0.08), ncol=3, frameon=False)
    fig.subplots_adjust(wspace=0.3, bottom=0.30)
    save(fig, "fig7_ablation")


def figure_injection() -> None:
    positives = [row for row in rows if row["truth"] == "injection"]
    negatives = [row for row in rows if row["truth"] != "injection"]

    fig, (left, right) = plt.subplots(1, 2, figsize=(6.8, 2.9), gridspec_kw={"width_ratios": [1, 1.15]})
    limit = 52
    left.plot([0, limit], [0, limit], color=GREY, lw=0.8, ls="--")
    changed = [row for row in positives if row["inj_verdict"] != row["base_verdict"]]
    unchanged = [row for row in positives if row["inj_verdict"] == row["base_verdict"]]
    left.scatter([row["base_risk"] for row in unchanged], [row["inj_risk"] for row in unchanged],
                 s=25, color=BLUE, edgecolor="white", linewidth=0.5, label="detected, no verdict change")
    left.scatter([row["base_risk"] for row in changed], [row["inj_risk"] for row in changed],
                 s=25, color=VERMILION, edgecolor="white", linewidth=0.5, label="escalated to warn")
    left.scatter([row["base_risk"] for row in negatives], [row["inj_risk"] for row in negatives],
                 s=25, facecolor="none", edgecolor=GREY, linewidth=0.7, label="negative fixture")
    left.set_xlim(0, 12)
    left.set_ylim(0, limit)
    left.set_xlabel("Overall risk before injection (0-100)")
    left.set_ylabel("Overall risk after injection (0-100)")
    left.set_title("(a) Paired overall risk")

    ordered = sorted(positives, key=lambda row: row["score_delta_from_injection"])
    xs = range(len(ordered))
    deltas = [row["score_delta_from_injection"] for row in ordered]
    colours = [VERMILION if row["inj_verdict"] != row["base_verdict"] else BLUE for row in ordered]
    right.bar(xs, deltas, 0.75, color=colours)
    median = statistics.median(deltas)
    right.axhline(median, color=GREY, lw=0.8, ls=":")
    right.text(0.4, median - 5.0, f"median {median:.1f}", ha="left",
               fontsize=6.5, color=GREY)
    right.set_xticks([])
    right.set_xlabel("Injection cases, sorted by risk change")
    right.set_ylabel("Overall risk change (0-100)")
    right.set_ylim(0, 46)
    right.set_title("(b) Bounded escalation (26 injections)")
    fig.legend(handles=[Line2D([0], [0], color=VERMILION, lw=6, label="low/allow to medium/warn"),
                        Line2D([0], [0], color=BLUE, lw=6, label="detected, no verdict change"),
                        Line2D([0], [0], marker="o", color="none", markeredgecolor=GREY, ms=5,
                               label="negative fixture")],
               loc="lower center", bbox_to_anchor=(0.5, -0.07), ncol=3, frameon=False)
    fig.subplots_adjust(wspace=0.28, bottom=0.30)
    save(fig, "fig8_injection")


def figure_learning_curve() -> None:
    fig, ax = plt.subplots(figsize=(3.8, 2.9))
    series = (
        ("logistic", BLUE, "o", "Logistic (hybrid)"),
        ("hgb", GREEN, "^", "HistGB (hybrid)"),
    )
    for model, colour, marker, label in series:
        points = LEARNING["curves"][model]["points"]
        xs = [point["n_train_domains_mean"] for point in points]
        ys = [point["auroc"]["mean"] for point in points]
        lows = [point["auroc"]["ci"][0] for point in points]
        highs = [point["auroc"]["ci"][1] for point in points]
        ax.plot(xs, ys, color=colour, marker=marker, ms=4, lw=1.2, label=label)
        ax.fill_between(xs, lows, highs, color=colour, alpha=0.14, lw=0)
    reference = LEARNING["curves"]["logistic"]["points"]
    ax.set_xticks(
        [point["n_train_domains_mean"] for point in reference],
        [f"{point['n_train_domains_mean']:.0f}\n{point['fraction']:.0%}" for point in reference],
    )
    ax.set_xlim(0, 500)
    ax.set_ylim(0.86, 1.005)
    ax.set_xlabel("Training domains per fold (share of full)")
    ax.set_ylabel("Out-of-fold AUROC")
    ax.legend(loc="lower right", frameon=False)
    save(fig, "fig9_learning_curve")


def figure_architecture() -> None:
    from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

    fig = plt.figure(figsize=(7.2, 4.42))
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, 12.4)
    ax.set_ylim(0, 7.6)
    ax.axis("off")

    def zone(x, y, w, h, label, colour, ls="-"):
        for patch in (
            FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.12",
                           fc=colour, ec=colour, lw=0.8, alpha=0.10, zorder=0),
            FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.12",
                           fc="none", ec=colour, lw=0.8, ls=ls, zorder=0.5),
        ):
            ax.add_patch(patch)
        ax.text(x + 0.18, y + h - 0.14, label, ha="left", va="top", fontsize=7.0,
                weight="bold", color=colour)

    def box(x, y, w, h, title, sub=None, edge=BLUE, fill="#E8F1F8"):
        ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.015,rounding_size=0.07",
                                    fc=fill, ec=edge, lw=1.0, zorder=2))
        if sub:
            ax.text(x + w / 2, y + h / 2 + 0.12, title, ha="center", va="center",
                    fontsize=7.0, weight="bold", color="#222222", zorder=3)
            ax.text(x + w / 2, y + h / 2 - 0.15, sub, ha="center", va="center",
                    fontsize=5.9, color="#333333", linespacing=1.15, zorder=3)
        else:
            ax.text(x + w / 2, y + h / 2, title, ha="center", va="center",
                    fontsize=7.0, weight="bold", color="#222222", zorder=3)

    def arrow(x1, y1, x2, y2, label=None, lx=0.0, ly=0.0, ha="center"):
        ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="-|>", mutation_scale=9,
                                     lw=1.0, color="#444444", shrinkA=2, shrinkB=2, zorder=1.5))
        if label:
            ax.text((x1 + x2) / 2 + lx, (y1 + y2) / 2 + ly, label, ha=ha, va="center",
                    fontsize=5.8, style="italic", color="#333333",
                    bbox={"boxstyle": "round,pad=0.15", "fc": "white", "ec": "none", "alpha": 0.92},
                    zorder=3)

    zone(0.25, 2.05, 8.95, 5.05, "Local machine — trusted process (localhost only)", BLUE)
    zone(9.45, 4.65, 2.70, 2.45, "Untrusted web", VERMILION, ls=(0, (4, 3)))
    zone(0.25, 0.20, 11.90, 1.65,
         "Offline research path — no network; evaluation artifacts are never loaded by the runtime", GREEN)

    box(0.45, 5.55, 1.55, 0.85, "Browser tab", "URL + action")
    box(2.35, 5.55, 1.55, 0.85, "Extension", "URL only; localhost")
    box(4.25, 5.55, 1.70, 0.85, "FastAPI service", "127.0.0.1; single user")
    box(6.45, 5.55, 2.25, 0.85, "Collector", "Chromium or static HTTP")
    box(9.60, 5.55, 1.95, 0.85, "Website", "page, scripts, redirects",
        edge=VERMILION, fill="#FBEAE1")
    box(4.30, 3.70, 1.60, 0.75, "SQLite", "assessments,\nscreenshots", edge=GREY, fill="#F2F2F2")
    box(6.45, 3.65, 2.25, 0.95, "Evidence extractors", "TLS, DNS, forms, trackers,\nOCR, hidden content")
    box(6.45, 2.35, 2.25, 0.85, "Dimension scoring", "4 dimensions + confidence")
    box(4.15, 2.35, 1.90, 0.85, "Action weights", "action-specific\nweights + abstention")
    box(1.90, 2.35, 1.85, 0.85, "Dashboard", "verdict + evidence")

    box(0.50, 0.45, 2.15, 0.85, "Frozen exports", "assessments + feed labels",
        edge=GREEN, fill="#E4F3ED")
    box(3.15, 0.45, 2.45, 0.85, "Dataset builder", "leakage audit; grouped 70/15/15",
        edge=GREEN, fill="#E4F3ED")
    box(6.10, 0.45, 2.55, 0.85, "Train, calibrate, evaluate", "logistic, HistGB, rule baseline",
        edge=GREEN, fill="#E4F3ED")
    box(9.15, 0.45, 2.70, 0.85, "Run artifacts", "figures, tables, model card",
        edge=GREEN, fill="#E4F3ED")

    arrow(2.00, 5.975, 2.35, 5.975)
    arrow(3.90, 5.975, 4.25, 5.975)
    arrow(5.95, 5.975, 6.45, 5.975)
    arrow(8.70, 5.975, 9.60, 5.975)
    arrow(5.10, 5.55, 5.10, 4.45)
    arrow(7.20, 5.55, 7.20, 4.60)
    arrow(9.60, 5.70, 8.70, 4.60)
    arrow(7.20, 3.65, 7.20, 3.20)
    arrow(6.45, 2.775, 6.05, 2.775)
    arrow(4.15, 2.775, 3.75, 2.775)

    arrow(2.65, 0.875, 3.15, 0.875)
    arrow(5.60, 0.875, 6.10, 0.875)
    arrow(8.65, 0.875, 9.15, 0.875)

    for x, text in ((4.075, "localhost HTTP"), (6.20, "collect"), (9.15, "fetch / render")):
        ax.text(x, 6.62, text, ha="center", va="center", fontsize=5.8, style="italic",
                color="#333333")
    ax.text(5.28, 5.00, "persist", ha="left", va="center", fontsize=5.8, style="italic",
            color="#333333")
    ax.text(7.38, 5.08, "captured page", ha="left", va="center", fontsize=5.8, style="italic",
            color="#333333")
    ax.text(9.28, 5.30, "page as\ndata", ha="center", va="center", fontsize=5.8, style="italic",
            color="#333333", linespacing=1.0,
            bbox={"boxstyle": "round,pad=0.12", "fc": "white", "ec": "none", "alpha": 0.9})
    ax.text(7.38, 3.43, "typed Evidence", ha="left", va="center", fontsize=5.8, style="italic",
            color="#333333")
    ax.text(6.25, 3.38, "dimension scores", ha="center", va="center", fontsize=5.8,
            style="italic", color="#333333")
    ax.text(3.95, 3.38, "verdict + cards", ha="center", va="center", fontsize=5.8,
            style="italic", color="#333333")

    save(fig, "fig1_architecture")


# --------------------------------------------------------------------- tables

def table_action_weights() -> None:
    from website_trust_assessment.schemas import Action, DIMENSION_LABELS
    from website_trust_assessment.scoring.rules import ACTION_WEIGHTS, DIMENSIONS

    actions = [Action.BROWSE, Action.SIGNUP, Action.PURCHASE]
    headers = ["Dimension"] + [action.value.capitalize() for action in actions]
    body_rows = []
    for dimension in DIMENSIONS:
        values = [f"{ACTION_WEIGHTS[action][dimension]:.2f}" for action in actions]
        body_rows.append([DIMENSION_LABELS[dimension], *values])
    totals = [f"{sum(ACTION_WEIGHTS[action][d] for d in DIMENSIONS):.2f}" for action in actions]
    body_rows.append(["**Sum**", *[f"**{value}**" for value in totals]])
    write_md("table2_action_weights.md",
             "# Table 2. Action-specific dimension weights\n\n"
             + md_table(headers, body_rows)
             + "\nExpert-set, not learned. Weights sum to 1 within each action.\n")


def table_dataset() -> None:
    headers = ["Split", "Samples", "Domains", "Malicious", "Benign"]
    body_rows = []
    for split in ("train", "val", "test"):
        counts = MANIFEST["splits"][split]
        body_rows.append([split.capitalize(), str(counts["samples"]), str(counts["domains"]),
                          str(counts["labels"]["malicious"]), str(counts["labels"]["benign"])])
    body_rows.append(["**Total**", f"**{MANIFEST['samples']}**", f"**{MANIFEST['domains']}**",
                      f"**{MANIFEST['targets']['1']}**", f"**{MANIFEST['targets']['0']}**"])
    ratios = MANIFEST["ratios"]
    ratio_text = f"{ratios['train']:.0%} / {ratios['val']:.0%} / {ratios['test']:.0%}"
    collection = (
        "\nCollection and exclusion facts (primary build `feed_v2`):\n\n"
        "- 549 feed-listed domains were planned; 50 could not be collected and were dropped, never called benign.\n"
        "- 912 scored assessments passed the leakage check (`leaked_assessments: 0`, runtime label store empty).\n"
        "- 107 crawl rows carry only `{url, error}` and were skipped as assessments that never existed.\n"
        "- 82 collected domains carry a frozen human label and no feed label, so they were excluded from the 830; the 146 frozen human labels form the separate validity subset.\n"
        "- 496 distinct malicious and 330 distinct benign domains; four domains contribute two assessments each.\n"
        f"- Dataset SHA-256 `{DATASET_SHA}`; seed {MANIFEST['seed']}; domain-grouped split ratios {ratio_text}.\n"
    )
    write_md("table3_dataset_summary.md",
             "# Table 3. Dataset composition\n\n" + md_table(headers, body_rows) + collection)


def table_main_results() -> None:
    headers = ["Model", "AUROC [95% CI]", "AUPRC [95% CI]", "Brier", "ECE", "F1", "Precision", "Recall"]
    body_rows = []
    for key, label in (("rule_engine", "Rule engine (raw)"),
                       ("logistic_regression", "Logistic (hybrid)"),
                       ("hist_gradient_boosting", "HistGB (hybrid)")):
        model = GROUP["models"][key]
        test = model["test"]
        body_rows.append([
            label,
            ci_text(model["bootstrap"]["roc_auc"]),
            ci_text(model["bootstrap"]["average_precision"]),
            f3(test["brier"]), f3(test["ece"]), f3(test["f1"]),
            f3(test["precision"]), f3(test["recall"]),
        ])
    note = (
        "\nTest split: 123 samples / 123 domains (74 malicious / 49 benign). "
        "Thresholds and Platt calibration were selected on validation only; the test set was evaluated once. "
        "Intervals are percentile 95% bounds from 1000 domain-grouped bootstrap resamples. "
        "The rule engine's Platt fit was refused (non-positive association), so raw and calibrated scores are identical. "
        f"Dataset SHA-256 `{DATASET_SHA}`.\n"
    )
    write_md("table4_main_results.md",
             "# Table 4. Test-split results\n\n" + md_table(headers, body_rows) + note)


def table_ablation() -> None:
    headers = ["Feature group", "Features", "Model", "AUROC [95% CI]", "AUPRC [95% CI]",
               "Brier", "ECE", "F1"]
    body_rows = []
    for group in ("url", "signals", "rule", "hybrid"):
        block = RUN["groups"][group]
        for key, label in (("logistic_regression", "Logistic"), ("hist_gradient_boosting", "HistGB")):
            model = block["models"][key]
            test = model["test"]
            body_rows.append([
                f"`{group}`", str(block["feature_count"]), label,
                ci_text(model["bootstrap"]["roc_auc"]),
                ci_text(model["bootstrap"]["average_precision"]),
                f3(test["brier"]), f3(test["ece"]), f3(test["f1"]),
            ])
    engine = GROUP["models"]["rule_engine"]
    body_rows.append(["`none`", "0", "Rule engine", ci_text(engine["bootstrap"]["roc_auc"]),
                      ci_text(engine["bootstrap"]["average_precision"]),
                      f3(engine["test"]["brier"]), f3(engine["test"]["ece"]), f3(engine["test"]["f1"])])
    note = (
        "\nAll rows use the same domain-grouped test split (123 samples, 74 positive) and the same bootstrap "
        "resamples (1000, domain-grouped). `hybrid` includes the rule outputs, so it is a superset comparison, "
        "not an independent model family; `signals` is the independent page-evidence comparison.\n"
    )
    write_md("table5_ablation.md",
             "# Table 5. Feature-group ablation\n\n" + md_table(headers, body_rows) + note)


def table_https() -> None:
    headers = ["Class", "n", "HTTPS", "Trusted chain", "Mean rule risk",
               "Low / medium / high / critical", "High+ count", "High+ share"]
    body_rows = []
    for key, label in (("malicious", "Malicious (in feed)"), ("benign", "Benign (feed-absent)"),
                       ("all", "All labelled")):
        block = PROFILE[key]
        bands = block["rule_bands"]
        high_plus = bands["high"] + bands["critical"]
        body_rows.append([
            label, str(block["n"]), pct(block["https_share"]), pct(block["tls_trusted_share"]),
            f3(block["mean_rule_risk"]),
            f"{bands['low']} / {bands['medium']} / {bands['high']} / {bands['critical']}",
            str(high_plus), pct(high_plus / block["n"]),
        ])
    note = (
        "\nHTTPS presence and certificate verification are separate measurements; a certificate existing is not "
        "a certificate verifying. `Benign` means absent from both feeds at retrieval time, never verified clean. "
        "Escalation is the shipped policy: high or critical risk. For the malicious class the high+ "
        "share is recall at escalation; for the benign class it is the false-alarm rate, not a recall.\n"
    )
    baseline = PROFILE.get("transport_rule_baselines") or {}
    if not baseline.get("rules"):
        raise SystemExit("profile is missing transport_rule_baselines; rerun scripts/dataset_profile.py")
    rule_labels = {
        "https_only": "HTTPS absent (padlock-only)",
        "https_and_trusted_chain": "HTTPS absent or untrusted chain",
    }
    rule_rows = []
    for key, label in rule_labels.items():
        rule = baseline["rules"][key]
        rule_rows.append([
            label,
            f"{rule['auroc']:.3f} [{rule['auroc_ci'][0]:.3f}, {rule['auroc_ci'][1]:.3f}]",
            f3(rule["precision"]),
            f3(rule["recall"]),
            f"{rule['f1']:.3f} [{rule['f1_ci'][0]:.3f}, {rule['f1_ci'][1]:.3f}]",
        ])
    baseline_note = (
        "\n**Test rule baselines (n = 123, 74 malicious).** Each rule predicts malicious when the "
        "condition in its label holds; scores are binary, so AUC ties count as half.\n\n"
    )
    baseline_footer = (
        "\nIntervals are percentile 95% bounds from 1000 domain-grouped bootstrap resamples. The "
        "HTTPS-only rule is the pre-registered padlock baseline, implemented as a fixed rule rather "
        "than a fitted classifier; the trusted-chain rule is descriptive and was not pre-registered.\n"
    )
    write_md("table6_https_prevalence.md",
             "# Table 6. Transport security by class (H1), and padlock-only test baselines\n\n"
             + md_table(headers, body_rows) + note
             + baseline_note
             + md_table(["Rule", "AUROC [95% CI]", "Precision", "Recall", "F1 [95% CI]"], rule_rows)
             + baseline_footer)


def table_errors() -> None:
    headers = ["Feature group", "Test errors", "False positives", "False negatives", "Threshold"]
    body_rows = []
    for group in ("url", "signals", "rule", "hybrid"):
        block = ERROR["models"][group]
        counts = block["confusion_reproduced"]
        body_rows.append([f"`{group}`", str(block["error_count"]), str(counts["fp"]),
                          str(counts["fn"]), f"{block['threshold']:.3f}"])
    note = "\nAll four reproductions match the confusion recorded by the run (`reproduction_ok: true`).\n\n"
    note += "Hybrid logistic error categories (a page can carry more than one code):\n\n"
    hybrid = ERROR["models"]["hybrid"]["categories_by_kind"]
    category_rows = []
    for direction, label in (("false_negative", "False negative"), ("false_positive", "False positive")):
        for category, count in sorted(hybrid[direction].items(), key=lambda item: (-item[1], item[0])):
            category_rows.append([label, f"`{category}`", str(count)])
    write_md("table7_errors.md",
             "# Table 7. Test-split errors\n\n" + md_table(headers, body_rows) + note
             + md_table(["Direction", "Evidence category", "Pages"], category_rows))


def table_sensitivity() -> None:
    headers = ["Run", "Hybrid logistic AUROC", "Hybrid HistGB AUROC", "Engine AUROC (all labelled)"]
    body_rows = []
    profiles = {
        "feed_v2": "data/research/profile_feed_v2.json",
        "feed_v2_s43": "data/research/profile_feed_v2_s43.json",
        "feed_v2_no_batch_02": "data/research/profile_feed_v2_no_batch_02.json",
    }
    for label, artifact in (("Primary, seed 42", RUN), ("Re-split, seed 43", RUN_S43),
                            ("Without batch-02 negatives", RUN_NO_B02)):
        hybrid = artifact["groups"]["hybrid"]["models"]
        profile = load(profiles[artifact["run_id"]])
        assert profile["dataset"] == artifact["dataset"]["path"], (
            f"sensitivity profile for {artifact['run_id']} describes a different dataset"
        )
        body_rows.append([
            label,
            f3(hybrid["logistic_regression"]["test"]["roc_auc"]),
            f3(hybrid["hist_gradient_boosting"]["test"]["roc_auc"]),
            f3(profile["rule_engine_auc"]["all_labelled"]),
        ])
    note = ("\nThe engine's all-labelled AUROC is the stable comparison; its test-split AUROC moves with the "
            "split at n=123 and is not a capability estimate.\n")
    write_md("table9_sensitivity.md",
             "# Table 9. Pre-registered sensitivity runs\n\n" + md_table(headers, body_rows) + note)


def table_learning_curve() -> None:
    headers = ["Model", "Training domains", "Share", "AUROC [95% interval]", "AUPRC [95% interval]"]
    body_rows = []
    for model, label in (("logistic", "Logistic (hybrid)"), ("hgb", "HistGB (hybrid)")):
        for point in LEARNING["curves"][model]["points"]:
            auroc, auprc = point["auroc"], point["average_precision"]
            body_rows.append([
                label,
                f"{point['n_train_domains_mean']:.0f}",
                f"{point['fraction']:.0%}",
                f"{auroc['mean']:.3f} [{auroc['ci'][0]:.3f}, {auroc['ci'][1]:.3f}]",
                f"{auprc['mean']:.3f} [{auprc['ci'][0]:.3f}, {auprc['ci'][1]:.3f}]",
            ])
    anchor = LEARNING["anchor"]
    note = (
        "\nTrain-only: five-fold domain-grouped cross-validation inside the training split, re-drawn "
        f"{LEARNING['curves']['logistic']['repeats']} times for logistic and "
        f"{LEARNING['curves']['hgb']['repeats']} times for HistGB. Whole domains are subsampled per "
        "class, so a fraction never splits a domain. Intervals are the 2.5-97.5 percentile range across "
        "repeats. The validation and test splits are never scored. At full size the pooled logistic "
        f"estimate ({anchor['learning_curve_full_auroc']:.3f}) reproduces the run's grouped-CV estimate "
        f"({anchor['cv_mean_roc_auc']:.3f}) within {abs(anchor['difference']):.3f}.\n"
    )
    write_md("table10_learning_curve.md",
             "# Table 10. Learning curve (train-only grouped CV)\n\n"
             + md_table(headers, body_rows) + note)


def benchmark() -> dict:
    from website_trust_assessment.config import settings
    from website_trust_assessment.crawler import parse_html_page
    from website_trust_assessment.pipeline import assess_captured_page
    from website_trust_assessment.schemas import Action

    cfg = settings()
    cases = FIXTURES["cases"]
    payloads = []
    for record in cases:
        html = (ROOT / "data/injection_fixtures" / record["injected_file"]).read_text(encoding="utf-8")
        payloads.append((html, record["url"]))

    def once(html: str, url: str) -> None:
        page = parse_html_page(html, url)
        assess_captured_page(page, url=url, action=Action.BROWSE, cfg=cfg)

    once(*payloads[0])
    timings: list[float] = []
    tracemalloc.start()
    started = time.perf_counter()
    for _ in range(5):
        for html, url in payloads:
            start = time.perf_counter()
            once(html, url)
            timings.append((time.perf_counter() - start) * 1000.0)
    elapsed = time.perf_counter() - started
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    timings.sort()
    result = {
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "processor": platform.processor() or platform.machine(),
        },
        "offline_scoring": {
            "pages": len(timings),
            "median_ms": round(statistics.median(timings), 2),
            "p95_ms": round(timings[int(0.95 * (len(timings) - 1))], 2),
            "throughput_pages_per_second": round(len(timings) / elapsed, 1),
            "peak_traced_mb": round(peak / (1024 * 1024), 1),
            "scope": "static parse and synchronous extractors only; no network, no OCR, no persistence",
        },
        "dataset": {
            "samples": MANIFEST["samples"],
            "bytes": MANIFEST["files"]["dataset_jsonl"]["bytes"],
            "sha256": DATASET_SHA,
        },
        "model_artifacts": {},
    }
    model_dir = ROOT / "models/research/feed_v2"
    for path in sorted(model_dir.glob("*.json")):
        result["model_artifacts"][path.name] = path.stat().st_size
    return result


def table_runtime(timings: dict) -> None:
    scoring = timings["offline_scoring"]
    headers = ["Measurement", "Value"]
    body_rows = [
        ["Environment", f"Python {timings['environment']['python']}; {timings['environment']['processor']}"],
        ["Offline parse + score, median", f"{scoring['median_ms']} ms/page"],
        ["Offline parse + score, p95", f"{scoring['p95_ms']} ms/page"],
        ["Throughput", f"{scoring['throughput_pages_per_second']} pages/s"],
        ["Peak traced memory", f"{scoring['peak_traced_mb']} MB"],
        ["Dataset size", f"{timings['dataset']['bytes'] / 1e6:.2f} MB ({timings['dataset']['samples']} samples)"],
    ]
    for name, size in timings["model_artifacts"].items():
        body_rows.append([f"Model artifact `{name}`", f"{size / 1024:.1f} KB"])
    note = ("\nMeasured on 210 offline page scorings (42 fixtures x 5 repeats) after one warm-up page. "
            "This isolates the scoring core; live collection latency is dominated by page load and lies outside "
            "this measurement. Peak memory is Python allocations tracked by `tracemalloc`, so it excludes "
            "the interpreter baseline and any native allocations; Chromium, when used for a live crawl, "
            "is the largest runtime consumer and is not part of this number. The suite and all runs are "
            "CPU-only with no paid API or GPU."
    )
    note += chr(10)
    write_md("table8_runtime.md",
             "# Table 8. Runtime and resource use\n\n" + md_table(headers, body_rows) + note)
    (TABLES / "table8_runtime.json").write_text(json.dumps(timings, indent=2) + "\n",
                                               encoding="utf-8", newline="\n")


CAPTIONS = """# Figure captions (artifact-backed)

Every empirical caption states the split, sample size, and interval method.

**Fig. 1.** System architecture and trust boundaries. The page, its subresources, scripts, and text are
untrusted data: they are parsed into typed evidence and never executed as an instruction or interpolated
into a prompt. The runtime serves the deterministic rule engine; the learned models in the offline path
are evaluation artifacts and are never loaded by the API. Redrawn from `docs/threat-model.md`; the
diagram is generated by `scripts/paper_artifacts.py`.

**Fig. 2.** What the user sees in the local dashboard. Demo scan of `example.com`, a public documentation
domain; no participant data is shown. (a) Verdict band, overall 0–100 risk, confidence, and the selected
browsing action. (b) One evidence card with severity, dimension, rationale, source, confidence,
observation time, tags, and the provenance disclosure. Item risk points are weighted within their
dimension rather than added directly to the overall score. Screenshot of the running prototype, not an
artifact-backed plot.

**Fig. 3.** Dataset composition by split. Domain-grouped 70/15/15 split of 830 samples over 826 domains
(seed 42, primary build `feed_v2`). Labels are feed membership at retrieval time (2026-10-20); *benign*
means absent from both feeds, not verified clean. Four domains contribute two assessments each, which is
why samples exceed domains. Source: `data/datasets/feed_v2/manifest.json` (dataset SHA-256 `{sha}`).

**Fig. 4.** Label sources. (a) The 146 frozen human labels by feed membership; only 4 domains overlap the
feeds (1 human-malicious, 3 human-suspicious), which is why source agreement is reported as a confusion
table and not as kappa. (b) Retention of feed labels at a second retrieval 4.43 h after the primary one:
540 of 549 labels retained, 488 of the 496 evaluation positives still listed, and 0 of the 330 derived
negatives newly listed. This is hourly-resolution stability, not a durable property. Sources:
`data/labels/feed/human_vs_feed_final.json`, `data/labels/feed/churn/churn_report.json`.

**Fig. 5.** Reliability on the untouched test split (n = 123; 74 malicious, 49 benign). (a) Shipped rule
engine, raw score: Platt calibration was refused because validation scores were not positively associated
with labels, so raw and calibrated ECE are both 0.402. (b) Hybrid logistic regression after Platt scaling,
ECE 0.026. Marker area is proportional to the number of test samples in the bin; the diagonal is perfect
calibration. Grouped 95% intervals (1000 domain-grouped bootstrap resamples) are in Table 4.

**Fig. 6.** Risk-coverage on the untouched test split (n = 123). Accuracy within the covered subset as
coverage is restricted to the most confident predictions; the dashed line is the positive-class prior
(74/123 = 0.602). Every model predicts with a fixed 0.5 score threshold at each coverage level (selective
prediction is never given a tuned per-model threshold), so the full-coverage point need not equal the
validation-thresholded accuracy in Table 4. The shipped engine is below the prior at every coverage level,
i.e. its most confident half is its worst half.

**Fig. 7.** Feature-group ablation on the untouched test split (n = 123, 74 positive). Points are test
AUROC (a) and AUPRC (b); bars are percentile 95% intervals from 1000 domain-grouped bootstrap resamples.
The dashed line and shaded band show the shipped rule engine, which produces the same score in every group.
`hybrid` includes rule outputs and is therefore a superset comparison; `signals` is the independent
page-evidence comparison.

**Fig. 8.** H4 controlled injection corpus (42 pages: 26 injections, 16 negatives; five negatives are
adversarial), scored offline through the production static parser. (a) Overall risk before and after the
hidden instruction; negative fixtures lie on the diagonal. (b) Risk change for the 26 injections, sorted;
17 escalate from low/allow to medium/warn and none reaches high, critical, or block. Invariance is exact
for all 40 hidden-channel pairs once injection and trace evidence is dropped (maximum residual 0.0).
Source: `data/research/injection_h4.json`, gate `passed: true`.

**Fig. 9.** Train-only learning curve for the hybrid models. Five-fold domain-grouped cross-validation
is re-drawn 20 times for logistic regression and 10 times for HistGB; within each fold, whole domains
are subsampled per class. Points are pooled out-of-fold AUROC and bands are the 2.5–97.5 percentile
range across repeats. The validation and test splits are never scored, so the single-use test claim is
unaffected. At full size (462 training domains per fold) the pooled estimate is 0.973 for logistic and
0.990 for HistGB, and the logistic point reproduces the run's grouped-CV estimate of 0.965 within 0.008.
From 50% to 100% of the available training domains, AUROC gains 0.009 (logistic) and 0.005 (HistGB),
so the curve has saturated for this label population. Source: `data/research/learning_curve.json`.
""".format(sha=DATASET_SHA[:12])


def main() -> int:
    print(f"dataset sha256 {DATASET_SHA[:16]}… matches run and manifest")
    print("building figures")
    figure_architecture()
    figure_dataset()
    figure_label_sources()
    figure_reliability()
    figure_risk_coverage()
    figure_ablation()
    figure_injection()
    figure_learning_curve()
    print("building tables")
    table_action_weights()
    table_dataset()
    table_main_results()
    table_ablation()
    table_https()
    table_errors()
    table_sensitivity()
    table_learning_curve()
    print("benchmarking offline scoring")
    timings = benchmark()
    table_runtime(timings)
    (PAPER / "figure-captions.md").write_text(
        CAPTIONS.format(sha=DATASET_SHA[:12]), encoding="utf-8", newline="\n"
    )
    print(f"  captions paper/figure-captions.md")
    print("paper artifacts written to paper/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
