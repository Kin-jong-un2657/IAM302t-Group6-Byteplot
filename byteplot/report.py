"""Standalone figures and a Markdown summary of actual experiment outputs."""

from collections import defaultdict
import os
from pathlib import Path

os.environ.setdefault("MPLCONFIGDIR", str(Path(".cache/matplotlib").resolve()))
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from .io import write_csv, write_json


def visualize(rows, out, limit=4):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    for row in rows[:limit]:
        with np.load(row["_feature_path"], allow_pickle=False) as feature:
            x, mask = feature["x"], feature["mask"]
        fig, axes = plt.subplots(1, 4, figsize=(12, 3))
        for ax, data, title in zip(axes, [*x, mask[0]], ["Grayscale", "Entropy / 8", "PE regions", "Valid bytes"]):
            ax.imshow(data, cmap="gray", vmin=0, vmax=1, interpolation="nearest")
            ax.set_title(title); ax.axis("off")
        flag = "SYNTHETIC mock regions | " if row.get("synthetic") == "1" else ""
        fig.suptitle(f"{flag}{row['parent_sha256'][:12]} {row['variant']} label={row['label']}")
        fig.tight_layout()
        fig.savefig(out / f"{row['parent_sha256'][:16]}_{row['variant']}.png", dpi=150)
        plt.close(fig)


def suite_report(out, records, comparisons, synthetic, skipped):
    out = Path(out)
    write_csv(out / "results.csv", records)
    write_json(out / "comparisons.json", comparisons)
    write_json(out / "skipped.json", skipped)
    central = []
    for seed in sorted({r["seed"] for r in records}):
        for experiment in ("E2", "E5", "E1"):
            channels = ("B1",) if experiment == "E1" else ("C1", "C2", "C3", "C4")
            for channel in channels:
                source_channel = "C1" if channel == "B1" else channel
                source = {r["variant"]: r for r in records if r["experiment"] == experiment and
                          r["channel"] == source_channel and r["seed"] == seed}
                if not source:
                    continue
                item = {"experiment": experiment, "seed": seed, "channel": channel,
                        "train_variants": {"E1": "V0", "E2": "V0,V1", "E5": "V1"}[experiment]}
                for variant in ("V0", "V1", "V2"):
                    origin = "V1u" if channel == "B1" and variant == "V1" else variant
                    applicable = variant == "V2" if experiment == "E5" else not (channel == "B1" and variant == "V2")
                    item[variant] = source[origin]["macro_f1"] if applicable and origin in source else None
                central.append(item)
    write_csv(out / "central_table.csv", central, ["experiment", "seed", "channel", "train_variants", "V0", "V1", "V2"])
    lines = ["# Byteplot experiment results", "",
             "**SYNTHETIC DEMO ONLY — not research evidence. V1/V2 and PE regions are mocked.**" if synthetic
             else "Real-data experiment. Inspect data quality, failure rates and sampling before drawing conclusions.", "",
             "All F1 values are fractions in [0,1]. Threshold is fixed at 0.5. Best checkpoints use validation only.", ""]
    sections = [
        ("E2", "E2 — Channel comparison (train V0+V1)",
         "C1-C4 train/validate on V0+V1. V2 scores here are E2 diagnostics, not E5 unseen-packer results."),
        ("E5", "E5 — Unseen packer (train only V1, test V2)",
         "C1-C4 train/validate only on V1 (UPX) and test V2 (another packer). Scores come only from E5 runs; no E2 fallback."),
        ("E1", "B1 — Static-unpack baseline (E1)",
         "B1 uses E1 C1 trained on V0 and evaluates V1u in the V1 column. V2 is N/A. "
         "This training/evaluation regime differs from E2/E5. Scores use all available samples; inspect matched B1 parent comparisons separately."),
    ]
    for experiment, title, explanation in sections:
        lines.extend([f"## {title}", "", explanation, ""])
        selected = [r for r in central if r["experiment"] == experiment]
        if not selected:
            lines.extend([f"No {experiment} results available; no scores substituted from other experiments.", ""])
            continue
        if experiment == "E5":
            lines.extend(["| Seed | Channel | Train variants | Test variant | Macro-F1 |",
                          "| --- | --- | --- | --- | --- |"])
            for r in selected:
                score = f"{r['V2']:.4f}" if r["V2"] is not None else "N/A"
                lines.append(f"| {r['seed']} | {r['channel']} | {r['train_variants']} | V2 | {score} |")
        else:
            v2_header = "F1 V2 (diagnostic)" if experiment == "E2" else "F1 V2"
            lines.extend([f"| Seed | Channel | Train variants | F1 V0 | F1 V1 | {v2_header} |",
                          "| --- | --- | --- | --- | --- | --- |"])
            for r in selected:
                values = [f"{r[v]:.4f}" if r[v] is not None else "N/A" for v in ("V0", "V1", "V2")]
                lines.append(f"| {r['seed']} | {r['channel']} | {r['train_variants']} | " + " | ".join(values) + " |")
        lines.append("")
    lines.extend(["", "## Classification results", "",
             "| Experiment | Channel / condition | Seed | Train fraction | Test variant | Macro-F1 | 95% F1 CI | FPR |",
             "| --- | --- | --- | --- | --- | --- | --- | --- |"])
    for r in records:
        ci = r.get("f1_ci95")
        ci_text = f"[{ci[0]:.3f}, {ci[1]:.3f}]" if ci else "not computed"
        fpr = f"{r['fpr']:.3f}" if r.get("fpr") is not None else "N/A"
        lines.append(f"| {r['experiment']} | {r['channel']} / {r['condition']} | {r['seed']} | {r['fraction']} | "
                     f"{r['variant']} | {r['macro_f1']:.4f} | {ci_text} | {fpr} |")
    lines.extend(["", "## Mean and seed variation", "",
                  "| Experiment | Channel | Condition | Fraction | Variant | Seeds | Mean F1 | Sample SD |",
                  "| --- | --- | --- | --- | --- | --- | --- | --- |"])
    groups = defaultdict(list)
    for row in records:
        groups[(row["experiment"], row["channel"], row["condition"], row["fraction"], row["variant"])].append(row["macro_f1"])
    for key, values in sorted(groups.items()):
        sd = f"{np.std(values, ddof=1):.4f}" if len(values) > 1 else "N/A (one seed)"
        lines.append("| " + " | ".join(map(str, key)) + f" | {len(values)} | {np.mean(values):.4f} | {sd} |")
    lines.extend(["", "## Reading the outputs", "",
                  "- `E0/data_quality.json` and `E0/artifact_metrics.json`: data audit and source-artifact baseline.",
                  "- Each classifier run: `run.json`, `selected_train.csv`, `selected_val.csv`, `history.csv`, `checkpoint.pt`, `predictions.csv`, `metrics.json`.",
                  "- E1 B1 is the E1 C1 model evaluated on V1u; its training regime differs from E2. Compare using matched parent pairs in `E1/matched_baseline_seed*.json`.",
                  "- `central_table.csv` identifies E2/E5/E1 in its experiment column. E5 rows contain only V2 scores from E5 runs.",
                  "- F1 CI: 95% percentile bootstrap of test parent clusters within class, conditional on the fitted model. Seed SD is reported separately.",
                  "- `comparisons.json`: per-seed C1/C2 and C2/C3 exact McNemar tests and F1 differences, plus E3 gap shrinkage.",
                  "- `E3/probe_seed_*/metrics.json`: MSE and Pearson correlation over valid bytes only, by variant.",
                  "- E4 FPR and Wilson intervals are in each run's `metrics.json` under `by_variant.V1`.",
                  "- E4 changes packed-benign availability only in training; validation and test samples are fixed between conditions for each seed.",
                  "- A missing variant is skipped and recorded; no score is invented.",
                  "- A heuristic PE-stub map is not byte-accurate stub ground truth; final pooling masks reduce but do not eliminate padding artifacts.",
                  "- No automatic conclusion about entropy redundancy is made from these scores.", ""])
    if skipped:
        lines.extend(["## Skipped work", "", *[f"- {s}" for s in skipped], ""])
    (out / "REPORT.md").write_text("\n".join(lines), encoding="utf-8")
    curve = [r for r in records if r["experiment"] == "E3" and r["variant"] == "V1"]
    if curve:
        fig, ax = plt.subplots(figsize=(7, 4))
        for channel in ("C1", "C2"):
            fractions = sorted({r["fraction"] for r in curve if r["channel"] == channel})
            data = [[r["macro_f1"] for r in curve if r["channel"] == channel and r["fraction"] == f] for f in fractions]
            means = [np.mean(v) for v in data]
            errors = [np.std(v, ddof=1) if len(v) > 1 else 0 for v in data]
            ax.errorbar(fractions, means, yerr=errors, marker="o", capsize=4, label=channel)
        ax.set(xlabel="Fraction of training parents", ylabel="Macro-F1 on V1", ylim=(0, 1),
               title="SYNTHETIC DEMO: learning curve" if synthetic else "Learning curve (mean +/- seed SD)")
        ax.legend(); ax.grid(alpha=0.25); fig.tight_layout()
        fig.savefig(out / "learning_curve.png", dpi=160); plt.close(fig)
