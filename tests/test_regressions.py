"""Regressions for report provenance, E4 holdouts and Markdown columns.

The deliberately distinct scores below are test fixtures, not experiment results.
"""

from copy import deepcopy

import numpy as np
import pytest

from byteplot.engine import TrainConfig
from byteplot.experiments import run_suite
from byteplot.io import read_csv
from byteplot.report import suite_report
from byteplot.representation import prepare
from byteplot.synthetic import make_synthetic


def score_record(experiment, channel, variant, score, seed=17):
    return dict(experiment=experiment, channel=channel, condition="standard", seed=seed,
                fraction=1.0, variant=variant, macro_f1=score, f1_ci95=None, fpr=None,
                run=f"{experiment}/{channel}_seed{seed}")


def markdown_tables(text):
    tables, current = [], []
    for line in text.splitlines() + [""]:
        if line.startswith("|"):
            current.append([cell.strip() for cell in line.strip().strip("|").split("|")])
        elif current:
            tables.append(current)
            current = []
    return tables


@pytest.mark.parametrize("experiments", [("E1", "E2", "E5"), ("E5",), ("E2",)])
def test_central_table_routes_e5_scores_without_e2_fallback(tmp_path, experiments):
    records = [score_record("E1", "C1", "V0", .31), score_record("E1", "C1", "V1u", .41)]
    for index, channel in enumerate(("C1", "C2", "C3", "C4")):
        records.extend(score_record("E2", channel, variant, .8 + index / 100)
                       for variant in ("V0", "V1", "V2"))
        # Include E5 diagnostics on V0/V1; its central table must use only V2.
        records.extend(score_record("E5", channel, variant, .2 + index / 100)
                       for variant in ("V0", "V1", "V2"))
    records = [r for r in records if r["experiment"] in experiments]
    original = deepcopy(records)
    suite_report(tmp_path, records, [], synthetic=True, skipped=[])
    central = read_csv(tmp_path / "central_table.csv")
    assert central and all("experiment" in r for r in central)
    e5 = [r for r in central if r["experiment"] == "E5"]
    assert len(e5) == (4 if "E5" in experiments else 0)
    for row in e5:
        expected = next(r["macro_f1"] for r in original if r["experiment"] == "E5" and
                        r["channel"] == row["channel"] and r["variant"] == "V2")
        assert float(row["V2"]) == expected
        assert row["train_variants"] == "V1" and row["V0"] == row["V1"] == ""
    for row in [r for r in central if r["experiment"] == "E2"]:
        assert row["train_variants"] == "V0,V1"
        expected = next(r["macro_f1"] for r in original if r["experiment"] == "E2" and
                        r["channel"] == row["channel"] and r["variant"] == "V2")
        assert float(row["V2"]) == expected  # E2's V2 is explicitly a diagnostic.
    if "E1" in experiments:
        baseline = next(r for r in central if r["channel"] == "B1")
        assert baseline["experiment"] == "E1" and baseline["train_variants"] == "V0"
        assert float(baseline["V1"]) == .41 and baseline["V2"] == ""
    report = (tmp_path / "REPORT.md").read_text(encoding="utf-8")
    if "E5" in experiments:
        section = report.split("## E5", 1)[1].split("\n## ", 1)[0]
        assert "train only V1" in section and "test V2" in section
        for row in e5:
            assert f"{float(row['V2']):.4f}" in section
    else:
        assert "No E5 results" in report
    assert records == original  # Reporting must never modify metrics in place.
    exported = read_csv(tmp_path / "results.csv")
    assert [float(r["macro_f1"]) for r in exported] == [r["macro_f1"] for r in original]


def test_seed_summary_has_eight_columns_and_unchanged_statistics(tmp_path):
    scores = [.2, .6]
    records = [score_record("E2", "C1", "V1", score, seed) for seed, score in zip((17, 37), scores)]
    suite_report(tmp_path, records, [], synthetic=True, skipped=[])
    text = (tmp_path / "REPORT.md").read_text(encoding="utf-8")
    # Validate every generated table, not only the originally broken one.
    for table in markdown_tables(text):
        assert all(len(row) == len(table[0]) for row in table)
    lines = text.splitlines()
    assert all(lines[i - 1] == "" for i, line in enumerate(lines) if line.startswith("## "))
    summary = markdown_tables(text.split("## Mean and seed variation", 1)[1])[0]
    assert summary[0] == ["Experiment", "Channel", "Condition", "Fraction", "Variant", "Seeds", "Mean F1", "Sample SD"]
    assert summary[2] == ["E2", "C1", "standard", "1.0", "V1", "2", "0.4000", f"{np.std(scores, ddof=1):.4f}"]
    suite_report(tmp_path, records[:1], [], synthetic=True, skipped=[])
    single = (tmp_path / "REPORT.md").read_text(encoding="utf-8")
    assert "N/A (one seed)" in single


def test_e4_changes_only_training_keeps_validation_and_test_fixed(tmp_path):
    # >= 2 validation parents/class is essential: one would hide the old bug
    # because max(1, ceil(n * .1)) would retain that single parent in both arms.
    raw = make_synthetic(tmp_path / "raw", parents_per_class=10)
    manifest = prepare(raw, tmp_path / "prepared", height=32, width=32)
    out = tmp_path / "runs"
    run_suite(manifest, out, TrainConfig(epochs=1, bootstrap=2, threads=1),
              seeds=[17, 37], fractions=[1.0], experiments=["E4"])

    def identities(rows):
        return {(r["parent_sha256"], r["variant"], r["label"], r["split"]) for r in rows}

    for seed in (17, 37):
        channel_inputs = {}
        for channel in ("C1", "C2"):
            balanced = out / "E4" / f"{channel}_balanced_f1_seed{seed}"
            rare = out / "E4" / f"{channel}_rare_benign_packed_f1_seed{seed}"
            train_a, train_b = [read_csv(p / "selected_train.csv") for p in (balanced, rare)]
            val_a, val_b = [read_csv(p / "selected_val.csv") for p in (balanced, rare)]
            pred_a, pred_b = [read_csv(p / "predictions.csv") for p in (balanced, rare)]
            assert len(val_a) >= 8
            assert val_a == val_b
            assert (balanced / "selected_val.csv").read_bytes() == (rare / "selected_val.csv").read_bytes()
            assert identities(pred_a) == identities(pred_b)
            assert identities(train_b) < identities(train_a)
            removed = identities(train_a) - identities(train_b)
            assert removed and all(variant == "V1" and label == "0" and split == "train"
                                   for _, variant, label, split in removed)
            # All parent variants remain confined to their original split.
            parent_sets = [{r["parent_sha256"] for r in subset} for subset in (train_b, val_b, pred_b)]
            assert not (parent_sets[0] & parent_sets[1] or parent_sets[0] & parent_sets[2] or parent_sets[1] & parent_sets[2])
            channel_inputs[channel] = (train_a, train_b, val_a)
        assert channel_inputs["C1"] == channel_inputs["C2"]
