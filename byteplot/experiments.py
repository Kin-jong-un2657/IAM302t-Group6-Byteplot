"""Explicit E0-E5 recipes. No variant from test enters fitting/selection."""

from collections import Counter, defaultdict
from dataclasses import replace
from pathlib import Path

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from .engine import fit_classifier, fit_probe
from .io import load_prepared, read_csv, write_csv, write_json
from .metrics import evaluate, mcnemar
from .report import suite_report, visualize


def audit(manifest, out, source_manifest=None, bootstrap=500):
    rows = load_prepared(manifest)
    out = Path(out)
    quality = {"synthetic": all(r["synthetic"] == "1" for r in rows), "samples": len(rows),
               "original_parents": len({r["parent_sha256"] for r in rows}),
               "split_variant_label_counts": dict(Counter(f"{r['split']}/{r['variant']}/{r['label']}" for r in rows)),
               "die_status_counts": dict(Counter(r.get("die_status", "missing") for r in rows)),
               "truncation_rate": float(np.mean([int(r["truncated"]) for r in rows])),
               "mean_padding_fraction": float(np.mean([float(r["padding_fraction"]) for r in rows])),
               "pair_coverage": {v: len({r["parent_sha256"] for r in rows if r["variant"] == "V0"} &
                                        {r["parent_sha256"] for r in rows if r["variant"] == v}) for v in ("V1", "V1u", "V2")}}
    if source_manifest:
        source = read_csv(source_manifest)
        counts = defaultdict(Counter)
        for r in source:
            counts[f"{r.get('packer')}/{r['label']}/{r['variant']}"][r.get("status", "ok")] += 1
        quality["source_status_by_packer_label_variant"] = {k: dict(v) for k, v in counts.items()}
        quality["variant_failure_rates"] = {
            k: {"attempts": sum(v.values()), "not_ok": sum(v.values()) - v.get("ok", 0),
                "not_ok_rate": (sum(v.values()) - v.get("ok", 0)) / sum(v.values())}
            for k, v in counts.items() if not k.endswith("/V0")}
    else:
        quality["failure_audit"] = "Not provided. Pass --source-manifest to audit failed/excluded attempts."
    write_json(out / "data_quality.json", quality)
    train = [r for r in rows if r["split"] == "train" and r["variant"] == "V0"]
    test = [r for r in rows if r["split"] == "test" and r["variant"] == "V0"]
    if {int(r["label"]) for r in train} != {0, 1} or not test:
        write_json(out / "artifact_metrics.json", {"status": "skipped", "reason": "Need V0 train with both labels and V0 test."})
        return quality
    features = lambda rs: np.array([[np.log1p(float(r["size_bytes"])), float(r["sections"]), float(r["signed"])] for r in rs])
    model = make_pipeline(StandardScaler(), LogisticRegression(random_state=17, max_iter=1000))
    model.fit(features(train), [int(r["label"]) for r in train])
    probabilities = model.predict_proba(features(test))[:, 1]
    predictions = [dict(r, prediction=int(p >= 0.5), probability_malware=float(p)) for r, p in zip(test, probabilities)]
    write_csv(out / "artifact_predictions.csv", predictions)
    write_json(out / "artifact_metrics.json", evaluate(predictions, bootstrap))
    return quality


def run_suite(manifest, out, base_config, seeds=(17, 37, 73), fractions=(0.1, 0.25, 0.5, 1.0),
              experiments=("E0", "E1", "E2", "E3", "E4", "E5"), source_manifest=None):
    out = Path(out)
    if (out / "suite.json").exists():
        raise ValueError("Suite exists. Choose a new --out directory.")
    rows = load_prepared(manifest)
    synthetic = all(r["synthetic"] == "1" for r in rows)
    if not seeds or not fractions or len(set(seeds)) != len(seeds) or len(set(fractions)) != len(fractions):
        raise ValueError("Seeds/fractions must be nonempty and unique.")
    if any(not 0 < f <= 1 for f in fractions):
        raise ValueError("Learning-curve fractions must be in (0,1].")
    available = {r["variant"] for r in rows}
    records, comparisons, skipped = [], [], []
    write_json(out / "suite.json", {"synthetic": synthetic, "seeds": list(seeds), "fractions": list(fractions),
               "experiments": list(experiments), "E1_train": ["V0"], "E2_E3_train": ["V0", "V1"],
               "E4_train": ["V0", "V1"], "E4_rare_benign_packed_keep": 0.1,
               "E4_validation_benign_packed_keep": 1.0, "E4_test": "fixed full test split", "E5_train": ["V1"]})
    visualize(rows, out / "examples")

    def run(experiment, channel, seed, variants, fraction=1.0, keep=1.0, condition="standard"):
        name = f"{channel}_{condition}_f{fraction:g}_seed{seed}"
        run_out = out / experiment / name
        config = replace(base_config, channel=channel, seed=seed, variants=tuple(variants),
                         fraction=fraction, benign_packed_keep=keep, balanced_pairs=experiment == "E4")
        result = fit_classifier(manifest, run_out, config)
        for variant, metric in result["by_variant"].items():
            records.append({"experiment": experiment, "channel": channel, "condition": condition,
                            "seed": seed, "fraction": fraction, "variant": variant,
                            "macro_f1": metric["macro_f1"], "f1_ci95": metric["macro_f1_ci95"],
                            "fpr": metric.get("fpr"), "run": str(run_out.relative_to(out))})
        return read_csv(run_out / "predictions.csv"), result

    def compare(experiment, seed, outputs, variant="V1", fraction=1.0):
        for a, b in (("C1", "C2"), ("C2", "C3")):
            if a in outputs and b in outputs and variant in outputs[a][1]["by_variant"]:
                comparisons.append({"experiment": experiment, "seed": seed, "fraction": fraction,
                                    "variant": variant, "a": a, "b": b,
                                    "f1_b_minus_a": outputs[b][1]["by_variant"][variant]["macro_f1"] -
                                                      outputs[a][1]["by_variant"][variant]["macro_f1"],
                                    "mcnemar": mcnemar(outputs[a][0], outputs[b][0], variant)})

    if "E0" in experiments:
        audit(manifest, out / "E0", source_manifest, base_config.bootstrap)
    for experiment in experiments:
        if experiment == "E0":
            continue
        needs = {"E1": {"V0", "V1"}, "E2": {"V0", "V1"}, "E3": {"V0", "V1"},
                 "E4": {"V0", "V1"}, "E5": {"V1", "V2"}}[experiment]
        if not needs.issubset(available):
            skipped.append(f"{experiment}: missing variants {sorted(needs - available)}")
            continue
        train_variants = ("V0",) if experiment == "E1" else ("V1",) if experiment == "E5" else ("V0", "V1")
        test_variants = ("V0", "V1") if experiment == "E1" else ("V2",) if experiment == "E5" else ("V1",)
        missing_groups = [f"{split}/{variant}" for split, variants in
                          (("train", train_variants), ("val", train_variants), ("test", test_variants))
                          for variant in variants if {int(r["label"]) for r in rows if
                          r["split"] == split and r["variant"] == variant} != {0, 1}]
        if missing_groups:
            skipped.append(f"{experiment}: both labels required in {missing_groups}")
            continue
        for seed in seeds:
            if experiment == "E1":
                predictions, _ = run(experiment, "C1", seed, ("V0",))
                # Match V0/V1/V1u parents to avoid success-selection bias in B1 comparisons.
                by_variant = {v: {r["parent_sha256"] for r in predictions if r["variant"] == v} for v in ("V0", "V1", "V1u")}
                common = set.intersection(*by_variant.values())
                matched = [r for r in predictions if r["parent_sha256"] in common and r["variant"] in by_variant]
                write_json(out / "E1" / f"matched_baseline_seed{seed}.json", evaluate(matched, base_config.bootstrap, seed))
                if not common:
                    skipped.append(f"B1 seed {seed}: no complete V0/V1/V1u test pairs.")
            elif experiment in ("E2", "E5"):
                variants = ("V0", "V1") if experiment == "E2" else ("V1",)
                outputs = {c: run(experiment, c, seed, variants) for c in ("C1", "C2", "C3", "C4")}
                compare(experiment, seed, outputs, "V1" if experiment == "E2" else "V2")
            elif experiment == "E3":
                gaps = {}
                for fraction in sorted(fractions):
                    outputs = {c: run(experiment, c, seed, ("V0", "V1"), fraction) for c in ("C1", "C2")}
                    compare(experiment, seed, outputs, fraction=fraction)
                    gaps[fraction] = outputs["C2"][1]["by_variant"]["V1"]["macro_f1"] - outputs["C1"][1]["by_variant"]["V1"]["macro_f1"]
                low, high = min(gaps), max(gaps)
                comparisons.append({"experiment": "E3_gap_shrinkage", "seed": seed, "low_fraction": low,
                                    "high_fraction": high, "gap_low": gaps[low], "gap_high": gaps[high],
                                    "gap_low_minus_high": gaps[low] - gaps[high]})
                fit_probe(manifest, out / "E3" / f"probe_seed_{seed}",
                          replace(base_config, seed=seed, variants=("V0", "V1")))
            elif experiment == "E4":
                for condition, keep in (("balanced", 1.0), ("rare_benign_packed", 0.1)):
                    outputs = {c: run(experiment, c, seed, ("V0", "V1"), keep=keep, condition=condition) for c in ("C1", "C2")}
                    compare(experiment + "_" + condition, seed, outputs)
    suite_report(out, records, comparisons, synthetic, skipped)
    print(f"Report -> {out / 'REPORT.md'}", flush=True)
    return out / "REPORT.md"
