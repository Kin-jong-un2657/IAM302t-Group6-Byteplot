"""Paired evaluation with parent-cluster bootstrap, Wilson and exact McNemar."""

from collections import defaultdict
from math import sqrt

import numpy as np
from scipy.stats import binomtest
from sklearn.metrics import confusion_matrix, f1_score


def macro_f1(y, pred):
    return float(f1_score(y, pred, labels=[0, 1], average="macro", zero_division=0))


def wilson(k, n, z=1.959963984540054):
    if n == 0:
        return None
    p = k / n
    denominator = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denominator
    radius = z * sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denominator
    return [max(0.0, center - radius), min(1.0, center + radius)]


def bootstrap_f1(rows, repeats=500, seed=17):
    """Stratified cluster bootstrap: sample parents, keep all their variants."""
    if repeats < 1:
        return None
    groups = defaultdict(list)
    for i, row in enumerate(rows):
        groups[row["parent_sha256"]].append(i)
    strata = [[p for p, indices in groups.items() if int(rows[indices[0]]["label"]) == label] for label in (0, 1)]
    rng = np.random.default_rng(seed)
    y = np.array([int(r["label"]) for r in rows])
    pred = np.array([int(r["prediction"]) for r in rows])
    estimates = []
    for _ in range(repeats):
        sampled = [p for stratum in strata if stratum for p in rng.choice(stratum, len(stratum), replace=True)]
        indices = [i for parent in sampled for i in groups[parent]]
        estimates.append(macro_f1(y[indices], pred[indices]))
    return [float(v) for v in np.quantile(estimates, [0.025, 0.975])]


def summarize(rows, bootstrap=500, seed=17):
    if not rows:
        return {"n": 0, "macro_f1": None, "macro_f1_ci95": None}
    y = np.array([int(r["label"]) for r in rows])
    pred = np.array([int(r["prediction"]) for r in rows])
    benign = y == 0
    fp = int(np.sum((pred == 1) & benign))
    n_benign = int(benign.sum())
    return {"n": len(rows), "parents": len({r['parent_sha256'] for r in rows}),
            "macro_f1": macro_f1(y, pred), "macro_f1_ci95": bootstrap_f1(rows, bootstrap, seed),
            "confusion_matrix_labels_0_1": confusion_matrix(y, pred, labels=[0, 1]).tolist(),
            "benign_n": n_benign, "false_positives": fp,
            "fpr": fp / n_benign if n_benign else None, "fpr_wilson_ci95": wilson(fp, n_benign)}


def paired_flips(rows, packed="V1"):
    originals = {r["parent_sha256"]: r for r in rows if r["variant"] == "V0"}
    changed = {r["parent_sha256"]: r for r in rows if r["variant"] == packed}
    parents = sorted(originals.keys() & changed.keys())
    originally_correct = flips = 0
    for parent in parents:
        a, b = originals[parent], changed[parent]
        correct = int(a["prediction"]) == int(a["label"])
        originally_correct += int(correct)
        flips += int(correct and int(b["prediction"]) != int(b["label"]))
    return {"paired_n": len(parents), "correct_at_V0": originally_correct, "correct_to_wrong": flips,
            "flip_rate_all_pairs": flips / len(parents) if parents else None,
            "flip_rate_given_correct_V0": flips / originally_correct if originally_correct else None}


def evaluate(rows, bootstrap=500, seed=17):
    variants = sorted({r["variant"] for r in rows})
    return {
        "all": summarize(rows, bootstrap, seed),
        "by_variant": {v: summarize([r for r in rows if r["variant"] == v], bootstrap, seed) for v in variants},
        "paired_flips": {v: paired_flips(rows, v) for v in variants if v != "V0"},
        "ci_method": "95% percentile bootstrap, resample parent clusters within label; fixed trained model",
        "decision_threshold": 0.5,
    }


def mcnemar(a, b, variant="V1"):
    key = lambda r: (r["parent_sha256"], r["variant"])
    left = {key(r): r for r in a if r["variant"] == variant}
    right = {key(r): r for r in b if r["variant"] == variant}
    if not left or left.keys() != right.keys():
        raise ValueError("McNemar requires the same nonempty set of test samples.")
    left_only = right_only = 0
    for k in left:
        if int(left[k]["label"]) != int(right[k]["label"]):
            raise ValueError("Conflicting labels in paired predictions.")
        ac = int(left[k]["prediction"]) == int(left[k]["label"])
        bc = int(right[k]["prediction"]) == int(right[k]["label"])
        left_only += int(ac and not bc)
        right_only += int(bc and not ac)
    discordant = left_only + right_only
    return {"n": len(left), "a_correct_b_wrong": left_only, "a_wrong_b_correct": right_only,
            "pvalue_exact": float(binomtest(left_only, discordant, 0.5).pvalue) if discordant else 1.0,
            "note": "Two-sided exact test of paired correctness, not a direct test of F1."}
