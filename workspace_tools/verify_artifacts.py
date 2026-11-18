"""Read-only metadata/result checks for the local interview packet."""
import argparse
import csv
import hashlib
import json
import math
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

def rows(path):
    with Path(path).open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))

def show(value):
    print(json.dumps(value, ensure_ascii=False, indent=2))

def audit():
    path = ROOT / "audit_182/Static182_audit_redacted.csv"
    receipt = json.loads((ROOT / "audit_182/STATIC182_REDACTED_EXPORT_RECEIPT.json").read_text(encoding="utf-8"))
    records = rows(path)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    assert digest == receipt["export_csv_sha256"]
    actual = dict(Counter(r["die_status"] for r in records))
    assert len(records) == 182 and actual == {"clean": 102, "packed": 58, "unknown": 22}
    assert not any(k.lower() in {"path", "sha256", "parent_sha256", "family"} for k in records[0])
    show({"check": "static182_metadata", "passed": True, "records": len(records),
          "die_status": actual, "truncated_at_64k": receipt["counts"]["truncated"],
          "sha256": digest, "raw_binaries_read": False,
          "note": "182 audit records; not evidence of 182 unique parents. DiE clean is not unpacked proof."})

def metrics(base):
    from byteplot.metrics import summarize
    base = Path(base)
    if not base.is_absolute():
        base = ROOT / base
    checks = variants = 0
    classifiers = set()
    for path in sorted(base.glob("E*/**/predictions.csv")):
        saved_path = path.parent / "metrics.json"
        if not saved_path.exists():
            continue
        saved = json.loads(saved_path.read_text(encoding="utf-8"))
        if "by_variant" not in saved:
            continue
        records = rows(path)
        assert all(r.get("synthetic") == "1" for r in records), "Synthetic demo verifier rejects real predictions."
        classifiers.add(str(path.parent.relative_to(base)))
        for name, expected in [("all", saved["all"])] + list(saved["by_variant"].items()):
            selected = records if name == "all" else [r for r in records if r["variant"] == name]
            actual = summarize(selected, bootstrap=0)
            for field in ["n", "parents", "confusion_matrix_labels_0_1", "benign_n", "false_positives"]:
                assert actual[field] == expected[field], (path, name, field)
            for field in ["macro_f1", "fpr"]:
                assert actual[field] is None and expected[field] is None or (
                    actual[field] is not None and expected[field] is not None and
                    math.isclose(actual[field], expected[field], rel_tol=1e-10, abs_tol=1e-10)), (path, name, field)
            checks += 1
            variants += name != "all"
    assert checks and classifiers
    skipped = json.loads((base / "skipped.json").read_text(encoding="utf-8"))
    show({"check": "saved_synthetic_metrics", "passed": True, "classifier_runs": len(classifiers),
          "variant_checks": variants, "all_and_variant_checks": checks,
          "skipped_experiments": skipped, "models_executed": False,
          "note": "Recomputed point metrics only; no new bootstrap CI or real-malware benchmark."})

def e5():
    records = rows(ROOT / "results_e5_summary/E5_RESULTS.csv")
    summary = rows(ROOT / "results_e5_summary/E5_CHANNEL_SUMMARY.csv")
    assert len(records) == 12 and {r["channel"] for r in records} == {"C1", "C2", "C3", "C4"}
    assert {int(r["seed"]) for r in records} == {17, 37, 73}
    by_channel = defaultdict(list)
    for r in records:
        cm = json.loads(r["confusion_matrix"])
        tn, fp = cm[0]
        fn, tp = cm[1]
        assert tn + fp + fn + tp == int(r["independent_test_parents"]) == 10
        assert tn + fp == int(r["benign_n"]) == 2
        f0 = 2 * tn / (2 * tn + fp + fn) if 2 * tn + fp + fn else 0
        f1 = 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else 0
        assert math.isclose((f0 + f1) / 2, float(r["macro_f1"]), abs_tol=1e-10)
        assert math.isclose(fp / 2, float(r["fpr"]), abs_tol=1e-10)
        by_channel[r["channel"]].append(r)
    for s in summary:
        rs = by_channel[s["channel"]]
        for metric in ["macro_f1", "fpr"]:
            values = [float(r[metric]) for r in rs]
            assert math.isclose(statistics.mean(values), float(s[metric + "_mean"]), abs_tol=1e-10)
            assert math.isclose(statistics.stdev(values), float(s[metric + "_sd"]), abs_tol=1e-10)
    show({"check": "real_e5_aggregate_consistency", "passed": True, "jobs": 12,
          "channel_summaries": 4, "test_parents": 10, "test_benign": 2,
          "models_replayed": False, "parent_predictions_available": False,
          "note": "Same ten parents across seeds; aggregate consistency is not independent inference or CI replay."})

def compare(expected, actual):
    def keyed(path):
        return {(r["parent_sha256"], r["variant"]): r for r in rows(path)}
    a, b = keyed(expected), keyed(actual)
    assert a.keys() == b.keys()
    maximum = 0.0
    for key in a:
        assert a[key]["label"] == b[key]["label"] and a[key]["prediction"] == b[key]["prediction"]
        error = abs(float(a[key]["probability_malware"]) - float(b[key]["probability_malware"]))
        maximum = max(maximum, error)
        assert error <= 1e-6, (key, error)
    show({"check": "synthetic_cpu_checkpoint_replay", "passed": True, "predictions": len(a),
          "parents": len({k[0] for k in a}), "max_probability_difference": maximum})

parser = argparse.ArgumentParser(description=__doc__)
sub = parser.add_subparsers(dest="command", required=True)
sub.add_parser("audit")
p = sub.add_parser("metrics")
p.add_argument("--root", default="demo-output/runs")
sub.add_parser("e5")
p = sub.add_parser("compare")
p.add_argument("--expected", required=True)
p.add_argument("--actual", required=True)
args = parser.parse_args()
if args.command == "audit": audit()
elif args.command == "metrics": metrics(args.root)
elif args.command == "e5": e5()
else: compare(args.expected, args.actual)
