"""Manifest contracts and deterministic parent-level dataset selection."""

import csv
import hashlib
import json
from collections import defaultdict
from pathlib import Path

import numpy as np

VARIANTS = ("V0", "V1", "V1u", "V2")
SPLITS = ("train", "val", "test")


def read_csv(path):
    with Path(path).open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(path, rows, fields=None):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = fields or sorted({k for row in rows for k in row if not k.startswith("_")})
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def write_json(path, value):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False), encoding="utf-8")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def validate_rows(rows, require_split=False):
    if not rows:
        raise ValueError("Manifest is empty.")
    parents, hashes, keys = {}, {}, set()
    for row in rows:
        parent = row.get("parent_sha256", "")
        if len(parent) != 64 or any(c not in "0123456789abcdef" for c in parent):
            raise ValueError("parent_sha256 must be a lowercase SHA-256 hash.")
        if str(row.get("label")) not in ("0", "1") or row.get("variant") not in VARIANTS:
            raise ValueError("Expected label 0/1 and variant V0/V1/V1u/V2.")
        key = (parent, row["variant"])
        if key in keys:
            raise ValueError(f"Duplicate parent/variant: {key}")
        keys.add(key)
        split = row.get("split", "")
        if require_split and split not in SPLITS:
            raise ValueError("Prepared manifest requires train/val/test split.")
        identity = (str(row["label"]), split)
        if parent in parents and parents[parent] != identity:
            raise ValueError(f"Label conflict or split leakage for parent {parent}")
        parents[parent] = identity
        file_hash = row.get("sha256")
        if file_hash:
            if file_hash in hashes and hashes[file_hash] != parent:
                raise ValueError(f"Identical bytes assigned to different parents: {file_hash}")
            hashes[file_hash] = parent


def assign_splits(rows, seed=17, val_fraction=0.15, test_fraction=0.15):
    """Stratify original parents by class; never split variants independently."""
    if not 0 < val_fraction < 1 or not 0 < test_fraction < 1 or val_fraction + test_fraction >= 1:
        raise ValueError("Validation/test fractions must be positive and sum to less than 1.")
    supplied = [bool(r.get("split")) for r in rows]
    if any(supplied):
        if not all(supplied):
            raise ValueError("Supply splits for all rows, or leave all splits empty.")
        validate_rows(rows, require_split=True)
        return rows
    validate_rows(rows)
    by_label = defaultdict(set)
    for row in rows:
        by_label[int(row["label"])].add(row["parent_sha256"])
    assignments = {}
    rng = np.random.default_rng(seed)
    for label in (0, 1):
        parents = sorted(by_label[label])
        if len(parents) < 3:
            raise ValueError("Need at least 3 original parents per class to create train/val/test.")
        rng.shuffle(parents)
        n_val = max(1, round(len(parents) * val_fraction))
        n_test = max(1, round(len(parents) * test_fraction))
        if n_val + n_test >= len(parents):
            raise ValueError("Not enough parents for the requested split fractions.")
        for index, parent in enumerate(parents):
            assignments[parent] = "val" if index < n_val else "test" if index < n_val + n_test else "train"
    result = [dict(row, split=assignments[row["parent_sha256"]]) for row in rows]
    validate_rows(result, require_split=True)
    return result


def load_prepared(path):
    path = Path(path).resolve()
    rows = read_csv(path)
    validate_rows(rows, require_split=True)
    if len({r.get("synthetic", "0") for r in rows}) != 1:
        raise ValueError("Do not mix synthetic and real data in one experiment.")
    for row in rows:
        row["_feature_path"] = str((path.parent / row["feature_path"]).resolve())
        if not Path(row["_feature_path"]).is_file():
            raise ValueError(f"Missing feature file: {row['_feature_path']}")
    return rows


def select_rows(rows, split, variants, fraction=1.0, seed=17, benign_packed_keep=1.0, balanced_pairs=False):
    """Nested parent subsets across learning-curve fractions, stratified by class."""
    if not 0 < fraction <= 1 or not 0 < benign_packed_keep <= 1:
        raise ValueError("Fractions must be in (0, 1].")
    candidates = [r for r in rows if r["split"] == split and r["variant"] in variants]
    if balanced_pairs:
        coverage = defaultdict(set)
        for row in candidates:
            coverage[row["parent_sha256"]].add(row["variant"])
        candidates = [r for r in candidates if coverage[r["parent_sha256"]] == set(variants)]
        per_label = {label: {r["parent_sha256"] for r in candidates if int(r["label"]) == label} for label in (0, 1)}
        count = min(len(parents) for parents in per_label.values())
        retained = {p for parents in per_label.values() for p in
                    sorted(parents, key=lambda p: sha256(f"{seed}:{p}".encode()))[:count]}
        candidates = [r for r in candidates if r["parent_sha256"] in retained]
    chosen, retained_benign = set(), set()
    for label in (0, 1):
        parents = {r["parent_sha256"] for r in candidates if int(r["label"]) == label}
        ordered = sorted(parents, key=lambda p: sha256(f"{seed}:{p}".encode()))
        count = max(1, int(np.ceil(len(ordered) * fraction)))
        selected = ordered[:count]
        chosen.update(selected)
        if label == 0:
            retained_benign.update(selected[:max(1, int(np.ceil(len(selected) * benign_packed_keep)))])
    return [r for r in candidates if r["parent_sha256"] in chosen and not (
        int(r["label"]) == 0 and r["variant"] in ("V1", "V2") and r["parent_sha256"] not in retained_benign
    )]
