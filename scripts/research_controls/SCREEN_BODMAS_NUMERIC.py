"""Bounded-memory metadata prescreen. Never opens, restores or trains on PE bytes.

EMBER v2 layout is taken from the official elastic/ember features.py. Numeric
columns are only a retrieval aid, not verified compiler provenance or a cohort.
"""
from collections import Counter, defaultdict, deque
from pathlib import Path
import csv
import hashlib
import io
import json
import re
import tempfile
import zipfile
import numpy as np

HERE = Path(__file__).resolve().parent
PRIVATE = HERE / "BODMAS_NUMERIC_PRIVATE"
NPZ_SHA = "641a1dd3137fc53ea8d2046c4b59fe7f7952eb90420bbcc70282c79039ac17d7"
META_SHA = "5f1dc793cac4a540ef9e0c40fd7897142095621790d3c6f2d6637971806f4c50"
ANCHOR_SHA = "fb34221d64c808bdcf0935f042a821a9ffb0ee0f0a2132b38eccc8b8b375ba6b"
# 256 histogram + 256 entropy + 104 strings; 10 general; 62 header.
GENERAL = 256 + 256 + 104
HEADER = GENERAL + 10
COLUMNS = (GENERAL, GENERAL + 7, HEADER + 1 + 5 * 10 + 2,
           HEADER + 1 + 5 * 10 + 3)
assert COLUMNS == (616, 623, 679, 680)


def sha(raw): return hashlib.sha256(raw).hexdigest()


def file_sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(1024**2), b""): h.update(block)
    return h.hexdigest()


def write_json(path, data):
    with Path(path).open("x", encoding="utf-8") as f:
        json.dump(data, f, indent=2, allow_nan=False)


def selected_columns(path, expected_rows=134435, progress=None):
    """Stream even the existing <U32 X (41 GB expanded), never extracting it.

    Unicode/byte strings must convert explicitly to floats; object/pickle arrays
    are forbidden. Only four scalar columns and y are retained in memory.
    """
    with zipfile.ZipFile(path) as z:
        if len(z.infolist()) != 2 or set(z.namelist()) != {"X.npy", "y.npy"}:
            raise ValueError("NPZ member allowlist differs")
        if any(i.flag_bits & 1 for i in z.infolist()): raise ValueError("Encrypted array")
        if z.getinfo("y.npy").file_size > expected_rows * 16 + 4096:
            raise ValueError("Oversized label array")
        y = np.load(io.BytesIO(z.read("y.npy")), allow_pickle=False)
        if y.shape != (expected_rows,) or y.dtype.kind not in "iufb" or not np.isin(y, (0, 1)).all():
            raise ValueError("Invalid label array")
        with z.open("X.npy") as f:
            version = np.lib.format.read_magic(f)
            if version == (1, 0): shape, fortran, dtype = np.lib.format.read_array_header_1_0(f)
            elif version == (2, 0): shape, fortran, dtype = np.lib.format.read_array_header_2_0(f)
            else: raise ValueError("Unsupported NPY version")
            if shape != (expected_rows, 2381) or dtype.kind not in "fiuUS" or dtype.hasobject:
                raise ValueError("Unexpected feature shape or dtype")
            if dtype.itemsize <= 0 or dtype.itemsize > 256:
                raise ValueError("Feature dtype exceeds bounded-memory schema")
            expected_bytes = expected_rows * 2381 * dtype.itemsize
            if z.getinfo("X.npy").file_size != f.tell() + expected_bytes:
                raise ValueError("Feature member length differs from NPY header")
            result = np.empty((expected_rows, len(COLUMNS)), dtype=np.float64)
            if not fortran:
                chunk_rows = max(1, (16 * 1024**2) // (2381 * dtype.itemsize))
                for start in range(0, expected_rows, chunk_rows):
                    n = min(chunk_rows, expected_rows - start)
                    raw = f.read(n * 2381 * dtype.itemsize)
                    if len(raw) != n * 2381 * dtype.itemsize: raise ValueError("Truncated feature array")
                    block = np.frombuffer(raw, dtype=dtype).reshape(n, 2381)
                    result[start:start+n] = block[:, COLUMNS].astype(np.float64)
                    if progress and (start // 10000 != (start+n) // 10000 or start+n == expected_rows):
                        progress(start+n, expected_rows)
            else:
                # Each entire column is at most ~34 MB with this grounded shape.
                for col in range(2381):
                    raw = f.read(expected_rows * dtype.itemsize)
                    if len(raw) != expected_rows * dtype.itemsize: raise ValueError("Truncated column")
                    if col in COLUMNS:
                        result[:, COLUMNS.index(col)] = np.frombuffer(raw, dtype=dtype).astype(np.float64)
            if f.read(1): raise ValueError("Trailing feature bytes")
        return result, y.astype(np.uint8), dict(shape=list(shape), dtype=str(dtype),
            Fortran_order=bool(fortran), expanded_bytes=expected_bytes,
            expanded_array_written_to_disk=False, retained_columns=list(COLUMNS))


def metadata_join(raw, labels, quarantine_invalid_benign=False):
    rows = list(csv.DictReader(io.StringIO(raw.decode("utf-8-sig"))))
    if len(rows) != len(labels): raise ValueError("Metadata row count differs")
    seen = set()
    for i, r in enumerate(rows):
        parent = r["sha"]
        if parent in seen: raise ValueError("Duplicate metadata parent")
        if not re.fullmatch("[0-9a-f]{64}", parent):
            if not quarantine_invalid_benign or bool(labels[i]) or r["family"].strip():
                raise ValueError("Invalid metadata parent")
            # Preserve this source row and its position; never invent a SHA.
            # It is benign, and eligible() never emits benign candidate rows.
        seen.add(parent)
        if bool(r["family"].strip()) != bool(labels[i]):
            raise ValueError("Metadata family/label row alignment differs")
    return rows


def validate_anchors(metadata, columns, anchors, minimum=100):
    index = {r["sha"]: i for i, r in enumerate(metadata)}
    checked = 0
    for r in anchors:
        if r["parent_sha256"] != r["sha256"]: raise ValueError("Anchor parent contract differs")
        i = index.get(r["parent_sha256"])
        if i is None or metadata[i]["family"] != r["family"]:
            raise ValueError("Anchor SHA/family alignment differs")
        n = int(r["file_size"])
        if 15000 <= n <= 2000000:
            if columns[i, 0] != n: raise ValueError("Anchor feature size/order mismatch")
            checked += 1
    if checked < minimum: raise ValueError("Insufficient original-size anchors")
    return checked


def eligible(metadata, columns, labels, disarm, excluded, supported_profiles):
    rows = []; rejected = Counter()
    for i, (r, v, label) in enumerate(zip(metadata, columns, labels)):
        if not label: continue
        parent = r["sha"]
        if parent not in disarm: raise ValueError("Original disarm metadata missing malware SHA")
        m = disarm[parent]
        if int(m["FILE_HEADER.Machine"]) != 332 or int(m["OPTIONAL_HEADER.Subsystem"]) != 2:
            rejected["not_x86_GUI"] += 1; continue
        if not np.isfinite(v).all() or not np.equal(v, np.floor(v)).all():
            rejected["invalid_numeric_header"] += 1; continue
        n, signed, major, minor = map(int, v)
        if not 15000 <= n <= 2000000:
            rejected["outside_size_gate"] += 1; continue
        if signed not in (0, 1) or not 0 <= major <= 255 or not 0 <= minor <= 255:
            rejected["invalid_numeric_header"] += 1; continue
        if (major, minor) not in supported_profiles:
            rejected["no_current_benign_linker_support"] += 1; continue
        if parent in excluded:
            rejected["already_pilot258"] += 1; continue
        rows.append(dict(parent_sha256=parent, disarmed_sha256="", family=r["family"],
                         feature_row_index=i, file_size=n, linker_major=major, linker_minor=minor,
                         reported_has_signature=signed, original_machine=332, original_subsystem=2,
                         PE_status="NOT_AUDITED", die_status="unknown",
                         V0_hash_verification="NOT_PERFORMED", training_admitted=0))
    return rows, dict(rejected)


def select(rows, old_families, limit=256, per_family=16):
    if not 1 <= limit <= 256 or not 1 <= per_family <= 16: raise ValueError("Selection cap exceeded")
    if len({r["parent_sha256"] for r in rows}) != len(rows): raise ValueError("Duplicate candidate parent")
    queues = defaultdict(list)
    for r in rows: queues[r["family"]].append(r)
    # Stable SHA tie break; no model results, test predictions or semantic labels used.
    for family in queues:
        queues[family] = deque(sorted(queues[family], key=lambda r: sha(
            ("G6-prescreen-v1:" + r["parent_sha256"]).encode())))
    families = sorted(queues, key=lambda f: (f in old_families, sha(f.encode())))
    chosen = []
    for _ in range(per_family):
        for family in families:
            if queues[family]: chosen.append(queues[family].popleft())
            if len(chosen) == limit: return chosen
    return chosen


def main():
    npz = PRIVATE / "bodmas.npz"; meta = PRIVATE / "bodmas_metadata.csv"
    if file_sha(npz) != NPZ_SHA or file_sha(meta) != META_SHA:
        raise ValueError("Grounded numeric input checksum differs")
    with zipfile.ZipFile(PRIVATE / "static182_disarmed_for_vm.zip") as z:
        raw = z.read("bodmas_pilot_258_metadata_readiness.csv")
    if sha(raw) != ANCHOR_SHA: raise ValueError("Existing pilot metadata differs")
    anchors = list(csv.DictReader(io.StringIO(raw.decode("utf-8-sig"))))
    with zipfile.ZipFile(PRIVATE / "v0-verify-five-kit-20261028.zip") as z:
        disarm_raw = z.read("meta_disarm.csv")
    disarm_rows = list(csv.DictReader(io.StringIO(disarm_raw.decode("utf-8-sig"))))
    disarm = {r["sha256"]: r for r in disarm_rows}
    if len(disarm) != 57293 or len(disarm_rows) != len(disarm): raise ValueError("Official metadata count differs")
    profile_file = HERE / "MATCHED_POOL_FINISH_RESULTS_RECEIVED/PROFILE_SUPPORT.csv"
    with profile_file.open(newline="", encoding="utf-8-sig") as f:
        support = {(int(r["linker_major"]), int(r["linker_minor"])): int(r["benign"])
                   for r in csv.DictReader(f) if r["scheme"] == "linker_major_minor" and int(r["benign"])}
    if sum(support.values()) != 225: raise ValueError("Completed benign pool differs")
    def progress(n, total): print(f"Streaming numeric array: {n}/{total}", flush=True)
    cache = PRIVATE / "NUMERIC_COLUMNS_CACHE.npz"
    cache_receipt = PRIVATE / "NUMERIC_COLUMNS_CACHE_RECEIPT.json"
    if cache.exists() and cache_receipt.exists():
        receipt = json.loads(cache_receipt.read_text())
        if receipt["source_sha256"] != NPZ_SHA or receipt["cache_sha256"] != file_sha(cache):
            raise ValueError("Numeric column cache differs")
        with np.load(cache, allow_pickle=False) as f:
            cols, y = f["columns"], f["labels"]
        schema = receipt["schema"]
    else:
        if cache.exists() or cache_receipt.exists(): raise ValueError("Incomplete cache; preserve for review")
        cols, y, schema = selected_columns(npz, progress=progress)
        with cache.open("xb") as f: np.savez_compressed(f, columns=cols, labels=y)
        write_json(cache_receipt, dict(source_sha256=NPZ_SHA, cache_sha256=file_sha(cache), schema=schema))
    metadata = metadata_join(meta.read_bytes(), y, quarantine_invalid_benign=True)
    if Counter(map(int, y)) != {0: 77142, 1: 57293}: raise ValueError("BODMAS labels differ")
    n_anchors = validate_anchors(metadata, cols, anchors)
    old_families = {r["family"] for r in anchors}
    candidates, rejections = eligible(metadata, cols, y, disarm,
        {r["parent_sha256"] for r in anchors}, support)
    chosen = select(candidates, old_families)
    profile_rows = []
    for (major, minor), benign in sorted(support.items()):
        pool = [r for r in candidates if (r["linker_major"], r["linker_minor"]) == (major, minor)]
        selected = [r for r in chosen if (r["linker_major"], r["linker_minor"]) == (major, minor)]
        profile_rows.append(dict(linker_major=major, linker_minor=minor, current_benign=benign,
            available_new_malware=len(pool), available_families=len({r["family"] for r in pool}),
            selected_candidates=len(selected), selected_families=len({r["family"] for r in selected}),
            linker_only_capacity_upper_bound=min(benign, len(pool))))
    out = Path(tempfile.mkdtemp(prefix="NUMERIC_SCREEN_", dir=PRIVATE))
    if chosen:
        with (out / "CANDIDATES_PRIVATE.csv").open("x", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(chosen[0])); w.writeheader(); w.writerows(chosen)
    with (out / "PROFILE_SUPPORT_SAFE.csv").open("x", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(profile_rows[0])); w.writeheader(); w.writerows(profile_rows)
    # Cache only four scalar columns, not the 41GB expanded feature matrix.
    with (out / "SELECTED_COLUMNS_PRIVATE.npz").open("xb") as f:
        np.savez_compressed(f, selected_columns=cols, labels=y)
    summary = dict(status="NUMERIC_PRESCREEN_ONLY_NOT_A_VERIFIED_COHORT", schema=schema,
        inputs_sha256=dict(numeric_vectors=NPZ_SHA, official_metadata=META_SHA,
                          original_pilot=ANCHOR_SHA, official_disarm_metadata=sha(disarm_raw),
                          current_benign_support=file_sha(profile_file)),
        rows=len(y), malware=int(y.sum()), benign=int(len(y)-y.sum()), exact_size_anchors=n_anchors,
        invalid_original_benign_identifiers_quarantined=sum(not bool(re.fullmatch("[0-9a-f]{64}", r["sha"])) for r in metadata),
        eligible_new_malware=len(candidates), eligible_families=len({r["family"] for r in candidates}),
        selected_candidates=len(chosen), selected_families=len({r["family"] for r in chosen}),
        selected_families_absent_from_pilot=len({r["family"] for r in chosen}-old_families),
        per_family_cap=16, total_cap=256, exclusions=rejections,
        linker_only_capacity_upper_bound=sum(r["linker_only_capacity_upper_bound"] for r in profile_rows),
        profiles=profile_rows, candidate_payload_bytes=sum(r["file_size"] for r in chosen),
        malware_binaries_downloaded=False, binary_audit_performed=False, restoration=False,
        training_performed=False, original_splits_changed=False, Drive_modified=False,
        limits=["Numeric features do not contain Rich build profiles or establish DiE clean/unpacked status",
                "Linker-only capacity ignores family/prefix, size/signature, PE and Rich gates; no matched sample count guaranteed",
                "Prescreen is not training and does not satisfy teacher100/class",
                "New sample transfer/restoration requires separate bounded approval; original identities remain unchanged"],
        references=["https://whyisyoung.github.io/BODMAS/", "https://github.com/elastic/ember/blob/master/ember/features.py"])
    write_json(out / "RESULTS_FOR_CODEX.json", summary)
    write_json(out / "FILES_SHA256.json", {p.name: file_sha(p) for p in out.iterdir() if p.is_file()})
    print(json.dumps(dict(output=str(out), **summary), indent=2))


if __name__ == "__main__": main()
