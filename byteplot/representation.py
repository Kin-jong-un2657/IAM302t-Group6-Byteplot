"""Offset-preserving byte, entropy, PE-region and valid-byte maps."""

from pathlib import Path

import numpy as np

from .io import assign_splits, read_csv, sha256, validate_rows, write_csv, write_json


def entropy_map(data, window=256, step=64):
    """Average all overlapping window entropies; include one end-aligned window.

    Only observed bytes are used, never zero-padding. Output is in bits [0, 8].
    """
    if window <= 0 or step <= 0 or step > window:
        raise ValueError("Expected 0 < step <= window.")
    values = np.frombuffer(data, dtype=np.uint8)
    n = len(values)
    if not n:
        return np.empty(0, dtype=np.float32)
    starts = list(range(0, max(1, n - window + 1), step))
    last = max(0, n - window)
    if starts[-1] != last:
        starts.append(last)
    sums = np.zeros(n + 1, dtype=np.float64)
    counts = np.zeros(n + 1, dtype=np.int32)
    for start in starts:
        end = min(n, start + window)
        hist = np.bincount(values[start:end], minlength=256)
        p = hist[hist > 0] / (end - start)
        h = float(-(p * np.log2(p)).sum())
        sums[start] += h
        sums[end] -= h
        counts[start] += 1
        counts[end] -= 1
    return (np.cumsum(sums)[:-1] / np.cumsum(counts)[:-1]).astype(np.float32)


def pe_regions(data, length):
    """0 unknown, .25 header, .5 section, .75 heuristic stub, 1 overlay.

    Stub is a heuristic (known packer section name AND entrypoint in that section),
    not byte-accurate unpacker ground truth. Only the observed prefix is mapped.
    """
    import pefile

    regions = np.zeros(length, dtype=np.float32)
    pe = pefile.PE(data=data, fast_load=True)
    try:
        regions[:min(length, int(pe.OPTIONAL_HEADER.SizeOfHeaders))] = 0.25
        ep = int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        stub_sections = []
        for section in pe.sections:
            start = int(section.PointerToRawData)
            end = start + int(section.SizeOfRawData)
            name = section.Name.rstrip(b"\x00").decode("ascii", errors="replace").lower()
            va = int(section.VirtualAddress)
            virtual_end = va + max(int(section.Misc_VirtualSize), int(section.SizeOfRawData))
            is_stub = any(t in name for t in ("upx", "mpress", "aspack", "adata")) and va <= ep < virtual_end
            if start < length and end > start:
                regions[start:min(length, end)] = 0.75 if is_stub else 0.5
            if is_stub:
                stub_sections.append(name)
        overlay = pe.get_overlay_data_start_offset()
        if overlay is not None and overlay < length:
            regions[overlay:] = 1.0
        security = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
        info = {"sections": len(pe.sections), "signed": int(security.Size > 0),
                "stub_heuristic_sections": ",".join(stub_sections), "pe_status": "parsed"}
    finally:
        pe.close()
    return regions, info


def encode(data, height=256, width=256, window=256, step=64, synthetic=False):
    if height < 8 or width < 8 or not data:
        raise ValueError("Nonempty data and image dimensions >= 8 are required.")
    capacity = height * width
    prefix = data[:capacity]
    n = len(prefix)
    x = np.zeros((3, capacity), dtype=np.float32)
    x[0, :n] = np.frombuffer(prefix, dtype=np.uint8).astype(np.float32) / 255.0
    # Compute only from the bytes the grayscale model actually sees.
    x[1, :n] = entropy_map(prefix, window, step) / 8.0
    if synthetic:
        regions = np.full(n, 0.5, dtype=np.float32)
        regions[:min(128, n)] = 0.25
        regions[max(128, n - 64):] = 1.0
        info = {"sections": 1, "signed": 0, "stub_heuristic_sections": "", "pe_status": "synthetic_mock"}
    else:
        regions, info = pe_regions(data, n)
    x[2, :n] = regions
    mask = np.zeros(capacity, dtype=np.float32)
    mask[:n] = 1
    info.update(size_bytes=len(data), visible_bytes=n, truncated=int(len(data) > capacity),
                padding_fraction=1 - n / capacity)
    return x.reshape(3, height, width), mask.reshape(1, height, width), info


def prepare(manifest, out, height=256, width=256, window=256, step=64, seed=17,
            val_fraction=0.15, test_fraction=0.15):
    manifest, out = Path(manifest).resolve(), Path(out).resolve()
    if (out / "prepared.csv").exists():
        raise ValueError("Output already has prepared.csv; choose a new output directory.")
    source = read_csv(manifest)
    eligible = [r for r in source if r.get("status", "ok") == "ok"]
    validate_rows(eligible)
    # Preserve the original parent split even if individual variants fail to parse.
    eligible = assign_splits(eligible, seed, val_fraction, test_fraction)
    (out / "features").mkdir(parents=True, exist_ok=True)
    rows, errors = [], []
    for row in eligible:
        try:
            synthetic = row.get("synthetic", "0") == "1"
            if not synthetic:
                expected_status = "packed" if row["variant"] in ("V1", "V2") else "clean"
                if row.get("die_status") != expected_status:
                    raise ValueError(f"{row['variant']} must have die_status={expected_status} after DiE inspection.")
                if row["variant"] == "V1" and "upx" not in row.get("packer", "").lower():
                    raise ValueError("V1 must record UPX as its packer.")
                if row["variant"] == "V2" and "upx" in row.get("packer", "").lower():
                    raise ValueError("V2 must use a different packer from UPX.")
            path = (manifest.parent / row["path"]).resolve()
            data = path.read_bytes()
            digest = sha256(data)
            if row.get("sha256") and row["sha256"] != digest:
                raise ValueError("SHA-256 does not match manifest.")
            if row["variant"] == "V0" and digest != row["parent_sha256"]:
                raise ValueError("V0 bytes must hash to parent_sha256.")
            x, mask, info = encode(data, height, width, window, step, synthetic)
            feature = f"features/{digest}.npz"
            np.savez_compressed(out / feature, x=x, mask=mask)
            # Exportable manifest contains no path to a raw binary.
            clean = {k: v for k, v in row.items() if k not in ("path", "split")}
            clean.update(info, sha256=digest, split=row["split"], feature_path=feature,
                         synthetic=int(synthetic), group=("malware" if int(row["label"]) else "benign") +
                         ("_packed" if row["variant"] in ("V1", "V2") else "_unpacked"))
            rows.append(clean)
        except (OSError, ValueError, IndexError) as exc:
            errors.append({"parent_sha256": row["parent_sha256"], "variant": row["variant"], "error": str(exc)})
        except Exception as exc:
            # pefile uses PEFormatError; retain a per-file error rather than drop silently.
            if exc.__class__.__name__ != "PEFormatError":
                raise
            errors.append({"parent_sha256": row["parent_sha256"], "variant": row["variant"], "error": str(exc)})
    write_csv(out / "prepare_errors.csv", errors, ["parent_sha256", "variant", "error"])
    validate_rows(rows, require_split=True)
    write_csv(out / "prepared.csv", rows)
    write_json(out / "dataset.json", {
        "height": height, "width": width, "entropy_window": window, "entropy_step": step,
        "entropy_overlap": "mean; final window end-aligned; observed prefix only",
        "normalization": "byte/255, entropy_bits/8, region in {0,.25,.5,.75,1}",
        "region_stub": "heuristic: known packer section containing entrypoint",
        "seed": seed, "val_fraction": val_fraction, "test_fraction": test_fraction,
        "input_rows": len(source), "excluded_status_rows": len(source) - len(eligible),
        "prepared_rows": len(rows), "failed_rows": len(errors),
        "truncation_rate": float(np.mean([int(r["truncated"]) for r in rows])),
        "synthetic": all(int(r["synthetic"]) for r in rows),
    })
    print(f"Prepared {len(rows)} samples; {len(errors)} errors -> {out / 'prepared.csv'}", flush=True)
    return out / "prepared.csv"
