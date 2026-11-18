"""Non-executable random byte fixtures, never real malware or real UPX data."""

import zlib
from pathlib import Path

import numpy as np

from .io import sha256, write_csv, write_json


def make_synthetic(out, parents_per_class=20, seed=17):
    out = Path(out).resolve()
    if (out / "manifest.csv").exists():
        raise ValueError("Synthetic manifest exists. Choose a new demo directory.")
    if parents_per_class < 6:
        raise ValueError("Demo needs >= 6 parents per class.")
    (out / "bytes").mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(seed)
    rows = []
    for label in (0, 1):
        for _ in range(parents_per_class):
            length = int(rng.integers(1600, 5600))
            if label == 0:
                payload = rng.integers(32, 128, length, dtype=np.uint8)
            else:
                payload = rng.integers(0, 256, length, dtype=np.uint8)
                payload[::4] = 0
            original = b"SYNTHETIC-NON-PE\x00" + payload.tobytes()
            parent = sha256(original)
            variants = {"V0": original, "V1": b"MOCK-ZLIB\x00" + zlib.compress(original),
                        "V1u": original, "V2": b"MOCK-XOR\x00" + bytes(b ^ 0xA5 for b in original)}
            for variant, data in variants.items():
                name = f"bytes/{parent}_{variant}.bin"
                (out / name).write_bytes(data)
                rows.append({"path": name, "sha256": sha256(data), "parent_sha256": parent,
                             "label": label, "family": "synthetic", "variant": variant,
                             "packer": "none" if variant in ("V0", "V1u") else "mock_not_real_packer",
                             "die_status": "synthetic_not_scanned", "status": "ok", "synthetic": 1})
    write_csv(out / "manifest.csv", rows)
    write_json(out / "SYNTHETIC_ONLY.json", {
        "warning": "Mock distributions and mock PE regions. V1/V2 are NOT UPX/MPRESS. No research conclusions.",
        "seed": seed, "parents_per_class": parents_per_class,
    })
    return out / "manifest.csv"
