"""Static tools for an isolated VM. Never invoke the sample as a process."""

import json
import os
import subprocess
from pathlib import Path

from .io import read_csv, sha256, write_csv


def run_tool(command, timeout=120):
    return subprocess.run([str(c) for c in command], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout, shell=False,
                          creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)


def interpret_die(document):
    """Read typed DiE detections; unrecognized JSON is never marked clean."""
    detections = []

    def visit(value):
        if isinstance(value, dict):
            if isinstance(value.get("type"), str):
                detections.append((value["type"].lower(), str(value.get("name", ""))))
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(document)
    packed = [(kind, name) for kind, name in detections if "packer" in kind or "protector" in kind]
    if packed:
        return "packed", "; ".join(name for _, name in packed)
    known = ("compiler", "linker", "library", "tool", "language", "format", "operation system", "sign tool")
    if any(kind in known for kind, _ in detections):
        return "clean", ""
    return "unknown", ""


def scan_die(path, executable, log_path):
    log_path = Path(log_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        result = run_tool([executable, "-j", path])
        log_path.write_text(result.stdout + "\n" + result.stderr, encoding="utf-8")
        if result.returncode != 0:
            return "unknown", ""
        return interpret_die(json.loads(result.stdout))
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(f"\nInspection error: {exc}\n")
        return "unknown", ""


def index_originals(benign, malware, out, die, metadata=None):
    out = Path(out).resolve()
    if (out / "originals.csv").exists():
        raise ValueError("originals.csv exists; choose a new output directory.")
    families = {}
    if metadata:
        for row in read_csv(metadata):
            digest = row.get("sha256") or row.get("sha")
            if digest:
                families[digest] = row.get("family", "")
    rows, seen = [], {}
    for label, folder in ((0, benign), (1, malware)):
        for path in sorted(Path(folder).resolve().rglob("*")):
            if not path.is_file():
                continue
            with path.open("rb") as handle:
                if handle.read(2) != b"MZ":
                    continue
            digest = sha256(path.read_bytes())
            if digest in seen:
                if seen[digest] != label:
                    raise ValueError(f"Same original has conflicting labels: {digest}")
                continue
            seen[digest] = label
            status, packer = scan_die(path, die, out / "die" / f"{digest}.json")
            rows.append({"path": str(path), "sha256": digest, "parent_sha256": digest,
                         "label": label, "variant": "V0", "family": families.get(digest, ""),
                         "packer": packer or "none", "die_status": status,
                         "status": "ok" if status == "clean" else "excluded", "synthetic": 0})
    if not rows:
        raise ValueError("No MZ files found in the input directories.")
    write_csv(out / "originals.csv", rows)
    print(f"Indexed {len(rows)} originals; {sum(r['status'] == 'ok' for r in rows)} clean by DiE.", flush=True)
    return out / "originals.csv"


def build_variants(manifest, out, upx, die, v2_dir=None, v2_packer="external"):
    manifest, out = Path(manifest).resolve(), Path(out).resolve()
    if (out / "manifest.csv").exists():
        raise ValueError("Variant manifest exists; choose a new output directory.")
    out.mkdir(parents=True, exist_ok=True)
    results = []
    for original in read_csv(manifest):
        if original.get("status", "ok") != "ok" or original.get("die_status") != "clean":
            results.append(dict(original, status="excluded"))
            continue
        if original["variant"] != "V0" or original.get("synthetic", "0") == "1":
            raise ValueError("variants expects real V0 originals inspected with DiE.")
        path = (manifest.parent / original["path"]).resolve()
        if sha256(path.read_bytes()) != original["parent_sha256"]:
            raise ValueError("Original hash changed since indexing.")
        results.append(dict(original, path=str(path)))
        parent = original["parent_sha256"]
        v1 = out / "bytes" / f"{parent}_V1.bin"
        v1.parent.mkdir(parents=True, exist_ok=True)
        succeeded = False
        for variant, input_path, output_path, options in (
            ("V1", path, v1, []),
            ("V1u", v1, out / "bytes" / f"{parent}_V1u.bin", ["-d"]),
        ):
            row = dict(original, variant=variant, path=str(output_path), sha256="", packer="UPX",
                       status="failed", die_status="unknown")
            try:
                if variant == "V1u" and not succeeded:
                    raise ValueError("V1 was not successfully packed/verified.")
                if output_path.exists():
                    raise ValueError("Output exists; refusing to overwrite binary.")
                result = run_tool([upx, *options, "-o", output_path, input_path])
                row["tool_log"] = (result.stdout + "\n" + result.stderr)[-4000:]
                if result.returncode != 0 or not output_path.exists():
                    raise ValueError("UPX failed; see tool_log.")
                status, detected = scan_die(output_path, die, out / "die" / f"{parent}_{variant}.json")
                row.update(sha256=sha256(output_path.read_bytes()), die_status=status, detected_packer=detected)
                verified = status == "clean" if variant == "V1u" else status == "packed" and "upx" in detected.lower()
                row["status"] = "ok" if verified else "unverified"
                if variant == "V1":
                    succeeded = verified
            except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
                row["error"] = str(exc)
            results.append(row)
        if v2_dir:
            v2 = Path(v2_dir).resolve() / f"{parent}.bin"
            row = dict(original, variant="V2", path=str(v2), sha256="", packer=v2_packer,
                       status="failed", die_status="unknown")
            if v2.is_file():
                status, detected = scan_die(v2, die, out / "die" / f"{parent}_V2.json")
                expected = v2_packer == "external" or v2_packer.lower() in detected.lower()
                verified = status == "packed" and "upx" not in detected.lower() and expected
                row.update(sha256=sha256(v2.read_bytes()), die_status=status, detected_packer=detected,
                           status="ok" if verified else "unverified")
            else:
                row["error"] = "V2 file not provided."
            results.append(row)
    write_csv(out / "manifest.csv", results)
    print(f"Variant audit saved -> {out / 'manifest.csv'}", flush=True)
    return out / "manifest.csv"
