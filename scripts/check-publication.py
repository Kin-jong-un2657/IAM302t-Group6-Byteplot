"""Check exactly the Git index for publication hygiene; print no sensitive values."""

import csv
import io
import json
import re
import subprocess
from pathlib import Path


def git(*args):
    return subprocess.check_output(["git", *args])


def main():
    files = git("ls-files", "--stage", "-z").decode("utf-8").split("\0")
    errors = []
    count = total = 0
    forbidden = {".exe", ".dll", ".bin", ".sys", ".npz", ".npy", ".pt", ".pth", ".ckpt",
                 ".zip", ".7z", ".rar", ".iso", ".vmdk", ".sqlite", ".db", ".pkl", ".pem", ".key"}
    expected_csvs = {
        "audit_182/Static182_audit_redacted.csv",
        "results_e5_summary/E5_RESULTS.csv",
        "results_e5_summary/E5_CHANNEL_SUMMARY.csv",
        "examples/manifest.template.csv",
    }
    personal = re.compile(rb"(?i)(?:[a-z]:(?:\\+|/)(?:users|documents and settings|projects)(?:\\+|/)|/(?:home|users)/|file:[/][/])")
    secrets = re.compile(rb"(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|AKIA[A-Z0-9]{16}|-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----)")
    for entry in files:
        if not entry:
            continue
        metadata, name = entry.split("\t", 1)
        mode, sha, stage = metadata.split()
        raw = git("cat-file", "blob", sha)
        count += 1
        total += len(raw)
        suffix = Path(name).suffix.lower()
        if mode not in {"100644", "100755"} or stage != "0":
            errors.append([name, "non-regular file or unresolved index"])
        if suffix in forbidden or len(raw) > 1_000_000 or raw.startswith((b"MZ", b"PK\x03\x04", b"\x7fELF")):
            errors.append([name, "prohibited artifact or size"])
        if any(part.lower() in {"private", ".venv", "__pycache__", ".cache"} for part in Path(name).parts):
            errors.append([name, "private/generated path"])
        if suffix == ".png":
            if name != "results_e5_summary/E5_MACRO_F1.png" or not raw.startswith(b"\x89PNG\r\n\x1a\n"):
                errors.append([name, "unreviewed binary image"])
            continue
        if b"\0" in raw or personal.search(raw) or secrets.search(raw):
            errors.append([name, "binary, personal path or credential pattern"])
        if suffix == ".json":
            json.loads(raw)
        if suffix == ".csv":
            if name not in expected_csvs:
                errors.append([name, "unreviewed CSV"])
            records = list(csv.DictReader(io.StringIO(raw.decode("utf-8-sig"))))
            if name == "examples/manifest.template.csv" and records:
                errors.append([name, "schema template must be empty"])
            if name.startswith("audit_182/") and any(k in {"sha256", "parent_sha256", "path", "family"} for k in (records[0] if records else {})):
                errors.append([name, "identity-bearing audit columns"])
    print(json.dumps({"check": "staged_publication", "files": count, "bytes": total,
                      "errors": errors, "passed": not errors}, indent=2))
    raise SystemExit(bool(errors))


if __name__ == "__main__":
    main()
