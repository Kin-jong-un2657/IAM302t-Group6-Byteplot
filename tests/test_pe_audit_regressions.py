"""Regressions for candidate cardinality, CLI and unchanged training contracts."""

import hashlib
import os
from pathlib import Path
import subprocess
import sys

import pytest

from byteplot.io import write_csv
from byteplot.pe_audit import audit_pe
from byteplot.representation import prepare

from test_pe_audit import candidate, pe_header, read_report, write_manifest


def test_ten_candidates_keep_one_record_each_without_benign_or_split(tmp_path):
    root = tmp_path / "binary"
    (root / "altered").mkdir(parents=True)
    rows = [candidate(f"altered/{i}.exe") for i in range(10)]
    # Retain duplicate parents too: this is an audit, not deduplication.
    (root / rows[0]["zip_member"]).write_bytes(pe_header())
    (root / rows[1]["zip_member"]).write_bytes(b"not a PE")
    manifest = tmp_path / "pilot.csv"
    write_manifest(manifest, rows)
    before = manifest.read_bytes()
    report = read_report(audit_pe(manifest, root, tmp_path / "out.csv"))
    assert len(report) == 10
    assert [r["audit_row"] for r in report] == [str(i) for i in range(1, 11)]
    assert [r["zip_member"] for r in report] == [r["zip_member"] for r in rows]
    assert [r["pe_status"] for r in report] == ["parsed", "parse_error"] + ["missing_file"] * 8
    assert all(r["parent_sha256"] == "a" * 64 and r["group"] == "malware_unverified" for r in report)
    assert manifest.read_bytes() == before
    assert sorted(p.name for p in root.iterdir()) == ["altered"]


def test_cli_dispatch_and_no_overwrite(tmp_path):
    root = tmp_path / "binary"
    root.mkdir()
    manifest, output = tmp_path / "pilot.csv", tmp_path / "out.csv"
    write_manifest(manifest, [candidate("missing.exe")])
    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    command = [sys.executable, "-B", "-m", "byteplot", "audit-pe",
               "--manifest", str(manifest), "--binary-root", str(root), "--out", str(output)]
    result = subprocess.run(command, cwd=Path(__file__).resolve().parents[1],
                            env=environment, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert read_report(output)[0]["pe_status"] == "missing_file"
    before = output.read_bytes()
    retry = subprocess.run(command, cwd=Path(__file__).resolve().parents[1],
                           env=environment, capture_output=True, text=True)
    assert retry.returncode == 2 and "Output exists" in retry.stderr
    assert "Traceback" not in retry.stderr and output.read_bytes() == before


def test_existing_prepare_still_requires_v0_content_hash_to_equal_parent(tmp_path):
    data = pe_header()
    sample = tmp_path / "sample.exe"
    sample.write_bytes(data)
    parent = "a" * 64
    manifest = tmp_path / "training.csv"
    row = dict(path="sample.exe", parent_sha256=parent,
               sha256=hashlib.sha256(data).hexdigest(), label="1", variant="V0",
               split="train", status="ok", die_status="clean", synthetic="0")
    write_csv(manifest, [row])
    with pytest.raises(ValueError, match="Manifest is empty"):
        prepare(manifest, tmp_path / "prepared", height=32, width=32)
    errors = read_report(tmp_path / "prepared/prepare_errors.csv")
    assert len(errors) == 1 and "V0 bytes must hash to parent_sha256" in errors[0]["error"]


def test_malformed_rows_are_retained_and_header_errors_create_no_output(tmp_path):
    root = tmp_path / "binary"
    root.mkdir()
    manifest = tmp_path / "pilot.csv"
    manifest.write_text("parent_sha256,zip_member\n" + "a" * 64 + ",missing.exe,extra\n" +
                        "b" * 64 + "\n", encoding="utf-8")
    report = read_report(audit_pe(manifest, root, tmp_path / "out.csv"))
    assert len(report) == 2 and all(r["file_status"] == "invalid_path" for r in report)
    manifest.write_text("parent_sha256,parent_sha256,zip_member\n", encoding="utf-8")
    out = tmp_path / "bad-header.csv"
    with pytest.raises(ValueError, match="Duplicate"):
        audit_pe(manifest, root, out)
    assert not out.exists()
