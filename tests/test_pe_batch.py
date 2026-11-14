"""Safe header fixtures and metadata: no real malware or archive extraction."""
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from types import SimpleNamespace

import pytest

from byteplot import pe_batch as batch
from test_pe_audit import pe_header, read_report, write_manifest


@pytest.fixture
def dataset(tmp_path):
    root = tmp_path / "staging"
    (root / "altered").mkdir(parents=True)
    rows = [dict(sha256=f"{i:064x}", file_size="1100", group="malware_unverified")
            for i in range(1, 4)]
    manifest = tmp_path / "bodmas_manifest_v0_verified.csv"
    write_manifest(manifest, rows)
    return root, manifest, rows, tmp_path / "state"


def stage(root, row, data=None):
    path = root / "altered" / (row["sha256"] + ".exe")
    path.write_bytes(pe_header() if data is None else data)
    return path


def run(dataset, **kwargs):
    root, manifest, _, state = dataset
    return batch.audit_pe_batches(manifest, root, state, min_free_bytes=0, **kwargs)


def test_plan_then_rotate_offline_batches_and_resume(dataset):
    root, manifest, rows, state = dataset
    before = manifest.read_bytes()
    summary, snapshot = run(dataset, batch_size=0, expected_count=3)
    assert summary["completed"] == 0 and summary["pending"] == 3
    assert [r["zip_member"] for r in read_report(snapshot / "next_batch.csv")] == [
        f"altered/{r['sha256']}.exe" for r in rows]
    first = stage(root, rows[0])
    summary, snapshot1 = run(dataset, resume=True, batch_size=1)
    previous = (snapshot1 / "summary.json").read_bytes()
    assert summary["completed"] == 1
    first.unlink()  # Safe fixture only: emulate removing a completed offline batch.
    stage(root, rows[1])
    summary, snapshot2 = run(dataset, resume=True)
    assert summary["completed"] == 2 and summary["pending"] == 1
    stage(root, rows[2])
    summary, final = run(dataset, resume=True, export=True)
    result = read_report(final / "results.csv")
    assert summary["dataset_complete"] and len(result) == 3
    assert [r["audit_row"] for r in result] == ["1", "2", "3"]
    assert [r["sha256"] for r in result] == [r["sha256"] for r in rows]
    assert all(r["parent_sha256"] == r["sha256"] != r["disarmed_sha256"] for r in result)
    assert len({snapshot, snapshot1, snapshot2, final}) == 4
    assert (snapshot1 / "summary.json").read_bytes() == previous
    assert manifest.read_bytes() == before
    with sqlite3.connect(state / "checkpoint.sqlite3") as db:
        assert db.execute("SELECT count(*) FROM results").fetchone()[0] == 3


def test_full_57293_manifest_only_needs_one_staged_fixture(tmp_path):
    root = tmp_path / "staging"
    (root / "altered").mkdir(parents=True)
    manifest, state = tmp_path / "full.csv", tmp_path / "state"
    rows = [dict(sha256=f"{i:064x}", file_size="1100") for i in range(1, 57294)]
    write_manifest(manifest, rows)
    stage(root, rows[0])
    summary, _ = batch.audit_pe_batches(manifest, root, state, batch_size=1,
                                         min_free_bytes=0, expected_count=57293)
    assert (summary["manifest_records"], summary["completed"], summary["pending"]) == (57293, 1, 57292)
    assert summary["next_batch_count"] == 1 and not summary["dataset_complete"]
    assert len(list((root / "altered").iterdir())) == 1


def test_interrupt_retains_each_commit_and_releases_lock(dataset, monkeypatch):
    root, _, rows, state = dataset
    for row in rows:
        stage(root, row)
    original = batch.single._audit_row

    def interrupted(source, index, *args):
        if index == 2:
            raise KeyboardInterrupt()
        return original(source, index, *args)

    monkeypatch.setattr(batch.single, "_audit_row", interrupted)
    with pytest.raises(KeyboardInterrupt):
        run(dataset)
    with sqlite3.connect(state / "checkpoint.sqlite3") as db:
        assert db.execute("SELECT row_index FROM results").fetchall() == [(1,)]
    snapshot, = (state / "snapshots").glob("*/summary.json")
    assert json.loads(snapshot.read_text())["stop_reason"] == "interrupted"
    monkeypatch.setattr(batch.single, "_audit_row", original)
    summary, _ = run(dataset, resume=True)
    assert summary["completed"] == 3 and summary["new_results_this_invocation"] == 2


def test_abrupt_exit_recovers_wal_and_lock(dataset, tmp_path):
    root, manifest, rows, state = dataset
    for row in rows:
        stage(root, row)
    script = tmp_path / "crash_simulation.py"
    repo = Path(__file__).resolve().parents[1]
    script.write_text(
        "import os,sys\nsys.path.insert(0,sys.argv[1])\n"
        "from byteplot import pe_batch as b\noriginal=b.single._audit_row\n"
        "def audit(source,index,*args):\n"
        "    if index==2: os._exit(9)\n"
        "    return original(source,index,*args)\n"
        "b.single._audit_row=audit\n"
        "b.audit_pe_batches(sys.argv[2],sys.argv[3],sys.argv[4],min_free_bytes=0)\n",
        encoding="utf-8")
    child = subprocess.run(
        [sys.executable, "-B", str(script), str(repo), str(manifest), str(root), str(state)],
        capture_output=True, text=True, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
    assert child.returncode == 9, child.stderr
    with sqlite3.connect(state / "checkpoint.sqlite3") as db:
        assert db.execute("SELECT count(*) FROM results").fetchone()[0] == 1
    (root / "altered" / (rows[0]["sha256"] + ".exe")).unlink()
    summary, snapshot = run(dataset, resume=True, export=True)
    assert summary["completed"] == 3 and len(read_report(snapshot / "results.csv")) == 3


def test_export_failure_preserves_results_without_reauditing(dataset, monkeypatch):
    root, _, rows, _ = dataset
    stage(root, rows[0])
    original = batch._write_csv
    def fail(*args):
        raise OSError("disk fixture")
    monkeypatch.setattr(batch, "_write_csv", fail)
    with pytest.raises(OSError, match="disk fixture"):
        run(dataset, batch_size=1)
    monkeypatch.setattr(batch, "_write_csv", original)
    monkeypatch.setattr(batch.single, "_audit_row", lambda *a: pytest.fail("Already committed"))
    summary, snapshot = run(dataset, resume=True, batch_size=0, export=True)
    assert summary["completed"] == 1 and len(read_report(snapshot / "results.csv")) == 1


@pytest.mark.parametrize("change", ["manifest", "settings"])
def test_resume_rejects_changed_inputs(dataset, change):
    root, manifest, rows, _ = dataset
    stage(root, rows[0])
    run(dataset, batch_size=1)
    if change == "manifest":
        write_manifest(manifest, list(reversed(rows)))
    with pytest.raises(ValueError, match="changed"):
        run(dataset, resume=True, height=512 if change == "settings" else 256)


def test_state_no_overwrite_and_one_writer(dataset):
    run(dataset, batch_size=0)
    with pytest.raises(FileExistsError):
        run(dataset)
    with batch._state_lock(dataset[3]):
        with pytest.raises(ValueError, match="already in use"):
            run(dataset, resume=True, batch_size=0)


def test_byte_budget_and_oversized_plans(dataset):
    root, _, rows, _ = dataset
    for row in rows:
        stage(root, row)
    summary, snapshot = run(dataset, max_batch_bytes=1500)
    assert summary["completed"] == 1 and summary["next_batch_known_bytes"] == 1100
    assert len(read_report(snapshot / "next_batch.csv")) == 1
    summary, _ = run(dataset, resume=True, max_batch_bytes=500)
    assert summary["completed"] == 1 and summary["oversized_pending"] == 2
    assert summary["next_batch_count"] == 0 and summary["pending"] == 2


def test_low_disk_stops_without_completing_rows(dataset, monkeypatch):
    root, manifest, rows, state = dataset
    stage(root, rows[0])
    monkeypatch.setattr(batch.shutil, "disk_usage", lambda *a: SimpleNamespace(free=0))
    summary, _ = batch.audit_pe_batches(manifest, root, state, min_free_bytes=100)
    assert summary["stop_reason"] == "low_disk_space"
    assert summary["completed"] == 0 and summary["pending"] == 3


def test_independent_errors_and_packing_truncation_summary(dataset, monkeypatch):
    root, manifest, rows, _ = dataset
    rows.extend([dict(sha256=f"{i:064x}", file_size="1100") for i in (4, 5)])
    write_manifest(manifest, rows)
    for index, row in enumerate(rows[:4]):
        stage(root, row, b"invalid" if index == 2 else None)
    original = batch.single._audit_row

    def audit(source, index, *args):
        if index == 4:
            raise RuntimeError("fixture parser crash")
        result = original(source, index, *args)
        result["die_status"] = {1: "packed", 2: "clean", 3: "unknown"}[index]
        return result

    monkeypatch.setattr(batch.single, "_audit_row", audit)
    summary, snapshot = run(dataset, height=8, width=8, export=True)
    assert summary["pe_parsed"] == 2 and summary["pe_parse_errors"] == 1
    assert summary["file_status_counts"]["audit_error"] == 1
    assert summary["die_counts"] == dict(packed=1, clean=1, unknown=2)
    assert (summary["completed"], summary["pending"]) == (4, 1)
    assert summary["truncated_files"] == 2 and summary["files_read"] == 3
    assert summary["truncation_rate_among_files_read"] == pytest.approx(2 / 3)
    assert len(read_report(snapshot / "results.csv")) == 4


@pytest.mark.parametrize("problem", ["duplicate", "count", "parent", "member", "sha"])
def test_invalid_manifest_precedes_checkpoint_creation(dataset, problem):
    _, manifest, rows, state = dataset
    if problem == "duplicate":
        rows.append(rows[0])
    elif problem == "parent":
        rows[0]["parent_sha256"] = "f" * 64
    elif problem == "member":
        rows[0]["zip_member"] = "../elsewhere.exe"
    elif problem == "sha":
        rows[0]["sha256"] = "not-a-sha"
    write_manifest(manifest, rows)
    with pytest.raises(ValueError):
        run(dataset, expected_count=57293 if problem == "count" else None)
    assert not state.exists()


def test_unknown_transfer_size_is_explicit(dataset):
    _, manifest, rows, _ = dataset
    for row in rows:
        row.pop("file_size")
    write_manifest(manifest, rows)
    summary, snapshot = run(dataset, batch_size=0)
    assert summary["next_batch_count"] == summary["next_batch_unknown_sizes"] == 1
    assert read_report(snapshot / "next_batch.csv")[0]["declared_file_size"] == ""


def test_cli_batch_mode_and_legacy_validation(dataset):
    root, manifest, _, state = dataset
    repo = Path(__file__).resolve().parents[1]
    command = [sys.executable, "-B", "-m", "byteplot", "audit-pe",
               "--manifest", str(manifest), "--binary-root", str(root),
               "--state-dir", str(state), "--batch-size", "0", "--expected-count", "3"]
    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    result = subprocess.run(command, cwd=repo, env=environment, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    resumed = subprocess.run(command + ["--resume", "--export"], cwd=repo, env=environment,
                             capture_output=True, text=True)
    assert resumed.returncode == 0, resumed.stderr
    invalid = subprocess.run(
        [sys.executable, "-B", "-m", "byteplot", "audit-pe", "--manifest", str(manifest),
         "--binary-root", str(root), "--out", str(state.parent / "legacy.csv"), "--resume"],
        cwd=repo, env=environment, capture_output=True, text=True)
    assert invalid.returncode == 2 and "require --state-dir" in invalid.stderr
