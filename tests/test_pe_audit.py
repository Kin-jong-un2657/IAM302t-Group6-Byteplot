"""Safe in-memory PE headers and mocked tools; no real malware fixtures."""

import csv
import hashlib
import json
import struct
import subprocess

import pytest

from byteplot.pe_audit import _inspect_pe, audit_pe


def pe_header(machine=0, subsystem=0, raw_size=512, total_size=1100):
    # Deliberately non-executed header/zero-byte fixture, with no program payload.
    data = bytearray(total_size)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3c, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, machine, 1, 0, 0, 0, 224, 2)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x10b)
    struct.pack_into("<I", data, optional + 16, 0x1000)
    struct.pack_into("<I", data, optional + 28, 0x400000)
    struct.pack_into("<II", data, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", data, optional + 56, 0x2000, 0x200)
    struct.pack_into("<H", data, optional + 68, subsystem)
    struct.pack_into("<I", data, optional + 92, 16)
    struct.pack_into("<8sIIIIIIHHI", data, optional + 224, b".text", 512,
                     0x1000, raw_size, 512, 0, 0, 0, 0, 0x40000040)
    return bytes(data)


def write_manifest(path, rows):
    fields = list(dict.fromkeys(key for row in rows for key in row))
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def read_report(path):
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def candidate(member="altered/sample.exe", **extra):
    # Same columns as the existing 10-row BODMAS CSV; no dataset IDs bundled.
    return dict(sha256="a" * 64, parent_sha256="a" * 64, family="fixture",
                group="malware_unverified", variant="V0", size_group="le_64k",
                file_size="1100", zip_member=member, zip_found="True", **extra)


@pytest.fixture
def sample(tmp_path):
    root = tmp_path / "binary"
    (root / "altered").mkdir(parents=True)
    path = root / "altered/sample.exe"
    path.write_bytes(pe_header())
    manifest = tmp_path / "candidates.csv"
    write_manifest(manifest, [candidate()])
    return root, path, manifest


def test_disarmed_identity_sections_overlay_and_warnings(sample, tmp_path):
    root, path, manifest = sample
    before = path.read_bytes(), manifest.read_bytes()
    report = audit_pe(manifest, root, tmp_path / "out.csv")
    row, = read_report(report)
    assert row["parent_sha256"] == row["sha256"] == "a" * 64
    assert row["disarmed_sha256"] == hashlib.sha256(before[0]).hexdigest()
    assert row["disarmed_sha256"] != row["parent_sha256"]
    assert row["disarmed_hash_check"] == "unverified"
    assert row["manifest_sha256"] == hashlib.sha256(before[1]).hexdigest()
    assert row["group"] == "malware_unverified" and row["pe_status"] == "parsed"
    assert row["machine"] == "0x0000" and row["disarm_header_hint"] == "1"
    assert row["architecture"] == "IMAGE_FILE_MACHINE_UNKNOWN"
    assert row["pe_format"] == "PE32" and row["section_count"] == "1"
    section, = json.loads(row["sections"])
    assert (section["raw_offset"], section["raw_size"], section["raw_end"]) == (512, 512, 1024)
    assert section["raw_in_bounds"] and section["visible_bytes"] == 512
    assert (row["overlay_offset"], row["overlay_size"]) == ("1024", "76")
    assert isinstance(json.loads(row["parse_warnings"]), list)
    assert row["die_status"] == "unknown" and row["die_tool_status"] == "not_run"
    assert (path.read_bytes(), manifest.read_bytes()) == before


def test_machine_and_bounds_are_observations():
    info = _inspect_pe(pe_header(machine=0x14c, subsystem=3), 600)
    assert info["architecture"] == "IMAGE_FILE_MACHINE_I386"
    assert info["disarm_header_hint"] == 0
    assert json.loads(info["sections"])[0]["visible_bytes"] == 88
    assert info["visible_overlay_bytes"] == 0
    bad = _inspect_pe(pe_header(raw_size=4096), 65536)
    assert not json.loads(bad["sections"])[0]["raw_in_bounds"]
    assert json.loads(bad["structure_warnings"])


@pytest.mark.parametrize("size,truncated,visible,padding", [
    (0, 0, 0, 1), (32, 0, 32, .5), (64, 0, 64, 0), (65, 1, 64, 0),
])
def test_truncation_even_when_pe_parse_fails(sample, tmp_path, size, truncated, visible, padding):
    root, path, manifest = sample
    path.write_bytes(b"X" * size)
    report = audit_pe(manifest, root, tmp_path / "out.csv", height=8, width=8)
    row, = read_report(report)
    assert row["pe_status"] == "parse_error"
    assert int(row["truncated"]) == truncated and int(row["visible_bytes"]) == visible
    assert float(row["padding_fraction"]) == padding
    assert float(row["visible_fraction"]) == (visible / size if size else 0)


@pytest.mark.parametrize("expected,check", [("actual", "match"), ("0" * 64, "mismatch")])
def test_only_explicit_disarmed_hash_is_compared(sample, tmp_path, expected, check):
    root, path, manifest = sample
    expected = hashlib.sha256(path.read_bytes()).hexdigest() if expected == "actual" else expected
    write_manifest(manifest, [candidate(expected_disarmed_sha256=expected)])
    row, = read_report(audit_pe(manifest, root, tmp_path / "out.csv"))
    assert row["disarmed_hash_check"] == check
    assert row["parent_sha256"] == "a" * 64


@pytest.mark.parametrize("member", ["../escape.exe", "/absolute.exe", "C:/sample.exe", "C:sample.exe"])
def test_paths_cannot_escape_binary_root(sample, tmp_path, member):
    root, _, manifest = sample
    write_manifest(manifest, [candidate(member)])
    row, = read_report(audit_pe(manifest, root, tmp_path / "out.csv"))
    assert row["file_status"] == "invalid_path" and row["disarmed_sha256"] == ""


def test_symlink_escape_is_reported(sample, tmp_path):
    root, path, manifest = sample
    outside = tmp_path / "outside.exe"
    outside.write_bytes(pe_header())
    link = root / "escape.exe"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("Host cannot create symlinks")
    write_manifest(manifest, [candidate("escape.exe")])
    row, = read_report(audit_pe(manifest, root, tmp_path / "out.csv"))
    assert row["file_status"] == "invalid_path"


@pytest.mark.parametrize("kind", ["existing", "inside_root"])
def test_output_protection_precedes_any_tool_or_sample_read(sample, tmp_path, monkeypatch, kind):
    root, _, manifest = sample
    out = tmp_path / "out.csv" if kind == "existing" else root / "out.csv"
    if kind == "existing":
        out.write_text("KEEP", encoding="utf-8")
    monkeypatch.setattr("byteplot.pe_audit.run_tool", lambda *a, **k: pytest.fail("Tool must not run"))
    with pytest.raises((FileExistsError, ValueError)):
        audit_pe(manifest, root, out, die="diec")
    assert out.read_text() == "KEEP" if kind == "existing" else not out.exists()


@pytest.mark.parametrize("mode,expected,tool_status", [
    ("clean", "clean", "ok"), ("packed", "packed", "ok"),
    ("unknown", "unknown", "ok"), ("invalid_json", "unknown", "error"),
    ("nonzero", "unknown", "error"), ("timeout", "unknown", "timeout"),
    ("json_error", "unknown", "error"), ("launch_error", "unknown", "error"),
])
def test_die_evidence_never_promotes_errors_to_clean(sample, tmp_path, monkeypatch, mode, expected, tool_status):
    root, path, manifest = sample
    tool = tmp_path / "diec"
    tool.write_text("not executable: mock only", encoding="utf-8")
    commands = []

    def fake_tool(command, timeout):
        commands.append(command)
        assert str(command[0]) == str(tool.resolve())
        if command[1] == "--version":
            return subprocess.CompletedProcess(command, 0, "DiE fixture v1", "")
        assert command[1:] == ["-j", path.resolve()]
        if mode == "timeout":
            raise subprocess.TimeoutExpired(command, timeout, output=b"partial", stderr=b"timed out")
        if mode == "launch_error":
            raise OSError("not available")
        body = {"detects": [{"values": [{"type": "Packer" if mode == "packed" else "Compiler", "name": "UPX" if mode == "packed" else "fixture"}]}]}
        if mode == "unknown":
            body = {"unexpected": True}
        if mode == "json_error":
            body["error"] = "scan failed"
        stdout = "not JSON" if mode == "invalid_json" else json.dumps(body)
        return subprocess.CompletedProcess(command, 1 if mode == "nonzero" else 0, stdout, "diagnostic\nline2")

    monkeypatch.setattr("byteplot.pe_audit.run_tool", fake_tool)
    report = audit_pe(manifest, root, tmp_path / "out.csv", die=tool, die_db_id="fixture-db")
    row, = read_report(report)
    assert row["die_status"] == expected and row["die_tool_status"] == tool_status
    assert row["die_version"] == "DiE fixture v1" and row["die_db_id"] == "fixture-db"
    assert len(commands) == 2
    if mode == "packed":
        assert row["die_packer"] == "UPX"
    if mode == "timeout":
        assert row["die_stdout"] == "partial" and row["die_stderr"] == "timed out"


def test_binary_cannot_be_selected_as_die_executable(sample, tmp_path, monkeypatch):
    root, path, manifest = sample
    monkeypatch.setattr("byteplot.pe_audit.run_tool", lambda *a, **k: pytest.fail("Sample must never run"))
    row, = read_report(audit_pe(manifest, root, tmp_path / "out.csv", die=path))
    assert row["die_status"] == "unknown" and row["die_tool_status"] == "error"
    assert "outside" in row["die_error"]


@pytest.mark.parametrize("height,width,timeout", [(0, 256, 1), (8, 7, 1), (8, 8, 0), (8, 8, float("nan"))])
def test_invalid_options_do_not_create_output(sample, tmp_path, height, width, timeout):
    root, _, manifest = sample
    out = tmp_path / "out.csv"
    with pytest.raises(ValueError):
        audit_pe(manifest, root, out, height, width, timeout=timeout)
    assert not out.exists()


def test_parser_warnings_are_preserved_verbatim(sample, tmp_path, monkeypatch):
    import byteplot.pe_audit as module
    monkeypatch.setattr(module.pefile.PE, "get_warnings",
                        lambda self: ["fixture warning: malformed field"])
    root, _, manifest = sample
    row, = read_report(audit_pe(manifest, root, tmp_path / "out.csv"))
    assert json.loads(row["parse_warnings"]) == ["fixture warning: malformed field"]


def test_unreadable_candidate_still_has_one_record(sample, tmp_path, monkeypatch):
    from pathlib import Path
    root, path, manifest = sample
    original = Path.read_bytes

    def read_bytes(self):
        if self == path:
            raise PermissionError("fixture read denied")
        return original(self)

    monkeypatch.setattr(Path, "read_bytes", read_bytes)
    row, = read_report(audit_pe(manifest, root, tmp_path / "out.csv"))
    assert row["file_status"] == row["pe_status"] == "read_error"
    assert "fixture read denied" in row["error"] and row["disarmed_sha256"] == ""


def test_exclusive_output_creation_rejects_a_race(sample, tmp_path, monkeypatch):
    from pathlib import Path
    root, _, manifest = sample
    out = tmp_path / "race.csv"
    original = Path.open

    def racing_open(self, mode="r", *args, **kwargs):
        if self == out and mode == "x":
            with original(self, "w", encoding="utf-8") as handle:
                handle.write("created by another writer")
        return original(self, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", racing_open)
    with pytest.raises(FileExistsError):
        audit_pe(manifest, root, out)
    assert out.read_text() == "created by another writer"


def test_alternate_path_column_and_portable_member_separators(sample, tmp_path):
    root, _, manifest = sample
    write_manifest(manifest, [dict(parent_sha256="a" * 64, path=r"altered\sample.exe")])
    row, = read_report(audit_pe(manifest, root, tmp_path / "out.csv", path_column="path"))
    assert row["pe_status"] == "parsed" and row["path"] == r"altered\sample.exe"
