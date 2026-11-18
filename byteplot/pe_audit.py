"""Read-only PE preflight for existing BODMAS candidates; never alter samples."""

import csv
import hashlib
import io
import json
import math
import shutil
import subprocess
from collections import Counter
from pathlib import Path, PurePosixPath, PureWindowsPath

import pefile

from .vm_tools import interpret_die, run_tool


AUDIT_FIELDS = (
    "audit_row", "manifest_sha256", "identity_status", "resolved_path",
    "file_status", "error", "disarmed_sha256", "disarmed_hash_check",
    "actual_size", "size_matches_manifest", "pe_status", "pe_error",
    "parse_warnings", "structure_warnings", "sections", "declared_sections",
    "section_count", "overlay_offset", "overlay_size", "visible_overlay_bytes",
    "machine", "architecture", "subsystem", "pe_format", "disarm_header_hint",
    "certificate_present", "height", "width", "capacity_bytes", "visible_bytes",
    "truncated", "visible_fraction", "padding_fraction", "die_status",
    "die_tool_status", "die_packer", "die_error", "die_exit_code",
    "die_stdout", "die_stderr", "die_executable", "die_version", "die_db_id",
)


def _json(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False)


def _sample_path(root, member):
    # ZIP member names are relative paths, never instructions to extract a ZIP.
    member = member.replace("\\", "/")
    relative = PurePosixPath(member)
    if (not member or relative.is_absolute() or PureWindowsPath(member).drive
            or ".." in relative.parts):
        raise ValueError("Expected a relative sample path without '..' or a drive.")
    path = (root / relative).resolve()
    if not path.is_relative_to(root):
        raise ValueError("Sample path escapes binary root (including symlinks).")
    return path


def _inspect_pe(data, capacity):
    with pefile.PE(data=data, fast_load=True) as pe:
        warnings = []
        sections = []
        for section in pe.sections:
            start, size = int(section.PointerToRawData), int(section.SizeOfRawData)
            end = start + size
            in_bounds = not size or (start <= len(data) and end <= len(data))
            name = section.Name.rstrip(b"\0").decode("utf-8", errors="replace")
            if not in_bounds:
                warnings.append(f"Section {name!r} raw range exceeds file size.")
            if size and start < int(pe.OPTIONAL_HEADER.SizeOfHeaders):
                warnings.append(f"Section {name!r} raw range overlaps headers.")
            sections.append({
                "name": name, "raw_offset": start, "raw_size": size, "raw_end": end,
                "virtual_address": int(section.VirtualAddress),
                "virtual_size": int(section.Misc_VirtualSize),
                "raw_in_bounds": in_bounds,
                "visible_bytes": max(0, min(end, len(data), capacity) - start),
            })
        declared = int(pe.FILE_HEADER.NumberOfSections)
        if declared != len(sections):
            warnings.append("Declared section count differs from parsed section count.")
        overlay = pe.get_overlay_data_start_offset()
        machine = int(pe.FILE_HEADER.Machine)
        subsystem = int(pe.OPTIONAL_HEADER.Subsystem)
        magic = int(pe.OPTIONAL_HEADER.Magic)
        directories = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        return {
            "pe_status": "parsed", "parse_warnings": _json(pe.get_warnings()),
            "structure_warnings": _json(warnings), "sections": _json(sections),
            "declared_sections": declared, "section_count": len(sections),
            "overlay_offset": overlay if overlay is not None else "",
            "overlay_size": len(data) - overlay if overlay is not None else 0,
            "visible_overlay_bytes": max(0, min(len(data), capacity) - overlay)
                if overlay is not None else 0,
            "machine": f"0x{machine:04x}",
            "architecture": pefile.MACHINE_TYPE.get(machine, "UNKNOWN"),
            "subsystem": subsystem,
            "pe_format": {0x10b: "PE32", 0x20b: "PE32+"}.get(magic, "unknown"),
            # A header observation, not proof of disarm, safety or packability.
            "disarm_header_hint": int(machine == 0 and subsystem == 0),
            "certificate_present": int(len(directories) > 4 and directories[4].Size > 0),
        }


def _die_setup(executable, root, timeout):
    if not executable:
        return {"die_executable": "", "die_version": ""}, ""
    located = shutil.which(str(executable))
    tool = Path(located or executable).resolve()
    metadata = {"die_executable": str(tool), "die_version": ""}
    if tool.is_relative_to(root):
        return metadata, "DiE executable must be outside the binary root."
    if not tool.is_file():
        return metadata, "DiE executable not found."
    try:
        version = run_tool([tool, "--version"], timeout=timeout)
        if version.returncode == 0:
            metadata["die_version"] = version.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        pass  # Version probing failure does not invent a scan result.
    return metadata, ""


def _has_die_error(document):
    if isinstance(document, dict):
        return any(
            (str(key).lower() in ("error", "errors") and bool(value))
            or _has_die_error(value) for key, value in document.items()
        )
    if isinstance(document, list):
        return any(_has_die_error(value) for value in document)
    return False


def _scan_die(path, executable, timeout):
    result = {
        "die_status": "unknown", "die_tool_status": "error", "die_packer": "",
        "die_error": "", "die_exit_code": "", "die_stdout": "", "die_stderr": "",
    }
    try:
        scan = run_tool([executable, "-j", path], timeout=timeout)
        result.update(die_exit_code=scan.returncode, die_stdout=scan.stdout,
                      die_stderr=scan.stderr)
        if scan.returncode != 0:
            result["die_error"] = "DiE returned a nonzero exit code."
            return result
        document = json.loads(scan.stdout)
        if not isinstance(document, (dict, list)) or _has_die_error(document):
            result["die_error"] = "DiE JSON contains an error or unsupported root."
            return result
        status, packer = interpret_die(document)
        result.update(die_status=status, die_packer=packer, die_tool_status="ok")
        if status == "unknown":
            result["die_error"] = "No recognized typed detection; packing is unverified."
    except subprocess.TimeoutExpired as exc:
        result.update(die_tool_status="timeout", die_error=str(exc))
        for field, value in (("die_stdout", exc.stdout), ("die_stderr", exc.stderr)):
            result[field] = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value or ""
    except (OSError, ValueError) as exc:
        result["die_error"] = f"{type(exc).__name__}: {exc}"
    return result


def _audit_row(source, index, root, path_column, capacity, height, width,
               manifest_hash, die, die_metadata, die_setup_error, timeout, die_db_id):
    result = dict(source)
    result.update({field: "" for field in AUDIT_FIELDS})
    parent = source.get("parent_sha256") or ""
    result.update(
        audit_row=index, manifest_sha256=manifest_hash,
        identity_status="valid" if len(parent) == 64 and all(c in "0123456789abcdef" for c in parent) else "invalid_parent",
        file_status="not_read", pe_status="not_attempted",
        parse_warnings="[]", structure_warnings="[]", sections="[]",
        height=height, width=width, capacity_bytes=capacity,
        disarmed_hash_check="unverified", die_status="unknown",
        die_tool_status="not_run", die_db_id=die_db_id, **die_metadata,
    )
    try:
        if None in source or any(value is None for value in source.values()):
            raise ValueError("Malformed CSV row: column count differs from the header.")
        path = _sample_path(root, source.get(path_column, ""))
        result["resolved_path"] = str(path)
    except (OSError, ValueError) as exc:
        result.update(file_status="invalid_path", error=str(exc))
        return result
    try:
        data = path.read_bytes()
    except FileNotFoundError as exc:
        result.update(file_status="missing", pe_status="missing_file", error=str(exc))
        return result
    except OSError as exc:
        result.update(file_status="read_error", pe_status="read_error", error=str(exc))
        return result

    digest = hashlib.sha256(data).hexdigest()
    size, visible = len(data), min(len(data), capacity)
    expected = source.get("expected_disarmed_sha256", "")
    result.update(
        file_status="read", disarmed_sha256=digest, actual_size=size,
        disarmed_hash_check=("match" if digest == expected else "mismatch") if expected else "unverified",
        visible_bytes=visible, truncated=int(size > capacity),
        visible_fraction=visible / size if size else 0.0,
        padding_fraction=1 - visible / capacity,
    )
    if source.get("file_size"):
        try:
            result["size_matches_manifest"] = int(int(source["file_size"]) == size)
        except ValueError:
            result["error"] = "Invalid declared file_size."
    try:
        result.update(_inspect_pe(data, capacity))
    except Exception as exc:
        # Preserve one record per candidate, including unsupported/malformed PE.
        result.update(pe_status="parse_error", pe_error=f"{type(exc).__name__}: {exc}")
    if die:
        if die_setup_error:
            result.update(die_tool_status="error", die_error=die_setup_error)
        else:
            result.update(_scan_die(path, die_metadata["die_executable"], timeout))
    return result


def audit_pe(manifest, binary_root, out, height=256, width=256, die=None,
             timeout=120.0, path_column="zip_member", die_db_id=""):
    """Write one CSV record per input row, preserving source identity columns.

    Only 'expected_disarmed_sha256', when explicitly supplied, is an expected
    content digest. Neither source sha256 nor parent_sha256 is reinterpreted.
    """
    if height < 8 or width < 8 or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("Dimensions must be >= 8 and timeout must be finite and positive.")
    root = Path(binary_root).resolve()
    if not root.is_dir():
        raise ValueError("binary-root must be an existing directory.")
    output = Path(out)
    if output.resolve().is_relative_to(root):
        raise ValueError("Output must be outside the binary root.")
    if output.exists() or output.is_symlink():
        raise FileExistsError(f"Output exists: {output}; choose a new --out file.")
    content = Path(manifest).read_bytes()
    reader = csv.DictReader(io.StringIO(content.decode("utf-8-sig"), newline=""))
    fields = reader.fieldnames or []
    if len(set(fields)) != len(fields):
        raise ValueError("Duplicate CSV column names.")
    if not {"parent_sha256", path_column}.issubset(fields):
        raise ValueError(f"CSV requires parent_sha256 and {path_column} columns.")
    if set(fields) & set(AUDIT_FIELDS):
        raise ValueError("Input contains reserved audit columns; use the original candidate CSV.")
    rows = list(reader)
    manifest_hash = hashlib.sha256(content).hexdigest()
    counts = Counter()
    output.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation protects against both existing output and a race.
    with output.open("x", encoding="utf-8", newline="") as handle:
        metadata, setup_error = _die_setup(die, root, timeout)
        writer = csv.DictWriter(handle, fieldnames=fields + list(AUDIT_FIELDS), extrasaction="ignore")
        writer.writeheader()
        for index, source in enumerate(rows, 1):
            result = _audit_row(
                source, index, root, path_column, height * width, height, width,
                manifest_hash, die, metadata, setup_error, timeout, die_db_id,
            )
            writer.writerow(result)
            counts[result["pe_status"]] += 1
    print(f"Audited {len(rows)} candidates -> {output}; PE statuses: {dict(counts)}")
    return output
