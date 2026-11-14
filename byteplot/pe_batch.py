"""Durable, offline batch orchestration around the existing per-file PE audit."""

from contextlib import contextmanager
import csv
import hashlib
import io
import json
import math
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import uuid

import pefile

from . import pe_audit as single


SCHEMA_VERSION = 1
GIB = 1024 ** 3


def _load_manifest(path, sha_column, expected_count):
    content = Path(path).read_bytes()
    reader = csv.DictReader(io.StringIO(content.decode("utf-8-sig"), newline=""))
    fields = reader.fieldnames or []
    if len(fields) != len(set(fields)) or sha_column not in fields:
        raise ValueError("Manifest requires unique column names and the selected SHA column.")
    if set(fields) & set(single.AUDIT_FIELDS):
        raise ValueError("Use the original verified manifest, not a previous audit report.")
    rows, seen = [], set()
    for index, source in enumerate(reader, 1):
        if None in source or any(value is None for value in source.values()):
            raise ValueError(f"Malformed manifest record {index}.")
        sha = source[sha_column]
        if len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha) or sha in seen:
            raise ValueError(f"Invalid or duplicate original SHA at record {index}.")
        seen.add(sha)
        member = f"altered/{sha}.exe"
        if source.get("parent_sha256", sha) != sha:
            raise ValueError(f"V0 parent differs from original SHA at record {index}.")
        if source.get("zip_member", member) != member:
            raise ValueError(f"zip_member does not match altered/<sha>.exe at record {index}.")
        if source.get("variant", "V0") != "V0":
            raise ValueError(f"Expected a V0 manifest at record {index}.")
        rows.append(dict(source, parent_sha256=sha, zip_member=member))
    if expected_count is not None and len(rows) != expected_count:
        raise ValueError(f"Expected {expected_count} manifest records, found {len(rows)}.")
    for field in ("parent_sha256", "zip_member"):
        if field not in fields:
            fields.append(field)
    return rows, fields, hashlib.sha256(content).hexdigest()


@contextmanager
def _state_lock(directory):
    # OS locks disappear on process death: no unsafe stale-lock deletion is needed.
    with (directory / ".audit.lock").open("a+b") as handle:
        if handle.seek(0, os.SEEK_END) == 0:
            handle.write(b"\0")
            handle.flush()
        handle.seek(0)
        locked = False
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            locked = True
            yield
        except OSError as exc:
            if not locked:
                raise ValueError("Checkpoint is already in use, or its lock is unavailable.") from exc
            raise
        finally:
            if locked:
                handle.seek(0)
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(handle, fcntl.LOCK_UN)


def _open_checkpoint(directory, config, resume):
    path = directory / "checkpoint.sqlite3"
    if resume and not path.is_file():
        raise ValueError("No initialized checkpoint to resume; choose a new state directory.")
    db = sqlite3.connect(path, timeout=0)
    try:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        if resume:
            if db.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise ValueError("Checkpoint integrity check failed; preserve it for recovery.")
            stored = json.loads(db.execute("SELECT config FROM metadata").fetchone()[0])
            if stored != config:
                raise ValueError("Resume manifest/settings/audit code/tool version changed; use the original settings.")
        else:
            with db:
                db.execute("CREATE TABLE metadata (config TEXT NOT NULL)")
                db.execute("INSERT INTO metadata VALUES (?)", (single._json(config),))
                db.execute(
                    "CREATE TABLE results (row_index INTEGER PRIMARY KEY, "
                    "source_sha256 TEXT UNIQUE NOT NULL, batch_id TEXT NOT NULL, result_json TEXT NOT NULL)"
                )
        return db
    except BaseException:
        db.close()
        raise


def _declared_size(row):
    try:
        size = int(row.get("file_size", ""))
        return size if size >= 0 else None
    except ValueError:
        return None


def _next_batch(rows, completed, batch_size, max_bytes):
    plan, known_bytes, unknown, oversized = [], 0, 0, 0
    for index, row in enumerate(rows, 1):
        if index in completed:
            continue
        size = _declared_size(row)
        if size is not None and size > max_bytes:
            oversized += 1
            continue
        if len(plan) >= batch_size:
            continue
        if size is not None and known_bytes + size > max_bytes:
            continue
        # One unknown-size candidate per plan; its transfer size is not guaranteed.
        if size is None and plan:
            continue
        if unknown:
            continue
        plan.append(dict(audit_row=index, original_sha256=row["parent_sha256"],
                         zip_member=row["zip_member"],
                         declared_file_size=size if size is not None else ""))
        if size is None:
            unknown += 1
        else:
            known_bytes += size
    return plan, known_bytes, unknown, oversized


def _write_csv(path, fields, rows):
    with path.open("x", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
        handle.flush()
        os.fsync(handle.fileno())


def _records(db, batch_id=None):
    query = "SELECT result_json FROM results"
    args = ()
    if batch_id is not None:
        query += " WHERE batch_id=?"
        args = (batch_id,)
    for record, in db.execute(query + " ORDER BY row_index", args):
        yield json.loads(record)


def _snapshot(db, directory, rows, fields, config, batch_id, plan_size, max_bytes,
              export, stop_reason, seen_missing, seen_oversize):
    from collections import Counter

    completed = {index for index, in db.execute("SELECT row_index FROM results")}
    pe_counts, die_counts, tool_counts, file_counts = Counter(), Counter(), Counter(), Counter()
    read_count = truncated = no_warnings = 0
    for record in _records(db):
        pe_counts[record["pe_status"]] += 1
        die_counts[record["die_status"]] += 1
        tool_counts[record["die_tool_status"]] += 1
        file_counts[record["file_status"]] += 1
        if record["file_status"] == "read":
            read_count += 1
            truncated += int(record["truncated"] or 0)
        if (record["pe_status"] == "parsed" and not json.loads(record["parse_warnings"])
                and not json.loads(record["structure_warnings"])):
            no_warnings += 1
    plan, estimated, unknown, oversized = _next_batch(rows, completed, plan_size, max_bytes)
    batch_count = db.execute("SELECT count(*) FROM results WHERE batch_id=?", (batch_id,)).fetchone()[0]
    summary = {
        "schema_version": SCHEMA_VERSION, "manifest_sha256": config["manifest_sha256"],
        "manifest_records": len(rows), "completed": len(completed),
        "pending": len(rows) - len(completed), "dataset_complete": len(completed) == len(rows),
        "new_results_this_invocation": batch_count, "stop_reason": stop_reason,
        "pe_parsed": pe_counts["parsed"], "pe_parse_errors": pe_counts["parse_error"],
        "pe_parsed_without_warnings": no_warnings, "pe_status_counts": dict(pe_counts),
        "file_status_counts": dict(file_counts),
        "die_counts": {key: die_counts[key] for key in ("packed", "clean", "unknown")},
        "die_tool_status_counts": dict(tool_counts),
        "files_read": read_count, "truncated_files": truncated,
        "truncation_rate_among_files_read": truncated / read_count if read_count else None,
        "missing_seen_this_invocation": seen_missing,
        "over_budget_seen_this_invocation": seen_oversize,
        "next_batch_count": len(plan), "next_batch_known_bytes": estimated,
        "next_batch_unknown_sizes": unknown, "oversized_pending": oversized,
        "binary_root_free_bytes": shutil.disk_usage(config["binary_root"]).free,
        "state_free_bytes": shutil.disk_usage(directory).free,
        "settings": config,
    }
    exports = directory / "snapshots"
    exports.mkdir(exist_ok=True)
    temporary = exports / (".partial-" + batch_id)
    temporary.mkdir()
    _write_csv(temporary / "batch.csv", fields + list(single.AUDIT_FIELDS), _records(db, batch_id))
    _write_csv(temporary / "next_batch.csv",
               ["audit_row", "original_sha256", "zip_member", "declared_file_size"], plan)
    if export:
        _write_csv(temporary / "results.csv", fields + list(single.AUDIT_FIELDS), _records(db))
    with (temporary / "summary.json").open("x", encoding="utf-8") as handle:
        handle.write(json.dumps(summary, indent=2, ensure_ascii=False, allow_nan=False) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    target = exports / batch_id
    temporary.rename(target)
    if os.name != "nt":
        descriptor = os.open(exports, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    print(f"Checkpoint: {len(completed)}/{len(rows)}; pending={summary['pending']}; "
          f"snapshot={target}; stop={stop_reason}", flush=True)
    return summary, target


def _failed_record(source, index, manifest_hash, error):
    record = dict(source)
    record.update({field: "" for field in single.AUDIT_FIELDS})
    record.update(audit_row=index, manifest_sha256=manifest_hash, file_status="audit_error",
                  pe_status="not_attempted", error=f"{type(error).__name__}: {error}",
                  die_status="unknown", die_tool_status="not_run", parse_warnings="[]",
                  structure_warnings="[]", sections="[]")
    return record


def audit_pe_batches(manifest, binary_root, state_dir, *, resume=False, batch_size=256,
                     max_batch_bytes=4 * GIB, min_free_bytes=5 * GIB, export=False,
                     sha_column="sha256", expected_count=None, height=256, width=256,
                     die=None, timeout=120.0, die_db_id=""):
    """Audit only staged candidates; SQLite commits each result before advancing."""
    if (batch_size < 0 or max_batch_bytes <= 0 or min_free_bytes < 0 or height < 8
            or width < 8 or not math.isfinite(timeout) or timeout <= 0):
        raise ValueError("Invalid batch limits, dimensions or timeout.")
    root, directory = Path(binary_root).resolve(), Path(state_dir).resolve()
    if not root.is_dir() or directory.is_relative_to(root):
        raise ValueError("binary-root must exist and state-dir must be outside it.")
    if resume:
        if not directory.is_dir():
            raise ValueError("State directory does not exist; omit --resume for a new audit.")
    elif directory.exists():
        raise FileExistsError("State directory exists; use --resume or a new directory.")
    rows, fields, manifest_hash = _load_manifest(manifest, sha_column, expected_count)
    if not resume:
        directory.mkdir(parents=True, exist_ok=False)
    with _state_lock(directory):
        metadata, setup_error = single._die_setup(die, root, timeout)
        config = {
            "schema_version": SCHEMA_VERSION, "manifest_sha256": manifest_hash,
            "manifest_records": len(rows), "binary_root": str(root), "sha_column": sha_column,
            "height": height, "width": width, "timeout": timeout,
            "die_enabled": bool(die), "die_db_id": die_db_id, **metadata,
            "pefile_version": pefile.__version__,
            "audit_code_sha256": hashlib.sha256(Path(single.__file__).read_bytes()).hexdigest(),
            "batch_code_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        }
        try:
            db = _open_checkpoint(directory, config, resume)
            try:
                completed = {index for index, in db.execute("SELECT row_index FROM results")}
                batch_id = uuid.uuid4().hex
                processed = consumed = seen_missing = seen_oversize = 0
                reason = "inventory_exhausted"
                try:
                    for index, source in enumerate(rows, 1):
                        if processed >= batch_size:
                            reason = "plan_only" if batch_size == 0 else "batch_limit"
                            break
                        if index in completed:
                            continue
                        if min(shutil.disk_usage(root).free, shutil.disk_usage(directory).free) < min_free_bytes:
                            reason = "low_disk_space"
                            break
                        failure = None
                        try:
                            path = single._sample_path(root, source["zip_member"])
                            info = path.stat()
                            if not stat.S_ISREG(info.st_mode):
                                failure = ValueError("Candidate is not a regular file.")
                            size = info.st_size
                        except FileNotFoundError:
                            seen_missing += 1
                            continue  # Absent offline batches remain pending, never terminal.
                        except (OSError, ValueError) as exc:
                            size, failure = 0, exc
                        if size > max_batch_bytes - consumed:
                            seen_oversize += 1
                            continue
                        if failure is not None:
                            result = _failed_record(source, index, manifest_hash, failure)
                        else:
                            try:
                                result = single._audit_row(
                                    source, index, root, "zip_member", height * width,
                                    height, width, manifest_hash, die, metadata,
                                    setup_error, timeout, die_db_id,
                                )
                            except Exception as exc:
                                result = _failed_record(source, index, manifest_hash, exc)
                            # A file removed between inventory and read must be retried later.
                            if result["file_status"] == "missing":
                                seen_missing += 1
                                continue
                        with db:
                            db.execute("INSERT INTO results VALUES (?, ?, ?, ?)",
                                       (index, source["parent_sha256"], batch_id, single._json(result)))
                        completed.add(index)
                        processed += 1
                        consumed += size
                        print(f"Committed {len(completed)}/{len(rows)}: record {index} "
                              f"PE={result['pe_status']}", flush=True)
                except KeyboardInterrupt:
                    reason = "interrupted"
                    _snapshot(db, directory, rows, fields, config, batch_id, batch_size or 256,
                              max_batch_bytes, export, reason, seen_missing, seen_oversize)
                    raise
                return _snapshot(db, directory, rows, fields, config, batch_id, batch_size or 256,
                                 max_batch_bytes, export, reason, seen_missing, seen_oversize)
            finally:
                db.close()
        except sqlite3.Error as exc:
            raise ValueError(f"Checkpoint error; preserve state and resume after fixing storage: {exc}") from exc
