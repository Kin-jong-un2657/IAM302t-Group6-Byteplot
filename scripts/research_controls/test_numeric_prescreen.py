"""Safe numeric fixtures only. No real binaries, training or network calls."""
import io
import csv
import zipfile
from collections import Counter
import numpy as np
import pytest
import SCREEN_BODMAS_NUMERIC as s


@pytest.mark.parametrize("dtype", [np.float32, np.float64, "<U32", "S32"])
@pytest.mark.parametrize("fortran", [False, True])
def test_stream_exact_columns_without_materializing_matrix(tmp_path, dtype, fortran):
    x = np.zeros((4, 2381), dtype=np.float64)
    x[:, s.COLUMNS] = [[16000,0,6,0],[32000,1,8,0],[64000,0,9,0],[99000,1,14,29]]
    x = x.astype(dtype)
    if fortran: x = np.asfortranarray(x)
    path = tmp_path / "fixture.npz"; np.savez_compressed(path, X=x, y=[1,0,1,0])
    columns, labels, schema = s.selected_columns(path, expected_rows=4)
    np.testing.assert_array_equal(columns, x[:, s.COLUMNS].astype(float))
    assert labels.tolist() == [1,0,1,0]
    assert schema["expanded_array_written_to_disk"] is False
    assert schema["Fortran_order"] == fortran
    assert sorted(p.name for p in tmp_path.iterdir()) == ["fixture.npz"]


@pytest.mark.parametrize("mode", ["shape", "label", "object", "extra", "nonnumeric"])
def test_invalid_numeric_archives_fail_closed(tmp_path, mode):
    x = np.zeros((2,2381)); y = np.array([1,0])
    if mode == "shape": x = x[:,:2380]
    if mode == "label": y = np.array([1,2])
    if mode == "object": x = x.astype(object)
    if mode == "nonnumeric":
        x = x.astype("<U32"); x[0,s.COLUMNS[0]] = "not numeric"
    path = tmp_path / "fixture.npz"; np.savez_compressed(path,X=x,y=y)
    if mode == "extra":
        with zipfile.ZipFile(path,"a") as z: z.writestr("unwanted.txt","fixture")
    with pytest.raises(ValueError): s.selected_columns(path,expected_rows=2)


def test_duplicate_member_rejected(tmp_path):
    p = tmp_path / "duplicate.npz"
    with zipfile.ZipFile(p,"w") as z:
        z.writestr("X.npy",b"fixture"); z.writestr("y.npy",b"fixture")
        with pytest.warns(UserWarning): z.writestr("X.npy",b"second fixture")
    with pytest.raises(ValueError,match="allowlist"): s.selected_columns(p,2)


def test_truncated_npy_is_rejected(tmp_path):
    b = io.BytesIO(); np.save(b,np.zeros((2,2381)),allow_pickle=False)
    labels = io.BytesIO(); np.save(labels,np.array([1,0]),allow_pickle=False)
    p = tmp_path / "truncated.npz"
    with zipfile.ZipFile(p,"w") as z:
        z.writestr("X.npy",b.getvalue()[:-16]);z.writestr("y.npy",labels.getvalue())
    with pytest.raises(ValueError,match="length"): s.selected_columns(p,2)


def metadata_bytes(rows):
    f=io.StringIO();w=csv.DictWriter(f,fieldnames=["sha","timestamp","family"])
    w.writeheader();w.writerows(rows);return f.getvalue().encode()


@pytest.mark.parametrize("mode",["label", "duplicate", "invalid_sha", "length"])
def test_metadata_order_identity_gates(mode):
    rows=[dict(sha="a"*64,timestamp="2019",family="f1"),
          dict(sha="b"*64,timestamp="2019",family="")]
    labels=[1,0]
    if mode=="label":labels=[0,1]
    if mode=="duplicate":rows[1]["sha"]=rows[0]["sha"]
    if mode=="invalid_sha":rows[1]["sha"]="bad"
    if mode=="length":labels=[1]
    with pytest.raises(ValueError):s.metadata_join(metadata_bytes(rows),labels)


def test_exact_size_anchors_and_permutation_failure():
    rows=[dict(sha="a"*64,family="f1"),dict(sha="b"*64,family="f2")]
    anchors=[dict(parent_sha256=r["sha"],sha256=r["sha"],family=r["family"],file_size=n)
             for r,n in zip(rows,[16000,32000])]
    cols=np.array([[16000,0,6,0],[32000,0,6,0]])
    assert s.validate_anchors(rows,cols,anchors,minimum=2)==2
    with pytest.raises(ValueError,match="size/order"):s.validate_anchors(rows,cols[::-1],anchors,minimum=2)
    with pytest.raises(ValueError,match="Insufficient"):s.validate_anchors(rows,cols,anchors,minimum=3)


def test_invalid_source_benign_identity_quarantined_without_reordering_or_repair():
    rows=[dict(sha="a"*64,timestamp="2019",family="f1"),
          dict(sha="VirusShare_source_identifier_not_sha256",timestamp="2019",family="")]
    actual=s.metadata_join(metadata_bytes(rows),[1,0],quarantine_invalid_benign=True)
    assert actual==rows
    with pytest.raises(ValueError):
        s.metadata_join(metadata_bytes(rows),[1,1],quarantine_invalid_benign=True)


def test_eligibility_preserves_parent_never_invents_disarmed_or_clean():
    rows=[dict(sha=f"{i:064x}",family="family") for i in range(6)]
    cols=np.array([[32000,0,6,0],[32000,0,6,0],[32000,0,6,0],
                   [9999999,0,6,0],[32000,0,14,38],[np.nan,0,6,0]])
    disarm={r["sha"]:{"FILE_HEADER.Machine":"332","OPTIONAL_HEADER.Subsystem":"2"} for r in rows}
    disarm[rows[2]["sha"]]["FILE_HEADER.Machine"]="34404"
    chosen,counts=s.eligible(rows,cols,[1]*6,disarm,{rows[1]["sha"]},{(6,0):29})
    assert len(chosen)==1 and sum(counts.values())==5
    assert chosen[0]["parent_sha256"]==rows[0]["sha"]
    assert chosen[0]["disarmed_sha256"]==""
    assert chosen[0]["die_status"]=="unknown"
    assert chosen[0]["training_admitted"]==0
    assert chosen[0]["V0_hash_verification"]=="NOT_PERFORMED"
    with pytest.raises(ValueError,match="missing"):s.eligible(rows,cols,[1]*6,{},set(),{(6,0):29})


def test_selection_family_round_robin_caps_reproducibility():
    rows=[dict(parent_sha256=f"{i:064x}",family=f"family-{i%20}") for i in range(600)]
    selected=s.select(rows,set())
    assert len(selected)==256
    assert len({r["family"] for r in selected})==20
    assert max(Counter(r["family"] for r in selected).values())<=16
    assert selected==s.select(list(reversed(rows)),set())
    with pytest.raises(ValueError):s.select(rows,set(),limit=257)
    with pytest.raises(ValueError):s.select(rows+rows[:1],set())
