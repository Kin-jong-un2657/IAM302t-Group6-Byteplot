import json
import subprocess

from byteplot.engine import TrainConfig
from byteplot.experiments import run_suite
from byteplot.io import read_csv, sha256
from byteplot.representation import prepare
from byteplot.synthetic import make_synthetic
from byteplot.vm_tools import build_variants, index_originals


def test_vm_wrappers_only_call_tools_and_preserve_originals(tmp_path, monkeypatch):
    benign, malware = tmp_path / 'benign', tmp_path / 'malware'
    benign.mkdir(); malware.mkdir()
    originals = [b'MZ-benign-fixture', b'MZ-malware-fixture-not-executable']
    (benign / 'a.bin').write_bytes(originals[0])
    (malware / 'b.bin').write_bytes(originals[1])
    commands = []

    def fake_tool(command, timeout=120):
        commands.append(command)
        if command[0] == 'diec':
            detection = {'type': 'Packer', 'name': 'UPX'} if str(command[-1]).endswith('_V1.bin') else {'type': 'Compiler', 'name': 'MSVC'}
            return subprocess.CompletedProcess(command, 0, json.dumps({'detects': [{'values': [detection]}]}), '')
        assert command[0] == 'upx'
        from pathlib import Path
        source = Path(command[-1]).read_bytes()
        output = Path(command[command.index('-o') + 1])
        output.write_bytes(source.removeprefix(b'MOCK_PACKED:') if '-d' in command else b'MOCK_PACKED:' + source)
        return subprocess.CompletedProcess(command, 0, 'mock success', '')

    monkeypatch.setattr('byteplot.vm_tools.run_tool', fake_tool)
    manifest = index_originals(benign, malware, tmp_path / 'index', 'diec')
    variants = build_variants(manifest, tmp_path / 'variants', 'upx', 'diec')
    rows = read_csv(variants)
    assert len(rows) == 6 and all(r['status'] == 'ok' for r in rows)
    assert all(command[0] in ('diec', 'upx') for command in commands)
    assert (benign / 'a.bin').read_bytes() == originals[0]
    for row in rows:
        if row['variant'] == 'V1u':
            assert row['sha256'] == row['parent_sha256']


def test_e5_multiple_seeds_never_select_on_v2(tmp_path):
    raw = make_synthetic(tmp_path / 'raw', parents_per_class=6)
    manifest = prepare(raw, tmp_path / 'prepared', height=32, width=32)
    out = tmp_path / 'runs'
    report = run_suite(manifest, out, TrainConfig(epochs=1, bootstrap=2, threads=1),
                       seeds=[17, 37], fractions=[1.0], experiments=['E5'])
    assert 'SYNTHETIC DEMO ONLY' in report.read_text(encoding='utf-8')
    validations = list((out / 'E5').glob('*/selected_val.csv'))
    assert len(validations) == 8
    for path in validations:
        rows = read_csv(path)
        assert {r['variant'] for r in rows} == {'V1'}
        assert {r['split'] for r in rows} == {'val'}
    assert len(json.loads((out / 'comparisons.json').read_text(encoding='utf-8'))) == 4
    assert json.loads((out / 'skipped.json').read_text(encoding='utf-8')) == []
