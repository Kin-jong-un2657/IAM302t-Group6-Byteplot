import struct
from dataclasses import replace

import numpy as np
import pytest
import torch

from byteplot.engine import TrainConfig, fit_classifier, fit_probe, predict_checkpoint
from byteplot.io import assign_splits, load_prepared, select_rows, validate_rows, write_csv
from byteplot.metrics import bootstrap_f1, mcnemar, paired_flips, wilson
from byteplot.models import masked_mse
from byteplot.representation import encode, entropy_map, pe_regions, prepare
from byteplot.synthetic import make_synthetic
from byteplot.vm_tools import interpret_die


def test_entropy_known_values_and_edges():
    assert np.all(entropy_map(b'\x00' * 300) == 0)
    np.testing.assert_allclose(entropy_map(bytes(range(256))), 8)
    assert np.isfinite(entropy_map(bytes(range(256)) + b'abc')).all()
    assert entropy_map(b'').size == 0
    with pytest.raises(ValueError):
        entropy_map(b'abc', window=10, step=11)


def test_offset_alignment_and_no_padding_in_entropy():
    data = bytes(range(256))
    x, mask, info = encode(data, height=32, width=16, synthetic=True)
    np.testing.assert_allclose(x[0].ravel()[:256], np.arange(256) / 255)
    np.testing.assert_allclose(x[1].ravel()[:256], 1)
    assert not x[:, 16:, :].any()
    assert mask.sum() == 256 and info['padding_fraction'] == 0.5


def test_real_pe_region_offsets():
    # Non-executed PE header fixture with one section and trailing overlay.
    data = bytearray(1100)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 0x3c, 0x80)
    data[0x80:0x84] = b'PE\x00\x00'
    struct.pack_into('<HHIIIHH', data, 0x84, 0x14c, 1, 0, 0, 0, 224, 2)
    optional = 0x98
    struct.pack_into('<H', data, optional, 0x10b)
    struct.pack_into('<I', data, optional + 16, 0x1000)
    struct.pack_into('<I', data, optional + 28, 0x400000)
    struct.pack_into('<II', data, optional + 32, 0x1000, 0x200)
    struct.pack_into('<II', data, optional + 56, 0x2000, 0x200)
    struct.pack_into('<I', data, optional + 92, 16)
    section = optional + 224
    struct.pack_into('<8sIIIIIIHHI', data, section, b'UPX1', 512, 0x1000, 512, 512, 0, 0, 0, 0, 0x60000020)
    regions, info = pe_regions(bytes(data), len(data))
    assert np.all(regions[:512] == .25)
    assert np.all(regions[512:1024] == .75)
    assert np.all(regions[1024:] == 1)
    assert info['sections'] == 1 and info['stub_heuristic_sections'] == 'upx1'


def parent_rows():
    return [dict(parent_sha256=f'{label * 100 + i:064x}', label=str(label), variant=variant)
            for label in (0, 1) for i in range(1, 21) for variant in ('V0', 'V1')]


def test_group_split_and_nested_subsets():
    rows = assign_splits(parent_rows(), seed=17)
    validate_rows(rows, require_split=True)
    for split in ('train', 'val', 'test'):
        assert {r['label'] for r in rows if r['split'] == split} == {'0', '1'}
    subset = lambda f: {r['parent_sha256'] for r in select_rows(rows, 'train', ['V0', 'V1'], f)}
    assert subset(.1) <= subset(.25) <= subset(.5) <= subset(1)
    assert assign_splits(parent_rows(), seed=17) == rows


def test_reject_leakage_hash_conflicts_and_label_conflicts():
    rows = assign_splits(parent_rows())
    rows[1]['split'] = 'test' if rows[0]['split'] != 'test' else 'train'
    with pytest.raises(ValueError, match='leakage'):
        validate_rows(rows, True)
    rows = parent_rows()
    rows[0]['sha256'] = rows[2]['sha256'] = 'a' * 64
    with pytest.raises(ValueError, match='Identical bytes'):
        validate_rows(rows)


def test_e4_balance_and_rare_condition_keep_test_fixed():
    rows = assign_splits(parent_rows())
    balanced = select_rows(rows, 'train', ['V0', 'V1'], balanced_pairs=True)
    counts = [sum(int(r['label']) == label and r['variant'] == v for r in balanced)
              for label in (0, 1) for v in ('V0', 'V1')]
    assert len(set(counts)) == 1
    rare = select_rows(rows, 'train', ['V0', 'V1'], benign_packed_keep=.1, balanced_pairs=True)
    assert len(rare) < len(balanced)
    assert {r['parent_sha256'] for r in balanced} == {r['parent_sha256'] for r in rare}


def test_metrics_pairs_and_exact_mcnemar():
    a = [dict(parent_sha256=str(i), variant='V1', label=str(y), prediction=str(p))
         for i, (y, p) in enumerate([(0, 0), (0, 1), (1, 1), (1, 0)])]
    b = [dict(r, prediction=r['label']) for r in a]
    result = mcnemar(a, b)
    assert result['a_wrong_b_correct'] == 2 and result['pvalue_exact'] == .5
    with pytest.raises(ValueError):
        mcnemar(a, b[:-1])
    originals = [dict(r, variant='V0', prediction=r['label']) for r in a]
    flips = paired_flips(originals + a)
    assert flips['correct_to_wrong'] == 2 and flips['flip_rate_all_pairs'] == .5
    assert wilson(0, 0) is None
    assert wilson(0, 10)[1] > 0
    assert bootstrap_f1(b, 20) == [1, 1]


def test_masked_loss_ignores_padding():
    pred = torch.tensor([[[[1., 100.]]]])
    target = torch.zeros_like(pred)
    mask = torch.tensor([[[[1., 0.]]]])
    assert masked_mse(pred, target, mask).item() == 1


def test_die_never_treats_unknown_format_as_clean():
    assert interpret_die({'error': 'failed'})[0] == 'unknown'
    assert interpret_die({'detects': [{'values': [{'type': 'Packer', 'name': 'UPX'}]}]}) == ('packed', 'UPX')
    assert interpret_die({'detects': [{'values': [{'type': 'Compiler', 'name': 'MSVC'}]}]})[0] == 'clean'


def test_end_to_end_training_probe_checkpoint(tmp_path):
    raw = make_synthetic(tmp_path / 'raw', parents_per_class=6)
    manifest = prepare(raw, tmp_path / 'prepared', height=32, width=32)
    rows = load_prepared(manifest)
    validate_rows(rows, True)
    config = TrainConfig(epochs=1, bootstrap=10, batch_size=8, device='cpu', threads=1)
    for channel in ('C1', 'C2', 'C3', 'C4'):
        out = tmp_path / channel
        result = fit_classifier(manifest, out, replace(config, channel=channel))
        assert result['synthetic'] and result['by_variant']['V1']['n'] == 2
        predictions = predict_checkpoint(out / 'checkpoint.pt', manifest, out / 'reloaded.csv')
        from byteplot.io import read_csv
        saved = read_csv(out / 'predictions.csv')
        np.testing.assert_allclose([float(r['probability_malware']) for r in saved],
                                   [r['probability_malware'] for r in predictions], atol=1e-7)
    probe = fit_probe(manifest, tmp_path / 'probe', config)
    assert np.isfinite(probe['all']['mse_normalized'])
    assert probe['all']['valid_pixels'] > 0


def test_preparation_records_bad_input_without_silent_drop(tmp_path):
    raw = make_synthetic(tmp_path / 'raw', parents_per_class=6)
    from byteplot.io import read_csv
    rows = read_csv(raw)
    rows[0]['sha256'] = '0' * 64
    write_csv(raw, rows)
    manifest = prepare(raw, tmp_path / 'prepared', height=32, width=32)
    errors = read_csv(manifest.parent / 'prepare_errors.csv')
    assert len(errors) == 1 and 'SHA-256' in errors[0]['error']
