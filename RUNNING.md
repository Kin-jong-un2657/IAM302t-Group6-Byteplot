# Running and Reproducing the Software

Run commands from a fresh repository checkout. Python 3.12 and CPU PyTorch are the verified configuration. No existing virtual environment, personal filesystem layout, dataset or checkpoint is assumed.

## Windows / PowerShell

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install torch --index-url https://download.pytorch.org/whl/cpu
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pytest -q
```

Alternatively, with `uv` already installed:

```powershell
powershell -NoProfile -File scripts/setup.ps1
```

`requirements.txt` gives supported dependency ranges; `requirements-tested.txt` records the verified environment. CPU PyTorch uses its separate package index.

## Linux

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install torch --index-url https://download.pytorch.org/whl/cpu
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m pytest -q
```

Linux commands are equivalent usage instructions; the included verification record was produced on Windows. A symlink test may run on a host where it was skipped during Windows verification.

## Synthetic CPU workflow

```powershell
.\.venv\Scripts\python.exe -m byteplot demo --out demo-output --parents-per-class 12 --epochs 1 --seed 17
.\.venv\Scripts\python.exe workspace_tools/verify_artifacts.py metrics --root demo-output/runs
```

Or use the portable PowerShell wrapper:

```powershell
powershell -NoProfile -File scripts/run-demo.ps1 -OutputDir demo-output -Epochs 1 -ParentsPerClass 12
```

The Linux equivalent is:

```bash
.venv/bin/python -m byteplot demo --out demo-output --parents-per-class 12 --epochs 1 --seed 17
.venv/bin/python workspace_tools/verify_artifacts.py metrics --root demo-output/runs
```

The demo generates 24 synthetic parents with four variants each (96 rows), prepares mock channels, runs 17 classifiers and one entropy probe, and exercises E0–E5. Its report is generated at `demo-output/runs/REPORT.md`. Generated output is intentionally absent from Git; use a fresh output directory when rerunning. Synthetic V1/V2 use zlib/XOR, not real UPX/MPRESS, and synthetic PE regions are mocked.

The metric verifier checks 85 total/per-variant groups, including 68 per-variant groups. These are software checks, not real-malware metrics. The demo uses one seed; the published real E5 pilot used three seeds separately.

## Inspect released evidence without model training

```powershell
.\.venv\Scripts\python.exe workspace_tools/verify_artifacts.py audit
.\.venv\Scripts\python.exe workspace_tools/verify_artifacts.py e5
```

The audit check recounts the redacted CSV and verifies its export checksum. The E5 check recomputes Macro-F1/FPR from saved confusion matrices and validates channel means/sample SDs. Neither command reads raw PE bytes, reconstructs private manifests, replays real checkpoints or independently regenerates the saved bootstrap intervals.

The optional `scripts/interview.ps1` runner supports `env`, `audit`, `metrics`, `e5`, `inference`, `demo` and `tests`, using this checkout's `.venv`. It needs no private runtime configuration:

```powershell
powershell -NoProfile -File scripts/interview.ps1 -Mode audit
powershell -NoProfile -File scripts/interview.ps1 -Mode metrics -DemoRoot demo-output
```

## Synthetic checkpoint inference

Generate the demo first, then choose a new prediction filename:

```powershell
.\.venv\Scripts\python.exe -m byteplot predict --checkpoint demo-output/runs/E2/C2_standard_f1_seed17/checkpoint.pt --manifest demo-output/prepared/prepared.csv --device cpu --out demo-output/replayed-predictions.csv
.\.venv\Scripts\python.exe workspace_tools/verify_artifacts.py compare --expected demo-output/runs/E2/C2_standard_f1_seed17/predictions.csv --actual demo-output/replayed-predictions.csv
```

## Real-data research workflow: isolated VM only

Real datasets and packer tools are not included. The CLI supports indexing verified originals, generating UPX V1 and statically unpacked V1u, importing separately created MPRESS V2, preparing channels and running the suite. Keep all related variants in one parent split. V0 must hash to its original parent; disarmed bytes have a separate content hash and must not silently replace V0.

Use `python -m byteplot --help` and each subcommand's `--help` in the authorized VM. The following examples use relative placeholder locations and require private inputs; they are not runnable from a source-only clone:

```bash
.venv/bin/python -m byteplot audit-pe \
  --manifest private/candidates.csv --binary-root private/disarmed \
  --out runs/static-audit.csv --height 256 --width 256

.venv/bin/python -m byteplot suite \
  --manifest private/prepared/prepared.csv --out runs/research-suite \
  --epochs 10 --seeds 17 37 73 --experiments E0 E1 E2 E3 E4 E5
```

`audit-pe` is read-only with respect to sample inputs; an explicitly configured trusted DiE executable can be invoked for static scanning. Batch mode uses `--state-dir`, immutable exports, resume checkpoints and resource limits; consult its CLI help. Audit output must stay outside the binary root. Full audit output contains identities and must remain private; only reviewed redacted exports belong in this repository.

For E5, train and select checkpoints on V1 only; evaluate V2 afterward. The included pilot protocol is fixed in [E5_STATUS.json](results_e5_summary/E5_STATUS.json). The PE-region encoder's packer-name heuristic is not byte-accurate stub ground truth. A valid-byte mask controls pooling/probe loss but convolutions still see padding boundaries.

The auxiliary [metadata controls](scripts/research_controls/README.md) are separate from the core CLI and require historical private kits/checksums. They do not establish a completed matched cohort.
