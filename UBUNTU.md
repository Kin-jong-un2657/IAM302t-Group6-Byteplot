# Ubuntu / VMware: clean source checkout

This repository contains source code, tests, setup scripts and documentation only.
The CLI, RQ1-RQ4, H1-H4 and E0-E5 recipes are preserved from the working project,
including the report provenance, E4 holdout and Markdown regression fixes.
No original Git directory, environment, dataset, executable sample, checkpoint,
source archive, experiment output, graph output or instructor PDF is included.
`examples/manifest.template.csv` contains column names only.

`readme.md`, `RUNNING.md` and `REVIEW.md` are retained from the working project.
References there to ProjectV1, an existing .venv, drive-download data, instructor
PDFs or historical demo/review outputs describe that original workspace. Those
files and outputs are not part of this checkout. Create a fresh environment and
fresh synthetic outputs as shown below. The old verification results in REVIEW.md
are historical; they do not claim that real malware experiments ran here.

## Install on Ubuntu

Run these commands from the cloned repository directory. Git is required for
cloning; Python 3.10 or newer is required by pyproject.toml.

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install 'torch>=2.4,<3' --index-url https://download.pytorch.org/whl/cpu
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m pytest -q
.venv/bin/python -m byteplot --help
```

Use requirements.txt for this Ubuntu setup. requirements-tested.txt records the
original tested environment and includes a CPU-specific PyTorch version; it is
not a cross-platform lockfile. No environment or dependencies are bundled here.

## Optional synthetic demo

```bash
.venv/bin/python -m byteplot demo --out runs/ubuntu-demo --epochs 1
```

The demo requires no malware samples, DiE, UPX or GPU. Its results are software
checks, not research evidence. Open runs/ubuntu-demo/runs/REPORT.md afterward.
Use a fresh output directory when repeating the demo. To use the separate model
examples in RUNNING.md, replace demo-output/prepared/prepared.csv with the new
runs/ubuntu-demo/prepared/prepared.csv path.

Real-data preparation remains a separate operation in the isolated research VM
with authorized datasets and the tools described in RUNNING.md. No full research
experiment is required to check this source repository.

## Keep the repository clean

.gitignore restricts eligible paths and excludes datasets, PE binaries, archives,
checkpoints, experiment outputs, virtual environments, caches, PDFs and secrets.
It does not inspect file contents. Review every new file before staging it, use
explicit file paths, and inspect git diff --cached before committing. Do not use
git add -f to bypass these exclusions or commit real manifests or credentials.
Keep the GitHub repository private until its contents have been reviewed.
