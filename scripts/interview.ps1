param(
    [ValidateSet('env','audit','metrics','e5','inference','demo','tests')]
    [string]$Mode = 'audit',
    [string]$DemoRoot = 'demo-output',
    [string]$OutputDir = ''
)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$pythonPath = Join-Path $projectRoot '.venv/Scripts/python.exe'
if (-not (Test-Path -LiteralPath $pythonPath)) { throw 'Create this checkout''s .venv first; see RUNNING.md.' }
$env:PYTHONDONTWRITEBYTECODE = '1'
$env:PYTHONNOUSERSITE = '1'
$env:MPLCONFIGDIR = Join-Path $projectRoot '.cache/matplotlib'
New-Item -ItemType Directory -Force -Path $env:MPLCONFIGDIR | Out-Null
Push-Location -LiteralPath $projectRoot
try {
    switch ($Mode) {
        'env' { & $pythonPath -B -c 'import sys, torch; print(sys.version); print(torch.__version__)' }
        'audit' { & $pythonPath -B workspace_tools/verify_artifacts.py audit }
        'e5' { & $pythonPath -B workspace_tools/verify_artifacts.py e5 }
        'metrics' { & $pythonPath -B workspace_tools/verify_artifacts.py metrics --root (Join-Path $DemoRoot 'runs') }
        'tests' { & $pythonPath -B -m pytest -q }
        'demo' {
            if (-not $OutputDir) { $OutputDir = 'demo-' + (Get-Date -Format 'yyyyMMdd-HHmmss') }
            if (Test-Path -LiteralPath $OutputDir) { throw 'Choose a new output directory.' }
            & $pythonPath -B -m byteplot demo --out $OutputDir --parents-per-class 12 --epochs 1 --seed 17
        }
        'inference' {
            if (-not $OutputDir) { $OutputDir = Join-Path $DemoRoot ('inference-' + (Get-Date -Format 'yyyyMMdd-HHmmss')) }
            if (Test-Path -LiteralPath $OutputDir) { throw 'Choose a new output directory.' }
            New-Item -ItemType Directory -Path $OutputDir | Out-Null
            & $pythonPath -B -m byteplot predict --checkpoint (Join-Path $DemoRoot 'runs/E2/C2_standard_f1_seed17/checkpoint.pt') --manifest (Join-Path $DemoRoot 'prepared/prepared.csv') --device cpu --out (Join-Path $OutputDir 'predictions.csv')
            if ($LASTEXITCODE -ne 0) { throw 'Synthetic checkpoint inference failed.' }
            & $pythonPath -B workspace_tools/verify_artifacts.py compare --expected (Join-Path $DemoRoot 'runs/E2/C2_standard_f1_seed17/predictions.csv') --actual (Join-Path $OutputDir 'predictions.csv')
        }
    }
    if ($LASTEXITCODE -ne 0) { throw "$Mode failed with exit code $LASTEXITCODE" }
} finally { Pop-Location }
