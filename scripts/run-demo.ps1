param([string]$OutputDir = 'demo-output', [int]$Epochs = 1, [int]$ParentsPerClass = 12)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location -LiteralPath $projectRoot
try {
    if (-not (Test-Path -LiteralPath '.venv/Scripts/python.exe')) {
        throw 'Missing .venv. Run scripts/setup.ps1 first.'
    }
    & '.\.venv\Scripts\python.exe' -m byteplot demo --out $OutputDir --epochs $Epochs --parents-per-class $ParentsPerClass --seed 17
    if ($LASTEXITCODE -ne 0) { throw 'Demo failed. Inspect the error above; use a new output directory when rerunning.' }
} finally {
    Pop-Location
}
