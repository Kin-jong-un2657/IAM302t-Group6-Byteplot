param([string]$PythonVersion = '3.12')
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location -LiteralPath $projectRoot
try {
    if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
        throw 'Install uv first, or follow the pip instructions in RUNNING.md.'
    }
    if (-not (Test-Path -LiteralPath '.venv/Scripts/python.exe')) {
        & uv --cache-dir '.cache/uv' venv --python $PythonVersion .venv
        if ($LASTEXITCODE -ne 0) { throw 'Could not create .venv.' }
    }
    & uv --cache-dir '.cache/uv' pip install --python '.venv/Scripts/python.exe' 'torch>=2.4,<3' --index-url 'https://download.pytorch.org/whl/cpu'
    if ($LASTEXITCODE -ne 0) { throw 'Could not install CPU PyTorch.' }
    & uv --cache-dir '.cache/uv' pip install --python '.venv/Scripts/python.exe' -r requirements.txt
    if ($LASTEXITCODE -ne 0) { throw 'Could not install dependencies.' }
    Write-Output 'Ready. Run: .\.venv\Scripts\python.exe -m byteplot demo'
} finally {
    Pop-Location
}
