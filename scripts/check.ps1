# Compiles the exporter script against the installed Ghidra, then runs fmt, clippy
# and the end-to-end test, which exports a fixture program with headless Ghidra.
#
# Usage, from the repo root: powershell -ExecutionPolicy Bypass -File scripts/check.ps1
# Needs GHIDRA_INSTALL_DIR set to a Ghidra install, e.g. D:\Programs\ghidra_12.1.2_PUBLIC.

$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)

if (-not $env:GHIDRA_INSTALL_DIR -or -not (Test-Path "$env:GHIDRA_INSTALL_DIR\support\analyzeHeadless.bat")) {
    Write-Host 'Set GHIDRA_INSTALL_DIR to a Ghidra installation (the folder containing support\analyzeHeadless.bat).' -ForegroundColor Red
    exit 1
}

function Invoke-Step([string]$name, [scriptblock]$command) {
    Write-Host "==> $name" -ForegroundColor Cyan
    & $command
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAILED: $name" -ForegroundColor Red
        exit $LASTEXITCODE
    }
}

# Every jar of Ghidra's framework and base features: enough to compile a script.
$jars = Get-ChildItem -Recurse -Filter *.jar -Path "$env:GHIDRA_INSTALL_DIR\Ghidra\Framework", "$env:GHIDRA_INSTALL_DIR\Ghidra\Features\Base" |
    ForEach-Object { $_.FullName }
$classes = Join-Path ([System.IO.Path]::GetTempPath()) 'imping-ghidra-classes'
Invoke-Step 'javac' { javac -d $classes -cp ($jars -join ';') '-Xlint:all,-path' -Werror ghidra_scripts\ImpingExport.java }

Invoke-Step 'cargo fmt --check' { cargo fmt --all --check }
Invoke-Step 'clippy' { cargo clippy --workspace --all-targets -- -D warnings }
Invoke-Step 'end-to-end test' { cargo test --workspace -- --nocapture }

Write-Host 'All checks passed.' -ForegroundColor Green
