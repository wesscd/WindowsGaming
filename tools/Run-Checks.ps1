param (
  [switch]$SkipPester
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$scriptPath = Join-Path $repoRoot "windowsdebloatandgamingtweaks.ps1"

Write-Host "[1/2] Parsing script: $scriptPath" -ForegroundColor Cyan
$tokens = $null
$errors = $null

$content = Get-Content -Path $scriptPath -Raw -Encoding UTF8
[void][System.Management.Automation.Language.Parser]::ParseInput(
  $content,
  $scriptPath,
  [ref]$tokens,
  [ref]$errors
)

if ($errors.Count -gt 0) {
  Write-Host "Parser errors found:" -ForegroundColor Red
  $errors | ForEach-Object {
    Write-Host "  line $($_.Extent.StartLineNumber): $($_.Message)" -ForegroundColor Red
  }
  exit 1
}

Write-Host "Parser checks passed." -ForegroundColor Green

if ($SkipPester) {
  Write-Host "[2/2] Pester checks skipped." -ForegroundColor Yellow
  exit 0
}

Write-Host "[2/2] Running Pester tests in ./tests" -ForegroundColor Cyan
if (-not (Get-Command Invoke-Pester -ErrorAction SilentlyContinue)) {
  Write-Host "Pester is not installed. Install with: Install-Module Pester -Scope CurrentUser -Force" -ForegroundColor Yellow
  exit 0
}

$result = Invoke-Pester -Path (Join-Path $repoRoot "tests") -PassThru
if ($result.FailedCount -gt 0) {
  exit 1
}

Write-Host "All checks passed." -ForegroundColor Green
