Describe "windowsdebloatandgamingtweaks.ps1 syntax" {
  It "parses without PowerShell parser errors" {
    $scriptPath = Join-Path $PSScriptRoot "..\windowsdebloatandgamingtweaks.ps1"
    $tokens = $null
    $errors = $null
    $content = Get-Content -Path $scriptPath -Raw -Encoding UTF8
    [void][System.Management.Automation.Language.Parser]::ParseInput(
      $content,
      $scriptPath,
      [ref]$tokens,
      [ref]$errors
    )

    $errors.Count | Should -Be 0
  }
}
