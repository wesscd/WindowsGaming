Describe "windowsdebloatandgamingtweaks.ps1 structure checks" {
  It "has no duplicate function names" {
    $scriptPath = Join-Path $PSScriptRoot "..\windowsdebloatandgamingtweaks.ps1"
    $matches = Select-String -Path $scriptPath -Pattern '^(function|Function)\s+([A-Za-z0-9_\-]+)'

    $names = foreach ($m in $matches) {
      $m.Matches[0].Groups[2].Value
    }

    $duplicates = $names | Group-Object | Where-Object { $_.Count -gt 1 }
    $duplicates.Count | Should -Be 0
  }
}

