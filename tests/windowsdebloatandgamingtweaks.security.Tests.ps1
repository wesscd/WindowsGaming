Describe "windowsdebloatandgamingtweaks.ps1 security checks" {
  BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot "..\windowsdebloatandgamingtweaks.ps1"
    $content = Get-Content -Path $scriptPath -Raw
  }

  It "does not use Invoke-Expression in the main script" {
    $content | Should -Not -Match "(?i)\bInvoke-Expression\b"
  }

  It "does not use WebClient.DownloadString in the main script" {
    $content | Should -Not -Match "(?i)DownloadString\s*\("
  }
}

