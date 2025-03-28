# Modules\Debloat.ps1

# Função para escrever texto colorido (se necessário)
function Write-Colored {
  param (
    [string]$Text,
    [ConsoleColor]$Color = 'White'
  )
  Write-Host $Text -ForegroundColor $Color
}

Function DebloatAll {
  Clear-Host
  $Bloatware = @(
    # Aplicativos padrão do Windows 10 e 11
    "*3DBuilder*", "*AppConnector*", "*BingFinance*", "*BingNews*", "*BingSports*", "*BingTranslator*", "*BingWeather*",
    "*GetHelp*", "*Getstarted*", "*Messaging*", "*Microsoft3DViewer*", "*MicrosoftSolitaireCollection*",
    "*MicrosoftPowerBIForWindows*", "*MicrosoftStickyNotes*", "*NetworkSpeedTest*", "*OneNote*", "*Lens*", "*Sway*",
    "*OneConnect*", "*People*", "*Print3D*", "*RemoteDesktop*", "*SkypeApp*", "*Wallet*", "*Whiteboard*",
    "*WindowsAlarms*", "*WindowsFeedbackHub*", "*WindowsMaps*", "*WindowsSoundRecorder*", "*MicrosoftOfficeHub*",
    "*MixedReality.Portal*", "*ScreenSketch*", "*Microsoft.MSPaint*", "Microsoft.549981C3F5F10", "*Advertising.Xaml*",
    "*SolitaireCollection*", "*Clipchamp*", "*MicrosoftTeams*", "*TikTok*",

    # Aplicativos patrocinados ou pré-instalados
    "*EclipseManager*", "*ActiproSoftwareLLC*", "*AdobePhotoshopExpress*", "*Duolingo-LearnLanguagesforFree*",
    "*PandoraMediaInc*", "*CandyCrush*", "*BubbleWitch3Saga*", "*Wunderlist*", "*Flipboard*", "*Twitter*", "*Facebook*",
    "*RoyalRevolt*", "*SpeedTest*", "*Viber*", "*ACGMediaPlayer*", "*Netflix*", "*OneCalendar*", "*LinkedInforWindows*",
    "*HiddenCityMysteryofShadows*", "*Hulu*", "*AutodeskSketchBook*", "*DisneyMagicKingdoms*", "*MarchofEmpires*",
    "*Plex*", "*FarmVille2CountryEscape*", "*CyberLinkMediaSuiteEssentials*", "*DrawboardPDF*", "*Asphalt8Airborne*",
    "*Keeper*", "*SpotifyMusic*", "*WinZipUniversal*", "*XING*", "*Roblox*"
  )

  $errpref = $ErrorActionPreference  # Salva a configuração atual
  $ErrorActionPreference = "SilentlyContinue"

  foreach ($Bloat in $Bloatware) {
    Get-AppxPackage -AllUsers -Name $Bloat | Remove-AppxPackage | Out-Null
    Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat | Remove-AppxProvisionedPackage -Online | Out-Null
    Write-Output "Removendo: $Bloat"
  }

  $ErrorActionPreference = $errpref  # Restaura a configuração anterior
}

Function RemoveBloatRegistry {
  Write-Colored "Removendo chaves de Registro de bloatware..." -Color Yellow
  $bloatKeys = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}", # 3D Objects
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" # App Suggestions
  )
  foreach ($key in $bloatKeys) {
    if (Test-Path $key) {
      Remove-Item -Path $key -Recurse -Force -ErrorAction SilentlyContinue
    }
  }
}

# Desinstala o OneDrive
Function UninstallOneDrive {
  Write-Colored "Desinstalando o OneDrive..." -Color Yellow
  # Mata o processo do OneDrive
  Stop-Process -Name "OneDrive" -Force -ErrorAction SilentlyContinue
  # Executa o desinstalador embutido
  if (Test-Path "$env:SystemRoot\SysWOW64\OneDriveSetup.exe") {
    Start-Process "$env:SystemRoot\SysWOW64\OneDriveSetup.exe" -ArgumentList "/uninstall" -NoNewWindow -Wait
  }
  elseif (Test-Path "$env:SystemRoot\System32\OneDriveSetup.exe") {
    Start-Process "$env:SystemRoot\System32\OneDriveSetup.exe" -ArgumentList "/uninstall" -NoNewWindow -Wait
  }
  # Remove pastas residuais
  Remove-Item "$env:UserProfile\OneDrive" -Recurse -Force -ErrorAction SilentlyContinue
}

# Reinstala o OneDrive (opcional)
Function InstallOneDrive {
  Write-Colored "Reinstalando o OneDrive..." -Color Green
  $oneDriveSetup = "$env:SystemRoot\SysWOW64\OneDriveSetup.exe"
  if (-not (Test-Path $oneDriveSetup)) { $oneDriveSetup = "$env:SystemRoot\System32\OneDriveSetup.exe" }
  if (Test-Path $oneDriveSetup) {
    Start-Process $oneDriveSetup -NoNewWindow -Wait
  }
  else {
    Write-Colored "OneDriveSetup.exe não encontrado. Reinstalação manual necessária." -Color Red
  }
}

# Remove bloatware específico da Microsoft
Function UninstallMsftBloat {
  Write-Colored "Removendo bloatware da Microsoft..." -Color Yellow
  $msftApps = @(
    "Microsoft.3DBuilder",
    "Microsoft.BingWeather",
    "Microsoft.GetHelp",
    "Microsoft.MixedReality.Portal",
    "Microsoft.SkypeApp",
    "Microsoft.YourPhone"
  )
  foreach ($app in $msftApps) {
    Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -ErrorAction SilentlyContinue
    Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq $app } | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
  }
}

# Desativa recursos do Xbox
Function DisableXboxFeatures {
  Write-Colored "Desativando recursos do Xbox..." -Color Yellow
  $regPath = "HKCU:\Software\Microsoft\GameBar"
  if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force }
  Set-ItemProperty -Path $regPath -Name "AllowGameDVR" -Value 0
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Value 0
  # Remove apps do Xbox
  Get-AppxPackage -Name "Microsoft.Xbox*" -AllUsers | Remove-AppxPackage -ErrorAction SilentlyContinue
}

# Exportar todas as funções
Export-ModuleMember -Function DebloatAll, RemoveBloatRegistry, UninstallOneDrive, InstallOneDrive, UninstallMsftBloat, DisableXboxFeatures