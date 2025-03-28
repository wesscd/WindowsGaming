# windowsdebloatandgamingtweaks.ps1
# Script principal para otimização de sistemas Windows focados em jogos
# Versão: 0.7.0.4 (VM GROK)
# Autores Originais: ChrisTitusTech, DaddyMadu, wesscd
# Modificado por: [Seu Nome]

# Definir página de código para suportar caracteres especiais

chcp 860 | Out-Null

# Função para texto colorido
function Write-Colored {
  param (
    [string]$Text,
    [string]$Color
  )
  $colors = @{
    'Preto'         = 'Black'
    'Azul'          = 'DarkBlue'
    'Verde'         = 'DarkGreen'
    'Ciano'         = 'DarkCyan'
    'Vermelho'      = 'DarkRed'
    'Magenta'       = 'DarkMagenta'
    'Amarelo'       = 'DarkYellow'
    'CinzaClaro'    = 'Gray'
    'CinzaEscuro'   = 'DarkGray'
    'AzulClaro'     = 'Blue'
    'VerdeClaro'    = 'Green'
    'CianoClaro'    = 'Cyan'
    'VermelhoClaro' = 'Red'
    'MagentaClaro'  = 'Magenta'
    'AmareloClaro'  = 'Yellow'
    'Branco'        = 'White'
  }
  $selectedColor = $colors[$Color]
  if (-not $selectedColor) {
    $selectedColor = 'White' # Cor padrão se a chave não for encontrada
  }
  Write-Host $Text -ForegroundColor $selectedColor
}

# Função SlowUpdatesTweaks definida diretamente
function SlowUpdatesTweaks {
  Write-Output "Aplicando tweaks para atualizações lentas..."
  If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdates" -Type DWord -Value 1
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdates" -Type DWord -Value 1
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdatesPeriodInDays" -Type DWord -Value 365
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdatesPeriodInDays" -Type DWord -Value 30
  Write-Colored "Atualizações do Windows configuradas para modo lento." -Color "VerdeClaro"
}

# Exibir introdução
function Show-Intro {
  Clear-Host
  $intro = @(
    "", "", "████████╗███████╗ ██████╗██╗  ██╗    ██████╗ ███████╗███╗   ███╗ ██████╗ ████████╗███████╗",
    "╚══██╔══╝██╔════╝██╔════╝██║  ██║    ██╔══██╗██╔════╝████╗ ████║██╔═══██╗╚══██╔══╝██╔════╝",
    "   ██║   █████╗  ██║     ███████║    ██████╔╝████X╗  ██╔████╔██║██║   ██║   ██║   █████╗  ",
    "   ██║   ██╔══╝  ██║     ██╔══██║    ██╔══██╗██╔══╝  ██║╚██╔╝██║██║   ██║   ██║   ██╔══╝  ",
    "   ██║   ███████╗╚██████╗██║  ██║    ██║  ██║███████╗██║ ╚═╝ ██║╚██████╔╝   ██║   ███████╗",
    "   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝    ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝ ╚═════╝    ╚═╝   ╚══════╝",
    "", "Bem-vindo ao TechRemote Ultimate Windows Debloater Gaming",
    "Este script otimizará o desempenho do seu sistema Windows.",
    "Um ponto de restauração será criado antes de prosseguir.",
    "DESATIVE SEU ANTIVÍRUS e PRESSIONE QUALQUER TECLA para continuar!"
  )
  $colors = @("VerdeClaro", "VerdeClaro", "VerdeClaro", "VerdeClaro", "VerdeClaro", "VerdeClaro", "VerdeClaro", "AzulClaro", "AmareloClaro", "AmareloClaro", "VermelhoClaro")
  for ($i = 0; $i -lt $intro.Length; $i++) {
    $color = if ($i -lt $colors.Length) { $colors[$i] } else { "Branco" }
    Write-Colored $intro[$i] $color
  }
  [Console]::ReadKey($true) | Out-Null
}

# (O restante do script continua como antes)

# Configurar drives de registro
New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT -ErrorAction SilentlyContinue | Out-Null
New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -ErrorAction SilentlyContinue | Out-Null

# Verificar privilégios administrativos
function RequireAdmin {
  if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Colored "Este script precisa ser executado como administrador. Reinicie com privilégios elevados." -Color "Vermelho"
    Start-Process Powershell -ArgumentList '-ExecutionPolicy bypass -NoProfile -command "irm https://raw.githubusercontent.com/wesscd/WindowsGaming/master/windowsdebloatandgamingtweaks.ps1 | iex"' -Verb RunAs
    Exit
  }
}

# Carregar módulos
$modules = @(
  ".\Modules\PerformanceTweaks.ps1",
  ".\Modules\PrivacyTweaks.ps1"
)
foreach ($module in $modules) {
  if (Test-Path $module) {
    Import-Module $module -Force
    Write-Colored "Módulo carregado: $module" -Color "Verde"
  }
  else {
    Write-Colored "Módulo não encontrado: $module" -Color "Vermelho"
  }
}

# Definir hashtable de funções de tweaks
$tweakFunctions = @{
  # Funções gerais
  "RequireAdmin"                = { RequireAdmin }
  "CreateRestorePoint"          = { CreateRestorePoint }
  "InstallMVC"                  = { InstallMVC }
  "Install7Zip"                 = { Install7Zip }
  "Write-ColorOutput"           = { Write-ColorOutput }
  "InstallTitusProgs"           = { InstallTitusProgs }
  "Check-Windows"               = { Check-Windows }
  "Execute-BatchScript"         = { Execute-BatchScript }
  "InstallChocoUpdates"         = { InstallChocoUpdates }
  "EnableUltimatePower"         = { EnableUltimatePower }
  "AskDefender"                 = { AskDefender }
  "AskXBOX"                     = { AskXBOX }
  "Windows11Extras"             = { Windows11Extras }
  "DebloatAll"                  = { DebloatAll }
  "RemoveBloatRegistry"         = { RemoveBloatRegistry }
  "Remove-OneDrive"             = { Remove-OneDrive }
  "UninstallMsftBloat"          = { UninstallMsftBloat }
  "DisableXboxFeatures"         = { DisableXboxFeatures }
  "DisableNewsFeed"             = { DisableNewsFeed }
  "SetUACLow"                   = { SetUACLow }
  "DisableSMB1"                 = { DisableSMB1 }
  "SetCurrentNetworkPrivate"    = { SetCurrentNetworkPrivate }
  "SetUnknownNetworksPrivate"   = { SetUnknownNetworksPrivate }
  "DisableNetDevicesAutoInst"   = { DisableNetDevicesAutoInst }
  "EnableF8BootMenu"            = { EnableF8BootMenu }
  "DisableMeltdownCompatFlag"   = { DisableMeltdownCompatFlag }
  "EnableUpdateMSRT"            = { EnableUpdateMSRT }
  "EnableUpdateDriver"          = { EnableUpdateDriver }
  "DisableUpdateRestart"        = { DisableUpdateRestart }
  "DisableHomeGroups"           = { DisableHomeGroups }
  "EnableSharedExperiences"     = { EnableSharedExperiences }
  "DisableRemoteAssistance"     = { DisableRemoteAssistance }
  "EnableRemoteDesktop"         = { EnableRemoteDesktop }
  "DisableAutoplay"             = { DisableAutoplay }
  "DisableAutorun"              = { DisableAutorun }
  "DisableStorageSense"         = { DisableStorageSense }
  "DisableDefragmentation"      = { DisableDefragmentation }
  "EnableIndexing"              = { EnableIndexing }
  "SetBIOSTimeUTC"              = { SetBIOSTimeUTC }
  "DisableHibernation"          = { DisableHibernation }
  "EnableSleepButton"           = { EnableSleepButton }
  "DisableSleepTimeout"         = { DisableSleepTimeout }
  "DisableFastStartup"          = { DisableFastStartup }
  "DisableGaming"               = { DisableGaming }
  "PowerThrottlingOff"          = { PowerThrottlingOff }
  "Win32PrioritySeparation"     = { Win32PrioritySeparation }
  "DisableAERO"                 = { DisableAERO }
  "BSODdetails"                 = { BSODdetails }
  "DisableliveTiles"            = { DisableliveTiles }
  "WallpaperQuality"            = { WallpaperQuality }
  "DisableShistory"             = { DisableShistory }
  "DisableShortcutWord"         = { DisableShortcutWord }
  "DisableMouseKKS"             = { DisableMouseKKS }
  "DisableTransparency"         = { DisableTransparency }
  "TurnOffSafeSearch"           = { TurnOffSafeSearch }
  "DisableCloudSearch"          = { DisableCloudSearch }
  "DisableDeviceHistory"        = { DisableDeviceHistory }
  "DisableSearchHistory"        = { DisableSearchHistory }
  "RemoveMeet"                  = { RemoveMeet }
  "EnableActionCenter"          = { EnableActionCenter }
  "EnableLockScreen"            = { EnableLockScreen }
  "EnableLockScreenRS1"         = { EnableLockScreenRS1 }
  "DisableStickyKeys"           = { DisableStickyKeys }
  "ShowTaskManagerDetails"      = { ShowTaskManagerDetails }
  "ShowFileOperationsDetails"   = { ShowFileOperationsDetails }
  "DisableFileDeleteConfirm"    = { DisableFileDeleteConfirm }
  "HideTaskbarSearch"           = { HideTaskbarSearch }
  "HideTaskView"                = { HideTaskView }
  "HideTaskbarPeopleIcon"       = { HideTaskbarPeopleIcon }
  "DisableSearchAppInStore"     = { DisableSearchAppInStore }
  "DisableNewAppPrompt"         = { DisableNewAppPrompt }
  "SetVisualFXPerformance"      = { SetVisualFXPerformance }
  "EnableNumlock"               = { EnableNumlock }
  "EnableDarkMode"              = { EnableDarkMode }
  "ShowKnownExtensions"         = { ShowKnownExtensions }
  "HideHiddenFiles"             = { HideHiddenFiles }
  "HideSyncNotifications"       = { HideSyncNotifications }
  "HideRecentShortcuts"         = { HideRecentShortcuts }
  "SetExplorerThisPC"           = { SetExplorerThisPC }
  "ShowThisPCOnDesktop"         = { ShowThisPCOnDesktop }
  "ShowUserFolderOnDesktop"     = { ShowUserFolderOnDesktop }
  "Hide3DObjectsFromThisPC"     = { Hide3DObjectsFromThisPC }
  "Hide3DObjectsFromExplorer"   = { Hide3DObjectsFromExplorer }
  "EnableThumbnails"            = { EnableThumbnails }
  "EnableThumbsDB"              = { EnableThumbsDB }
  "UninstallInternetExplorer"   = { UninstallInternetExplorer }
  "UninstallWorkFolders"        = { UninstallWorkFolders }
  "UninstallLinuxSubsystem"     = { UninstallLinuxSubsystem }
  "SetPhotoViewerAssociation"   = { SetPhotoViewerAssociation }
  "AddPhotoViewerOpenWith"      = { AddPhotoViewerOpenWith }
  "InstallPDFPrinter"           = { InstallPDFPrinter }
  "SVCHostTweak"                = { SVCHostTweak }
  "UnpinStartMenuTiles"         = { UnpinStartMenuTiles }
  "QOL"                         = { QOL }
  "FullscreenOptimizationFIX"   = { FullscreenOptimizationFIX }
  "GameOptimizationFIX"         = { GameOptimizationFIX }
  "RawMouseInput"               = { RawMouseInput }
  "DetectnApplyMouseFIX"        = { DetectnApplyMouseFIX }
  "DisableHPET"                 = { DisableHPET }
  "EnableGameMode"              = { EnableGameMode }
  "EnableHAGS"                  = { EnableHAGS }
  "DisableCoreParking"          = { DisableCoreParking }
  "DisableDMA"                  = { DisableDMA }
  "DisablePKM"                  = { DisablePKM }
  "DisallowDIP"                 = { DisallowDIP }
  "UseBigM"                     = { UseBigM }
  "ForceContiguousM"            = { ForceContiguousM }
  "DecreaseMKBuffer"            = { DecreaseMKBuffer }
  "StophighDPC"                 = { StophighDPC }
  "Ativar-Servicos"             = { Ativar-Servicos }
  "RemoveEdit3D"                = { RemoveEdit3D }
  "FixURLext"                   = { FixURLext }
  "UltimateCleaner"             = { UltimateCleaner }
  "Clear-PSHistory"             = { Clear-PSHistory }
  "Finished"                    = { Finished }

  # Funções de Performance (assumidas em PerformanceTweaks.ps1)
  #"SlowUpdatesTweaks"           = { SlowUpdatesTweaks }
  "Set-RamThreshold"            = { Set-RamThreshold }
  "Set-MemoriaVirtual-Registry" = { Set-MemoriaVirtual-Registry }
  "DownloadAndExtractISLC"      = { DownloadAndExtractISLC }
  "UpdateISLCConfig"            = { UpdateISLCConfig }
  "ApplyPCOptimizations"        = { ApplyPCOptimizations }
  "MSIMode"                     = { MSIMode }
  "NvidiaTweaks"                = { NvidiaTweaks }
  "AMDGPUTweaks"                = { AMDGPUTweaks }
  "NetworkOptimizations"        = { NetworkOptimizations }
  "DisableNagle"                = { DisableNagle }
  "NetworkAdapterRSS"           = { NetworkAdapterRSS }

  # Funções de Privacidade (assumidas em PrivacyTweaks.ps1)
  "DisableTelemetry"            = { DisableTelemetry }
  "DisableWiFiSense"            = { DisableWiFiSense }
  "DisableSmartScreen"          = { DisableSmartScreen }
  "DisableWebSearch"            = { DisableWebSearch }
  "DisableAppSuggestions"       = { DisableAppSuggestions }
  "DisableActivityHistory"      = { DisableActivityHistory }
  "EnableBackgroundApps"        = { EnableBackgroundApps }
  "DisableLocationTracking"     = { DisableLocationTracking }
  "DisableMapUpdates"           = { DisableMapUpdates }
  "DisableFeedback"             = { DisableFeedback }
  "DisableTailoredExperiences"  = { DisableTailoredExperiences }
  "DisableAdvertisingID"        = { DisableAdvertisingID }
  "DisableCortana"              = { DisableCortana }
  "DisableErrorReporting"       = { DisableErrorReporting }
  "SetP2PUpdateLocal"           = { SetP2PUpdateLocal }
  "DisableWAPPush"              = { DisableWAPPush }
}

# Lista de tweaks a serem executados
$tweaks = @(
  "RequireAdmin",
  "CreateRestorePoint",
  "InstallMVC",
  "Install7Zip",
  "SlowUpdatesTweaks", # Mantida, pois está definida no script principal
  "InstallTitusProgs",
  "Check-Windows",
  "Execute-BatchScript",
  "InstallChocoUpdates",
  "EnableUltimatePower",
  "AskDefender",
  "AskXBOX",
  "Windows11Extras",
  "DebloatAll",
  "RemoveBloatRegistry",
  "Remove-OneDrive -AskUser",
  "UninstallMsftBloat",
  "DisableXboxFeatures",
  "DisableNewsFeed",
  "SetUACLow",
  "DisableSMB1",
  "SetCurrentNetworkPrivate",
  "SetUnknownNetworksPrivate",
  "DisableNetDevicesAutoInst",
  "EnableF8BootMenu",
  "DisableMeltdownCompatFlag",
  "EnableUpdateMSRT",
  "EnableUpdateDriver",
  "DisableUpdateRestart",
  "DisableHomeGroups",
  "EnableSharedExperiences",
  "DisableRemoteAssistance",
  "EnableRemoteDesktop",
  "DisableAutoplay",
  "DisableAutorun",
  "DisableStorageSense",
  "DisableDefragmentation",
  "EnableIndexing",
  "SetBIOSTimeUTC",
  "DisableHibernation",
  "EnableSleepButton",
  "DisableSleepTimeout",
  "DisableFastStartup",
  "DisableGaming",
  "PowerThrottlingOff",
  "Win32PrioritySeparation",
  "DisableAERO",
  "BSODdetails",
  "DisableliveTiles",
  "WallpaperQuality",
  "DisableShistory",
  "DisableShortcutWord",
  "DisableMouseKKS",
  "DisableTransparency",
  "TurnOffSafeSearch",
  "DisableCloudSearch",
  "DisableDeviceHistory",
  "DisableSearchHistory",
  "RemoveMeet",
  "EnableActionCenter",
  "EnableLockScreen",
  "EnableLockScreenRS1",
  "DisableStickyKeys",
  "ShowTaskManagerDetails",
  "ShowFileOperationsDetails",
  "DisableFileDeleteConfirm",
  "HideTaskbarSearch",
  "HideTaskView",
  "HideTaskbarPeopleIcon",
  "DisableSearchAppInStore",
  "DisableNewAppPrompt",
  "SetVisualFXPerformance",
  "EnableNumlock",
  "EnableDarkMode",
  "ShowKnownExtensions",
  "HideHiddenFiles",
  "HideSyncNotifications",
  "HideRecentShortcuts",
  "SetExplorerThisPC",
  "ShowThisPCOnDesktop",
  "ShowUserFolderOnDesktop",
  "Hide3DObjectsFromThisPC",
  "Hide3DObjectsFromExplorer",
  "EnableThumbnails",
  "EnableThumbsDB",
  "UninstallInternetExplorer",
  "UninstallWorkFolders",
  "UninstallLinuxSubsystem",
  "SetPhotoViewerAssociation",
  "AddPhotoViewerOpenWith",
  "InstallPDFPrinter",
  "SVCHostTweak",
  "UnpinStartMenuTiles",
  "QOL",
  "FullscreenOptimizationFIX",
  "GameOptimizationFIX",
  "RawMouseInput",
  "DetectnApplyMouseFIX",
  "DisableHPET",
  "EnableGameMode",
  "EnableHAGS",
  "DisableCoreParking",
  "DisableDMA",
  "DisablePKM",
  "DisallowDIP",
  "UseBigM",
  "ForceContiguousM",
  "DecreaseMKBuffer",
  "StophighDPC",
  "Ativar-Servicos",
  "RemoveEdit3D",
  "FixURLext",
  "UltimateCleaner",
  "Clear-PSHistory",
  "Finished"
)

# Funções definidas no script principal
function Write-ColorOutput {
  [CmdletBinding()]
  Param(
    [Parameter(Mandatory = $False, Position = 1, ValueFromPipeline = $True, ValueFromPipelinebyPropertyName = $True)][Object] $Object,
    [Parameter(Mandatory = $False, Position = 2, ValueFromPipeline = $True, ValueFromPipelinebyPropertyName = $True)][ConsoleColor] $ForegroundColor,
    [Parameter(Mandatory = $False, Position = 3, ValueFromPipeline = $True, ValueFromPipelinebyPropertyName = $True)][ConsoleColor] $BackgroundColor,
    [Switch]$NoNewline
  )    
  $previousForegroundColor = $host.UI.RawUI.ForegroundColor
  $previousBackgroundColor = $host.UI.RawUI.BackgroundColor
  if ($BackgroundColor -ne $null) { $host.UI.RawUI.BackgroundColor = $BackgroundColor }
  if ($ForegroundColor -ne $null) { $host.UI.RawUI.ForegroundColor = $ForegroundColor }
  if ($null -eq $Object) { $Object = "" }
  if ($NoNewline) { [Console]::Write($Object) } else { Write-Output $Object }
  $host.UI.RawUI.ForegroundColor = $previousForegroundColor
  $host.UI.RawUI.BackgroundColor = $previousBackgroundColor
}

function InstallTitusProgs {
  Write-Output "Verificando e instalando Chocolatey, se necessário..."
  if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
    try {
      Set-ExecutionPolicy Bypass -Scope Process -Force
      [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
      Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
      Write-Output "Chocolatey instalado com sucesso."
    }
    catch {
      Write-Output "Erro ao instalar o Chocolatey: $_"
      return
    }
  }
  else {
    Write-Output "Chocolatey já está instalado."
  }
  try {
    choco install chocolatey-core.extension -y
  }
  catch {
    Write-Output "Erro ao instalar chocolatey-core.extension: $_"
  }
  Write-Output "Executando O&O ShutUp10 com as configurações recomendadas..."
  Import-Module BitsTransfer
  try {
    $configUrl = "https://raw.githubusercontent.com/wesscd/WindowsGaming/master/ooshutup10.cfg"
    $exeUrl = "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe"
    $configFile = "$env:TEMP\ooshutup10.cfg"
    $exeFile = "$env:TEMP\OOSU10.exe"
    Start-BitsTransfer -Source $configUrl -Destination $configFile
    Start-BitsTransfer -Source $exeUrl -Destination $exeFile
    & $exeFile $configFile /quiet
    Start-Sleep -Seconds 10
    Remove-Item -Path $configFile, $exeFile -Force -ErrorAction Stop
    Write-Output "O&O ShutUp10 executado e arquivos temporários removidos."
  }
  catch {
    Write-Output "Erro ao executar O&O ShutUp10: $_"
  }
}

function Execute-BatchScript {
  Write-Output "Baixando e executando o script em batch..."
  $remoteUrl = "https://raw.githubusercontent.com/TitusConsultingBR/techremote/main/techremote.bat"
  $localPath = "$env:TEMP\techremote.bat"
  try {
    Invoke-WebRequest -Uri $remoteUrl -OutFile $localPath -ErrorAction Stop
    if (Test-Path $localPath) {
      Write-Output "Download concluído. Executando o script..."
      Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$localPath`"" -Wait -NoNewWindow -ErrorAction Stop
      Write-Colored "Script em batch executado com sucesso." -Color "VerdeClaro"
    }
    else {
      Write-Colored "Erro: O arquivo não foi baixado corretamente." -Color "VermelhoClaro"
    }
  }
  catch {
    Write-Colored "Erro ao baixar ou executar o script em batch: $_" -Color "VermelhoClaro"
  }
  finally {
    if (Test-Path $localPath) {
      Remove-Item $localPath -Force -ErrorAction SilentlyContinue
      Write-Output "Arquivo temporário removido."
    }
  }
}

function Check-Windows {
  Write-Output "Verificando ativação do Windows..."
  try {
    $slmgrOutput = cscript //NoLogo "$env:SystemRoot\System32\slmgr.vbs" /dli | Out-String
    if ($slmgrOutput -match "Licensed" -or $slmgrOutput -match "Ativado") {
      Write-Colored "O Windows já está ativado." -Color "VerdeClaro"
    }
    else {
      Write-Colored "O Windows não está ativado." -Color "AmareloClaro"
      $choice = Read-Host "Deseja inserir uma chave de produto para ativar? (S/N)"
      if ($choice -match "(?i)^s$") {
        $productKey = Read-Host "Digite a chave de produto (ex.: XXXXX-XXXXX-XXXXX-XXXXX-XXXXX)"
        cscript //NoLogo "$env:SystemRoot\System32\slmgr.vbs" /ipk $productKey | Out-Null
        $activationResult = cscript //NoLogo "$env:SystemRoot\System32\slmgr.vbs" /ato | Out-String
        if ($activationResult -match "successfully" -or $activationResult -match "ativado com sucesso") {
          Write-Colored "Windows ativado com sucesso." -Color "VerdeClaro"
        }
        else {
          Write-Colored "Falha ao ativar o Windows com a chave fornecida." -Color "VermelhoClaro"
          Write-Output $activationResult
        }
      }
      else {
        Write-Colored "Ativação ignorada. O Windows permanece não ativado." -Color "AmareloClaro"
      }
    }
  }
  catch {
    Write-Colored "Erro ao verificar ou ativar o Windows: $_" -Color "VermelhoClaro"
    Write-Output "Certifique-se de ter permissões administrativas e uma conexão com a internet (se necessário)."
  }
}

function InstallMVC {
  choco install -y vcredist2010 | Out-Null
}

function Install7Zip {
  choco install 7zip -y
}

function InstallChocoUpdates {
  Clear-Host
  choco upgrade all -y
}

function AskXBOX {
  $winVer = [System.Environment]::OSVersion.Version
  $isWin11 = $winVer.Major -eq 10 -and $winVer.Build -ge 22000
  do {
    Clear-Host
    Write-Colored "" "Azul"
    Write-Colored "================ Desabilitar os recursos do XBOX e todos os aplicativos relacionados? ================" "Azul"
    Write-Colored "" "Azul"
    Write-Colored "AVISO: REMOVER OS APLICATIVOS DO XBOX fará com que o Win+G não funcione!" "Vermelho"
    Write-Colored "Pressione 'D' para desabilitar os recursos do XBOX." "Azul"
    Write-Colored "Pressione 'H' para habilitar os recursos do XBOX." "Azul"
    Write-Colored "Pressione 'P' para pular isso." "Azul"
    $selection = Read-Host "Por favor, escolha"
  } until ($selection -match "(?i)^(d|h|p)$")
  if ($selection -match "(?i)^d$") {
    try {
      $errpref = $ErrorActionPreference
      $ErrorActionPreference = "SilentlyContinue"
      Write-Output "Desativando recursos do Xbox..."
      $xboxApps = @(
        "Microsoft.XboxApp",
        "Microsoft.XboxIdentityProvider",
        "Microsoft.XboxSpeechToTextOverlay",
        "Microsoft.XboxGameOverlay",
        "Microsoft.Xbox.TCUI"
      )
      if ($isWin11) { $xboxApps += "Microsoft.XboxGamingOverlay" }
      foreach ($app in $xboxApps) {
        $pkg = Get-AppxPackage $app
        if ($pkg) { $pkg | Remove-AppxPackage }
      }
      Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 0
      if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Force | Out-Null
      }
      Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0
    }
    finally {
      $ErrorActionPreference = $errpref
    }
  }
  elseif ($selection -match "(?i)^h$") {
    try {
      $errpref = $ErrorActionPreference
      $ErrorActionPreference = "SilentlyContinue"
      Write-Output "Habilitando recursos do Xbox..."
      $xboxApps = @(
        "Microsoft.XboxApp",
        "Microsoft.XboxIdentityProvider",
        "Microsoft.XboxSpeechToTextOverlay",
        "Microsoft.XboxGameOverlay",
        "Microsoft.Xbox.TCUI"
      )
      if ($isWin11) { $xboxApps += "Microsoft.XboxGamingOverlay" }
      foreach ($app in $xboxApps) {
        $pkg = Get-AppxPackage -AllUsers $app
        if ($pkg) { $pkg | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" } }
      }
      Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 1
      Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -ErrorAction SilentlyContinue
    }
    finally {
      $ErrorActionPreference = $errpref
    }
  }
}

function DisableNewsFeed {
  Write-Output "Disabling Windows 10 News and Interests Feed..."
  If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Type DWord -Value 0
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds" -Name "ShellFeedsTaskbarViewMode" -Type DWord -Value 2
}

function SetUACLow {
  Write-Output "Lowering UAC level..."
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 0
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 0
}

function SetUACHigh {
  Write-Output "Raising UAC level..."
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 5
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 1
}

function EnableSharingMappedDrives {
  Write-Output "Enabling sharing mapped drives between users..."
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLinkedConnections" -Type DWord -Value 1
}

function DisableSharingMappedDrives {
  Write-Output "Disabling sharing mapped drives between users..."
  Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLinkedConnections" -ErrorAction SilentlyContinue
}

function DisableAdminShares {
  Write-Output "Disabling implicit administrative shares..."
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareWks" -Type DWord -Value 0
}

function EnableAdminShares {
  Write-Output "Enabling implicit administrative shares..."
  Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareWks" -ErrorAction SilentlyContinue
}

function DisableSMB1 {
  Write-Output "Disabling SMB 1.0 protocol..."
  Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
}

function EnableSMB1 {
  Write-Output "Enabling SMB 1.0 protocol..."
  Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force
}

function DisableSMBServer {
  Write-Output "Disabling SMB Server..."
  Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
  Set-SmbServerConfiguration -EnableSMB2Protocol $false -Force
}

function EnableSMBServer {
  Write-Output "Enabling SMB Server..."
  Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force
}

function DisableLLMNR {
  Write-Output "Disabling LLMNR..."
  If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Type DWord -Value 0
}

function EnableLLMNR {
  Write-Output "Enabling LLMNR..."
  Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue
}

function SetCurrentNetworkPrivate {
  Write-Output "Setting current network profile to private..."
  Set-NetConnectionProfile -NetworkCategory Private
}

function SetCurrentNetworkPublic {
  Write-Output "Setting current network profile to public..."
  Set-NetConnectionProfile -NetworkCategory Public
}

function SetUnknownNetworksPrivate {
  Write-Output "Setting unknown networks profile to private..."
  If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" -Name "Category" -Type DWord -Value 1
}

function SetUnknownNetworksPublic {
  Write-Output "Setting unknown networks profile to public..."
  Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" -Name "Category" -ErrorAction SilentlyContinue
}

function DisableNetDevicesAutoInst {
  Write-Output "Disabling automatic installation of network devices..."
  If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name "AutoSetup" -Type DWord -Value 0
}

function EnableNetDevicesAutoInst {
  Write-Output "Enabling automatic installation of network devices..."
  Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name "AutoSetup" -ErrorAction SilentlyContinue
}

function AskDefender {
  $osVersion = [System.Environment]::OSVersion.Version
  $isWindows11 = $osVersion.Build -ge 22000
  function Test-Admin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal $currentUser
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  }
  if (-not (Test-Admin)) {
    Write-Colored "Este script precisa ser executado como Administrador. Por favor, execute-o novamente como Administrador." "Vermelho"
    break
  }
  $tasks = @(
    "\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance",
    "\Microsoft\Windows\Windows Defender\Windows Defender Cleanup",
    "\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan",
    "\Microsoft\Windows\Windows Defender\Windows Defender Verification"
  )
  do {
    Clear-Host
    Write-Colored "" "Azul"
    Write-Colored "================ Desabilitar o Microsoft Windows Defender? ================" "Azul"
    Write-Colored "" "Azul"
    Write-Colored "Pressione 'D' para desabilitar o Microsoft Windows Defender." "Azul"
    Write-Colored "Pressione 'H' para habilitar o Microsoft Windows Defender." "Azul"
    Write-Colored "Pressione 'P' para pular isso." "Azul"
    $selection = Read-Host "Por favor, escolha."
  } until ($selection -match "(?i)^(d|h|p)$")
  if ($selection -match "(?i)^d$") {
    Write-Output "Desativando Microsoft Windows Defender e processos relacionados..."
    if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile") {
      Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -Name "EnableFirewall" -Type DWord -Value 0
    }
    if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender")) {
      New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 1
    if ($osVersion.Build -eq 14393) {
      Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsDefender" -ErrorAction SilentlyContinue
    }
    elseif ($osVersion.Build -ge 15063) {
      Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -ErrorAction SilentlyContinue
    }
    if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet")) {
      New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Type DWord -Value 2
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "PUAProtection" -ErrorAction SilentlyContinue
    Set-MpPreference -EnableControlledFolderAccess Disabled -ErrorAction SilentlyContinue
    foreach ($task in $tasks) {
      Disable-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
    }
  }
  elseif ($selection -match "(?i)^h$") {
    Write-Output "Ativando Microsoft Windows Defender e processos relacionados..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -Name "EnableFirewall" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -ErrorAction SilentlyContinue
    if ($osVersion.Build -eq 14393) {
      Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsDefender" -Type ExpandString -Value "`"%ProgramFiles%\Windows Defender\MSASCuiL.exe`"" 
    }
    elseif ($osVersion.Build -ge 15063) {
      Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -Type ExpandString -Value "%windir%\system32\SecurityHealthSystray.exe"
    }
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "PUAProtection" -Type DWord -Value 1
    foreach ($task in $tasks) {
      Enable-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
    }
  }
}

function EnableF8BootMenu {
  Write-Output "Enabling F8 boot menu options..."
  bcdedit /set bootmenupolicy Legacy | Out-Null
}

function DisableF8BootMenu {
  Write-Output "Disabling F8 boot menu options..."
  bcdedit /set bootmenupolicy Standard | Out-Null
}

function SetDEPOptOut {
  Write-Output "Setting Data Execution Prevention (DEP) policy to OptOut..."
  bcdedit /set nx OptOut | Out-Null
}

function SetDEPOptIn {
  Write-Output "Setting Data Execution Prevention (DEP) policy to OptIn..."
  bcdedit /set nx OptIn | Out-Null
}

function EnableCIMemoryIntegrity {
  Write-Output "Enabling Core Isolation Memory Integrity..."
  If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Type DWord -Value 1
}

function DisableCIMemoryIntegrity {
  Write-Output "Disabling Core Isolation Memory Integrity..."
  Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -ErrorAction SilentlyContinue
}

function DisableScriptHost {
  Write-Output "Disabling Windows Script Host..."
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Type DWord -Value 0
}

function EnableScriptHost {
  Write-Output "Enabling Windows Script Host..."
  Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -ErrorAction SilentlyContinue
}

function EnableDotNetStrongCrypto {
  Write-Output "Enabling .NET strong cryptography..."
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Type DWord -Value 1
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Type DWord -Value 1
}

function DisableDotNetStrongCrypto {
  Write-Output "Disabling .NET strong cryptography..."
  Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -ErrorAction SilentlyContinue
  Remove-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -ErrorAction SilentlyContinue
}

function EnableMeltdownCompatFlag {
  Write-Output "Enabling Meltdown (CVE-2017-5754) compatibility flag..."
  If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" | Out-Null
  }
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" -Name "cadca5fe-87d3-4b96-b7fb-a231484277cc" -Type DWord -Value 0
}

function DisableMeltdownCompatFlag {
  Write-Output "Disabling Meltdown (CVE-2017-5754) compatibility flag..."
  Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" -Name "cadca5fe-87d3-4b96-b7fb-a231484277cc" -ErrorAction SilentlyContinue
}

function DisableGaming {
  Write-Output "Stopping and disabling unnecessary services for gaming..."
  $errpref = $ErrorActionPreference
  $ErrorActionPreference = "silentlycontinue"
  Stop-Service "wisvc" -WarningAction SilentlyContinue
  Set-Service "wisvc" -StartupType Disabled
  Stop-Service "MapsBroker" -WarningAction SilentlyContinue
  Set-Service "MapsBroker" -StartupType Disabled
  Stop-Service "UmRdpService" -WarningAction SilentlyContinue
  Set-Service "UmRdpService" -StartupType Disabled
  Stop-Service "TrkWks" -WarningAction SilentlyContinue
  Set-Service "TrkWks" -StartupType Disabled
  Stop-Service "TermService" -WarningAction SilentlyContinue
  Set-Service "TermService" -StartupType Disabled
  $ErrorActionPreference = $errpref
}

function DisableUpdateMSRT {
  Write-Output "Disabling Malicious Software Removal Tool offering..."
  If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" | Out-Null
  }
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontOfferThroughWUAU" -Type DWord -Value 1
}

function EnableUpdateMSRT {
  Write-Output "Enabling Malicious Software Removal Tool offering..."
  Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontOfferThroughWUAU" -ErrorAction SilentlyContinue
}

function DisableUpdateDriver {
  Write-Output "Disabling driver offering through Windows Update..."
  If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Type DWord -Value 1
  If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontPromptForWindowsUpdate" -Type DWord -Value 1
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchWindowsUpdate" -Type DWord -Value 1
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DriverUpdateWizardWuSearchEnabled" -Type DWord -Value 0
  If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" | Out-Null
  }
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -Type DWord -Value 1
}

function EnableUpdateDriver {
  Write-Output "Enabling driver offering through Windows Update..."
  Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -ErrorAction SilentlyContinue
  Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontPromptForWindowsUpdate" -ErrorAction SilentlyContinue
  Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchWindowsUpdate" -ErrorAction SilentlyContinue
  Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DriverUpdateWizardWuSearchEnabled" -ErrorAction SilentlyContinue
  Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -ErrorAction SilentlyContinue
}

function DisableUpdateRestart {
  Write-Output "Disabling Windows Update automatic restart..."
  If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Type DWord -Value 1
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -Type DWord -Value 0
}

function EnableUpdateRestart {
  Write-Output "Enabling Windows Update automatic restart..."
  Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -ErrorAction SilentlyContinue
  Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -ErrorAction SilentlyContinue
}

function DisableHomeGroups {
  Write-Output "Stopping and disabling Home Groups services..."
  $errpref = $ErrorActionPreference
  $ErrorActionPreference = "silentlycontinue"
  Stop-Service "HomeGroupListener" -WarningAction SilentlyContinue
  Set-Service "HomeGroupListener" -StartupType Disabled
  Stop-Service "HomeGroupProvider" -WarningAction SilentlyContinue
  Set-Service "HomeGroupProvider" -StartupType Disabled
  $ErrorActionPreference = $errpref
}

function EnableHomeGroups {
  Write-Output "Starting and enabling Home Groups services..."
  $errpref = $ErrorActionPreference
  $ErrorActionPreference = "silentlycontinue"
  Set-Service "HomeGroupListener" -StartupType Manual
  Set-Service "HomeGroupProvider" -StartupType Manual
  Start-Service "HomeGroupProvider" -WarningAction SilentlyContinue
  $ErrorActionPreference = $errpref
}

function DisableSharedExperiences {
  Write-Output "Disabling Shared Experiences..."
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableCdp" -Type DWord -Value 0
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableMmx" -Type DWord -Value 0
}

function EnableSharedExperiences {
  Write-Output "Enabling Shared Experiences..."
  Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableCdp" -ErrorAction SilentlyContinue
  Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableMmx" -ErrorAction SilentlyContinue
}

function EnableRemoteAssistance {
  Write-Output "Enabling Remote Assistance..."
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 1
}

function EnableRemoteDesktop {
  Write-Output "Enabling Remote Desktop w/o Network Level Authentication..."
  $errpref = $ErrorActionPreference
  $ErrorActionPreference = "silentlycontinue"
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 0
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Type DWord -Value 0
  Enable-NetFirewallRule -Name "RemoteDesktop*" | Out-Null
  $ErrorActionPreference = $errpref
}

function DisableRemoteDesktop {
  Write-Output "Disabling Remote Desktop..."
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 1
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Type DWord -Value 1
  Disable-NetFirewallRule -Name "RemoteDesktop*" | Out-Null
}

function DisableAutoplay {
  Write-Output "Disabling Autoplay..."
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 1
}

function EnableAutoplay {
  Write-Output "Enabling Autoplay..."
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 0
}

function DisableAutorun {
  Write-Output "Disabling Autorun..."
  If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 255
}

function EnableAutorun {
  Write-Output "Enabling Autorun..."
  Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
}

function DisableStorageSense {
  Write-Output "Disabling Storage Sense..."
  If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy")) {
    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "01" -Type DWord -Value 0
}

function EnableStorageSense {
  Write-Output "Enabling Storage Sense..."
  Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "01" -ErrorAction SilentlyContinue
}

function DisableDefragmentation {
  Write-Output "Disabling Defragmentation..."
  If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Defrag")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Defrag" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Defrag" -Name "EnableDefrag" -Type DWord -Value 0
}

function EnableDefragmentation {
  Write-Output "Enabling Defragmentation..."
  Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Defrag" -Name "EnableDefrag" -ErrorAction SilentlyContinue
}

function EnableIndexing {
  Write-Output "Enabling Indexing..."
  Set-Service "WSearch" -StartupType Automatic
  Start-Service "WSearch" -ErrorAction SilentlyContinue
}

function DisableIndexing {
  Write-Output "Disabling Indexing..."
  Stop-Service "WSearch" -ErrorAction SilentlyContinue
  Set-Service "WSearch" -StartupType Disabled
}

function SetBIOSTimeUTC {
  Write-Output "Setting BIOS time to UTC..."
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -Name "RealTimeIsUniversal" -Type DWord -Value 1
}

function SetBIOSTimeLocal {
  Write-Output "Setting BIOS time to local time..."
  Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -Name "RealTimeIsUniversal" -ErrorAction SilentlyContinue
}

function DisableHibernation {
  Write-Output "Disabling Hibernation..."
  powercfg /hibernate off | Out-Null
}

function EnableHibernation {
  Write-Output "Enabling Hibernation..."
  powercfg /hibernate on | Out-Null
}

function EnableSleepButton {
  Write-Output "Enabling Sleep Button..."
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "SleepButtonEnabled" -Type DWord -Value 1
}

function DisableSleepButton {
  Write-Output "Disabling Sleep Button..."
  Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "SleepButtonEnabled" -ErrorAction SilentlyContinue
}

function DisableSleepTimeout {
  Write-Output "Disabling Sleep Timeout..."
  powercfg -change -standby-timeout-ac 0
  powercfg -change -standby-timeout-dc 0
}

function EnableSleepTimeout {
  Write-Output "Enabling Sleep Timeout..."
  powercfg -change -standby-timeout-ac 15
  powercfg -change -standby-timeout-dc 10
}

function DisableFastStartup {
  Write-Output "Disabling Fast Startup..."
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 0
}

function EnableFastStartup {
  Write-Output "Enabling Fast Startup..."
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 1
}

function PowerThrottlingOff {
  Write-Output "Disabling Power Throttling..."
  If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" -Name "PowerThrottlingOff" -Type DWord -Value 1
}

function PowerThrottlingOn {
  Write-Output "Enabling Power Throttling..."
  Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" -Name "PowerThrottlingOff" -ErrorAction SilentlyContinue
}

function Win32PrioritySeparation {
  Write-Output "Optimizing Win32 Priority Separation for gaming..."
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Type DWord -Value 38
}

function DisableAERO {
  Write-Output "Disabling AERO effects..."
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type DWord -Value 0
}

function EnableAERO {
  Write-Output "Enabling AERO effects..."
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type DWord -Value 1
}

function BSODdetails {
  Write-Output "Enabling detailed BSOD information..."
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "DisplayParameters" -Type DWord -Value 1
}

function DisableliveTiles {
  Write-Output "Disabling Live Tiles..."
  If (!(Test-Path "HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications")) {
    New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoTileApplicationNotification" -Type DWord -Value 1
}

function WallpaperQuality {
  Write-Output "Setting wallpaper quality to maximum..."
  Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "JPEGImportQuality" -Type DWord -Value 100
}

function DisableShistory {
  Write-Output "Disabling Shell history..."
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackDocs" -Type DWord -Value 0
}

function DisableShortcutWord {
  Write-Output "Removing 'Shortcut' word from new shortcuts..."
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "link" -Type Binary -Value ([byte[]](0, 0, 0, 0))
}

function DisableMouseKKS {
  Write-Output "Disabling mouse keys..."
  Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\MouseKeys" -Name "Flags" -Type String -Value "0"
}

function DisableTransparency {
  Write-Output "Disabling transparency effects..."
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Type DWord -Value 0
}

function TurnOffSafeSearch {
  Write-Output "Turning off Safe Search..."
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings" -Name "SafeSearch" -Type DWord -Value 0
}

function DisableCloudSearch {
  Write-Output "Disabling cloud search..."
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0
}

function DisableDeviceHistory {
  Write-Output "Disabling device history..."
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace" -Name "DelegateFolders" -Type DWord -Value 0
}

function DisableSearchHistory {
  Write-Output "Disabling search history..."
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "HistoryViewEnabled" -Type DWord -Value 0
}

function RemoveMeet {
  Write-Output "Removing Meet Now from taskbar..."
  If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Type DWord -Value 1
}

function EnableActionCenter {
  Write-Output "Enabling Action Center..."
  Remove-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -ErrorAction SilentlyContinue
}

function EnableLockScreen {
  Write-Output "Enabling Lock Screen..."
  Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -ErrorAction SilentlyContinue
}

function EnableLockScreenRS1 {
  Write-Output "Enabling Lock Screen (RS1 compatibility)..."
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" -Name "LockScreenEnabled" -Type DWord -Value 1
}

function DisableStickyKeys {
  Write-Output "Disabling Sticky Keys..."
  Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "506"
}

function ShowTaskManagerDetails {
  Write-Output "Showing Task Manager details..."
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -Type Binary -Value ([byte[]](0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00))
}

function ShowFileOperationsDetails {
  Write-Output "Showing file operations details..."
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Type DWord -Value 1
}

function DisableFileDeleteConfirm {
  Write-Output "Disabling file delete confirmation..."
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ConfirmFileDelete" -Type DWord -Value 0
}

function HideTaskbarSearch {
  Write-Output "Hiding taskbar search..."
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0
}

function HideTaskView {
  Write-Output "Hiding Task View button..."
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0
}

function HideTaskbarPeopleIcon {
  Write-Output "Hiding People icon from taskbar..."
  If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {
    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0
}

function DisableSearchAppInStore {
  Write-Output "Disabling search for apps in Store..."
  If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Type DWord -Value 1
}

function DisableNewAppPrompt {
  Write-Output "Disabling new app installed prompt..."
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_NotifyNewApps" -Type DWord -Value 0
}

function SetVisualFXPerformance {
  Write-Output "Setting visual effects for performance..."
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value 2
}

function EnableNumlock {
  Write-Output "Enabling Num Lock on startup..."
  Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value 2
}

function EnableDarkMode {
  Write-Output "Enabling Dark Mode..."
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Type DWord -Value 0
}

function ShowKnownExtensions {
  Write-Output "Showing known file extensions..."
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0
}

function HideHiddenFiles {
  Write-Output "Hiding hidden files..."
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 2
}

function HideSyncNotifications {
  Write-Output "Hiding sync provider notifications..."
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Type DWord -Value 0
}

function HideRecentShortcuts {
  Write-Output "Hiding recent shortcuts..."
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackDocs" -Type DWord -Value 0
}

function SetExplorerThisPC {
  Write-Output "Setting Explorer to open This PC..."
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1
}

function ShowThisPCOnDesktop {
  Write-Output "Showing This PC on Desktop..."
  If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{20D04FE0-3AEA-1069-A2D8-08002B30309D}")) {
    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Force | Out-Null
  }
}

function ShowUserFolderOnDesktop {
  Write-Output "Showing User folder on Desktop..."
  If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{59031a47-3f72-44a7-89c5-5595fe6b30ee}")) {
    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -Force | Out-Null
  }
}

function Hide3DObjectsFromThisPC {
  Write-Output "Hiding 3D Objects from This PC..."
  Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-0E5C-4FDD-9C0B-0A5A8D2A5F5E}" -Recurse -ErrorAction SilentlyContinue
}

function Hide3DObjectsFromExplorer {
  Write-Output "Hiding 3D Objects from Explorer..."
  Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0BDFD-8D7C-4F5E-9C0E-5E5C5D5A5F5E}" -Recurse -ErrorAction SilentlyContinue
}

function EnableThumbnails {
  Write-Output "Enabling thumbnails..."
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "IconsOnly" -Type DWord -Value 0
}

function EnableThumbsDB {
  Write-Output "Enabling Thumbs.db on network folders..."
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbnailCache" -Type DWord -Value 0
}

function UninstallInternetExplorer {
  Write-Output "Uninstalling Internet Explorer..."
  Disable-WindowsOptionalFeature -Online -FeatureName "Internet-Explorer-Optional-amd64" -NoRestart -ErrorAction SilentlyContinue
}

function UninstallWorkFolders {
  Write-Output "Uninstalling Work Folders..."
  Disable-WindowsOptionalFeature -Online -FeatureName "WorkFolders-Client" -NoRestart -ErrorAction SilentlyContinue
}

function UninstallLinuxSubsystem {
  Write-Output "Uninstalling Linux Subsystem..."
  Disable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-Subsystem-Linux" -NoRestart -ErrorAction SilentlyContinue
}

function SetPhotoViewerAssociation {
  Write-Output "Setting Photo Viewer associations..."
  If (!(Test-Path "HKCR:\Applications\photoviewer.dll")) {
    New-Item -Path "HKCR:\Applications\photoviewer.dll" -Force | Out-Null
  }
  $extensions = @(".bmp", ".jpg", ".jpeg", ".png", ".gif")
  foreach ($ext in $extensions) {
    If (!(Test-Path "HKCR:\$ext")) {
      New-Item -Path "HKCR:\$ext" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCR:\$ext" -Name "(Default)" -Value "PhotoViewer.FileAssoc.Tiff"
  }
}

function AddPhotoViewerOpenWith {
  Write-Output "Adding Photo Viewer to 'Open with' menu..."
  If (!(Test-Path "HKCR:\Applications\photoviewer.dll\shell\open")) {
    New-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open" -Name "(Default)" -Value "Open"
  If (!(Test-Path "HKCR:\Applications\photoviewer.dll\shell\open\command")) {
    New-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open\command" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open\command" -Name "(Default)" -Type ExpandString -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1"
}

function InstallPDFPrinter {
  Write-Output "Installing Microsoft Print to PDF..."
  Enable-WindowsOptionalFeature -Online -FeatureName "Printing-PrintToPDFServices-Features" -NoRestart -ErrorAction SilentlyContinue
}

function SVCHostTweak {
  Write-Output "Tweaking SVCHost process priority..."
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -Type DWord -Value 4194304
}

function UnpinStartMenuTiles {
  Write-Output "Unpinning all Start Menu tiles..."
  $key = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount" -Name "*"
  if ($key) {
    Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\*" -Recurse -Force -ErrorAction SilentlyContinue
  }
}

function QOL {
  Write-Output "Applying Quality of Life tweaks..."
  Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Type DWord -Value 0
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -Type DWord -Value 1
}

function FullscreenOptimizationFIX {
  Write-Output "Disabling Fullscreen Optimizations for all applications..."
  Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehaviorMode" -Type DWord -Value 2
  If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" -Name "~ DISABLEDXMAXIMIZEDWINDOWEDMODE" -Type String -Value ""
}

function GameOptimizationFIX {
  Write-Output "Applying game optimization fixes..."
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Priority" -Type DWord -Value 6
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Scheduling Category" -Type String -Value "High"
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "SFIO Priority" -Type String -Value "High"
}

function RawMouseInput {
  Write-Output "Enabling raw mouse input..."
  Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSensitivity" -Type DWord -Value 20
  Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "SmoothMouseXCurve" -Type Binary -Value ([byte[]](0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00))
  Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "SmoothMouseYCurve" -Type Binary -Value ([byte[]](0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00))
}

function DetectnApplyMouseFIX {
  Write-Output "Detecting and applying mouse acceleration fix..."
  Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSpeed" -Type DWord -Value 0
  Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold1" -Type DWord -Value 0
  Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold2" -Type DWord -Value 0
}

function DisableHPET {
  Write-Output "Disabling High Precision Event Timer (HPET)..."
  bcdedit /deletevalue useplatformclock | Out-Null
  bcdedit /set disabledynamictick yes | Out-Null
}

function EnableGameMode {
  Write-Output "Enabling Game Mode..."
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AllowAutoGameMode" -Type DWord -Value 1
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AutoGameModeEnabled" -Type DWord -Value 1
}

function EnableHAGS {
  Write-Output "Enabling Hardware-Accelerated GPU Scheduling..."
  If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "HwSchMode" -Type DWord -Value 2
}

function DisableCoreParking {
  Write-Output "Disabling CPU core parking..."
  powercfg -setacvalueindex SCHEME_CURRENT SUB_PROCESSOR CPMINCORES 100
  powercfg -setactive SCHEME_CURRENT
}

function DisableDMA {
  Write-Output "Disabling Direct Memory Access remapping..."
  bcdedit /set configaccesspolicy DisallowMmConfig | Out-Null
}

function DisablePKM {
  Write-Output "Disabling Power Key Management..."
  powercfg -setacvalueindex SCHEME_CURRENT SUB_BUTTONS PBUTTONPOWER 0
  powercfg -setactive SCHEME_CURRENT
}

function DisallowDIP {
  Write-Output "Disallowing driver installation prompts..."
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverInstall" -Name "PromptOnNewDevice" -Type DWord -Value 0
}

function UseBigM {
  Write-Output "Enabling big memory allocation..."
  bcdedit /set increaseuserva 4096 | Out-Null
}

function ForceContiguousM {
  Write-Output "Forcing contiguous memory allocation..."
  bcdedit /set removememory 1024 | Out-Null
}

function DecreaseMKBuffer {
  Write-Output "Decreasing mouse/keyboard buffer size..."
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" -Name "KeyboardDataQueueSize" -Type DWord -Value 50
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" -Name "MouseDataQueueSize" -Type DWord -Value 50
}

function StophighDPC {
  Write-Output "Reducing high DPC latency..."
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "ExitLatency" -Type DWord -Value 0
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "ExitLatencyCheckEnabled" -Type DWord -Value 0
}

function Ativar-Servicos {
  Write-Output "Ativando serviços essenciais para desempenho..."
  $services = @("Dnscache", "wuauserv", "Winmgmt")
  foreach ($service in $services) {
    Set-Service $service -StartupType Automatic
    Start-Service $service -ErrorAction SilentlyContinue
  }
}

function RemoveEdit3D {
  Write-Output "Removing 'Edit with 3D Paint' from context menu..."
  Remove-Item -Path "HKCR:\SystemFileAssociations\.bmp\Shell\3D Edit" -Recurse -ErrorAction SilentlyContinue
  Remove-Item -Path "HKCR:\SystemFileAssociations\.jpg\Shell\3D Edit" -Recurse -ErrorAction SilentlyContinue
  Remove-Item -Path "HKCR:\SystemFileAssociations\.png\Shell\3D Edit" -Recurse -ErrorAction SilentlyContinue
}

function FixURLext {
  Write-Output "Fixing URL file associations..."
  If (!(Test-Path "HKCR:\.url")) {
    New-Item -Path "HKCR:\.url" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKCR:\.url" -Name "(Default)" -Value "InternetShortcut"
}

function UltimateCleaner {
  Write-Output "Running ultimate system cleanup..."
  Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
  Remove-Item -Path "$env:windir\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
  Remove-Item -Path "$env:windir\Prefetch\*" -Recurse -Force -ErrorAction SilentlyContinue
  Clear-RecycleBin -Force -ErrorAction SilentlyContinue
}

function Clear-PSHistory {
  Write-Output "Clearing PowerShell command history..."
  Remove-Item -Path (Get-PSReadlineOption).HistorySavePath -Force -ErrorAction SilentlyContinue
}

function Remove-OneDrive {
  [CmdletBinding()]
  param (
    [switch]$AskUser
  )
  
  if ($AskUser) {
    do {
      Clear-Host
      Write-Colored "" "Azul"
      Write-Colored "================ Desinstalar o OneDrive? ================" "Azul"
      Write-Colored "" "Azul"
      Write-Colored "Pressione 'S' para desinstalar o OneDrive." "Azul"
      Write-Colored "Pressione 'N' para pular isso." "Azul"
      $selection = Read-Host "Por favor, escolha."
    } until ($selection -match "(?i)^(s|n)$")
    if ($selection -match "(?i)^n$") {
      Write-Colored "Desinstalação do OneDrive ignorada." -Color "AmareloClaro"
      return
    }
  }

  Write-Output "Desinstalando o OneDrive..."
  try {
    Stop-Process -Name "OneDrive" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    $onedrivePath = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
    if (Test-Path $onedrivePath) {
      Start-Process -FilePath $onedrivePath -ArgumentList "/uninstall" -Wait -NoNewWindow -ErrorAction Stop
    }
    else {
      Write-Output "OneDriveSetup.exe não encontrado em $onedrivePath. Pode já estar desinstalado."
    }
    Remove-Item "$env:USERPROFILE\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe" -Force -ErrorAction SilentlyContinue
    Write-Colored "OneDrive desinstalado com sucesso." -Color "VerdeClaro"
  }
  catch {
    Write-Colored "Erro ao desinstalar o OneDrive: $_" -Color "VermelhoClaro"
  }
}

function Windows11Extras {
  if ([System.Environment]::OSVersion.Version.Build -ge 22000) {
    Write-Output "Applying Windows 11 specific tweaks..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Type DWord -Value 0 # Centralizar barra de tarefas
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 1 # Mostrar busca na barra
  }
}

function DebloatAll {
  Write-Output "Running full debloat process..."
  $bloatware = @(
    "Microsoft.3DBuilder",
    "Microsoft.BingWeather",
    "Microsoft.GetHelp",
    "Microsoft.Getstarted",
    "Microsoft.Messaging",
    "Microsoft.Microsoft3DViewer",
    "Microsoft.MicrosoftSolitaireCollection",
    "Microsoft.MixedReality.Portal",
    "Microsoft.Office.OneNote",
    "Microsoft.OneConnect",
    "Microsoft.People",
    "Microsoft.Print3D",
    "Microsoft.SkypeApp",
    "Microsoft.Wallet",
    "Microsoft.WindowsAlarms",
    "Microsoft.WindowsCamera",
    "Microsoft.windowscommunicationsapps",
    "Microsoft.WindowsFeedbackHub",
    "Microsoft.WindowsMaps",
    "Microsoft.WindowsSoundRecorder",
    "Microsoft.ZuneMusic",
    "Microsoft.ZuneVideo"
  )
  foreach ($app in $bloatware) {
    Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -ErrorAction SilentlyContinue
    Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq $app | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
  }
}

function RemoveBloatRegistry {
  Write-Output "Removing bloatware registry entries..."
  $keys = @(
    "HKCR:\Applications\photoviewer.dll",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}"
  )
  foreach ($key in $keys) {
    Remove-Item -Path $key -Recurse -Force -ErrorAction SilentlyContinue
  }
}

function UninstallMsftBloat {
  Write-Output "Uninstalling additional Microsoft bloatware..."
  $bloatware = @(
    "Microsoft.Windows.Photos",
    "Microsoft.MicrosoftEdge.Stable",
    "Microsoft.WindowsCalculator",
    "Microsoft.WindowsStore"
  )
  foreach ($app in $bloatware) {
    Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -ErrorAction SilentlyContinue
    Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq $app | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
  }
}

function DisableXboxFeatures {
  Write-Output "Disabling Xbox features..."
  $xboxApps = @(
    "Microsoft.XboxApp",
    "Microsoft.XboxIdentityProvider",
    "Microsoft.XboxSpeechToTextOverlay",
    "Microsoft.XboxGameOverlay",
    "Microsoft.Xbox.TCUI",
    "Microsoft.XboxGamingOverlay"
  )
  foreach ($app in $xboxApps) {
    Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -ErrorAction SilentlyContinue
  }
  Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 0
  If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0
}

function EnableUltimatePower {
  Write-Output "Enabling Ultimate Performance power plan..."
  powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61
  powercfg -setactive e9a42b02-d5df-448d-aa00-03f14749eb61
}

function CreateRestorePoint {
  Write-Output "Creating system restore point..."
  Checkpoint-Computer -Description "Before Windows Debloater Gaming Tweaks" -RestorePointType "MODIFY_SETTINGS" -ErrorAction SilentlyContinue
}

function Finished {
  Clear-Host
  Write-Colored "" "Azul"
  Write-Colored "================ Otimização Concluída ================" "Verde"
  Write-Colored "O sistema foi otimizado para desempenho em jogos." "Azul"
  Write-Colored "Reinicie o computador para aplicar todas as alterações." "Amarelo"
  Write-Colored "Pressione qualquer tecla para sair..." "Azul"
  [Console]::ReadKey($true) | Out-Null
}

# Executar introdução
Show-Intro

# Executar os tweaks
foreach ($tweak in $tweaks) {
  $tweakName = $tweak.Split()[0]
  if ($tweakFunctions.ContainsKey($tweakName)) {
    Invoke-Expression $tweak
  }
  else {
    Write-Colored "Tweak não encontrado: $tweak" -Color "VermelhoClaro"
  }
}