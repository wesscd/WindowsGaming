# windowsdebloatandgamingtweaks.ps1
# Script principal para otimização de sistemas Windows focados em jogos
# Versão: 0.7.0.4 (VM GROK)
# Autores Originais: ChrisTitusTech, DaddyMadu, wesscd
# Modificado por: [Seu Nome]

# Definir página de código para suportar caracteres especiais

chcp 1252 | Out-Null

# Função para texto colorido
function Write-Colored {
  <#
  .SYNOPSIS
    Exibe texto colorido no console, aceitando nomes de cores em português ou inglês.

  .PARAMETER Text
    O texto a ser exibido.

  .PARAMETER Color
    O nome da cor do texto em português ou inglês.

  .PARAMETER BackgroundColor
    (Opcional) O nome da cor de fundo em português ou inglês.

  .EXAMPLE
    Write-Colored -Text "Olá, mundo!" -Color "VerdeClaro"
    Exibe "Olá, mundo!" em verde claro.

  .EXAMPLE
    Write-Colored -Text "Erro!" -Color "Vermelho" -BackgroundColor "Branco"
    Exibe "Erro!" em vermelho com fundo branco.
  #>
  param (
    [string]$Text,
    [string]$Color,
    [string]$BackgroundColor = $null
  )

  # Mapeamento de cores em português para inglês
  $colors = @{
    'preto'         = 'Black'
    'azul'          = 'DarkBlue'
    'verde'         = 'DarkGreen'
    'ciano'         = 'DarkCyan'
    'vermelho'      = 'DarkRed'
    'magenta'       = 'DarkMagenta'
    'amarelo'       = 'DarkYellow'
    'cinzaclaro'    = 'Gray'
    'cinzaescuro'   = 'DarkGray'
    'azulclaro'     = 'Blue'
    'verdeclaro'    = 'Green'  # Corrigido typo de 'verdecalar' para 'verdeclaro'
    'cianoclaro'    = 'Cyan'
    'vermelhoclaro' = 'Red'
    'magentaclaro'  = 'Magenta'
    'amareloclaro'  = 'Yellow'
    'branco'        = 'White'
  }

  # Converter a cor para minúsculas para torná-la case-insensitive
  $ColorLower = $Color.ToLower()
  $selectedColor = $colors[$ColorLower]

  # Se não encontrada no mapeamento, verificar se é uma cor válida em inglês
  if (-not $selectedColor) {
    $validColors = [Enum]::GetNames([System.ConsoleColor])
    if ($validColors -contains $Color) {
      $selectedColor = $Color
    }
    else {
      Write-Warning "Cor '$Color' não encontrada. Usando 'White' como padrão."
      $selectedColor = 'White'
    }
  }

  # Tratar a cor de fundo, se fornecida
  $selectedBgColor = $null
  if ($BackgroundColor) {
    $BgColorLower = $BackgroundColor.ToLower()
    $selectedBgColor = $colors[$BgColorLower]
    if (-not $selectedBgColor) {
      $validColors = [Enum]::GetNames([System.ConsoleColor])
      if ($validColors -contains $BackgroundColor) {
        $selectedBgColor = $BackgroundColor
      }
      else {
        Write-Warning "Cor de fundo '$BackgroundColor' não encontrada. Ignorando."
      }
    }
  }

  # Exibir o texto com as cores selecionadas
  if ($selectedBgColor) {
    Write-Host $Text -ForegroundColor $selectedColor -BackgroundColor $selectedBgColor
  }
  else {
    Write-Host $Text -ForegroundColor $selectedColor
  }
}

# Função SlowUpdatesTweaks definida diretamente
function SlowUpdatesTweaks {
  Write-Output "Improving Windows Update to delay Feature updates and only install Security Updates"
  try {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Force -ErrorAction Stop | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdates" -Type DWord -Value 1 -ErrorAction Stop
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdates" -Type DWord -Value 1 -ErrorAction Stop
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdatesPeriodInDays" -Type DWord -Value 30 -ErrorAction Stop
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdatesPeriodInDays" -Type DWord -Value 4 -ErrorAction Stop
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "PauseFeatureUpdatesStartTime" -Type String -Value "" -ErrorAction Stop
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "PauseQualityUpdatesStartTime" -Type String -Value "" -ErrorAction Stop
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "ActiveHoursEnd" -Type DWord -Value 2 -ErrorAction Stop
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "ActiveHoursStart" -Type DWord -Value 8 -ErrorAction Stop
    Write-Colored "Ajustes de atualização aplicados com sucesso." -Color "Green"
  }
  catch {
    Write-Colored "Erro ao aplicar ajustes de atualização: $_" -Color "Red"
  }
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
    "                                                                                  V0.7.1.1",
    "", "Bem-vindo ao TechRemote Ultimate Windows Debloater Gaming",
    "Este script otimizará o desempenho do seu sistema Windows.",
    "Um ponto de restauração será criado antes de prosseguir.",
    "DESATIVE SEU ANTIVÍRUS e PRESSIONE QUALQUER TECLA para continuar!"
  )
  $colors = @("VerdeClaro", "VerdeClaro", "VerdeClaro", "VerdeClaro", "VerdeClaro", "VerdeClaro", "VerdeClaro", "VerdeClaro", "VerdeClaro", "AzulClaro", "AmareloClaro", "AmareloClaro", "VermelhoClaro")
  for ($i = 0; $i -lt $intro.Length; $i++) {
    $color = if ($i -lt $colors.Length) { $colors[$i] } else { "Branco" }
    Write-Colored $intro[$i] $color
  }
  [Console]::ReadKey($true)
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
  ".\Modules\PrivacyTweaks.ps1",
  ".\Modules\Debloat.ps1"
)

foreach ($module in $modules) {
  try {
    if (Test-Path $module) {
      Import-Module $module -Force -ErrorAction Stop
      Write-Colored "Módulo carregado: $module" -Color "Verde"
    }
    else {
      Write-Colored "Módulo não encontrado: $module" -Color "VermelhoClaro"
      Write-Output "Certifique-se de que o arquivo está no diretório correto."
    }
  }
  catch {
    Write-Colored "Erro ao carregar o módulo $($module): $_" -Color "VermelhoClaro"
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
  "SlowUpdatesTweaks"           = { SlowUpdatesTweaks }
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
  "SlowUpdatesTweaks",
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
  # Adicionando funções de desempenho aqui
  "Set-RamThreshold",
  "Set-MemoriaVirtual-Registry",
  "DownloadAndExtractISLC",
  "UpdateISLCConfig",
  "ApplyPCOptimizations",
  "MSIMode",
  "NvidiaTweaks",
  "AMDGPUTweaks",
  "NetworkOptimizations",
  "DisableNagle",
  "NetworkAdapterRSS",
  # Continuação dos tweaks existentes
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
    # Verifica o status de ativação com slmgr.vbs
    $slmgrOutput = cscript //NoLogo "$env:SystemRoot\System32\slmgr.vbs" /dli | Out-String
    if ($slmgrOutput -match "Licensed" -or $slmgrOutput -match "Ativado") {
      Write-Colored "O Windows já está ativado." -Color "VerdeClaro"
    }
    else {
      Write-Colored "O Windows não está ativado." -Color "AmareloClaro"
      do {
        Clear-Host
        Write-Colored "" "Azul"
        Write-Colored "================ Ativar o Windows ================" "Azul"
        Write-Colored "" "Azul"
        Write-Colored "Pressione 'C' para inserir uma nova chave de produto." "Azul"
        Write-Colored "Pressione 'K' para ativar via KMS." "Azul"
        Write-Colored "Pressione 'P' para pular a ativação." "Azul"
        $selection = Read-Host "Por favor, escolha."
      } until ($selection -match "(?i)^(c|k|p)$")

      switch ($selection.ToLower()) {
        "c" {
          Write-Output "Opção escolhida: Inserir nova chave de produto."
          $productKey = Read-Host "Digite a chave de produto (ex.: XXXXX-XXXXX-XXXXX-XXXXX-XXXXX)"
          try {
            cscript //NoLogo "$env:SystemRoot\System32\slmgr.vbs" /ipk $productKey | Out-Null
            $activationResult = cscript //NoLogo "$env:SystemRoot\System32\slmgr.vbs" /ato | Out-String
            if ($activationResult -match "successfully" -or $activationResult -match "ativado com sucesso") {
              Write-Colored "Windows ativado com sucesso usando a chave fornecida." -Color "VerdeClaro"
            }
            else {
              Write-Colored "Falha ao ativar o Windows com a chave fornecida." -Color "VermelhoClaro"
              Write-Output $activationResult
            }
          }
          catch {
            Write-Colored "Erro ao aplicar a chave de produto: $_" -Color "VermelhoClaro"
          }
        }
        "k" {
          Write-Output "Opção escolhida: Ativar via KMS."
          try {
            Write-Colored "Conectando ao servidor KMS para ativação..." -Color "AmareloClaro"
            Invoke-Expression (Invoke-RestMethod -Uri "https://get.activated.win" -ErrorAction Stop)
            # Verifica novamente após tentativa de ativação
            $postActivation = cscript //NoLogo "$env:SystemRoot\System32\slmgr.vbs" /dli | Out-String
            if ($postActivation -match "Licensed" -or $postActivation -match "Ativado") {
              Write-Colored "Windows ativado com sucesso via KMS." -Color "VerdeClaro"
            }
            else {
              Write-Colored "Falha ao ativar o Windows via KMS. Verifique sua conexão ou o servidor KMS." -Color "VermelhoClaro"
            }
          }
          catch {
            Write-Colored "Erro ao executar a ativação KMS: $_" -Color "VermelhoClaro"
            Write-Output "Certifique-se de ter conexão com a internet."
          }
        }
        "p" {
          Write-Colored "Ativação ignorada. O Windows permanece não ativado." -Color "AmareloClaro"
        }
      }
    }
  }
  catch {
    Write-Colored "Erro ao verificar o status de ativação do Windows: $_" -Color "VermelhoClaro"
    Write-Output "Certifique-se de ter permissões administrativas."
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
  $osVersion = [System.Environment]::OSVersion.Version
  if ($osVersion.Major -eq 10) {
    Write-Output "Disabling Windows 10 News and Interests Feed..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds")) {
      New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds" -Name "ShellFeedsTaskbarViewMode" -Type DWord -Value 2
  }
  else {
    Write-Output "Windows 11 detectado, pulando desativação do News Feed."
  }
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


# Funções de Performance.
# Funções de Performance.
# Funções de Performance.


function Set-RamThreshold {
  $ramGB = [math]::Round((Get-WmiObject -Class Win32_ComputerSystem).TotalPhysicalMemory / 1GB)
  $value = switch ($ramGB) {
    4 { 4194304 }  # 4GB em KB
    6 { 6291456 }  # 6GB em KB
    8 { 8388608 }
    12 { 12582912 }
    16 { 16777216 }
    19 { 19922944 }
    20 { 20971520 }
    24 { 25165824 }
    32 { 33554432 }
    64 { 67108864 }
    128 { 134217728 }
    default {
      Write-Colored "Memória RAM não suportada para esta configuração." -Color "Red"
      return
    }
  }
  $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control"
  $regName = "SvcHostSplitThresholdInKB"
  try {
    Set-ItemProperty -Path $regPath -Name $regName -Value $value -Type DWord -ErrorAction Stop
    Write-Colored "Registro atualizado com o valor correto: $value KB" -Color "Green"
  }
  catch {
    Write-Colored "Erro ao atualizar registro: $_" -Color "Red"
  }
}

function Set-MemoriaVirtual-Registry {
  Clear-Host
  # Banner
  Write-Colored -Text "" -Color "verde" # Linha em branco para espaçamento
  Write-Colored -Text "================================" -Color "Cyan"
  Write-Colored -Text " Configurando Memória Virtual " -Color "Cyan"
  Write-Colored -Text "================================" -Color "Cyan"
  Write-Colored -Text "" -Color "verde" # Linha em branco para espaçamento

  Write-Colored -Text "Informe a letra do drive (ex: C) para configurar a memória virtual:" -Color "Cyan"
  $Drive = Read-Host
  $DrivePath = "${Drive}:"
  # Validação do drive
  if (-not (Test-Path $DrivePath)) {
    Write-Colored -Text "Drive $DrivePath não encontrado." -Color "Red"
    return
  }
  # Cálculo da memória RAM total em MB
  $TotalRAM = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1MB)
  $InitialSize = 9081  # Valor fixo inicial
  $MaxSize = [math]::Round($TotalRAM * 1.5)  # Máximo como 1,5x a RAM
  $RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
  try {
    Set-ItemProperty -Path $RegPath -Name "PagingFiles" -Value "$DrivePath\pagefile.sys $InitialSize $MaxSize" -ErrorAction Stop
    Set-ItemProperty -Path $RegPath -Name "AutomaticManagedPagefile" -Value 0 -ErrorAction Stop
    Write-Colored -Text "Memória virtual configurada para $DrivePath com inicial $InitialSize MB e máximo $MaxSize MB." -Color "Green"
    Write-Colored -Text "Reinicie o computador para aplicar as mudanças." -Color "Green"
  }
  catch {
    Write-Colored -Text "Erro ao configurar memória virtual: $_" -Color "Red"
  }
}

## Download and extract ISLC
function DownloadAndExtractISLC {
  # Definir o link de download e o caminho do arquivo
  $downloadUrl = "https://raw.githubusercontent.com/wesscd/WindowsGaming/main/ISLC%20v1.0.3.4.exe"
  $downloadPath = "C:\ISLC_v1.0.3.4.exe"
  $extractPath = "C:\"
  $newFolderName = "ISLC"

  # Baixar o arquivo executável
  Write-Colored "Iniciando o download do arquivo..." "Verde"
  try {
    Invoke-WebRequest -Uri $downloadUrl -OutFile $downloadPath
    Write-Colored "Arquivo baixado com sucesso!" "Verde"
  }
  catch {
    Write-Colored "Erro ao baixar o arquivo: $_" "Vermelho"
    return
  }

  # Verificar se a pasta de extração existe, caso contrário, criar
  if (-Not (Test-Path -Path $extractPath)) {
    Write-Colored "Criando a pasta de extração..." "Verde"
    New-Item -ItemType Directory -Path $extractPath
  }

  # Caminho do 7z.exe
  $sevenZipPath = "C:\Program Files\7-Zip\7z.exe"  # Altere conforme o local do seu 7z.exe

  # Verificar se o 7z está instalado
  if (Test-Path -Path $sevenZipPath) {
    Write-Colored "Extraindo o conteudo do arquivo usando 7-Zip..." "Verde"
    try {
      # Extrair diretamente na pasta ISLC
      & $sevenZipPath x $downloadPath -o"$extractPath" -y
      Write-Colored "Arquivo extraido com sucesso para $extractPath" "Verde"
          
      # Renomear a pasta extraída para MEM
      $extractedFolderPath = "$extractPath\ISLC v1.0.3.4"

      if (Test-Path -Path $extractedFolderPath) {
        Rename-Item -Path $extractedFolderPath -NewName $newFolderName
        Write-Colored "Pasta renomeada para '$newFolderName'." "Verde"
      }
      else {
        Write-Colored "Pasta extraída não encontrada." "Vermelho"
      }
    }
    catch {
      Write-Colored "Erro ao extrair o arquivo: $_" "Vermelho"
    }
  }
  else {
    Write-Colored "7-Zip não encontrado no caminho especificado." "Amarelo"
  }

  Remove-Item -Path $downloadPath -Force
  Write-Colored "Excluindo $downloadPath" "Verde"

  # Caminho completo do executável do programa
  $origem = "C:\ISLC\Intelligent standby list cleaner ISLC.exe"

  # Nome do atalho que será criado
  $atalhoNome = "Intelligent standby list cleaner ISLC.lnk"

  # Caminho para a pasta de Inicialização do usuário
  $destino = [System.IO.Path]::Combine($env:APPDATA, "Microsoft\Windows\Start Menu\Programs\Startup", $atalhoNome)

  # Criação do objeto Shell
  $shell = New-Object -ComObject WScript.Shell

  # Criação do atalho
  $atalho = $shell.CreateShortcut($destino)
  $atalho.TargetPath = $origem
  $atalho.Save()

  Write-Output "Atalho criado em: $destino"


}

# Update ISLC Config
function UpdateISLCConfig {
  # Caminho para o arquivo de configuração (ajuste conforme necessário)
  $configFilePath = "C:\ISLC\Intelligent standby list cleaner ISLC.exe.Config"

  # Verificar se o arquivo de configuração existe
  if (Test-Path -Path $configFilePath) {
    Write-Colored "Arquivo de configuracao encontrado. Atualizando..." "Verde"

    try {
      # Carregar o conteúdo do arquivo XML
      [xml]$configXml = Get-Content -Path $configFilePath -Raw

      # Obter a quantidade total de memória RAM do sistema (em MB)
      $totalMemory = (Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1MB
      $freeMemory = [math]::Round($totalMemory / 2)  # Calcular metade da memória

      # Alterar as configurações conforme solicitado
      $configXml.configuration.appSettings.add | Where-Object { $_.key -eq "Free memory" } | ForEach-Object { $_.value = "$freeMemory" }
      $configXml.configuration.appSettings.add | Where-Object { $_.key -eq "Start minimized" } | ForEach-Object { $_.value = "True" }
      $configXml.configuration.appSettings.add | Where-Object { $_.key -eq "Wanted timer" } | ForEach-Object { $_.value = "0.50" }
      $configXml.configuration.appSettings.add | Where-Object { $_.key -eq "Custom timer" } | ForEach-Object { $_.value = "True" }
      $configXml.configuration.appSettings.add | Where-Object { $_.key -eq "TaskScheduler" } | ForEach-Object { $_.value = "True" }

      # Salvar as alterações de volta no arquivo XML
      $configXml.Save($configFilePath)
      Write-Colored "Arquivo de configuracao atualizado com sucesso!" "Verde"
    }
    catch {
      Write-Colored "Erro ao atualizar o arquivo de configuracao: $_" "Vermelho"
    }
  }
  else {
    Write-Colored "Arquivo de configuracao nao encontrado em $configFilePath" "Amarelo"
  }
}

function ApplyPCOptimizations {
  Write-Output "Aplicando otimizações..."
  try {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -Type DWord -Value 0 -ErrorAction Stop
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Type DWord -Value 10 -ErrorAction Stop
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "AlwaysOn" -Type DWord -Value 1 -ErrorAction Stop
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "LazyMode" -Type DWord -Value 1 -ErrorAction Stop
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "LazyModeTimeout" -Type DWord -Value 25000 -ErrorAction Stop
    Write-Colored "Otimizações aplicadas com sucesso." -Color "Green"
  }
  catch {
    Write-Colored "Erro ao aplicar otimizações: $_" -Color "Red"
  }
}

function MSIMode {
  Write-Colored "AVISO: Ativar o modo MSI pode causar instabilidade. Use com cautela." -Color "Yellow"
  $gpuDevices = Get-PnpDevice -Class "Display" | Where-Object { $_.Status -eq "OK" -and $_.FriendlyName -match "NVIDIA|AMD" }
  if ($gpuDevices) {
    foreach ($device in $gpuDevices) {
      $path = "HKLM:\SYSTEM\CurrentControlSet\Enum\$($device.InstanceId)\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties"
      try {
        New-Item -Path $path -Force -ErrorAction Stop | Out-Null
        Set-ItemProperty -Path $path -Name "MSISupported" -Type DWord -Value 1 -ErrorAction Stop
      }
      catch {
        Write-Colored "Erro ao ativar MSI para $($device.FriendlyName): $_" -Color "Red"
      }
    }
    Write-Colored "Modo MSI ativado para GPUs compatíveis." -Color "Green"
  }
  else {
    Write-Colored "Nenhuma GPU compatível encontrada." -Color "Yellow"
  }
}

Function NvidiaTweaks {
  $CheckGPU = Get-CimInstance -ClassName Win32_VideoController | Select-Object -ExpandProperty Name
  if (($CheckGPU -like "*GTX*") -or ($CheckGPU -like "*RTX*")) {
    Write-Output "NVIDIA GTX/RTX Card Detected! Applying Nvidia Power Tweaks..."

    $url_base = "https://raw.githubusercontent.com/wesscd/WindowsGaming/main/BaseProfile.nip"
    $url_nvidiaprofile = "https://raw.githubusercontent.com/wesscd/WindowsGaming/main/nvidiaProfileInspector.exe"

    Invoke-WebRequest -Uri $url_base -OutFile "$Env:windir\system32\BaseProfile.nip" -ErrorAction SilentlyContinue
    Invoke-WebRequest -Uri $url_nvidiaprofile -OutFile "$Env:windir\system32\nvidiaProfileInspector.exe" -ErrorAction SilentlyContinue
    Push-Location
    set-location "$Env:windir\system32\"
    nvidiaProfileInspector.exe /s -load "BaseProfile.nip"
    Pop-Location
  }
  else {
    Write-Output "Nvidia GTX/RTX Card Not Detected! Skipping..."
  } 
  $errpref = $ErrorActionPreference #save actual preference
  $ErrorActionPreference = "silentlycontinue"	   
  $CheckGPURegistryKey0 = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000").DriverDesc
  $CheckGPURegistryKey1 = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001").DriverDesc
  $CheckGPURegistryKey2 = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002").DriverDesc
  $CheckGPURegistryKey3 = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003").DriverDesc
  $ErrorActionPreference = $errpref #restore previous preference
  if (($CheckGPURegistryKey0 -like "*GTX*") -or ($CheckGPURegistryKey0 -like "*RTX*")) {
    Write-Output "Nvidia GTX/RTX Card Registry Path 0000 Detected! Applying Nvidia Latency Tweaks..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "D3PCLatency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "F1TransitionLatency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "LOWLATENCY" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "Node3DLowLatency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "PciLatencyTimerControl" -Type DWord -Value "0x00000020"
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "RMDeepL1EntryLatencyUsec" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "RmGspcMaxFtuS" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "RmGspcMinFtuS" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "RmGspcPerioduS" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "RMLpwrEiIdleThresholdUs" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "RMLpwrGrIdleThresholdUs" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "RMLpwrGrRgIdleThresholdUs" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "RMLpwrMsIdleThresholdUs" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "VRDirectFlipDPCDelayUs" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "VRDirectFlipTimingMarginUs" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "VRDirectJITFlipMsHybridFlipDelayUs" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "vrrCursorMarginUs" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "vrrDeflickerMarginUs" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "vrrDeflickerMaxUs" -Type DWord -Value 1
  }
  elseif (($CheckGPURegistryKey1 -like "*GTX*") -or ($CheckGPURegistryKey1 -like "*RTX*")) {
    Write-Output "Nvidia GTX/RTX Card Registry Path 0001 Detected! Applying Nvidia Latency Tweaks..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "D3PCLatency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "F1TransitionLatency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "LOWLATENCY" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "Node3DLowLatency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "PciLatencyTimerControl" -Type DWord -Value "0x00000020"
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "RMDeepL1EntryLatencyUsec" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "RmGspcMaxFtuS" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "RmGspcMinFtuS" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "RmGspcPerioduS" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "RMLpwrEiIdleThresholdUs" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "RMLpwrGrIdleThresholdUs" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "RMLpwrGrRgIdleThresholdUs" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "RMLpwrMsIdleThresholdUs" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "VRDirectFlipDPCDelayUs" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "VRDirectFlipTimingMarginUs" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "VRDirectJITFlipMsHybridFlipDelayUs" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "vrrCursorMarginUs" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "vrrDeflickerMarginUs" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "vrrDeflickerMaxUs" -Type DWord -Value 1
  }
  elseif (($CheckGPURegistryKey2 -like "*GTX*") -or ($CheckGPURegistryKey2 -like "*RTX*")) {
    Write-Output "Nvidia GTX/RTX Card Registry Path 0002 Detected! Applying Nvidia Latency Tweaks..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "D3PCLatency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "F1TransitionLatency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "LOWLATENCY" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "Node3DLowLatency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "PciLatencyTimerControl" -Type DWord -Value "0x00000020"
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "RMDeepL1EntryLatencyUsec" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "RmGspcMaxFtuS" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "RmGspcMinFtuS" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "RmGspcPerioduS" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "RMLpwrEiIdleThresholdUs" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "RMLpwrGrIdleThresholdUs" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "RMLpwrGrRgIdleThresholdUs" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "RMLpwrMsIdleThresholdUs" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "VRDirectFlipDPCDelayUs" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "VRDirectFlipTimingMarginUs" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "VRDirectJITFlipMsHybridFlipDelayUs" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "vrrCursorMarginUs" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "vrrDeflickerMarginUs" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "vrrDeflickerMaxUs" -Type DWord -Value 1
  }
  elseif (($CheckGPURegistryKey3 -like "*GTX*") -or ($CheckGPURegistryKey3 -like "*RTX*")) {
    Write-Output "Nvidia GTX/RTX Card Registry Path 0003 Detected! Applying Nvidia Latency Tweaks..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "D3PCLatency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "F1TransitionLatency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "LOWLATENCY" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "Node3DLowLatency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "PciLatencyTimerControl" -Type DWord -Value "0x00000020"
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "RMDeepL1EntryLatencyUsec" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "RmGspcMaxFtuS" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "RmGspcMinFtuS" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "RmGspcPerioduS" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "RMLpwrEiIdleThresholdUs" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "RMLpwrGrIdleThresholdUs" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "RMLpwrGrRgIdleThresholdUs" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "RMLpwrMsIdleThresholdUs" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "VRDirectFlipDPCDelayUs" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "VRDirectFlipTimingMarginUs" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "VRDirectJITFlipMsHybridFlipDelayUs" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "vrrCursorMarginUs" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "vrrDeflickerMarginUs" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "vrrDeflickerMaxUs" -Type DWord -Value 1
  }
  else {
    Write-Output "No NVIDIA GTX/RTX Card Registry entry Found! Skipping..."
  }
}

#Applying AMD Tweaks If Detected!
Function AMDGPUTweaks {
  $errpref = $ErrorActionPreference #save actual preference
  $ErrorActionPreference = "silentlycontinue"
  $CheckGPURegistryKey0 = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000").DriverDesc
  $CheckGPURegistryKey1 = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001").DriverDesc
  $CheckGPURegistryKey2 = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002").DriverDesc
  $CheckGPURegistryKey3 = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003").DriverDesc
  $ErrorActionPreference = $errpref #restore previous preference
  if ($CheckGPURegistryKey0 -like "*amd*") {
    Write-Output "AMD GPU Registry Path 0000 Detected! Applying AMD Latency Tweaks..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "LTRSnoopL1Latency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "LTRSnoopL0Latency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "LTRNoSnoopL1Latency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "LTRMaxNoSnoopLatency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "KMD_RpmComputeLatency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "DalUrgentLatencyNs" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "memClockSwitchLatency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "PP_RTPMComputeF1Latency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "PP_DGBMMMaxTransitionLatencyUvd" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "PP_DGBPMMaxTransitionLatencyGfx" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "DalNBLatencyForUnderFlow" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "DalDramClockChangeLatencyNs" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "BGM_LTRSnoopL1Latency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "BGM_LTRSnoopL0Latency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "BGM_LTRNoSnoopL1Latency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "BGM_LTRNoSnoopL0Latency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "BGM_LTRMaxSnoopLatencyValue" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "BGM_LTRMaxNoSnoopLatencyValue" -Type DWord -Value 1
  }
  elseif ($CheckGPURegistryKey1 -like "*amd*") {
    Write-Output "AMD GPU Registry Path 0001 Detected! Applying AMD Latency Tweaks..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "LTRSnoopL1Latency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "LTRSnoopL0Latency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "LTRNoSnoopL1Latency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "LTRMaxNoSnoopLatency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "KMD_RpmComputeLatency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "DalUrgentLatencyNs" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "memClockSwitchLatency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "PP_RTPMComputeF1Latency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "PP_DGBMMMaxTransitionLatencyUvd" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "PP_DGBPMMaxTransitionLatencyGfx" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "DalNBLatencyForUnderFlow" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "DalDramClockChangeLatencyNs" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "BGM_LTRSnoopL1Latency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "BGM_LTRSnoopL0Latency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "BGM_LTRNoSnoopL1Latency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "BGM_LTRNoSnoopL0Latency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "BGM_LTRMaxSnoopLatencyValue" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "BGM_LTRMaxNoSnoopLatencyValue" -Type DWord -Value 1
  }
  elseif ($CheckGPURegistryKey2 -like "*amd*") {
    Write-Output "AMD GPU Registry Path 0002 Detected! Applying AMD Latency Tweaks..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "LTRSnoopL1Latency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "LTRSnoopL0Latency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "LTRNoSnoopL1Latency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "LTRMaxNoSnoopLatency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "KMD_RpmComputeLatency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "DalUrgentLatencyNs" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "memClockSwitchLatency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "PP_RTPMComputeF1Latency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "PP_DGBMMMaxTransitionLatencyUvd" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "PP_DGBPMMaxTransitionLatencyGfx" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "DalNBLatencyForUnderFlow" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "DalDramClockChangeLatencyNs" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "BGM_LTRSnoopL1Latency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "BGM_LTRSnoopL0Latency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "BGM_LTRNoSnoopL1Latency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "BGM_LTRNoSnoopL0Latency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "BGM_LTRMaxSnoopLatencyValue" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "BGM_LTRMaxNoSnoopLatencyValue" -Type DWord -Value 1
  }
  elseif ($CheckGPURegistryKey3 -like "*amd*") {
    Write-Output "AMD GPU Registry Path 0003 Detected! Applying AMD Latency Tweaks..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "LTRSnoopL1Latency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "LTRSnoopL0Latency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "LTRNoSnoopL1Latency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "LTRMaxNoSnoopLatency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "KMD_RpmComputeLatency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "DalUrgentLatencyNs" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "memClockSwitchLatency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "PP_RTPMComputeF1Latency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "PP_DGBMMMaxTransitionLatencyUvd" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "PP_DGBPMMaxTransitionLatencyGfx" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "DalNBLatencyForUnderFlow" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "DalDramClockChangeLatencyNs" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "BGM_LTRSnoopL1Latency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "BGM_LTRSnoopL0Latency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "BGM_LTRNoSnoopL1Latency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "BGM_LTRNoSnoopL0Latency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "BGM_LTRMaxSnoopLatencyValue" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "BGM_LTRMaxNoSnoopLatencyValue" -Type DWord -Value 1
  }
  else {
    Write-Output "No AMD GPU Registry entry Found! Skipping..."
  }
}


#Optimizing Network and applying Tweaks for no throttle and maximum speed!
Function NetworkOptimizations {
  Write-Output "Otimizando a rede e aplicando ajustes para máximo desempenho..."
	
  # Salvando a preferência de erro original
  $errpref = $ErrorActionPreference 
  $ErrorActionPreference = "SilentlyContinue"

  # Criando chaves de registro se não existirem
  New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" -Force | Out-Null
  New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\QoS" -Force | Out-Null
  New-Item -Path "HKLM:\SOFTWARE\Microsoft\MSMQ\Parameters" -Force | Out-Null

  # Ajustes de Registro para otimização de rede
  $regConfigs = @{
    "HKLM:\SOFTWARE\Microsoft\Internet Explorer\MAIN\FeatureControl\FEATURE_MAXCONNECTIONSPER1_0SERVER" = @("explorer.exe", 10)
    "HKLM:\SOFTWARE\Microsoft\Internet Explorer\MAIN\FeatureControl\FEATURE_MAXCONNECTIONSPERSERVER"    = @("explorer.exe", 10)
    "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider"                                     = @("LocalPriority", 4), @("HostsPriority", 5), @("DnsPriority", 6), @("NetbtPriority", 7)
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched"                                                  = @("NonBestEffortlimit", 0)
    "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\QoS"                                                 = @("Do not use NLA", "1")
    "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"                                   = @("Size", 1), @("IRPStackSize", 20)
    "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"                                          = @("MaxUserPort", 65534), @("TcpTimedWaitDelay", 30), @("DefaultTTL", 64), @("MaxNumRssCpus", 4), @("DisableTaskOffload", 0)
    "HKLM:\SOFTWARE\Microsoft\MSMQ\Parameters"                                                          = @("TCPNoDelay", 1)
    "HKLM:\SYSTEM\ControlSet001\Control\Lsa"                                                            = @("LmCompatibilityLevel", 1)
    "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"                                       = @("EnableAutoDoh", 2)
  }

  foreach ($path in $regConfigs.Keys) {
    foreach ($setting in $regConfigs[$path]) {
      Set-ItemProperty -Path $path -Name $setting[0] -Type DWord -Value $setting[1] -ErrorAction SilentlyContinue
    }
  }

  # Ajustes de TCP/IP
  Set-NetTCPSetting -SettingName internet -EcnCapability disabled | Out-Null
  Set-NetTCPSetting -SettingName internet -Timestamps disabled | Out-Null
  Set-NetTCPSetting -SettingName internet -MaxSynRetransmissions 2 | Out-Null
  Set-NetTCPSetting -SettingName internet -NonSackRttResiliency disabled | Out-Null
  Set-NetTCPSetting -SettingName internet -InitialRto 2000 | Out-Null
  Set-NetTCPSetting -SettingName internet -MinRto 300 | Out-Null
  Set-NetTCPSetting -SettingName Internet -AutoTuningLevelLocal normal | Out-Null
  Set-NetTCPSetting -SettingName internet -ScalingHeuristics disabled | Out-Null

  # Ajustes de Netsh
  $netshCommands = @(
    "int ip set global taskoffload=enabled",
    "int tcp set global ecncapability=enabled",
    "int tcp set global rss=enabled",
    "int tcp set global rsc=enabled",
    "int tcp set global dca=enabled",
    "int tcp set global netdma=enabled",
    "int tcp set global fastopen=enabled",
    "int tcp set global fastopenfallback=enabled",
    "int tcp set global prr=enabled",
    "int tcp set global pacingprofile=always",
    "int tcp set global hystart=enabled",
    "int tcp set supplemental internet enablecwndrestart=enabled",
    "int tcp set security mpp=enabled",
    "int tcp set global autotuninglevel=normal",
    "int tcp set supplemental internet congestionprovider=dctcp"
  )
  foreach ($cmd in $netshCommands) {
    netsh $cmd | Out-Null
  }

  # Ajustes globais de offload
  Set-NetOffloadGlobalSetting -ReceiveSegmentCoalescing disabled | Out-Null
  Set-NetOffloadGlobalSetting -ReceiveSideScaling enabled | Out-Null

  # Ativação e desativação de funcionalidades em adaptadores de rede
  $netAdapterSettings = @(
    "Enable-NetAdapterChecksumOffload",
    "Enable-NetAdapterIPsecOffload",
    "Enable-NetAdapterRsc",
    "Enable-NetAdapterRss",
    "Enable-NetAdapterQos",
    "Enable-NetAdapterEncapsulatedPacketTaskOffload",
    "Enable-NetAdapterSriov",
    "Enable-NetAdapterVmq"
  )
  foreach ($setting in $netAdapterSettings) {
    & $setting -Name "*" | Out-Null
  }

  Disable-NetAdapterLso -Name "*" -IPv4  | Out-Null
  Disable-NetAdapterLso -Name "*" -IPv6  | Out-Null

  # Ajustes avançados dos adaptadores de rede
  $advancedProperties = @(
    "Energy-Efficient Ethernet", "Energy Efficient Ethernet", "Ultra Low Power Mode",
    "System Idle Power Saver", "Green Ethernet", "Power Saving Mode", "Gigabit Lite",
    "EEE", "Advanced EEE", "ARP Offload", "NS Offload", "Large Send Offload v2 (IPv4)",
    "Large Send Offload v2 (IPv6)", "TCP Checksum Offload (IPv4)", "TCP Checksum Offload (IPv6)",
    "UDP Checksum Offload (IPv4)", "UDP Checksum Offload (IPv6)", "Idle Power Saving",
    "Flow Control", "Interrupt Moderation", "Reduce Speed On Power Down", "Interrupt Moderation Rate",
    "Log Link State Event", "Packet Priority & VLAN", "Priority & VLAN",
    "IPv4 Checksum Offload", "Jumbo Frame", "Maximum Number of RSS Queues"
  )

  foreach ($prop in $advancedProperties) {
    Set-NetAdapterAdvancedProperty -Name * -DisplayName $prop -DisplayValue "Disabled" -ErrorAction SilentlyContinue
  }

  # Restaurando a preferência de erro original
  $ErrorActionPreference = $errpref

  Write-Output "Otimizações de rede concluídas com sucesso!"
}

function Finished {
  Clear-Host
  Write-Colored "" "Azul"
  Write-Colored "================ Otimização Concluída ================" "Verde"
  Write-Colored "O sistema foi otimizado para desempenho em jogos." "Azul"
  Write-Colored "Reinicie o computador para aplicar todas as alterações." "Amarelo"
  
  do {
    Write-Colored "Deseja reiniciar agora? (S/N)" "Azul"
    $resposta = Read-Host "Digite 'S' para reiniciar agora ou 'N' para sair"
    $resposta = $resposta.Trim().ToUpper()
  } while ($resposta -ne 'S' -and $resposta -ne 'N')
  
  if ($resposta -eq 'S') {
    Write-Colored "Reiniciando o computador..." "Vermelho"
    Restart-Computer -Force
  }
  else {
    Write-Colored "Pressione qualquer tecla para sair..." "Azul"
    [Console]::ReadKey($true) | Out-Null
  }
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