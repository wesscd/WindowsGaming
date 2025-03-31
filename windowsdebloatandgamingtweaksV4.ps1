# windowsdebloatandgamingtweaks.ps1
# Script principal para otimização de sistemas Windows focados em jogos
# Versão: 0.7.0.4 (VM GROK)
# Autores Originais: ChrisTitusTech, DaddyMadu, wesscd
# Modificado por: César Marques
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
    "                                                                                  V0.7.2.0_",
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
  Write-Log "Iniciando verificação e instalação do Chocolatey e O&O ShutUp10." -ConsoleOutput

  try {
    # Verificar e instalar Chocolatey
    Write-Log "Verificando se o Chocolatey está instalado..." -ConsoleOutput
    Write-Output "Verificando e instalando Chocolatey, se necessário..."
    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
      Write-Log "Chocolatey não encontrado. Iniciando instalação..." -ConsoleOutput
      Set-ExecutionPolicy Bypass -Scope Process -Force -ErrorAction Stop
      [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
      
      $webClient = New-Object System.Net.WebClient -ErrorAction Stop
      $script = $webClient.DownloadString('https://chocolatey.org/install.ps1')
      Invoke-Expression $script


      Write-Log "Chocolatey instalado com sucesso." -Level "INFO" -ConsoleOutput
      Write-Output "Chocolatey instalado com sucesso."
    }
    else {
      Write-Log "Chocolatey já está instalado." -Level "INFO" -ConsoleOutput
      Write-Output "Chocolatey já está instalado."
    }

    # Instalar chocolatey-core.extension
    Write-Log "Instalando chocolatey-core.extension..." -ConsoleOutput
    choco install chocolatey-core.extension -y -ErrorAction Stop
    Write-Log "chocolatey-core.extension instalado com sucesso." -Level "INFO" -ConsoleOutput

    # Executar O&O ShutUp10
    Write-Log "Iniciando execução do O&O ShutUp10 com configurações recomendadas..." -ConsoleOutput
    Write-Output "Executando O&O ShutUp10 com as configurações recomendadas..."
    Import-Module BitsTransfer -ErrorAction Stop

    $configUrl = "https://raw.githubusercontent.com/wesscd/WindowsGaming/master/ooshutup10.cfg"
    $exeUrl = "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe"
    $configFile = "$env:TEMP\ooshutup10.cfg"
    $exeFile = "$env:TEMP\OOSU10.exe"

    Write-Log "Baixando arquivos de configuração e executável do O&O ShutUp10..." -ConsoleOutput
    Start-BitsTransfer -Source $configUrl -Destination $configFile -ErrorAction Stop
    Start-BitsTransfer -Source $exeUrl -Destination $exeFile -ErrorAction Stop

    Write-Log "Executando O&O ShutUp10..." -ConsoleOutput
    & $exeFile $configFile /quiet -ErrorAction Stop
    Start-Sleep -Seconds 10

    Write-Log "Removendo arquivos temporários do O&O ShutUp10..." -ConsoleOutput
    Remove-Item -Path $configFile, $exeFile -Force -ErrorAction Stop
    Write-Log "O&O ShutUp10 executado e arquivos temporários removidos com sucesso." -Level "INFO" -ConsoleOutput
    Write-Output "O&O ShutUp10 executado e arquivos temporários removidos."

    Write-Log "Função InstallTitusProgs concluída com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função InstallTitusProgs: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    Write-Colored $errorMessage -Color "Vermelho"
    throw  # Repropaga o erro para o caller, se necessário
  }
}

function Execute-BatchScript {
  Write-Log "Iniciando download e execução do script em batch." -ConsoleOutput

  try {
    $remoteUrl = "https://raw.githubusercontent.com/wesscd/WindowsGaming/refs/heads/main/script-ccleaner.bat"
    $localPath = "$env:TEMP\techremote.bat"

    Write-Log "Baixando script em batch de $remoteUrl para $localPath..." -ConsoleOutput
    Write-Output "Baixando e executando o script em batch..."

    # Download do script
    Invoke-WebRequest -Uri $remoteUrl -OutFile $localPath -ErrorAction Stop

    if (Test-Path $localPath) {
      Write-Log "Download concluído com sucesso. Executando o script..." -Level "INFO" -ConsoleOutput
      Write-Output "Download concluído. Executando o script..."

      # Executar o script
      Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$localPath`"" -Wait -NoNewWindow -ErrorAction Stop
      Write-Log "Script em batch executado com sucesso." -Level "INFO" -ConsoleOutput
      Write-Colored "Script em batch executado com sucesso." -Color "VerdeClaro"
    }
    else {
      $errorMessage = "O arquivo não foi baixado corretamente."
      Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
      Write-Colored $errorMessage -Color "VermelhoClaro"
      throw $errorMessage  # Lança o erro para ser capturado pelo try/catch externo
    }
  }
  catch {
    $errorMessage = "Erro ao baixar ou executar o script em batch: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    Write-Colored $errorMessage -Color "VermelhoClaro"
    throw  # Repropaga o erro para o caller
  }
  finally {
    if (Test-Path $localPath) {
      Write-Log "Removendo arquivo temporário $localPath..." -ConsoleOutput
      try {
        Remove-Item $localPath -Force -ErrorAction Stop
        Write-Log "Arquivo temporário removido com sucesso." -Level "INFO" -ConsoleOutput
        Write-Output "Arquivo temporário removido."
      }
      catch {
        $errorMessage = "Erro ao remover arquivo temporário $localPath $_"
        Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
        Write-Colored $errorMessage -Color "VermelhoClaro"
      }
    }
    else {
      Write-Log "Nenhum arquivo temporário para remover." -Level "INFO" -ConsoleOutput
    }
  }

  Write-Log "Função Execute-BatchScript concluída." -Level "INFO" -ConsoleOutput
}

function Check-Windows {
  Write-Log "Iniciando verificação da ativação do Windows." -ConsoleOutput

  try {
    Write-Output "Verificando ativação do Windows..."
    Write-Log "Verificando status de ativação com slmgr.vbs..." -ConsoleOutput

    # Verifica o status de ativação com slmgr.vbs
    $slmgrOutput = cscript //NoLogo "$env:SystemRoot\System32\slmgr.vbs" /dli | Out-String -ErrorAction Stop

    if ($slmgrOutput -match "Licensed" -or $slmgrOutput -match "Ativado") {
      Write-Log "Windows já está ativado." -Level "INFO" -ConsoleOutput
      Write-Colored "O Windows já está ativado." -Color "VerdeClaro"
    }
    else {
      Write-Log "Windows não está ativado. Solicitando ação do usuário." -Level "WARNING" -ConsoleOutput
      Write-Colored "O Windows não está ativado." -Color "AmareloClaro"

      do {
        Clear-Host
        Write-Log "Exibindo menu de opções para ativação do Windows." -ConsoleOutput
        Write-Colored "" "Azul"
        Write-Colored "================ Ativar o Windows ================" "Azul"
        Write-Colored "" "Azul"
        Write-Colored "Pressione 'C' para inserir uma nova chave de produto." "Azul"
        Write-Colored "Pressione 'K' para ativar via KMS." "Azul"
        Write-Colored "Pressione 'P' para pular a ativação." "Azul"
        $selection = Read-Host "Por favor, escolha."
        Write-Log "Usuário selecionou: $selection" -ConsoleOutput
      } until ($selection -match "(?i)^(c|k|p)$")

      switch ($selection.ToLower()) {
        "c" {
          Write-Log "Opção escolhida: Inserir nova chave de produto." -ConsoleOutput
          Write-Output "Opção escolhida: Inserir nova chave de produto."
          $productKey = Read-Host "Digite a chave de produto (ex.: XXXXX-XXXXX-XXXXX-XXXXX-XXXXX)"
          Write-Log "Chave de produto inserida: $productKey" -ConsoleOutput

          try {
            Write-Log "Aplicando chave de produto..." -ConsoleOutput
            cscript //NoLogo "$env:SystemRoot\System32\slmgr.vbs" /ipk $productKey | Out-Null -ErrorAction Stop
            $activationResult = cscript //NoLogo "$env:SystemRoot\System32\slmgr.vbs" /ato | Out-String -ErrorAction Stop

            if ($activationResult -match "successfully" -or $activationResult -match "ativado com sucesso") {
              Write-Log "Windows ativado com sucesso usando a chave fornecida." -Level "INFO" -ConsoleOutput
              Write-Colored "Windows ativado com sucesso usando a chave fornecida." -Color "VerdeClaro"
            }
            else {
              $errorMessage = "Falha ao ativar o Windows com a chave fornecida. Resultado: $activationResult"
              Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
              Write-Colored "Falha ao ativar o Windows com a chave fornecida." -Color "VermelhoClaro"
              Write-Output $activationResult
            }
          }
          catch {
            $errorMessage = "Erro ao aplicar a chave de produto: $_"
            Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
            Write-Colored $errorMessage -Color "VermelhoClaro"
          }
        }
        "k" {
          Write-Log "Opção escolhida: Ativar via KMS." -ConsoleOutput
          Write-Output "Opção escolhida: Ativar via KMS."

          try {
            Write-Log "Conectando ao servidor KMS para ativação..." -ConsoleOutput
            Write-Colored "Conectando ao servidor KMS para ativação..." -Color "AmareloClaro"

            $Xscript = Invoke-RestMethod -Uri "https://get.activated.win" -ErrorAction Stop
            Write-Host $Xscript  # Exibe o conteúdo antes de executar

            # Verifica novamente após tentativa de ativação
            $postActivation = cscript //NoLogo "$env:SystemRoot\System32\slmgr.vbs" /dli | Out-String -ErrorAction Stop

            if ($postActivation -match "Licensed" -or $postActivation -match "Ativado") {
              Write-Log "Windows ativado com sucesso via KMS." -Level "INFO" -ConsoleOutput
              Write-Colored "Windows ativado com sucesso via KMS." -Color "VerdeClaro"
            }
            else {
              $errorMessage = "Falha ao ativar o Windows via KMS. Verifique sua conexão ou o servidor KMS."
              Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
              Write-Colored $errorMessage -Color "VermelhoClaro"
            }
          }
          catch {
            $errorMessage = "Erro ao executar a ativação KMS: $_"
            Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
            Write-Colored $errorMessage -Color "VermelhoClaro"
            Write-Output "Certifique-se de ter conexão com a internet."
          }
        }
        "p" {
          Write-Log "Ativação ignorada. Windows permanece não ativado." -Level "WARNING" -ConsoleOutput
          Write-Colored "Ativação ignorada. O Windows permanece não ativado." -Color "AmareloClaro"
        }
      }
    }
  }
  catch {
    $errorMessage = "Erro ao verificar o status de ativação do Windows: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    Write-Colored $errorMessage -Color "VermelhoClaro"
    Write-Output "Certifique-se de ter permissões administrativas."
  }
  finally {
    Write-Log "Finalizando verificação de ativação do Windows." -Level "INFO" -ConsoleOutput
  }
}


function InstallMVC {
  Write-Log "Iniciando instalação do Microsoft Visual C++ 2010 Redistributable." -ConsoleOutput

  try {
    # Verificar se o Chocolatey está instalado
    Write-Log "Verificando se o Chocolatey está instalado..." -ConsoleOutput
    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
      $errorMessage = "Chocolatey não está instalado. Instale-o primeiro usando InstallTitusProgs."
      Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
      Write-Colored $errorMessage -Color "Vermelho"
      throw $errorMessage
    }

    # Verificar permissões administrativas
    $currentUser = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
      $errorMessage = "Esta função requer privilégios administrativos. Execute como administrador."
      Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
      Write-Colored $errorMessage -Color "Vermelho"
      throw $errorMessage
    }

    # Verificar se o pacote já está instalado
    Write-Log "Verificando se o vcredist2010 já está instalado..." -ConsoleOutput
    $installedPackages = choco list --local-only | Select-String "vcredist2010"
    if ($installedPackages) {
      Write-Log "vcredist2010 já está instalado. Verificando atualizações..." -Level "INFO" -ConsoleOutput
      choco upgrade vcredist2010 -y -ErrorAction Stop | Out-Null
      Write-Log "vcredist2010 atualizado com sucesso (se houver atualizações)." -Level "INFO" -ConsoleOutput
      Write-Colored "Microsoft Visual C++ 2010 Redistributable já estava instalado e foi atualizado, se necessário." -Color "VerdeClaro"
      return
    }

    # Instalar o pacote
    Write-Log "Iniciando instalação do vcredist2010 via Chocolatey..." -ConsoleOutput
    Write-Output "Instalando Microsoft Visual C++ 2010 Redistributable..."
    $installResult = choco install -y vcredist2010 -r --force --limitoutput --no-progress | Out-String -ErrorAction Stop

    if ($LASTEXITCODE -eq 0) {
      Write-Log "Microsoft Visual C++ 2010 Redistributable instalado com sucesso." -Level "INFO" -ConsoleOutput
      Write-Colored "Microsoft Visual C++ 2010 Redistributable instalado com sucesso." -Color "VerdeClaro"
    }
    else {
      $errorMessage = "Falha ao instalar vcredist2010. Saída: $installResult"
      Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
      Write-Colored "Erro ao instalar o Microsoft Visual C++ 2010 Redistributable." -Color "Vermelho"
      throw $errorMessage
    }
  }
  catch {
    $errorMessage = "Erro durante a instalação do Microsoft Visual C++ 2010 Redistributable: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    Write-Colored $errorMessage -Color "Vermelho"
    throw  # Repropaga o erro
  }
  finally {
    Write-Log "Finalizando instalação do Microsoft Visual C++ 2010 Redistributable." -Level "INFO" -ConsoleOutput
  }
}

function Install7Zip {
  Write-Log "Iniciando instalação do 7-Zip via Chocolatey." -ConsoleOutput

  try {
    # Verificar se o Chocolatey está instalado
    Write-Log "Verificando se o Chocolatey está instalado..." -ConsoleOutput
    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
      $errorMessage = "Chocolatey não está instalado. Instale-o primeiro usando InstallTitusProgs."
      Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
      Write-Colored $errorMessage -Color "Vermelho"
      throw $errorMessage
    }

    # Verificar permissões administrativas
    $currentUser = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
      $errorMessage = "Esta função requer privilégios administrativos. Execute como administrador."
      Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
      Write-Colored $errorMessage -Color "Vermelho"
      throw $errorMessage
    }

    # Verificar se o 7-Zip já está instalado
    Write-Log "Verificando se o 7-Zip já está instalado..." -ConsoleOutput
    $installedPackages = choco list --local-only | Select-String "7zip"
    if ($installedPackages) {
      Write-Log "7-Zip já está instalado. Verificando atualizações..." -Level "INFO" -ConsoleOutput
      choco upgrade 7zip -y -ErrorAction Stop | Out-Null
      Write-Log "7-Zip atualizado com sucesso (se houver atualizações)." -Level "INFO" -ConsoleOutput
      Write-Colored "7-Zip já estava instalado e foi atualizado, se necessário." -Color "VerdeClaro"
      return
    }

    # Instalar o 7-Zip
    Write-Log "Iniciando instalação do 7-Zip via Chocolatey..." -ConsoleOutput
    Write-Output "Instalando 7-Zip..."
    $installResult = choco install -y 7zip -r --force --limitoutput --no-progress | Out-String -ErrorAction Stop

    if ($LASTEXITCODE -eq 0) {
      Write-Log "7-Zip instalado com sucesso." -Level "INFO" -ConsoleOutput
      Write-Colored "7-Zip instalado com sucesso." -Color "VerdeClaro"
    }
    else {
      $errorMessage = "Falha ao instalar 7-Zip. Saída: $installResult"
      Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
      Write-Colored "Erro ao instalar o 7-Zip." -Color "Vermelho"
      throw $errorMessage
    }
  }
  catch {
    $errorMessage = "Erro durante a instalação do 7-Zip: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    Write-Colored $errorMessage -Color "Vermelho"
    throw  # Repropaga o erro
  }
  finally {
    Write-Log "Finalizando instalação do 7-Zip." -Level "INFO" -ConsoleOutput
  }
}

function InstallChocoUpdates {
  Write-Log "Iniciando atualização de todos os pacotes do Chocolatey." -ConsoleOutput

  try {
    # Verificar se o Chocolatey está instalado
    Write-Log "Verificando se o Chocolatey está instalado..." -ConsoleOutput
    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
      $errorMessage = "Chocolatey não está instalado. Instale-o primeiro usando InstallTitusProgs."
      Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
      Write-Colored $errorMessage -Color "Vermelho"
      throw $errorMessage
    }

    # Verificar permissões administrativas
    $currentUser = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
      $errorMessage = "Esta função requer privilégios administrativos. Execute como administrador."
      Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
      Write-Colored $errorMessage -Color "Vermelho"
      throw $errorMessage
    }

    # Limpar a tela e atualizar os pacotes
    Write-Log "Limpando a tela e iniciando atualização de todos os pacotes..." -ConsoleOutput
    Clear-Host
    Write-Output "Atualizando todos os pacotes instalados via Chocolatey..."

    $updateResult = choco upgrade all -y -r --limitoutput --no-progress | Out-String -ErrorAction Stop

    if ($LASTEXITCODE -eq 0) {
      Write-Log "Todos os pacotes do Chocolatey foram atualizados com sucesso." -Level "INFO" -ConsoleOutput
      Write-Colored "Atualização de todos os pacotes concluída com sucesso." -Color "VerdeClaro"
    }
    else {
      $errorMessage = "Falha ao atualizar os pacotes do Chocolatey. Saída: $updateResult"
      Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
      Write-Colored "Erro ao atualizar os pacotes do Chocolatey." -Color "Vermelho"
      throw $errorMessage
    }
  }
  catch {
    $errorMessage = "Erro durante a atualização dos pacotes do Chocolatey: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    Write-Colored $errorMessage -Color "Vermelho"
    throw  # Repropaga o erro
  }
  finally {
    Write-Log "Finalizando atualização dos pacotes do Chocolatey." -Level "INFO" -ConsoleOutput
  }
}


function AskXBOX {
  Write-Log "Iniciando função AskXBOX para gerenciar recursos do Xbox." -ConsoleOutput

  try {
    # Obter versão do Windows
    $winVer = [System.Environment]::OSVersion.Version
    $isWin11 = $winVer.Major -eq 10 -and $winVer.Build -ge 22000
    Write-Log "Versão do Windows detectada: Major $($winVer.Major), Build $($winVer.Build). Windows 11: $isWin11" -ConsoleOutput

    # Solicitar escolha do usuário
    do {
      Clear-Host
      Write-Log "Exibindo menu de opções para gerenciar recursos do Xbox." -ConsoleOutput
      Write-Colored "" "Azul"
      Write-Colored "================ Desabilitar os recursos do XBOX e todos os aplicativos relacionados? ================" "Azul"
      Write-Colored "" "Azul"
      Write-Colored "AVISO: REMOVER OS APLICATIVOS DO XBOX fará com que o Win+G não funcione!" "Vermelho"
      Write-Colored "Pressione 'D' para desabilitar os recursos do XBOX." "Azul"
      Write-Colored "Pressione 'H' para habilitar os recursos do XBOX." "Azul"
      Write-Colored "Pressione 'P' para pular isso." "Azul"
      $selection = Read-Host "Por favor, escolha"
      Write-Log "Usuário selecionou: $selection" -ConsoleOutput
    } until ($selection -match "(?i)^(d|h|p)$")

    # Processar escolha do usuário
    if ($selection -match "(?i)^d$") {
      Write-Log "Opção escolhida: Desabilitar recursos do Xbox." -ConsoleOutput
      Write-Output "Desativando recursos do Xbox..."

      try {
        $errpref = $ErrorActionPreference
        $ErrorActionPreference = "SilentlyContinue"

        $xboxApps = @(
          "Microsoft.XboxApp",
          "Microsoft.XboxIdentityProvider",
          "Microsoft.XboxSpeechToTextOverlay",
          "Microsoft.XboxGameOverlay",
          "Microsoft.Xbox.TCUI"
        )
        if ($isWin11) { 
          $xboxApps += "Microsoft.XboxGamingOverlay" 
          Write-Log "Adicionando Microsoft.XboxGamingOverlay à lista para Windows 11." -ConsoleOutput
        }

        Write-Log "Removendo aplicativos do Xbox..." -ConsoleOutput
        foreach ($app in $xboxApps) {
          $pkg = Get-AppxPackage $app -ErrorAction Stop
          if ($pkg) {
            Write-Log "Removendo aplicativo: $app" -ConsoleOutput
            $pkg | Remove-AppxPackage -ErrorAction Stop
          }
          else {
            Write-Log "Aplicativo $app não encontrado, ignorando." -Level "INFO" -ConsoleOutput
          }
        }

        Write-Log "Desativando GameDVR no registro..." -ConsoleOutput
        Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 0 -ErrorAction Stop
        if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR")) {
          Write-Log "Criando chave de registro HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR." -ConsoleOutput
          New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Force -ErrorAction Stop | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0 -ErrorAction Stop

        Write-Log "Recursos do Xbox desativados com sucesso." -Level "INFO" -ConsoleOutput
        Write-Colored "Recursos do Xbox desativados com sucesso." -Color "VerdeClaro"
      }
      catch {
        $errorMessage = "Erro ao desativar recursos do Xbox: $_"
        Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
        Write-Colored $errorMessage -Color "Vermelho"
        throw
      }
      finally {
        $ErrorActionPreference = $errpref
        Write-Log "Restaurando preferência de erro original: $errpref" -ConsoleOutput
      }
    }
    elseif ($selection -match "(?i)^h$") {
      Write-Log "Opção escolhida: Habilitar recursos do Xbox." -ConsoleOutput
      Write-Output "Habilitando recursos do Xbox..."

      try {
        $errpref = $ErrorActionPreference
        $ErrorActionPreference = "SilentlyContinue"

        $xboxApps = @(
          "Microsoft.XboxApp",
          "Microsoft.XboxIdentityProvider",
          "Microsoft.XboxSpeechToTextOverlay",
          "Microsoft.XboxGameOverlay",
          "Microsoft.Xbox.TCUI"
        )
        if ($isWin11) { 
          $xboxApps += "Microsoft.XboxGamingOverlay" 
          Write-Log "Adicionando Microsoft.XboxGamingOverlay à lista para Windows 11." -ConsoleOutput
        }

        Write-Log "Reinstalando aplicativos do Xbox..." -ConsoleOutput
        foreach ($app in $xboxApps) {
          $pkg = Get-AppxPackage -AllUsers $app -ErrorAction Stop
          if ($pkg) {
            Write-Log "Reinstalando aplicativo: $app" -ConsoleOutput
            $pkg | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" -ErrorAction Stop }
          }
          else {
            Write-Log "Aplicativo $app não encontrado para reinstalação, ignorando." -Level "WARNING" -ConsoleOutput
          }
        }

        Write-Log "Habilitando GameDVR no registro..." -ConsoleOutput
        Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 1 -ErrorAction Stop
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -ErrorAction Stop

        Write-Log "Recursos do Xbox habilitados com sucesso." -Level "INFO" -ConsoleOutput
        Write-Colored "Recursos do Xbox habilitados com sucesso." -Color "VerdeClaro"
      }
      catch {
        $errorMessage = "Erro ao habilitar recursos do Xbox: $_"
        Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
        Write-Colored $errorMessage -Color "Vermelho"
        throw
      }
      finally {
        $ErrorActionPreference = $errpref
        Write-Log "Restaurando preferência de erro original: $errpref" -ConsoleOutput
      }
    }
    else {
      Write-Log "Opção escolhida: Pular gerenciamento dos recursos do Xbox." -Level "INFO" -ConsoleOutput
      Write-Colored "Gerenciamento dos recursos do Xbox foi pulado." -Color "AmareloClaro"
    }
  }
  catch {
    $errorMessage = "Erro na função AskXBOX: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    Write-Colored $errorMessage -Color "Vermelho"
    throw
  }
  finally {
    Write-Log "Finalizando função AskXBOX." -Level "INFO" -ConsoleOutput
  }
}

function DisableNewsFeed {
  Write-Log "Iniciando função DisableNewsFeed para desativar o News Feed." -ConsoleOutput

  try {
    # Obter versão do sistema operacional
    $osVersion = [System.Environment]::OSVersion.Version
    Write-Log "Versão do sistema operacional detectada: Major $($osVersion.Major), Build $($osVersion.Build)" -ConsoleOutput

    # Verificar se é Windows 10 ou superior
    if ($osVersion.Major -eq 10) {
      Write-Log "Windows 10 detectado. Prosseguindo com a desativação do News and Interests Feed." -ConsoleOutput
      Write-Output "Disabling Windows 10 News and Interests Feed..."

      # Verificar e criar chave de registro HKLM, se necessário
      $registryPathHKLM = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds"
      if (-not (Test-Path $registryPathHKLM)) {
        Write-Log "Chave $registryPathHKLM não existe. Criando..." -ConsoleOutput
        New-Item -Path $registryPathHKLM -Force -ErrorAction Stop | Out-Null
        Write-Log "Chave $registryPathHKLM criada com sucesso." -Level "INFO" -ConsoleOutput
      }
      else {
        Write-Log "Chave $registryPathHKLM já existe. Prosseguindo com a configuração." -ConsoleOutput
      }

      # Configurar propriedade EnableFeeds
      Write-Log "Configurando EnableFeeds para 0 em $registryPathHKLM..." -ConsoleOutput
      Set-ItemProperty -Path $registryPathHKLM -Name "EnableFeeds" -Type DWord -Value 0 -ErrorAction Stop
      Write-Log "EnableFeeds configurado com sucesso." -Level "INFO" -ConsoleOutput

      # Verificar e configurar chave HKCU
      $registryPathHKCU = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds"
      if (-not (Test-Path $registryPathHKCU)) {
        Write-Log "Chave $registryPathHKCU não existe. Criando..." -ConsoleOutput
        New-Item -Path $registryPathHKCU -Force -ErrorAction Stop | Out-Null
        Write-Log "Chave $registryPathHKCU criada com sucesso." -Level "INFO" -ConsoleOutput
      }
      else {
        Write-Log "Chave $registryPathHKCU já existe. Prosseguindo com a configuração." -ConsoleOutput
      }

      Write-Log "Configurando ShellFeedsTaskbarViewMode para 2 em $registryPathHKCU..." -ConsoleOutput
      Set-ItemProperty -Path $registryPathHKCU -Name "ShellFeedsTaskbarViewMode" -Type DWord -Value 2 -ErrorAction Stop
      Write-Log "ShellFeedsTaskbarViewMode configurado com sucesso." -Level "INFO" -ConsoleOutput

      Write-Log "News and Interests Feed desativado com sucesso no Windows 10." -Level "INFO" -ConsoleOutput
      Write-Colored "News and Interests Feed desativado com sucesso." -Color "VerdeClaro"
    }
    elseif ($osVersion.Major -eq 6) {
      Write-Log "Sistema operacional anterior ao Windows 10 detectado (Major $($osVersion.Major)). News Feed não aplicável." -Level "WARNING" -ConsoleOutput
      Write-Colored "Versão do Windows anterior ao Windows 10 detectada. Desativação do News Feed não aplicável." -Color "AmareloClaro"
    }
    else {
      # Assumindo Windows 11 ou superior (Major > 10 ou build específico)
      Write-Log "Windows 11 ou superior detectado. Pulando desativação do News Feed." -Level "INFO" -ConsoleOutput
      Write-Output "Windows 11 detectado, pulando desativação do News Feed."
    }
  }
  catch {
    $errorMessage = "Erro na função DisableNewsFeed: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    Write-Colored $errorMessage -Color "Vermelho"
    throw  # Repropaga o erro
  }
  finally {
    Write-Log "Finalizando função DisableNewsFeed." -Level "INFO" -ConsoleOutput
  }
}

function SetUACLow {
  Write-Log "Iniciando função SetUACLow para reduzir o nível do UAC." -ConsoleOutput

  try {
    Write-Output "Lowering UAC level..."
    Write-Log "Reduzindo o nível do Controle de Conta de Usuário (UAC)..." -ConsoleOutput

    Write-Log "Configurando ConsentPromptBehaviorAdmin para 0..." -ConsoleOutput
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 0 -ErrorAction Stop
    Write-Log "ConsentPromptBehaviorAdmin configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Configurando PromptOnSecureDesktop para 0..." -ConsoleOutput
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 0 -ErrorAction Stop
    Write-Log "PromptOnSecureDesktop configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Nível do UAC reduzido com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função SetUACLow: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    throw  # Repropaga o erro
  }
  finally {
    Write-Log "Finalizando função SetUACLow." -Level "INFO" -ConsoleOutput
  }
}

function DisableSMB1 {
  Write-Log "Iniciando função DisableSMB1 para desativar o protocolo SMB 1.0." -ConsoleOutput

  try {
    Write-Output "Disabling SMB 1.0 protocol..."
    Write-Log "Desativando o protocolo SMB 1.0..." -ConsoleOutput

    Write-Log "Executando Set-SmbServerConfiguration para desativar SMB1..." -ConsoleOutput
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop
    Write-Log "Protocolo SMB 1.0 desativado com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função DisableSMB1: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    throw  # Repropaga o erro
  }
  finally {
    Write-Log "Finalizando função DisableSMB1." -Level "INFO" -ConsoleOutput
  }
}

function SetCurrentNetworkPrivate {
  Write-Log "Iniciando função SetCurrentNetworkPrivate para definir o perfil de rede atual como privado." -ConsoleOutput

  try {
    Write-Output "Setting current network profile to private..."
    Write-Log "Definindo o perfil de rede atual como privado..." -ConsoleOutput

    Write-Log "Executando Set-NetConnectionProfile para alterar o perfil de rede..." -ConsoleOutput
    Set-NetConnectionProfile -NetworkCategory Private -ErrorAction Stop
    Write-Log "Perfil de rede atual definido como privado com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função SetCurrentNetworkPrivate: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    throw  # Repropaga o erro
  }
  finally {
    Write-Log "Finalizando função SetCurrentNetworkPrivate." -Level "INFO" -ConsoleOutput
  }
}

function SetUnknownNetworksPrivate {
  Write-Log "Iniciando função SetUnknownNetworksPrivate para definir redes desconhecidas como privadas." -ConsoleOutput

  try {
    Write-Output "Setting unknown networks profile to private..."
    Write-Log "Definindo o perfil de redes desconhecidas como privado..." -ConsoleOutput

    # Definir o caminho do registro
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24"

    # Verificar e criar a chave de registro, se necessário
    if (-not (Test-Path $registryPath)) {
      Write-Log "Chave $registryPath não existe. Criando..." -ConsoleOutput
      New-Item -Path $registryPath -Force -ErrorAction Stop | Out-Null
      Write-Log "Chave $registryPath criada com sucesso." -Level "INFO" -ConsoleOutput
    }
    else {
      Write-Log "Chave $registryPath já existe. Prosseguindo com a configuração." -ConsoleOutput
    }

    # Configurar a propriedade Category
    Write-Log "Configurando Category para 1 em $registryPath..." -ConsoleOutput
    Set-ItemProperty -Path $registryPath -Name "Category" -Type DWord -Value 1 -ErrorAction Stop
    Write-Log "Category configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Perfil de redes desconhecidas definido como privado com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função SetUnknownNetworksPrivate: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    throw  # Repropaga o erro
  }
  finally {
    Write-Log "Finalizando função SetUnknownNetworksPrivate." -Level "INFO" -ConsoleOutput
  }
}

function DisableNetDevicesAutoInst {
  Write-Log "Iniciando função DisableNetDevicesAutoInst para desativar a instalação automática de dispositivos de rede." -ConsoleOutput

  try {
    Write-Output "Disabling automatic installation of network devices..."
    Write-Log "Desativando a instalação automática de dispositivos de rede..." -ConsoleOutput

    # Definir o caminho do registro
    $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private"

    # Verificar e criar a chave de registro, se necessário
    if (-not (Test-Path $registryPath)) {
      Write-Log "Chave $registryPath não existe. Criando..." -ConsoleOutput
      New-Item -Path $registryPath -Force -ErrorAction Stop | Out-Null
      Write-Log "Chave $registryPath criada com sucesso." -Level "INFO" -ConsoleOutput
    }
    else {
      Write-Log "Chave $registryPath já existe. Prosseguindo com a configuração." -ConsoleOutput
    }

    # Configurar a propriedade AutoSetup
    Write-Log "Configurando AutoSetup para 0 em $registryPath..." -ConsoleOutput
    Set-ItemProperty -Path $registryPath -Name "AutoSetup" -Type DWord -Value 0 -ErrorAction Stop
    Write-Log "AutoSetup configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Instalação automática de dispositivos de rede desativada com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função DisableNetDevicesAutoInst: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    throw  # Repropaga o erro
  }
  finally {
    Write-Log "Finalizando função DisableNetDevicesAutoInst." -Level "INFO" -ConsoleOutput
  }
}


function AskDefender {
  Write-Log "Iniciando função AskDefender para gerenciar o Microsoft Windows Defender." -ConsoleOutput

  try {
    # Obter versão do sistema operacional
    $osVersion = [System.Environment]::OSVersion.Version
    $isWindows11 = $osVersion.Build -ge 22000
    Write-Log "Versão do SO detectada: Build $($osVersion.Build). Windows 11: $isWindows11" -ConsoleOutput

    # Função interna para verificar privilégios administrativos
    function Test-Admin {
      $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
      $principal = New-Object Security.Principal.WindowsPrincipal $currentUser
      return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    # Verificar privilégios administrativos
    if (-not (Test-Admin)) {
      Write-Log "Script não está sendo executado como administrador. Interrompendo." -Level "ERROR" -ConsoleOutput
      Write-Colored "Este script precisa ser executado como Administrador. Por favor, execute-o novamente como Administrador." "Vermelho"
      break
    }
    Write-Log "Privilégios administrativos confirmados." -Level "INFO" -ConsoleOutput

    # Lista de tarefas do Defender
    $tasks = @(
      "\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance",
      "\Microsoft\Windows\Windows Defender\Windows Defender Cleanup",
      "\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan",
      "\Microsoft\Windows\Windows Defender\Windows Defender Verification"
    )
    Write-Log "Lista de tarefas do Defender carregada: $($tasks -join ', ')" -ConsoleOutput

    # Solicitar escolha do usuário
    do {
      Clear-Host
      Write-Log "Exibindo menu de opções para o Microsoft Windows Defender." -ConsoleOutput
      Write-Colored "" "Azul"
      Write-Colored "================ Desabilitar o Microsoft Windows Defender? ================" "Azul"
      Write-Colored "" "Azul"
      Write-Colored "Pressione 'D' para desabilitar o Microsoft Windows Defender." "Azul"
      Write-Colored "Pressione 'H' para habilitar o Microsoft Windows Defender." "Azul"
      Write-Colored "Pressione 'P' para pular isso." "Azul"
      $selection = Read-Host "Por favor, escolha."
      Write-Log "Usuário selecionou: $selection" -ConsoleOutput
    } until ($selection -match "(?i)^(d|h|p)$")

    # Processar escolha do usuário
    if ($selection -match "(?i)^d$") {
      Write-Log "Opção escolhida: Desativar o Microsoft Windows Defender." -ConsoleOutput
      Write-Output "Desativando Microsoft Windows Defender e processos relacionados..."

      if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile") {
        Write-Log "Configurando EnableFirewall para 0 em HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile..." -ConsoleOutput
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -Name "EnableFirewall" -Type DWord -Value 0 -ErrorAction Stop
        Write-Log "EnableFirewall configurado com sucesso." -Level "INFO" -ConsoleOutput
      }
      if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender")) {
        Write-Log "Chave HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender não existe. Criando..." -ConsoleOutput
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Force -ErrorAction Stop | Out-Null
        Write-Log "Chave criada com sucesso." -Level "INFO" -ConsoleOutput
      }
      Write-Log "Configurando DisableAntiSpyware para 1..." -ConsoleOutput
      Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 1 -ErrorAction Stop
      Write-Log "DisableAntiSpyware configurado com sucesso." -Level "INFO" -ConsoleOutput

      if ($osVersion.Build -eq 14393) {
        Write-Log "Removendo WindowsDefender do registro para Build 14393..." -ConsoleOutput
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsDefender" -ErrorAction Stop
        Write-Log "WindowsDefender removido com sucesso." -Level "INFO" -ConsoleOutput
      }
      elseif ($osVersion.Build -ge 15063) {
        Write-Log "Removendo SecurityHealth do registro para Build >= 15063..." -ConsoleOutput
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -ErrorAction Stop
        Write-Log "SecurityHealth removido com sucesso." -Level "INFO" -ConsoleOutput
      }

      if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet")) {
        Write-Log "Chave HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet não existe. Criando..." -ConsoleOutput
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Force -ErrorAction Stop | Out-Null
        Write-Log "Chave criada com sucesso." -Level "INFO" -ConsoleOutput
      }
      Write-Log "Configurando SpynetReporting para 0..." -ConsoleOutput
      Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Type DWord -Value 0 -ErrorAction Stop
      Write-Log "SpynetReporting configurado com sucesso." -Level "INFO" -ConsoleOutput
      Write-Log "Configurando SubmitSamplesConsent para 2..." -ConsoleOutput
      Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Type DWord -Value 2 -ErrorAction Stop
      Write-Log "SubmitSamplesConsent configurado com sucesso." -Level "INFO" -ConsoleOutput

      Write-Log "Removendo PUAProtection..." -ConsoleOutput
      Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "PUAProtection" -ErrorAction Stop
      Write-Log "PUAProtection removido com sucesso." -Level "INFO" -ConsoleOutput

      Write-Log "Desativando Controlled Folder Access..." -ConsoleOutput
      Set-MpPreference -EnableControlledFolderAccess Disabled -ErrorAction Stop
      Write-Log "Controlled Folder Access desativado com sucesso." -Level "INFO" -ConsoleOutput

      foreach ($task in $tasks) {
        Write-Log "Desativando tarefa agendada: $task..." -ConsoleOutput
        Disable-ScheduledTask -TaskName $task -ErrorAction Stop
        Write-Log "Tarefa $task desativada com sucesso." -Level "INFO" -ConsoleOutput
      }

      Write-Log "Microsoft Windows Defender desativado com sucesso." -Level "INFO" -ConsoleOutput
    }
    elseif ($selection -match "(?i)^h$") {
      Write-Log "Opção escolhida: Habilitar o Microsoft Windows Defender." -ConsoleOutput
      Write-Output "Ativando Microsoft Windows Defender e processos relacionados..."

      Write-Log "Removendo EnableFirewall do registro..." -ConsoleOutput
      Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -Name "EnableFirewall" -ErrorAction Stop
      Write-Log "EnableFirewall removido com sucesso." -Level "INFO" -ConsoleOutput

      Write-Log "Removendo DisableAntiSpyware do registro..." -ConsoleOutput
      Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -ErrorAction Stop
      Write-Log "DisableAntiSpyware removido com sucesso." -Level "INFO" -ConsoleOutput

      if ($osVersion.Build -eq 14393) {
        Write-Log "Configurando WindowsDefender no registro para Build 14393..." -ConsoleOutput
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsDefender" -Type ExpandString -Value "`"%ProgramFiles%\Windows Defender\MSASCuiL.exe`"" -ErrorAction Stop
        Write-Log "WindowsDefender configurado com sucesso." -Level "INFO" -ConsoleOutput
      }
      elseif ($osVersion.Build -ge 15063) {
        Write-Log "Configurando SecurityHealth no registro para Build >= 15063..." -ConsoleOutput
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -Type ExpandString -Value "%windir%\system32\SecurityHealthSystray.exe" -ErrorAction Stop
        Write-Log "SecurityHealth configurado com sucesso." -Level "INFO" -ConsoleOutput
      }

      Write-Log "Removendo SpynetReporting do registro..." -ConsoleOutput
      Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -ErrorAction Stop
      Write-Log "SpynetReporting removido com sucesso." -Level "INFO" -ConsoleOutput

      Write-Log "Removendo SubmitSamplesConsent do registro..." -ConsoleOutput
      Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -ErrorAction Stop
      Write-Log "SubmitSamplesConsent removido com sucesso." -Level "INFO" -ConsoleOutput

      Write-Log "Configurando PUAProtection para 1..." -ConsoleOutput
      Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "PUAProtection" -Type DWord -Value 1 -ErrorAction Stop
      Write-Log "PUAProtection configurado com sucesso." -Level "INFO" -ConsoleOutput

      foreach ($task in $tasks) {
        Write-Log "Ativando tarefa agendada: $task..." -ConsoleOutput
        Enable-ScheduledTask -TaskName $task -ErrorAction Stop
        Write-Log "Tarefa $task ativada com sucesso." -Level "INFO" -ConsoleOutput
      }

      Write-Log "Microsoft Windows Defender habilitado com sucesso." -Level "INFO" -ConsoleOutput
    }
    else {
      Write-Log "Opção escolhida: Pular gerenciamento do Microsoft Windows Defender." -Level "INFO" -ConsoleOutput
    }
  }
  catch {
    $errorMessage = "Erro na função AskDefender: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    throw  # Repropaga o erro
  }
  finally {
    Write-Log "Finalizando função AskDefender." -Level "INFO" -ConsoleOutput
  }
}

function EnableF8BootMenu {
  Write-Log "Iniciando função EnableF8BootMenu para habilitar as opções do menu de inicialização F8." -ConsoleOutput

  try {
    Write-Output "Enabling F8 boot menu options..."
    Write-Log "Habilitando as opções do menu de inicialização F8..." -ConsoleOutput

    Write-Log "Executando bcdedit para definir bootmenupolicy como Legacy..." -ConsoleOutput
    bcdedit /set bootmenupolicy Legacy -ErrorAction Stop | Out-Null
    Write-Log "Menu de inicialização F8 habilitado com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função EnableF8BootMenu: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    throw  # Repropaga o erro
  }
  finally {
    Write-Log "Finalizando função EnableF8BootMenu." -Level "INFO" -ConsoleOutput
  }
}

function DisableMeltdownCompatFlag {
  Write-Log "Iniciando função DisableMeltdownCompatFlag para desativar o flag de compatibilidade do Meltdown (CVE-2017-5754)." -ConsoleOutput

  try {
    Write-Output "Disabling Meltdown (CVE-2017-5754) compatibility flag..."
    Write-Log "Desativando o flag de compatibilidade do Meltdown (CVE-2017-5754)..." -ConsoleOutput

    Write-Log "Removendo a propriedade cadca5fe-87d3-4b96-b7fb-a231484277cc do registro..." -ConsoleOutput
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" -Name "cadca5fe-87d3-4b96-b7fb-a231484277cc" -ErrorAction Stop
    Write-Log "Flag de compatibilidade do Meltdown removido com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função DisableMeltdownCompatFlag: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    throw  # Repropaga o erro
  }
  finally {
    Write-Log "Finalizando função DisableMeltdownCompatFlag." -Level "INFO" -ConsoleOutput
  }
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

#Disabling Windows Remote Assistance.
Function DisableRemoteAssistance {
  Write-Output "Disabling Windows Remote Assistance..."
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowFullControl" -Type DWord -Value 0
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0
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
  Write-Output "Exibindo detalhes do Gerenciador de Tarefas..."

  # Define o caminho do registro
  $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager"

  # Verifica se a chave existe, senão cria
  if (!(Test-Path $regPath)) {
    Write-Output "A chave do registro não existe. Criando agora..."
    New-Item -Path $regPath -Force | Out-Null
  }

  # Define a propriedade "Preferences"
  Set-ItemProperty -Path $regPath -Name "Preferences" -Type Binary -Value ([byte[]](0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00))
  
  Write-Output "Configuração do Gerenciador de Tarefas aplicada com sucesso."
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
  Write-Output "Verificando se o Internet Explorer está instalado..."
  
  # Obtém a lista de recursos opcionais
  $features = Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -like "*Internet*" }

  # Verifica se o Internet Explorer está na lista
  $ieFeature = $features | Where-Object { $_.FeatureName -match "Internet-Explorer" }

  if ($ieFeature) {
    Write-Output "Desinstalando Internet Explorer ($($ieFeature.FeatureName))..."
    Disable-WindowsOptionalFeature -Online -FeatureName $ieFeature.FeatureName -NoRestart -ErrorAction Stop
    Write-Output "Internet Explorer desativado com sucesso."
  }
  else {
    Write-Output "Internet Explorer não encontrado ou já removido."
  }
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
  Write-Output "Desativando prompts de instalação de drivers..."

  # Define o caminho do registro
  $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverInstall"

  # Verifica se a chave existe, senão cria
  if (!(Test-Path $regPath)) {
    Write-Output "A chave do registro não existe. Criando agora..."
    New-Item -Path $regPath -Force | Out-Null
  }

  # Define a propriedade "PromptOnNewDevice"
  Set-ItemProperty -Path $regPath -Name "PromptOnNewDevice" -Type DWord -Value 0

  Write-Output "Configuração aplicada com sucesso."
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
  param (
    [string[]]$Servicos = @('SysMain', 'PcaSvc', 'DiagTrack')
  )

  # Exibir banner informativo
  Clear-Host
  Write-Colored "" "Vermelho"
  Write-Colored "======================================================" "Vermelho"
  Write-Colored "===  Servicos Essenciais para Investigacao Forense ===" "Vermelho"
  Write-Colored "======================================================" "Vermelho"
  Write-Colored "" "Vermelho"
  Write-Colored "Este menu auxilia na ativacao dos seguintes servicos:" "CinzaClaro"
  Write-Colored "- SysMain: " "Amarelo"; Write-Colored "O SysMain, anteriormente conhecido como Superfetch, e um servico do Windows que preenche a memoria RAM com aplicativos frequentemente usados para acelerar o carregamento dos programas mais utilizados." "Branco"
  Write-Colored "- PcaSvc: " "Amarelo"; Write-Colored "O PcaSvc (Program Compatibility Assistant Service) e um servico que detecta problemas de compatibilidade em programas legados e aplica correcao para melhorar a estabilidade do sistema." "Branco"
  Write-Colored "- DiagTrack: " "Amarelo"; Write-Colored "O DiagTrack (Connected User Experiences and Telemetry) coleta e envia dados de diagnostico e uso para a Microsoft, auxiliando na melhoria dos servicos e na resolucao de problemas." "Branco"
  Write-Colored "" "CinzaClaro"
  Write-Colored "Estes servicos sao essenciais para a investigacao forense de cheats em servidores de Minecraft, DayZ e FIVEM GTA5 que utilizam o Echo AntiCheat." "Amarelo"
  Write-Colored "" "Amarelo"
  Write-Colored "===============================================" "AmareloClaro"

  # Função interna para ativar um servico
  function Ativar-Servico {
    param (
      [string]$NomeServico
    )
    $servico = Get-Service -Name $NomeServico -ErrorAction SilentlyContinue
    if ($null -eq $servico) {
      Write-Colored "Servico '$NomeServico' nao encontrado." "VermelhoClaro"
      return
    }
    Write-Colored "Servico encontrado: $($servico.DisplayName) ($($servico.Name))" "CinzaClaro"
    if ($servico.Status -eq 'Running') {
      Write-Colored "Servico '$($servico.Name)' ja esta em execucao." "VerdeClaro"
    }
    else {
      Start-Service -Name $servico.Name
      Set-Service -Name $servico.Name -StartupType Automatic
      Write-Colored "Servico '$($servico.Name)' ativado com sucesso." "VerdeClaro"
    }
  }

  # Loop para cada servico
  foreach ($nomeServico in $Servicos) {
    $pergunta = "Deseja ativar o servico '$nomeServico'? (S/N): "
    $resposta = Read-Host -Prompt $pergunta
    if ($resposta.ToUpper() -eq 'S') {
      Ativar-Servico -NomeServico $nomeServico
    }
    else {
      Write-Colored "Servico '$nomeServico' nao foi ativado." "Amarelo"
    }
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
    "Microsoft.WindowsStore"
  )
  foreach ($app in $bloatware) {
    Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -ErrorAction SilentlyContinue
    Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq $app | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
  }
}

function DisableXboxFeatures {
  Write-Output "Disabling Xbox features...(tudo porcaria)"
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
  Write-Colored "" "Azul"
  Write-Colored -Text "================================" -Color "Azul"
  Write-Colored -Text " Configurando Memória Virtual " -Color "Azul"
  Write-Colored -Text "================================" -Color "Azul"
  Write-Colored "" "Azul"

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

  Disable-LSO # Desativar LSO (Large Send Offload) para todos os adaptadores de rede

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

function Disable-LSO {
  $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.InterfaceDescription -notmatch "Loopback" }

  foreach ($adapter in $adapters) {
    Write-Output "Desativando Large Send Offload (LSO) para: $($adapter.Name)"

    # Verifica se há suporte ao LSO antes de tentar desativar
    $lsoSupport = Get-NetAdapterAdvancedProperty -Name $adapter.Name -RegistryKeyword "*LsoV2IPv4" -ErrorAction SilentlyContinue
    if ($lsoSupport) {
      try {
        Disable-NetAdapterLso -Name $adapter.Name -IPv4 -ErrorAction Stop
        Disable-NetAdapterLso -Name $adapter.Name -IPv6 -ErrorAction Stop
        Write-Output "LSO desativado para: $($adapter.Name)"
      }
      catch {
        Write-Warning "Falha ao desativar LSO para: $($adapter.Name). Motivo: $($_.Exception.Message)"
      }
    }
    else {
      Write-Warning "LSO não suportado para: $($adapter.Name), ignorando."
    }
  }
}

# Disable Nagle's Algorithm
Function DisableNagle {
  $errpref = $ErrorActionPreference #save actual preference
  $ErrorActionPreference = "silentlycontinue"
  $NetworkIDS = @(
(Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\*").PSChildName
  )
  foreach ($NetworkID in $NetworkIDS) {
    Write-Output "Disabling Nagles Algorithm..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$NetworkID" -Name "TcpAckFrequency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$NetworkID" -Name "TCPNoDelay" -Type DWord -Value 1
  }
  $ErrorActionPreference = $errpref #restore previous preference
}

#setting network adabter optimal rss
Function NetworkAdapterRSS {
  $errpref = $ErrorActionPreference #save actual preference
  $ErrorActionPreference = "silentlycontinue"
  Write-Output "Setting network adapter RSS..."
  $PhysicalAdapters = Get-WmiObject -Class Win32_NetworkAdapter | Where-Object { $_.PNPDeviceID -notlike "ROOT\*" -and $_.Manufacturer -ne "Microsoft" -and $_.ConfigManagerErrorCode -eq 0 -and $_.ConfigManagerErrorCode -ne 22 }
	
  Foreach ($PhysicalAdapter in $PhysicalAdapters) {
    # $PhysicalAdapterName = $PhysicalAdapter.Name
    $DeviceID = $PhysicalAdapter.DeviceID
    If ([Int32]$DeviceID -lt 10) {
      $AdapterDeviceNumber = "000" + $DeviceID
    }
    Else {
      $AdapterDeviceNumber = "00" + $DeviceID
    }
    $KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\$AdapterDeviceNumber"
    $KeyPath2 = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\$AdapterDeviceNumber\Ndi\params\*RSS\Enum"
    $KeyPath3 = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\$AdapterDeviceNumber\Ndi\params\*RSS"
    $KeyPath4 = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\$AdapterDeviceNumber\Ndi\params\*NumRssQueues\Enum"
    $KeyPath5 = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\$AdapterDeviceNumber\Ndi\params\*NumRssQueues"
    $KeyPath6 = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\$AdapterDeviceNumber\Ndi\params\*ReceiveBuffers"
    $KeyPath7 = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\$AdapterDeviceNumber\Ndi\params\*TransmitBuffers"
		
    If (Test-Path -Path $KeyPath) {
      new-Item -Path $KeyPath2 -Force | Out-Null
      new-Item -Path $KeyPath4 -Force | Out-Null
      Set-ItemProperty -Path $KeyPath -Name "*NumRssQueues" -Type String -Value 2 | Out-Null
      Set-ItemProperty -Path $KeyPath -Name "*RSS" -Type String -Value 1 | Out-Null
      Set-ItemProperty -Path $KeyPath -Name "*RSSProfile" -Type String -Value 4 | Out-Null
      Set-ItemProperty -Path $KeyPath -Name "*RssBaseProcNumber" -Type String -Value 2 | Out-Null
      Set-ItemProperty -Path $KeyPath -Name "*MaxRssProcessors" -Type String -Value 4 | Out-Null
      Set-ItemProperty -Path $KeyPath -Name "*NumaNodeId" -Type String -Value 0 | Out-Null
      Set-ItemProperty -Path $KeyPath -Name "*RssBaseProcGroup" -Type String -Value 0 | Out-Null
      Set-ItemProperty -Path $KeyPath -Name "*RssMaxProcNumber" -Type String -Value 4 | Out-Null
      Set-ItemProperty -Path $KeyPath -Name "*RssMaxProcGroup" -Type String -Value 0 | Out-Null
      Set-ItemProperty -Path $KeyPath -Name "*ReceiveBuffers" -Type String -Value 2048 | Out-Null
      Set-ItemProperty -Path $KeyPath -Name "*TransmitBuffers" -Type String -Value 4096 | Out-Null
      New-ItemProperty -Path $KeyPath3 -Name "default" -Type String -Value 1 | Out-Null
      New-ItemProperty -Path $KeyPath3 -Name "ParamDesc" -Type String -Value "Receive Side Scaling" | Out-Null
      New-ItemProperty -Path $KeyPath3 -Name "type" -Type String -Value "enum" | Out-Null
      New-ItemProperty -Path $KeyPath2 -Name "0" -Type String -Value "Disabled" | Out-Null
      New-ItemProperty -Path $KeyPath2 -Name "1" -Type String -Value "Enabled" | Out-Null
      New-ItemProperty -Path $KeyPath4 -Name "1" -Type String -Value "1 Queue" | Out-Null
      New-ItemProperty -Path $KeyPath4 -Name "2" -Type String -Value "2 Queue" | Out-Null
      New-ItemProperty -Path $KeyPath4 -Name "3" -Type String -Value "3 Queue" | Out-Null
      New-ItemProperty -Path $KeyPath4 -Name "4" -Type String -Value "4 Queue" | Out-Null
      New-ItemProperty -Path $KeyPath5 -Name "default" -Type String -Value "2" | Out-Null
      New-ItemProperty -Path $KeyPath5 -Name "ParamDesc" -Type String -Value "Maximum Number of RSS Queues" | Out-Null
      New-ItemProperty -Path $KeyPath5 -Name "type" -Type String -Value "enum" | Out-Null
      Set-ItemProperty -Path $KeyPath6 -Name "Max" -Type String -Value 6144 | Out-Null
      Set-ItemProperty -Path $KeyPath6 -Name "Default" -Type String -Value 2048 | Out-Null
      Set-ItemProperty -Path $KeyPath7 -Name "Max" -Type String -Value 6144 | Out-Null
      Set-ItemProperty -Path $KeyPath7 -Name "Default" -Type String -Value 4096 | Out-Null
    }
    Else {
      Write-Colored "Caminho ($KeyPath) Nao encontrado." "Vermelho"
    }
  }
  $ErrorActionPreference = $errpref #restore previous preference
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
