# windowsdebloatandgamingtweaks.ps1
# Script principal para otimização de sistemas Windows focados em jogos
# Versão: V0.7.2.5.3 (GROK / GPT)
# Autores Originais: ChrisTitusTech, DaddyMadu
# Modificado por: César Marques.
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

function Verify-FileHash {
  param (
    [string]$FilePath,
    [string]$ExpectedHash
  )

  try {
    $actualHash = Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction Stop | Select-Object -ExpandProperty Hash
    if ($actualHash -ne $ExpectedHash) {
      Write-Log "Hash do arquivo $FilePath não corresponde ao esperado. Download pode estar corrompido ou comprometido." -Level "ERROR" -ConsoleOutput
      Remove-Item -Path $FilePath -Force -ErrorAction SilentlyContinue
      throw "Falha na verificação de integridade."
    }
    Write-Log "Verificação de integridade do arquivo $FilePath concluída com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    Write-Log "Erro ao verificar o hash do arquivo $FilePath $_" -Level "ERROR" -ConsoleOutput
    throw
  }
}

function Write-Log {
  param (
    [string]$Message,
    [string]$Level = "INFO", # Pode ser "INFO", "WARNING", "ERROR"
    [switch]$ConsoleOutput = $false,
    [int]$MaxLogSizeMB = 10, # Tamanho máximo do log em MB (padrão: 10MB)
    [int]$MaxLogFiles = 5    # Número máximo de arquivos de log rotacionados
  )

  # Definir caminho base para logs (usando Temp do usuário)
  $logBasePath = "$env:TEMP"
  $logBaseName = "optimization_log"
  $logExtension = ".txt"

  # Gerar nome do arquivo com timestamp para evitar sobrescrita
  $timestamp = Get-Date -Format "ddMMyyyy_HHmmss"
  $logPath = Join-Path -Path $logBasePath -ChildPath "$logBaseName_$timestamp$logExtension"

  # Verificar se o diretório de logs existe e é acessível
  if (-not (Test-Path $logBasePath)) {
    try {
      New-Item -Path $logBasePath -ItemType Directory -Force -ErrorAction Stop | Out-Null
      Write-Verbose "Diretório de logs criado em $logBasePath."
    }
    catch {
      Write-Error "Não foi possível criar ou acessar o diretório de logs $logBasePath. Erro: $_"
      return
    }
  }

  # Verificar e gerenciar rotação de logs
  $existingLogs = Get-ChildItem -Path $logBasePath -Filter "$logBaseName*_*$logExtension" | Sort-Object LastWriteTime -Descending
  if ($existingLogs.Count -ge $MaxLogFiles) {
    $logsToDelete = $existingLogs | Select-Object -Skip ($MaxLogFiles - 1)
    foreach ($log in $logsToDelete) {
      try {
        Remove-Item -Path $log.FullName -Force -ErrorAction Stop
        Write-Verbose "Log antigo removido: $($log.FullName)"
      }
      catch {
        Write-Warning "Não foi possível remover o log antigo $($log.FullName). Erro: $_"
      }
    }
  }

  # Verificar tamanho atual do log mais recente (se existir)
  $latestLog = $existingLogs | Select-Object -First 1
  if ($latestLog -and ($latestLog.Length / 1MB) -gt $MaxLogSizeMB) {
    Write-Verbose "Tamanho do log excedeu $MaxLogSizeMB MB. Criando novo log."
  }

  # Formatar a entrada do log
  $logTimestamp = Get-Date -Format "dd-MM-yyyy HH:mm:ss"
  $logEntry = "[$logTimestamp] [$Level] $Message"

  # Tentar escrever no arquivo de log
  try {
    # Criar o arquivo se não existir
    if (-not (Test-Path $logPath)) {
      New-Item -Path $logPath -ItemType File -Force -ErrorAction Stop | Out-Null
      Add-Content -Path $logPath -Value "Início do log em $logTimestamp" -ErrorAction Stop
    }

    # Adicionar a nova entrada
    Add-Content -Path $logPath -Value $logEntry -ErrorAction Stop

    # Saída no console, se solicitado
    if ($ConsoleOutput) {
      switch ($Level.ToUpper()) {
        "ERROR" {
          Write-Colored "$logEntry" -Color "Vermelho"
        }
        "WARNING" {
          Write-Colored "$logEntry" -Color "AmareloClaro"
        }
        default {
          Write-Colored "$logEntry" -Color "VerdeClaro"
        }
      }
    }
  }
  catch {
    # Se falhar ao escrever no log, exibir mensagem de erro
    $errorMsg = "Falha ao escrever no log $logPath. Erro: $_"
    Write-Error $errorMsg

    # Tentar registrar o erro em um log de emergência (se possível)
    $emergencyLog = Join-Path -Path $logBasePath -ChildPath "emergency_log.txt"
    try {
      Add-Content -Path $emergencyLog -Value $errorMsg -ErrorAction Stop
    }
    catch {
      Write-Error "Não foi possível registrar no log de emergência. Erro: $_"
    }

    # Forçar saída no console, mesmo sem ConsoleOutput
    Write-Colored "Erro crítico no logging: $errorMsg" -Color "Vermelho"
  }
}

# Notas adicionais:
# - A função agora usa um nome de arquivo único com timestamp para evitar sobrescrita.
# - Implementada rotação de logs para manter até $MaxLogFiles arquivos, excluindo os mais antigos.
# - Adicionado limite de tamanho do log ($MaxLogSizeMB).
# - Melhorada a gestão de erros com blocos try/catch para capturar falhas ao criar ou escrever no log.
# - Adicionado log de emergência caso o log principal falhe.

# Exemplo de uso:
# Write-Log "Iniciando processo" -Level "INFO" -ConsoleOutput
# Write-Log "Erro detectado" -Level "ERROR" -ConsoleOutput


function Show-ProgressBar {
  param (
    [int]$CurrentStep,
    [int]$TotalSteps,
    [string]$TaskName,
    [int]$EstimatedTimeSeconds = 5
  )

  # Obter as dimensões do console
  $consoleWidth = $Host.UI.RawUI.BufferSize.Width
  $consoleHeight = $Host.UI.RawUI.BufferSize.Height

  # Calcular posição no rodapé (última linha ou penúltima, deixando espaço para outras saídas)
  $footerLine = $consoleHeight - 2  # Deixar uma linha acima para outras mensagens

  # Calcular progresso
  $percentComplete = [math]::Round(($CurrentStep / $TotalSteps) * 100)
  $barLength = 50
  $filledLength = [math]::Round(($percentComplete / 100) * $barLength)
  $emptyLength = $barLength - $filledLength
  $filledBar = "█" * $filledLength
  $emptyBar = "-" * $emptyLength
  $remaining = [math]::Round(($TotalSteps - $CurrentStep) * $EstimatedTimeSeconds / 60, 2)
  $progressBar = "[$filledBar$emptyBar] $percentComplete% (Restam ~$remaining minutos) - $TaskName"

  # Mover o cursor para o rodapé e escrever a barra
  [Console]::SetCursorPosition(0, $footerLine)
  Write-Host (" " * $consoleWidth) -NoNewline  # Limpar a linha anterior
  [Console]::SetCursorPosition(0, $footerLine)
  Write-Colored $progressBar -Color "VerdeClaro" -NoNewline

  # Restaurar o cursor para a posição anterior (se necessário)
  [Console]::SetCursorPosition(0, $consoleHeight - 1)
}

# Exibir introdução
function Show-Intro {
  Clear-Host

  # Obter as informações do computador
  $hostName = [System.Environment]::MachineName
  $osName = (Get-ComputerInfo).WindowsProductName
  $osVersion = (Get-ComputerInfo).WindowsVersion
  $processor = (Get-CimInstance Win32_Processor).Name
  $ramGB = [math]::Round((Get-ComputerInfo).CsTotalPhysicalMemory / 1GB, 2)

  # Calcular o preenchimento para alinhamento (garantir que o resultado seja >= 0)
  #$hostNamePadding = [math]::Max(0, 35 - $hostName.Length)
  #$osNamePadding = [math]::Max(0, 35 - $osName.Length)
  #$osVersionPadding = [math]::Max(0, 35 - $osVersion.Length)
  #$ramPadding = [math]::Max(0, 35 - ($ramGB.ToString() + " GB").Length)

  # Construir o array $intro
  $intro = @(
    "",
    "",
    "████████╗███████╗ ██████╗██╗  ██╗    ██████╗ ███████╗███╗   ███╗ ██████╗ ████████╗███████╗",
    "╚══██╔══╝██╔════╝██╔════╝██║  ██║    ██╔══██╗██╔════╝████╗ ████║██╔═══██╗╚══██╔══╝██╔════╝",
    "   ██║   █████╗  ██║     ███████║    ██████╔╝████X╗  ██╔████╔██║██║   ██║   ██║   █████╗  ",
    "   ██║   ██╔══╝  ██║     ██╔══██║    ██╔══██╗██╔══╝  ██║╚██╔╝██║██║   ██║   ██║   ██╔══╝  ",
    "   ██║   ███████╗╚██████╗██║  ██║    ██║  ██║███████╗██║ ╚═╝ ██║╚██████╔╝   ██║   ███████╗",
    "   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝    ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝ ╚═════╝    ╚═╝   ╚══════╝",
    "                                                                                  V0.7.2.5.3",
    "",
    "Bem-vindo ao TechRemote Ultimate Windows Debloater Gaming",
    "Este script otimizará o desempenho do seu sistema Windows.",
    "Um ponto de restauração será criado antes de prosseguir.",
    "",
    "╔═════════════════════════════════════════════════════════════════════════════════════════╗",
    "╠═══════════════════════════════ Informações do Computador ═══════════════════════════════╣",
    "╚═════════════════════════════════════════════════════════════════════════════════════════╝",
    "",
    "≫ Nome do Host: $hostName"# + (" " * $hostNamePadding),
    "≫ Sistema Operacional: $osName"# + (" " * $osNamePadding),
    "≫ Versão do Windows: $osVersion" #+ (" " * $osVersionPadding),
    "≫ Processador: $processor",
    "≫ Memória RAM: $ramGB GB"# + (" " * $ramPadding),
    "",
    "Pressione qualquer tecla para continuar..."
  )

  $colors = @(
    "VerdeClaro", "VerdeClaro", "VerdeClaro", "VerdeClaro", "VerdeClaro", "VerdeClaro", "VerdeClaro", "VerdeClaro", "VerdeClaro", 
    "AzulClaro",
    "AmareloClaro", "AmareloClaro", "VermelhoClaro", 
    "Amarelo",
    "Amarelo", "Amarelo", "Amarelo", "Amarelo", "Amarelo", "Amarelo", "Amarelo", "Amarelo", "Amarelo", "Amarelo",
    "Verde"
  )

  for ($i = 0; $i -lt $intro.Length; $i++) {
    $color = if ($i -lt $colors.Length) { $colors[$i] } else { "Branco" }
    Write-Colored $intro[$i] $color
  }

  [Console]::ReadKey($true)

  Clear-Host
}

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

# Definir hashtable de funções de tweaks
$tweakFunctions = @{
  # Funções gerais
  "RequireAdmin"                = { RequireAdmin }
  "CreateRestorePoint"          = { CreateRestore }
  "InstallChocolateyPackages"   = { InstallChocolateyPackages }
  "DownloadFiles"               = { DownloadFiles }
  "Check-Windows"               = { Check-Windows }
  "Execute-BatchScript"         = { Execute-BatchScript }
  "InstallChocoUpdates"         = { InstallChocoUpdates }
  "Download-GPUFiles"           = { Download-GPUFiles }
  "EnableUltimatePower"         = { EnableUltimatePower }
  "ManagePowerProfiles"         = { ManagePowerProfiles }
  "AskDefender"                 = { AskDefender }
  "AskXBOX"                     = { AskXBOX }
  "Windows11Extras"             = { Windows11Extras }
  "DebloatAll"                  = { DebloatAll }
  "RemoveBloatRegistry"         = { RemoveBloatRegistry }
  "Remove-OneDrive"             = { Remove-OneDrive }
  "UninstallMsftBloat"          = { UninstallMsftBloat }
  "DisableNewsFeed"             = { DisableNewsFeed }
  "SetUACLow"                   = { SetUACLow }
  "DisableSMB1"                 = { DisableSMB1 }
  "SetCurrentNetworkPrivate"    = { SetCurrentNetworkPrivate }
  "SetUnknownNetworksPrivate"   = { SetUnknownNetworksPrivate }
  "DisableNetDevicesAutoInst"   = { DisableNetDevicesAutoInst }
  "EnableF8BootMenu"            = { EnableF8BootMenu }
  "ConfigureWindowsUpdate"      = { ConfigureWindowsUpdate }
  "DisableMeltdownCompatFlag"   = { DisableMeltdownCompatFlag }
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
  
  "Set-RamThreshold"            = { Set-RamThreshold }
  "Set-MemoriaVirtual-Registry" = { Set-MemoriaVirtual-Registry }
  "DownloadAndExtractISLC"      = { DownloadAndExtractISLC }
  "UpdateISLCConfig"            = { UpdateISLCConfig }
  "ApplyPCOptimizations"        = { ApplyPCOptimizations }
  "MSIMode"                     = { MSIMode }
  "OptimizeGPUTweaks"           = { OptimizeGPUTweaks }
  "OptimizeNetwork"             = { OptimizeNetwork }

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
  "InstallChocolateyPackages",
  "DownloadFiles",
  "Check-Windows",
  "Execute-BatchScript",
  "InstallChocoUpdates",
  "EnableUltimatePower",
  "ManagePowerProfiles",
  "AskDefender",
  "AskXBOX",
  "Windows11Extras",
  "DebloatAll",
  "RemoveBloatRegistry",
  "Remove-OneDrive -AskUser",
  "UninstallMsftBloat",
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
  "OptimizeGPUTweaks",
  "OptimizeNetwork",
  #Continuação dos tweaks existentes
  "EnableF8BootMenu",
  "ConfigureWindowsUpdate",
  "DisableMeltdownCompatFlag",
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

function Execute-BatchScript {
  Write-Log "Iniciando download e execução do script em batch." -ConsoleOutput

  try {
    $remoteUrl = "https://raw.githubusercontent.com/wesscd/WindowsGaming/refs/heads/main/script-ccleaner.bat"
    $localPath = "$env:TEMP\techremote.bat"
    $expectedHash = "319048D53494BFAD71260B6415A2FFC90F0A83565A52856DFAE70810B40E593A"  # hash real

    Write-Log "Baixando script em batch de $remoteUrl para $localPath..." -ConsoleOutput
    Write-Output "Baixando e executando o script em batch..."

    # Download do script
    Invoke-WebRequest -Uri $remoteUrl -OutFile $localPath -ErrorAction Stop

    # Verificar hash
    Verify-FileHash -FilePath $localPath -ExpectedHash $expectedHash

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
      throw $errorMessage  # Lança o erro
    }
  }
  catch {
    $errorMessage = "Erro ao baixar ou executar o script em batch: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    Write-Colored $errorMessage -Color "VermelhoClaro"
    throw  # Repropaga o erro
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
    Write-Log "Função Execute-BatchScript concluída." -Level "INFO" -ConsoleOutput
  }
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

      Clear-Host
      Write-Log "Exibindo menu de opções para ativação do Windows." -ConsoleOutput
      $banner = @(
        "",
        "",
        "╔════════════════════════════════════════╗",
        "╠═══════════ Ativar o Windows ═══════════╣",
        "╚════════════════════════════════════════╝",
        "",
        "≫ Este menu permite ativar o Windows caso ele não esteja ativado.",
        "≫ Você pode inserir uma chave de produto ou usar um servidor KMS para ativação.",
        "",
        "≫ Pressione 'C' para inserir uma nova chave de produto.",
        "≫ Pressione 'K' para ativar via KMS.",
        "≫ Pressione 'P' para pular a ativação.",
        ""
        
      )

      $colors = @(
        "Branco", "Branco", 
        "Amarelo", "Amarelo", "Amarelo", 
        "Branco", 
        "AmareloClaro", "AmareloClaro", 
        "Branco", 
        "AmareloClaro", "AmareloClaro", "AmareloClaro", 
        "Branco"
      )

      for ($i = 0; $i -lt $banner.Length; $i++) {
        $color = if ($i -lt $colors.Length) { $colors[$i] } else { "Branco" }
        Write-Colored $banner[$i] $color
      }

      do {
        
        Write-Colored "" "Branco"
        Write-Colored "Digite sua escolha (C/K/P):" "Cyan"
        $selection = Read-Host
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

function InstallChocolateyPackages {
  [CmdletBinding()]
  Param (
    # Lista de pacotes a serem instalados via Chocolatey
    [string[]]$Packages = @("vcredist2010", "7zip", "vcredist140", "vcredist2013", "directx")

  )

  Write-Log "Iniciando instalação de pacotes via Chocolatey..." -Level "INFO" -ConsoleOutput

  if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
    Write-Log "Chocolatey não encontrado. Instalando..." -Level "INFO" -ConsoleOutput
    try {
      Set-ExecutionPolicy Bypass -Scope Process -Force
      [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
      Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
      Write-Log "Chocolatey instalado com sucesso." -Level "INFO" -ConsoleOutput
    }
    catch {
      Write-Log "Erro ao instalar Chocolatey: $_" -Level "ERROR" -ConsoleOutput
      return
    }
  }
  else {
    Write-Log "Chocolatey já instalado." -Level "INFO" -ConsoleOutput
  }

  foreach ($package in $Packages) {
    Write-Log "Instalando/atualizando $package..." -Level "INFO" -ConsoleOutput
    try {
      choco install $package -y --force | Out-Null
      Write-Log "$package instalado com sucesso." -Level "INFO" -ConsoleOutput
    }
    catch {
      Write-Log "Erro ao instalar $package $_" -Level "ERROR" -ConsoleOutput
    }
  }

  Write-Log "Instalação de pacotes concluída." -Level "INFO" -ConsoleOutput
}

function DownloadFiles {
  [CmdletBinding()]
  Param (
    [hashtable]$BaseItems = @{
      "MSI_Util"            = @{
        Url         = "https://github.com/wesscd/WindowsGaming/raw/refs/heads/main/MSI_util_v3.exe"
        Hash        = "695800AFAD96F858A3F291B7DF21C16649528F13D39B63FB7C233E5676C8DF6F"
        Destination = "$env:TEMP\GPU\MSI_util_v3.exe"
        Execute     = $false
      }
      "IObit_DriverBooster" = @{
        Url         = "https://github.com/wesscd/WindowsGaming/raw/refs/heads/main/IObit.Driver.Booster.Pro.8.1.0.276.Portable.rar"
        Hash        = "E171C6298F8D01170668754C6625CA065AE76CCD79D6B472EE8CDC40A6942653"
        Destination = "$env:TEMP\GPU\IObit.Driver.Booster.Pro.8.1.0.276.Portable.rar"
        Execute     = $false
      }
    },
    [hashtable]$GpuItems = @{
      "OOSU10"        = @{
        Url               = "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe"
        Hash              = "6FF124ADBD65B5C74EDCC5A60B386919542CA2A83BC4FCF95DB1274AF7963C6E"
        Destination       = "$env:TEMP\OOSU10.exe"
        ConfigUrl         = "https://raw.githubusercontent.com/wesscd/WindowsGaming/master/ooshutup10.cfg"
        ConfigHash        = "C8FA1E1EECCD10230452FC3D2E08F882B0AF7710A6CCDA35DB17E97394B305C9"
        ConfigDestination = "$env:TEMP\ooshutup10.cfg"
        Execute           = $true
        Args              = "$env:TEMP\ooshutup10.cfg /quiet /nosrp"
      }
      "NVIDIA_Driver" = @{
        Url         = "https://us.download.nvidia.com/nvapp/client/11.0.3.218/NVIDIA_app_v11.0.3.218.exe"
        Hash        = "C19A150E53427175E5996100A25ED016F6730B627B1D6B85813811A8751C77B7"
        Destination = "$env:TEMP\GPU\NVIDIA_app_v11.0.3.218.exe"
        Execute     = $false
      }
      "AMD_Driver"    = @{
        Url         = "https://github.com/wesscd/WindowsGaming/raw/refs/heads/main/AMD_ADRENALIN_WEB.exe"
        Hash        = "87888CE67AF3B7A1652FF134192420CA4CE644EFFB8368E570707A9E224F02F2"
        Destination = "$env:TEMP\GPU\AMD_ADRENALIN_WEB.exe"
        Execute     = $false
      }
    }
  )

  Write-Log "Iniciando download de arquivos..." -Level "INFO" -ConsoleOutput

  # Criar pasta GPU
  $gpuPath = "$env:TEMP\GPU"
  if (-not (Test-Path $gpuPath)) { New-Item -Path $gpuPath -ItemType Directory -Force | Out-Null }

  # Detectar GPU
  $gpuName = (Get-CimInstance Win32_VideoController).Name
  Write-Log "GPU detectada: $gpuName" -Level "INFO" -ConsoleOutput
  $isNvidia = $gpuName -like "*NVIDIA*" -or $gpuName -like "*GTX*" -or $gpuName -like "*RTX*"
  $isAMD = $gpuName -like "*AMD*" -or $gpuName -like "*Radeon*" -or $gpuName -like "*RX*"

  # Definir downloads base
  $downloads = @{}
  foreach ($key in $BaseItems.Keys) {
    $downloads[$key] = $BaseItems[$key]
  }

  # Adicionar downloads específicos por GPU
  $downloads["OOSU10"] = $GpuItems["OOSU10"]  # Sempre incluído
  if ($isNvidia) {
    Write-Log "Placa NVIDIA detectada. Adicionando driver NVIDIA..." -Level "INFO" -ConsoleOutput
    $downloads["NVIDIA_Driver"] = $GpuItems["NVIDIA_Driver"]
  }
  elseif ($isAMD) {
    Write-Log "Placa AMD detectada. Adicionando driver AMD..." -Level "INFO" -ConsoleOutput
    $downloads["AMD_Driver"] = $GpuItems["AMD_Driver"]
  }

  foreach ($itemName in $downloads.Keys) {
    $item = $downloads[$itemName]

    # Baixar arquivo principal
    Write-Log "Baixando $itemName de $($item.Url)..." -Level "INFO" -ConsoleOutput
    try {
      Invoke-WebRequest -Uri $item.Url -OutFile $item.Destination -ErrorAction Stop
      $hash = (Get-FileHash -Path $item.Destination -Algorithm SHA256).Hash
      if ($hash -ne $item.Hash) {
        Write-Log "Hash de $itemName não corresponde. Esperado: $($item.Hash), Obtido: $hash" -Level "ERROR" -ConsoleOutput
        continue
      }
      Write-Log "$itemName baixado e verificado com sucesso." -Level "INFO" -ConsoleOutput
    }
    catch {
      Write-Log "Erro ao baixar $itemName $_" -Level "ERROR" -ConsoleOutput
      continue
    }

    # Baixar arquivo de configuração (se aplicável)
    if ($item.ConfigUrl) {
      Write-Log "Baixando configuração de $itemName de $($item.ConfigUrl)..." -Level "INFO" -ConsoleOutput
      try {
        Invoke-WebRequest -Uri $item.ConfigUrl -OutFile $item.ConfigDestination -ErrorAction Stop
        $configHash = (Get-FileHash -Path $item.ConfigDestination -Algorithm SHA256).Hash
        if ($configHash -ne $item.ConfigHash) {
          Write-Log "Hash da configuração de $itemName não corresponde. Esperado: $($item.ConfigHash), Obtido: $configHash" -Level "ERROR" -ConsoleOutput
          continue
        }
        Write-Log "Configuração de $itemName baixada e verificada com sucesso." -Level "INFO" -ConsoleOutput
      }
      catch {
        Write-Log "Erro ao baixar configuração de $itemName $_" -Level "ERROR" -ConsoleOutput
        continue
      }
    }

    # Executar (se aplicável)
    if ($item.Execute) {
      # Trecho original de execução do O&O ShutUp10
      Write-Log "Executando O&O ShutUp10..." -ConsoleOutput
      try {
        & $item.Destination $item.ConfigDestination /quiet -ErrorAction Stop  # Substitui Start-Process conforme original
        Start-Sleep -Seconds 10  # Atraso de 10 segundos conforme original
        Write-Log "Removendo arquivos temporários do O&O ShutUp10..." -ConsoleOutput
        Remove-Item -Path $item.ConfigDestination, $item.Destination -Force -ErrorAction Stop
        Write-Log "O&O ShutUp10 executado e arquivos temporários removidos com sucesso." -Level "INFO" -ConsoleOutput
        Write-Output "O&O ShutUp10 executado e arquivos temporários removidos."
      }
      catch {
        Write-Log "Erro ao executar ou limpar O&O ShutUp10: $_" -Level "ERROR" -ConsoleOutput
      }
    }
  }

  Write-Log "Download de arquivos concluído." -Level "INFO" -ConsoleOutput
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
    Clear-Host
    Write-Log "Exibindo menu de opções para gerenciar recursos do Xbox." -ConsoleOutput
    $banner = @(
      "",
      "",
      "╔════════════════════════════════════════╗",
      "╠══════ Gerenciar Recursos do Xbox ══════╣",
      "╚════════════════════════════════════════╝",
      "",
      "≫ Este menu permite gerenciar os recursos e aplicativos relacionados ao Xbox.",
      "≫ AVISO: Desabilitar os aplicativos do Xbox fará com que o Win+G (Game Bar) não funcione!",
      "",
      "≫ Pressione 'D' para desabilitar os recursos do Xbox.",
      "≫ Pressione 'H' para habilitar os recursos do Xbox.",
      "≫ Pressione 'P' para pular esta etapa.",
      ""
      
    )

    $colors = @(
      "Branco", "Branco", 
      "Amarelo", "Amarelo", "Amarelo", 
      "Branco", 
      "AmareloClaro", "AmareloClaro", 
      "Branco", 
      "AmareloClaro", "AmareloClaro", "AmareloClaro", 
      "Branco"
    )

    for ($i = 0; $i -lt $banner.Length; $i++) {
      $color = if ($i -lt $colors.Length) { $colors[$i] } else { "Branco" }
      Write-Colored $banner[$i] $color
    }

    do {
      
      Write-Colored "" "Branco"
      Write-Colored "Digite sua escolha (D/H/P):" "Cyan"
      $selection = Read-Host
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

        Write-Log "Removendo aplicativos do Xbox para todos os usuários..." -ConsoleOutput
        foreach ($app in $xboxApps) {
          $pkgs = Get-AppxPackage -Name $app -AllUsers -ErrorAction Stop
          if ($pkgs) {
            Write-Log "Removendo aplicativo: $app" -ConsoleOutput
            $pkgs | Remove-AppxPackage -ErrorAction Stop
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
          $pkgs = Get-AppxPackage -AllUsers $app -ErrorAction Stop
          if ($pkgs) {
            Write-Log "Reinstalando aplicativo: $app" -ConsoleOutput
            $pkgs | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" -ErrorAction Stop }
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
      $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()

      # Verificar se o script tem permissão para modificar HKCU
      try {
        if (-not (Test-Path $registryPathHKCU)) {
          Write-Log "Chave $registryPathHKCU não existe. Criando..." -ConsoleOutput
          New-Item -Path $registryPathHKCU -Force -ErrorAction Stop | Out-Null
          Write-Log "Chave $registryPathHKCU criada com sucesso." -Level "INFO" -ConsoleOutput
        }
        else {
          Write-Log "Chave $registryPathHKCU já existe. Prosseguindo com a configuração." -ConsoleOutput
        }

        # Tentar configurar a propriedade com tratamento de erro adicional
        Write-Log "Configurando ShellFeedsTaskbarViewMode para 2 em $registryPathHKCU..." -ConsoleOutput
        Set-ItemProperty -Path $registryPathHKCU -Name "ShellFeedsTaskbarViewMode" -Type DWord -Value 2 -ErrorAction Stop
        Write-Log "ShellFeedsTaskbarViewMode configurado com sucesso." -Level "INFO" -ConsoleOutput
      }
      catch [System.UnauthorizedAccessException] {
        Write-Log "Sem permissão para modificar $registryPathHKCU. Tente executar o script como o usuário atual ou com permissões elevadas." -Level "WARNING" -ConsoleOutput
        Write-Colored "Não foi possível desativar o News Feed no perfil do usuário atual devido a restrições de permissão. Execute o script como o usuário ou contate o administrador." -Color "AmareloClaro"
      }
      catch {
        $errorMessage = "Erro ao configurar $registryPathHKCU $_" #comentando para atualizar........................
        Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
        Write-Colored $errorMessage -Color "Vermelho"
        throw
      }

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
    Clear-Host
    Write-Log "Exibindo menu de opções para o Microsoft Windows Defender." -ConsoleOutput
    $banner = @(
      "",
      "",
      "╔══════════════════════════════════════════╗",
      "╠═══════ Gerenciar Windows Defender ═══════╣",
      "╚══════════════════════════════════════════╝",
      "",
      "≫ Este menu permite gerenciar o Microsoft Windows Defender.",
      "≫ Você pode desabilitar ou habilitar o Defender e suas tarefas associadas.",
      "",
      "≫ Pressione 'D' para desabilitar o Microsoft Windows Defender.",
      "≫ Pressione 'H' para habilitar o Microsoft Windows Defender.",
      "≫ Pressione 'P' para pular esta etapa.",
      ""
    )

    $colors = @(
      "Branco", "Branco", 
      "Amarelo", "Amarelo", "Amarelo", 
      "Branco", 
      "AmareloClaro", "AmareloClaro", 
      "Branco", 
      "AmareloClaro", "AmareloClaro", "AmareloClaro", 
      "Branco"
    )

    for ($i = 0; $i -lt $banner.Length; $i++) {
      $color = if ($i -lt $colors.Length) { $colors[$i] } else { "Branco" }
      Write-Colored $banner[$i] $color
    }

    do {
      
      Write-Colored "" "Branco"
      Write-Colored "Digite sua escolha (D/H/P):" "Cyan"
      $selection = Read-Host
      Write-Log "Usuário selecionou: $selection" -ConsoleOutput
    } until ($selection -match "(?i)^(d|h|p)$")

    # Processar escolha do usuário
    if ($selection -match "(?i)^d$") {
      Write-Log "Opção escolhida: Desativar o Microsoft Windows Defender." -ConsoleOutput
      Write-Output "Desativando Microsoft Windows Defender e processos relacionados..."

      # Configurações do Firewall
      if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile") {
        Write-Log "Configurando EnableFirewall para 0 em HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile..." -ConsoleOutput
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -Name "EnableFirewall" -Type DWord -Value 0 -ErrorAction Stop
        Write-Log "EnableFirewall configurado com sucesso." -Level "INFO" -ConsoleOutput
      }

      # Criar chave do Defender se não existir
      $defenderPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
      if (-not (Test-Path $defenderPath)) {
        Write-Log "Chave $defenderPath não existe. Criando..." -ConsoleOutput
        New-Item -Path $defenderPath -Force -ErrorAction Stop | Out-Null
        Write-Log "Chave criada com sucesso." -Level "INFO" -ConsoleOutput
      }

      # Desativar AntiSpyware
      Write-Log "Configurando DisableAntiSpyware para 1..." -ConsoleOutput
      Set-ItemProperty -Path $defenderPath -Name "DisableAntiSpyware" -Type DWord -Value 1 -ErrorAction Stop
      Write-Log "DisableAntiSpyware configurado com sucesso." -Level "INFO" -ConsoleOutput

      # Remover ou configurar propriedades baseadas na versão
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

      # Tratar Spynet
      $spynetPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
      if (-not (Test-Path $spynetPath)) {
        Write-Log "Chave $spynetPath não existe. Criando..." -ConsoleOutput
        New-Item -Path $spynetPath -Force -ErrorAction Stop | Out-Null
        Write-Log "Chave criada com sucesso." -Level "INFO" -ConsoleOutput
      }

      Write-Log "Configurando SpynetReporting para 0..." -ConsoleOutput
      Set-ItemProperty -Path $spynetPath -Name "SpynetReporting" -Type DWord -Value 0 -ErrorAction Stop
      Write-Log "SpynetReporting configurado com sucesso." -Level "INFO" -ConsoleOutput

      Write-Log "Configurando SubmitSamplesConsent para 2..." -ConsoleOutput
      Set-ItemProperty -Path $spynetPath -Name "SubmitSamplesConsent" -Type DWord -Value 2 -ErrorAction Stop
      Write-Log "SubmitSamplesConsent configurado com sucesso." -Level "INFO" -ConsoleOutput

      # Remover PUAProtection
      Write-Log "Removendo PUAProtection..." -ConsoleOutput
      if (Get-ItemProperty -Path $defenderPath -Name "PUAProtection" -ErrorAction SilentlyContinue) {
        Remove-ItemProperty -Path $defenderPath -Name "PUAProtection" -ErrorAction Stop
        Write-Log "PUAProtection removido com sucesso." -Level "INFO" -ConsoleOutput
      }
      else {
        Write-Log "Propriedade PUAProtection não encontrada. Nenhuma ação necessária." -Level "INFO" -ConsoleOutput
      }

      # Desativar Controlled Folder Access
      Write-Log "Desativando Controlled Folder Access..." -ConsoleOutput
      Set-MpPreference -EnableControlledFolderAccess Disabled -ErrorAction Stop
      Write-Log "Controlled Folder Access desativado com sucesso." -Level "INFO" -ConsoleOutput

      # Desativar tarefas agendadas
      foreach ($task in $tasks) {
        Write-Log "Desativando tarefa agendada: $task..." -ConsoleOutput
        Disable-ScheduledTask -TaskName $task -ErrorAction Stop
        Write-Log "Tarefa $task desativada com sucesso." -Level "INFO" -ConsoleOutput
      }

      Write-Log "Microsoft Windows Defender desativado com sucesso." -Level "INFO" -ConsoleOutput
      Write-Colored "Microsoft Windows Defender desativado com sucesso." -Color "VerdeClaro"
    }
    elseif ($selection -match "(?i)^h$") {
      Write-Log "Opção escolhida: Habilitar o Microsoft Windows Defender." -ConsoleOutput
      Write-Output "Ativando Microsoft Windows Defender e processos relacionados..."

      # Remover EnableFirewall
      if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile") {
        Write-Log "Removendo EnableFirewall do registro..." -ConsoleOutput
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -Name "EnableFirewall" -ErrorAction Stop
        Write-Log "EnableFirewall removido com sucesso." -Level "INFO" -ConsoleOutput
      }

      # Remover DisableAntiSpyware
      $defenderPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
      $propertyName = "DisableAntiSpyware"
      if (Test-Path $defenderPath) {
        if (Get-ItemProperty -Path $defenderPath -Name $propertyName -ErrorAction SilentlyContinue) {
          Remove-ItemProperty -Path $defenderPath -Name $propertyName -ErrorAction Stop
          Write-Log "$propertyName removido com sucesso." -Level "INFO" -ConsoleOutput
        }
        else {
          Write-Log "Propriedade $propertyName não encontrada no caminho $defenderPath. Nenhuma ação necessária." -Level "INFO" -ConsoleOutput
        }
      }

      # Configurar propriedades baseadas na versão
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

      # Remover SpynetReporting e SubmitSamplesConsent
      $spynetPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
      if (Test-Path $spynetPath) {
        if (Get-ItemProperty -Path $spynetPath -Name "SpynetReporting" -ErrorAction SilentlyContinue) {
          Remove-ItemProperty -Path $spynetPath -Name "SpynetReporting" -ErrorAction Stop
          Write-Log "SpynetReporting removido com sucesso." -Level "INFO" -ConsoleOutput
        }
        if (Get-ItemProperty -Path $spynetPath -Name "SubmitSamplesConsent" -ErrorAction SilentlyContinue) {
          Remove-ItemProperty -Path $spynetPath -Name "SubmitSamplesConsent" -ErrorAction Stop
          Write-Log "SubmitSamplesConsent removido com sucesso." -Level "INFO" -ConsoleOutput
        }
      }
      else {
        Write-Log "Caminho $spynetPath não encontrado. Nenhuma ação necessária." -Level "INFO" -ConsoleOutput
      }

      # Configurar PUAProtection
      Write-Log "Configurando PUAProtection para 1..." -ConsoleOutput
      Set-ItemProperty -Path $defenderPath -Name "PUAProtection" -Type DWord -Value 1 -ErrorAction Stop
      Write-Log "PUAProtection configurado com sucesso." -Level "INFO" -ConsoleOutput

      # Ativar tarefas agendadas
      foreach ($task in $tasks) {
        Write-Log "Ativando tarefa agendada: $task..." -ConsoleOutput
        Enable-ScheduledTask -TaskName $task -ErrorAction Stop
        Write-Log "Tarefa $task ativada com sucesso." -Level "INFO" -ConsoleOutput
      }

      Write-Log "Microsoft Windows Defender habilitado com sucesso." -Level "INFO" -ConsoleOutput
      Write-Colored "Microsoft Windows Defender habilitado com sucesso." -Color "VerdeClaro"
    }
    else {
      Write-Log "Opção escolhida: Pular gerenciamento do Microsoft Windows Defender." -Level "INFO" -ConsoleOutput
      Write-Colored "Gerenciamento do Microsoft Windows Defender foi pulado." -Color "AmareloClaro"
    }
  }
  catch {
    $errorMessage = "Erro na função AskDefender: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    Write-Colored $errorMessage -Color "VermelhoClaro"
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

function ConfigureWindowsUpdate {
  [CmdletBinding()]
  Param (
    [int]$DelayFeatureUpdatesDays = 365,
    [switch]$DisableAutoRestart = $true,
    [switch]$EnableMSRT = $true,
    [switch]$EnableDrivers = $true
  )

  Write-Log "Iniciando configuração do Windows Update..." -Level "INFO" -ConsoleOutput

  # Caminhos do registro
  $wuPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
  $auPath = "$wuPath\AU"

  # Cria as chaves se não existirem
  if (-not (Test-Path $wuPath)) { New-Item -Path $wuPath -Force | Out-Null }
  if (-not (Test-Path $auPath)) { New-Item -Path $auPath -Force | Out-Null }

  # Configurações de adiamento de atualizações (SlowUpdatesTweaks)
  Write-Log "Aplicando ajustes para adiar atualizações de recursos..." -Level "INFO" -ConsoleOutput
  Set-ItemProperty -Path $wuPath -Name "BranchReadinessLevel" -Value 16 -Type DWord -Force
  Set-ItemProperty -Path $wuPath -Name "DeferFeatureUpdates" -Value 1 -Type DWord -Force
  Set-ItemProperty -Path $wuPath -Name "DeferFeatureUpdatesPeriodInDays" -Value $DelayFeatureUpdatesDays -Type DWord -Force
  Set-ItemProperty -Path $wuPath -Name "ManagePreviewBuilds" -Value 1 -Type DWord -Force
  Set-ItemProperty -Path $wuPath -Name "ManagePreviewBuildsPolicyValue" -Value 2 -Type DWord -Force
  Set-ItemProperty -Path $wuPath -Name "PauseFeatureUpdatesStartTime" -Value "2025-04-03" -Type String -Force
  Set-ItemProperty -Path $wuPath -Name "PauseFeatureUpdatesEndTime" -Value "2030-04-03" -Type String -Force
  Set-ItemProperty -Path $auPath -Name "NoAutoUpdate" -Value 0 -Type DWord -Force

  # Desativar reinícios automáticos (DisableUpdateRestart)
  if ($DisableAutoRestart) {
    Write-Log "Desativando reinícios automáticos após atualizações..." -Level "INFO" -ConsoleOutput
    Set-ItemProperty -Path $auPath -Name "NoAutoRebootWithLoggedOnUsers" -Value 1 -Type DWord -Force
  }

  # Habilitar MSRT (EnableUpdateMSRT)
  if ($EnableMSRT) {
    # MSRT é geralmente incluído em atualizações de segurança; garantimos que não seja bloqueado
    Write-Log "Garantindo atualizações do Microsoft Malicious Software Removal Tool..." -Level "INFO" -ConsoleOutput
    # Não há chave específica para MSRT, mas mantemos atualizações de qualidade ativas (NoAutoUpdate = 0)
  }

  # Habilitar atualizações de drivers (EnableUpdateDriver)
  if ($EnableDrivers) {
    Write-Log "Habilitando atualizações de drivers via Windows Update..." -Level "INFO" -ConsoleOutput
    Set-ItemProperty -Path $wuPath -Name "ExcludeWUDriversInQualityUpdate" -Value 0 -Type DWord -Force
  }

  Write-Log "Configuração do Windows Update concluída com sucesso." -Level "INFO" -ConsoleOutput
}

function DisableMeltdownCompatFlag {
  Write-Log "Iniciando função DisableMeltdownCompatFlag para desativar o flag de compatibilidade do Meltdown (CVE-2017-5754)." -ConsoleOutput

  try {
    Write-Output "Disabling Meltdown (CVE-2017-5754) compatibility flag..."
    Write-Log "Desativando o flag de compatibilidade do Meltdown (CVE-2017-5754)..." -ConsoleOutput

    # Definir o caminho do registro
    $qualityCompatPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat"

    # Verificar se o caminho existe
    if (Test-Path $qualityCompatPath) {
      # Verificar se a propriedade existe
      $propertyName = "cadca5fe-87d3-4b96-b7fb-a231484277cc"
      if (Get-ItemProperty -Path $qualityCompatPath -Name $propertyName -ErrorAction SilentlyContinue) {
        Remove-ItemProperty -Path $qualityCompatPath -Name $propertyName -ErrorAction Stop
        Write-Log "Flag de compatibilidade do Meltdown ($propertyName) removido com sucesso." -Level "INFO" -ConsoleOutput
      }
      else {
        Write-Log "Propriedade $propertyName não encontrada no caminho $qualityCompatPath. Nenhuma ação necessária." -Level "INFO" -ConsoleOutput
      }
    }
    else {
      Write-Log "Caminho $qualityCompatPath não encontrado. Nenhuma ação necessária." -Level "INFO" -ConsoleOutput
    }
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
  Write-Log "Iniciando função DisableGaming para parar e desativar serviços desnecessários para jogos." -ConsoleOutput

  try {
    Write-Output "Stopping and disabling unnecessary services for gaming..."
    Write-Log "Parando e desativando serviços desnecessários para jogos..." -ConsoleOutput

    $errpref = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"
    Write-Log "Alterando ErrorActionPreference para SilentlyContinue temporariamente." -ConsoleOutput

    # wisvc
    Write-Log "Parando o serviço wisvc..." -ConsoleOutput
    Stop-Service "wisvc" -WarningAction SilentlyContinue -ErrorAction Stop
    Write-Log "Configurando wisvc para inicialização desativada..." -ConsoleOutput
    Set-Service "wisvc" -StartupType Disabled -ErrorAction Stop
    Write-Log "Serviço wisvc processado com sucesso." -Level "INFO" -ConsoleOutput

    # MapsBroker
    Write-Log "Parando o serviço MapsBroker..." -ConsoleOutput
    Stop-Service "MapsBroker" -WarningAction SilentlyContinue -ErrorAction Stop
    Write-Log "Configurando MapsBroker para inicialização desativada..." -ConsoleOutput
    Set-Service "MapsBroker" -StartupType Disabled -ErrorAction Stop
    Write-Log "Serviço MapsBroker processado com sucesso." -Level "INFO" -ConsoleOutput

    # UmRdpService
    Write-Log "Parando o serviço UmRdpService..." -ConsoleOutput
    Stop-Service "UmRdpService" -WarningAction SilentlyContinue -ErrorAction Stop
    Write-Log "Configurando UmRdpService para inicialização desativada..." -ConsoleOutput
    Set-Service "UmRdpService" -StartupType Disabled -ErrorAction Stop
    Write-Log "Serviço UmRdpService processado com sucesso." -Level "INFO" -ConsoleOutput

    # TrkWks
    Write-Log "Parando o serviço TrkWks..." -ConsoleOutput
    Stop-Service "TrkWks" -WarningAction SilentlyContinue -ErrorAction Stop
    Write-Log "Configurando TrkWks para inicialização desativada..." -ConsoleOutput
    Set-Service "TrkWks" -StartupType Disabled -ErrorAction Stop
    Write-Log "Serviço TrkWks processado com sucesso." -Level "INFO" -ConsoleOutput

    # TermService
    Write-Log "Parando o serviço TermService..." -ConsoleOutput
    Stop-Service "TermService" -WarningAction SilentlyContinue -ErrorAction Stop
    Write-Log "Configurando TermService para inicialização desativada..." -ConsoleOutput
    Set-Service "TermService" -StartupType Disabled -ErrorAction Stop
    Write-Log "Serviço TermService processado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Serviços desnecessários para jogos desativados com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função DisableGaming: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    throw  # Repropaga o erro
  }
  finally {
    $ErrorActionPreference = $errpref
    Write-Log "Restaurando ErrorActionPreference para $errpref." -ConsoleOutput
    Write-Log "Finalizando função DisableGaming." -Level "INFO" -ConsoleOutput
  }
}

function DisableHomeGroups {
  Write-Log "Iniciando função DisableHomeGroups para parar e desativar serviços de Grupos Domésticos." -ConsoleOutput

  try {
    Write-Output "Stopping and disabling Home Groups services..."
    Write-Log "Parando e desativando serviços de Grupos Domésticos..." -ConsoleOutput

    $errpref = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"
    Write-Log "Alterando ErrorActionPreference para SilentlyContinue temporariamente." -ConsoleOutput

    # Obter versão do sistema operacional
    $osVersion = [System.Environment]::OSVersion.Version
    $isWindows10OrLater = $osVersion.Build -ge 10240

    # Função interna para processar um serviço
    function Process-Service {
      param ($serviceName)
      try {
        Write-Log "Verificando serviço $serviceName..." -ConsoleOutput
        if (Get-Service $serviceName -ErrorAction SilentlyContinue) {
          Write-Log "Parando o serviço $serviceName..." -ConsoleOutput
          Stop-Service $serviceName -WarningAction SilentlyContinue -ErrorAction Stop
          Write-Log "Configurando $serviceName para inicialização desativada..." -ConsoleOutput
          Set-Service $serviceName -StartupType Disabled -ErrorAction Stop
          Write-Log "Serviço $serviceName processado com sucesso." -Level "INFO" -ConsoleOutput
        }
        else {
          Write-Log "Serviço $serviceName não encontrado no sistema. Nenhuma ação necessária." -Level "INFO" -ConsoleOutput
        }
      }
      catch {
        Write-Log "Erro ao processar serviço $serviceName $_" -Level "ERROR" -ConsoleOutput
      }
    }

    # Processar HomeGroupListener
    if (-not $isWindows10OrLater) {
      Process-Service "HomeGroupListener"
    }
    else {
      Write-Log "Versão do Windows não suporta Grupos Domésticos. Pulando HomeGroupListener." -Level "INFO" -ConsoleOutput
    }

    # Processar HomeGroupProvider (pode existir mesmo em versões mais novas)
    Process-Service "HomeGroupProvider"

    Write-Log "Serviços de Grupos Domésticos processados com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função DisableHomeGroups: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    throw  # Repropaga o erro
  }
  finally {
    $ErrorActionPreference = $errpref
    Write-Log "Restaurando ErrorActionPreference para $errpref." -ConsoleOutput
    Write-Log "Finalizando função DisableHomeGroups." -Level "INFO" -ConsoleOutput
  }
}

function EnableSharedExperiences {
  Write-Log "Iniciando função EnableSharedExperiences para habilitar Experiências Compartilhadas." -ConsoleOutput

  try {
    Write-Output "Enabling Shared Experiences..."
    Write-Log "Habilitando Experiências Compartilhadas..." -ConsoleOutput

    # Definir o caminho do registro
    $systemPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"

    # Verificar se o caminho existe, senão criar
    if (-not (Test-Path $systemPath)) {
      Write-Log "Caminho $systemPath não existe. Criando..." -ConsoleOutput
      New-Item -Path $systemPath -Force -ErrorAction Stop | Out-Null
      Write-Log "Caminho $systemPath criado com sucesso." -Level "INFO" -ConsoleOutput
    }

    # Remover a propriedade EnableCdp, se existir
    Write-Log "Removendo a propriedade EnableCdp do registro..." -ConsoleOutput
    if (Get-ItemProperty -Path $systemPath -Name "EnableCdp" -ErrorAction SilentlyContinue) {
      Remove-ItemProperty -Path $systemPath -Name "EnableCdp" -ErrorAction Stop
      Write-Log "EnableCdp removido com sucesso." -Level "INFO" -ConsoleOutput
    }
    else {
      Write-Log "Propriedade EnableCdp não encontrada no caminho $systemPath. Nenhuma ação necessária." -Level "INFO" -ConsoleOutput
    }

    # Remover a propriedade EnableMmx, se existir
    Write-Log "Removendo a propriedade EnableMmx do registro..." -ConsoleOutput
    if (Get-ItemProperty -Path $systemPath -Name "EnableMmx" -ErrorAction SilentlyContinue) {
      Remove-ItemProperty -Path $systemPath -Name "EnableMmx" -ErrorAction Stop
      Write-Log "EnableMmx removido com sucesso." -Level "INFO" -ConsoleOutput
    }
    else {
      Write-Log "Propriedade EnableMmx não encontrada no caminho $systemPath. Nenhuma ação necessária." -Level "INFO" -ConsoleOutput
    }

    Write-Log "Experiências Compartilhadas habilitadas com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função EnableSharedExperiences: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    throw  # Repropaga o erro
  }
  finally {
    Write-Log "Finalizando função EnableSharedExperiences." -Level "INFO" -ConsoleOutput
  }
}

function EnableRemoteDesktop {
  Write-Log "Iniciando função EnableRemoteDesktop para habilitar a Área de Trabalho Remota sem autenticação de nível de rede." -ConsoleOutput

  try {
    Write-Output "Enabling Remote Desktop w/o Network Level Authentication..."
    Write-Log "Habilitando a Área de Trabalho Remota sem autenticação de nível de rede..." -ConsoleOutput

    $errpref = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"
    Write-Log "Alterando ErrorActionPreference para SilentlyContinue temporariamente." -ConsoleOutput

    Write-Log "Configurando fDenyTSConnections para 0..." -ConsoleOutput
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 0 -ErrorAction Stop
    Write-Log "fDenyTSConnections configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Configurando UserAuthentication para 0..." -ConsoleOutput
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Type DWord -Value 0 -ErrorAction Stop
    Write-Log "UserAuthentication configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Habilitando regras de firewall para RemoteDesktop..." -ConsoleOutput
    Enable-NetFirewallRule -Name "RemoteDesktop*" -ErrorAction Stop | Out-Null
    Write-Log "Regras de firewall para RemoteDesktop habilitadas com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Área de Trabalho Remota habilitada com sucesso sem autenticação de nível de rede." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função EnableRemoteDesktop: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    throw  # Repropaga o erro
  }
  finally {
    $ErrorActionPreference = $errpref
    Write-Log "Restaurando ErrorActionPreference para $errpref." -ConsoleOutput
    Write-Log "Finalizando função EnableRemoteDesktop." -Level "INFO" -ConsoleOutput
  }
}

#Disabling Windows Remote Assistance.
function DisableRemoteAssistance {
  Write-Log "Iniciando função DisableRemoteAssistance para desativar a Assistência Remota do Windows." -ConsoleOutput

  try {
    Write-Output "Disabling Windows Remote Assistance..."
    Write-Log "Desativando a Assistência Remota do Windows..." -ConsoleOutput

    Write-Log "Configurando fAllowFullControl para 0..." -ConsoleOutput
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowFullControl" -Type DWord -Value 0 -ErrorAction Stop
    Write-Log "fAllowFullControl configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Configurando fAllowToGetHelp para 0..." -ConsoleOutput
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0 -ErrorAction Stop
    Write-Log "fAllowToGetHelp configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Assistência Remota do Windows desativada com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função DisableRemoteAssistance: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    throw  # Repropaga o erro
  }
  finally {
    Write-Log "Finalizando função DisableRemoteAssistance." -Level "INFO" -ConsoleOutput
  }
}

function DisableAutoplay {
  Write-Log "Iniciando função DisableAutoplay para desativar a Reprodução Automática." -ConsoleOutput

  try {
    Write-Output "Disabling Autoplay..."
    Write-Log "Desativando a Reprodução Automática..." -ConsoleOutput

    Write-Log "Configurando DisableAutoplay para 1 em HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers..." -ConsoleOutput
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 1 -ErrorAction Stop
    Write-Log "DisableAutoplay configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Reprodução Automática desativada com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função DisableAutoplay: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    throw  # Repropaga o erro
  }
  finally {
    Write-Log "Finalizando função DisableAutoplay." -Level "INFO" -ConsoleOutput
  }
}

function DisableAutorun {
  Write-Log "Iniciando função DisableAutorun para desativar o Autorun." -ConsoleOutput

  try {
    Write-Output "Disabling Autorun..."
    Write-Log "Desativando o Autorun..." -ConsoleOutput

    # Definir o caminho do registro
    $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"

    # Verificar e criar a chave de registro, se necessário
    if (-not (Test-Path $registryPath)) {
      Write-Log "Chave $registryPath não existe. Criando..." -ConsoleOutput
      New-Item -Path $registryPath -Force -ErrorAction Stop | Out-Null
      Write-Log "Chave $registryPath criada com sucesso." -Level "INFO" -ConsoleOutput
    }
    else {
      Write-Log "Chave $registryPath já existe. Prosseguindo com a configuração." -ConsoleOutput
    }

    # Configurar NoDriveTypeAutoRun
    Write-Log "Configurando NoDriveTypeAutoRun para 255 em $registryPath..." -ConsoleOutput
    Set-ItemProperty -Path $registryPath -Name "NoDriveTypeAutoRun" -Type DWord -Value 255 -ErrorAction Stop
    Write-Log "NoDriveTypeAutoRun configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Autorun desativado com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função DisableAutorun: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    throw  # Repropaga o erro
  }
  finally {
    Write-Log "Finalizando função DisableAutorun." -Level "INFO" -ConsoleOutput
  }
}

function DisableStorageSense {
  Write-Log "Iniciando função DisableStorageSense para desativar o Storage Sense." -ConsoleOutput

  try {
    Write-Output "Disabling Storage Sense..."
    Write-Log "Desativando o Storage Sense..." -ConsoleOutput

    # Definir o caminho do registro
    $registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy"

    # Verificar e criar a chave de registro, se necessário
    if (-not (Test-Path $registryPath)) {
      Write-Log "Chave $registryPath não existe. Criando..." -ConsoleOutput
      New-Item -Path $registryPath -Force -ErrorAction Stop | Out-Null
      Write-Log "Chave $registryPath criada com sucesso." -Level "INFO" -ConsoleOutput
    }
    else {
      Write-Log "Chave $registryPath já existe. Prosseguindo com a configuração." -ConsoleOutput
    }

    # Configurar a propriedade 01
    Write-Log "Configurando a propriedade '01' para 0 em $registryPath..." -ConsoleOutput
    Set-ItemProperty -Path $registryPath -Name "01" -Type DWord -Value 0 -ErrorAction Stop
    Write-Log "Propriedade '01' configurada com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Storage Sense desativado com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função DisableStorageSense: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    throw  # Repropaga o erro
  }
  finally {
    Write-Log "Finalizando função DisableStorageSense." -Level "INFO" -ConsoleOutput
  }
}

function DisableDefragmentation {
  Write-Log "Iniciando função DisableDefragmentation para desativar a desfragmentação." -ConsoleOutput

  try {
    Write-Output "Disabling Defragmentation..."
    Write-Log "Desativando a desfragmentação..." -ConsoleOutput

    # Definir o caminho do registro
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Defrag"

    # Verificar e criar a chave de registro, se necessário
    if (-not (Test-Path $registryPath)) {
      Write-Log "Chave $registryPath não existe. Criando..." -ConsoleOutput
      New-Item -Path $registryPath -Force -ErrorAction Stop | Out-Null
      Write-Log "Chave $registryPath criada com sucesso." -Level "INFO" -ConsoleOutput
    }
    else {
      Write-Log "Chave $registryPath já existe. Prosseguindo com a configuração." -ConsoleOutput
    }

    # Configurar a propriedade EnableDefrag
    Write-Log "Configurando EnableDefrag para 0 em $registryPath..." -ConsoleOutput
    Set-ItemProperty -Path $registryPath -Name "EnableDefrag" -Type DWord -Value 0 -ErrorAction Stop
    Write-Log "EnableDefrag configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Desfragmentação desativada com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função DisableDefragmentation: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    throw  # Repropaga o erro
  }
  finally {
    Write-Log "Finalizando função DisableDefragmentation." -Level "INFO" -ConsoleOutput
  }
}

function EnableIndexing {
  Write-Log "Iniciando função EnableIndexing para habilitar a indexação." -ConsoleOutput

  try {
    Write-Output "Enabling Indexing..."
    Write-Log "Habilitando a indexação..." -ConsoleOutput

    Write-Log "Configurando o serviço WSearch para inicialização automática..." -ConsoleOutput
    Set-Service "WSearch" -StartupType Automatic -ErrorAction Stop
    Write-Log "WSearch configurado para inicialização automática com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Iniciando o serviço WSearch..." -ConsoleOutput
    Start-Service "WSearch" -ErrorAction Stop
    Write-Log "Serviço WSearch iniciado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Indexação habilitada com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função EnableIndexing: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    throw  # Repropaga o erro
  }
  finally {
    Write-Log "Finalizando função EnableIndexing." -Level "INFO" -ConsoleOutput
  }
}

function SetBIOSTimeUTC {
  Write-Log "Iniciando função SetBIOSTimeUTC para definir o tempo do BIOS como UTC." -ConsoleOutput

  try {
    Write-Output "Setting BIOS time to UTC..."
    Write-Log "Definindo o tempo do BIOS como UTC..." -ConsoleOutput

    Write-Log "Configurando RealTimeIsUniversal para 1 em HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation..." -ConsoleOutput
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -Name "RealTimeIsUniversal" -Type DWord -Value 1 -ErrorAction Stop
    Write-Log "RealTimeIsUniversal configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Tempo do BIOS definido como UTC com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função SetBIOSTimeUTC: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    throw  # Repropaga o erro
  }
  finally {
    Write-Log "Finalizando função SetBIOSTimeUTC." -Level "INFO" -ConsoleOutput
  }
}

function DisableHibernation {
  Write-Log "Iniciando função DisableHibernation para desativar a hibernação." -ConsoleOutput

  try {
    Write-Output "Disabling Hibernation..."
    Write-Log "Desativando a hibernação..." -ConsoleOutput

    Write-Log "Executando powercfg /hibernate off..." -ConsoleOutput
    powercfg /hibernate off -ErrorAction Stop | Out-Null
    Write-Log "Hibernação desativada com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função DisableHibernation: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    throw  # Repropaga o erro
  }
  finally {
    Write-Log "Finalizando função DisableHibernation." -Level "INFO" -ConsoleOutput
  }
}

function EnableSleepButton {
  Write-Log "Iniciando função EnableSleepButton para habilitar o botão de suspensão." -ConsoleOutput

  try {
    Write-Output "Enabling Sleep Button..."
    Write-Log "Habilitando o botão de suspensão..." -ConsoleOutput

    Write-Log "Configurando SleepButtonEnabled para 1 em HKLM:\SYSTEM\CurrentControlSet\Control\Power..." -ConsoleOutput
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "SleepButtonEnabled" -Type DWord -Value 1 -ErrorAction Stop
    Write-Log "SleepButtonEnabled configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Botão de suspensão habilitado com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função EnableSleepButton: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    throw  # Repropaga o erro
  }
  finally {
    Write-Log "Finalizando função EnableSleepButton." -Level "INFO" -ConsoleOutput
  }
}

function DisableSleepTimeout {
  Write-Log "Iniciando função DisableSleepTimeout para desativar o tempo limite de suspensão." -ConsoleOutput

  try {
    Write-Output "Disabling Sleep Timeout..."
    Write-Log "Desativando o tempo limite de suspensão..." -ConsoleOutput

    Write-Log "Executando powercfg -change -standby-timeout-ac 0 para desativar timeout em AC..." -ConsoleOutput
    powercfg -change -standby-timeout-ac 0 -ErrorAction Stop
    Write-Log "Tempo limite de suspensão em AC desativado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Executando powercfg -change -standby-timeout-dc 0 para desativar timeout em DC..." -ConsoleOutput
    powercfg -change -standby-timeout-dc 0 -ErrorAction Stop
    Write-Log "Tempo limite de suspensão em DC desativado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Tempo limite de suspensão desativado com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função DisableSleepTimeout: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    throw  # Repropaga o erro
  }
  finally {
    Write-Log "Finalizando função DisableSleepTimeout." -Level "INFO" -ConsoleOutput
  }
}

function DisableFastStartup {
  Write-Log "Iniciando função DisableFastStartup para desativar a inicialização rápida." -ConsoleOutput

  try {
    Write-Output "Disabling Fast Startup..."
    Write-Log "Desativando a inicialização rápida..." -ConsoleOutput

    Write-Log "Configurando HiberbootEnabled para 0 em HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power..." -ConsoleOutput
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 0 -ErrorAction Stop
    Write-Log "HiberbootEnabled configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Inicialização rápida desativada com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função DisableFastStartup: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    throw  # Repropaga o erro
  }
  finally {
    Write-Log "Finalizando função DisableFastStartup." -Level "INFO" -ConsoleOutput
  }
}

function PowerThrottlingOff {
  Write-Log "Iniciando função PowerThrottlingOff para desativar o Power Throttling." -ConsoleOutput

  try {
    Write-Output "Disabling Power Throttling..."
    Write-Log "Desativando o Power Throttling..." -ConsoleOutput

    # Definir o caminho do registro
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling"

    # Verificar e criar a chave de registro, se necessário
    if (-not (Test-Path $registryPath)) {
      Write-Log "Chave $registryPath não existe. Criando..." -ConsoleOutput
      New-Item -Path $registryPath -Force -ErrorAction Stop | Out-Null
      Write-Log "Chave $registryPath criada com sucesso." -Level "INFO" -ConsoleOutput
    }
    else {
      Write-Log "Chave $registryPath já existe. Prosseguindo com a configuração." -ConsoleOutput
    }

    # Configurar a propriedade PowerThrottlingOff
    Write-Log "Configurando PowerThrottlingOff para 1 em $registryPath..." -ConsoleOutput
    Set-ItemProperty -Path $registryPath -Name "PowerThrottlingOff" -Type DWord -Value 1 -ErrorAction Stop
    Write-Log "PowerThrottlingOff configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Power Throttling desativado com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função PowerThrottlingOff: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    throw  # Repropaga o erro
  }
  finally {
    Write-Log "Finalizando função PowerThrottlingOff." -Level "INFO" -ConsoleOutput
  }
}

function Win32PrioritySeparation {
  Write-Log "Iniciando função Win32PrioritySeparation para otimizar a separação de prioridade Win32 para jogos." -ConsoleOutput

  try {
    Write-Output "Optimizing Win32 Priority Separation for gaming..."
    Write-Log "Otimizando a separação de prioridade Win32 para jogos..." -ConsoleOutput

    Write-Log "Configurando Win32PrioritySeparation para 38 em HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl..." -ConsoleOutput
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Type DWord -Value 38 -ErrorAction Stop
    Write-Log "Win32PrioritySeparation configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Separação de prioridade Win32 otimizada para jogos com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função Win32PrioritySeparation: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    throw  # Repropaga o erro
  }
  finally {
    Write-Log "Finalizando função Win32PrioritySeparation." -Level "INFO" -ConsoleOutput
  }
}

function DisableAERO {
  Write-Log "Iniciando função DisableAERO para desativar os efeitos AERO." -ConsoleOutput

  try {
    Write-Output "Disabling AERO effects..."
    Write-Log "Desativando os efeitos AERO..." -ConsoleOutput

    Write-Log "Configurando EnableAeroPeek para 0 em HKCU:\Software\Microsoft\Windows\DWM..." -ConsoleOutput
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type DWord -Value 0 -ErrorAction Stop
    Write-Log "EnableAeroPeek configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Efeitos AERO desativados com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função DisableAERO: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    throw  # Repropaga o erro
  }
  finally {
    Write-Log "Finalizando função DisableAERO." -Level "INFO" -ConsoleOutput
  }
}

function BSODdetails {
  Write-Log "Iniciando função BSODdetails para habilitar informações detalhadas do BSOD." -ConsoleOutput

  try {
    Write-Output "Enabling detailed BSOD information..."
    Write-Log "Habilitando informações detalhadas do BSOD..." -ConsoleOutput

    Write-Log "Configurando DisplayParameters para 1 em HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl..." -ConsoleOutput
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "DisplayParameters" -Type DWord -Value 1 -ErrorAction Stop
    Write-Log "DisplayParameters configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Informações detalhadas do BSOD habilitadas com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função BSODdetails: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    throw  # Repropaga o erro
  }
  finally {
    Write-Log "Finalizando função BSODdetails." -Level "INFO" -ConsoleOutput
  }
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
  Write-Log "Iniciando função ShowFileOperationsDetails para exibir detalhes de operações de arquivo no Explorer." -ConsoleOutput

  try {
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager"
      
    # Verificar se o caminho existe, caso contrário, criá-lo
    if (-not (Test-Path $regPath)) {
      Write-Log "Caminho de registro $regPath não existe. Criando..." -ConsoleOutput
      New-Item -Path $regPath -Force -ErrorAction Stop | Out-Null
      Write-Log "Caminho $regPath criado com sucesso." -Level "INFO" -ConsoleOutput
    }
    else {
      Write-Log "Caminho $regPath já existe. Prosseguindo com a configuração..." -ConsoleOutput
    }

    # Configurar a propriedade EnthusiastMode para exibir detalhes
    Write-Log "Configurando EnthusiastMode para 1 em $regPath..." -ConsoleOutput
    Set-ItemProperty -Path $regPath -Name "EnthusiastMode" -Type DWord -Value 1 -ErrorAction Stop
    Write-Log "EnthusiastMode configurado com sucesso para exibir detalhes de operações de arquivo." -Level "INFO" -ConsoleOutput
    Write-Output "Detalhes de operações de arquivo configurados para serem exibidos."
  }
  catch {
    $errorMessage = "Erro na função ShowFileOperationsDetails: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    Write-Colored "Erro ao configurar detalhes de operações de arquivo. Veja o log para detalhes." -Color "Vermelho"
    throw  # Repropaga o erro para ser tratado externamente, se necessário
  }
  finally {
    Write-Log "Finalizando função ShowFileOperationsDetails." -Level "INFO" -ConsoleOutput
  }
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

Function QOL {
  Write-Log "Iniciando função QOL para aplicar ajustes de qualidade de vida do DaddyMadu." -ConsoleOutput

  try {
    Write-Output "Habilitando ajustes de qualidade de vida do DaddyMadu..."
    Write-Log "Habilitando ajustes de qualidade de vida do DaddyMadu..." -ConsoleOutput

    $errpref = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"
    Write-Log "Alterando ErrorActionPreference para SilentlyContinue temporariamente." -ConsoleOutput

    Write-Log "Criando chave HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement..." -ConsoleOutput
    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -ErrorAction Stop | Out-Null
    Write-Log "Chave HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement criada ou verificada com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Configurando ScoobeSystemSettingEnabled para 0 para desativar 'Aproveite ainda mais o Windows'..." -ConsoleOutput
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Name "ScoobeSystemSettingEnabled" -Type DWord -Value 0 -ErrorAction Stop | Out-Null
    Write-Log "ScoobeSystemSettingEnabled configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Configurando DynamicScrollbars para 0 para desativar ocultar barras de rolagem..." -ConsoleOutput
    Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility" -Name "DynamicScrollbars" -Type DWord -Value 0 -ErrorAction Stop
    Write-Log "DynamicScrollbars configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Configurando SmoothScroll para 0 para desativar rolagem suave..." -ConsoleOutput
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "SmoothScroll" -Type DWord -Value 0 -ErrorAction Stop
    Write-Log "SmoothScroll configurado com sucesso." -Level "INFO" -ConsoleOutput

    $osBuild = [System.Environment]::OSVersion.Version.Build
    Write-Log "Verificando versão do SO (Build: $osBuild) para aplicar NoInstrumentation..." -ConsoleOutput
    If ($osBuild -ge 22000) {
      Write-Log "Configurando NoInstrumentation para 1 no Windows 11 ou superior para desativar rastreamento de usuário da Microsoft..." -ConsoleOutput
      Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoInstrumentation" -Type DWord -Value 1 -ErrorAction Stop
      Write-Log "NoInstrumentation configurado com sucesso para Windows 11 ou superior." -Level "INFO" -ConsoleOutput
    }
    Else {
      Write-Log "Configurando NoInstrumentation para 1 em versões anteriores ao Windows 11 para desativar rastreamento de usuário da Microsoft..." -ConsoleOutput
      Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoInstrumentation" -Type DWord -Value 1 -ErrorAction Stop
      Write-Log "NoInstrumentation configurado com sucesso para versões anteriores ao Windows 11." -Level "INFO" -ConsoleOutput
    }

    Write-Log "Removendo TaskbarNoMultimon de HKCU:\Software\Policies\Microsoft\Windows\Explorer..." -ConsoleOutput
    Remove-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "TaskbarNoMultimon" -ErrorAction Stop
    Write-Log "TaskbarNoMultimon removido com sucesso de HKCU." -Level "INFO" -ConsoleOutput

    Write-Log "Removendo TaskbarNoMultimon de HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer..." -ConsoleOutput
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "TaskbarNoMultimon" -ErrorAction Stop
    Write-Log "TaskbarNoMultimon removido com sucesso de HKLM." -Level "INFO" -ConsoleOutput

    Write-Log "Configurando MMTaskbarMode para 2 para mostrar botões da barra de tarefas apenas onde a janela está aberta..." -ConsoleOutput
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "MMTaskbarMode" -Type DWord -Value 2 -ErrorAction Stop
    Write-Log "MMTaskbarMode configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Ajustes de qualidade de vida aplicados com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função QOL: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    throw  # Repropaga o erro
  }
  finally {
    $ErrorActionPreference = $errpref
    Write-Log "Restaurando ErrorActionPreference para $errpref." -ConsoleOutput
    Write-Log "Finalizando função QOL." -Level "INFO" -ConsoleOutput
  }
}
Function FullscreenOptimizationFIX {
  Write-Log "Iniciando função FullscreenOptimizationFIX para desativar otimizações de tela cheia." -ConsoleOutput

  try {
    $errpref = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"
    Write-Log "Alterando ErrorActionPreference para SilentlyContinue temporariamente." -ConsoleOutput

    Write-Output "Desativando otimizações de tela cheia..."
    Write-Log "Desativando otimizações de tela cheia..." -ConsoleOutput

    Write-Log "Configurando GameDVR_FSEBehaviorMode para 2 em HKCU:\System\GameConfigStore..." -ConsoleOutput
    Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehaviorMode" -Type DWord -Value 2 -ErrorAction Stop
    Write-Log "GameDVR_FSEBehaviorMode configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Configurando GameDVR_HonorUserFSEBehaviorMode para 1 em HKCU:\System\GameConfigStore..." -ConsoleOutput
    Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_HonorUserFSEBehaviorMode" -Type DWord -Value 1 -ErrorAction Stop
    Write-Log "GameDVR_HonorUserFSEBehaviorMode configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Configurando GameDVR_FSEBehavior para 2 em HKCU:\System\GameConfigStore..." -ConsoleOutput
    Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehavior" -Type DWord -Value 2 -ErrorAction Stop
    Write-Log "GameDVR_FSEBehavior configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Configurando GameDVR_DXGIHonorFSEWindowsCompatible para 1 em HKCU:\System\GameConfigStore..." -ConsoleOutput
    Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_DXGIHonorFSEWindowsCompatible" -Type DWord -Value 1 -ErrorAction Stop
    Write-Log "GameDVR_DXGIHonorFSEWindowsCompatible configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Configurando GameDVR_EFSEFeatureFlags para 0 em HKCU:\System\GameConfigStore..." -ConsoleOutput
    Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_EFSEFeatureFlags" -Type DWord -Value 0 -ErrorAction Stop
    Write-Log "GameDVR_EFSEFeatureFlags configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Configurando GameDVR_DSEBehavior para 2 em HKCU:\System\GameConfigStore..." -ConsoleOutput
    Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_DSEBehavior" -Type DWord -Value 2 -ErrorAction Stop
    Write-Log "GameDVR_DSEBehavior configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Configurando AppCaptureEnabled para 0 em HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR..." -ConsoleOutput
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Type DWord -Value 0 -ErrorAction Stop
    Write-Log "AppCaptureEnabled configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Configurando SwapEffectUpgradeCache para 1 em HKCU:\Software\Microsoft\DirectX\GraphicsSettings..." -ConsoleOutput
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\DirectX\GraphicsSettings" -Name "SwapEffectUpgradeCache" -Type DWord -Value 1 -ErrorAction Stop
    Write-Log "SwapEffectUpgradeCache configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Configurando DirectXUserGlobalSettings para 'SwapEffectUpgradeEnable=1;' em HKCU:\Software\Microsoft\DirectX\UserGpuPreferences..." -ConsoleOutput
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\DirectX\UserGpuPreferences" -Name "DirectXUserGlobalSettings" -Type String -Value 'SwapEffectUpgradeEnable=1;' -ErrorAction Stop
    Write-Log "DirectXUserGlobalSettings configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Configurando InactivityShutdownDelay para 4294967295 em HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform..." -ConsoleOutput
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform" -Name "InactivityShutdownDelay" -Type DWord -Value 4294967295 -ErrorAction Stop
    Write-Log "InactivityShutdownDelay configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Configurando OverlayTestMode para 5 em HKLM:\SOFTWARE\Microsoft\Windows\Dwm..." -ConsoleOutput
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Dwm" -Name "OverlayTestMode" -Type DWord -Value 5 -ErrorAction Stop
    Write-Log "OverlayTestMode configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Desativando compressão de memória via MMAgent..." -ConsoleOutput
    Disable-MMAgent -MemoryCompression -ErrorAction Stop | Out-Null
    Write-Log "Compressão de memória desativada com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Ajustes de otimização de tela cheia aplicados com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função FullscreenOptimizationFIX: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    throw  # Repropaga o erro
  }
  finally {
    $ErrorActionPreference = $errpref
    Write-Log "Restaurando ErrorActionPreference para $errpref." -ConsoleOutput
    Write-Log "Finalizando função FullscreenOptimizationFIX." -Level "INFO" -ConsoleOutput
  }
}

Function GameOptimizationFIX {
  Write-Log "Iniciando função GameOptimizationFIX para aplicar correções de otimização para jogos." -ConsoleOutput

  try {
    Write-Output "Aplicando correções de otimização para jogos..."
    Write-Log "Aplicando correções de otimização para jogos..." -ConsoleOutput

    Write-Log "Configurando GPU Priority para 8 em HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games..." -ConsoleOutput
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "GPU Priority" -Type DWord -Value 8 -ErrorAction Stop
    Write-Log "GPU Priority configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Configurando Priority para 6 em HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games..." -ConsoleOutput
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Priority" -Type DWord -Value 6 -ErrorAction Stop
    Write-Log "Priority configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Configurando Scheduling Category para 'High' em HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games..." -ConsoleOutput
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Scheduling Category" -Type String -Value "High" -ErrorAction Stop
    Write-Log "Scheduling Category configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Configurando SFIO Priority para 'High' em HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games..." -ConsoleOutput
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "SFIO Priority" -Type String -Value "High" -ErrorAction Stop
    Write-Log "SFIO Priority configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Configurando IRQ8Priority para 1 em HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl..." -ConsoleOutput
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "IRQ8Priority" -Type DWord -Value 1 -ErrorAction Stop
    Write-Log "IRQ8Priority configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Adicionando CpuPriorityClass para 4 em HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions..." -ConsoleOutput
    reg ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v CpuPriorityClass /t REG_DWORD /d 4 /f -ErrorAction Stop | Out-Null
    Write-Log "CpuPriorityClass adicionado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Adicionando IoPriority para 3 em HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions..." -ConsoleOutput
    reg ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v IoPriority /t REG_DWORD /d 3 /f -ErrorAction Stop | Out-Null
    Write-Log "IoPriority adicionado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Desativando suporte a nomes 8.3 via fsutil..." -ConsoleOutput
    fsutil behavior set disable8dot3 1 -ErrorAction Stop
    Write-Log "Suporte a nomes 8.3 desativado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Desativando última atualização de acesso via fsutil..." -ConsoleOutput
    fsutil behavior set disablelastaccess 1 -ErrorAction Stop
    Write-Log "Última atualização de acesso desativada com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Verificando tipo de plataforma do sistema..." -ConsoleOutput
    $PlatformCheck = (Get-ComputerInfo -ErrorAction Stop).CsPCSystemType
    Write-Log "Plataforma detectada: $PlatformCheck" -ConsoleOutput

    if ($PlatformCheck -eq "Desktop") {
      Write-Output "A plataforma é $PlatformCheck. Desativando opções de economia de energia em todos os dispositivos conectados..."
      Write-Log "A plataforma é $PlatformCheck. Desativando opções de economia de energia em todos os dispositivos conectados..." -ConsoleOutput

      Get-WmiObject MSPower_DeviceEnable -Namespace root\wmi -ErrorAction Stop | ForEach-Object { 
        Write-Log "Desativando economia de energia para dispositivo: $($_.InstanceName)..." -ConsoleOutput
        $_.enable = $false
        $_.psbase.put() | Out-Null
        Write-Log "Economia de energia desativada com sucesso para $($_.InstanceName)." -Level "INFO" -ConsoleOutput
      }
      Write-Log "Opções de economia de energia desativadas com sucesso em todos os dispositivos conectados." -Level "INFO" -ConsoleOutput
    }
    else {
      Write-Output "A plataforma é $PlatformCheck. Nenhuma edição de economia de energia foi realizada."
      Write-Log "A plataforma é $PlatformCheck. Nenhuma edição de economia de energia foi realizada." -ConsoleOutput
    }

    Write-Log "Correções de otimização para jogos aplicadas com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função GameOptimizationFIX: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    throw  # Repropaga o erro
  }
  finally {
    Write-Log "Finalizando função GameOptimizationFIX." -Level "INFO" -ConsoleOutput
  }
}

Function RawMouseInput {
  Write-Log "Iniciando função RawMouseInput para forçar entrada bruta do mouse e desativar precisão aprimorada do ponteiro." -ConsoleOutput

  try {
    Write-Output "Forçando entrada bruta do mouse e desativando precisão aprimorada do ponteiro..."
    Write-Log "Forçando entrada bruta do mouse e desativando precisão aprimorada do ponteiro..." -ConsoleOutput

    Write-Log "Configurando MouseSpeed para 0 em HKCU:\Control Panel\Mouse..." -ConsoleOutput
    Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSpeed" -Type String -Value "0" -ErrorAction Stop
    Write-Log "MouseSpeed configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Configurando MouseThreshold1 para 0 em HKCU:\Control Panel\Mouse..." -ConsoleOutput
    Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold1" -Type String -Value "0" -ErrorAction Stop
    Write-Log "MouseThreshold1 configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Configurando MouseThreshold2 para 0 em HKCU:\Control Panel\Mouse..." -ConsoleOutput
    Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold2" -Type String -Value "0" -ErrorAction Stop
    Write-Log "MouseThreshold2 configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Configurando MouseSensitivity para 10 em HKCU:\Control Panel\Mouse..." -ConsoleOutput
    Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSensitivity" -Type String -Value "10" -ErrorAction Stop
    Write-Log "MouseSensitivity configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Configurando MouseHoverTime para 0 em HKCU:\Control Panel\Mouse..." -ConsoleOutput
    Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseHoverTime" -Type String -Value "0" -ErrorAction Stop
    Write-Log "MouseHoverTime configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Configurando MouseTrails para 0 em HKCU:\Control Panel\Mouse..." -ConsoleOutput
    Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseTrails" -Type String -Value "0" -ErrorAction Stop
    Write-Log "MouseTrails configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Entrada bruta do mouse forçada e precisão aprimorada do ponteiro desativada com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função RawMouseInput: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    throw  # Repropaga o erro
  }
  finally {
    Write-Log "Finalizando função RawMouseInput." -Level "INFO" -ConsoleOutput
  }
}

Function DetectnApplyMouseFIX {
  Add-Type @'
  using System; 
  using System.Runtime.InteropServices;
  using System.Drawing;

  public class DPI {  
    [DllImport("gdi32.dll")]
    static extern int GetDeviceCaps(IntPtr hdc, int nIndex);

    public enum DeviceCap {
      VERTRES = 10,
      DESKTOPVERTRES = 117
    } 

    public static float scaling() {
      Graphics g = Graphics.FromHwnd(IntPtr.Zero);
      IntPtr desktop = g.GetHdc();
      int LogicalScreenHeight = GetDeviceCaps(desktop, (int)DeviceCap.VERTRES);
      int PhysicalScreenHeight = GetDeviceCaps(desktop, (int)DeviceCap.DESKTOPVERTRES);

      return (float)PhysicalScreenHeight / (float)LogicalScreenHeight;
    }
  }
'@ -ReferencedAssemblies 'System.Drawing.dll'

  $checkscreenscale = [Math]::round([DPI]::scaling(), 2) * 100
  if ($checkscreenscale -eq "100") {
    Write-Output "Windows screen scale is Detected as 100%, Applying Mouse Fix for it..."
    $YourInputX = "00,00,00,00,00,00,00,00,C0,CC,0C,00,00,00,00,00,80,99,19,00,00,00,00,00,40,66,26,00,00,00,00,00,00,33,33,00,00,00,00,00"
    $YourInputY = "00,00,00,00,00,00,00,00,00,00,38,00,00,00,00,00,00,00,70,00,00,00,00,00,00,00,A8,00,00,00,00,00,00,00,E0,00,00,00,00,00"
    $RegPath = 'HKCU:\Control Panel\Mouse'
    $hexifiedX = $YourInputX.Split(',') | ForEach-Object { "0x$_" }
    $hexifiedY = $YourInputY.Split(',') | ForEach-Object { "0x$_" }
    Set-ItemProperty -Path "$RegPath" -Name "SmoothMouseXCurve" -Type Binary -Value (([byte[]]$hexifiedX))
    Set-ItemProperty -Path "$RegPath" -Name "SmoothMouseYCurve" -Type Binary -Value (([byte[]]$hexifiedY))
  }
  elseif ($checkscreenscale -eq "125") {
    Write-Output "Windows screen scale is Detected as 125%, Applying Mouse Fix for it..."
    $YourInputX = "00,00,00,00,00,00,00,00,00,00,10,00,00,00,00,00,00,00,20,00,00,00,00,00,00,00,30,00,00,00,00,00,00,00,40,00,00,00,00,00"
    $YourInputY = "00,00,00,00,00,00,00,00,00,00,38,00,00,00,00,00,00,00,70,00,00,00,00,00,00,00,A8,00,00,00,00,00,00,00,E0,00,00,00,00,00"
    $RegPath = 'HKCU:\Control Panel\Mouse'
    $hexifiedX = $YourInputX.Split(',') | ForEach-Object { "0x$_" }
    $hexifiedY = $YourInputY.Split(',') | ForEach-Object { "0x$_" }
    Set-ItemProperty -Path "$RegPath" -Name "SmoothMouseXCurve" -Type Binary -Value (([byte[]]$hexifiedX))
    Set-ItemProperty -Path "$RegPath" -Name "SmoothMouseYCurve" -Type Binary -Value (([byte[]]$hexifiedY))
  }
  elseif ($checkscreenscale -eq "150") {
    Write-Output "Windows screen scale is Detected as 150%, Applying Mouse Fix for it..."
    $YourInputX = "00,00,00,00,00,00,00,00,30,33,13,00,00,00,00,00,60,66,26,00,00,00,00,00,90,99,39,00,00,00,00,00,C0,CC,4C,00,00,00,00,00"
    $YourInputY = "00,00,00,00,00,00,00,00,00,00,38,00,00,00,00,00,00,00,70,00,00,00,00,00,00,00,A8,00,00,00,00,00,00,00,E0,00,00,00,00,00"
    $RegPath = 'HKCU:\Control Panel\Mouse'
    $hexifiedX = $YourInputX.Split(',') | ForEach-Object { "0x$_" }
    $hexifiedY = $YourInputY.Split(',') | ForEach-Object { "0x$_" }
    Set-ItemProperty -Path "$RegPath" -Name "SmoothMouseXCurve" -Type Binary -Value (([byte[]]$hexifiedX))
    Set-ItemProperty -Path "$RegPath" -Name "SmoothMouseYCurve" -Type Binary -Value (([byte[]]$hexifiedY))
  }
  elseif ($checkscreenscale -eq "175") {
    Write-Output "Windows screen scale is Detected as 175%, Applying Mouse Fix for it..."
    $YourInputX = "00,00,00,00,00,00,00,00,60,66,16,00,00,00,00,00,C0,CC,2C,00,00,00,00,00,20,33,43,00,00,00,00,00,80,99,59,00,00,00,00,00"
    $YourInputY = "00,00,00,00,00,00,00,00,00,00,38,00,00,00,00,00,00,00,70,00,00,00,00,00,00,00,A8,00,00,00,00,00,00,00,E0,00,00,00,00,00"
    $RegPath = 'HKCU:\Control Panel\Mouse'
    $hexifiedX = $YourInputX.Split(',') | ForEach-Object { "0x$_" }
    $hexifiedY = $YourInputY.Split(',') | ForEach-Object { "0x$_" }
    Set-ItemProperty -Path "$RegPath" -Name "SmoothMouseXCurve" -Type Binary -Value (([byte[]]$hexifiedX))
    Set-ItemProperty -Path "$RegPath" -Name "SmoothMouseYCurve" -Type Binary -Value (([byte[]]$hexifiedY))
  }
  elseif ($checkscreenscale -eq "200") {
    Write-Output "Windows screen scale is Detected as 200%, Applying Mouse Fix for it..."
    $YourInputX = "00,00,00,00,00,00,00,00,90,99,19,00,00,00,00,00,20,33,33,00,00,00,00,00,B0,CC,4C,00,00,00,00,00,40,66,66,00,00,00,00,00"
    $YourInputY = "00,00,00,00,00,00,00,00,00,00,38,00,00,00,00,00,00,00,70,00,00,00,00,00,00,00,A8,00,00,00,00,00,00,00,E0,00,00,00,00,00"
    $RegPath = 'HKCU:\Control Panel\Mouse'
    $hexifiedX = $YourInputX.Split(',') | ForEach-Object { "0x$_" }
    $hexifiedY = $YourInputY.Split(',') | ForEach-Object { "0x$_" }
    Set-ItemProperty -Path "$RegPath" -Name "SmoothMouseXCurve" -Type Binary -Value (([byte[]]$hexifiedX))
    Set-ItemProperty -Path "$RegPath" -Name "SmoothMouseYCurve" -Type Binary -Value (([byte[]]$hexifiedY))
  }
  elseif ($checkscreenscale -eq "225") {
    Write-Output "Windows screen scale is Detected as 225%, Applying Mouse Fix for it..."
    $YourInputX = "00,00,00,00,00,00,00,00,C0,CC,1C,00,00,00,00,00,80,99,39,00,00,00,00,00,40,66,56,00,00,00,00,00,00,33,73,00,00,00,00,00"
    $YourInputY = "00,00,00,00,00,00,00,00,00,00,38,00,00,00,00,00,00,00,70,00,00,00,00,00,00,00,A8,00,00,00,00,00,00,00,E0,00,00,00,00,00"
    $RegPath = 'HKCU:\Control Panel\Mouse'
    $hexifiedX = $YourInputX.Split(',') | ForEach-Object { "0x$_" }
    $hexifiedY = $YourInputY.Split(',') | ForEach-Object { "0x$_" }
    Set-ItemProperty -Path "$RegPath" -Name "SmoothMouseXCurve" -Type Binary -Value (([byte[]]$hexifiedX))
    Set-ItemProperty -Path "$RegPath" -Name "SmoothMouseYCurve" -Type Binary -Value (([byte[]]$hexifiedY))
  }
  elseif ($checkscreenscale -eq "250") {
    Write-Output "Windows screen scale is Detected as 250%, Applying Mouse Fix for it..."
    $YourInputX = "00,00,00,00,00,00,00,00,00,00,20,00,00,00,00,00,00,00,40,00,00,00,00,00,00,00,60,00,00,00,00,00,00,00,80,00,00,00,00,00"
    $YourInputY = "00,00,00,00,00,00,00,00,00,00,38,00,00,00,00,00,00,00,70,00,00,00,00,00,00,00,A8,00,00,00,00,00,00,00,E0,00,00,00,00,00"
    $RegPath = 'HKCU:\Control Panel\Mouse'
    $hexifiedX = $YourInputX.Split(',') | ForEach-Object { "0x$_" }
    $hexifiedY = $YourInputY.Split(',') | ForEach-Object { "0x$_" }
    Set-ItemProperty -Path "$RegPath" -Name "SmoothMouseXCurve" -Type Binary -Value (([byte[]]$hexifiedX))
    Set-ItemProperty -Path "$RegPath" -Name "SmoothMouseYCurve" -Type Binary -Value (([byte[]]$hexifiedY))
  }
  elseif ($checkscreenscale -eq "300") {
    Write-Output "Windows screen scale is Detected as 300%, Applying Mouse Fix for it..."
    $YourInputX = "00,00,00,00,00,00,00,00,60,66,26,00,00,00,00,00,C0,CC,4C,00,00,00,00,00,20,33,73,00,00,00,00,00,80,99,99,00,00,00,00,00"
    $YourInputY = "00,00,00,00,00,00,00,00,00,00,38,00,00,00,00,00,00,00,70,00,00,00,00,00,00,00,A8,00,00,00,00,00,00,00,E0,00,00,00,00,00"
    $RegPath = 'HKCU:\Control Panel\Mouse'
    $hexifiedX = $YourInputX.Split(',') | ForEach-Object { "0x$_" }
    $hexifiedY = $YourInputY.Split(',') | ForEach-Object { "0x$_" }
    Set-ItemProperty -Path "$RegPath" -Name "SmoothMouseXCurve" -Type Binary -Value (([byte[]]$hexifiedX))
    Set-ItemProperty -Path "$RegPath" -Name "SmoothMouseYCurve" -Type Binary -Value (([byte[]]$hexifiedY))
  }
  elseif ($checkscreenscale -eq "350") {
    Write-Output "Windows screen scale is Detected as 350%, Applying Mouse Fix for it..."
    $YourInputX = "00,00,00,00,00,00,00,00,C0,CC,2C,00,00,00,00,00,80,99,59,00,00,00,00,00,40,66,86,00,00,00,00,00,00,33,B3,00,00,00,00,00"
    $YourInputY = "00,00,00,00,00,00,00,00,00,00,38,00,00,00,00,00,00,00,70,00,00,00,00,00,00,00,A8,00,00,00,00,00,00,00,E0,00,00,00,00,00"
    $RegPath = 'HKCU:\Control Panel\Mouse'
    $hexifiedX = $YourInputX.Split(',') | ForEach-Object { "0x$_" }
    $hexifiedY = $YourInputY.Split(',') | ForEach-Object { "0x$_" }
    Set-ItemProperty -Path "$RegPath" -Name "SmoothMouseXCurve" -Type Binary -Value (([byte[]]$hexifiedX))
    Set-ItemProperty -Path "$RegPath" -Name "SmoothMouseYCurve" -Type Binary -Value (([byte[]]$hexifiedY))
  }
  else {
    Write-Output "HOUSTON WE HAVE A PROBLEM! screen scale is not set to traditional value, nothing has been set!"
  }
}

Function DisableHPET {
  Write-Output "Disabling High Precision Event Timer..."
  $errpref = $ErrorActionPreference #save actual preference
  $ErrorActionPreference = "silentlycontinue"
  bcdedit /set x2apicpolicy Enable | Out-Null
  bcdedit /set configaccesspolicy Default | Out-Null
  bcdedit /set MSI Default | Out-Null
  bcdedit /set usephysicaldestination No | Out-Null
  bcdedit /set usefirmwarepcisettings No | Out-Null
  bcdedit /deletevalue useplatformclock | Out-Null
  bcdedit /deletevalue useplatformtick | Out-Null
  bcdedit /deletevalue disabledynamictick | Out-Null
  bcdedit /deletevalue tscsyncpolicy | Out-Null
  bcdedit /timeout 10 | Out-Null
  bcdedit /set nx optout | Out-Null
  bcdedit /set bootux disabled | Out-Null
  bcdedit /set quietboot yes | Out-Null
  bcdedit /set { globalsettings } custom:16000067 true | Out-Null
  bcdedit /set { globalsettings } custom:16000069 true | Out-Null
  bcdedit /set { globalsettings } custom:16000068 true | Out-Null
  wmic path Win32_PnPEntity where "name='High precision event timer'" call enable | Out-Null
  if ($PlatformCheck -eq "Desktop") {
    Write-Output "Platform is $PlatformCheck disabling dynamic tick..."
    bcdedit /set disabledynamictick yes | Out-Null
  }
  else {
    Write-Output "Platform is $PlatformCheck enabling dynamic tick..."
    bcdedit /set disabledynamictick no
  }
  $ErrorActionPreference = $errpref #restore previous preference
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

# Função DisableCoreParking (mantida como antes, mas ajustada para consistência)
Function DisableCoreParking {
  [CmdletBinding(SupportsShouldProcess = $true)]
  Param (
    [Parameter(Mandatory = $true)]
    [string]$PlanGUID
  )

  Begin {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
      Write-Error "Este script deve ser executado como administrador."
      return
    }

    try {
      $null = Get-Command powercfg -ErrorAction Stop
    }
    catch {
      Write-Error "Comando powercfg não encontrado."
      return
    }

    Write-Output "Desativando Core Parking no plano com GUID: $PlanGUID..."
  }

  Process {
    $success = $false
    try {
      # Ativar o plano
      & powercfg /setactive $PlanGUID 2>$null
      if ($LASTEXITCODE -ne 0) {
        Write-Error "Falha ao ativar o plano $PlanGUID."
        return
      }
      Write-Output "Plano ativado: $PlanGUID"

      # Desativar Core Parking
      & powercfg -attributes SUB_PROCESSOR CPMINCORES -ATTRIB_HIDE 2>$null
      & powercfg -setacvalueindex $PlanGUID SUB_PROCESSOR CPMINCORES 100 2>$null
      if ($LASTEXITCODE -ne 0) {
        Write-Warning "Falha ao ajustar CPMINCORES."
      }
      else {
        Write-Verbose "Core Parking desativado (CPMINCORES = 100)."
      }

      # Outras configurações
      $settings = @(
        @{ GUID = "2a737441-1930-4402-8d77-b2bebba308a3"; SubGUID = "d4e98f31-5ffe-4ce1-be31-1b38b384c009"; Value = 0 },
        @{ GUID = "2a737441-1930-4402-8d77-b2bebba308a3"; SubGUID = "48e6b7a6-50f5-4782-a5d4-53bb8f07e226"; Value = 0 },
        @{ GUID = "7516b95f-f776-4464-8c53-06167f40cc99"; SubGUID = "3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e"; Value = 0 },
        @{ GUID = "54533251-82be-4824-96c1-47b60b740d00"; SubGUID = "4d2b0152-7d5c-498b-88e2-34345392a2c5"; Value = 5000 }
      )

      foreach ($setting in $settings) {
        & powercfg /setacvalueindex $PlanGUID $setting.GUID $setting.SubGUID $setting.Value 2>$null
        if ($LASTEXITCODE -eq 0) {
          Write-Verbose "Configuração $($setting.GUID)/$($setting.SubGUID) ajustada para $($setting.Value)."
        }
      }

      # Reativar o plano
      & powercfg /setactive $PlanGUID 2>$null
      if ($LASTEXITCODE -eq 0) {
        Write-Output "Core Parking desativado no plano $PlanGUID."
        $success = $true
      }
      else {
        Write-Error "Falha ao reativar o plano $PlanGUID."
        return
      }
    }
    catch {
      Write-Error "Erro ao desativar Core Parking: $_"
      return
    }
  }

  End {
    if ($success) {
      Write-Output "Desativação do Core Parking concluída. Reinicie o sistema para garantir as alterações."
    }
  }
}

# Função ManagePowerProfiles (corrigida)
function ManagePowerProfiles {
  Write-Log "Iniciando função ManagePowerProfiles para gerenciar perfis de energia." -ConsoleOutput

  try {
    Write-Output "Gerenciando Perfis de Energia..."
    Clear-Host
    Write-Log "Exibindo menu de opções para gerenciar perfis de energia." -ConsoleOutput
    $banner = @(
      "",
      "",
      "╔═══════════════════════════════════════════╗",
      "╠════════ Gerenciar Perfis de Energia ══════╣",
      "╚═══════════════════════════════════════════╝",
      "",
      "≫ Escolha uma opção para configurar o perfil de energia:",
      "",
      "≫ 1 - Perfil Full Power Gaming (ideal para jogos)",
      "≫ 2 - Perfil Balanceado (padrão do Windows)",
      "≫ 3 - Perfil Econômico (economia de energia)",
      "≫ 4 - Pular esta etapa",
      ""
    )

    $colors = @(
      "Branco", "Branco", 
      "Amarelo", "Amarelo", "Amarelo", 
      "Branco", 
      "AmareloClaro", 
      "Branco", 
      "AmareloClaro", "AmareloClaro", "AmareloClaro", "AmareloClaro", 
      "Branco"
    )

    for ($i = 0; $i -lt $banner.Length; $i++) {
      $color = if ($i -lt $colors.Length) { $colors[$i] } else { "Branco" }
      Write-Colored $banner[$i] $color
    }

    do {
      
      Write-Colored "" "Branco"
      Write-Colored "Digite sua escolha (1-4):" "Cyan"
      $choice = Read-Host
      Write-Log "Usuário selecionou: $choice" -ConsoleOutput
    } until ($choice -match "^[1-4]$")

    switch ($choice) {
      "1" {
        Write-Log "Aplicando perfil Full Power Gaming..." -ConsoleOutput
        Write-Colored "Configurando perfil Full Power Gaming..." -Color "VerdeClaro"
        $fullPowerGamingGUID = "7c6f06f3-81e0-4dd7-a003-46b268fffb5a"  # GUID original

        # Verificar se o GUID existe
        $schemes = & powercfg /list | ForEach-Object {
          if ($_ -match "(\w{8}-\w{4}-\w{4}-\w{4}-\w{12})") {
            $matches[1]
          }
        }

        if ($schemes -notcontains $fullPowerGamingGUID) {
          Write-Output "O perfil Full Power Gaming (GUID: $fullPowerGamingGUID) não existe. Criando um novo..."
          # Criar novo plano baseado em Alto Desempenho
          $newSchemeOutput = & powercfg /duplicatescheme 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
          if ($newSchemeOutput) {
            $newGUID = $newSchemeOutput | Select-String -Pattern "(\w{8}-\w{4}-\w{4}-\w{4}-\w{12})" | ForEach-Object { $_.Matches.Value }
            if ($newGUID) {
              & powercfg /changename $newGUID "Full Power Gaming" "Perfil otimizado para jogos" 2>$null
              $fullPowerGamingGUID = $newGUID
              Write-Output "Novo perfil Full Power Gaming criado com GUID: $fullPowerGamingGUID"
            }
            else {
              Write-Error "Falha ao extrair o novo GUID após duplicação."
              return
            }
          }
          else {
            Write-Error "Falha ao duplicar o plano Alto Desempenho."
            return
          }
        }

        # Ativar o plano (existente ou recém-criado)
        & powercfg /setactive $fullPowerGamingGUID 2>$null
        if ($LASTEXITCODE -ne 0) {
          Write-Error "Falha ao ativar o perfil Full Power Gaming com GUID: $fullPowerGamingGUID"
          return
        }
        Write-Output "Perfil Full Power Gaming ativado com sucesso!"

        # Ajustes adicionais
        & powercfg /change standby-timeout-ac 0 2>$null
        & powercfg /change hibernate-timeout-ac 0 2>$null
        & powercfg /change monitor-timeout-ac 0 2>$null

        Write-Log "Perfil Full Power Gaming aplicado com sucesso." -Level "INFO" -ConsoleOutput
        Write-Colored "Perfil Full Power Gaming aplicado com sucesso!" -Color "Verde"

        # Chamar DisableCoreParking
        Write-Output "Desativando Core Parking no perfil Full Power Gaming..."
        DisableCoreParking -PlanGUID $fullPowerGamingGUID
      }
      "2" {
        Write-Log "Aplicando perfil Balanceado..." -ConsoleOutput
        Write-Colored "Configurando perfil Balanceado..." -Color "AmareloClaro"
        $balancedGUID = "381b4222-f694-41f0-9685-ff5bb260df2e"
        & powercfg /setactive $balancedGUID 2>$null
        Write-Log "Perfil Balanceado aplicado com sucesso." -Level "INFO" -ConsoleOutput
        Write-Colored "Perfil Balanceado aplicado com sucesso!" -Color "Amarelo"
      }
      "3" {
        Write-Log "Aplicando perfil Econômico..." -ConsoleOutput
        Write-Colored "Configurando perfil Econômico..." -Color "CianoClaro"
        $powerSaverGUID = "a1841308-3541-4fab-bc81-f71556f20b4a"
        & powercfg /setactive $powerSaverGUID 2>$null
        & powercfg /change standby-timeout-ac 10 2>$null
        & powercfg /change monitor-timeout-ac 5 2>$null
        Write-Log "Perfil Econômico aplicado com sucesso." -Level "INFO" -ConsoleOutput
        Write-Colored "Perfil Econômico aplicado com sucesso!" -Color "Ciano"
      }
      "4" {
        Write-Log "Perfil de energia não alterado (opção de pular escolhida)." -Level "INFO" -ConsoleOutput
        Write-Colored "Configuração de perfil de energia ignorada." -Color "VermelhoClaro"
      }
    }
  }
  catch {
    $errorMessage = "Erro ao gerenciar perfis de energia: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    Write-Colored $errorMessage -Color "Vermelho"
  }
  finally {
    Write-Log "Finalizando função ManagePowerProfiles." -Level "INFO" -ConsoleOutput
  }
}

# Configuração inicial para codificação
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'
$PSDefaultParameterValues['*:Encoding'] = 'utf8'
[System.Threading.Thread]::CurrentThread.CurrentCulture = "pt-BR"
[System.Threading.Thread]::CurrentThread.CurrentUICulture = "pt-BR"

function DisableDMA {
  Write-Output "Disabling Direct Memory Access remapping..."
  bcdedit /set configaccesspolicy DisallowMmConfig | Out-Null
}

Function DisablePKM {
  Write-Output "Disabling Process and Kernel Mitigations..."
  $errpref = $ErrorActionPreference #save actual preference
  $ErrorActionPreference = "silentlycontinue"
  ForEach ($v in (Get-Command -Name "Set-ProcessMitigation").Parameters["Disable"].Attributes.ValidValues) { Set-ProcessMitigation -System -Disable $v.ToString() -ErrorAction SilentlyContinue }
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DisableExceptionChainValidation" -Type DWord -Value 1
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "KernelSEHOPEnabled" -Type DWord -Value 0
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "EnableCfg" -Type DWord -Value 0
  $ErrorActionPreference = $errpref #restore previous preference
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
  $banner = @(
    "",
    "",
    "╔═══════════════════════════════════════╗",
    "╠══════ Ativar Serviços Essenciais ══════╣",
    "╚═══════════════════════════════════════╝",
    "",
    "≫ Este menu auxilia na ativação dos seguintes serviços, essenciais para investigação forense de cheats em servidores de Minecraft, DayZ e FIVEM GTA5 que utilizam o Echo AntiCheat:",
    "",
    "≫ SysMain: O SysMain, anteriormente conhecido como Superfetch, é um serviço do Windows que preenche a memória RAM com aplicativos frequentemente usados para acelerar o carregamento dos programas mais utilizados.",
    "≫ PcaSvc: O PcaSvc (Program Compatibility Assistant Service) é um serviço que detecta problemas de compatibilidade em programas legados e aplica correções para melhorar a estabilidade do sistema.",
    "≫ DiagTrack: O DiagTrack (Connected User Experiences and Telemetry) coleta e envia dados de diagnóstico e uso para a Microsoft, auxiliando na melhoria dos serviços e na resolução de problemas.",
    ""
  )

  $colors = @(
    "Branco", "Branco", 
    "Amarelo", "Amarelo", "Amarelo", 
    "Branco", 
    "AmareloClaro", 
    "Branco", 
    "AmareloClaro", "AmareloClaro", "AmareloClaro", 
    "Branco"
  )

  for ($i = 0; $i -lt $banner.Length; $i++) {
    $color = if ($i -lt $colors.Length) { $colors[$i] } else { "Branco" }
    Write-Colored $banner[$i] $color
  }
  # Função interna para ativar um serviço
  function Ativar-Servico {
    param (
      [string]$NomeServico
    )
    $servico = Get-Service -Name $NomeServico -ErrorAction SilentlyContinue
    if ($null -eq $servico) {
      Write-Colored "Serviço '$NomeServico' não encontrado." "VermelhoClaro"
      return
    }
    Write-Colored "Serviço encontrado: $($servico.DisplayName) ($($servico.Name))" "CinzaClaro"
    if ($servico.Status -eq 'Running') {
      Write-Colored "Serviço '$($servico.Name)' já está em execução." "VerdeClaro"
    }
    else {
      Start-Service -Name $servico.Name
      Set-Service -Name $servico.Name -StartupType Automatic
      Write-Colored "Serviço '$($servico.Name)' ativado com sucesso." "VerdeClaro"
    }
  }

  # Loop para cada serviço
  foreach ($nomeServico in $Servicos) {
    $pergunta = "Deseja ativar o serviço '$nomeServico'? (S/N): "
    $resposta = Read-Host -Prompt $pergunta
    if ($resposta.ToUpper() -eq 'S') {
      Ativar-Servico -NomeServico $nomeServico
    }
    else {
      Write-Colored "Serviço '$nomeServico' não foi ativado." "Amarelo"
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

  Write-Log "Iniciando função Remove-OneDrive para desinstalar o OneDrive." -ConsoleOutput

  try {
    if ($AskUser) {
      Clear-Host
      Write-Log "Exibindo menu de opções para desinstalar o OneDrive." -ConsoleOutput
      $banner = @(
        "",
        "",
        "╔════════════════════════════════════════╗",
        "╠════════ Desinstalar o OneDrive ════════╣",
        "╚════════════════════════════════════════╝",
        "",
        "≫ Este menu permite desinstalar o OneDrive do sistema.",
        "≫ O processo encerrará o OneDrive, desinstalará o programa e removerá pastas associadas.",
        "≫ Atenção: Certifique-se de que todos os arquivos importantes foram sincronizados ou movidos antes de prosseguir.",
        "",
        "≫ Pressione 'S' para desinstalar o OneDrive.",
        "≫ Pressione 'N' para pular esta etapa.",
        ""
      )

      $colors = @(
        "Branco", "Branco", 
        "Amarelo", "Amarelo", "Amarelo", 
        "Branco", 
        "AmareloClaro", "AmareloClaro", "AmareloClaro", 
        "Branco", 
        "AmareloClaro", "AmareloClaro", 
        "Branco"
      )

      for ($i = 0; $i -lt $banner.Length; $i++) {
        $color = if ($i -lt $colors.Length) { $colors[$i] } else { "Branco" }
        Write-Colored $banner[$i] $color
      }

      do {
        
        Write-Colored "" "Branco"
        Write-Colored "Digite sua escolha (S/N):" "Cyan"
        $selection = Read-Host
        Write-Log "Usuário selecionou: $selection" -ConsoleOutput
      } until ($selection -match "(?i)^(s|n)$")

      if ($selection -match "(?i)^n$") {
        Write-Log "Desinstalação do OneDrive ignorada pelo usuário." -Level "INFO" -ConsoleOutput
        Write-Colored "Desinstalação do OneDrive ignorada." -Color "AmareloClaro"
        return
      }
    }

    Write-Output "Desinstalando o OneDrive..."
    Write-Log "Iniciando desinstalação do OneDrive..." -ConsoleOutput

    Write-Log "Verificando se o processo OneDrive está em execução..." -ConsoleOutput
    $onedriveProcess = Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue

    if ($onedriveProcess) {
      Write-Log "Processo OneDrive encontrado. Encerrando..." -ConsoleOutput
      Stop-Process -Name "OneDrive" -Force -ErrorAction Stop
      Write-Log "Processo OneDrive parado com sucesso." -Level "INFO" -ConsoleOutput
      Start-Sleep -Seconds 2
    }
    else {
      Write-Log "Processo OneDrive não encontrado. Continuando a desinstalação..." -Level "WARNING" -ConsoleOutput
    }

    $onedrivePath = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
    if (Test-Path $onedrivePath) {
      Write-Log "Executando $onedrivePath /uninstall para desinstalar o OneDrive..." -ConsoleOutput
      Start-Process -FilePath $onedrivePath -ArgumentList "/uninstall" -Wait -NoNewWindow -ErrorAction Stop
      Write-Log "OneDrive desinstalado via OneDriveSetup.exe com sucesso." -Level "INFO" -ConsoleOutput
    }
    else {
      Write-Log "OneDriveSetup.exe não encontrado em $onedrivePath. Pode já estar desinstalado." -Level "WARNING" -ConsoleOutput
      Write-Output "OneDriveSetup.exe não encontrado em $onedrivePath. Pode já estar desinstalado."
    }

    Write-Log "Removendo pasta $env:USERPROFILE\OneDrive..." -ConsoleOutput
    Remove-Item "$env:USERPROFILE\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
    Write-Log "Pasta $env:USERPROFILE\OneDrive removida com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Removendo pasta $env:LOCALAPPDATA\Microsoft\OneDrive..." -ConsoleOutput
    Remove-Item "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
    Write-Log "Pasta $env:LOCALAPPDATA\Microsoft\OneDrive removida com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Removendo pasta $env:PROGRAMDATA\Microsoft OneDrive..." -ConsoleOutput
    Remove-Item "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
    Write-Log "Pasta $env:PROGRAMDATA\Microsoft OneDrive removida com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Removendo $env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe..." -ConsoleOutput
    Remove-Item "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe" -Force -ErrorAction SilentlyContinue
    Write-Log "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe removido com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "OneDrive desinstalado com sucesso." -Level "INFO" -ConsoleOutput
    Write-Colored "OneDrive desinstalado com sucesso." -Color "VerdeClaro"
  }
  catch {
    $errorMessage = "Erro ao desinstalar o OneDrive: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    Write-Colored $errorMessage -Color "VermelhoClaro"
    throw  # Repropaga o erro
  }
  finally {
    Write-Log "Finalizando função Remove-OneDrive." -Level "INFO" -ConsoleOutput
  }
}

function Windows11Extras {
  Write-Log "Iniciando função Windows11Extras para aplicar ajustes específicos do Windows 11." -ConsoleOutput

  try {
    $osBuild = [System.Environment]::OSVersion.Version.Build
    Write-Log "Versão do sistema operacional detectada: Build $osBuild" -ConsoleOutput

    if ($osBuild -ge 22000) {
      Write-Output "Applying Windows 11 specific tweaks..."
      Write-Log "Aplicando ajustes específicos do Windows 11..." -ConsoleOutput

      Write-Log "Configurando TaskbarAl para 0 em HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced..." -ConsoleOutput
      Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Type DWord -Value 0 -ErrorAction Stop
      Write-Log "TaskbarAl configurado com sucesso para centralizar a barra de tarefas." -Level "INFO" -ConsoleOutput

      Write-Log "Configurando SearchboxTaskbarMode para 1 em HKCU:\Software\Microsoft\Windows\CurrentVersion\Search..." -ConsoleOutput
      Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 1 -ErrorAction Stop
      Write-Log "SearchboxTaskbarMode configurado com sucesso para mostrar busca na barra." -Level "INFO" -ConsoleOutput

      Write-Log "Ajustes específicos do Windows 11 aplicados com sucesso." -Level "INFO" -ConsoleOutput
    }
    else {
      Write-Log "Sistema operacional não é Windows 11 (Build < 22000). Pulando ajustes." -Level "INFO" -ConsoleOutput
    }
  }
  catch {
    $errorMessage = "Erro na função Windows11Extras: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    throw  # Repropaga o erro
  }
  finally {
    Write-Log "Finalizando função Windows11Extras." -Level "INFO" -ConsoleOutput
  }
}

function DebloatAll {
  Write-Log "Iniciando função DebloatAll para executar o processo completo de debloat." -ConsoleOutput

  try {
    Write-Output "Running full debloat process..."
    Write-Log "Executando o processo completo de debloat..." -ConsoleOutput

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
    Write-Log "Lista de bloatware carregada: $($bloatware -join ', ')" -ConsoleOutput

    foreach ($app in $bloatware) {
      Write-Log "Removendo o aplicativo $app para todos os usuários..." -ConsoleOutput
      Get-AppxPackage -Name $app -AllUsers -ErrorAction Stop | Remove-AppxPackage -ErrorAction Stop
      Write-Log "Aplicativo $app removido com sucesso para todos os usuários." -Level "INFO" -ConsoleOutput

      Write-Log "Removendo o pacote provisionado $app..." -ConsoleOutput
      Get-AppxProvisionedPackage -Online -ErrorAction Stop | Where-Object DisplayName -eq $app | Remove-AppxProvisionedPackage -Online -ErrorAction Stop
      Write-Log "Pacote provisionado $app removido com sucesso." -Level "INFO" -ConsoleOutput
    }

    Write-Log "Processo completo de debloat concluído com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função DebloatAll: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    throw  # Repropaga o erro
  }
  finally {
    Write-Log "Finalizando função DebloatAll." -Level "INFO" -ConsoleOutput
  }
}

function RemoveBloatRegistry {
  Write-Log "Iniciando função RemoveBloatRegistry para remover entradas de registro de bloatware." -ConsoleOutput

  try {
    Write-Output "Removing bloatware registry entries..."
    Write-Log "Removendo entradas de registro de bloatware..." -ConsoleOutput

    $keys = @(
      "HKCR:\Applications\photoviewer.dll",
      "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}"
    )
    Write-Log "Lista de chaves de registro carregada: $($keys -join ', ')" -ConsoleOutput

    foreach ($key in $keys) {
      Write-Log "Verificando e removendo a chave de registro $key..." -ConsoleOutput

      if (Test-Path $key) {
        Write-Log "Caminho $key encontrado. Removendo..." -ConsoleOutput
        Remove-Item -Path $key -Recurse -Force -ErrorAction Stop
        Write-Log "Chave $key removida com sucesso." -Level "INFO" -ConsoleOutput
      }
      else {
        Write-Log "Caminho $key não encontrado. Nenhuma ação necessária." -Level "WARNING" -ConsoleOutput
      }
    }

    Write-Log "Entradas de registro de bloatware processadas com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função RemoveBloatRegistry: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    throw  # Repropaga o erro
  }
  finally {
    Write-Log "Finalizando função RemoveBloatRegistry." -Level "INFO" -ConsoleOutput
  }
}

function UninstallMsftBloat {
  Write-Log "Iniciando função UninstallMsftBloat para desinstalar bloatware adicional da Microsoft." -ConsoleOutput

  try {
    Write-Output "Uninstalling additional Microsoft bloatware..."
    Write-Log "Desinstalando bloatware adicional da Microsoft..." -ConsoleOutput

    $bloatware = @(
      "Microsoft.Windows.Photos",
      "Microsoft.MicrosoftEdge.Stable",
      "Microsoft.WindowsStore"
    )
    Write-Log "Lista de bloatware carregada: $($bloatware -join ', ')" -ConsoleOutput

    foreach ($app in $bloatware) {
      Write-Log "Removendo o aplicativo $app para todos os usuários..." -ConsoleOutput
      Get-AppxPackage -Name $app -AllUsers -ErrorAction Stop | Remove-AppxPackage -ErrorAction Stop
      Write-Log "Aplicativo $app removido com sucesso para todos os usuários." -Level "INFO" -ConsoleOutput

      Write-Log "Removendo o pacote provisionado $app..." -ConsoleOutput
      Get-AppxProvisionedPackage -Online -ErrorAction Stop | Where-Object DisplayName -eq $app | Remove-AppxProvisionedPackage -Online -ErrorAction Stop
      Write-Log "Pacote provisionado $app removido com sucesso." -Level "INFO" -ConsoleOutput
    }

    Write-Log "Bloatware adicional da Microsoft desinstalado com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função UninstallMsftBloat: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    throw  # Repropaga o erro
  }
  finally {
    Write-Log "Finalizando função UninstallMsftBloat." -Level "INFO" -ConsoleOutput
  }
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
  Write-Log "Iniciando função Set-RamThreshold para configurar o limite de RAM no registro." -ConsoleOutput

  try {
    $ramGB = [math]::Round((Get-WmiObject -Class Win32_ComputerSystem).TotalPhysicalMemory / 1GB)
    Write-Log "Quantidade de RAM detectada: $ramGB GB" -ConsoleOutput

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
        $errorMessage = "Memória RAM ($ramGB GB) não suportada para esta configuração."
        Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
        Write-Colored "Memória RAM não suportada para esta configuração." -Color "Red"
        return
      }
    }
    Write-Log "Valor calculado para SvcHostSplitThresholdInKB: $value KB" -ConsoleOutput

    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control"
    $regName = "SvcHostSplitThresholdInKB"
    Write-Log "Configurando $regName para $value em $regPath..." -ConsoleOutput
    Set-ItemProperty -Path $regPath -Name $regName -Value $value -Type DWord -ErrorAction Stop
    Write-Log "Registro $regName atualizado com sucesso para $value KB." -Level "INFO" -ConsoleOutput
    Write-Colored "Registro atualizado com o valor correto: $value KB" -Color "Green"
  }
  catch {
    $errorMessage = "Erro ao atualizar registro: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    Write-Colored $errorMessage -Color "Red"
    throw  # Repropaga o erro
  }
  finally {
    Write-Log "Finalizando função Set-RamThreshold." -Level "INFO" -ConsoleOutput
  }
}

function Set-MemoriaVirtual-Registry {
  Write-Log "Iniciando função Set-MemoriaVirtual-Registry para configurar a memória virtual." -ConsoleOutput

  try {
    Clear-Host
    $banner = @(
      "",
      "",
      "╔══════════════════════════════════════════╗",
      "╠═══════ Configurar Memória Virtual ═══════╣",
      "╚══════════════════════════════════════════╝",
      "",
      "≫ Este menu permite configurar a memória virtual do sistema.",
      "≫ A memória virtual será ajustada com base na RAM total detectada.",
      "≫ Tamanho inicial: 9081 MB (fixo).",
      "≫ Tamanho máximo: 1,5x a RAM total.",
      "≫ O sistema desativará a gestão automática da memória virtual.",
      ""
    )

    $colors = @(
      "Branco", "Branco", 
      "Amarelo", "Amarelo", "Amarelo", 
      "Branco", 
      "AmareloClaro", "AmareloClaro", "AmareloClaro", "AmareloClaro", "AmareloClaro", 
      "Branco"
    )

    for ($i = 0; $i -lt $banner.Length; $i++) {
      $color = if ($i -lt $colors.Length) { $colors[$i] } else { "Branco" }
      Write-Colored $banner[$i] $color
    }

    Write-Log "Exibindo interface de configuração da memória virtual." -ConsoleOutput
    Write-Colored "" "Branco"
    Write-Colored -Text "Informe a letra do drive (ex: C) para configurar a memória virtual:" -Color "Cyan"
    $Drive = Read-Host
    $DrivePath = "${Drive}:"
    Write-Log "Usuário informou o drive: $DrivePath" -ConsoleOutput

    # Validação do drive
    if (-not (Test-Path $DrivePath)) {
      $errorMessage = "Drive $DrivePath não encontrado."
      Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
      Write-Colored -Text $errorMessage -Color "Red"
      return
    }
    Write-Log "Drive $DrivePath validado com sucesso." -Level "INFO" -ConsoleOutput

    # Cálculo da memória RAM total em MB
    $TotalRAM = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1MB)
    $InitialSize = 9081  # Valor fixo inicial
    $MaxSize = [math]::Round($TotalRAM * 1.5)  # Máximo como 1,5x a RAM
    $RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
    Write-Log "RAM total detectada: $TotalRAM MB. Configurando memória virtual com inicial: $InitialSize MB, máximo: $MaxSize MB." -ConsoleOutput

    Write-Log "Configurando PagingFiles em $RegPath..." -ConsoleOutput
    Set-ItemProperty -Path $RegPath -Name "PagingFiles" -Value "$DrivePath\pagefile.sys $InitialSize $MaxSize" -ErrorAction Stop
    Write-Log "PagingFiles configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Configurando AutomaticManagedPagefile para 0 em $RegPath..." -ConsoleOutput
    Set-ItemProperty -Path $RegPath -Name "AutomaticManagedPagefile" -Value 0 -ErrorAction Stop
    Write-Log "AutomaticManagedPagefile configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Memória virtual configurada com sucesso para $DrivePath com inicial $InitialSize MB e máximo $MaxSize MB." -Level "INFO" -ConsoleOutput
    Write-Colored -Text "Memória virtual configurada para $DrivePath com inicial $InitialSize MB e máximo $MaxSize MB." -Color "Green"
    Write-Colored -Text "Reinicie o computador para aplicar as mudanças." -Color "Green"
  }
  catch {
    $errorMessage = "Erro ao configurar memória virtual: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    Write-Colored -Text $errorMessage -Color "Red"
    throw  # Repropaga o erro
  }
  finally {
    Write-Log "Finalizando função Set-MemoriaVirtual-Registry." -Level "INFO" -ConsoleOutput
  }
}

## Download and extract ISLC
function DownloadAndExtractISLC {
  Write-Log "Iniciando função DownloadAndExtractISLC para baixar e extrair o ISLC." -ConsoleOutput

  try {
    # Definir o link de download e o caminho do arquivo
    $downloadUrl = "https://raw.githubusercontent.com/wesscd/WindowsGaming/main/ISLC%20v1.0.3.4.exe"
    $downloadPath = "C:\ISLC_v1.0.3.4.exe"
    $extractPath = "C:\"
    $newFolderName = "ISLC"

    Write-Log "Configurações definidas: URL=$downloadUrl, Caminho Download=$downloadPath, Caminho Extração=$extractPath, Nome Pasta=$newFolderName" -ConsoleOutput

    # Baixar o arquivo executável
    Write-Colored "Iniciando o download do arquivo..." "Verde"
    Write-Log "Iniciando o download do arquivo de $downloadUrl para $downloadPath..." -ConsoleOutput
    Invoke-WebRequest -Uri $downloadUrl -OutFile $downloadPath -ErrorAction Stop
    Write-Log "Arquivo baixado com sucesso para $downloadPath." -Level "INFO" -ConsoleOutput
    Write-Colored "Arquivo baixado com sucesso!" "Verde"

    # Verificar se a pasta de extração existe, caso contrário, criar
    if (-Not (Test-Path -Path $extractPath)) {
      Write-Log "Pasta de extração $extractPath não existe. Criando..." -ConsoleOutput
      Write-Colored "Criando a pasta de extração..." "Verde"
      New-Item -ItemType Directory -Path $extractPath -ErrorAction Stop
      Write-Log "Pasta de extração $extractPath criada com sucesso." -Level "INFO" -ConsoleOutput
    }
    else {
      Write-Log "Pasta de extração $extractPath já existe." -ConsoleOutput
    }

    # Caminho do 7z.exe
    $sevenZipPath = "C:\Program Files\7-Zip\7z.exe"  # Altere conforme o local do seu 7z.exe
    Write-Log "Caminho do 7z.exe definido como: $sevenZipPath" -ConsoleOutput

    # Verificar se o 7z está instalado
    if (Test-Path -Path $sevenZipPath) {
      Write-Log "7-Zip encontrado em $sevenZipPath. Extraindo o conteúdo..." -ConsoleOutput
      Write-Colored "Extraindo o conteúdo do arquivo usando 7-Zip..." "Verde"

      # Executar o 7-Zip e capturar saída e erro separadamente
      $process = Start-Process -FilePath $sevenZipPath -ArgumentList "x", "$downloadPath", "-o$extractPath", "-y" -NoNewWindow -Wait -PassThru
      $exitCode = $process.ExitCode

      if ($exitCode -ne 0) {
        Write-Log "Erro ao extrair o arquivo com 7-Zip. Código de saída: $exitCode" -Level "ERROR" -ConsoleOutput
        throw "Erro ao extrair o arquivo com 7-Zip. Código de saída: $exitCode"
      }

      Write-Log "Arquivo extraído com sucesso para $extractPath." -Level "INFO" -ConsoleOutput
      Write-Colored "Arquivo extraído com sucesso para $extractPath" "Verde"

      # Renomear a pasta extraída para ISLC
      $extractedFolderPath = Join-Path -Path $extractPath -ChildPath "ISLC v1.0.3.4"
      if (Test-Path -Path $extractedFolderPath) {
        Write-Log "Renomeando a pasta extraída de $extractedFolderPath para $newFolderName..." -ConsoleOutput
        Rename-Item -Path $extractedFolderPath -NewName $newFolderName -ErrorAction Stop
        Write-Log "Pasta renomeada com sucesso para $newFolderName." -Level "INFO" -ConsoleOutput
        Write-Colored "Pasta renomeada para '$newFolderName'." "Verde"
      }
      else {
        Write-Log "Pasta extraída $extractedFolderPath não encontrada. Verificando subpastas..." -Level "WARNING" -ConsoleOutput

        # Tentar encontrar a pasta extraída manualmente
        $foundFolder = Get-ChildItem -Path $extractPath -Directory | Where-Object { $_.Name -like "ISLC*" } | Select-Object -First 1
        if ($foundFolder) {
          Write-Log "Pasta encontrada: $($foundFolder.FullName). Renomeando para $newFolderName..." -Level "INFO" -ConsoleOutput
          Rename-Item -Path $foundFolder.FullName -NewName $newFolderName -ErrorAction Stop
          Write-Colored "Pasta renomeada para '$newFolderName'." "Verde"
        }
        else {
          Write-Log "Nenhuma pasta extraída encontrada em $extractPath." -Level "ERROR" -ConsoleOutput
          Write-Colored "Nenhuma pasta extraída encontrada." "Vermelho"
          throw "Pasta extraída não encontrada após extração."
        }
      }
    }
    else {
      Write-Log "7-Zip não encontrado em $sevenZipPath." -Level "WARNING" -ConsoleOutput
      Write-Colored "7-Zip não encontrado no caminho especificado." "Amarelo"
      throw "7-Zip não instalado ou não encontrado."
    }

    Write-Log "Removendo o arquivo baixado $downloadPath..." -ConsoleOutput
    Remove-Item -Path $downloadPath -Force -ErrorAction Stop
    Write-Log "Arquivo $downloadPath excluído com sucesso." -Level "INFO" -ConsoleOutput
    Write-Colored "Excluindo $downloadPath" "Verde"

    # Caminho completo do executável do programa
    $origem = "C:\ISLC\Intelligent standby list cleaner ISLC.exe"
    # Nome do atalho que será criado
    $atalhoNome = "Intelligent standby list cleaner ISLC.lnk"
    # Caminho para a pasta de Inicialização do usuário
    $destino = [System.IO.Path]::Combine($env:APPDATA, "Microsoft\Windows\Start Menu\Programs\Startup", $atalhoNome)
    Write-Log "Configurando atalho: Origem=$origem, Destino=$destino" -ConsoleOutput

    # Criação do objeto Shell
    Write-Log "Criando objeto Shell para criar o atalho..." -ConsoleOutput
    $shell = New-Object -ComObject WScript.Shell -ErrorAction Stop
    # Criação do atalho
    Write-Log "Criando o atalho em $destino..." -ConsoleOutput
    $atalho = $shell.CreateShortcut($destino)
    $atalho.TargetPath = $origem
    $atalho.Save()
    Write-Log "Atalho criado com sucesso em $destino." -Level "INFO" -ConsoleOutput
    Write-Output "Atalho criado em: $destino"
  }
  catch {
    $errorMessage = "Erro na função DownloadAndExtractISLC: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    Write-Colored $errorMessage "Vermelho"
    throw  # Repropaga o erro
  }
  finally {
    Write-Log "Finalizando função DownloadAndExtractISLC." -Level "INFO" -ConsoleOutput
  }
}

# Update ISLC Config
function UpdateISLCConfig {
  Write-Log "Iniciando função UpdateISLCConfig para atualizar o arquivo de configuração do ISLC." -ConsoleOutput

  try {
    # Caminho para o arquivo de configuração (ajuste conforme necessário)
    $configFilePath = "C:\ISLC\Intelligent standby list cleaner ISLC.exe.Config"
    Write-Log "Caminho do arquivo de configuração definido como: $configFilePath" -ConsoleOutput

    # Verificar se o arquivo de configuração existe
    if (Test-Path -Path $configFilePath) {
      Write-Log "Arquivo de configuração encontrado em $configFilePath. Iniciando atualização..." -ConsoleOutput
      Write-Colored "Arquivo de configuração encontrado. Atualizando..." "Verde"

      # Carregar o conteúdo do arquivo XML
      Write-Log "Carregando o conteúdo do arquivo XML de $configFilePath..." -ConsoleOutput
      [xml]$configXml = Get-Content -Path $configFilePath -Raw -ErrorAction Stop
      Write-Log "Conteúdo XML carregado com sucesso." -Level "INFO" -ConsoleOutput

      # Obter a quantidade total de memória RAM do sistema (em MB)
      $totalMemory = (Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1MB
      $freeMemory = [math]::Round($totalMemory / 2)  # Calcular metade da memória
      Write-Log "Memória total detectada: $totalMemory MB. Memória livre configurada como: $freeMemory MB" -ConsoleOutput

      # Alterar as configurações conforme solicitado
      Write-Log "Atualizando configuração 'Free memory' para $freeMemory..." -ConsoleOutput
      $configXml.configuration.appSettings.add | Where-Object { $_.key -eq "Free memory" } | ForEach-Object { $_.value = "$freeMemory" }
      Write-Log "'Free memory' atualizado com sucesso." -Level "INFO" -ConsoleOutput

      Write-Log "Atualizando configuração 'Start minimized' para True..." -ConsoleOutput
      $configXml.configuration.appSettings.add | Where-Object { $_.key -eq "Start minimized" } | ForEach-Object { $_.value = "True" }
      Write-Log "'Start minimized' atualizado com sucesso." -Level "INFO" -ConsoleOutput

      Write-Log "Atualizando configuração 'Wanted timer' para 0.50..." -ConsoleOutput
      $configXml.configuration.appSettings.add | Where-Object { $_.key -eq "Wanted timer" } | ForEach-Object { $_.value = "0.50" }
      Write-Log "'Wanted timer' atualizado com sucesso." -Level "INFO" -ConsoleOutput

      Write-Log "Atualizando configuração 'Custom timer' para True..." -ConsoleOutput
      $configXml.configuration.appSettings.add | Where-Object { $_.key -eq "Custom timer" } | ForEach-Object { $_.value = "True" }
      Write-Log "'Custom timer' atualizado com sucesso." -Level "INFO" -ConsoleOutput

      Write-Log "Atualizando configuração 'TaskScheduler' para True..." -ConsoleOutput
      $configXml.configuration.appSettings.add | Where-Object { $_.key -eq "TaskScheduler" } | ForEach-Object { $_.value = "True" }
      Write-Log "'TaskScheduler' atualizado com sucesso." -Level "INFO" -ConsoleOutput

      # Salvar as alterações de volta no arquivo XML
      Write-Log "Salvando as alterações no arquivo $configFilePath..." -ConsoleOutput
      $configXml.Save($configFilePath)
      Write-Log "Arquivo de configuração atualizado com sucesso." -Level "INFO" -ConsoleOutput
      Write-Colored "Arquivo de configuração atualizado com sucesso!" "Verde"
    }
    else {
      Write-Log "Arquivo de configuração não encontrado em $configFilePath." -Level "WARNING" -ConsoleOutput
      Write-Colored "Arquivo de configuração não encontrado em $configFilePath" "Amarelo"
    }
  }
  catch {
    $errorMessage = "Erro ao atualizar o arquivo de configuração: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    Write-Colored $errorMessage "Vermelho"
    throw  # Repropaga o erro
  }
  finally {
    Write-Log "Finalizando função UpdateISLCConfig." -Level "INFO" -ConsoleOutput
  }
}

function ApplyPCOptimizations {
  Write-Log "Iniciando função ApplyPCOptimizations para aplicar otimizações no PC." -ConsoleOutput

  try {
    Write-Output "Aplicando otimizações..."
    Write-Log "Aplicando otimizações..." -ConsoleOutput

    Write-Log "Configurando SystemResponsiveness para 0 em HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile..." -ConsoleOutput
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -Type DWord -Value 0 -ErrorAction Stop
    Write-Log "SystemResponsiveness configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Configurando NetworkThrottlingIndex para 10 em HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile..." -ConsoleOutput
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Type DWord -Value 10 -ErrorAction Stop
    Write-Log "NetworkThrottlingIndex configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Configurando AlwaysOn para 1 em HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile..." -ConsoleOutput
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "AlwaysOn" -Type DWord -Value 1 -ErrorAction Stop
    Write-Log "AlwaysOn configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Configurando LazyMode para 1 em HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile..." -ConsoleOutput
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "LazyMode" -Type DWord -Value 1 -ErrorAction Stop
    Write-Log "LazyMode configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Configurando LazyModeTimeout para 25000 em HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile..." -ConsoleOutput
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "LazyModeTimeout" -Type DWord -Value 25000 -ErrorAction Stop
    Write-Log "LazyModeTimeout configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Otimizações aplicadas com sucesso." -Level "INFO" -ConsoleOutput
    Write-Colored "Otimizações aplicadas com sucesso." -Color "Green"
  }
  catch {
    $errorMessage = "Erro ao aplicar otimizações: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    Write-Colored $errorMessage -Color "Red"
    throw  # Repropaga o erro
  }
  finally {
    Write-Log "Finalizando função ApplyPCOptimizations." -Level "INFO" -ConsoleOutput
  }
}

function MSIMode {
  Write-Log "Iniciando função MSIMode para habilitar o modo MSI em GPUs compatíveis." -ConsoleOutput

  try {
    $errpref = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"
    Write-Log "Alterando ErrorActionPreference para SilentlyContinue temporariamente." -ConsoleOutput

    # Usar Get-CimInstance para obter os IDs PNP das placas de vídeo
    $GPUIDS = Get-CimInstance -ClassName Win32_VideoController | Select-Object -ExpandProperty PNPDeviceID
    if ($null -eq $GPUIDS -or $GPUIDS.Count -eq 0) {
      Write-Log "Nenhuma placa de vídeo detectada. Pulando configuração do modo MSI." -Level "WARNING" -ConsoleOutput
      'No Video Controllers Found! Skipping...'
      return
    }

    Write-Log "IDs de GPUs detectados: $($GPUIDS -join ', ')" -ConsoleOutput

    foreach ($GPUID in $GPUIDS) {
      if ([string]::IsNullOrWhiteSpace($GPUID)) {
        Write-Log "ID de GPU inválido encontrado. Pulando..." -Level "WARNING" -ConsoleOutput
        continue
      }

      Write-Log "Verificando descrição do dispositivo para GPUID: $GPUID..." -ConsoleOutput

      # Obter a descrição do dispositivo a partir do registro
      $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\$GPUID"
      if (Test-Path $registryPath) {
        $CheckDeviceDes = Get-ItemProperty -Path $registryPath -ErrorAction Stop | Select-Object -ExpandProperty DeviceDesc
        Write-Log "Descrição do dispositivo obtida: $CheckDeviceDes" -ConsoleOutput
      }
      else {
        Write-Log "Caminho do registro $registryPath não encontrado para GPUID: $GPUID. Pulando..." -Level "WARNING" -ConsoleOutput
        continue
      }

      if ($CheckDeviceDes -like "*GTX*" -or $CheckDeviceDes -like "*RTX*" -or $CheckDeviceDes -like "*AMD*") {
        Write-Log "Placa compatível GTX/RTX/AMD encontrada! Habilitando modo MSI..." -ConsoleOutput
        'GTX/RTX/AMD Compatible Card Found! Enabling MSI Mode...'

        $msiRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\$GPUID\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties"
        if (-not (Test-Path $msiRegistryPath)) {
          Write-Log "Caminho $msiRegistryPath não existe. Criando..." -ConsoleOutput
          New-Item -Path $msiRegistryPath -Force -ErrorAction Stop | Out-Null
          Write-Log "Chave $msiRegistryPath criada com sucesso." -Level "INFO" -ConsoleOutput
        }

        Write-Log "Configurando MSISupported para 1 em $msiRegistryPath..." -ConsoleOutput
        Set-ItemProperty -Path $msiRegistryPath -Name "MSISupported" -Type DWord -Value 1 -ErrorAction Stop
        Write-Log "MSISupported configurado com sucesso." -Level "INFO" -ConsoleOutput

        Write-Log "Modo MSI habilitado com sucesso para a GPU compatível ($GPUID)." -Level "INFO" -ConsoleOutput
      }
      else {
        Write-Log "Placa $GPUID não é compatível (GTX/RTX/AMD). Pulando..." -Level "INFO" -ConsoleOutput
      }
    }
  }
  catch {
    $errorMessage = "Erro na função MSIMode: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    throw  # Repropaga o erro
  }
  finally {
    $ErrorActionPreference = $errpref
    Write-Log "Restaurando ErrorActionPreference para $errpref." -ConsoleOutput
    Write-Log "Finalizando função MSIMode." -Level "INFO" -ConsoleOutput
  }
}

function OptimizeGPUTweaks {
  [CmdletBinding()]
  Param ()

  Write-Log "Iniciando otimizações de GPU..." -Level "INFO" -ConsoleOutput

  # Detectar GPU
  $gpuName = (Get-CimInstance Win32_VideoController).Name
  Write-Log "GPU detectada: $gpuName" -Level "INFO" -ConsoleOutput
  $isNvidia = $gpuName -like "*NVIDIA*" -or $gpuName -like "*GTX*" -or $gpuName -like "*RTX*"
  $isAMD = $gpuName -like "*AMD*" -or $gpuName -like "*Radeon*" -or $gpuName -like "*RX*"

  if (-not $isNvidia -and -not $isAMD) {
    Write-Log "Nenhuma GPU NVIDIA ou AMD detectada. Pulando otimizações." -Level "WARNING" -ConsoleOutput
    return
  }

  # Tweaks comuns (NVIDIA e AMD)
  try {
    # Desativar telemetria genérica
    Stop-Service -Name "NvTelemetryContainer" -ErrorAction SilentlyContinue
    Set-Service -Name "NvTelemetryContainer" -StartupType Disabled -ErrorAction SilentlyContinue
    Write-Log "Telemetria genérica desativada (se aplicável)." -Level "INFO" -ConsoleOutput

    # Priorizar desempenho no plano de energia
    powercfg -setactive SCHEME_MIN  # Máximo desempenho
    Write-Log "Plano de energia ajustado para máximo desempenho." -Level "INFO" -ConsoleOutput
  }
  catch {
    Write-Log "Erro ao aplicar tweaks comuns: $_" -Level "ERROR" -ConsoleOutput
  }

  # Tweaks específicos para NVIDIA
  if ($isNvidia) {
    Write-Log "Aplicando otimizações para NVIDIA..." -Level "INFO" -ConsoleOutput
    Write-Log "Iniciando função NvidiaTweaks para aplicar otimizações em GPUs NVIDIA GTX/RTX." -Level "INFO" -ConsoleOutput

    try {
      # Verificar se o script está rodando como administrador
      $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
      if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Log "Este script requer privilégios administrativos para acessar o registro e arquivos do sistema. Por favor, execute como administrador." -Level "ERROR" -ConsoleOutput
        Write-Output "Erro: Privilégios administrativos necessários. Execute o script como administrador."
        return
      }
      Write-Log "Script em execução com privilégios administrativos confirmados." -Level "INFO" -ConsoleOutput

      # Salvar a preferência de erro original
      $errpref = $ErrorActionPreference
      $ErrorActionPreference = "SilentlyContinue"
      Write-Log "Alterando ErrorActionPreference para SilentlyContinue temporariamente." -ConsoleOutput

      # Identificar GPUs NVIDIA usando CIM/WMI
      Write-Log "Obtendo informações de GPUs via CIM/WMI..." -ConsoleOutput
      $gpuInfo = Get-CimInstance -ClassName Win32_VideoController -ErrorAction Stop | Where-Object { $_.CurrentBitsPerPixel -and $_.AdapterDACType }
      $nvidiaGPUs = $gpuInfo | Where-Object { $_.Name -match "nvidia|gtx|rtx" -and $_.Status -eq "OK" }

      if (-not $nvidiaGPUs) {
        Write-Output "No NVIDIA GPU detected via CIM/WMI! Checking registry as fallback..."
        Write-Log "Nenhuma GPU NVIDIA detectada via CIM/WMI. Verificando registro como fallback..." -Level "INFO" -ConsoleOutput
      }
      else {
        Write-Log "GPUs NVIDIA detectadas via CIM/WMI: $($nvidiaGPUs.Name -join ', ')" -Level "INFO" -ConsoleOutput
      }

      # Aplicar otimizações de energia se NVIDIA for detectada via CIM/WMI
      if ($nvidiaGPUs) {
        Write-Output "NVIDIA GTX/RTX Card Detected! Applying Nvidia Power Tweaks..."
        Write-Log "Placa NVIDIA GTX/RTX detectada! Aplicando otimizações de energia..." -ConsoleOutput

        $url_base = "https://raw.githubusercontent.com/wesscd/WindowsGaming/main/BaseProfile.nip"
        $url_nvidiaprofile = "https://raw.githubusercontent.com/wesscd/WindowsGaming/main/nvidiaProfileInspector.exe"
        $system32Path = "$Env:windir\system32"

        Write-Log "Baixando BaseProfile.nip de $url_base para $system32Path\BaseProfile.nip..." -ConsoleOutput
        Invoke-WebRequest -Uri $url_base -OutFile "$system32Path\BaseProfile.nip" -ErrorAction Stop
        Write-Log "BaseProfile.nip baixado com sucesso." -Level "INFO" -ConsoleOutput

        Write-Log "Baixando nvidiaProfileInspector.exe de $url_nvidiaprofile para $system32Path\nvidiaProfileInspector.exe..." -ConsoleOutput
        Invoke-WebRequest -Uri $url_nvidiaprofile -OutFile "$system32Path\nvidiaProfileInspector.exe" -ErrorAction Stop
        Write-Log "nvidiaProfileInspector.exe baixado com sucesso." -Level "INFO" -ConsoleOutput

        Write-Log "Mudando diretório para $system32Path para executar o nvidiaProfileInspector..." -ConsoleOutput
        Push-Location
        Set-Location $system32Path
        Write-Log "Executando nvidiaProfileInspector.exe com o perfil BaseProfile.nip..." -ConsoleOutput
        & "nvidiaProfileInspector.exe" /s -load "BaseProfile.nip" -ErrorAction Stop
        Write-Log "Perfil BaseProfile.nip aplicado com sucesso pelo nvidiaProfileInspector." -Level "INFO" -ConsoleOutput
        Pop-Location
        Write-Log "Diretório restaurado." -ConsoleOutput
      }

      # Buscar dinamicamente todas as subchaves de dispositivos de vídeo no registro
      $baseRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}"
      Write-Log "Verificando entradas de registro em $baseRegPath..." -ConsoleOutput
      $subKeys = $null
      try {
        # Tentar ajustar permissões para o administrador atual
        $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}", [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::ChangePermissions)
        if ($regKey) {
          $acl = $regKey.GetAccessControl()
          $rule = New-Object System.Security.AccessControl.RegistryAccessRule (
            [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
            "FullControl",
            "Allow"
          )
          $acl.SetAccessRule($rule)
          $regKey.SetAccessControl($acl)
          Write-Log "Permissões ajustadas para $baseRegPath." -Level "INFO" -ConsoleOutput
          $regKey.Close()
        }
        $subKeys = Get-ChildItem -Path $baseRegPath -ErrorAction Stop | Where-Object { $_.PSChildName -match '^\d{4}$' }
      }
      catch {
        Write-Log "Falha ao listar subchaves ou ajustar permissões em $baseRegPath $_" -Level "WARNING" -ConsoleOutput
        Write-Output "Aviso: Não foi possível acessar o registro de dispositivos de vídeo. Continuando com base em CIM/WMI..."
      }

      $foundNvidia = $false
      if ($subKeys) {
        foreach ($key in $subKeys) {
          $regPath = $key.PSPath
          $driverDesc = (Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue).DriverDesc

          if ($driverDesc -and ($driverDesc -match "nvidia|gtx|rtx" -or ($nvidiaGPUs -and $nvidiaGPUs.Name -contains $driverDesc))) {
            $subKeyName = $key.PSChildName
            Write-Output "NVIDIA GTX/RTX Card Registry Path $subKeyName Detected! Applying Nvidia Latency Tweaks..."
            Write-Log "Placa NVIDIA GTX/RTX detectada no caminho de registro $subKeyName (DriverDesc: $driverDesc)! Aplicando otimizações de latência..." -ConsoleOutput
            $foundNvidia = $true

            Write-Log "Aplicando ajustes de latência no caminho $regPath..." -ConsoleOutput
            $properties = @{
              "D3PCLatency"                        = 1
              "F1TransitionLatency"                = 1
              "LOWLATENCY"                         = 1
              "Node3DLowLatency"                   = 1
              "PciLatencyTimerControl"             = "0x00000020"
              "RMDeepL1EntryLatencyUsec"           = 1
              "RmGspcMaxFtuS"                      = 1
              "RmGspcMinFtuS"                      = 1
              "RmGspcPerioduS"                     = 1
              "RMLpwrEiIdleThresholdUs"            = 1
              "RMLpwrGrIdleThresholdUs"            = 1
              "RMLpwrGrRgIdleThresholdUs"          = 1
              "RMLpwrMsIdleThresholdUs"            = 1
              "VRDirectFlipDPCDelayUs"             = 1
              "VRDirectFlipTimingMarginUs"         = 1
              "VRDirectJITFlipMsHybridFlipDelayUs" = 1
              "vrrCursorMarginUs"                  = 1
              "vrrDeflickerMarginUs"               = 1
              "vrrDeflickerMaxUs"                  = 1
            }

            foreach ($prop in $properties.GetEnumerator()) {
              try {
                Set-ItemProperty -Path $regPath -Name $prop.Name -Type DWord -Value $prop.Value -ErrorAction Stop
                Write-Log "Propriedade $($prop.Name) configurada com sucesso em $regPath." -Level "DEBUG" -ConsoleOutput
              }
              catch {
                Write-Log "Falha ao configurar $($prop.Name) em $regPath $_" -Level "WARNING" -ConsoleOutput
              }
            }
            Write-Log "Otimizações de latência NVIDIA aplicadas com sucesso no caminho $subKeyName." -Level "INFO" -ConsoleOutput
          }
        }
      }

      # Se nenhuma GPU foi encontrada no registro, mas CIM/WMI detectou NVIDIA, tentar aplicar otimizações em uma chave padrão
      if (-not $foundNvidia -and $nvidiaGPUs) {
        Write-Log "Nenhum registro acessível encontrado, mas GPU NVIDIA detectada via CIM/WMI. Tentando chave padrão..." -Level "INFO" -ConsoleOutput
        $defaultRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000"
        if (Test-Path $defaultRegPath) {
          Write-Output "Tentando aplicar otimizações na chave padrão 0000 para GPU NVIDIA..."
          Write-Log "Aplicando ajustes de latência no caminho padrão $defaultRegPath..." -ConsoleOutput
          $properties = @{
            "D3PCLatency"                        = 1
            "F1TransitionLatency"                = 1
            "LOWLATENCY"                         = 1
            "Node3DLowLatency"                   = 1
            "PciLatencyTimerControl"             = "0x00000020"
            "RMDeepL1EntryLatencyUsec"           = 1
            "RmGspcMaxFtuS"                      = 1
            "RmGspcMinFtuS"                      = 1
            "RmGspcPerioduS"                     = 1
            "RMLpwrEiIdleThresholdUs"            = 1
            "RMLpwrGrIdleThresholdUs"            = 1
            "RMLpwrGrRgIdleThresholdUs"          = 1
            "RMLpwrMsIdleThresholdUs"            = 1
            "VRDirectFlipDPCDelayUs"             = 1
            "VRDirectFlipTimingMarginUs"         = 1
            "VRDirectJITFlipMsHybridFlipDelayUs" = 1
            "vrrCursorMarginUs"                  = 1
            "vrrDeflickerMarginUs"               = 1
            "vrrDeflickerMaxUs"                  = 1
          }

          foreach ($prop in $properties.GetEnumerator()) {
            try {
              Set-ItemProperty -Path $defaultRegPath -Name $prop.Name -Type DWord -Value $prop.Value -ErrorAction Stop
              Write-Log "Propriedade $($prop.Name) configurada com sucesso em $defaultRegPath." -Level "DEBUG" -ConsoleOutput
            }
            catch {
              Write-Log "Falha ao configurar $($prop.Name) em $defaultRegPath $_" -Level "WARNING" -ConsoleOutput
            }
          }
          Write-Log "Otimizações de latência NVIDIA aplicadas com sucesso no caminho padrão 0000." -Level "INFO" -ConsoleOutput
          $foundNvidia = $true
        }
      }

      if (-not $foundNvidia -and -not $nvidiaGPUs) {
        Write-Output "No NVIDIA GTX/RTX Card Registry entry Found or Accessible! Skipping..."
        Write-Log "Nenhuma entrada de registro NVIDIA GTX/RTX encontrada ou acessível! Pulando otimizações..." -Level "INFO" -ConsoleOutput
      }
    }
    catch {
      $errorMessage = "Erro na função NvidiaTweaks: $_"
      Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
      throw  # Repropaga o erro
    }
    finally {
      $ErrorActionPreference = $errpref
      Write-Log "Restaurando ErrorActionPreference para $errpref." -ConsoleOutput
      Write-Log "Finalizando função NvidiaTweaks." -Level "INFO" -ConsoleOutput
    }
  }

  # Tweaks específicos para AMD
  if ($isAMD) {
    Write-Log "Aplicando otimizações para AMD..." -Level "INFO" -ConsoleOutput
    Write-Log "Iniciando função AMDGPUTweaks para aplicar otimizações em GPUs AMD." -Level "INFO" -ConsoleOutput

    try {
      # Verificar se o script está rodando como administrador
      $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
      if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Log "Este script requer privilégios administrativos para acessar o registro. Por favor, execute como administrador." -Level "ERROR" -ConsoleOutput
        Write-Output "Erro: Privilégios administrativos necessários. Execute o script como administrador."
        return
      }
      Write-Log "Script em execução com privilégios administrativos confirmados." -Level "INFO" -ConsoleOutput

      # Salvar a preferência de erro original
      $errpref = $ErrorActionPreference
      $ErrorActionPreference = "SilentlyContinue"
      Write-Log "Alterando ErrorActionPreference para SilentlyContinue temporariamente." -ConsoleOutput

      # Identificar GPUs AMD usando CIM/WMI
      Write-Log "Obtendo informações de GPUs via CIM/WMI..." -ConsoleOutput
      $gpuInfo = Get-CimInstance -ClassName Win32_VideoController -ErrorAction Stop | Where-Object { $_.CurrentBitsPerPixel -and $_.AdapterDACType }
      $amdGPUs = $gpuInfo | Where-Object { $_.Name -match "amd|radeon|rx|vega" -and $_.Status -eq "OK" }

      if (-not $amdGPUs) {
        Write-Output "No AMD GPU detected via CIM/WMI! Checking registry as fallback..."
        Write-Log "Nenhuma GPU AMD detectada via CIM/WMI. Verificando registro como fallback..." -Level "INFO" -ConsoleOutput
      }
      else {
        Write-Log "GPUs AMD detectadas via CIM/WMI: $($amdGPUs.Name -join ', ')" -Level "INFO" -ConsoleOutput
      }

      # Buscar dinamicamente todas as subchaves de dispositivos de vídeo no registro
      $baseRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}"
      Write-Log "Verificando entradas de registro em $baseRegPath..." -ConsoleOutput
      $subKeys = $null
      try {
        # Tentar ajustar permissões para o administrador atual
        $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}", [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::ChangePermissions)
        if ($regKey) {
          $acl = $regKey.GetAccessControl()
          $rule = New-Object System.Security.AccessControl.RegistryAccessRule (
            [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
            "FullControl",
            "Allow"
          )
          $acl.SetAccessRule($rule)
          $regKey.SetAccessControl($acl)
          Write-Log "Permissões ajustadas para $baseRegPath." -Level "INFO" -ConsoleOutput
          $regKey.Close()
        }
        $subKeys = Get-ChildItem -Path $baseRegPath -ErrorAction Stop | Where-Object { $_.PSChildName -match '^\d{4}$' }
      }
      catch {
        Write-Log "Falha ao listar subchaves ou ajustar permissões em $baseRegPath $_" -Level "WARNING" -ConsoleOutput
        Write-Output "Aviso: Não foi possível acessar o registro de dispositivos de vídeo. Continuando com base em CIM/WMI..."
      }

      $foundAMD = $false
      if ($subKeys) {
        foreach ($key in $subKeys) {
          $regPath = $key.PSPath
          $driverDesc = (Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue).DriverDesc

          if ($driverDesc -and ($driverDesc -match "amd|radeon|rx|vega" -or ($amdGPUs -and $amdGPUs.Name -contains $driverDesc))) {
            $subKeyName = $key.PSChildName
            Write-Output "AMD GPU Registry Path $subKeyName Detected! Applying AMD Latency Tweaks..."
            Write-Log "GPU AMD detectada no caminho de registro $subKeyName (DriverDesc: $driverDesc)! Aplicando otimizações de latência..." -ConsoleOutput
            $foundAMD = $true

            Write-Log "Aplicando ajustes de latência no caminho $regPath..." -ConsoleOutput
            $properties = @{
              "LTRSnoopL1Latency"               = 1
              "LTRSnoopL0Latency"               = 1
              "LTRNoSnoopL1Latency"             = 1
              "LTRMaxNoSnoopLatency"            = 1
              "KMD_RpmComputeLatency"           = 1
              "DalUrgentLatencyNs"              = 1
              "memClockSwitchLatency"           = 1
              "PP_RTPMComputeF1Latency"         = 1
              "PP_DGBMMMaxTransitionLatencyUvd" = 1
              "PP_DGBPMMaxTransitionLatencyGfx" = 1
              "DalNBLatencyForUnderFlow"        = 1
              "DalDramClockChangeLatencyNs"     = 1
              "BGM_LTRSnoopL1Latency"           = 1
              "BGM_LTRSnoopL0Latency"           = 1
              "BGM_LTRNoSnoopL1Latency"         = 1
              "BGM_LTRNoSnoopL0Latency"         = 1
              "BGM_LTRMaxSnoopLatencyValue"     = 1
              "BGM_LTRMaxNoSnoopLatencyValue"   = 1
            }

            foreach ($prop in $properties.GetEnumerator()) {
              try {
                Set-ItemProperty -Path $regPath -Name $prop.Name -Type DWord -Value $prop.Value -ErrorAction Stop
                Write-Log "Propriedade $($prop.Name) configurada com sucesso em $regPath." -Level "DEBUG" -ConsoleOutput
              }
              catch {
                Write-Log "Falha ao configurar $($prop.Name) em $regPath $_" -Level "WARNING" -ConsoleOutput
              }
            }
            Write-Log "Otimizações de latência AMD aplicadas com sucesso no caminho $subKeyName." -Level "INFO" -ConsoleOutput
          }
        }
      }

      # Se nenhuma GPU foi encontrada no registro, mas CIM/WMI detectou AMD, tentar aplicar otimizações em uma chave padrão
      if (-not $foundAMD -and $amdGPUs) {
        Write-Log "Nenhum registro acessível encontrado, mas GPU AMD detectada via CIM/WMI. Tentando chave padrão..." -Level "INFO" -ConsoleOutput
        $defaultRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000"
        if (Test-Path $defaultRegPath) {
          Write-Output "Tentando aplicar otimizações na chave padrão 0000 para GPU AMD..."
          Write-Log "Aplicando ajustes de latência no caminho padrão $defaultRegPath..." -ConsoleOutput
          $properties = @{
            "LTRSnoopL1Latency"               = 1
            "LTRSnoopL0Latency"               = 1
            "LTRNoSnoopL1Latency"             = 1
            "LTRMaxNoSnoopLatency"            = 1
            "KMD_RpmComputeLatency"           = 1
            "DalUrgentLatencyNs"              = 1
            "memClockSwitchLatency"           = 1
            "PP_RTPMComputeF1Latency"         = 1
            "PP_DGBMMMaxTransitionLatencyUvd" = 1
            "PP_DGBPMMaxTransitionLatencyGfx" = 1
            "DalNBLatencyForUnderFlow"        = 1
            "DalDramClockChangeLatencyNs"     = 1
            "BGM_LTRSnoopL1Latency"           = 1
            "BGM_LTRSnoopL0Latency"           = 1
            "BGM_LTRNoSnoopL1Latency"         = 1
            "BGM_LTRNoSnoopL0Latency"         = 1
            "BGM_LTRMaxSnoopLatencyValue"     = 1
            "BGM_LTRMaxNoSnoopLatencyValue"   = 1
          }

          foreach ($prop in $properties.GetEnumerator()) {
            try {
              Set-ItemProperty -Path $defaultRegPath -Name $prop.Name -Type DWord -Value $prop.Value -ErrorAction Stop
              Write-Log "Propriedade $($prop.Name) configurada com sucesso em $defaultRegPath." -Level "DEBUG" -ConsoleOutput
            }
            catch {
              Write-Log "Falha ao configurar $($prop.Name) em $defaultRegPath $_" -Level "WARNING" -ConsoleOutput
            }
          }
          Write-Log "Otimizações de latência AMD aplicadas com sucesso no caminho padrão 0000." -Level "INFO" -ConsoleOutput
          $foundAMD = $true
        }
      }

      if (-not $foundAMD) {
        Write-Output "No AMD GPU Registry entry Found or Accessible! Skipping..."
        Write-Log "Nenhuma entrada de registro AMD GPU encontrada ou acessível! Pulando otimizações de latência..." -Level "INFO" -ConsoleOutput
      }
    }
    catch {
      $errorMessage = "Erro na função AMDGPUTweaks: $_"
      Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
      throw  # Repropaga o erro
    }
    finally {
      $ErrorActionPreference = $errpref
      Write-Log "Restaurando ErrorActionPreference para $errpref." -ConsoleOutput
      Write-Log "Finalizando função AMDGPUTweaks." -Level "INFO" -ConsoleOutput
    }
  }

  Write-Log "Otimização de GPU concluída." -Level "INFO" -ConsoleOutput
}

function OptimizeNetwork {
  [CmdletBinding()]
  Param (
    [switch]$DisableNagle = $true,
    [switch]$EnableRSS = $true,
    [switch]$DisableLSO = $true
  )

  Write-Log "Iniciando otimizações de rede..." -Level "INFO" -ConsoleOutput

  # Configurações globais de TCP/IP (sem TCPNoDelay aqui, movido para DisableNagle)
  $tcpParams = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
  Write-Log "Ajustando parâmetros TCP/IP globais..." -Level "INFO" -ConsoleOutput
  try {
    Set-ItemProperty -Path $tcpParams -Name "MaxUserPort" -Value 65534 -Type DWord -Force -ErrorAction Stop
    Set-ItemProperty -Path $tcpParams -Name "TcpTimedWaitDelay" -Value 30 -Type DWord -Force -ErrorAction Stop
    Set-ItemProperty -Path $tcpParams -Name "DefaultTTL" -Value 64 -Type DWord -Force -ErrorAction Stop
    Set-ItemProperty -Path $tcpParams -Name "TcpMaxDataRetransmissions" -Value 5 -Type DWord -Force -ErrorAction Stop
    Set-ItemProperty -Path $tcpParams -Name "EnableTCPA" -Value 1 -Type DWord -Force -ErrorAction Stop
  }
  catch {
    Write-Log "Erro ao ajustar parâmetros TCP/IP: $_" -Level "ERROR" -ConsoleOutput
  }

  # Configurações globais via Netsh
  Write-Log "Aplicando configurações globais via Netsh..." -Level "INFO" -ConsoleOutput
  try {
    netsh int tcp set global autotuninglevel=normal | Out-Null
    netsh int tcp set global congestionprovider=ctcp | Out-Null
    netsh int tcp set global rss=enabled | Out-Null
    netsh int tcp set global chimney=enabled | Out-Null
    netsh int tcp set global dca=enabled | Out-Null
    netsh int tcp set global ecncapability=disabled | Out-Null
  }
  catch {
    Write-Log "Erro ao executar comandos Netsh: $_" -Level "ERROR" -ConsoleOutput
  }

  # Desativar Nagle por interface
  if ($DisableNagle) {
    Write-Log "Desativando algoritmo de Nagle por interface..." -Level "INFO" -ConsoleOutput
    $interfaces = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" -ErrorAction SilentlyContinue
    foreach ($interface in $interfaces) {
      try {
        Set-ItemProperty -Path $interface.PSPath -Name "TcpAckFrequency" -Value 1 -Type DWord -Force -ErrorAction Stop
        Set-ItemProperty -Path $interface.PSPath -Name "TCPNoDelay" -Value 1 -Type DWord -Force -ErrorAction Stop
      }
      catch {
        Write-Log "Erro ao ajustar interface ${interface.PSChildName}: $_" -Level "WARNING" -ConsoleOutput
      }
    }
  }

  # Configurar RSS por adaptador
  if ($EnableRSS) {
    Write-Log "Configurando Receive Side Scaling (RSS) nos adaptadores..." -Level "INFO" -ConsoleOutput
    $adapters = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}" -ErrorAction SilentlyContinue
    foreach ($adapter in $adapters) {
      $desc = (Get-ItemProperty -Path $adapter.PSPath -ErrorAction SilentlyContinue).DriverDesc
      if ($desc -and $desc -notmatch "Virtual|WAN") {
        try {
          Set-ItemProperty -Path $adapter.PSPath -Name "*RSS" -Value 1 -Type DWord -Force -ErrorAction Stop
          Set-ItemProperty -Path $adapter.PSPath -Name "*NumRssQueues" -Value 4 -Type DWord -Force -ErrorAction Stop
          Set-ItemProperty -Path $adapter.PSPath -Name "*ReceiveBuffers" -Value 2048 -Type DWord -Force -ErrorAction Stop
          Set-ItemProperty -Path $adapter.PSPath -Name "*TransmitBuffers" -Value 2048 -Type DWord -Force -ErrorAction Stop
        }
        catch {
          Write-Log "Erro ao ajustar adaptador ${desc}: $_" -Level "WARNING" -ConsoleOutput
        }
      }
    }
  }

  # Desativar LSO
  if ($DisableLSO) {
    Write-Log "Desativando Large Send Offload (LSO)..." -Level "INFO" -ConsoleOutput
    try {
      Disable-NetAdapterLso -Name "*" -IPv4 -IPv6 -ErrorAction Stop
    }
    catch {
      Write-Log "Erro ao desativar LSO: $_" -Level "WARNING" -ConsoleOutput
    }
  }

  # Propriedades avançadas dos adaptadores (sem LSO v2, coberto por Disable-NetAdapterLso)
  Write-Log "Ajustando propriedades avançadas dos adaptadores..." -Level "INFO" -ConsoleOutput
  $properties = @("FlowControl", "Energy-Efficient Ethernet", "Green Ethernet", "Interrupt Moderation")
  foreach ($prop in $properties) {
    try {
      Set-NetAdapterAdvancedProperty -Name "*" -DisplayName $prop -DisplayValue "Disabled" -ErrorAction SilentlyContinue
    }
    catch {
      Write-Log "Erro ao ajustar propriedade ${prop}: $_" -Level "WARNING" -ConsoleOutput
    }
  }

  Write-Log "Otimização de rede concluída com sucesso." -Level "INFO" -ConsoleOutput
}


function Finished {
  Write-Log "Iniciando função Finished para finalizar o processo de otimização." -ConsoleOutput

  try {
    Write-Log "Iniciando configurações finais de OEM e personalização do sistema." -ConsoleOutput

    # Baixar a imagem do logo
    $url_logo = "https://raw.githubusercontent.com/wesscd/WindowsGaming/main/logo.bmp"
    $destino_logo = "C:\Windows\oemlogo.bmp"
    Write-Log "Baixando logo de $url_logo para $destino_logo..." -ConsoleOutput
    Invoke-WebRequest -Uri $url_logo -OutFile $destino_logo -ErrorAction Stop
    Write-Log "Logo baixado com sucesso." -Level "INFO" -ConsoleOutput

    # Configurar permissões para pacotes MSI
    Write-Log "Configurando permissões para pacotes MSI no registro..." -ConsoleOutput
    New-Item -Path "HKCR:\Msi.Package\shell\runas\command" -Force -ErrorAction Stop | Out-Null
    Set-ItemProperty -Path "HKCR:\Msi.Package\shell\runas" -Name "HasLUAShield" -Type String -Value "" -ErrorAction Stop | Out-Null
    Set-ItemProperty -Path "HKCR:\Msi.Package\shell\runas\command" -Name "(Default)" -Type ExpandString -Value '"%SystemRoot%\System32\msiexec.exe" /i "%1" %*' -ErrorAction Stop | Out-Null
    Write-Log "Permissões para pacotes MSI configuradas com sucesso." -Level "INFO" -ConsoleOutput

    # Habilitar histórico da área de transferência
    Write-Log "Habilitando histórico da área de transferência..." -ConsoleOutput
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowClipboardHistory" -Type DWord -Value 1 -ErrorAction Stop
    Write-Log "Histórico da área de transferência habilitado com sucesso." -Level "INFO" -ConsoleOutput

    # Configurar informações OEM no registro
    Write-Log "Configurando informações OEM no registro..." -ConsoleOutput
    cmd /c 'REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v "Manufacturer" /t REG_SZ /d "PC Otimizado por Cesar Marques (Barao)" /f 2>nul' >$null
    cmd /c 'REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v "Model" /t REG_SZ /d "Otimizacao, Hardware, Infra & Redes" /f 2>nul' >$null
    cmd /c 'REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v "SupportURL" /t REG_SZ /d "http://techremote.com.br" /f 2>nul' >$null
    cmd /c 'REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v "SupportHours" /t REG_SZ /d "Seg-Sex: 08h-18h" /f 2>nul' >$null
    cmd /c 'REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v "SupportPhone" /t REG_SZ /d "+55 16 99263-6487" /f 2>nul' >$null
    cmd /c 'REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v "Logo" /t REG_SZ /d "C:\Windows\oemlogo.bmp" /f 2>nul' >$null
    Write-Log "Informações OEM configuradas com sucesso." -Level "INFO" -ConsoleOutput

    # Pequena pausa para garantir que as alterações sejam processadas
    Start-Sleep -Seconds 5
    Write-Log "Pausa de 5 segundos concluída." -ConsoleOutput

    # Exibir mensagem final
    Clear-Host
    Write-Log "Limpando a tela para exibir mensagem de conclusão." -ConsoleOutput

    $banner = @(
      "",
      "",
      "╔═══════════════════════════════════════╗",
      "╠════════ Otimização Concluída! ════════╣",
      "╚═══════════════════════════════════════╝",
      "",
      "≫ Parabéns! O processo de otimização do seu sistema foi concluído com sucesso.",
      "≫ Seu computador agora está configurado para oferecer o melhor desempenho em jogos e aplicações exigentes.",
      "≫ Durante este processo, ajustamos serviços, perfis de energia, configurações de memória virtual e outros recursos para maximizar a performance.",
      "≫ Também adicionamos informações de suporte personalizadas (Cesar Marques - Barão) e um logo OEM para o sistema.",
      "≫ Para garantir que todas as alterações sejam aplicadas corretamente, é necessário reiniciar o computador.",
      "",
      "≫ Você pode reiniciar agora ou fazer isso manualmente mais tarde.",
      "≫ Agradecemos por usar nosso script de otimização! Não se esqueça de nos seguir em http://techremote.com.br para mais dicas e suporte.",
      "",
      "Pressione qualquer tecla para continuar..."
    )

    $colors = @(
      "Branco", "Branco", 
      "Amarelo", "Amarelo", "Amarelo", 
      "Branco", 
      "AmareloClaro", "AmareloClaro", "AmareloClaro", "AmareloClaro", "AmareloClaro", 
      "Branco", 
      "AmareloClaro", "AmareloClaro", 
      "Branco", 
      "Verde"
    )

    for ($i = 0; $i -lt $banner.Length; $i++) {
      $color = if ($i -lt $colors.Length) { $colors[$i] } else { "Branco" }
      Write-Colored $banner[$i] $color
    }

    [Console]::ReadKey($true)

    # Abrir a URL no navegador
    Write-Log "Abrindo URL de suporte http://techremote.com.br no navegador..." -ConsoleOutput
    Start-Process "http://techremote.com.br" -ErrorAction Stop
    Write-Log "URL aberta com sucesso." -Level "INFO" -ConsoleOutput

    do {
      Write-Colored "" "Branco"
      Write-Colored "Deseja reiniciar agora? (S/N):" "Cyan"
      Write-Log "Solicitando escolha do usuário para reiniciar (S/N)..." -ConsoleOutput
      $resposta = Read-Host
      $resposta = $resposta.Trim().ToUpper()
      Write-Log "Usuário respondeu: $resposta" -ConsoleOutput
    } while ($resposta -ne 'S' -and $resposta -ne 'N')

    if ($resposta -eq 'S') {
      Write-Colored "Reiniciando o computador..." "VermelhoClaro"
      Write-Log "Usuário escolheu reiniciar. Reiniciando o computador..." -ConsoleOutput
      Restart-Computer -Force -ErrorAction Stop
      Write-Log "Comando de reinicialização executado com sucesso." -Level "INFO" -ConsoleOutput
    }
    else {
      Write-Colored "Pressione qualquer tecla para sair..." "Verde"
      Write-Log "Usuário escolheu não reiniciar. Aguardando pressionamento de tecla para sair..." -ConsoleOutput
      [Console]::ReadKey($true) | Out-Null
      Write-Log "Tecla pressionada. Encerrando função." -Level "INFO" -ConsoleOutput
    }
  }
  catch {
    $errorMessage = "Erro na função Finished: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    Write-Colored $errorMessage -Color "VermelhoClaro"
    throw  # Repropaga o erro
  }
  finally {
    Write-Log "Finalizando função Finished." -Level "INFO" -ConsoleOutput
  }
}

# Executar introdução
Show-Intro

# Executar os tweaks com barra de progresso
$totalTweaks = $tweaks.Count
$currentStep = 0

# Exemplo de uso no loop principal
foreach ($tweak in $tweaks) {
  $currentStep++
  $tweakName = $tweak.Split()[0]
  Write-Log "Iniciando execução do tweak: $tweakName (Passo $currentStep de $totalTweaks)" -Level "INFO" -ConsoleOutput
  Show-ProgressBar -CurrentStep $currentStep -TotalSteps $totalTweaks -TaskName $tweakName

  if ($tweakFunctions.ContainsKey($tweakName)) {
    try {
      Invoke-Expression $tweak
      Write-Log "Tweak $tweakName concluído com sucesso." -Level "INFO" -ConsoleOutput
    }
    catch {
      Write-Log "Erro ao executar o tweak $tweakName $_" -Level "ERROR" -ConsoleOutput
      Write-Colored "`nErro ao executar $tweakName. Veja o log para detalhes." -Color "VermelhoClaro"
      continue
    }
  }
  else {
    Write-Log "Tweak não encontrado: $tweak" -Level "WARNING" -ConsoleOutput
    Write-Colored "`nTweak não encontrado: $tweak" -Color "VermelhoClaro"
  }

  Start-Sleep -Milliseconds 100
}
