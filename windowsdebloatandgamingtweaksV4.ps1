# windowsdebloatandgamingtweaks.ps1
# Script principal para otimização de sistemas Windows focados em jogos
# Versão: V0.7.2.6.3 (GROK / GPT)
# Autores Originais: ChrisTitusTech, DaddyMadu
# Modificado por: César Marques.
# Definir página de código para suportar caracteres especiais

$versao = "V0.7.2.6.3 (GROK / GPT)"

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
      Log-Action -Message "Hash do arquivo $FilePath não corresponde ao esperado. Download pode estar corrompido ou comprometido." -Level "ERROR" -ConsoleOutput
      Remove-Item -Path $FilePath -Force -ErrorAction SilentlyContinue
      throw "Falha na verificação de integridade."
    }
    Log-Action -Message "Verificação de integridade do arquivo $FilePath concluída com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    Log-Action -Message "Erro ao verificar o hash do arquivo $FilePath $_" -Level "ERROR" -ConsoleOutput
    throw
  }
}

function Write-Log {
  param (
    [string]$Message,
    [string]$Level = "INFO", # Pode ser "INFO", "WARNING", "ERROR"
    [switch]$ConsoleOutput = $false # Este parâmetro será ignorado aqui, mas mantido por compatibilidade
  )

  # Definir caminho do log único
  $logBasePath = "$env:TEMP"
  $logFileName = "techremote_otimizacao_log.txt"
  $logPath = Join-Path -Path $logBasePath -ChildPath $logFileName

  # Verificar se o diretório de logs existe
  if (-not (Test-Path $logBasePath)) {
    try {
      New-Item -Path $logBasePath -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }
    catch {
      Write-Error "Não foi possível criar ou acessar o diretório de logs $logBasePath. Erro: $_"
      return
    }
  }

  # Formatar a entrada do log com timestamp
  $logTimestamp = Get-Date -Format "dd-MM-yyyy HH:mm:ss"
  $logEntry = "[$logTimestamp] [$Level] $Message"

  # Tentar escrever no arquivo de log
  try {
    # Se o arquivo não existe, criar com cabeçalho
    if (-not (Test-Path $logPath)) {
      "Início do log em $logTimestamp" | Out-File -FilePath $logPath -Encoding UTF8 -ErrorAction Stop
    }

    # Adicionar a nova entrada ao final do arquivo
    Add-Content -Path $logPath -Value $logEntry -ErrorAction Stop

    # Verificar tamanho do log (opcional: truncar se exceder 10MB)
    $logSize = (Get-Item $logPath).Length / 1MB
    if ($logSize -gt 10) {
      Write-Warning "O arquivo de log excedeu 10MB. As entradas mais antigas serão truncadas."
      $content = Get-Content $logPath -Tail 1000 | Out-String  # Manter últimas 1000 linhas
      $content | Out-File $logPath -Encoding UTF8 -ErrorAction Stop
    }
  }
  catch {
    # Se falhar ao escrever no log, exibir mensagem de erro
    $errorMsg = "Falha ao escrever no log $logPath. Erro: $_"
    Write-Error $errorMsg

    # Tentar registrar o erro em um log de emergência (simplificado)
    $emergencyLog = Join-Path -Path $logBasePath -ChildPath "emergency_log.txt"
    try {
      Add-Content -Path $emergencyLog -Value $errorMsg -ErrorAction Stop
    }
    catch {
      Write-Error "Não foi possível registrar no log de emergência. Erro: $_"
    }
  }
}

function Log-Action {
  param (
    [string]$Message,
    [string]$Level = "INFO", # Pode ser "INFO", "WARNING", "ERROR"
    [string]$Color = "VerdeClaro", # Cor padrão para saída no console
    [switch]$ConsoleOutput = $false
  )

  # Chamar Write-Log (sem MaxLogSizeMB e MaxLogFiles, pois foram removidos)
  # e não é necessário para o log de ações
  Write-Log -Message $Message -Level $Level -ConsoleOutput:$false

  # Se ConsoleOutput for verdadeiro, formatar e exibir no console com cor
  if ($ConsoleOutput) {
    # Determinar a cor com base no nível, se não especificado
    if (-not $PSBoundParameters.ContainsKey('Color')) {
      switch ($Level.ToUpper()) {
        "ERROR" { $Color = "Vermelho" }
        "WARNING" { $Color = "AmareloClaro" }
        default { $Color = "VerdeClaro" }
      }
    }

    # Formatar a mensagem como na Write-Log para consistência
    $logTimestamp = Get-Date -Format "dd-MM-yyyy HH:mm:ss"
    $formattedMessage = "[$logTimestamp] [$Level] $Message"

    # Exibir no console com a cor escolhida
    Write-Colored -Text $formattedMessage -Color $Color
  }
}

function Show-Menu {
  param (
    [string[]]$BannerLines, # Array de linhas para o banner (titulos, mensagens, opções)
    [string[]]$Options, # Array de opções válidas (ex.: "D", "H", "P")
    [string]$Prompt = "Digite sua escolha", # Mensagem de prompt para o usuário
    [string]$ColorScheme = "AmareloClaro"   # Cor padrão para o banner (pode ser ajustada)
  )

  # Limpar a tela
  Clear-Host

  # Emitir um bipe para alertar o usuário (frequência: 1000 Hz, duração: 500 ms)
  [Console]::Beep(1000, 500)

  # Exibir o banner com cores
  $colors = @("Branco", "Branco", $ColorScheme, $ColorScheme, $ColorScheme, "Branco", $ColorScheme, $ColorScheme, "Branco")
  for ($i = 0; $i -lt $BannerLines.Length; $i++) {
    $color = if ($i -lt $colors.Length) { $colors[$i] } else { "Branco" }
    Write-Colored -Text $BannerLines[$i] -Color $color
  }

  # Solicitar entrada do usuário em loop até uma opção válida
  do {
    Write-Colored "" "Branco"  # Linha em branco
    Write-Colored "${Prompt}:" "Cyan"  # Correção aplicada aqui
    $selection = Read-Host
    Log-Action -Message "Usuário selecionou: $selection" -Level "INFO" -ConsoleOutput
  } until ($Options -contains $selection.ToUpper())

  # Retornar a escolha (em maiúsculas para consistência)
  return $selection.ToUpper()
}


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
    "                                                                                  $versao",
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

function Get-GPUType {
  [CmdletBinding()]
  param (
    [switch]$IncludePNPIds = $false  # Opção para retornar IDs PNP, útil para MSIMode
  )

  Log-Action -Message "Iniciando detecção de GPU com Get-GPUType..." -Level "INFO" -ConsoleOutput

  try {
    # Obter informações das GPUs instaladas
    $gpuInfo = Get-CimInstance -ClassName Win32_VideoController -ErrorAction Stop | 
    Where-Object { $_.CurrentBitsPerPixel -and $_.AdapterDACType } |
    Select-Object Name, PNPDeviceID

    if (-not $gpuInfo) {
      Log-Action -Message "Nenhuma GPU detectada no sistema." -Level "WARNING" -ConsoleOutput
      return [PSCustomObject]@{
        Type   = "Nenhum"
        Name   = "Nenhuma GPU detectada"
        PNPIds = $null
      }
    }

    # Processar cada GPU encontrada (suporte a múltiplas GPUs)
    $gpuResults = foreach ($gpu in $gpuInfo) {
      $gpuName = $gpu.Name
      Log-Action -Message "GPU detectada: $gpuName" -Level "INFO" -ConsoleOutput

      # Determinar o tipo de GPU
      $isNvidia = $gpuName -like "*NVIDIA*" -or $gpuName -like "*GTX*" -or $gpuName -like "*RTX*"
      $isAMD = $gpuName -like "*AMD*" -or $gpuName -like "*Radeon*" -or $gpuName -like "*RX*"

      $gpuType = if ($isNvidia) { "NVIDIA" }
      elseif ($isAMD) { "AMD" }
      else { "Outro" }

      # Criar objeto de resultado
      $result = [PSCustomObject]@{
        Type   = $gpuType
        Name   = $gpuName
        PNPIds = if ($IncludePNPIds) { $gpu.PNPDeviceID } else { $null }
      }
      $result
    }

    # Retornar todos os resultados (array se houver múltiplas GPUs)
    return $gpuResults
  }
  catch {
    $errorMessage = "Erro ao detectar GPU: $_"
    Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
    Write-Colored $errorMessage -Color "VermelhoClaro"
    return [PSCustomObject]@{
      Type   = "Erro"
      Name   = "Erro ao detectar GPU"
      PNPIds = $null
    }
  }
}

# Função para definir valores no registro
function Set-RegistryValue {
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [string]$Path, # Caminho do registro (ex.: "HKLM:\SOFTWARE\...")
    [Parameter(Mandatory = $true)]
    [string]$Name, # Nome da propriedade
    [Parameter(Mandatory = $true)]
    $Value, # Valor a ser definido
    [string]$Type = "DWord", # Tipo do valor (DWord, String, etc.)
    [switch]$Force = $false     # Forçar a criação do caminho se não existir
  )

  Log-Action -Message "Iniciando configuração do registro em $Path\$Name com valor $Value." -Level "INFO" -ConsoleOutput

  try {
    # Verificar se o caminho existe; criar se necessário e $Force estiver ativado
    if (-not (Test-Path $Path)) {
      if ($Force) {
        New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
        Log-Action -Message "Caminho $Path criado com sucesso." -Level "INFO" -ConsoleOutput
      }
      else {
        throw "Caminho $Path não existe e -Force não foi especificado."
      }
    }

    # Definir o valor no registro
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force -ErrorAction Stop
    Log-Action -Message "Propriedade $Name configurada com sucesso em $Path com valor $Value." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro ao configurar o registro em $Path\$Name $_"
    Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
    Write-Colored $errorMessage -Color "VermelhoClaro"
    throw  # Repropaga o erro para a função chamadora
  }
}

# Verificar privilégios administrativos
function RequireAdmin {
  if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Log-Action -Message "Este script precisa ser executado como administrador." -Level "ERROR" -ConsoleOutput
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
  "ServicesSet"                 = { Invoke-WPFTweaksServices -Action Set }
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
  "DisableHibernation",
  "SetServices",
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
  Log-Action -Message "Iniciando download e execução do script em batch." -ConsoleOutput

  try {
    $remoteUrl = "https://raw.githubusercontent.com/wesscd/WindowsGaming/refs/heads/main/script-ccleaner.bat"
    $localPath = "$env:TEMP\techremote.bat"
    $expectedHash = "319048D53494BFAD71260B6415A2FFC90F0A83565A52856DFAE70810B40E593A"  # hash real

    Log-Action -Message "Baixando script em batch de $remoteUrl para $localPath..." -ConsoleOutput
    
    # Download do script
    Invoke-WebRequest -Uri $remoteUrl -OutFile $localPath -ErrorAction Stop

    # Verificar hash
    Verify-FileHash -FilePath $localPath -ExpectedHash $expectedHash

    if (Test-Path $localPath) {
      Log-Action -Message "Download concluído com sucesso. Executando o script..." -Level "INFO" -ConsoleOutput
      
      # Executar o script
      Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$localPath`"" -Wait -NoNewWindow -ErrorAction Stop
      Log-Action -Message "Script em batch executado com sucesso." -Level "INFO" -ConsoleOutput
      
    }
    else {
      $errorMessage = "O arquivo não foi baixado corretamente."
      Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
      throw $errorMessage  # Lança o erro
    }
  }
  catch {
    $errorMessage = "Erro ao baixar ou executar o script em batch: $_"
    Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
    throw  # Repropaga o erro
  }
  finally {
    if (Test-Path $localPath) {
      Log-Action -Message "Removendo arquivo temporário $localPath..." -ConsoleOutput
      try {
        Remove-Item $localPath -Force -ErrorAction Stop
        Log-Action -Message "Arquivo temporário removido com sucesso." -Level "INFO" -ConsoleOutput
        
      }
      catch {
        $errorMessage = "Erro ao remover arquivo temporário $localPath $_"
        Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
        
      }
    }
    else {
      Log-Action -Message "Nenhum arquivo temporário para remover." -Level "INFO" -ConsoleOutput
    }
    Log-Action -Message "Função Execute-BatchScript concluída." -Level "INFO" -ConsoleOutput
  }
}

function Check-Windows {
  Log-Action "Iniciando verificação da ativação do Windows." -Level "INFO" -ConsoleOutput

  try {
    Log-Action "Verificando status de ativação com slmgr.vbs..." -Level "INFO" -ConsoleOutput

    # Verifica o status de ativação do Windows
    $activationStatus = (Get-CimInstance -ClassName SoftwareLicensingProduct -Filter "Name like 'Windows%'" | Where-Object { $_.PartialProductKey }).LicenseStatus

    if ($activationStatus -eq 1) {
      Log-Action "Windows já está ativado." -Level "INFO" -ConsoleOutput
    }
    else {
      Log-Action "Windows não está ativado. Solicitando ação do usuário." -Level "WARNING" -ConsoleOutput
          
      # Definir o banner e opções para o menu
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

      # Opções válidas
      $options = @("C", "K", "P")

      # Chamar o menu e obter a escolha
      $selection = Show-Menu -BannerLines $banner -Options $options -Prompt "Digite sua escolha (C/K/P)" -ColorScheme "AmareloClaro"

      # Processar a escolha
      switch ($selection) {
        "C" {
          Log-Action "Opção escolhida: Inserir nova chave de produto." -ConsoleOutput
          $productKey = Read-Host "Digite a chave de produto (ex.: XXXXX-XXXXX-XXXXX-XXXXX-XXXXX)"
          Log-Action "Chave de produto inserida: $productKey" -ConsoleOutput

          try {
            Log-Action "Aplicando chave de produto..." -ConsoleOutput
            cscript //NoLogo "$env:SystemRoot\System32\slmgr.vbs" /ipk $productKey | Out-Null -ErrorAction Stop
            $activationResult = cscript //NoLogo "$env:SystemRoot\System32\slmgr.vbs" /ato | Out-String -ErrorAction Stop

            if ($activationResult -match "successfully" -or $activationResult -match "ativado com sucesso") {
              Log-Action "Windows ativado com sucesso usando a chave fornecida." -Level "INFO" -ConsoleOutput
            }
            else {
              $errorMessage = "Falha ao ativar o Windows com a chave fornecida. Resultado: $activationResult"
              Log-Action $errorMessage -Level "ERROR" -ConsoleOutput
              
            }
          }
          catch {
            $errorMessage = "Erro ao aplicar a chave de produto: $_"
            Log-Action $errorMessage -Level "ERROR" -ConsoleOutput
                      
          }
        }
        "K" {
          Log-Action "Opção escolhida: Ativar via KMS." -ConsoleOutput
                  
          try {
            Log-Action "Conectando ao servidor KMS para ativação..." -ConsoleOutput
                      
            irm https://get.activated.win | iex

            # Verifica novamente após tentativa de ativação
            $postActivation = cscript //NoLogo "$env:SystemRoot\System32\slmgr.vbs" /dli | Out-String -ErrorAction Stop

            if ($postActivation -match "Licensed" -or $postActivation -match "Ativado") {
              Log-Action "Windows ativado com sucesso via KMS." -Level "INFO" -ConsoleOutput
            }
            else {
              $errorMessage = "Falha ao ativar o Windows via KMS. Verifique sua conexão ou o servidor KMS."
              Log-Action $errorMessage -Level "ERROR" -ConsoleOutput
            }
          }
          catch {
            $errorMessage = "Erro ao executar a ativação KMS: $_"
            Log-Action $errorMessage -Level "ERROR" -ConsoleOutput
            Log-Action "Certifique-se de ter conexão com a internet." -Level "INFO" -ConsoleOutput
          }
        }
        "P" {
          Log-Action "Ativação ignorada. Windows permanece não ativado." -Level "WARNING" -ConsoleOutput
        }
      }
    }
  }
  catch {
    $errorMessage = "Erro ao verificar o status de ativação do Windows: $_"
    Log-Action $errorMessage -Level "ERROR" -ConsoleOutput
    
    Log-Action "Certifique-se de ter permissões administrativas." -Level "INFO" -ConsoleOutput
    
  }
  finally {
    Log-Action "Finalizando verificação de ativação do Windows." -Level "INFO" -ConsoleOutput
  }
}

function InstallChocolateyPackages {
  [CmdletBinding()]
  Param (
    # Lista de pacotes a serem instalados via Chocolatey
    [string[]]$Packages = @("vcredist2010", "7zip", "vcredist140", "vcredist2013", "directx")

  )

  Log-Action -Message "Iniciando instalação de pacotes via Chocolatey..." -Level "INFO" -ConsoleOutput

  if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
    Log-Action -Message "Chocolatey não encontrado. Instalando..." -Level "INFO" -ConsoleOutput
    try {
      Set-ExecutionPolicy Bypass -Scope Process -Force
      [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
      Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
      Log-Action -Message "Chocolatey instalado com sucesso." -Level "INFO" -ConsoleOutput
    }
    catch {
      Log-Action -Message "Erro ao instalar Chocolatey: $_" -Level "ERROR" -ConsoleOutput
      return
    }
  }
  else {
    Log-Action -Message "Chocolatey já instalado." -Level "INFO" -ConsoleOutput
  }

  foreach ($package in $Packages) {
    Log-Action -Message "Instalando/atualizando $package..." -Level "INFO" -ConsoleOutput
    try {
      choco install $package -y --force | Out-Null
      Log-Action -Message "$package instalado com sucesso." -Level "INFO" -ConsoleOutput
    }
    catch {
      Log-Action -Message "Erro ao instalar $package $_" -Level "ERROR" -ConsoleOutput
    }
  }

  Log-Action -Message "Instalação de pacotes concluída." -Level "INFO" -ConsoleOutput
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

  Log-Action -Message "Iniciando download de arquivos..." -Level "INFO" -ConsoleOutput

  # Criar pasta GPU
  $gpuPath = "$env:TEMP\GPU"
  if (-not (Test-Path $gpuPath)) { New-Item -Path $gpuPath -ItemType Directory -Force | Out-Null }

  # Detectar GPU com Get-GPUType
  Log-Action -Message "Detectando tipo de GPU..." -Level "INFO" -ConsoleOutput

  $gpu = Get-GPUType
  $isNvidia = $gpu.Type -eq "NVIDIA"
  $isAMD = $gpu.Type -eq "AMD"
  # O log já é feito dentro de Get-GPUType, então não precisa repetir

  # Definir downloads base
  $downloads = @{}
  foreach ($key in $BaseItems.Keys) {
    $downloads[$key] = $BaseItems[$key]
  }

  # Adicionar downloads específicos por GPU
  $downloads["OOSU10"] = $GpuItems["OOSU10"]  # Sempre incluído
  if ($isNvidia) {
    Log-Action -Message "Placa NVIDIA detectada. Adicionando driver NVIDIA..." -Level "INFO" -ConsoleOutput
    $downloads["NVIDIA_Driver"] = $GpuItems["NVIDIA_Driver"]
  }
  elseif ($isAMD) {
    Log-Action -Message "Placa AMD detectada. Adicionando driver AMD..." -Level "INFO" -ConsoleOutput
    $downloads["AMD_Driver"] = $GpuItems["AMD_Driver"]
  }

  foreach ($itemName in $downloads.Keys) {
    $item = $downloads[$itemName]

    # Baixar arquivo principal
    Log-Action -Message "Baixando $itemName de $($item.Url)..." -Level "INFO" -ConsoleOutput
    try {
      Invoke-WebRequest -Uri $item.Url -OutFile $item.Destination -ErrorAction Stop
      $hash = (Get-FileHash -Path $item.Destination -Algorithm SHA256).Hash
      if ($hash -ne $item.Hash) {
        Log-Action -Message "Hash de $itemName não corresponde. Esperado: $($item.Hash), Obtido: $hash" -Level "ERROR" -ConsoleOutput
        continue
      }
      Log-Action -Message "$itemName baixado e verificado com sucesso." -Level "INFO" -ConsoleOutput
    }
    catch {
      Log-Action -Message "Erro ao baixar $itemName $_" -Level "ERROR" -ConsoleOutput
      continue
    }

    # Baixar arquivo de configuração (se aplicável)
    if ($item.ConfigUrl) {
      Log-Action -Message "Baixando configuração de $itemName de $($item.ConfigUrl)..." -Level "INFO" -ConsoleOutput
      try {
        Invoke-WebRequest -Uri $item.ConfigUrl -OutFile $item.ConfigDestination -ErrorAction Stop
        $configHash = (Get-FileHash -Path $item.ConfigDestination -Algorithm SHA256).Hash
        if ($configHash -ne $item.ConfigHash) {
          Log-Action -Message "Hash da configuração de $itemName não corresponde. Esperado: $($item.ConfigHash), Obtido: $configHash" -Level "ERROR" -ConsoleOutput
          continue
        }
        Log-Action -Message "Configuração de $itemName baixada e verificada com sucesso." -Level "INFO" -ConsoleOutput
      }
      catch {
        Log-Action -Message "Erro ao baixar configuração de $itemName $_" -Level "ERROR" -ConsoleOutput
        continue
      }
    }

    # Executar (se aplicável)
    if ($item.Execute) {
      # Trecho original de execução do O&O ShutUp10
      Log-Action -Message "Executando O&O ShutUp10..." -ConsoleOutput
      try {
        & $item.Destination $item.ConfigDestination /quiet -ErrorAction Stop  # Substitui Start-Process conforme original
        Start-Sleep -Seconds 10  # Atraso de 10 segundos conforme original
        Log-Action -Message "Removendo arquivos temporários do O&O ShutUp10..." -ConsoleOutput
        Remove-Item -Path $item.ConfigDestination, $item.Destination -Force -ErrorAction Stop
        Log-Action -Message "O&O ShutUp10 executado e arquivos temporários removidos com sucesso." -Level "INFO" -ConsoleOutput
        
      }
      catch {
        Log-Action -Message "Erro ao executar ou limpar O&O ShutUp10: $_" -Level "ERROR" -ConsoleOutput
      }
    }
  }

  Log-Action -Message "Download de arquivos concluído." -Level "INFO" -ConsoleOutput
}

function InstallChocoUpdates {
  Log-Action -Message "Iniciando atualização de todos os pacotes do Chocolatey." -ConsoleOutput

  try {
    # Verificar se o Chocolatey está instalado
    Log-Action -Message "Verificando se o Chocolatey está instalado..." -ConsoleOutput
    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
      $errorMessage = "Chocolatey não está instalado. Instale-o primeiro usando InstallTitusProgs."
      Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
      throw $errorMessage
    }

    # Verificar permissões administrativas
    $currentUser = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
      $errorMessage = "Esta função requer privilégios administrativos. Execute como administrador."
      Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
      
      throw $errorMessage
    }

    # Limpar a tela e atualizar os pacotes
    Log-Action -Message "Limpando a tela e iniciando atualização de todos os pacotes Chocollatey..." -ConsoleOutput
    Clear-Host
    

    $updateResult = choco upgrade all -y -r --limitoutput --no-progress | Out-String -ErrorAction Stop

    if ($LASTEXITCODE -eq 0) {
      Log-Action -Message "Todos os pacotes do Chocolatey foram atualizados com sucesso." -Level "INFO" -ConsoleOutput
      
    }
    else {
      $errorMessage = "Falha ao atualizar os pacotes do Chocolatey. Saída: $updateResult"
      Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
            
      throw $errorMessage
    }
  }
  catch {
    $errorMessage = "Erro durante a atualização dos pacotes do Chocolatey: $_"
    Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
    
    throw  # Repropaga o erro
  }
  finally {
    Log-Action -Message "Finalizando atualização dos pacotes do Chocolatey." -Level "INFO" -ConsoleOutput
  }
}


function AskXBOX {
  Log-Action "Iniciando função AskXBOX para gerenciar recursos do Xbox." -Level "INFO" -ConsoleOutput

  try {
    # Obter versão do Windows
    $winVer = [System.Environment]::OSVersion.Version
    $isWin11 = $winVer.Major -eq 10 -and $winVer.Build -ge 22000
    Log-Action "Versão do Windows detectada: Major $($winVer.Major), Build $($winVer.Build). Windows 11: $isWin11" -Level "INFO" -ConsoleOutput

    # Definir o banner e opções para o menu
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

    # Opções válidas
    $options = @("D", "H", "P")

    # Chamar o menu e obter a escolha
    $selection = Show-Menu -BannerLines $banner -Options $options -Prompt "Digite sua escolha (D/H/P)" -ColorScheme "AmareloClaro"

    # Processar a escolha
    switch ($selection) {
      "D" {
        Log-Action "Opção escolhida: Desabilitar recursos do Xbox." -Level "INFO" -ConsoleOutput
              
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
            # Lógica para Windows 11, se necessário
          }

          foreach ($app in $xboxApps) {
            Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -ErrorAction SilentlyContinue
            Log-Action "Aplicativo $app desinstalado." -Level "INFO" -ConsoleOutput
          }

          Log-Action "Recursos do Xbox desativados com sucesso." -Level "INFO" -ConsoleOutput
        }
        catch {
          $errorMessage = "Erro ao desativar recursos do Xbox: $_"
          Log-Action $errorMessage -Level "ERROR" -ConsoleOutput
        }
        finally {
          $ErrorActionPreference = $errpref
        }
      }
      "H" {
        Log-Action "Opção escolhida: Habilitar recursos do Xbox." -Level "INFO" -ConsoleOutput
              
        # Lógica para habilitar (se aplicável)
      }
      "P" {
        Log-Action "Ativação ignorada. Recursos do Xbox permanecem inalterados." -Level "WARNING" -ConsoleOutput
              
      }
    }
  }
  catch {
    $errorMessage = "Erro na função AskXBOX: $_"
    Log-Action $errorMessage -Level "ERROR" -Color "Vermelho" -ConsoleOutput
    throw  # Repropaga o erro
  }
  finally {
    Log-Action "Finalizando função AskXBOX." -Level "INFO" -ConsoleOutput
  }
}

function DisableNewsFeed {
  Log-Action -Message "Iniciando função DisableNewsFeed para desativar o feed de notícias." -Level "INFO" -ConsoleOutput

  try {
    # Desativar o feed de notícias na barra de tarefas
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds"
    Set-RegistryValue -Path $regPath -Name "ShellFeedsTaskbarViewMode" -Value 2 -Type "DWord" -Force

    Log-Action -Message "Feed de notícias desativado com sucesso." -Level "INFO" -ConsoleOutput
    Write-Colored "Feed de notícias desativado com sucesso." -Color "VerdeClaro"
  }
  catch {
    $errorMessage = "Erro ao desativar o feed de notícias: $_"
    Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
    Write-Colored $errorMessage -Color "VermelhoClaro"
    throw
  }
  finally {
    Log-Action -Message "Finalizando função DisableNewsFeed." -Level "INFO" -ConsoleOutput
  }
}

function SetUACLow {
  Log-Action -Message "Iniciando função SetUACLow para configurar UAC em nível baixo." -Level "INFO" -ConsoleOutput

  try {
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    Set-RegistryValue -Path $regPath -Name "ConsentPromptBehaviorAdmin" -Value 0 -Type "DWord"
    Set-RegistryValue -Path $regPath -Name "ConsentPromptBehaviorUser" -Value 0 -Type "DWord"
    Set-RegistryValue -Path $regPath -Name "EnableLUA" -Value 1 -Type "DWord"
    Set-RegistryValue -Path $regPath -Name "PromptOnSecureDesktop" -Value 0 -Type "DWord"

    Log-Action -Message "UAC configurado para nível baixo com sucesso." -Level "INFO" -ConsoleOutput
    Write-Colored "UAC configurado para nível baixo com sucesso." -Color "VerdeClaro"
  }
  catch {
    $errorMessage = "Erro ao configurar UAC em nível baixo: $_"
    Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
    Write-Colored $errorMessage -Color "VermelhoClaro"
    throw
  }
  finally {
    Log-Action -Message "Finalizando função SetUACLow." -Level "INFO" -ConsoleOutput
  }
}

function DisableSMB1 {
  Log-Action -Message "Iniciando função DisableSMB1 para desativar o protocolo SMB1." -Level "INFO" -ConsoleOutput

  try {
    # Desativar SMB1 via registro
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    Set-RegistryValue -Path $regPath -Name "SMB1" -Value 0 -Type "DWord"

    # Desativar SMB1 via recursos do Windows
    Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -ErrorAction Stop

    Log-Action -Message "Protocolo SMB1 desativado com sucesso." -Level "INFO" -ConsoleOutput
    Write-Colored "Protocolo SMB1 desativado com sucesso." -Color "VerdeClaro"
  }
  catch {
    $errorMessage = "Erro ao desativar o protocolo SMB1: $_"
    Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
    Write-Colored $errorMessage -Color "VermelhoClaro"
    throw
  }
  finally {
    Log-Action -Message "Finalizando função DisableSMB1." -Level "INFO" -ConsoleOutput
  }
}

function SetCurrentNetworkPrivate {
  Log-Action -Message "Iniciando função SetCurrentNetworkPrivate para definir a rede atual como privada." -Level "INFO" -ConsoleOutput

  try {
    $networkProfiles = Get-NetConnectionProfile -ErrorAction Stop
    foreach ($profile in $networkProfiles) {
      if ($profile.NetworkCategory -ne "Private") {
        Set-NetConnectionProfile -InterfaceIndex $profile.InterfaceIndex -NetworkCategory Private -ErrorAction Stop
        Log-Action -Message "Rede '$($profile.Name)' definida como privada com sucesso." -Level "INFO" -ConsoleOutput
      }
      else {
        Log-Action -Message "Rede '$($profile.Name)' já está definida como privada." -Level "INFO" -ConsoleOutput
      }
    }

    Log-Action -Message "Redes atuais definidas como privadas com sucesso." -Level "INFO" -ConsoleOutput
    Write-Colored "Redes atuais definidas como privadas com sucesso." -Color "VerdeClaro"
  }
  catch {
    $errorMessage = "Erro ao definir a rede atual como privada: $_"
    Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
    Write-Colored $errorMessage -Color "VermelhoClaro"
    throw
  }
  finally {
    Log-Action -Message "Finalizando função SetCurrentNetworkPrivate." -Level "INFO" -ConsoleOutput
  }
}

function SetUnknownNetworksPrivate {
  Log-Action -Message "Iniciando função SetUnknownNetworksPrivate para definir redes desconhecidas como privadas." -Level "INFO" -ConsoleOutput

  try {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103"
    #$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24"
    Set-RegistryValue -Path $regPath -Name "Category" -Value 1 -Type "DWord" -Force

    Log-Action -Message "Redes desconhecidas definidas como privadas com sucesso." -Level "INFO" -ConsoleOutput
    Write-Colored "Redes desconhecidas definidas como privadas com sucesso." -Color "VerdeClaro"
  }
  catch {
    $errorMessage = "Erro ao definir redes desconhecidas como privadas: $_"
    Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
    Write-Colored $errorMessage -Color "VermelhoClaro"
    throw
  }
  finally {
    Log-Action -Message "Finalizando função SetUnknownNetworksPrivate." -Level "INFO" -ConsoleOutput
  }
}

function DisableNetDevicesAutoInst {
  Log-Action -Message "Iniciando função DisableNetDevicesAutoInst para desativar a instalação automática de dispositivos de rede." -Level "INFO" -ConsoleOutput

  try {
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A5A2C63F-3909-4C83-BADB-1E93F38BE6DD}"
    #$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private"
    Set-RegistryValue -Path $regPath -Name "Value" -Value "Deny" -Type "String" -Force

    Log-Action -Message "Instalação automática de dispositivos de rede desativada com sucesso." -Level "INFO" -ConsoleOutput
    Write-Colored "Instalação automática de dispositivos de rede desativada com sucesso." -Color "VerdeClaro"
  }
  catch {
    $errorMessage = "Erro ao desativar a instalação automática de dispositivos de rede: $_"
    Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
    Write-Colored $errorMessage -Color "VermelhoClaro"
    throw
  }
  finally {
    Log-Action -Message "Finalizando função DisableNetDevicesAutoInst." -Level "INFO" -ConsoleOutput
  }
}

function AskDefender {
  Log-Action "Iniciando função AskDefender para gerenciar o Windows Defender." -Level "INFO" -ConsoleOutput

  try {
    # Definir o banner e opções para o menu
    $banner = @(
      "",
      "",
      "╔════════════════════════════════════╗",
      "╠════ Gerenciar Windows Defender ════╣",
      "╚════════════════════════════════════╝",
      "",
      "≫ Este menu permite gerenciar o Windows Defender.",
      "≫ Desativar o Defender pode melhorar o desempenho, mas reduz a segurança.",
      "",
      "≫ Pressione 'D' para desativar o Windows Defender.",
      "≫ Pressione 'M' para manter o Windows Defender ativo.",
      "≫ Pressione 'P' para pular esta etapa.",
      ""
    )

    # Opções válidas
    $options = @("D", "M", "P")

    # Chamar o menu e obter a escolha
    $selection = Show-Menu -BannerLines $banner -Options $options -Prompt "Digite sua escolha (D/M/P)" -ColorScheme "AmareloClaro"

    # Processar a escolha
    switch ($selection) {
      "D" {
        Log-Action "Opção escolhida: Desativar o Windows Defender." -Level "INFO" -ConsoleOutput
              
        try {
          Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop
          Log-Action "Windows Defender desativado com sucesso." -Level "INFO" -ConsoleOutput
                  
        }
        catch {
          $errorMessage = "Erro ao desativar o Windows Defender: $_"
          Log-Action $errorMessage -Level "ERROR" -ConsoleOutput
                  
        }
      }
      "M" {
        Log-Action "Opção escolhida: Manter o Windows Defender ativo." -Level "INFO" -ConsoleOutput
              
        try {
          Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
          Log-Action "Windows Defender mantido ativo." -Level "INFO" -ConsoleOutput
                  
        }
        catch {
          $errorMessage = "Erro ao manter o Windows Defender ativo: $_"
          Log-Action $errorMessage -Level "ERROR" -ConsoleOutput
                  
        }
      }
      "P" {
        Log-Action "Ação ignorada. Configuração do Windows Defender permanece inalterada." -Level "WARNING" -ConsoleOutput
              
      }
    }
  }
  catch {
    $errorMessage = "Erro na função AskDefender: $_"
    Log-Action $errorMessage -Level "ERROR" -ConsoleOutput
  }
  finally {
    Log-Action "Finalizando função AskDefender." -Level "INFO" -ConsoleOutput
  }
}


function EnableF8BootMenu {
  Log-Action -Message "Iniciando função EnableF8BootMenu para habilitar as opções do menu de inicialização F8." -ConsoleOutput

  try {
    
    Log-Action -Message "Habilitando as opções do menu de inicialização F8..." -ConsoleOutput

    Log-Action -Message "Executando bcdedit para definir bootmenupolicy como Legacy..." -ConsoleOutput
    bcdedit /set bootmenupolicy Legacy -ErrorAction Stop | Out-Null
    Log-Action -Message "Menu de inicialização F8 habilitado com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função EnableF8BootMenu: $_"
    Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
    
    throw  # Repropaga o erro
  }
  finally {
    Log-Action -Message "Finalizando função EnableF8BootMenu." -Level "INFO" -ConsoleOutput
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

  Log-Action -Message "Iniciando configuração do Windows Update..." -Level "INFO" -ConsoleOutput

  try {
    # Caminhos do registro
    $wuPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    $auPath = "$wuPath\AU"

    # Configurações de adiamento de atualizações (SlowUpdatesTweaks)
    Log-Action -Message "Aplicando ajustes para adiar atualizações de recursos..." -Level "INFO" -ConsoleOutput
    Set-RegistryValue -Path $wuPath -Name "BranchReadinessLevel" -Value 16 -Type "DWord" -Force
    Set-RegistryValue -Path $wuPath -Name "DeferFeatureUpdates" -Value 1 -Type "DWord" -Force
    Set-RegistryValue -Path $wuPath -Name "DeferFeatureUpdatesPeriodInDays" -Value $DelayFeatureUpdatesDays -Type "DWord" -Force
    Set-RegistryValue -Path $wuPath -Name "ManagePreviewBuilds" -Value 1 -Type "DWord" -Force
    Set-RegistryValue -Path $wuPath -Name "ManagePreviewBuildsPolicyValue" -Value 2 -Type "DWord" -Force
    Set-RegistryValue -Path $wuPath -Name "PauseFeatureUpdatesStartTime" -Value "2025-04-03" -Type "String" -Force
    Set-RegistryValue -Path $wuPath -Name "PauseFeatureUpdatesEndTime" -Value "2030-04-03" -Type "String" -Force
    Set-RegistryValue -Path $auPath -Name "NoAutoUpdate" -Value 0 -Type "DWord" -Force

    # Desativar reinícios automáticos (DisableUpdateRestart)
    if ($DisableAutoRestart) {
      Log-Action -Message "Desativando reinícios automáticos após atualizações..." -Level "INFO" -ConsoleOutput
      Set-RegistryValue -Path $auPath -Name "NoAutoRebootWithLoggedOnUsers" -Value 1 -Type "DWord" -Force
    }

    # Habilitar MSRT (EnableUpdateMSRT)
    if ($EnableMSRT) {
      Log-Action -Message "Garantindo atualizações do Microsoft Malicious Software Removal Tool..." -Level "INFO" -ConsoleOutput
      # MSRT depende de atualizações de qualidade; NoAutoUpdate já está em 0
    }

    # Habilitar atualizações de drivers (EnableUpdateDriver)
    if ($EnableDrivers) {
      Log-Action -Message "Habilitando atualizações de drivers via Windows Update..." -Level "INFO" -ConsoleOutput
      Set-RegistryValue -Path $wuPath -Name "ExcludeWUDriversInQualityUpdate" -Value 0 -Type "DWord" -Force
    }

    Log-Action -Message "Configuração do Windows Update concluída com sucesso." -Level "INFO" -ConsoleOutput
    Write-Colored "Configuração do Windows Update concluída com sucesso." -Color "VerdeClaro"
  }
  catch {
    $errorMessage = "Erro na função ConfigureWindowsUpdate: $_"
    Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
    Write-Colored $errorMessage -Color "VermelhoClaro"
    throw
  }
}

function DisableMeltdownCompatFlag {
  Log-Action -Message "Iniciando função DisableMeltdownCompatFlag para desativar o flag de compatibilidade do Meltdown (CVE-2017-5754)." -ConsoleOutput

  try {
    
    Log-Action -Message "Desativando o flag de compatibilidade do Meltdown (CVE-2017-5754)..." -ConsoleOutput

    # Definir o caminho do registro
    $qualityCompatPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat"

    # Verificar se o caminho existe
    if (Test-Path $qualityCompatPath) {
      # Verificar se a propriedade existe
      $propertyName = "cadca5fe-87d3-4b96-b7fb-a231484277cc"
      if (Get-ItemProperty -Path $qualityCompatPath -Name $propertyName -ErrorAction SilentlyContinue) {
        Remove-ItemProperty -Path $qualityCompatPath -Name $propertyName -ErrorAction Stop
        Log-Action -Message "Flag de compatibilidade do Meltdown ($propertyName) removido com sucesso." -Level "INFO" -ConsoleOutput
      }
      else {
        Log-Action -Message "Propriedade $propertyName não encontrada no caminho $qualityCompatPath. Nenhuma ação necessária." -Level "INFO" -ConsoleOutput
      }
    }
    else {
      Log-Action -Message "Caminho $qualityCompatPath não encontrado. Nenhuma ação necessária." -Level "INFO" -ConsoleOutput
    }
  }
  catch {
    $errorMessage = "Erro na função DisableMeltdownCompatFlag: $_"
    Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
    
    throw  # Repropaga o erro
  }
  finally {
    Log-Action -Message "Finalizando função DisableMeltdownCompatFlag." -Level "INFO" -ConsoleOutput
  }
}

function DisableGaming {
  Log-Action -Message "Iniciando função DisableGaming para parar e desativar serviços desnecessários para jogos." -ConsoleOutput

  try {
    
    Log-Action -Message "Parando e desativando serviços desnecessários para jogos..." -ConsoleOutput

    $errpref = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"
    Log-Action -Message "Alterando ErrorActionPreference para SilentlyContinue temporariamente." -ConsoleOutput

    # wisvc
    Log-Action -Message "Parando o serviço wisvc..." -ConsoleOutput
    Stop-Service "wisvc" -WarningAction SilentlyContinue -ErrorAction Stop
    Log-Action -Message "Configurando wisvc para inicialização desativada..." -ConsoleOutput
    Set-Service "wisvc" -StartupType Disabled -ErrorAction Stop
    Log-Action -Message "Serviço wisvc processado com sucesso." -Level "INFO" -ConsoleOutput

    # MapsBroker
    Log-Action -Message "Parando o serviço MapsBroker..." -ConsoleOutput
    Stop-Service "MapsBroker" -WarningAction SilentlyContinue -ErrorAction Stop
    Log-Action -Message "Configurando MapsBroker para inicialização desativada..." -ConsoleOutput
    Set-Service "MapsBroker" -StartupType Disabled -ErrorAction Stop
    Log-Action -Message "Serviço MapsBroker processado com sucesso." -Level "INFO" -ConsoleOutput

    # UmRdpService
    Log-Action -Message "Parando o serviço UmRdpService..." -ConsoleOutput
    Stop-Service "UmRdpService" -WarningAction SilentlyContinue -ErrorAction Stop
    Log-Action -Message "Configurando UmRdpService para inicialização desativada..." -ConsoleOutput
    Set-Service "UmRdpService" -StartupType Disabled -ErrorAction Stop
    Log-Action -Message "Serviço UmRdpService processado com sucesso." -Level "INFO" -ConsoleOutput

    # TrkWks
    Log-Action -Message "Parando o serviço TrkWks..." -ConsoleOutput
    Stop-Service "TrkWks" -WarningAction SilentlyContinue -ErrorAction Stop
    Log-Action -Message "Configurando TrkWks para inicialização desativada..." -ConsoleOutput
    Set-Service "TrkWks" -StartupType Disabled -ErrorAction Stop
    Log-Action -Message "Serviço TrkWks processado com sucesso." -Level "INFO" -ConsoleOutput

    # TermService
    Log-Action -Message "Parando o serviço TermService..." -ConsoleOutput
    Stop-Service "TermService" -WarningAction SilentlyContinue -ErrorAction Stop
    Log-Action -Message "Configurando TermService para inicialização desativada..." -ConsoleOutput
    Set-Service "TermService" -StartupType Disabled -ErrorAction Stop
    Log-Action -Message "Serviço TermService processado com sucesso." -Level "INFO" -ConsoleOutput

    Log-Action -Message "Serviços desnecessários para jogos desativados com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função DisableGaming: $_"
    Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
    
    throw  # Repropaga o erro
  }
  finally {
    $ErrorActionPreference = $errpref
    Log-Action -Message "Restaurando ErrorActionPreference para $errpref." -ConsoleOutput
    Log-Action -Message "Finalizando função DisableGaming." -Level "INFO" -ConsoleOutput
  }
}

function DisableHomeGroups {
  Log-Action -Message "Iniciando função DisableHomeGroups para parar e desativar serviços de Grupos Domésticos." -ConsoleOutput

  try {
    
    Log-Action -Message "Parando e desativando serviços de Grupos Domésticos..." -ConsoleOutput

    $errpref = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"
    Log-Action -Message "Alterando ErrorActionPreference para SilentlyContinue temporariamente." -ConsoleOutput

    # Obter versão do sistema operacional
    $osVersion = [System.Environment]::OSVersion.Version
    $isWindows10OrLater = $osVersion.Build -ge 10240

    # Função interna para processar um serviço
    function Process-Service {
      param ($serviceName)
      try {
        Log-Action -Message "Verificando serviço $serviceName..." -ConsoleOutput
        if (Get-Service $serviceName -ErrorAction SilentlyContinue) {
          Log-Action -Message "Parando o serviço $serviceName..." -ConsoleOutput
          Stop-Service $serviceName -WarningAction SilentlyContinue -ErrorAction Stop
          Log-Action -Message "Configurando $serviceName para inicialização desativada..." -ConsoleOutput
          Set-Service $serviceName -StartupType Disabled -ErrorAction Stop
          Log-Action -Message "Serviço $serviceName processado com sucesso." -Level "INFO" -ConsoleOutput
        }
        else {
          Log-Action -Message "Serviço $serviceName não encontrado no sistema. Nenhuma ação necessária." -Level "INFO" -ConsoleOutput
        }
      }
      catch {
        Log-Action -Message "Erro ao processar serviço $serviceName $_" -Level "ERROR" -ConsoleOutput
      }
    }

    # Processar HomeGroupListener
    if (-not $isWindows10OrLater) {
      Process-Service "HomeGroupListener"
    }
    else {
      Log-Action -Message "Versão do Windows não suporta Grupos Domésticos. Pulando HomeGroupListener." -Level "INFO" -ConsoleOutput
    }

    # Processar HomeGroupProvider (pode existir mesmo em versões mais novas)
    Process-Service "HomeGroupProvider"

    Log-Action -Message "Serviços de Grupos Domésticos processados com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função DisableHomeGroups: $_"
    Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
    
    throw  # Repropaga o erro
  }
  finally {
    $ErrorActionPreference = $errpref
    Log-Action -Message "Restaurando ErrorActionPreference para $errpref." -ConsoleOutput
    Log-Action -Message "Finalizando função DisableHomeGroups." -Level "INFO" -ConsoleOutput
  }
}

function EnableSharedExperiences {
  Log-Action -Message "Iniciando função EnableSharedExperiences para habilitar Experiências Compartilhadas." -ConsoleOutput

  try {
    
    Log-Action -Message "Habilitando Experiências Compartilhadas..." -ConsoleOutput

    # Definir o caminho do registro
    $systemPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"

    # Verificar se o caminho existe, senão criar
    if (-not (Test-Path $systemPath)) {
      Log-Action -Message "Caminho $systemPath não existe. Criando..." -ConsoleOutput
      New-Item -Path $systemPath -Force -ErrorAction Stop | Out-Null
      Log-Action -Message "Caminho $systemPath criado com sucesso." -Level "INFO" -ConsoleOutput
    }

    # Remover a propriedade EnableCdp, se existir
    Log-Action -Message "Removendo a propriedade EnableCdp do registro..." -ConsoleOutput
    if (Get-ItemProperty -Path $systemPath -Name "EnableCdp" -ErrorAction SilentlyContinue) {
      Remove-ItemProperty -Path $systemPath -Name "EnableCdp" -ErrorAction Stop
      Log-Action -Message "EnableCdp removido com sucesso." -Level "INFO" -ConsoleOutput
    }
    else {
      Log-Action -Message "Propriedade EnableCdp não encontrada no caminho $systemPath. Nenhuma ação necessária." -Level "INFO" -ConsoleOutput
    }

    # Remover a propriedade EnableMmx, se existir
    Log-Action -Message "Removendo a propriedade EnableMmx do registro..." -ConsoleOutput
    if (Get-ItemProperty -Path $systemPath -Name "EnableMmx" -ErrorAction SilentlyContinue) {
      Remove-ItemProperty -Path $systemPath -Name "EnableMmx" -ErrorAction Stop
      Log-Action -Message "EnableMmx removido com sucesso." -Level "INFO" -ConsoleOutput
    }
    else {
      Log-Action -Message "Propriedade EnableMmx não encontrada no caminho $systemPath. Nenhuma ação necessária." -Level "INFO" -ConsoleOutput
    }

    Log-Action -Message "Experiências Compartilhadas habilitadas com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função EnableSharedExperiences: $_"
    Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
    
    throw  # Repropaga o erro
  }
  finally {
    Log-Action -Message "Finalizando função EnableSharedExperiences." -Level "INFO" -ConsoleOutput
  }
}

function EnableRemoteDesktop {
  Log-Action -Message "Iniciando função EnableRemoteDesktop para habilitar a Área de Trabalho Remota sem autenticação de nível de rede." -Level "INFO" -ConsoleOutput

  try {
    Log-Action -Message "Habilitando a Área de Trabalho Remota sem autenticação de nível de rede..." -ConsoleOutput
    
    $errpref = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"
    Log-Action -Message "Alterando ErrorActionPreference para SilentlyContinue temporariamente." -Level "INFO" -ConsoleOutput

    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0 -Type "DWord"
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 0 -Type "DWord"

    Log-Action -Message "Habilitando regras de firewall para RemoteDesktop..." -Level "INFO" -ConsoleOutput
    Enable-NetFirewallRule -Name "RemoteDesktop*" -ErrorAction Stop | Out-Null

    Log-Action -Message "Área de Trabalho Remota habilitada com sucesso sem autenticação de nível de rede." -Level "INFO" -ConsoleOutput
    Write-Colored "Área de Trabalho Remota habilitada com sucesso." -Color "VerdeClaro"
  }
  catch {
    $errorMessage = "Erro na função EnableRemoteDesktop: $_"
    Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
    Write-Colored $errorMessage -Color "VermelhoClaro"
    throw
  }
  finally {
    $ErrorActionPreference = $errpref
    Log-Action -Message "Restaurando ErrorActionPreference para $errpref." -Level "INFO" -ConsoleOutput
    Log-Action -Message "Finalizando função EnableRemoteDesktop." -Level "INFO" -ConsoleOutput
  }
}

#Disabling Windows Remote Assistance.
function DisableRemoteAssistance {
  Log-Action -Message "Iniciando função DisableRemoteAssistance para desativar a Assistência Remota do Windows." -Level "INFO" -ConsoleOutput

  try {
    Log-Action -Message "Desativando a Assistência Remota do Windows..." -ConsoleOutput
      
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance"
    Set-RegistryValue -Path $regPath -Name "fAllowFullControl" -Value 0 -Type "DWord"
    Set-RegistryValue -Path $regPath -Name "fAllowToGetHelp" -Value 0 -Type "DWord"

    Log-Action -Message "Assistência Remota do Windows desativada com sucesso." -Level "INFO" -ConsoleOutput
      
  }
  catch {
    $errorMessage = "Erro na função DisableRemoteAssistance: $_"
    Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
    throw
  }
  finally {
    Log-Action -Message "Finalizando função DisableRemoteAssistance." -Level "INFO" -ConsoleOutput
  }
}

function DisableAutoplay {
  Log-Action -Message "Iniciando função DisableAutoplay para desativar a Reprodução Automática." -Level "INFO" -ConsoleOutput

  try {
    Log-Action -Message "Desativando a Reprodução Automática..." -ConsoleOutput

    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Value 1 -Type "DWord"

    Log-Action -Message "Reprodução Automática desativada com sucesso." -Level "INFO" -ConsoleOutput
      
  }
  catch {
    $errorMessage = "Erro na função DisableAutoplay: $_"
    Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
      
    throw
  }
  finally {
    Log-Action -Message "Finalizando função DisableAutoplay." -Level "INFO" -ConsoleOutput
  }
}

function DisableAutorun {
  Log-Action -Message "Iniciando função DisableAutorun para desativar o Autorun." -Level "INFO" -ConsoleOutput

  try {
    Log-Action -Message "Desativando o Autorun..." -ConsoleOutput

    $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    Set-RegistryValue -Path $registryPath -Name "NoDriveTypeAutoRun" -Value 255 -Type "DWord" -Force

    Log-Action -Message "Autorun desativado com sucesso." -Level "INFO" -ConsoleOutput
      
  }
  catch {
    $errorMessage = "Erro na função DisableAutorun: $_"
    Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
  
    throw
  }
  finally {
    Log-Action -Message "Finalizando função DisableAutorun." -Level "INFO" -ConsoleOutput
  }
}

function DisableStorageSense {
  Log-Action -Message "Iniciando função DisableStorageSense para desativar o Storage Sense." -Level "INFO" -ConsoleOutput

  try {
    Log-Action -Message "Desativando o Storage Sense..." -ConsoleOutput

    $registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy"
    Set-RegistryValue -Path $registryPath -Name "01" -Value 0 -Type "DWord" -Force

    Log-Action -Message "Storage Sense desativado com sucesso." -Level "INFO" -ConsoleOutput
      
  }
  catch {
    $errorMessage = "Erro na função DisableStorageSense: $_"
    Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
      
    throw
  }
  finally {
    Log-Action -Message "Finalizando função DisableStorageSense." -Level "INFO" -ConsoleOutput
  }
}

function DisableDefragmentation {
  Log-Action -Message "Iniciando função DisableDefragmentation para desativar a desfragmentação." -Level "INFO" -ConsoleOutput

  try {
    Log-Action -Message "Desativando a desfragmentação..." -ConsoleOutput

    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Defrag"
    Set-RegistryValue -Path $registryPath -Name "EnableDefrag" -Value 0 -Type "DWord" -Force

    Log-Action -Message "Desfragmentação desativada com sucesso." -Level "INFO" -ConsoleOutput
      
  }
  catch {
    $errorMessage = "Erro na função DisableDefragmentation: $_"
    Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
      
    throw
  }
  finally {
    Log-Action -Message "Finalizando função DisableDefragmentation." -Level "INFO" -ConsoleOutput
  }
}

function EnableIndexing {
  Log-Action -Message "Iniciando função EnableIndexing para habilitar a indexação." -ConsoleOutput

  try {
    
    Log-Action -Message "Habilitando a indexação..." -ConsoleOutput

    Log-Action -Message "Configurando o serviço WSearch para inicialização automática..." -ConsoleOutput
    Set-Service "WSearch" -StartupType Automatic -ErrorAction Stop
    Log-Action -Message "WSearch configurado para inicialização automática com sucesso." -Level "INFO" -ConsoleOutput

    Log-Action -Message "Iniciando o serviço WSearch..." -ConsoleOutput
    Start-Service "WSearch" -ErrorAction Stop
    Log-Action -Message "Serviço WSearch iniciado com sucesso." -Level "INFO" -ConsoleOutput

    Log-Action -Message "Indexação habilitada com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função EnableIndexing: $_"
    Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
    throw  # Repropaga o erro
  }
  finally {
    Log-Action -Message "Finalizando função EnableIndexing." -Level "INFO" -ConsoleOutput
  }
}

function SetBIOSTimeUTC {
  Log-Action -Message "Iniciando função SetBIOSTimeUTC para definir o tempo do BIOS como UTC." -ConsoleOutput

  try {
    
    Log-Action -Message "Definindo o tempo do BIOS como UTC..." -ConsoleOutput

    Log-Action -Message "Configurando RealTimeIsUniversal para 1 em HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation..." -ConsoleOutput
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -Name "RealTimeIsUniversal" -Value 1 -Type "DWord" -Force
    
    Log-Action -Message "RealTimeIsUniversal configurado com sucesso." -Level "INFO" -ConsoleOutput

    Log-Action -Message "Tempo do BIOS definido como UTC com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função SetBIOSTimeUTC: $_"
    Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
    
    throw  # Repropaga o erro
  }
  finally {
    Log-Action -Message "Finalizando função SetBIOSTimeUTC." -Level "INFO" -ConsoleOutput
  }
}

function DisableHibernation {
  Log-Action -Message "Iniciando função DisableHibernation para desativar a hibernação." -ConsoleOutput

  try {
    
    Log-Action -Message "Desativando a hibernação..." -ConsoleOutput

    Log-Action -Message "Executando powercfg /hibernate off..." -ConsoleOutput
    powercfg /hibernate off -ErrorAction Stop | Out-Null
    Log-Action -Message "Hibernação desativada com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função DisableHibernation: $_"
    Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
    
    throw  # Repropaga o erro
  }
  finally {
    Log-Action -Message "Finalizando função DisableHibernation." -Level "INFO" -ConsoleOutput
  }
}

function EnableSleepButton {
  Log-Action -Message "Iniciando função EnableSleepButton para habilitar o botão de suspensão." -ConsoleOutput

  try {
    
    Log-Action -Message "Habilitando o botão de suspensão..." -ConsoleOutput

    Log-Action -Message "Configurando SleepButtonEnabled para 1 em HKLM:\SYSTEM\CurrentControlSet\Control\Power..." -ConsoleOutput
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "SleepButtonEnabled" -Value 1 -Type "DWord" -Force
    Log-Action -Message "SleepButtonEnabled configurado com sucesso." -Level "INFO" -ConsoleOutput

    Log-Action -Message "Botão de suspensão habilitado com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função EnableSleepButton: $_"
    Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput

    throw  # Repropaga o erro
  }
  finally {
    Log-Action -Message "Finalizando função EnableSleepButton." -Level "INFO" -ConsoleOutput
  }
}

function DisableSleepTimeout {
  Log-Action -Message "Iniciando função DisableSleepTimeout para desativar o tempo limite de suspensão." -ConsoleOutput

  try {
    
    Log-Action -Message "Desativando o tempo limite de suspensão..." -ConsoleOutput

    Log-Action -Message "Executando powercfg -change -standby-timeout-ac 0 para desativar timeout em AC..." -ConsoleOutput
    powercfg -change -standby-timeout-ac 0 -ErrorAction Stop
    Log-Action -Message "Tempo limite de suspensão em AC desativado com sucesso." -Level "INFO" -ConsoleOutput

    Log-Action -Message "Executando powercfg -change -standby-timeout-dc 0 para desativar timeout em DC..." -ConsoleOutput
    powercfg -change -standby-timeout-dc 0 -ErrorAction Stop
    Log-Action -Message "Tempo limite de suspensão em DC desativado com sucesso." -Level "INFO" -ConsoleOutput

    Log-Action -Message "Tempo limite de suspensão desativado com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função DisableSleepTimeout: $_"
    Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
    
    throw  # Repropaga o erro
  }
  finally {
    Log-Action -Message "Finalizando função DisableSleepTimeout." -Level "INFO" -ConsoleOutput
  }
}

function DisableFastStartup {
  Log-Action -Message "Iniciando função DisableFastStartup para desativar a inicialização rápida." -ConsoleOutput

  try {
    
    Log-Action -Message "Desativando a inicialização rápida..." -ConsoleOutput

    Log-Action -Message "Configurando HiberbootEnabled para 0 em HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power..." -ConsoleOutput
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Value 0 -Type "DWord" -Force
    
    Log-Action -Message "HiberbootEnabled configurado com sucesso." -Level "INFO" -ConsoleOutput

    Log-Action -Message "Inicialização rápida desativada com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função DisableFastStartup: $_"
    Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
    
    throw  # Repropaga o erro
  }
  finally {
    Log-Action -Message "Finalizando função DisableFastStartup." -Level "INFO" -ConsoleOutput
  }
}

function PowerThrottlingOff {
  Log-Action -Message "Iniciando função PowerThrottlingOff para desativar o Power Throttling." -ConsoleOutput

  try {
    
    Log-Action -Message "Desativando o Power Throttling..." -ConsoleOutput

    # Definir o caminho do registro
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling"

    # Verificar e criar a chave de registro, se necessário
    if (-not (Test-Path $registryPath)) {
      Log-Action -Message "Chave $registryPath não existe. Criando..." -ConsoleOutput
      New-Item -Path $registryPath -Force -ErrorAction Stop | Out-Null
      Log-Action -Message "Chave $registryPath criada com sucesso." -Level "INFO" -ConsoleOutput
    }
    else {
      Log-Action -Message "Chave $registryPath já existe. Prosseguindo com a configuração." -ConsoleOutput
    }

    # Configurar a propriedade PowerThrottlingOff
    Log-Action -Message "Configurando PowerThrottlingOff para 1 em $registryPath..." -ConsoleOutput
    Set-RegistryValue -Path $registryPath -Name "PowerThrottlingOff" -Value 1 -Type "DWord" -Force
    
    Log-Action -Message "PowerThrottlingOff configurado com sucesso." -Level "INFO" -ConsoleOutput

    Log-Action -Message "Power Throttling desativado com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função PowerThrottlingOff: $_"
    Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
    
    throw  # Repropaga o erro
  }
  finally {
    Log-Action -Message "Finalizando função PowerThrottlingOff." -Level "INFO" -ConsoleOutput
  }
}

function Win32PrioritySeparation {
  Log-Action -Message "Iniciando função Win32PrioritySeparation para otimizar a separação de prioridade Win32 para jogos." -ConsoleOutput

  try {
    
    Log-Action -Message "Otimizando a separação de prioridade Win32 para jogos..." -ConsoleOutput

    Log-Action -Message "Configurando Win32PrioritySeparation para 38 em HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl..." -ConsoleOutput
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Value 38 -Type "DWord" -Force
    
    Log-Action -Message "Win32PrioritySeparation configurado com sucesso." -Level "INFO" -ConsoleOutput

    Log-Action -Message "Separação de prioridade Win32 otimizada para jogos com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função Win32PrioritySeparation: $_"
    Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
    
    throw  # Repropaga o erro
  }
  finally {
    Log-Action -Message "Finalizando função Win32PrioritySeparation." -Level "INFO" -ConsoleOutput
  }
}

function DisableAERO {
  Log-Action -Message "Iniciando função DisableAERO para desativar os efeitos AERO." -ConsoleOutput

  try {
    
    Log-Action -Message "Desativando os efeitos AERO..." -ConsoleOutput

    Log-Action -Message "Configurando EnableAeroPeek para 0 em HKCU:\Software\Microsoft\Windows\DWM..." -ConsoleOutput
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Value 0 -Type "DWord" -Force
    
    Log-Action -Message "EnableAeroPeek configurado com sucesso." -Level "INFO" -ConsoleOutput

    Log-Action -Message "Efeitos AERO desativados com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função DisableAERO: $_"
    Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
    
    throw  # Repropaga o erro
  }
  finally {
    Log-Action -Message "Finalizando função DisableAERO." -Level "INFO" -ConsoleOutput
  }
}

function BSODdetails {
  Log-Action -Message "Iniciando função BSODdetails para habilitar informações detalhadas do BSOD." -ConsoleOutput

  try {
    
    Log-Action -Message "Habilitando informações detalhadas do BSOD..." -ConsoleOutput

    Log-Action -Message "Configurando DisplayParameters para 1 em HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl..." -ConsoleOutput
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "DisplayParameters" -Value 1 -Type "DWord" -Force
    
    Log-Action -Message "DisplayParameters configurado com sucesso." -Level "INFO" -ConsoleOutput

    Log-Action -Message "Informações detalhadas do BSOD habilitadas com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função BSODdetails: $_"
    Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
    
    throw  # Repropaga o erro
  }
  finally {
    Log-Action -Message "Finalizando função BSODdetails." -Level "INFO" -ConsoleOutput
  }
}

function DisableliveTiles {
  Log-Action -Message "Iniciando função DisableliveTiles para desativar os Live Tiles." -ConsoleOutput
  
  If (!(Test-Path "HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications")) {
    New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Force | Out-Null
  }
  Set-RegistryValue -Path "HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoTileApplicationNotification" -Value 1 -Type "DWord" -Force
  
}

function WallpaperQuality {
  Log-Action -Message "Iniciando função WallpaperQuality para definir a qualidade do papel de parede." -ConsoleOutput
  
  Set-RegistryValue -Path "HKCU:\Control Panel\Desktop" -Name "JPEGImportQuality" -Value 100 -Type "DWord" -Force
  
}

function DisableShistory {
  Log-Action -Message "Iniciando função DisableShistory para desativar o histórico do Shell." -ConsoleOutput
  
  Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "Shell Folders" -Value 0 -Type "DWord" -Force
  
}

function DisableShortcutWord {
  Write-Output "Removing 'Shortcut' word from new shortcuts..."
  Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "link" -Value ([byte[]](0, 0, 0, 0)) -Type "Binary" -Force
  
}

function DisableMouseKKS {
  Log-Action -Message "Iniciando função DisableMouseKKS para desativar as teclas do mouse." -ConsoleOutput
  
  Set-RegistryValue -Path "HKCU:\Control Panel\Accessibility\MouseKeys" -Name "Flags" -Value 0 -Type "DWord" -Force
  
}

function DisableTransparency {
  Log-Action -Message "Iniciando função DisableTransparency para desativar os efeitos de transparência." -ConsoleOutput
  
  Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Value 0 -Type "DWord" -Force
  
}

function TurnOffSafeSearch {
  Log-Action -Message "Iniciando função TurnOffSafeSearch para desativar a pesquisa segura." -ConsoleOutput
  
  Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SafeSearch" -Value 0 -Type "DWord" -Force
  
}

function DisableCloudSearch {
  Log-Action -Message "Iniciando função DisableCloudSearch para desativar a pesquisa na nuvem." -ConsoleOutput
  
  Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Value 0 -Type "DWord" -Force
  
}

function DisableDeviceHistory {
  Log-Action -Message "Iniciando função DisableDeviceHistory para desativar o histórico de dispositivos." -ConsoleOutput
  
  Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeviceAccess" -Name "DeviceHistory" -Value 0 -Type "DWord" -Force
  
}

function DisableSearchHistory {
  Log-Action -Message "Iniciando função DisableSearchHistory para desativar o histórico de pesquisa." -ConsoleOutput
  
  Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "HistoryEnabled" -Value 0 -Type "DWord" -Force
  
}

function RemoveMeet {
  Log-Action -Message "Iniciando função RemoveMeet para remover o Meet Now da barra de tarefas." -ConsoleOutput
  
  If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force | Out-Null
  }
  Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Value 1 -Type "DWord" -Force
  
}

function EnableActionCenter {
  Log-Action -Message "Iniciando função EnableActionCenter para habilitar o Action Center." -ConsoleOutput
  
  Remove-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -ErrorAction SilentlyContinue
}

function EnableLockScreen {
  Log-Action -Message "Iniciando função EnableLockScreen para habilitar a tela de bloqueio." -ConsoleOutput
  
  Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -ErrorAction SilentlyContinue
}

function EnableLockScreenRS1 {
  Log-Action -Message "Iniciando função EnableLockScreenRS1 para habilitar a tela de bloqueio (compatibilidade com RS1)." -ConsoleOutput
  
  Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" -Name "LockScreenEnabled" -Value 1 -Type "DWord" -Force
  
}

function DisableStickyKeys {
  Log-Action -Message "Iniciando função DisableStickyKeys para desativar as teclas de aderência." -ConsoleOutput
  
  Set-RegistryValue -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Value 506 -Type "DWord" -Force
}

function ShowTaskManagerDetails {
  Log-Action -Message "Iniciando função ShowTaskManagerDetails para exibir detalhes do Gerenciador de Tarefas." -ConsoleOutput
  
  # Define o caminho do registro
  $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager"

  # Verifica se a chave existe, senão cria
  if (!(Test-Path $regPath)) {
    Log-Action -Message "A chave do registro $regPath não existe. Criando..." -ConsoleOutput
    
    New-Item -Path $regPath -Force | Out-Null
  }

  # Define a propriedade "Preferences"
  Set-RegistryValue -Path $regPath -Name "Preferences" -Value ([byte[]](0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00)) -Type "Binary" -Force

  #Set-ItemProperty -Path $regPath -Name "Preferences" -Type Binary -Value ([byte[]](0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00))
  
  Log-Action -Message "Configuração do Gerenciador de Tarefas aplicada com sucesso." -Level "INFO" -ConsoleOutput
  
}

function ShowFileOperationsDetails {
  Log-Action -Message "Iniciando função ShowFileOperationsDetails para exibir detalhes de operações de arquivo no Explorer." -ConsoleOutput

  try {
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager"
      
    # Verificar se o caminho existe, caso contrário, criá-lo
    if (-not (Test-Path $regPath)) {
      Log-Action -Message "Caminho de registro $regPath não existe. Criando..." -ConsoleOutput
      New-Item -Path $regPath -Force -ErrorAction Stop | Out-Null
      Log-Action -Message "Caminho $regPath criado com sucesso." -Level "INFO" -ConsoleOutput
    }
    else {
      Log-Action -Message "Caminho $regPath já existe. Prosseguindo com a configuração..." -ConsoleOutput
    }

    # Configurar a propriedade EnthusiastMode para exibir detalhes
    Log-Action -Message "Configurando EnthusiastMode para 1 em $regPath..." -ConsoleOutput
    Set-RegistryValue -Path $regPath -Name "EnthusiastMode" -Value 1 -Type "DWord" -Force
    #Set-ItemProperty -Path $regPath -Name "EnthusiastMode" -Type DWord -Value 1 -ErrorAction Stop
    Log-Action -Message "EnthusiastMode configurado com sucesso para exibir detalhes de operações de arquivo." -Level "INFO" -ConsoleOutput
    
  }
  catch {
    $errorMessage = "Erro na função ShowFileOperationsDetails: $_"
    Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
        
    throw  # Repropaga o erro para ser tratado externamente, se necessário
  }
  finally {
    Log-Action -Message "Finalizando função ShowFileOperationsDetails." -Level "INFO" -ConsoleOutput
  }
}

function DisableFileDeleteConfirm {
  Log-Action -Message "Iniciando função DisableFileDeleteConfirm para desativar a confirmação de exclusão de arquivos." -ConsoleOutput
  
  Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ConfirmFileDelete" -Value 0 -Type "DWord" -Force
  #Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ConfirmFileDelete" -Type DWord -Value 0
}

function HideTaskbarSearch {
  Log-Action -Message "Iniciando função HideTaskbarSearch para ocultar a pesquisa na barra de tarefas." -ConsoleOutput
  
  Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 0 -Type "DWord" -Force
  #Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0
}

function HideTaskView {
  Log-Action -Message "Iniciando função HideTaskView para ocultar o botão de visualização de tarefas." -ConsoleOutput
  
  Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Value 0 -Type "DWord" -Force
  #Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0
}

function HideTaskbarPeopleIcon {
  Log-Action -Message "Iniciando função HideTaskbarPeopleIcon para ocultar o ícone de pessoas na barra de tarefas." -ConsoleOutput
  
  If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {
    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Force | Out-Null
  }
  Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Value 0 -Type "DWord" -Force
  #Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0
}

function DisableSearchAppInStore {
  Log-Action -Message "Iniciando função DisableSearchAppInStore para desativar a pesquisa de aplicativos na Microsoft Store." -ConsoleOutput
  
  If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Type DWord -Value 1
}

function DisableNewAppPrompt {
  Log-Action -Message "Iniciando função DisableNewAppPrompt para desativar o prompt de novos aplicativos instalados." -ConsoleOutput
  
  Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_NotifyNewApps" -Value 0 -Type "DWord" -Force
  #Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_NotifyNewApps" -Type DWord -Value 0
}

function SetVisualFXPerformance {
  Log-Action -Message "Iniciando função SetVisualFXPerformance para definir os efeitos visuais para desempenho." -ConsoleOutput
  
  Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Value 2 -Type "DWord" -Force
  #Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value 2
}

function EnableNumlock {
  Log-Action -Message "Iniciando função EnableNumlock para habilitar o Num Lock na inicialização." -ConsoleOutput
  
  Set-RegistryValue -Path "HKCU:\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Value 2 -Type "DWord" -Force
  #Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value 2
}

function EnableDarkMode {
  Log-Action -Message "Iniciando função EnableDarkMode para habilitar o modo escuro." -ConsoleOutput
  
  Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0 -Type "DWord" -Force
  #Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Type DWord -Value 0
}

function ShowKnownExtensions {
  Log-Action -Message "Iniciando função ShowKnownExtensions para mostrar extensões de arquivos conhecidas." -ConsoleOutput
  
  Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 1 -Type "DWord" -Force
  #Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0
}

function HideHiddenFiles {
  Log-Action -Message "Iniciando função HideHiddenFiles para ocultar arquivos ocultos." -ConsoleOutput
  
  Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Value 2 -Type "DWord" -Force
  #Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 2
}

function HideSyncNotifications {
  Log-Action -Message "Iniciando função HideSyncNotifications para ocultar notificações de sincronização." -ConsoleOutput
  
  Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Value 0 -Type "DWord" -Force
  #Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Type DWord -Value 0
}

function HideRecentShortcuts {
  Log-Output "Iniciando função HideRecentShortcuts para ocultar atalhos recentes." -ConsoleOutput
  
  Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackProgs" -Value 0 -Type "DWord" -Force
  #Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackDocs" -Type DWord -Value 0
}

function SetExplorerThisPC {
  Log-Output "Iniciando função SetExplorerThisPC para definir o Explorer para abrir This PC." -ConsoleOutput
  
  Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Value 1 -Type "DWord" -Force
  #Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1
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
  Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "IconsOnly" -Value 0 -Type "DWord" -Force
  #Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "IconsOnly" -Type DWord -Value 0
}

function EnableThumbsDB {
  Write-Output "Enabling Thumbs.db on network folders..."
  Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbnailCache" -Value 0 -Type "DWord" -Force
  #Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbnailCache" -Type DWord -Value 0
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
    Set-RegistryValue -Path "HKCR:\$ext" -Name "(Default)" -Value "PhotoViewer.FileAssoc.Tiff" -Type "String" -Force
    #Set-ItemProperty -Path "HKCR:\$ext" -Name "(Default)" -Value "PhotoViewer.FileAssoc.Tiff"
  }
}

function AddPhotoViewerOpenWith {
  Write-Output "Adding Photo Viewer to 'Open with' menu..."
  If (!(Test-Path "HKCR:\Applications\photoviewer.dll\shell\open")) {
    New-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open" -Force | Out-Null
  }
  Set-RegistryValue -Path "HKCR:\Applications\photoviewer.dll\shell\open" -Name "(Default)" -Value "Open with Photo Viewer" -Type "String" -Force
  #Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open" -Name "(Default)" -Value "Open"
  If (!(Test-Path "HKCR:\Applications\photoviewer.dll\shell\open\command")) {
    New-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open\command" -Force | Out-Null
  }
  Set-RegistryValue -Path "HKCR:\Applications\photoviewer.dll\shell\open\command" -Name "(Default)" -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1" -Type "String" -Force
  #Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open\command" -Name "(Default)" -Type ExpandString -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1"
}

function InstallPDFPrinter {
  Write-Output "Installing Microsoft Print to PDF..."
  Enable-WindowsOptionalFeature -Online -FeatureName "Printing-PrintToPDFServices-Features" -NoRestart -ErrorAction SilentlyContinue
}

function SVCHostTweak {
  Write-Output "Tweaking SVCHost process priority..."
  Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -Value 4194304 -Type "DWord" -Force
  #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -Type DWord -Value 4194304
}

function UnpinStartMenuTiles {
  Write-Output "Unpinning all Start Menu tiles..."
  $key = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount" -Name "*"
  if ($key) {
    Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\*" -Recurse -Force -ErrorAction SilentlyContinue
  }
}

Function QOL {
  Log-Action -Message "Iniciando função QOL para aplicar ajustes de qualidade de vida do DaddyMadu." -ConsoleOutput

  try {
    Write-Output "Habilitando ajustes de qualidade de vida do DaddyMadu..."
    Log-Action -Message "Habilitando ajustes de qualidade de vida do DaddyMadu..." -ConsoleOutput

    $errpref = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"
    Log-Action -Message "Alterando ErrorActionPreference para SilentlyContinue temporariamente." -ConsoleOutput

    Log-Action -Message "Criando chave HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement..." -ConsoleOutput
    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -ErrorAction Stop | Out-Null
    Log-Action -Message "Chave HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement criada ou verificada com sucesso." -Level "INFO" -ConsoleOutput

    Log-Action -Message "Configurando ScoobeSystemSettingEnabled para 0 para desativar 'Aproveite ainda mais o Windows'..." -ConsoleOutput
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Name "ScoobeSystemSettingEnabled" -Value 0 -Type "DWord" -Force
    #Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Name "ScoobeSystemSettingEnabled" -Type DWord -Value 0 -ErrorAction Stop | Out-Null
    Log-Action -Message "ScoobeSystemSettingEnabled configurado com sucesso." -Level "INFO" -ConsoleOutput

    Log-Action -Message "Configurando DynamicScrollbars para 0 para desativar ocultar barras de rolagem..." -ConsoleOutput
    Set-RegistryValue -Path "HKCU:\Control Panel\Accessibility" -Name "DynamicScrollbars" -Value 0 -Type "DWord" -Force
    #Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility" -Name "DynamicScrollbars" -Type DWord -Value 0 -ErrorAction Stop
    Log-Action -Message "DynamicScrollbars configurado com sucesso." -Level "INFO" -ConsoleOutput

    Log-Action -Message "Configurando SmoothScroll para 0 para desativar rolagem suave..." -ConsoleOutput
    Set-RegistryValue -Path "HKCU:\Control Panel\Desktop" -Name "SmoothScroll" -Value 0 -Type "DWord" -Force
    #Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "SmoothScroll" -Type DWord -Value 0 -ErrorAction Stop
    Log-Action -Message "SmoothScroll configurado com sucesso." -Level "INFO" -ConsoleOutput

    $osBuild = [System.Environment]::OSVersion.Version.Build
    Log-Action -Message "Verificando versão do SO (Build: $osBuild) para aplicar NoInstrumentation..." -ConsoleOutput
    If ($osBuild -ge 22000) {
      Log-Action -Message "Configurando NoInstrumentation para 1 no Windows 11 ou superior para desativar rastreamento de usuário da Microsoft..." -ConsoleOutput
      Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoInstrumentation" -Value 1 -Type "DWord" -Force
      #Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoInstrumentation" -Type DWord -Value 1 -ErrorAction Stop
      Log-Action -Message "NoInstrumentation configurado com sucesso para Windows 11 ou superior." -Level "INFO" -ConsoleOutput
    }
    Else {
      Log-Action -Message "Configurando NoInstrumentation para 1 em versões anteriores ao Windows 11 para desativar rastreamento de usuário da Microsoft..." -ConsoleOutput
      Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoInstrumentation" -Value 1 -Type "DWord" -Force
      #Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoInstrumentation" -Type DWord -Value 1 -ErrorAction Stop
      Log-Action -Message "NoInstrumentation configurado com sucesso para versões anteriores ao Windows 11." -Level "INFO" -ConsoleOutput
    }

    Log-Action -Message "Removendo TaskbarNoMultimon de HKCU:\Software\Policies\Microsoft\Windows\Explorer..." -ConsoleOutput
    Remove-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "TaskbarNoMultimon" -ErrorAction Stop
    Log-Action -Message "TaskbarNoMultimon removido com sucesso de HKCU." -Level "INFO" -ConsoleOutput

    Log-Action -Message "Removendo TaskbarNoMultimon de HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer..." -ConsoleOutput
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "TaskbarNoMultimon" -ErrorAction Stop
    Log-Action -Message "TaskbarNoMultimon removido com sucesso de HKLM." -Level "INFO" -ConsoleOutput

    Log-Action -Message "Configurando MMTaskbarMode para 2 para mostrar botões da barra de tarefas apenas onde a janela está aberta..." -ConsoleOutput
    Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "MMTaskbarMode" -Value 2 -Type "DWord" -Force
    #Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "MMTaskbarMode" -Type DWord -Value 2 -ErrorAction Stop
    Log-Action -Message "MMTaskbarMode configurado com sucesso." -Level "INFO" -ConsoleOutput

    Log-Action -Message "Ajustes de qualidade de vida aplicados com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função QOL: $_"
    Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
    
    throw  # Repropaga o erro
  }
  finally {
    $ErrorActionPreference = $errpref
    Log-Action -Message "Restaurando ErrorActionPreference para $errpref." -ConsoleOutput
    Log-Action -Message "Finalizando função QOL." -Level "INFO" -ConsoleOutput
  }
}
Function FullscreenOptimizationFIX {
  Log-Action -Message "Iniciando função FullscreenOptimizationFIX para desativar otimizações de tela cheia." -ConsoleOutput

  try {
    $errpref = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"
    Log-Action -Message "Alterando ErrorActionPreference para SilentlyContinue temporariamente." -ConsoleOutput

    Write-Output "Desativando otimizações de tela cheia..."
    Log-Action -Message "Desativando otimizações de tela cheia..." -ConsoleOutput

    Log-Action -Message "Configurando GameDVR_FSEBehaviorMode para 2 em HKCU:\System\GameConfigStore..." -ConsoleOutput
    Set-RegistryValue -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehaviorMode" -Value 2 -Type "DWord" -Force
    #Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehaviorMode" -Type DWord -Value 2 -ErrorAction Stop
    Log-Action -Message "GameDVR_FSEBehaviorMode configurado com sucesso." -Level "INFO" -ConsoleOutput

    Log-Action -Message "Configurando GameDVR_HonorUserFSEBehaviorMode para 1 em HKCU:\System\GameConfigStore..." -ConsoleOutput
    Set-RegistryValue -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_HonorUserFSEBehaviorMode" -Value 1 -Type "DWord" -Force
    #Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_HonorUserFSEBehaviorMode" -Type DWord -Value 1 -ErrorAction Stop
    Log-Action -Message "GameDVR_HonorUserFSEBehaviorMode configurado com sucesso." -Level "INFO" -ConsoleOutput

    Log-Action -Message "Configurando GameDVR_FSEBehavior para 2 em HKCU:\System\GameConfigStore..." -ConsoleOutput
    Set-RegistryValue -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehavior" -Value 2 -Type "DWord" -Force
    #Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehavior" -Type DWord -Value 2 -ErrorAction Stop
    Log-Action -Message "GameDVR_FSEBehavior configurado com sucesso." -Level "INFO" -ConsoleOutput

    Log-Action -Message "Configurando GameDVR_DXGIHonorFSEWindowsCompatible para 1 em HKCU:\System\GameConfigStore..." -ConsoleOutput
    Set-RegistryValue -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_DXGIHonorFSEWindowsCompatible" -Value 1 -Type "DWord" -Force
    #Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_DXGIHonorFSEWindowsCompatible" -Type DWord -Value 1 -ErrorAction Stop
    Log-Action -Message "GameDVR_DXGIHonorFSEWindowsCompatible configurado com sucesso." -Level "INFO" -ConsoleOutput

    Log-Action -Message "Configurando GameDVR_EFSEFeatureFlags para 0 em HKCU:\System\GameConfigStore..." -ConsoleOutput
    Set-RegistryValue -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_EFSEFeatureFlags" -Value 0 -Type "DWord" -Force
    #Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_EFSEFeatureFlags" -Type DWord -Value 0 -ErrorAction Stop
    Log-Action -Message "GameDVR_EFSEFeatureFlags configurado com sucesso." -Level "INFO" -ConsoleOutput

    Log-Action -Message "Configurando GameDVR_DSEBehavior para 2 em HKCU:\System\GameConfigStore..." -ConsoleOutput
    Set-RegistryValue -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_DSEBehavior" -Value 2 -Type "DWord" -Force
    #Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_DSEBehavior" -Type DWord -Value 2 -ErrorAction Stop
    Log-Action -Message "GameDVR_DSEBehavior configurado com sucesso." -Level "INFO" -ConsoleOutput

    Log-Action -Message "Configurando AppCaptureEnabled para 0 em HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR..." -ConsoleOutput
    Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Value 0 -Type "DWord" -Force
    #Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Type DWord -Value 0 -ErrorAction Stop
    Log-Action -Message "AppCaptureEnabled configurado com sucesso." -Level "INFO" -ConsoleOutput

    Log-Action -Message "Configurando SwapEffectUpgradeCache para 1 em HKCU:\Software\Microsoft\DirectX\GraphicsSettings..." -ConsoleOutput
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\DirectX\GraphicsSettings" -Name "SwapEffectUpgradeCache" -Value 1 -Type "DWord" -Force
    #Set-ItemProperty -Path "HKCU:\Software\Microsoft\DirectX\GraphicsSettings" -Name "SwapEffectUpgradeCache" -Type DWord -Value 1 -ErrorAction Stop
    Log-Action -Message "SwapEffectUpgradeCache configurado com sucesso." -Level "INFO" -ConsoleOutput

    Log-Action -Message "Configurando DirectXUserGlobalSettings para 'SwapEffectUpgradeEnable=1;' em HKCU:\Software\Microsoft\DirectX\UserGpuPreferences..." -ConsoleOutput
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\DirectX\UserGpuPreferences" -Name "DirectXUserGlobalSettings" -Value 'SwapEffectUpgradeEnable=1;' -Type "String" -Force
    #Set-ItemProperty -Path "HKCU:\Software\Microsoft\DirectX\UserGpuPreferences" -Name "DirectXUserGlobalSettings" -Type String -Value 'SwapEffectUpgradeEnable=1;' -ErrorAction Stop    
    Log-Action -Message "DirectXUserGlobalSettings configurado com sucesso." -Level "INFO" -ConsoleOutput

    Log-Action -Message "Configurando InactivityShutdownDelay para 4294967295 em HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform..." -ConsoleOutput
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform" -Name "InactivityShutdownDelay" -Value 4294967295 -Type "DWord" -Force
    #Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform" -Name "InactivityShutdownDelay" -Type DWord -Value 4294967295 -ErrorAction Stop
    Log-Action -Message "InactivityShutdownDelay configurado com sucesso." -Level "INFO" -ConsoleOutput

    Log-Action -Message "Configurando OverlayTestMode para 5 em HKLM:\SOFTWARE\Microsoft\Windows\Dwm..." -ConsoleOutput
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\Dwm" -Name "OverlayTestMode" -Value 5 -Type "DWord" -Force
    #Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Dwm" -Name "OverlayTestMode" -Type DWord -Value 5 -ErrorAction Stop
    Log-Action -Message "OverlayTestMode configurado com sucesso." -Level "INFO" -ConsoleOutput

    Log-Action -Message "Desativando compressão de memória via MMAgent..." -ConsoleOutput
    Disable-MMAgent -MemoryCompression -ErrorAction Stop | Out-Null
    Log-Action -Message "Compressão de memória desativada com sucesso." -Level "INFO" -ConsoleOutput

    Log-Action -Message "Ajustes de otimização de tela cheia aplicados com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função FullscreenOptimizationFIX: $_"
    Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
    
    throw  # Repropaga o erro
  }
  finally {
    $ErrorActionPreference = $errpref
    Log-Action -Message "Restaurando ErrorActionPreference para $errpref." -ConsoleOutput
    Log-Action -Message "Finalizando função FullscreenOptimizationFIX." -Level "INFO" -ConsoleOutput
  }
}

Function GameOptimizationFIX {
  Log-Action -Message "Iniciando função GameOptimizationFIX para aplicar correções de otimização para jogos." -ConsoleOutput

  try {
    Write-Output "Aplicando correções de otimização para jogos..."
    Log-Action -Message "Aplicando correções de otimização para jogos..." -ConsoleOutput

    Log-Action -Message "Configurando GPU Priority para 8 em HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games..." -ConsoleOutput
    #Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "GPU Priority" -Type DWord -Value 8 -ErrorAction Stop
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "GPU Priority" -Value 8 -Type "DWord" -Force
    Log-Action -Message "GPU Priority configurado com sucesso." -Level "INFO" -ConsoleOutput

    Log-Action -Message "Configurando Priority para 6 em HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games..." -ConsoleOutput
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Priority" -Value 6 -Type "DWord" -Force
    #Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Priority" -Type DWord -Value 6 -ErrorAction Stop
    Log-Action -Message "Priority configurado com sucesso." -Level "INFO" -ConsoleOutput

    Log-Action -Message "Configurando Scheduling Category para 'High' em HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games..." -ConsoleOutput
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Scheduling Category" -Value "High" -Type "String" -Force
    #Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Scheduling Category" -Type String -Value "High" -ErrorAction Stop
    Log-Action -Message "Scheduling Category configurado com sucesso." -Level "INFO" -ConsoleOutput

    Log-Action -Message "Configurando SFIO Priority para 'High' em HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games..." -ConsoleOutput
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "SFIO Priority" -Value "High" -Type "String" -Force
    #Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "SFIO Priority" -Type String -Value "High" -ErrorAction Stop
    Log-Action -Message "SFIO Priority configurado com sucesso." -Level "INFO" -ConsoleOutput

    Log-Action -Message "Configurando IRQ8Priority para 1 em HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl..." -ConsoleOutput
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "IRQ8Priority" -Value 1 -Type "DWord" -Force
    #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "IRQ8Priority" -Type DWord -Value 1 -ErrorAction Stop
    Log-Action -Message "IRQ8Priority configurado com sucesso." -Level "INFO" -ConsoleOutput

    Log-Action -Message "Adicionando CpuPriorityClass para 4 em HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions..." -ConsoleOutput
    reg ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v CpuPriorityClass /t REG_DWORD /d 4 /f -ErrorAction Stop | Out-Null
    Log-Action -Message "CpuPriorityClass adicionado com sucesso." -Level "INFO" -ConsoleOutput

    Log-Action -Message "Adicionando IoPriority para 3 em HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions..." -ConsoleOutput
    reg ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v IoPriority /t REG_DWORD /d 3 /f -ErrorAction Stop | Out-Null
    Log-Action -Message "IoPriority adicionado com sucesso." -Level "INFO" -ConsoleOutput

    Log-Action -Message "Desativando suporte a nomes 8.3 via fsutil..." -ConsoleOutput
    fsutil behavior set disable8dot3 1 -ErrorAction Stop
    Log-Action -Message "Suporte a nomes 8.3 desativado com sucesso." -Level "INFO" -ConsoleOutput

    Log-Action -Message "Desativando última atualização de acesso via fsutil..." -ConsoleOutput
    fsutil behavior set disablelastaccess 1 -ErrorAction Stop
    Log-Action -Message "Última atualização de acesso desativada com sucesso." -Level "INFO" -ConsoleOutput

    Log-Action -Message "Verificando tipo de plataforma do sistema..." -ConsoleOutput
    $PlatformCheck = (Get-ComputerInfo -ErrorAction Stop).CsPCSystemType
    Log-Action -Message "Plataforma detectada: $PlatformCheck" -ConsoleOutput

    if ($PlatformCheck -eq "Desktop") {
      Write-Output "A plataforma é $PlatformCheck. Desativando opções de economia de energia em todos os dispositivos conectados..."
      Log-Action -Message "A plataforma é $PlatformCheck. Desativando opções de economia de energia em todos os dispositivos conectados..." -ConsoleOutput

      Get-WmiObject MSPower_DeviceEnable -Namespace root\wmi -ErrorAction Stop | ForEach-Object { 
        Log-Action -Message "Desativando economia de energia para dispositivo: $($_.InstanceName)..." -ConsoleOutput
        $_.enable = $false
        $_.psbase.put() | Out-Null
        Log-Action -Message "Economia de energia desativada com sucesso para $($_.InstanceName)." -Level "INFO" -ConsoleOutput
      }
      Log-Action -Message "Opções de economia de energia desativadas com sucesso em todos os dispositivos conectados." -Level "INFO" -ConsoleOutput
    }
    else {
      Write-Output "A plataforma é $PlatformCheck. Nenhuma edição de economia de energia foi realizada."
      Log-Action -Message "A plataforma é $PlatformCheck. Nenhuma edição de economia de energia foi realizada." -ConsoleOutput
    }

    Log-Action -Message "Correções de otimização para jogos aplicadas com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função GameOptimizationFIX: $_"
    Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
    
    throw  # Repropaga o erro
  }
  finally {
    Log-Action -Message "Finalizando função GameOptimizationFIX." -Level "INFO" -ConsoleOutput
  }
}

function RawMouseInput {
  Log-Action -Message "Iniciando função RawMouseInput para forçar entrada bruta do mouse e desativar precisão aprimorada do ponteiro." -Level "INFO" -ConsoleOutput

  try {
    Write-Output "Forçando entrada bruta do mouse e desativando precisão aprimorada do ponteiro..."

    $registryPath = "HKCU:\Control Panel\Mouse"
    Set-RegistryValue -Path $registryPath -Name "MouseSpeed" -Value "0" -Type "String"
    Set-RegistryValue -Path $registryPath -Name "MouseThreshold1" -Value "0" -Type "String"
    Set-RegistryValue -Path $registryPath -Name "MouseThreshold2" -Value "0" -Type "String"
    Set-RegistryValue -Path $registryPath -Name "MouseSensitivity" -Value "10" -Type "String"
    Set-RegistryValue -Path $registryPath -Name "MouseHoverTime" -Value "0" -Type "String"
    Set-RegistryValue -Path $registryPath -Name "MouseTrails" -Value "0" -Type "String"

    Log-Action -Message "Entrada bruta do mouse forçada e precisão aprimorada do ponteiro desativada com sucesso." -Level "INFO" -ConsoleOutput
    Write-Colored "Entrada bruta do mouse forçada e precisão aprimorada do ponteiro desativada com sucesso." -Color "VerdeClaro"
  }
  catch {
    $errorMessage = "Erro na função RawMouseInput: $_"
    Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
    Write-Colored $errorMessage -Color "VermelhoClaro"
    throw
  }
  finally {
    Log-Action -Message "Finalizando função RawMouseInput." -Level "INFO" -ConsoleOutput
  }
}

function DetectnApplyMouseFIX {
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

  Log-Action -Message "Iniciando função DetectnApplyMouseFIX para detectar e aplicar correção de mouse." -Level "INFO" -ConsoleOutput

  try {
    $checkscreenscale = [Math]::Round([DPI]::scaling(), 2) * 100
    $regPath = "HKCU:\Control Panel\Mouse"

    if ($checkscreenscale -eq "100") {
      Write-Output "Windows screen scale is Detected as 100%, Applying Mouse Fix for it..."
      $YourInputX = "00,00,00,00,00,00,00,00,C0,CC,0C,00,00,00,00,00,80,99,19,00,00,00,00,00,40,66,26,00,00,00,00,00,00,33,33,00,00,00,00,00"
      $YourInputY = "00,00,00,00,00,00,00,00,00,00,38,00,00,00,00,00,00,00,70,00,00,00,00,00,00,00,A8,00,00,00,00,00,00,00,E0,00,00,00,00,00"
      $hexifiedX = $YourInputX.Split(',') | ForEach-Object { "0x$_" }
      $hexifiedY = $YourInputY.Split(',') | ForEach-Object { "0x$_" }
      Set-RegistryValue -Path $regPath -Name "SmoothMouseXCurve" -Value ([byte[]]$hexifiedX) -Type "Binary"
      Set-RegistryValue -Path $regPath -Name "SmoothMouseYCurve" -Value ([byte[]]$hexifiedY) -Type "Binary"
    }
    elseif ($checkscreenscale -eq "125") {
      Write-Output "Windows screen scale is Detected as 125%, Applying Mouse Fix for it..."
      $YourInputX = "00,00,00,00,00,00,00,00,00,00,10,00,00,00,00,00,00,00,20,00,00,00,00,00,00,00,30,00,00,00,00,00,00,00,40,00,00,00,00,00"
      $YourInputY = "00,00,00,00,00,00,00,00,00,00,38,00,00,00,00,00,00,00,70,00,00,00,00,00,00,00,A8,00,00,00,00,00,00,00,E0,00,00,00,00,00"
      $hexifiedX = $YourInputX.Split(',') | ForEach-Object { "0x$_" }
      $hexifiedY = $YourInputY.Split(',') | ForEach-Object { "0x$_" }
      Set-RegistryValue -Path $regPath -Name "SmoothMouseXCurve" -Value ([byte[]]$hexifiedX) -Type "Binary"
      Set-RegistryValue -Path $regPath -Name "SmoothMouseYCurve" -Value ([byte[]]$hexifiedY) -Type "Binary"
    }
    elseif ($checkscreenscale -eq "150") {
      Write-Output "Windows screen scale is Detected as 150%, Applying Mouse Fix for it..."
      $YourInputX = "00,00,00,00,00,00,00,00,30,33,13,00,00,00,00,00,60,66,26,00,00,00,00,00,90,99,39,00,00,00,00,00,C0,CC,4C,00,00,00,00,00"
      $YourInputY = "00,00,00,00,00,00,00,00,00,00,38,00,00,00,00,00,00,00,70,00,00,00,00,00,00,00,A8,00,00,00,00,00,00,00,E0,00,00,00,00,00"
      $hexifiedX = $YourInputX.Split(',') | ForEach-Object { "0x$_" }
      $hexifiedY = $YourInputY.Split(',') | ForEach-Object { "0x$_" }
      Set-RegistryValue -Path $regPath -Name "SmoothMouseXCurve" -Value ([byte[]]$hexifiedX) -Type "Binary"
      Set-RegistryValue -Path $regPath -Name "SmoothMouseYCurve" -Value ([byte[]]$hexifiedY) -Type "Binary"
    }
    elseif ($checkscreenscale -eq "175") {
      Write-Output "Windows screen scale is Detected as 175%, Applying Mouse Fix for it..."
      $YourInputX = "00,00,00,00,00,00,00,00,60,66,16,00,00,00,00,00,C0,CC,2C,00,00,00,00,00,20,33,43,00,00,00,00,00,80,99,59,00,00,00,00,00"
      $YourInputY = "00,00,00,00,00,00,00,00,00,00,38,00,00,00,00,00,00,00,70,00,00,00,00,00,00,00,A8,00,00,00,00,00,00,00,E0,00,00,00,00,00"
      $hexifiedX = $YourInputX.Split(',') | ForEach-Object { "0x$_" }
      $hexifiedY = $YourInputY.Split(',') | ForEach-Object { "0x$_" }
      Set-RegistryValue -Path $regPath -Name "SmoothMouseXCurve" -Value ([byte[]]$hexifiedX) -Type "Binary"
      Set-RegistryValue -Path $regPath -Name "SmoothMouseYCurve" -Value ([byte[]]$hexifiedY) -Type "Binary"
    }
    elseif ($checkscreenscale -eq "200") {
      Write-Output "Windows screen scale is Detected as 200%, Applying Mouse Fix for it..."
      $YourInputX = "00,00,00,00,00,00,00,00,90,99,19,00,00,00,00,00,20,33,33,00,00,00,00,00,B0,CC,4C,00,00,00,00,00,40,66,66,00,00,00,00,00"
      $YourInputY = "00,00,00,00,00,00,00,00,00,00,38,00,00,00,00,00,00,00,70,00,00,00,00,00,00,00,A8,00,00,00,00,00,00,00,E0,00,00,00,00,00"
      $hexifiedX = $YourInputX.Split(',') | ForEach-Object { "0x$_" }
      $hexifiedY = $YourInputY.Split(',') | ForEach-Object { "0x$_" }
      Set-RegistryValue -Path $regPath -Name "SmoothMouseXCurve" -Value ([byte[]]$hexifiedX) -Type "Binary"
      Set-RegistryValue -Path $regPath -Name "SmoothMouseYCurve" -Value ([byte[]]$hexifiedY) -Type "Binary"
    }
    elseif ($checkscreenscale -eq "225") {
      Write-Output "Windows screen scale is Detected as 225%, Applying Mouse Fix for it..."
      $YourInputX = "00,00,00,00,00,00,00,00,C0,CC,1C,00,00,00,00,00,80,99,39,00,00,00,00,00,40,66,56,00,00,00,00,00,00,33,73,00,00,00,00,00"
      $YourInputY = "00,00,00,00,00,00,00,00,00,00,38,00,00,00,00,00,00,00,70,00,00,00,00,00,00,00,A8,00,00,00,00,00,00,00,E0,00,00,00,00,00"
      $hexifiedX = $YourInputX.Split(',') | ForEach-Object { "0x$_" }
      $hexifiedY = $YourInputY.Split(',') | ForEach-Object { "0x$_" }
      Set-RegistryValue -Path $regPath -Name "SmoothMouseXCurve" -Value ([byte[]]$hexifiedX) -Type "Binary"
      Set-RegistryValue -Path $regPath -Name "SmoothMouseYCurve" -Value ([byte[]]$hexifiedY) -Type "Binary"
    }
    elseif ($checkscreenscale -eq "250") {
      Write-Output "Windows screen scale is Detected as 250%, Applying Mouse Fix for it..."
      $YourInputX = "00,00,00,00,00,00,00,00,00,00,20,00,00,00,00,00,00,00,40,00,00,00,00,00,00,00,60,00,00,00,00,00,00,00,80,00,00,00,00,00"
      $YourInputY = "00,00,00,00,00,00,00,00,00,00,38,00,00,00,00,00,00,00,70,00,00,00,00,00,00,00,A8,00,00,00,00,00,00,00,E0,00,00,00,00,00"
      $hexifiedX = $YourInputX.Split(',') | ForEach-Object { "0x$_" }
      $hexifiedY = $YourInputY.Split(',') | ForEach-Object { "0x$_" }
      Set-RegistryValue -Path $regPath -Name "SmoothMouseXCurve" -Value ([byte[]]$hexifiedX) -Type "Binary"
      Set-RegistryValue -Path $regPath -Name "SmoothMouseYCurve" -Value ([byte[]]$hexifiedY) -Type "Binary"
    }
    elseif ($checkscreenscale -eq "300") {
      Write-Output "Windows screen scale is Detected as 300%, Applying Mouse Fix for it..."
      $YourInputX = "00,00,00,00,00,00,00,00,60,66,26,00,00,00,00,00,C0,CC,4C,00,00,00,00,00,20,33,73,00,00,00,00,00,80,99,99,00,00,00,00,00"
      $YourInputY = "00,00,00,00,00,00,00,00,00,00,38,00,00,00,00,00,00,00,70,00,00,00,00,00,00,00,A8,00,00,00,00,00,00,00,E0,00,00,00,00,00"
      $hexifiedX = $YourInputX.Split(',') | ForEach-Object { "0x$_" }
      $hexifiedY = $YourInputY.Split(',') | ForEach-Object { "0x$_" }
      Set-RegistryValue -Path $regPath -Name "SmoothMouseXCurve" -Value ([byte[]]$hexifiedX) -Type "Binary"
      Set-RegistryValue -Path $regPath -Name "SmoothMouseYCurve" -Value ([byte[]]$hexifiedY) -Type "Binary"
    }
    elseif ($checkscreenscale -eq "350") {
      Write-Output "Windows screen scale is Detected as 350%, Applying Mouse Fix for it..."
      $YourInputX = "00,00,00,00,00,00,00,00,C0,CC,2C,00,00,00,00,00,80,99,59,00,00,00,00,00,40,66,86,00,00,00,00,00,00,33,B3,00,00,00,00,00"
      $YourInputY = "00,00,00,00,00,00,00,00,00,00,38,00,00,00,00,00,00,00,70,00,00,00,00,00,00,00,A8,00,00,00,00,00,00,00,E0,00,00,00,00,00"
      $hexifiedX = $YourInputX.Split(',') | ForEach-Object { "0x$_" }
      $hexifiedY = $YourInputY.Split(',') | ForEach-Object { "0x$_" }
      Set-RegistryValue -Path $regPath -Name "SmoothMouseXCurve" -Value ([byte[]]$hexifiedX) -Type "Binary"
      Set-RegistryValue -Path $regPath -Name "SmoothMouseYCurve" -Value ([byte[]]$hexifiedY) -Type "Binary"
    }
    else {
      Write-Output "HOUSTON WE HAVE A PROBLEM! screen scale is not set to traditional value, nothing has been set!"
      Log-Action -Message "Escala de tela não tradicional detectada ($checkscreenscale%). Nenhuma correção aplicada." -Level "WARNING" -ConsoleOutput
    }

    Log-Action -Message "Correção de mouse aplicada com sucesso para escala $checkscreenscale%." -Level "INFO" -ConsoleOutput
    Write-Colored "Correção de mouse aplicada com sucesso." -Color "VerdeClaro"
  }
  catch {
    $errorMessage = "Erro na função DetectnApplyMouseFIX: $_"
    Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
    Write-Colored $errorMessage -Color "VermelhoClaro"
    throw
  }
  finally {
    Log-Action -Message "Finalizando função DetectnApplyMouseFIX." -Level "INFO" -ConsoleOutput
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
  Log-Action -Message "Iniciando função EnableGameMode para habilitar o Modo de Jogo." -Level "INFO" -ConsoleOutput

  try {
    Log-Action -Message "Habilitando Modo de Jogo..." -ConsoleOutput
      
    $registryPath = "HKCU:\Software\Microsoft\GameBar"
    Set-RegistryValue -Path $registryPath -Name "AllowAutoGameMode" -Value 1 -Type "DWord"
    Set-RegistryValue -Path $registryPath -Name "AutoGameModeEnabled" -Value 1 -Type "DWord"

    Log-Action -Message "Modo de Jogo habilitado com sucesso." -Level "INFO" -ConsoleOutput
      
  }
  catch {
    $errorMessage = "Erro na função EnableGameMode: $_"
    Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
      
    throw
  }
  finally {
    Log-Action -Message "Finalizando função EnableGameMode." -Level "INFO" -ConsoleOutput
  }
}

function EnableHAGS {
  Log-Action -Message "Iniciando função EnableHAGS para habilitar o Agendamento de GPU Acelerado por Hardware." -Level "INFO" -ConsoleOutput

  try {
    Log-Action -Message "Habilitando Agendamento de GPU Acelerado por Hardware..." -ConsoleOutput
      
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers"
    Set-RegistryValue -Path $registryPath -Name "HwSchMode" -Value 2 -Type "DWord" -Force

    Log-Action -Message "Agendamento de GPU Acelerado por Hardware habilitado com sucesso." -Level "INFO" -ConsoleOutput
      
  }
  catch {
    $errorMessage = "Erro na função EnableHAGS: $_"
    Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
      
    throw
  }
  finally {
    Log-Action -Message "Finalizando função EnableHAGS." -Level "INFO" -ConsoleOutput
  }
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
  Log-Action -Message "Iniciando função ManagePowerProfiles para gerenciar perfis de energia." -Level "INFO" -ConsoleOutput

  try {
    Log-Action -Message "Gerenciando Perfis de Energia..." -Level "INFO" -ConsoleOutput
    
    # Definir o banner e opções para o menu
    $banner = @(
      "",
      "",
      "╔═══════════════════════════════════════════╗",
      "╠════════ Gerenciar Perfis de Energia ══════╣",
      "╚═══════════════════════════════════════════╝",
      "",
      "≫ Escolha uma opção para configurar o perfil de energia:",
      "",
      "≫ F - Perfil Full Power Gaming (ideal para jogos)",
      "≫ B - Perfil Balanceado (padrão do Windows)",
      "≫ E - Perfil Econômico (economia de energia)",
      "≫ P - Pular esta etapa",
      ""
    )

    # Opções válidas
    $options = @("F", "B", "E", "P")

    # Chamar o menu e obter a escolha
    $choice = Show-Menu -BannerLines $banner -Options $options -Prompt "Digite sua escolha (1-4)" -ColorScheme "AmareloClaro"

    # Processar a escolha
    switch ($choice) {
      "F" {
        Log-Action -Message "Aplicando perfil Full Power Gaming..." -Level "INFO" -ConsoleOutput
        $fullPowerGamingGUID = "7c6f06f3-81e0-4dd7-a003-46b268fffb5a"  # GUID original

        # Verificar se o GUID existe
        $schemes = & powercfg /list | ForEach-Object {
          if ($_ -match "(\w{8}-\w{4}-\w{4}-\w{4}-\w{12})") {
            $matches[1]
          }
        }

        if ($schemes -notcontains $fullPowerGamingGUID) {
          Log-Action -Message "O perfil Full Power Gaming (GUID: $fullPowerGamingGUID) não existe." -Level "WARNING" -ConsoleOutput
          
          # Criar novo plano baseado em Alto Desempenho
          $newSchemeOutput = & powercfg /duplicatescheme 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
          if ($newSchemeOutput) {
            $newGUID = $newSchemeOutput | Select-String -Pattern "(\w{8}-\w{4}-\w{4}-\w{4}-\w{12})" | ForEach-Object { $_.Matches.Value }
            if ($newGUID) {
              & powercfg /changename $newGUID "Full Power Gaming" "Perfil otimizado para jogos" 2>$null
              $fullPowerGamingGUID = $newGUID
              Log-Action -Message "Novo perfil Full Power Gaming criado com GUID: $fullPowerGamingGUID" -Level "INFO" -ConsoleOutput
            }
            else {
              $errorMessage = "Falha ao extrair o novo GUID após duplicação."
              Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
              return
            }
          }
          else {
            $errorMessage = "Falha ao duplicar o plano Alto Desempenho."
            Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
            return
          }
        }

        # Ativar o plano (existente ou recém-criado)
        & powercfg /setactive $fullPowerGamingGUID 2>$null
        if ($LASTEXITCODE -ne 0) {
          $errorMessage = "Falha ao ativar o perfil Full Power Gaming com GUID: $fullPowerGamingGUID"
          Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
          return
        }
        Log-Action -Message "Perfil Full Power Gaming ativado com sucesso." -Level "INFO" -ConsoleOutput
        
        # Ajustes adicionais
        & powercfg /change standby-timeout-ac 0 2>$null
        & powercfg /change hibernate-timeout-ac 0 2>$null
        & powercfg /change monitor-timeout-ac 0 2>$null

        Log-Action -Message "Perfil Full Power Gaming aplicado com sucesso." -Level "INFO" -ConsoleOutput
        
        # Chamar DisableCoreParking
        Log-Action -Message "Desativando Core Parking no perfil Full Power Gaming..." -Level "INFO" -ConsoleOutput
        DisableCoreParking -PlanGUID $fullPowerGamingGUID
      }
      "B" {
        Log-Action -Message "Aplicando perfil Balanceado..." -Level "INFO" -ConsoleOutput
        $balancedGUID = "381b4222-f694-41f0-9685-ff5bb260df2e"
        & powercfg /setactive $balancedGUID 2>$null
        if ($LASTEXITCODE -ne 0) {
          $errorMessage = "Falha ao ativar o perfil Balanceado com GUID: $balancedGUID"
          Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
          return
        }
        Log-Action -Message "Perfil Balanceado aplicado com sucesso." -Level "INFO" -ConsoleOutput
      }
      "E" {
        Log-Action -Message "Aplicando perfil Econômico..." -Level "INFO" -ConsoleOutput
        $powerSaverGUID = "a1841308-3541-4fab-bc81-f71556f20b4a"
        & powercfg /setactive $powerSaverGUID 2>$null
        if ($LASTEXITCODE -ne 0) {
          $errorMessage = "Falha ao ativar o perfil Econômico com GUID: $powerSaverGUID"
          Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
          return
        }
        & powercfg /change standby-timeout-ac 10 2>$null
        & powercfg /change monitor-timeout-ac 5 2>$null
        Log-Action -Message "Perfil Econômico aplicado com sucesso." -Level "INFO" -ConsoleOutput
        
      }
      "P" {
        Log-Action -Message "Perfil de energia não alterado (opção de pular escolhida)." -Level "INFO" -ConsoleOutput
        
      }
    }
  }
  catch {
    $errorMessage = "Erro ao gerenciar perfis de energia: $_"
    Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
    
  }
  finally {
    Log-Action -Message "Finalizando função ManagePowerProfiles." -Level "INFO" -ConsoleOutput
  }
}

# Configuração inicial para codificação
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'
$PSDefaultParameterValues['*:Encoding'] = 'utf8'
[System.Threading.Thread]::CurrentThread.CurrentCulture = "pt-BR"
[System.Threading.Thread]::CurrentThread.CurrentUICulture = "pt-BR"

function DisableDMA {
  Log-Action -Message "Desativando o acesso direto à memória (DMA)..." -Level "INFO" -ConsoleOutput
  bcdedit /set configaccesspolicy DisallowMmConfig | Out-Null
}

Function DisablePKM {
  Log-Action -Message "Desativando o Kernel Memory Protection..." -Level "INFO" -ConsoleOutput
  
  $errpref = $ErrorActionPreference #save actual preference
  $ErrorActionPreference = "silentlycontinue"
  ForEach ($v in (Get-Command -Name "Set-ProcessMitigation").Parameters["Disable"].Attributes.ValidValues) { Set-ProcessMitigation -System -Disable $v.ToString() -ErrorAction SilentlyContinue }
  Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" -Name "DisableExceptionChainValidation" -Value 1 -Type "DWord" -Force
  #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DisableExceptionChainValidation" -Type DWord -Value 1
  Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "KernelSEHOPEnabled" -Value 0 -Type "DWord" -Force
  #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "KernelSEHOPEnabled" -Type DWord -Value 0
  Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "EnableCfg" -Value 0 -Type "DWord" -Force
  #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "EnableCfg" -Type DWord -Value 0
  $ErrorActionPreference = $errpref #restore previous preference
}

function DisallowDIP {
  Log-Action -Message "Desativando prompts de instalação de drivers..." -Level "INFO" -ConsoleOutput
  
  # Define o caminho do registro
  $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverInstall"

  # Verifica se a chave existe, senão cria
  if (!(Test-Path $regPath)) {
    Log-Action -Message "A chave do registro não existe. Criando agora..." -Level "INFO" -ConsoleOutput
    
    New-Item -Path $regPath -Force | Out-Null
  }

  # Define a propriedade "PromptOnNewDevice"
  Set-RegistryValue -Path $regPath -Name "PromptOnNewDevice" -Value 0 -Type "DWord" -Force
  #Set-ItemProperty -Path $regPath -Name "PromptOnNewDevice" -Type DWord -Value 0

  Log-Action -Message "Configuração aplicada com sucesso." -Level "INFO" -ConsoleOutput

}

function UseBigM {
  Log-Action -Message "Habilitando alocação de memória grande..." -Level "INFO" -ConsoleOutput
  
  bcdedit /set increaseuserva 4096 | Out-Null
}

function ForceContiguousM {
  Log-Action -Message "Forçando alocação de memória contígua..." -Level "INFO" -ConsoleOutput
  
  bcdedit /set removememory 1024 | Out-Null
}

function DecreaseMKBuffer {
  Log-Action -Message "Reduzindo o tamanho do buffer do mouse/teclado..." -Level "INFO" -ConsoleOutput
  
  Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" -Name "MouseDataQueueSize" -Value 50 -Type "DWord" -Force
  Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" -Name "KeyboardDataQueueSize" -Value 50 -Type "DWord" -Force
   
  #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" -Name "KeyboardDataQueueSize" -Type DWord -Value 50
  #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" -Name "MouseDataQueueSize" -Type DWord -Value 50
}

function StophighDPC {
  Log-Action -Message "Reduzindo alta latência DPC..." -Level "INFO" -ConsoleOutput
  
  Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "ExitLatency" -Value 0 -Type "DWord" -Force
  #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "ExitLatency" -Type DWord -Value 0
  Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "ExitLatencyCheckEnabled" -Value 0 -Type "DWord" -Force
  #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "ExitLatencyCheckEnabled" -Type DWord -Value 0
}

function Ativar-Servicos {
  param (
    [string[]]$Servicos = @('SysMain', 'PcaSvc', 'DiagTrack')
  )

  Log-Action -Message "Iniciando função Ativar-Servicos para ativar serviços essenciais." -Level "INFO" -ConsoleOutput

  try {
    # Exibir banner informativo inicial usando Show-Menu (sem opções ainda, apenas informativo)
    $banner = @(
      "",
      "",
      "╔════════════════════════════════════════╗",
      "╠══════ Ativar Serviços Essenciais ══════╣",
      "╚════════════════════════════════════════╝",
      "",
      "≫ Este menu auxilia na ativação dos seguintes serviços, essenciais para investigação forense de cheats em servidores de Minecraft, DayZ e FIVEM GTA5 que utilizam o Echo AntiCheat:",
      "",
      "≫ SysMain: O SysMain, anteriormente conhecido como Superfetch, é um serviço do Windows que preenche a memória RAM com aplicativos frequentemente usados para acelerar o carregamento dos programas mais utilizados.",
      "≫ PcaSvc: O PcaSvc (Program Compatibility Assistant Service) é um serviço que detecta problemas de compatibilidade em programas legados e aplica correções para melhorar a estabilidade do sistema.",
      "≫ DiagTrack: O DiagTrack (Connected User Experiences and Telemetry) coleta e envia dados de diagnóstico e uso para a Microsoft, auxiliando na melhoria dos serviços e na resolução de problemas.",
      "",
      "Pressione qualquer tecla para continuar..."
    )

    # Exibir o banner inicial (sem opções interativas, apenas informativo)
    Clear-Host
    $colors = @("Branco", "Branco", "Amarelo", "Amarelo", "Amarelo", "Branco", "AmareloClaro", "Branco", "AmareloClaro", "AmareloClaro", "AmareloClaro", "Verde")
    for ($i = 0; $i -lt $banner.Length; $i++) {
      $color = if ($i -lt $colors.Length) { $colors[$i] } else { "Branco" }
      Write-Colored -Text $banner[$i] -Color $color
    }
    [Console]::ReadKey($true) | Out-Null

    # Função interna para ativar um serviço (mantida como está)
    function Ativar-Servico {
      param (
        [string]$NomeServico
      )
      $servico = Get-Service -Name $NomeServico -ErrorAction SilentlyContinue
      if ($null -eq $servico) {
        Log-Action -Message "Serviço '$NomeServico' não encontrado." -Level "ERROR" -ConsoleOutput
        return
      }
      # Verifica se o serviço já está em execução
      Log-Action -Message "Serviço encontrado: $($servico.DisplayName) ($($servico.Name))" -Level "INFO" -ConsoleOutput
      if ($servico.Status -eq 'Running') {
        Log-Action -Message "Serviço '$($servico.Name)' já está em execução." -Level "INFO" -ConsoleOutput
      }
      else {
        Start-Service -Name $servico.Name -ErrorAction Stop
        Set-Service -Name $servico.Name -StartupType Automatic -ErrorAction Stop
        Log-Action -Message "Serviço '$($servico.Name)' ativado com sucesso." -Level "INFO" -ConsoleOutput
      }
    }

    # Loop para cada serviço com Show-Menu
    foreach ($nomeServico in $Servicos) {
      $serviceBanner = @(
        "",
        "",
        "╔═══════════════════════════════════════╗",
        "╠════ Ativar Serviço: $nomeServico ═════╣",
        "╚═══════════════════════════════════════╝",
        "",
        "≫ Deseja ativar o serviço '$nomeServico'?",
        "",
        "≫ Pressione 'S' para ativar o serviço.",
        "≫ Pressione 'N' para não ativar o serviço.",
        ""
      )

      # Opções válidas
      $options = @("S", "N")

      # Chamar o menu e obter a escolha
      $resposta = Show-Menu -BannerLines $serviceBanner -Options $options -Prompt "Deseja ativar o serviço '$nomeServico'? (S/N)" -ColorScheme "AmareloClaro"

      if ($resposta -eq 'S') {
        Ativar-Servico -NomeServico $nomeServico
      }
      else {
        Log-Action -Message "Serviço '$nomeServico' não foi ativado." -Level "INFO" -ConsoleOutput
      }
    }
  }
  catch {
    $errorMessage = "Erro na função Ativar-Servicos: $_"
    Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
    Write-Colored $errorMessage -Color "VermelhoClaro"
  }
  finally {
    Log-Action -Message "Finalizando função Ativar-Servicos." -Level "INFO" -ConsoleOutput
  }
}

function RemoveEdit3D {
  Log-Action -Message "Removendo 'Editar com 3D Paint' do menu de contexto." -Level "INFO" -ConsoleOutput
  
  Remove-Item -Path "HKCR:\SystemFileAssociations\.bmp\Shell\3D Edit" -Recurse -ErrorAction SilentlyContinue
  Remove-Item -Path "HKCR:\SystemFileAssociations\.jpg\Shell\3D Edit" -Recurse -ErrorAction SilentlyContinue
  Remove-Item -Path "HKCR:\SystemFileAssociations\.png\Shell\3D Edit" -Recurse -ErrorAction SilentlyContinue
}

function FixURLext {
  Log-Action -Message "Corrigindo associações de arquivos .url." -Level "INFO" -ConsoleOutput
  
  If (!(Test-Path "HKCR:\.url")) {
    New-Item -Path "HKCR:\.url" -Force | Out-Null
  }
  Set-RegistryValue -Path "HKCR:\.url" -Name "(Default)" -Value "InternetShortcut" -Type "String" -Force
  #Set-ItemProperty -Path "HKCR:\.url" -Name "(Default)" -Value "InternetShortcut"
}

function UltimateCleaner {
  Log-Action -Message "Iniciando função UltimateCleaner para limpeza do sistema." -Level "INFO" -ConsoleOutput
  
  Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
  Remove-Item -Path "$env:windir\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
  Remove-Item -Path "$env:windir\Prefetch\*" -Recurse -Force -ErrorAction SilentlyContinue
  Clear-RecycleBin -Force -ErrorAction SilentlyContinue
}

function Clear-PSHistory {
  Log-Action -Message "Iniciando função Clear-PSHistory para limpar o histórico do PowerShell." -Level "INFO" -ConsoleOutput
  
  Remove-Item -Path (Get-PSReadlineOption).HistorySavePath -Force -ErrorAction SilentlyContinue
}

function Remove-OneDrive {
  Log-Action "Iniciando função Remove-OneDrive para remover o OneDrive." -Level "INFO" -ConsoleOutput

  try {
    # Definir o banner e opções para o menu
    $banner = @(
      "",
      "",
      "╔════════════════════════════════════╗",
      "╠════ Remover o OneDrive ════════════╣",
      "╚════════════════════════════════════╝",
      "",
      "≫ Este menu permite remover o OneDrive do sistema.",
      "≫ Remover o OneDrive pode liberar recursos, mas desativa a sincronização de arquivos na nuvem.",
      "",
      "≫ Pressione 'R' para remover o OneDrive.",
      "≫ Pressione 'M' para manter o OneDrive.",
      "≫ Pressione 'P' para pular esta etapa.",
      ""
    )

    # Opções válidas
    $options = @("R", "M", "P")

    # Chamar o menu e obter a escolha
    $selection = Show-Menu -BannerLines $banner -Options $options -Prompt "Digite sua escolha (R/M/P)" -ColorScheme "AmareloClaro"

    # Processar a escolha
    switch ($selection) {
      "R" {
        Log-Action "Opção escolhida: Remover o OneDrive." -Level "INFO" -ConsoleOutput

        Log-Action "Removendo o OneDrive..." -Level "INFO" -ConsoleOutput
        
        try {
          # Parar o processo do OneDrive
          Stop-Process -Name "OneDrive" -Force -ErrorAction SilentlyContinue

          # Desinstalar o OneDrive
          $oneDrivePath = "$env:SystemRoot\SysWOW64\OneDriveSetup.exe"
          if (Test-Path $oneDrivePath) {
            Start-Process -FilePath $oneDrivePath -ArgumentList "/uninstall" -NoNewWindow -Wait -ErrorAction Stop
          }

          # Remover atalhos e arquivos residuais
          Remove-Item -Path "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" -Force -ErrorAction SilentlyContinue
          Remove-Item -Path "$env:USERPROFILE\OneDrive" -Recurse -Force -ErrorAction SilentlyContinue

          Log-Action "OneDrive removido com sucesso." -Level "INFO" -ConsoleOutput
          Write-Colored "OneDrive removido com sucesso." -Color "VerdeClaro"
        }
        catch {
          $errorMessage = "Erro ao remover o OneDrive: $_"
          Log-Action $errorMessage -Level "ERROR" -ConsoleOutput
          
        }
      }
      "M" {
        Log-Action "Opção escolhida: Manter o OneDrive." -Level "INFO" -ConsoleOutput
        
        Log-Action "OneDrive mantido no sistema." -Level "INFO" -ConsoleOutput
        
      }
      "P" {
        Log-Action "Remoção do OneDrive ignorada." -Level "WARNING" -ConsoleOutput
        
      }
    }
  }
  catch {
    $errorMessage = "Erro na função Remove-OneDrive: $_"
    Log-Action $errorMessage -Level "ERROR" -ConsoleOutput
    
  }
  finally {
    Log-Action "Finalizando função Remove-OneDrive." -Level "INFO" -ConsoleOutput
  }
}

function Windows11Extras {
  Log-Action -Message "Iniciando função Windows11Extras para aplicar ajustes específicos do Windows 11." -ConsoleOutput

  try {
    $osBuild = [System.Environment]::OSVersion.Version.Build
    Log-Action -Message "Versão do sistema operacional detectada: Build $osBuild" -ConsoleOutput

    if ($osBuild -ge 22000) {
      Log-Action -Message "Sistema operacional é Windows 11 (Build >= 22000). Aplicando ajustes..." -ConsoleOutput
      
      Log-Action -Message "Aplicando ajustes específicos do Windows 11..." -ConsoleOutput

      Log-Action -Message "Configurando TaskbarAl para 0 em HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced..." -ConsoleOutput
      Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value 0 -Type "DWord" -Force
      #Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Type DWord -Value 0 -ErrorAction Stop
      Log-Action -Message "TaskbarAl configurado com sucesso para centralizar a barra de tarefas." -Level "INFO" -ConsoleOutput

      Log-Action -Message "Configurando SearchboxTaskbarMode para 1 em HKCU:\Software\Microsoft\Windows\CurrentVersion\Search..." -ConsoleOutput
      Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 1 -Type "DWord" -Force
      #Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 1 -ErrorAction Stop
      Log-Action -Message "SearchboxTaskbarMode configurado com sucesso para mostrar busca na barra." -Level "INFO" -ConsoleOutput

      Log-Action -Message "Ajustes específicos do Windows 11 aplicados com sucesso." -Level "INFO" -ConsoleOutput
    }
    else {
      Log-Action -Message "Sistema operacional não é Windows 11 (Build < 22000). Pulando ajustes." -Level "INFO" -ConsoleOutput
    }
  }
  catch {
    $errorMessage = "Erro na função Windows11Extras: $_"
    Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
    
    throw  # Repropaga o erro
  }
  finally {
    Log-Action -Message "Finalizando função Windows11Extras." -Level "INFO" -ConsoleOutput
  }
}

function DebloatAll {
  Log-Action -Message "Iniciando função DebloatAll para executar o processo completo de debloat." -ConsoleOutput

  try {
    # Exibir banner informativo inicial usando Show-Menu (sem opções ainda, apenas informativo)
    Log-Action -Message "Executando o processo completo de debloat..." -ConsoleOutput

    $bloatware = @(
      "Microsoft.Microsoft3DViewer",
      "Microsoft.AppConnector",
      "Microsoft.BingFinance",
      "Microsoft.BingNews",
      "Microsoft.BingSports",
      "Microsoft.BingTranslator",
      "Microsoft.BingWeather",
      "Microsoft.BingFoodAndDrink",
      "Microsoft.BingHealthAndFitness",
      "Microsoft.BingTravel",
      "Microsoft.MinecraftUWP",
      "Microsoft.GamingServices",
      "Microsoft.GetHelp",
      "Microsoft.Getstarted",
      "Microsoft.Messaging",
      "Microsoft.Microsoft3DViewer",
      "Microsoft.MicrosoftSolitaireCollection",
      "Microsoft.NetworkSpeedTest",
      "Microsoft.News",
      "Microsoft.Office.Lens",
      "Microsoft.Office.Sway",
      "Microsoft.Office.OneNote",
      "Microsoft.OneConnect",
      "Microsoft.People",
      "Microsoft.Print3D",
      "Microsoft.SkypeApp",
      "Microsoft.Wallet",
      "Microsoft.Whiteboard",
      "Microsoft.WindowsAlarms",
      "microsoft.windowscommunicationsapps",
      "Microsoft.WindowsFeedbackHub",
      "Microsoft.WindowsMaps",
      "Microsoft.WindowsSoundRecorder",
      "Microsoft.ConnectivityStore",
      "Microsoft.ScreenSketch",
      "Microsoft.MixedReality.Portal",
      "Microsoft.ZuneMusic",
      "Microsoft.ZuneVideo",
      "Microsoft.Getstarted",
      "Microsoft.MicrosoftOfficeHub",
      "*EclipseManager*",
      "*ActiproSoftwareLLC*",
      "*AdobeSystemsIncorporated.AdobePhotoshopExpress*",
      "*Duolingo-LearnLanguagesforFree*",
      "*PandoraMediaInc*",
      "*CandyCrush*",
      "*BubbleWitch3Saga*",
      "*Wunderlist*",
      "*Flipboard*",
      "*Twitter*",
      "*Facebook*",
      "*Royal Revolt*",
      "*Sway*",
      "*Speed Test*",
      "*Dolby*",
      "*Viber*",
      "*ACGMediaPlayer*",
      "*Netflix*",
      "*OneCalendar*",
      "*LinkedInforWindows*",
      "*HiddenCityMysteryofShadows*",
      "*Hulu*",
      "*HiddenCity*",
      "*AdobePhotoshopExpress*",
      "*HotspotShieldFreeVPN*",
      "*Microsoft.Advertising.Xaml*"
    )
    Log-Action -Message "Lista de bloatware carregada: $($bloatware -join ', ')" -ConsoleOutput

    foreach ($app in $bloatware) {
      Log-Action -Message "Removendo o aplicativo $app para todos os usuários..." -ConsoleOutput
      Get-AppxPackage -Name $app -AllUsers -ErrorAction Stop | Remove-AppxPackage -ErrorAction Stop
      Log-Action -Message "Aplicativo $app removido com sucesso para todos os usuários." -Level "INFO" -ConsoleOutput

      Log-Action -Message "Removendo o pacote provisionado $app..." -ConsoleOutput
      Get-AppxProvisionedPackage -Online -ErrorAction Stop | Where-Object DisplayName -eq $app | Remove-AppxProvisionedPackage -Online -ErrorAction Stop
      Log-Action -Message "Pacote provisionado $app removido com sucesso." -Level "INFO" -ConsoleOutput
    }

    Log-Action -Message "Processo completo de debloat concluído com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função DebloatAll: $_"
    Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
    
    throw  # Repropaga o erro
  }
  finally {
    Log-Action -Message "Finalizando função DebloatAll." -Level "INFO" -ConsoleOutput
  }
}

function Invoke-WPFTweaksServices {
  <#
  .SYNOPSIS
  Ajusta o tipo de inicialização de serviços do sistema para otimizar o desempenho.

  .DESCRIPTION
  Esta função modifica o tipo de inicialização de uma série de serviços do Windows para "Manual", "Automatic", "AutomaticDelayedStart" ou "Disabled", conforme necessário. Esses ajustes são considerados inofensivos, pois os serviços podem iniciar sob demanda se forem necessários. A função também permite reverter as alterações para os valores originais.

  .PARAMETER Action
  Especifica se a ação é 'Set' (aplicar as alterações) ou 'Revert' (reverter para os valores originais). Por padrão, é 'Set'.

  .EXAMPLE
  Invoke-WPFTweaksServices -Action Set
  Ajusta os serviços para os tipos de inicialização especificados (ex.: Manual, Disabled, etc.).

  .EXAMPLE
  Invoke-WPFTweaksServices -Action Revert
  Reverte os serviços para seus tipos de inicialização originais.

  .NOTES
  Categoria: Essential Tweaks
  Ordem: a014_
  Link: https://christitustech.github.io/winutil/dev/tweaks/Essential-Tweaks/Services
  #>

  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $false)]
    [ValidateSet('Set', 'Revert')]
    [string]$Action = 'Set'
  )

  # Definir configurações dos serviços
  $serviceSettings = @(
    @{ Name = "AJRouter"; StartupType = "Disabled"; OriginalType = "Manual" },
    @{ Name = "ALG"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "AppIDSvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "AppMgmt"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "AppReadiness"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "AppVClient"; StartupType = "Disabled"; OriginalType = "Disabled" },
    @{ Name = "AppXSvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "Appinfo"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "AssignedAccessManagerSvc"; StartupType = "Disabled"; OriginalType = "Manual" },
    @{ Name = "AudioEndpointBuilder"; StartupType = "Automatic"; OriginalType = "Automatic" },
    @{ Name = "AudioSrv"; StartupType = "Automatic"; OriginalType = "Automatic" },
    @{ Name = "Audiosrv"; StartupType = "Automatic"; OriginalType = "Automatic" },
    @{ Name = "AxInstSV"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "BDESVC"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "BFE"; StartupType = "Automatic"; OriginalType = "Automatic" },
    @{ Name = "BITS"; StartupType = "AutomaticDelayedStart"; OriginalType = "Automatic" },
    @{ Name = "BTAGService"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "BcastDVRUserService_*"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "BluetoothUserService_*"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "BrokerInfrastructure"; StartupType = "Automatic"; OriginalType = "Automatic" },
    @{ Name = "Browser"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "BthAvctpSvc"; StartupType = "Automatic"; OriginalType = "Automatic" },
    @{ Name = "BthHFSrv"; StartupType = "Automatic"; OriginalType = "Automatic" },
    @{ Name = "CDPSvc"; StartupType = "Manual"; OriginalType = "Automatic" },
    @{ Name = "CDPUserSvc_*"; StartupType = "Automatic"; OriginalType = "Automatic" },
    @{ Name = "COMSysApp"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "CaptureService_*"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "CertPropSvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "ClipSVC"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "ConsentUxUserSvc_*"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "CoreMessagingRegistrar"; StartupType = "Automatic"; OriginalType = "Automatic" },
    @{ Name = "CredentialEnrollmentManagerUserSvc_*"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "CryptSvc"; StartupType = "Automatic"; OriginalType = "Automatic" },
    @{ Name = "CscService"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "DPS"; StartupType = "Automatic"; OriginalType = "Automatic" },
    @{ Name = "DcomLaunch"; StartupType = "Automatic"; OriginalType = "Automatic" },
    @{ Name = "DcpSvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "DevQueryBroker"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "DeviceAssociationBrokerSvc_*"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "DeviceAssociationService"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "DeviceInstall"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "DevicePickerUserSvc_*"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "DevicesFlowUserSvc_*"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "Dhcp"; StartupType = "Automatic"; OriginalType = "Automatic" },
    @{ Name = "DiagTrack"; StartupType = "Disabled"; OriginalType = "Automatic" },
    @{ Name = "DialogBlockingService"; StartupType = "Disabled"; OriginalType = "Disabled" },
    @{ Name = "DispBrokerDesktopSvc"; StartupType = "Automatic"; OriginalType = "Automatic" },
    @{ Name = "DisplayEnhancementService"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "DmEnrollmentSvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "Dnscache"; StartupType = "Automatic"; OriginalType = "Automatic" },
    @{ Name = "EFS"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "EapHost"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "EntAppSvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "EventLog"; StartupType = "Automatic"; OriginalType = "Automatic" },
    @{ Name = "EventSystem"; StartupType = "Automatic"; OriginalType = "Automatic" },
    @{ Name = "FDResPub"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "Fax"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "FontCache"; StartupType = "Automatic"; OriginalType = "Automatic" },
    @{ Name = "FrameServer"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "FrameServerMonitor"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "GraphicsPerfSvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "HomeGroupListener"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "HomeGroupProvider"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "HvHost"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "IEEtwCollectorService"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "IKEEXT"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "InstallService"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "InventorySvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "IpxlatCfgSvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "KeyIso"; StartupType = "Automatic"; OriginalType = "Automatic" },
    @{ Name = "KtmRm"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "LSM"; StartupType = "Automatic"; OriginalType = "Automatic" },
    @{ Name = "LanmanServer"; StartupType = "Automatic"; OriginalType = "Automatic" },
    @{ Name = "LanmanWorkstation"; StartupType = "Automatic"; OriginalType = "Automatic" },
    @{ Name = "LicenseManager"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "LxpSvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "MSDTC"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "MSiSCSI"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "MapsBroker"; StartupType = "AutomaticDelayedStart"; OriginalType = "Automatic" },
    @{ Name = "McpManagementService"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "MessagingService_*"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "MicrosoftEdgeElevationService"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "MixedRealityOpenXRSvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "MpsSvc"; StartupType = "Automatic"; OriginalType = "Automatic" },
    @{ Name = "MsKeyboardFilter"; StartupType = "Manual"; OriginalType = "Disabled" },
    @{ Name = "NPSMSvc_*"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "NaturalAuthentication"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "NcaSvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "NcbService"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "NcdAutoSetup"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "NetSetupSvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "NetTcpPortSharing"; StartupType = "Disabled"; OriginalType = "Disabled" },
    @{ Name = "Netlogon"; StartupType = "Automatic"; OriginalType = "Automatic" },
    @{ Name = "Netman"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "NgcCtnrSvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "NgcSvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "NlaSvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "OneSyncSvc_*"; StartupType = "Automatic"; OriginalType = "Automatic" },
    @{ Name = "P9RdrService_*"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "PNRPAutoReg"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "PNRPsvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "PcaSvc"; StartupType = "Manual"; OriginalType = "Automatic" },
    @{ Name = "PeerDistSvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "PenService_*"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "PerfHost"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "PhoneSvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "PimIndexMaintenanceSvc_*"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "PlugPlay"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "PolicyAgent"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "Power"; StartupType = "Automatic"; OriginalType = "Automatic" },
    @{ Name = "PrintNotify"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "PrintWorkflowUserSvc_*"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "ProfSvc"; StartupType = "Automatic"; OriginalType = "Automatic" },
    @{ Name = "PushToInstall"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "QWAVE"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "RasAuto"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "RasMan"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "RemoteAccess"; StartupType = "Disabled"; OriginalType = "Disabled" },
    @{ Name = "RemoteRegistry"; StartupType = "Disabled"; OriginalType = "Disabled" },
    @{ Name = "RetailDemo"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "RmSvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "RpcEptMapper"; StartupType = "Automatic"; OriginalType = "Automatic" },
    @{ Name = "RpcLocator"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "RpcSs"; StartupType = "Automatic"; OriginalType = "Automatic" },
    @{ Name = "SCPolicySvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "SCardSvr"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "SDRSVC"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "SEMgrSvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "SENS"; StartupType = "Automatic"; OriginalType = "Automatic" },
    @{ Name = "SNMPTRAP"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "SNMPTrap"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "SSDPSRV"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "SamSs"; StartupType = "Automatic"; OriginalType = "Automatic" },
    @{ Name = "ScDeviceEnum"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "Schedule"; StartupType = "Automatic"; OriginalType = "Automatic" },
    @{ Name = "SecurityHealthService"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "Sense"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "SensorDataService"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "SensorService"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "SensrSvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "SessionEnv"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "SharedAccess"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "SharedRealitySvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "ShellHWDetection"; StartupType = "Automatic"; OriginalType = "Automatic" },
    @{ Name = "SmsRouter"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "Spooler"; StartupType = "Automatic"; OriginalType = "Automatic" },
    @{ Name = "SstpSvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "StiSvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "StorSvc"; StartupType = "Manual"; OriginalType = "Automatic" },
    @{ Name = "SysMain"; StartupType = "Automatic"; OriginalType = "Automatic" },
    @{ Name = "SystemEventsBroker"; StartupType = "Automatic"; OriginalType = "Automatic" },
    @{ Name = "TabletInputService"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "TapiSrv"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "TermService"; StartupType = "Automatic"; OriginalType = "Automatic" },
    @{ Name = "Themes"; StartupType = "Automatic"; OriginalType = "Automatic" },
    @{ Name = "TieringEngineService"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "TimeBroker"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "TimeBrokerSvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "TokenBroker"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "TrkWks"; StartupType = "Automatic"; OriginalType = "Automatic" },
    @{ Name = "TroubleshootingSvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "TrustedInstaller"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "UI0Detect"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "UdkUserSvc_*"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "UevAgentService"; StartupType = "Disabled"; OriginalType = "Disabled" },
    @{ Name = "UmRdpService"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "UnistoreSvc_*"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "UserDataSvc_*"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "UserManager"; StartupType = "Automatic"; OriginalType = "Automatic" },
    @{ Name = "UsoSvc"; StartupType = "Manual"; OriginalType = "Automatic" },
    @{ Name = "VGAuthService"; StartupType = "Automatic"; OriginalType = "Automatic" },
    @{ Name = "VMTools"; StartupType = "Automatic"; OriginalType = "Automatic" },
    @{ Name = "VSS"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "VacSvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "VaultSvc"; StartupType = "Automatic"; OriginalType = "Automatic" },
    @{ Name = "W32Time"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "WEPHOSTSVC"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "WFDSConMgrSvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "WMPNetworkSvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "WManSvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "WPDBusEnum"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "WSService"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "WSearch"; StartupType = "AutomaticDelayedStart"; OriginalType = "Automatic" },
    @{ Name = "WaaSMedicSvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "WalletService"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "WarpJITSvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "WbioSrvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "Wcmsvc"; StartupType = "Automatic"; OriginalType = "Automatic" },
    @{ Name = "WcsPlugInService"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "WdNisSvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "WdiServiceHost"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "WdiSystemHost"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "WebClient"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "Wecsvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "WerSvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "WiaRpc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "WinDefend"; StartupType = "Automatic"; OriginalType = "Automatic" },
    @{ Name = "WinHttpAutoProxySvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "WinRM"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "Winmgmt"; StartupType = "Automatic"; OriginalType = "Automatic" },
    @{ Name = "WlanSvc"; StartupType = "Automatic"; OriginalType = "Automatic" },
    @{ Name = "WpcMonSvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "WpnService"; StartupType = "Manual"; OriginalType = "Automatic" },
    @{ Name = "WpnUserService_*"; StartupType = "Automatic"; OriginalType = "Automatic" },
    @{ Name = "XblAuthManager"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "XblGameSave"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "XboxGipSvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "XboxNetApiSvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "autotimesvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "bthserv"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "camsvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "cbdhsvc_*"; StartupType = "Manual"; OriginalType = "Automatic" },
    @{ Name = "cloudidsvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "dcsvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "defragsvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "diagnosticshub.standardcollector.service"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "diagsvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "dmwappushservice"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "dot3svc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "edgeupdate"; StartupType = "Manual"; OriginalType = "Automatic" },
    @{ Name = "edgeupdatem"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "embeddedmode"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "fdPHost"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "fhsvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "gpsvc"; StartupType = "Automatic"; OriginalType = "Automatic" },
    @{ Name = "hidserv"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "icssvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "iphlpsvc"; StartupType = "Automatic"; OriginalType = "Automatic" },
    @{ Name = "lfsvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "lltdsvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "lmhosts"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "mpssvc"; StartupType = "Automatic"; OriginalType = "Automatic" },
    @{ Name = "msiserver"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "netprofm"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "nsi"; StartupType = "Automatic"; OriginalType = "Automatic" },
    @{ Name = "p2pimsvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "p2psvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "perceptionsimulation"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "pla"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "seclogon"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "shpamsvc"; StartupType = "Disabled"; OriginalType = "Disabled" },
    @{ Name = "smphost"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "spectrum"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "sppsvc"; StartupType = "AutomaticDelayedStart"; OriginalType = "Automatic" },
    @{ Name = "ssh-agent"; StartupType = "Disabled"; OriginalType = "Disabled" },
    @{ Name = "svsvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "swprv"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "tiledatamodelsvc"; StartupType = "Automatic"; OriginalType = "Automatic" },
    @{ Name = "tzautoupdate"; StartupType = "Disabled"; OriginalType = "Disabled" },
    @{ Name = "uhssvc"; StartupType = "Disabled"; OriginalType = "Disabled" },
    @{ Name = "upnphost"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "vds"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "vm3dservice"; StartupType = "Manual"; OriginalType = "Automatic" },
    @{ Name = "vmicguestinterface"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "vmicheartbeat"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "vmickvpexchange"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "vmicrdv"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "vmicshutdown"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "vmictimesync"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "vmicvmsession"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "vmicvss"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "vmvss"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "wbengine"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "wcncsvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "webthreatdefsvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "webthreatdefusersvc_*"; StartupType = "Automatic"; OriginalType = "Automatic" },
    @{ Name = "wercplsupport"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "wisvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "wlidsvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "wlpasvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "wmiApSrv"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "workfolderssvc"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "wscsvc"; StartupType = "AutomaticDelayedStart"; OriginalType = "Automatic" },
    @{ Name = "wuauserv"; StartupType = "Manual"; OriginalType = "Manual" },
    @{ Name = "wudfsvc"; StartupType = "Manual"; OriginalType = "Manual" }
  )

  try {
    # Verificar se o usuário tem permissões administrativas
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
      Write-Error "Esta função requer privilégios de administrador. Por favor, execute o PowerShell como administrador."
      return
    }

    # Processar cada serviço
    foreach ($service in $serviceSettings) {
      $serviceName = $service.Name
      $targetStartupType = if ($Action -eq 'Set') { $service.StartupType } else { $service.OriginalType }

      # Verificar se o serviço existe
      if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
        # Ajustar o tipo de inicialização
        Set-Service -Name $serviceName -StartupType $targetStartupType -ErrorAction Stop
        Write-Host "Serviço '$serviceName' ajustado para '$targetStartupType'"
      }
      else {
        Write-Warning "Serviço '$serviceName' não encontrado. Pulando..."
      }
    }

    if ($Action -eq 'Set') {
      Write-Host "Serviços ajustados para os tipos de inicialização especificados com sucesso."
    }
    else {
      Write-Host "Serviços revertidos para seus tipos de inicialização originais com sucesso."
    }
  }
  catch {
    Write-Error "Ocorreu um erro ao $($Action.ToLower()) os serviços: $_"
  }
}


function RemoveBloatRegistry {
  Log-Action -Message "Iniciando função RemoveBloatRegistry para remover entradas de registro de bloatware." -ConsoleOutput

  try {
    
    Log-Action -Message "Removendo entradas de registro de bloatware..." -ConsoleOutput

    $keys = @(
      "HKCR:\Applications\photoviewer.dll",
      "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}"
    )
    Log-Action -Message "Lista de chaves de registro carregada: $($keys -join ', ')" -ConsoleOutput

    foreach ($key in $keys) {
      Log-Action -Message "Verificando e removendo a chave de registro $key..." -ConsoleOutput

      if (Test-Path $key) {
        Log-Action -Message "Caminho $key encontrado. Removendo..." -ConsoleOutput
        Remove-Item -Path $key -Recurse -Force -ErrorAction Stop
        Log-Action -Message "Chave $key removida com sucesso." -Level "INFO" -ConsoleOutput
      }
      else {
        Log-Action -Message "Caminho $key não encontrado. Nenhuma ação necessária." -Level "WARNING" -ConsoleOutput
      }
    }

    Log-Action -Message "Entradas de registro de bloatware processadas com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função RemoveBloatRegistry: $_"
    Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
    
    throw  # Repropaga o erro
  }
  finally {
    Log-Action -Message "Finalizando função RemoveBloatRegistry." -Level "INFO" -ConsoleOutput
  }
}

function UninstallMsftBloat {
  Log-Action -Message "Iniciando função UninstallMsftBloat para desinstalar bloatware adicional da Microsoft." -ConsoleOutput

  try {
    
    Log-Action -Message "Desinstalando bloatware adicional da Microsoft..." -ConsoleOutput

    $bloatware = @(
      "Microsoft.Windows.Photos",
      "Microsoft.MicrosoftEdge.Stable",
      "Microsoft.WindowsStore"
    )
    Log-Action -Message "Lista de bloatware carregada: $($bloatware -join ', ')" -ConsoleOutput

    foreach ($app in $bloatware) {
      Log-Action -Message "Removendo o aplicativo $app para todos os usuários..." -ConsoleOutput
      Get-AppxPackage -Name $app -AllUsers -ErrorAction Stop | Remove-AppxPackage -ErrorAction Stop
      Log-Action -Message "Aplicativo $app removido com sucesso para todos os usuários." -Level "INFO" -ConsoleOutput

      Log-Action -Message "Removendo o pacote provisionado $app..." -ConsoleOutput
      Get-AppxProvisionedPackage -Online -ErrorAction Stop | Where-Object DisplayName -eq $app | Remove-AppxProvisionedPackage -Online -ErrorAction Stop
      Log-Action -Message "Pacote provisionado $app removido com sucesso." -Level "INFO" -ConsoleOutput
    }

    Log-Action -Message "Bloatware adicional da Microsoft desinstalado com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função UninstallMsftBloat: $_"
    Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
    
    throw  # Repropaga o erro
  }
  finally {
    Log-Action -Message "Finalizando função UninstallMsftBloat." -Level "INFO" -ConsoleOutput
  }
}


function EnableUltimatePower {
  Log-Action -Message "Iniciando função EnableUltimatePower para habilitar o plano de energia Ultimate Performance." -ConsoleOutput
  
  powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61
  powercfg -setactive e9a42b02-d5df-448d-aa00-03f14749eb61
}

function CreateRestorePoint {
  Log-Action -Message "Iniciando função CreateRestorePoint para criar um ponto de restauração do sistema." -ConsoleOutput
  
  Checkpoint-Computer -Description "Before Windows Debloater Gaming Tweaks" -RestorePointType "MODIFY_SETTINGS" -ErrorAction SilentlyContinue
}


# Funções de Performance.
# Funções de Performance.
# Funções de Performance.


function Set-RamThreshold {
  Log-Action -Message "Iniciando função Set-RamThreshold para configurar o limite de RAM no registro." -ConsoleOutput

  try {
    $ramGB = [math]::Round((Get-WmiObject -Class Win32_ComputerSystem).TotalPhysicalMemory / 1GB)
    Log-Action -Message "Quantidade de RAM detectada: $ramGB GB" -ConsoleOutput

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
        Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
        
        return
      }
    }
    Log-Action -Message "Valor calculado para SvcHostSplitThresholdInKB: $value KB" -ConsoleOutput

    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control"
    $regName = "SvcHostSplitThresholdInKB"
    Log-Action -Message "Configurando $regName para $value em $regPath..." -ConsoleOutput
    Set-RegistryValue -Path $regPath -Name $regName -Value $value -Type DWord -ErrorAction Stop
    #Set-ItemProperty -Path $regPath -Name $regName -Value $value -Type DWord -ErrorAction Stop
    Log-Action -Message "Registro $regName atualizado com sucesso para $value KB." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro ao atualizar registro: $_"
    Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
    
    throw  # Repropaga o erro
  }
  finally {
    Log-Action -Message "Finalizando função Set-RamThreshold." -Level "INFO" -ConsoleOutput
  }
}

function Set-MemoriaVirtual-Registry {
  Log-Action "Iniciando função Set-MemoriaVirtual-Registry para configurar memória virtual." -Level "INFO" -ConsoleOutput

  try {
    # Definir o banner e opções para o menu
    $banner = @(
      "",
      "",
      "╔═══════════════════════════════════════╗",
      "╠════ Configurar Memória Virtual ══════╣",
      "╚═══════════════════════════════════════╝",
      "",
      "≫ Este menu permite configurar a memória virtual do sistema.",
      "≫ Ajustar manualmente pode otimizar o desempenho em jogos.",
      "",
      "≫ Pressione 'M' para definir manualmente a memória virtual.",
      "≫ Pressione 'A' para configurar automaticamente pelo Windows.",
      "≫ Pressione 'P' para pular esta configuração.",
      ""
    )

    # Opções válidas
    $options = @("M", "A", "P")

    # Chamar o menu e obter a escolha
    $selection = Show-Menu -BannerLines $banner -Options $options -Prompt "Digite sua escolha (M/A/P)" -ColorScheme "AmareloClaro"

    # Processar a escolha
    switch ($selection) {
      "M" {
        Log-Action "Opção escolhida: Definir memória virtual manualmente." -Level "INFO" -ConsoleOutput
      
        $ramGB = [math]::Round((Get-ComputerInfo).CsTotalPhysicalMemory / 1GB, 2)
        $initialSize = [math]::Round($ramGB * 1024 * 1.5)  # 1.5x RAM em MB
        $maxSize = [math]::Round($ramGB * 1024 * 3)        # 3x RAM em MB

        try {
          Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "PagingFiles" -Value "C:\pagefile.sys $initialSize $maxSize" -Type String -ErrorAction Stop
          #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "PagingFiles" -Value "C:\pagefile.sys $initialSize $maxSize" -ErrorAction Stop
          Log-Action "Memória virtual definida manualmente: Inicial=$initialSize MB, Máximo=$maxSize MB." -Level "INFO" -ConsoleOutput
      
        }
        catch {
          $errorMessage = "Erro ao definir memória virtual manualmente: $_"
          Log-Action $errorMessage -Level "ERROR" -ConsoleOutput
      
        }
      }
      "A" {
        Log-Action "Opção escolhida: Configurar memória virtual automaticamente." -Level "INFO" -ConsoleOutput
      

        try {
          Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "PagingFiles" -Value "" -Type String -ErrorAction Stop
          #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "PagingFiles" -Value "" -ErrorAction Stop
          Log-Action "Memória virtual configurada para gerenciamento automático pelo Windows." -Level "INFO" -ConsoleOutput
      
        }
        catch {
          $errorMessage = "Erro ao configurar memória virtual automaticamente: $_"
          Log-Action $errorMessage -Level "ERROR" -ConsoleOutput
      
        }
      }
      "P" {
        Log-Action "Configuração de memória virtual ignorada." -Level "WARNING" -ConsoleOutput
      
      }
    }
  }
  catch {
    $errorMessage = "Erro na função Set-MemoriaVirtual-Registry: $_"
    Log-Action $errorMessage -Level "ERROR" -ConsoleOutput
      
  }
  finally {
    Log-Action "Finalizando função Set-MemoriaVirtual-Registry." -Level "INFO" -ConsoleOutput
  }
}

## Download and extract ISLC
function DownloadAndExtractISLC {
  Log-Action -Message "Iniciando função DownloadAndExtractISLC para baixar e extrair o ISLC." -ConsoleOutput

  try {
    # Definir o link de download e o caminho do arquivo
    $downloadUrl = "https://raw.githubusercontent.com/wesscd/WindowsGaming/main/ISLC%20v1.0.3.4.exe"
    $downloadPath = "C:\ISLC_v1.0.3.4.exe"
    $extractPath = "C:\"
    $newFolderName = "ISLC"

    Log-Action -Message "Configurações definidas: URL=$downloadUrl, Caminho Download=$downloadPath, Caminho Extração=$extractPath, Nome Pasta=$newFolderName" -ConsoleOutput

    # Baixar o arquivo executável
    Log-Action -Message "Iniciando o download do arquivo de $downloadUrl para $downloadPath..." -ConsoleOutput
    Invoke-WebRequest -Uri $downloadUrl -OutFile $downloadPath -ErrorAction Stop
    Log-Action -Message "Arquivo baixado com sucesso para $downloadPath." -Level "INFO" -ConsoleOutput
    
    # Verificar se a pasta de extração existe, caso contrário, criar
    if (-Not (Test-Path -Path $extractPath)) {
      Log-Action -Message "Pasta de extração $extractPath não existe. Criando..." -ConsoleOutput
      New-Item -ItemType Directory -Path $extractPath -ErrorAction Stop
      Log-Action -Message "Pasta de extração $extractPath criada com sucesso." -Level "INFO" -ConsoleOutput
    }
    else {
      Log-Action -Message "Pasta de extração $extractPath já existe." -ConsoleOutput
    }

    # Caminho do 7z.exe
    $sevenZipPath = "C:\Program Files\7-Zip\7z.exe"  # Altere conforme o local do seu 7z.exe
    Log-Action -Message "Caminho do 7z.exe definido como: $sevenZipPath" -ConsoleOutput

    # Verificar se o 7z está instalado
    if (Test-Path -Path $sevenZipPath) {
      Log-Action -Message "7-Zip encontrado em $sevenZipPath. Extraindo o conteúdo..." -ConsoleOutput
      Write-Colored "Extraindo o conteúdo do arquivo usando 7-Zip..." "Verde"

      # Executar o 7-Zip e capturar saída e erro separadamente
      $process = Start-Process -FilePath $sevenZipPath -ArgumentList "x", "$downloadPath", "-o$extractPath", "-y" -NoNewWindow -Wait -PassThru
      $exitCode = $process.ExitCode

      if ($exitCode -ne 0) {
        Log-Action -Message "Erro ao extrair o arquivo com 7-Zip. Código de saída: $exitCode" -Level "ERROR" -ConsoleOutput
        throw "Erro ao extrair o arquivo com 7-Zip. Código de saída: $exitCode"
      }

      Log-Action -Message "Arquivo extraído com sucesso para $extractPath." -Level "INFO" -ConsoleOutput
      
      # Renomear a pasta extraída para ISLC
      $extractedFolderPath = Join-Path -Path $extractPath -ChildPath "ISLC v1.0.3.4"
      if (Test-Path -Path $extractedFolderPath) {
        Log-Action -Message "Renomeando a pasta extraída de $extractedFolderPath para $newFolderName..." -ConsoleOutput
        Rename-Item -Path $extractedFolderPath -NewName $newFolderName -ErrorAction Stop
        Log-Action -Message "Pasta renomeada com sucesso para $newFolderName." -Level "INFO" -ConsoleOutput
      }
      else {
        Log-Action -Message "Pasta extraída $extractedFolderPath não encontrada. Verificando subpastas..." -Level "WARNING" -ConsoleOutput

        # Tentar encontrar a pasta extraída manualmente
        $foundFolder = Get-ChildItem -Path $extractPath -Directory | Where-Object { $_.Name -like "ISLC*" } | Select-Object -First 1
        if ($foundFolder) {
          Log-Action -Message "Pasta encontrada: $($foundFolder.FullName). Renomeando para $newFolderName..." -Level "INFO" -ConsoleOutput
          Rename-Item -Path $foundFolder.FullName -NewName $newFolderName -ErrorAction Stop
        }
        else {
          Log-Action -Message "Nenhuma pasta extraída encontrada em $extractPath." -Level "ERROR" -ConsoleOutput
          throw "Pasta extraída não encontrada após extração."
        }
      }
    }
    else {
      Log-Action -Message "7-Zip não encontrado em $sevenZipPath." -Level "WARNING" -ConsoleOutput
      throw "7-Zip não instalado ou não encontrado."
    }

    Log-Action -Message "Removendo o arquivo baixado $downloadPath..." -ConsoleOutput
    Remove-Item -Path $downloadPath -Force -ErrorAction Stop
    Log-Action -Message "Arquivo $downloadPath excluído com sucesso." -Level "INFO" -ConsoleOutput
    
    # Caminho completo do executável do programa
    $origem = "C:\ISLC\Intelligent standby list cleaner ISLC.exe"
    # Nome do atalho que será criado
    $atalhoNome = "Intelligent standby list cleaner ISLC.lnk"
    # Caminho para a pasta de Inicialização do usuário
    $destino = [System.IO.Path]::Combine($env:APPDATA, "Microsoft\Windows\Start Menu\Programs\Startup", $atalhoNome)
    Log-Action -Message "Configurando atalho: Origem=$origem, Destino=$destino" -ConsoleOutput

    # Criação do objeto Shell
    Log-Action -Message "Criando objeto Shell para criar o atalho..." -ConsoleOutput
    $shell = New-Object -ComObject WScript.Shell -ErrorAction Stop
    # Criação do atalho
    Log-Action -Message "Criando o atalho em $destino..." -ConsoleOutput
    $atalho = $shell.CreateShortcut($destino)
    $atalho.TargetPath = $origem
    $atalho.Save()
    Log-Action -Message "Atalho criado com sucesso em $destino." -Level "INFO" -ConsoleOutput
    
  }
  catch {
    $errorMessage = "Erro na função DownloadAndExtractISLC: $_"
    Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
    
    throw  # Repropaga o erro
  }
  finally {
    Log-Action -Message "Finalizando função DownloadAndExtractISLC." -Level "INFO" -ConsoleOutput
  }
}

# Update ISLC Config
function UpdateISLCConfig {
  Log-Action -Message "Iniciando função UpdateISLCConfig para atualizar o arquivo de configuração do ISLC." -ConsoleOutput

  try {
    # Caminho para o arquivo de configuração (ajuste conforme necessário)
    $configFilePath = "C:\ISLC\Intelligent standby list cleaner ISLC.exe.Config"
    Log-Action -Message "Caminho do arquivo de configuração definido como: $configFilePath" -ConsoleOutput

    # Verificar se o arquivo de configuração existe
    if (Test-Path -Path $configFilePath) {
      Log-Action -Message "Arquivo de configuração encontrado em $configFilePath. Iniciando atualização..." -ConsoleOutput
      
      # Carregar o conteúdo do arquivo XML
      Log-Action -Message "Carregando o conteúdo do arquivo XML de $configFilePath..." -ConsoleOutput
      [xml]$configXml = Get-Content -Path $configFilePath -Raw -ErrorAction Stop
      Log-Action -Message "Conteúdo XML carregado com sucesso." -Level "INFO" -ConsoleOutput

      # Obter a quantidade total de memória RAM do sistema (em MB)
      $totalMemory = (Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1MB
      $freeMemory = [math]::Round($totalMemory / 2)  # Calcular metade da memória
      Log-Action -Message "Memória total detectada: $totalMemory MB. Memória livre configurada como: $freeMemory MB" -ConsoleOutput

      # Alterar as configurações conforme solicitado
      Log-Action -Message "Atualizando configuração 'Free memory' para $freeMemory..." -ConsoleOutput
      $configXml.configuration.appSettings.add | Where-Object { $_.key -eq "Free memory" } | ForEach-Object { $_.value = "$freeMemory" }
      Log-Action -Message "'Free memory' atualizado com sucesso." -Level "INFO" -ConsoleOutput

      Log-Action -Message "Atualizando configuração 'Start minimized' para True..." -ConsoleOutput
      $configXml.configuration.appSettings.add | Where-Object { $_.key -eq "Start minimized" } | ForEach-Object { $_.value = "True" }
      Log-Action -Message "'Start minimized' atualizado com sucesso." -Level "INFO" -ConsoleOutput

      Log-Action -Message "Atualizando configuração 'Wanted timer' para 0.50..." -ConsoleOutput
      $configXml.configuration.appSettings.add | Where-Object { $_.key -eq "Wanted timer" } | ForEach-Object { $_.value = "0.50" }
      Log-Action -Message "'Wanted timer' atualizado com sucesso." -Level "INFO" -ConsoleOutput

      Log-Action -Message "Atualizando configuração 'Custom timer' para True..." -ConsoleOutput
      $configXml.configuration.appSettings.add | Where-Object { $_.key -eq "Custom timer" } | ForEach-Object { $_.value = "True" }
      Log-Action -Message "'Custom timer' atualizado com sucesso." -Level "INFO" -ConsoleOutput

      Log-Action -Message "Atualizando configuração 'TaskScheduler' para True..." -ConsoleOutput
      $configXml.configuration.appSettings.add | Where-Object { $_.key -eq "TaskScheduler" } | ForEach-Object { $_.value = "True" }
      Log-Action -Message "'TaskScheduler' atualizado com sucesso." -Level "INFO" -ConsoleOutput

      # Salvar as alterações de volta no arquivo XML
      Log-Action -Message "Salvando as alterações no arquivo $configFilePath..." -ConsoleOutput
      $configXml.Save($configFilePath)
      Log-Action -Message "Arquivo de configuração atualizado com sucesso." -Level "INFO" -ConsoleOutput
    }
    else {
      Log-Action -Message "Arquivo de configuração não encontrado em $configFilePath." -Level "WARNING" -ConsoleOutput
    }
  }
  catch {
    $errorMessage = "Erro ao atualizar o arquivo de configuração: $_"
    Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
    
    throw  # Repropaga o erro
  }
  finally {
    Log-Action -Message "Finalizando função UpdateISLCConfig." -Level "INFO" -ConsoleOutput
  }
}

function ApplyPCOptimizations {
  Log-Action -Message "Iniciando função ApplyPCOptimizations para aplicar otimizações no PC." -Level "INFO" -ConsoleOutput

  try {
    Log-Action -Message "Aplicando otimizações..." -Level "INFO" -ConsoleOutput
    
    $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"

    # Configurar otimizações usando Set-RegistryValue
    Set-RegistryValue -Path $registryPath -Name "SystemResponsiveness" -Value 0 -Type "DWord"
    Set-RegistryValue -Path $registryPath -Name "NetworkThrottlingIndex" -Value 10 -Type "DWord"
    Set-RegistryValue -Path $registryPath -Name "AlwaysOn" -Value 1 -Type "DWord"
    Set-RegistryValue -Path $registryPath -Name "LazyMode" -Value 1 -Type "DWord"
    Set-RegistryValue -Path $registryPath -Name "LazyModeTimeout" -Value 25000 -Type "DWord"

    Log-Action -Message "Otimizações aplicadas com sucesso." -Level "INFO" -ConsoleOutput
    Write-Colored "Otimizações aplicadas com sucesso." -Color "VerdeClaro"
  }
  catch {
    $errorMessage = "Erro ao aplicar otimizações: $_"
    Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
    Write-Colored $errorMessage -Color "VermelhoClaro"
    throw  # Repropaga o erro
  }
  finally {
    Log-Action -Message "Finalizando função ApplyPCOptimizations." -Level "INFO" -ConsoleOutput
  }
}

function MSIMode {
  Log-Action -Message "Iniciando função MSIMode para habilitar o modo MSI em GPUs compatíveis." -Level "INFO" -ConsoleOutput

  try {
    $errpref = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"
    Log-Action -Message "Alterando ErrorActionPreference para SilentlyContinue temporariamente." -Level "INFO" -ConsoleOutput

    # Usar Get-GPUType para obter informações da GPU, incluindo PNPDeviceID
    $gpus = Get-GPUType -IncludePNPIds
    if ($gpus.Type -eq "Nenhum" -or $gpus.Type -eq "Erro") {
      Log-Action -Message "Nenhuma placa de vídeo detectada ou erro na detecção. Pulando configuração do modo MSI." -Level "WARNING" -ConsoleOutput
      
      return
    }

    foreach ($gpu in $gpus) {
      $GPUID = $gpu.PNPIds
      if ([string]::IsNullOrWhiteSpace($GPUID)) {
        Log-Action -Message "ID de GPU inválido encontrado ($($gpu.Name)). Pulando..." -Level "WARNING" -ConsoleOutput
        continue
      }

      Log-Action -Message "Verificando descrição do dispositivo para GPUID: $GPUID..." -Level "INFO" -ConsoleOutput

      # Obter descrição do dispositivo a partir do registro
      $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\$GPUID"
      if (Test-Path $registryPath) {
        $CheckDeviceDes = Get-ItemProperty -Path $registryPath -ErrorAction Stop | Select-Object -ExpandProperty DeviceDesc
        Log-Action -Message "Descrição do dispositivo obtida: $CheckDeviceDes" -Level "INFO" -ConsoleOutput
      }
      else {
        Log-Action -Message "Caminho do registro $registryPath não encontrado para GPUID: $GPUID. Pulando..." -Level "WARNING" -ConsoleOutput
        continue
      }

      # Verificar se a GPU é compatível (NVIDIA GTX/RTX ou AMD)
      if ($gpu.Type -eq "NVIDIA" -or $gpu.Type -eq "AMD") {
        Log-Action -Message "Placa compatível ($($gpu.Type)) encontrada! Habilitando modo MSI para $($gpu.Name)..." -Level "INFO" -ConsoleOutput
        
        $msiRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\$GPUID\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties"

        # Usar Set-RegistryValue para configurar MSISupported
        Set-RegistryValue -Path $msiRegistryPath -Name "MSISupported" -Value 1 -Type "DWord" -Force

        Log-Action -Message "Modo MSI habilitado com sucesso para a GPU compatível ($GPUID)." -Level "INFO" -ConsoleOutput
      }
      else {
        Log-Action -Message "Placa $($gpu.Name) não é compatível (não é GTX/RTX/AMD). Pulando..." -Level "INFO" -ConsoleOutput
      }
    }
  }
  catch {
    $errorMessage = "Erro na função MSIMode: $_"
    Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
    Write-Colored $errorMessage -Color "VermelhoClaro"
    throw  # Repropaga o erro
  }
  finally {
    $ErrorActionPreference = $errpref
    Log-Action -Message "Restaurando ErrorActionPreference para $errpref." -Level "INFO" -ConsoleOutput
    Log-Action -Message "Finalizando função MSIMode." -Level "INFO" -ConsoleOutput
  }
}

function OptimizeGPUTweaks {
  [CmdletBinding()]
  Param ()

  Log-Action -Message "Iniciando otimizações de GPU..." -Level "INFO" -ConsoleOutput

  # Detectar GPU
  $gpu = Get-GPUType
  $isNvidia = $gpu.Type -eq "NVIDIA"
  $isAMD = $gpu.Type -eq "AMD"

  if (-not $isNvidia -and -not $isAMD) {
    Log-Action -Message "Nenhuma GPU NVIDIA ou AMD detectada. Pulando otimizações." -Level "WARNING" -ConsoleOutput
    return
  }

  # Tweaks comuns (NVIDIA e AMD)
  try {
    # Desativar telemetria genérica
    Stop-Service -Name "NvTelemetryContainer" -ErrorAction SilentlyContinue
    Set-Service -Name "NvTelemetryContainer" -StartupType Disabled -ErrorAction SilentlyContinue
    Log-Action -Message "Telemetria genérica desativada (se aplicável)." -Level "INFO" -ConsoleOutput

    # Priorizar desempenho no plano de energia
    powercfg -setactive SCHEME_MIN  # Máximo desempenho
    Log-Action -Message "Plano de energia ajustado para máximo desempenho." -Level "INFO" -ConsoleOutput
  }
  catch {
    Log-Action -Message "Erro ao aplicar tweaks comuns: $_" -Level "ERROR" -ConsoleOutput
  }

  # Tweaks específicos para NVIDIA
  if ($isNvidia) {
    Log-Action -Message "Aplicando otimizações para NVIDIA..." -Level "INFO" -ConsoleOutput
    Log-Action -Message "Iniciando função NvidiaTweaks para aplicar otimizações em GPUs NVIDIA GTX/RTX." -Level "INFO" -ConsoleOutput

    try {
      # Verificar se o script está rodando como administrador
      $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
      if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Log-Action -Message "Este script requer privilégios administrativos para acessar o registro e arquivos do sistema. Por favor, execute como administrador." -Level "ERROR" -ConsoleOutput
        
        return
      }
      Log-Action -Message "Script em execução com privilégios administrativos confirmados." -Level "INFO" -ConsoleOutput

      # Salvar a preferência de erro original
      $errpref = $ErrorActionPreference
      $ErrorActionPreference = "SilentlyContinue"
      Log-Action -Message "Alterando ErrorActionPreference para SilentlyContinue temporariamente." -ConsoleOutput

      # Identificar GPUs NVIDIA usando CIM/WMI
      Log-Action -Message "Obtendo informações de GPUs via CIM/WMI..." -ConsoleOutput
      $gpuInfo = Get-CimInstance -ClassName Win32_VideoController -ErrorAction Stop | Where-Object { $_.CurrentBitsPerPixel -and $_.AdapterDACType }
      $nvidiaGPUs = $gpuInfo | Where-Object { $_.Name -match "nvidia|gtx|rtx" -and $_.Status -eq "OK" }

      if (-not $nvidiaGPUs) {
        
        Log-Action -Message "Nenhuma GPU NVIDIA detectada via CIM/WMI. Verificando registro como fallback..." -Level "INFO" -ConsoleOutput
      }
      else {
        Log-Action -Message "GPUs NVIDIA detectadas via CIM/WMI: $($nvidiaGPUs.Name -join ', ')" -Level "INFO" -ConsoleOutput
      }

      # Aplicar otimizações de energia se NVIDIA for detectada via CIM/WMI
      if ($nvidiaGPUs) {
        
        Log-Action -Message "Placa NVIDIA GTX/RTX detectada! Aplicando otimizações de energia..." -ConsoleOutput

        $url_base = "https://raw.githubusercontent.com/wesscd/WindowsGaming/main/BaseProfile.nip"
        $url_nvidiaprofile = "https://raw.githubusercontent.com/wesscd/WindowsGaming/main/nvidiaProfileInspector.exe"
        $system32Path = "$Env:windir\system32"

        Log-Action -Message "Baixando BaseProfile.nip de $url_base para $system32Path\BaseProfile.nip..." -ConsoleOutput
        Invoke-WebRequest -Uri $url_base -OutFile "$system32Path\BaseProfile.nip" -ErrorAction Stop
        Log-Action -Message "BaseProfile.nip baixado com sucesso." -Level "INFO" -ConsoleOutput

        Log-Action -Message "Baixando nvidiaProfileInspector.exe de $url_nvidiaprofile para $system32Path\nvidiaProfileInspector.exe..." -ConsoleOutput
        Invoke-WebRequest -Uri $url_nvidiaprofile -OutFile "$system32Path\nvidiaProfileInspector.exe" -ErrorAction Stop
        Log-Action -Message "nvidiaProfileInspector.exe baixado com sucesso." -Level "INFO" -ConsoleOutput

        Log-Action -Message "Mudando diretório para $system32Path para executar o nvidiaProfileInspector..." -ConsoleOutput
        Push-Location
        Set-Location $system32Path
        Log-Action -Message "Executando nvidiaProfileInspector.exe com o perfil BaseProfile.nip..." -ConsoleOutput
        & "nvidiaProfileInspector.exe" /s -load "BaseProfile.nip" -ErrorAction Stop
        Log-Action -Message "Perfil BaseProfile.nip aplicado com sucesso pelo nvidiaProfileInspector." -Level "INFO" -ConsoleOutput
        Pop-Location
        Log-Action -Message "Diretório restaurado." -ConsoleOutput
      }

      # Buscar dinamicamente todas as subchaves de dispositivos de vídeo no registro
      $baseRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}"
      Log-Action -Message "Verificando entradas de registro em $baseRegPath..." -ConsoleOutput
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
          Log-Action -Message "Permissões ajustadas para $baseRegPath." -Level "INFO" -ConsoleOutput
          $regKey.Close()
        }
        $subKeys = Get-ChildItem -Path $baseRegPath -ErrorAction Stop | Where-Object { $_.PSChildName -match '^\d{4}$' }
      }
      catch {
        Log-Action -Message "Falha ao listar subchaves ou ajustar permissões em $baseRegPath $_" -Level "WARNING" -ConsoleOutput
        Log-Action -Message "Aviso: Não foi possível acessar o registro de dispositivos de vídeo. Continuando com base em CIM/WMI..." -Level "WARNING" -ConsoleOutput
        
      }

      $foundNvidia = $false
      if ($subKeys) {
        foreach ($key in $subKeys) {
          $regPath = $key.PSPath
          $driverDesc = (Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue).DriverDesc

          if ($driverDesc -and ($driverDesc -match "nvidia|gtx|rtx" -or ($nvidiaGPUs -and $nvidiaGPUs.Name -contains $driverDesc))) {
            $subKeyName = $key.PSChildName
            
            Log-Action -Message "Placa NVIDIA GTX/RTX detectada no caminho de registro $subKeyName (DriverDesc: $driverDesc)! Aplicando otimizações de latência..." -ConsoleOutput
            $foundNvidia = $true

            Log-Action -Message "Aplicando ajustes de latência no caminho $regPath..." -ConsoleOutput
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
              Set-RegistryValue -Path $defaultRegPath -Name $prop.Name -Value $prop.Value -Type "DWord"
            }

            Log-Action -Message "Otimizações de latência NVIDIA aplicadas com sucesso no caminho $subKeyName." -Level "INFO" -ConsoleOutput
          }
        }
      }

      # Se nenhuma GPU foi encontrada no registro, mas CIM/WMI detectou NVIDIA, tentar aplicar otimizações em uma chave padrão
      if (-not $foundNvidia -and $nvidiaGPUs) {
        Log-Action -Message "Nenhum registro acessível encontrado, mas GPU NVIDIA detectada via CIM/WMI. Tentando chave padrão..." -Level "INFO" -ConsoleOutput
        $defaultRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000"
        if (Test-Path $defaultRegPath) {
          
          Log-Action -Message "Aplicando ajustes de latência no caminho padrão $defaultRegPath..." -ConsoleOutput

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
            Set-RegistryValue -Path $defaultRegPath -Name $prop.Name -Value $prop.Value -Type "DWord"
          }
          
          Log-Action -Message "Otimizações de latência NVIDIA aplicadas com sucesso no caminho padrão 0000." -Level "INFO" -ConsoleOutput
          $foundNvidia = $true
        }
      }

      if (-not $foundNvidia -and -not $nvidiaGPUs) {
        
        Log-Action -Message "Nenhuma entrada de registro NVIDIA GTX/RTX encontrada ou acessível! Pulando otimizações..." -Level "INFO" -ConsoleOutput
      }
    }
    catch {
      $errorMessage = "Erro na função NvidiaTweaks: $_"
      Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
      
      throw  # Repropaga o erro
    }
    finally {
      $ErrorActionPreference = $errpref
      Log-Action -Message "Restaurando ErrorActionPreference para $errpref." -ConsoleOutput
      Log-Action -Message "Finalizando função NvidiaTweaks." -Level "INFO" -ConsoleOutput
    }
  }

  # Tweaks específicos para AMD
  if ($isAMD) {
    Log-Action -Message "Aplicando otimizações para AMD..." -Level "INFO" -ConsoleOutput
    Log-Action -Message "Iniciando função AMDGPUTweaks para aplicar otimizações em GPUs AMD." -Level "INFO" -ConsoleOutput

    try {
      # Verificar se o script está rodando como administrador
      $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
      if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Log-Action -Message "Este script requer privilégios administrativos para acessar o registro. Por favor, execute como administrador." -Level "ERROR" -ConsoleOutput
        
        return
      }
      Log-Action -Message "Script em execução com privilégios administrativos confirmados." -Level "INFO" -ConsoleOutput

      # Salvar a preferência de erro original
      $errpref = $ErrorActionPreference
      $ErrorActionPreference = "SilentlyContinue"
      Log-Action -Message "Alterando ErrorActionPreference para SilentlyContinue temporariamente." -ConsoleOutput

      # Identificar GPUs AMD usando CIM/WMI
      Log-Action -Message "Obtendo informações de GPUs via CIM/WMI..." -ConsoleOutput
      $gpuInfo = Get-CimInstance -ClassName Win32_VideoController -ErrorAction Stop | Where-Object { $_.CurrentBitsPerPixel -and $_.AdapterDACType }
      $amdGPUs = $gpuInfo | Where-Object { $_.Name -match "amd|radeon|rx|vega" -and $_.Status -eq "OK" }

      if (-not $amdGPUs) {
        
        Log-Action -Message "Nenhuma GPU AMD detectada via CIM/WMI. Verificando registro como fallback..." -Level "INFO" -ConsoleOutput
      }
      else {
        Log-Action -Message "GPUs AMD detectadas via CIM/WMI: $($amdGPUs.Name -join ', ')" -Level "INFO" -ConsoleOutput
      }

      # Buscar dinamicamente todas as subchaves de dispositivos de vídeo no registro
      $baseRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}"
      Log-Action -Message "Verificando entradas de registro em $baseRegPath..." -ConsoleOutput
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
          Log-Action -Message "Permissões ajustadas para $baseRegPath." -Level "INFO" -ConsoleOutput
          $regKey.Close()
        }
        $subKeys = Get-ChildItem -Path $baseRegPath -ErrorAction Stop | Where-Object { $_.PSChildName -match '^\d{4}$' }
      }
      catch {
        Log-Action -Message "Falha ao listar subchaves ou ajustar permissões em $baseRegPath $_" -Level "WARNING" -ConsoleOutput
        Log-Action -Message "Aviso: Não foi possível acessar o registro de dispositivos de vídeo. Continuando com base em CIM/WMI..." -Level "WARNING" -ConsoleOutput
        
      }

      $foundAMD = $false
      if ($subKeys) {
        foreach ($key in $subKeys) {
          $regPath = $key.PSPath
          $driverDesc = (Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue).DriverDesc

          if ($driverDesc -and ($driverDesc -match "amd|radeon|rx|vega" -or ($amdGPUs -and $amdGPUs.Name -contains $driverDesc))) {
            $subKeyName = $key.PSChildName
            
            Log-Action -Message "GPU AMD detectada no caminho de registro $subKeyName (DriverDesc: $driverDesc)! Aplicando otimizações de latência..." -ConsoleOutput
            $foundAMD = $true

            Log-Action -Message "Aplicando ajustes de latência no caminho $regPath..." -ConsoleOutput
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
              Set-RegistryValue -Path $regPath -Name $prop.Name -Value $prop.Value -Type "DWord"
            }

            Log-Action -Message "Otimizações de latência AMD aplicadas com sucesso no caminho $subKeyName." -Level "INFO" -ConsoleOutput
          }
        }
      }

      # Se nenhuma GPU foi encontrada no registro, mas CIM/WMI detectou AMD, tentar aplicar otimizações em uma chave padrão
      if (-not $foundAMD -and $amdGPUs) {
        Log-Action -Message "Nenhum registro acessível encontrado, mas GPU AMD detectada via CIM/WMI. Tentando chave padrão..." -Level "INFO" -ConsoleOutput
        $defaultRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000"
        if (Test-Path $defaultRegPath) {
          
          Log-Action -Message "Aplicando ajustes de latência no caminho padrão $defaultRegPath..." -ConsoleOutput
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
            Set-RegistryValue -Path $defaultRegPath -Name $prop.Name -Value $prop.Value -Type "DWord"
          }

          Log-Action -Message "Otimizações de latência AMD aplicadas com sucesso no caminho padrão 0000." -Level "INFO" -ConsoleOutput
          $foundAMD = $true
        }
      }

      if (-not $foundAMD) {
        
        Log-Action -Message "Nenhuma entrada de registro AMD GPU encontrada ou acessível! Pulando otimizações de latência..." -Level "INFO" -ConsoleOutput
      }
    }
    catch {
      $errorMessage = "Erro na função AMDGPUTweaks: $_"
      Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
      
      throw  # Repropaga o erro
    }
    finally {
      $ErrorActionPreference = $errpref
      Log-Action -Message "Restaurando ErrorActionPreference para $errpref." -ConsoleOutput
      Log-Action -Message "Finalizando função AMDGPUTweaks." -Level "INFO" -ConsoleOutput
    }
  }

  Log-Action -Message "Otimização de GPU concluída." -Level "INFO" -ConsoleOutput
}

function OptimizeNetwork {
  [CmdletBinding()]
  Param (
    [switch]$DisableNagle = $true,
    [switch]$EnableRSS = $true,
    [switch]$DisableLSO = $true
  )

  Log-Action -Message "Iniciando otimizações de rede..." -Level "INFO" -ConsoleOutput

  try {
    # Configurações globais de TCP/IP
    $tcpParams = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    Log-Action -Message "Ajustando parâmetros TCP/IP globais..." -Level "INFO" -ConsoleOutput
    Set-RegistryValue -Path $tcpParams -Name "MaxUserPort" -Value 65534 -Type "DWord"
    Set-RegistryValue -Path $tcpParams -Name "TcpTimedWaitDelay" -Value 30 -Type "DWord"
    Set-RegistryValue -Path $tcpParams -Name "DefaultTTL" -Value 64 -Type "DWord"
    Set-RegistryValue -Path $tcpParams -Name "TcpMaxDataRetransmissions" -Value 5 -Type "DWord"
    Set-RegistryValue -Path $tcpParams -Name "EnableTCPA" -Value 1 -Type "DWord"

    # Configurações globais via Netsh
    Log-Action -Message "Aplicando configurações globais via Netsh..." -Level "INFO" -ConsoleOutput
    netsh int tcp set global autotuninglevel=normal | Out-Null
    netsh int tcp set global congestionprovider=ctcp | Out-Null
    netsh int tcp set global rss=enabled | Out-Null
    netsh int tcp set global chimney=enabled | Out-Null
    netsh int tcp set global dca=enabled | Out-Null
    netsh int tcp set global ecncapability=disabled | Out-Null

    # Desativar Nagle por interface
    if ($DisableNagle) {
      Log-Action -Message "Desativando algoritmo de Nagle por interface..." -Level "INFO" -ConsoleOutput
      $interfaces = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" -ErrorAction SilentlyContinue
      foreach ($interface in $interfaces) {
        Set-RegistryValue -Path $interface.PSPath -Name "TcpAckFrequency" -Value 1 -Type "DWord"
        Set-RegistryValue -Path $interface.PSPath -Name "TCPNoDelay" -Value 1 -Type "DWord"
      }
    }

    # Configurar RSS por adaptador
    if ($EnableRSS) {
      Log-Action -Message "Configurando Receive Side Scaling (RSS) nos adaptadores..." -Level "INFO" -ConsoleOutput
      $adapters = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}" -ErrorAction SilentlyContinue
      foreach ($adapter in $adapters) {
        $desc = (Get-ItemProperty -Path $adapter.PSPath -ErrorAction SilentlyContinue).DriverDesc
        if ($desc -and $desc -notmatch "Virtual|WAN") {
          Set-RegistryValue -Path $adapter.PSPath -Name "*RSS" -Value 1 -Type "DWord"
          Set-RegistryValue -Path $adapter.PSPath -Name "*NumRssQueues" -Value 4 -Type "DWord"
          Set-RegistryValue -Path $adapter.PSPath -Name "*ReceiveBuffers" -Value 2048 -Type "DWord"
          Set-RegistryValue -Path $adapter.PSPath -Name "*TransmitBuffers" -Value 2048 -Type "DWord"
        }
      }
    }

    # Desativar LSO
    if ($DisableLSO) {
      Log-Action -Message "Desativando Large Send Offload (LSO)..." -Level "INFO" -ConsoleOutput
      try {
        Disable-NetAdapterLso -Name "*" -IPv4 -IPv6 -ErrorAction Stop
      }
      catch {
        Log-Action -Message "Erro ao desativar LSO: $_" -Level "WARNING" -ConsoleOutput
      }
    }

    # Propriedades avançadas dos adaptadores
    Log-Action -Message "Ajustando propriedades avançadas dos adaptadores..." -Level "INFO" -ConsoleOutput
    $properties = @("FlowControl", "Energy-Efficient Ethernet", "Green Ethernet", "Interrupt Moderation")
    foreach ($prop in $properties) {
      try {
        Set-NetAdapterAdvancedProperty -Name "*" -DisplayName $prop -DisplayValue "Disabled" -ErrorAction SilentlyContinue
      }
      catch {
        Log-Action -Message "Erro ao ajustar propriedade ${prop}: $_" -Level "WARNING" -ConsoleOutput
      }
    }

    Log-Action -Message "Otimização de rede concluída com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função OptimizeNetwork: $_"
    Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
    Write-Colored $errorMessage -Color "VermelhoClaro"
    throw  # Repropaga o erro
  }
}

function Finished {
  Log-Action -Message "Iniciando função Finished para finalizar o processo de otimização." -Level "INFO" -ConsoleOutput

  try {
    Log-Action -Message "Iniciando configurações finais de OEM e personalização do sistema." -Level "INFO" -ConsoleOutput

    # Baixar a imagem do logo
    $url_logo = "https://raw.githubusercontent.com/wesscd/WindowsGaming/main/logo.bmp"
    $destino_logo = "C:\Windows\oemlogo.bmp"
    Log-Action -Message "Baixando logo de $url_logo para $destino_logo..." -Level "INFO" -ConsoleOutput
    Invoke-WebRequest -Uri $url_logo -OutFile $destino_logo -ErrorAction Stop

    # Configurar permissões para pacotes MSI
    $msiPath = "HKCR:\Msi.Package\shell\runas"
    Set-RegistryValue -Path $msiPath -Name "HasLUAShield" -Value "" -Type "String" -Force
    Set-RegistryValue -Path "$msiPath\command" -Name "(Default)" -Value '"%SystemRoot%\System32\msiexec.exe" /i "%1" %*' -Type "ExpandString" -Force

    # Habilitar histórico da área de transferência
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowClipboardHistory" -Value 1 -Type "DWord" -Force

    # Configurar informações OEM
    $oemPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation"
    Set-RegistryValue -Path $oemPath -Name "Manufacturer" -Value "PC Otimizado por Cesar Marques (Barao)" -Type "String" -Force
    Set-RegistryValue -Path $oemPath -Name "Model" -Value "Otimizacao, Hardware, Infra & Redes" -Type "String" -Force
    Set-RegistryValue -Path $oemPath -Name "SupportURL" -Value "http://techremote.com.br" -Type "String" -Force
    Set-RegistryValue -Path $oemPath -Name "SupportHours" -Value "Seg-Sex: 08h-18h" -Type "String" -Force
    Set-RegistryValue -Path $oemPath -Name "SupportPhone" -Value "+55 16 99263-6487" -Type "String" -Force
    Set-RegistryValue -Path $oemPath -Name "Logo" -Value "C:\Windows\oemlogo.bmp" -Type "String" -Force

    # Pequena pausa
    Start-Sleep -Seconds 5
    Log-Action -Message "Pausa de 5 segundos concluída." -Level "INFO" -ConsoleOutput

    # Exibir mensagem final
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

    for ($i = 0; $i -lt $banner.Length; $i++) {
      $color = if ($i -lt 5) { "Amarelo" } elseif ($i -ge 6 -and $i -lt 16) { "AmareloClaro" } else { "Verde" }
      #Log-Action -Message $banner[$i] -Level "INFO" -ConsoleOutput
      Write-Colored -Text $banner[$i] -Color $color
    }
    [Console]::ReadKey($true) | Out-Null

    # Abrir URL no navegador
    Write-Colored -Text "Abrindo URL de suporte http://techremote.com.br no navegador..." -Color "AmareloClaro"
    #Log-Action -Message "Abrindo URL de suporte http://techremote.com.br no navegador..." -Level "INFO" -ConsoleOutput
    Start-Process "http://techremote.com.br" -ErrorAction Stop

    # Perguntar se deseja reiniciar
    $reinicioBanner = @(
      "",
      "",
      "╔════════════════════════════════════╗",
      "╠════ Confirmar Reinício ════════════╣",
      "╚════════════════════════════════════╝",
      "",
      "≫ Deseja reiniciar o computador agora?",
      ""
    )
    $options = @("S", "N")
    $reinicioSelection = Show-Menu -BannerLines $reinicioBanner -Options $options -Prompt "Deseja reiniciar agora? (S/N)" -ColorScheme "AmareloClaro"

    if ($reinicioSelection -eq "S") {
          
      Log-Action -Message "Usuário escolheu reiniciar. Reiniciando o computador..." -Level "INFO" -ConsoleOutput
      Restart-Computer -Force -ErrorAction Stop
    }
    else {
          
      Log-Action -Message "Usuário escolheu não reiniciar. Aguardando pressionamento de tecla para sair..." -Level "INFO" -ConsoleOutput
      [Console]::ReadKey($true) | Out-Null
    }
  }
  catch {
    $errorMessage = "Erro na função Finished: $_"
    Log-Action -Message $errorMessage -Level "ERROR" -ConsoleOutput
      
    throw
  }
  finally {
    Log-Action -Message "Finalizando função Finished." -Level "INFO" -ConsoleOutput
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
  Log-Action -Message "Iniciando execução do tweak: $tweakName (Passo $currentStep de $totalTweaks)" -Level "INFO" -ConsoleOutput
  Show-ProgressBar -CurrentStep $currentStep -TotalSteps $totalTweaks -TaskName $tweakName

  if ($tweakFunctions.ContainsKey($tweakName)) {
    try {
      Invoke-Expression $tweak
      Log-Action -Message "Tweak $tweakName concluído com sucesso." -Level "INFO" -ConsoleOutput
    }
    catch {
      Log-Action -Message "Erro ao executar o tweak $tweakName $_" -Level "ERROR" -ConsoleOutput
      
      continue
    }
  }
  else {
    Log-Action -Message "Tweak não encontrado: $tweak" -Level "WARNING" -ConsoleOutput
    
  }

  Start-Sleep -Milliseconds 100
}
