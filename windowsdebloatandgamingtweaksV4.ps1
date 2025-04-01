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

# Função SlowUpdatesTweaks definida diretamente

function SlowUpdatesTweaks {
  Write-Log "Iniciando função SlowUpdatesTweaks para melhorar o Windows Update e atrasar atualizações de recursos." -ConsoleOutput

  try {
    Write-Output "Improving Windows Update to delay Feature updates and only install Security Updates"
    Write-Log "Melhorando o Windows Update para atrasar atualizações de recursos e instalar apenas atualizações de segurança..." -ConsoleOutput

    Write-Log "Criando a chave HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate..." -ConsoleOutput
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Force -ErrorAction Stop | Out-Null
    Write-Log "Chave criada ou verificada com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Configurando DeferFeatureUpdates para 1..." -ConsoleOutput
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdates" -Type DWord -Value 1 -ErrorAction Stop
    Write-Log "DeferFeatureUpdates configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Configurando DeferQualityUpdates para 1..." -ConsoleOutput
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdates" -Type DWord -Value 1 -ErrorAction Stop
    Write-Log "DeferQualityUpdates configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Configurando DeferFeatureUpdatesPeriodInDays para 30..." -ConsoleOutput
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdatesPeriodInDays" -Type DWord -Value 30 -ErrorAction Stop
    Write-Log "DeferFeatureUpdatesPeriodInDays configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Configurando DeferQualityUpdatesPeriodInDays para 4..." -ConsoleOutput
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdatesPeriodInDays" -Type DWord -Value 4 -ErrorAction Stop
    Write-Log "DeferQualityUpdatesPeriodInDays configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Configurando PauseFeatureUpdatesStartTime para vazio..." -ConsoleOutput
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "PauseFeatureUpdatesStartTime" -Type String -Value "" -ErrorAction Stop
    Write-Log "PauseFeatureUpdatesStartTime configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Configurando PauseQualityUpdatesStartTime para vazio..." -ConsoleOutput
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "PauseQualityUpdatesStartTime" -Type String -Value "" -ErrorAction Stop
    Write-Log "PauseQualityUpdatesStartTime configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Configurando ActiveHoursEnd para 2..." -ConsoleOutput
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "ActiveHoursEnd" -Type DWord -Value 2 -ErrorAction Stop
    Write-Log "ActiveHoursEnd configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Configurando ActiveHoursStart para 8..." -ConsoleOutput
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "ActiveHoursStart" -Type DWord -Value 8 -ErrorAction Stop
    Write-Log "ActiveHoursStart configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Ajustes de atualização aplicados com sucesso." -Level "INFO" -ConsoleOutput
    Write-Colored "Ajustes de atualização aplicados com sucesso." -Color "Green"
  }
  catch {
    $errorMessage = "Erro ao aplicar ajustes de atualização: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    Write-Colored $errorMessage -Color "Red"
    throw  # Repropaga o erro
  }
  finally {
    Write-Log "Finalizando função SlowUpdatesTweaks." -Level "INFO" -ConsoleOutput
  }
}

function ManagePowerProfiles {
  Write-Log "Iniciando função ManagePowerProfiles para gerenciar perfis de energia." -ConsoleOutput

  try {
    Write-Output "Gerenciando Perfis de Energia..."
    do {
      Clear-Host
      Write-Colored "" "Azul"
      Write-Colored "================ Gerenciar Perfis de Energia ================" "Azul"
      Write-Colored "Escolha uma opção para configurar o perfil de energia:" "Branco"
      Write-Colored "1 - Perfil de Alto Desempenho (ideal para jogos)" "VerdeClaro"
      Write-Colored "2 - Perfil Balanceado (padrão do Windows)" "AmareloClaro"
      Write-Colored "3 - Perfil Econômico (economia de energia)" "CianoClaro"
      Write-Colored "4 - Pular esta etapa" "VermelhoClaro"
      $choice = Read-Host "Digite sua escolha (1-4)"
      Write-Log "Usuário selecionou: $choice" -ConsoleOutput
    } until ($choice -match "^[1-4]$")

    switch ($choice) {
      "1" {
        Write-Log "Aplicando perfil de Alto Desempenho..." -ConsoleOutput
        Write-Colored "Configurando perfil de Alto Desempenho..." -Color "VerdeClaro"
        # Criar ou ativar o plano de alto desempenho
        powercfg /duplicatescheme 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
        powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
        # Ajustes adicionais para desempenho máximo
        powercfg /change standby-timeout-ac 0
        powercfg /change hibernate-timeout-ac 0
        powercfg /change monitor-timeout-ac 0
        Write-Log "Perfil de Alto Desempenho aplicado com sucesso." -Level "INFO" -ConsoleOutput
        Write-Colored "Perfil de Alto Desempenho aplicado com sucesso!" -Color "Verde"
      }
      "2" {
        Write-Log "Aplicando perfil Balanceado..." -ConsoleOutput
        Write-Colored "Configurando perfil Balanceado..." -Color "AmareloClaro"
        powercfg /duplicatescheme 381b4222-f694-41f0-9685-ff5bb260df2e
        powercfg /setactive 381b4222-f694-41f0-9685-ff5bb260df2e
        Write-Log "Perfil Balanceado aplicado com sucesso." -Level "INFO" -ConsoleOutput
        Write-Colored "Perfil Balanceado aplicado com sucesso!" -Color "Amarelo"
      }
      "3" {
        Write-Log "Aplicando perfil Econômico..." -ConsoleOutput
        Write-Colored "Configurando perfil Econômico..." -Color "CianoClaro"
        powercfg /duplicatescheme a1841308-3541-4fab-bc81-f71556f20b4a
        powercfg /setactive a1841308-3541-4fab-bc81-f71556f20b4a
        powercfg /change standby-timeout-ac 10
        powercfg /change monitor-timeout-ac 5
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

function Show-ProgressBar {
  param (
    [int]$CurrentStep,
    [int]$TotalSteps,
    [string]$TaskName
  )

  $percentComplete = [math]::Round(($CurrentStep / $TotalSteps) * 100)
  $barLength = 50
  $filledLength = [math]::Round(($percentComplete / 100) * $barLength)
  $emptyLength = $barLength - $filledLength

  $filledBar = "█" * $filledLength
  $emptyBar = " " * $emptyLength
  $progressBar = "[$filledBar$emptyBar] $percentComplete%"

  Write-Host "`r" -NoNewline # Retorna ao início da linha
  Write-Colored "$progressBar - Executando: $TaskName" -Color "VerdeClaro" -NoNewline
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
    "                                                                                  V0.7.2.3.4",
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
  "Download-GPUFiles",
  "EnableUltimatePower",
  "ManagePowerProfiles",
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

function EnableUpdateMSRT {
  Write-Log "Iniciando função EnableUpdateMSRT para habilitar a oferta da Ferramenta de Remoção de Software Malicioso." -ConsoleOutput

  try {
    Write-Output "Enabling Malicious Software Removal Tool offering..."
    Write-Log "Habilitando a oferta da Ferramenta de Remoção de Software Malicioso..." -ConsoleOutput

    # Definir o caminho do registro
    $mrtPath = "HKLM:\SOFTWARE\Policies\Microsoft\MRT"

    # Verificar se o caminho existe
    Write-Log "Verificando se o caminho $mrtPath existe..." -ConsoleOutput
    if (-not (Test-Path $mrtPath)) {
      Write-Log "Caminho $mrtPath não encontrado. Nenhuma ação necessária ou caminho não aplicável." -Level "INFO" -ConsoleOutput
    }
    else {
      # Verificar se a propriedade DontOfferThroughWUAU existe
      Write-Log "Verificando se a propriedade DontOfferThroughWUAU existe no caminho $mrtPath..." -ConsoleOutput
      if (Get-ItemProperty -Path $mrtPath -Name "DontOfferThroughWUAU" -ErrorAction SilentlyContinue) {
        Write-Log "Removendo a propriedade DontOfferThroughWUAU do registro..." -ConsoleOutput
        Remove-ItemProperty -Path $mrtPath -Name "DontOfferThroughWUAU" -ErrorAction Stop
        Write-Log "Propriedade DontOfferThroughWUAU removida com sucesso." -Level "INFO" -ConsoleOutput
      }
      else {
        Write-Log "Propriedade DontOfferThroughWUAU não encontrada no caminho $mrtPath. Nenhuma ação necessária." -Level "INFO" -ConsoleOutput
      }
    }

    Write-Log "Oferta da Ferramenta de Remoção de Software Malicioso habilitada com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função EnableUpdateMSRT: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    throw  # Repropaga o erro
  }
  finally {
    Write-Log "Finalizando função EnableUpdateMSRT." -Level "INFO" -ConsoleOutput
  }
}

function EnableUpdateDriver {
  Write-Log "Iniciando função EnableUpdateDriver para habilitar a oferta de drivers pelo Windows Update." -ConsoleOutput

  try {
    Write-Output "Enabling driver offering through Windows Update..."
    Write-Log "Habilitando a oferta de drivers pelo Windows Update..." -ConsoleOutput

    # Definir os caminhos dos registros
    $deviceMetadataPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata"
    $driverSearchingPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching"
    $windowsUpdatePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"

    # Remover PreventDeviceMetadataFromNetwork
    Write-Log "Removendo PreventDeviceMetadataFromNetwork do registro..." -ConsoleOutput
    if (Test-Path $deviceMetadataPath) {
      if (Get-ItemProperty -Path $deviceMetadataPath -Name "PreventDeviceMetadataFromNetwork" -ErrorAction SilentlyContinue) {
        Remove-ItemProperty -Path $deviceMetadataPath -Name "PreventDeviceMetadataFromNetwork" -ErrorAction Stop
        Write-Log "PreventDeviceMetadataFromNetwork removido com sucesso." -Level "INFO" -ConsoleOutput
      }
      else {
        Write-Log "Propriedade PreventDeviceMetadataFromNetwork não encontrada no caminho $deviceMetadataPath. Nenhuma ação necessária." -Level "INFO" -ConsoleOutput
      }
    }
    else {
      Write-Log "Caminho $deviceMetadataPath não encontrado. Nenhuma ação necessária." -Level "INFO" -ConsoleOutput
    }

    # Remover DontPromptForWindowsUpdate
    Write-Log "Removendo DontPromptForWindowsUpdate do registro..." -ConsoleOutput
    if (Test-Path $driverSearchingPath) {
      if (Get-ItemProperty -Path $driverSearchingPath -Name "DontPromptForWindowsUpdate" -ErrorAction SilentlyContinue) {
        Remove-ItemProperty -Path $driverSearchingPath -Name "DontPromptForWindowsUpdate" -ErrorAction Stop
        Write-Log "DontPromptForWindowsUpdate removido com sucesso." -Level "INFO" -ConsoleOutput
      }
      else {
        Write-Log "Propriedade DontPromptForWindowsUpdate não encontrada no caminho $driverSearchingPath. Nenhuma ação necessária." -Level "INFO" -ConsoleOutput
      }
    }
    else {
      Write-Log "Caminho $driverSearchingPath não encontrado. Nenhuma ação necessária." -Level "INFO" -ConsoleOutput
    }

    # Remover DontSearchWindowsUpdate
    Write-Log "Removendo DontSearchWindowsUpdate do registro..." -ConsoleOutput
    if (Test-Path $driverSearchingPath) {
      if (Get-ItemProperty -Path $driverSearchingPath -Name "DontSearchWindowsUpdate" -ErrorAction SilentlyContinue) {
        Remove-ItemProperty -Path $driverSearchingPath -Name "DontSearchWindowsUpdate" -ErrorAction Stop
        Write-Log "DontSearchWindowsUpdate removido com sucesso." -Level "INFO" -ConsoleOutput
      }
      else {
        Write-Log "Propriedade DontSearchWindowsUpdate não encontrada no caminho $driverSearchingPath. Nenhuma ação necessária." -Level "INFO" -ConsoleOutput
      }
    }

    # Remover DriverUpdateWizardWuSearchEnabled
    Write-Log "Removendo DriverUpdateWizardWuSearchEnabled do registro..." -ConsoleOutput
    if (Test-Path $driverSearchingPath) {
      if (Get-ItemProperty -Path $driverSearchingPath -Name "DriverUpdateWizardWuSearchEnabled" -ErrorAction SilentlyContinue) {
        Remove-ItemProperty -Path $driverSearchingPath -Name "DriverUpdateWizardWuSearchEnabled" -ErrorAction Stop
        Write-Log "DriverUpdateWizardWuSearchEnabled removido com sucesso." -Level "INFO" -ConsoleOutput
      }
      else {
        Write-Log "Propriedade DriverUpdateWizardWuSearchEnabled não encontrada no caminho $driverSearchingPath. Nenhuma ação necessária." -Level "INFO" -ConsoleOutput
      }
    }

    # Remover ExcludeWUDriversInQualityUpdate
    Write-Log "Removendo ExcludeWUDriversInQualityUpdate do registro..." -ConsoleOutput
    if (Test-Path $windowsUpdatePath) {
      if (Get-ItemProperty -Path $windowsUpdatePath -Name "ExcludeWUDriversInQualityUpdate" -ErrorAction SilentlyContinue) {
        Remove-ItemProperty -Path $windowsUpdatePath -Name "ExcludeWUDriversInQualityUpdate" -ErrorAction Stop
        Write-Log "ExcludeWUDriversInQualityUpdate removido com sucesso." -Level "INFO" -ConsoleOutput
      }
      else {
        Write-Log "Propriedade ExcludeWUDriversInQualityUpdate não encontrada no caminho $windowsUpdatePath. Nenhuma ação necessária." -Level "INFO" -ConsoleOutput
      }
    }
    else {
      Write-Log "Caminho $windowsUpdatePath não encontrado. Nenhuma ação necessária." -Level "INFO" -ConsoleOutput
    }

    Write-Log "Oferta de drivers pelo Windows Update habilitada com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função EnableUpdateDriver: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    throw  # Repropaga o erro
  }
  finally {
    Write-Log "Finalizando função EnableUpdateDriver." -Level "INFO" -ConsoleOutput
  }
}

function DisableUpdateRestart {
  Write-Log "Iniciando função DisableUpdateRestart para desativar a reinicialização automática do Windows Update." -ConsoleOutput

  try {
    Write-Output "Disabling Windows Update automatic restart..."
    Write-Log "Desativando a reinicialização automática do Windows Update..." -ConsoleOutput

    # Definir o caminho do registro
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"

    # Verificar e criar a chave de registro, se necessário
    if (-not (Test-Path $registryPath)) {
      Write-Log "Chave $registryPath não existe. Criando..." -ConsoleOutput
      New-Item -Path $registryPath -Force -ErrorAction Stop | Out-Null
      Write-Log "Chave $registryPath criada com sucesso." -Level "INFO" -ConsoleOutput
    }
    else {
      Write-Log "Chave $registryPath já existe. Prosseguindo com a configuração." -ConsoleOutput
    }

    # Configurar NoAutoRebootWithLoggedOnUsers
    Write-Log "Configurando NoAutoRebootWithLoggedOnUsers para 1 em $registryPath..." -ConsoleOutput
    Set-ItemProperty -Path $registryPath -Name "NoAutoRebootWithLoggedOnUsers" -Type DWord -Value 1 -ErrorAction Stop
    Write-Log "NoAutoRebootWithLoggedOnUsers configurado com sucesso." -Level "INFO" -ConsoleOutput

    # Configurar AUPowerManagement
    Write-Log "Configurando AUPowerManagement para 0 em $registryPath..." -ConsoleOutput
    Set-ItemProperty -Path $registryPath -Name "AUPowerManagement" -Type DWord -Value 0 -ErrorAction Stop
    Write-Log "AUPowerManagement configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Reinicialização automática do Windows Update desativada com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função DisableUpdateRestart: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    throw  # Repropaga o erro
  }
  finally {
    Write-Log "Finalizando função DisableUpdateRestart." -Level "INFO" -ConsoleOutput
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

  Write-Log "Iniciando função Remove-OneDrive para desinstalar o OneDrive." -ConsoleOutput

  try {
    if ($AskUser) {
      do {
        Clear-Host
        Write-Log "Exibindo menu de opções para desinstalar o OneDrive." -ConsoleOutput
        Write-Colored "" "Azul"
        Write-Colored "================ Desinstalar o OneDrive? ================" "Azul"
        Write-Colored "" "Azul"
        Write-Colored "Pressione 'S' para desinstalar o OneDrive." "Azul"
        Write-Colored "Pressione 'N' para pular isso." "Azul"
        $selection = Read-Host "Por favor, escolha."
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

function DisableXboxFeatures {
  Write-Log "Iniciando função DisableXboxFeatures para desativar recursos do Xbox." -ConsoleOutput

  try {
    Write-Output "Disabling Xbox features...(tudo porcaria)"
    Write-Log "Desativando recursos do Xbox...(tudo porcaria)" -ConsoleOutput

    $xboxApps = @(
      "Microsoft.XboxApp",
      "Microsoft.XboxIdentityProvider",
      "Microsoft.XboxSpeechToTextOverlay",
      "Microsoft.XboxGameOverlay",
      "Microsoft.Xbox.TCUI",
      "Microsoft.XboxGamingOverlay"
    )
    Write-Log "Lista de aplicativos Xbox carregada: $($xboxApps -join ', ')" -ConsoleOutput

    foreach ($app in $xboxApps) {
      Write-Log "Removendo o aplicativo Xbox $app para todos os usuários..." -ConsoleOutput
      Get-AppxPackage -Name $app -AllUsers -ErrorAction Stop | Remove-AppxPackage -ErrorAction Stop
      Write-Log "Aplicativo $app removido com sucesso." -Level "INFO" -ConsoleOutput
    }

    Write-Log "Configurando GameDVR_Enabled para 0 em HKCU:\System\GameConfigStore..." -ConsoleOutput
    Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 0 -ErrorAction Stop
    Write-Log "GameDVR_Enabled configurado com sucesso." -Level "INFO" -ConsoleOutput

    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR"
    if (-not (Test-Path $registryPath)) {
      Write-Log "Chave $registryPath não existe. Criando..." -ConsoleOutput
      New-Item -Path $registryPath -Force -ErrorAction Stop | Out-Null
      Write-Log "Chave $registryPath criada com sucesso." -Level "INFO" -ConsoleOutput
    }
    else {
      Write-Log "Chave $registryPath já existe. Prosseguindo com a configuração." -ConsoleOutput
    }

    Write-Log "Configurando AllowGameDVR para 0 em $registryPath..." -ConsoleOutput
    Set-ItemProperty -Path $registryPath -Name "AllowGameDVR" -Type DWord -Value 0 -ErrorAction Stop
    Write-Log "AllowGameDVR configurado com sucesso." -Level "INFO" -ConsoleOutput

    Write-Log "Recursos do Xbox desativados com sucesso." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função DisableXboxFeatures: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    throw  # Repropaga o erro
  }
  finally {
    Write-Log "Finalizando função DisableXboxFeatures." -Level "INFO" -ConsoleOutput
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
    Write-Colored "" "Azul"
    Write-Colored -Text "===================================================" -Color "Azul"
    Write-Colored -Text "==========  Configurando Memória Virtual ==========" -Color "Azul"
    Write-Colored -Text "===================================================" -Color "Azul"
    Write-Colored "" "Azul"
    Write-Log "Exibindo interface de configuração da memória virtual." -ConsoleOutput
    Write-Colored "" "Azul"
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
      & $sevenZipPath x $downloadPath -o"$extractPath" -y -ErrorAction Stop
      Write-Log "Arquivo extraído com sucesso para $extractPath." -Level "INFO" -ConsoleOutput
      Write-Colored "Arquivo extraído com sucesso para $extractPath" "Verde"

      # Renomear a pasta extraída para ISLC
      $extractedFolderPath = "$extractPath\ISLC v1.0.3.4"
      if (Test-Path -Path $extractedFolderPath) {
        Write-Log "Renomeando a pasta extraída de $extractedFolderPath para $newFolderName..." -ConsoleOutput
        Rename-Item -Path $extractedFolderPath -NewName $newFolderName -ErrorAction Stop
        Write-Log "Pasta renomeada com sucesso para $newFolderName." -Level "INFO" -ConsoleOutput
        Write-Colored "Pasta renomeada para '$newFolderName'." "Verde"
      }
      else {
        Write-Log "Pasta extraída $extractedFolderPath não encontrada." -Level "ERROR" -ConsoleOutput
        Write-Colored "Pasta extraída não encontrada." "Vermelho"
      }
    }
    else {
      Write-Log "7-Zip não encontrado em $sevenZipPath." -Level "WARNING" -ConsoleOutput
      Write-Colored "7-Zip não encontrado no caminho especificado." "Amarelo"
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

Function NvidiaTweaks {
  Write-Log "Iniciando função NvidiaTweaks para aplicar otimizações em GPUs NVIDIA GTX/RTX." -ConsoleOutput

  try {
    # Verificar se há GPU NVIDIA GTX/RTX
    $CheckGPU = Get-CimInstance -ClassName Win32_VideoController -ErrorAction Stop | Select-Object -ExpandProperty Name
    Write-Log "Nome da GPU detectado: $CheckGPU" -ConsoleOutput

    if (($CheckGPU -like "*GTX*") -or ($CheckGPU -like "*RTX*")) {
      Write-Output "NVIDIA GTX/RTX Card Detected! Applying Nvidia Power Tweaks..."
      Write-Log "Placa NVIDIA GTX/RTX detectada! Aplicando otimizações de energia..." -ConsoleOutput

      $url_base = "https://raw.githubusercontent.com/wesscd/WindowsGaming/main/BaseProfile.nip"
      $url_nvidiaprofile = "https://raw.githubusercontent.com/wesscd/WindowsGaming/main/nvidiaProfileInspector.exe"

      Write-Log "Baixando BaseProfile.nip de $url_base para $Env:windir\system32\BaseProfile.nip..." -ConsoleOutput
      Invoke-WebRequest -Uri $url_base -OutFile "$Env:windir\system32\BaseProfile.nip" -ErrorAction Stop
      Write-Log "BaseProfile.nip baixado com sucesso." -Level "INFO" -ConsoleOutput

      Write-Log "Baixando nvidiaProfileInspector.exe de $url_nvidiaprofile para $Env:windir\system32\nvidiaProfileInspector.exe..." -ConsoleOutput
      Invoke-WebRequest -Uri $url_nvidiaprofile -OutFile "$Env:windir\system32\nvidiaProfileInspector.exe" -ErrorAction Stop
      Write-Log "nvidiaProfileInspector.exe baixado com sucesso." -Level "INFO" -ConsoleOutput

      Write-Log "Mudando diretório para $Env:windir\system32\ para executar o nvidiaProfileInspector..." -ConsoleOutput
      Push-Location
      Set-Location "$Env:windir\system32\"
      Write-Log "Executando nvidiaProfileInspector.exe com o perfil BaseProfile.nip..." -ConsoleOutput
      & "nvidiaProfileInspector.exe" /s -load "BaseProfile.nip" -ErrorAction Stop
      Write-Log "Perfil BaseProfile.nip aplicado com sucesso pelo nvidiaProfileInspector." -Level "INFO" -ConsoleOutput
      Pop-Location
      Write-Log "Diretório restaurado." -ConsoleOutput
    }
    else {
      Write-Output "Nvidia GTX/RTX Card Not Detected! Skipping..."
      Write-Log "Placa NVIDIA GTX/RTX não detectada! Pulando otimizações de energia..." -Level "INFO" -ConsoleOutput
    }

    # Verificação de entradas de registro para ajustes de latência
    $errpref = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"
    Write-Log "Alterando ErrorActionPreference para SilentlyContinue temporariamente para verificação de registro." -ConsoleOutput

    Write-Log "Verificando entradas de registro para GPUs NVIDIA..." -ConsoleOutput
    $CheckGPURegistryKey0 = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -ErrorAction Stop).DriverDesc
    $CheckGPURegistryKey1 = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -ErrorAction Stop).DriverDesc
    $CheckGPURegistryKey2 = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -ErrorAction Stop).DriverDesc
    $CheckGPURegistryKey3 = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -ErrorAction Stop).DriverDesc
    Write-Log "Entradas de registro verificadas: 0000=$CheckGPURegistryKey0, 0001=$CheckGPURegistryKey1, 0002=$CheckGPURegistryKey2, 0003=$CheckGPURegistryKey3" -ConsoleOutput

    $ErrorActionPreference = $errpref
    Write-Log "Restaurando ErrorActionPreference para $errpref após verificação de registro." -ConsoleOutput

    if (($CheckGPURegistryKey0 -like "*GTX*") -or ($CheckGPURegistryKey0 -like "*RTX*")) {
      Write-Output "Nvidia GTX/RTX Card Registry Path 0000 Detected! Applying Nvidia Latency Tweaks..."
      Write-Log "Placa NVIDIA GTX/RTX detectada no caminho de registro 0000! Aplicando otimizações de latência..." -ConsoleOutput

      $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000"
      Write-Log "Aplicando ajustes de latência no caminho $regPath..." -ConsoleOutput
      Set-ItemProperty -Path $regPath -Name "D3PCLatency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "F1TransitionLatency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "LOWLATENCY" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "Node3DLowLatency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "PciLatencyTimerControl" -Type DWord -Value "0x00000020" -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "RMDeepL1EntryLatencyUsec" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "RmGspcMaxFtuS" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "RmGspcMinFtuS" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "RmGspcPerioduS" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "RMLpwrEiIdleThresholdUs" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "RMLpwrGrIdleThresholdUs" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "RMLpwrGrRgIdleThresholdUs" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "RMLpwrMsIdleThresholdUs" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "VRDirectFlipDPCDelayUs" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "VRDirectFlipTimingMarginUs" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "VRDirectJITFlipMsHybridFlipDelayUs" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "vrrCursorMarginUs" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "vrrDeflickerMarginUs" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "vrrDeflickerMaxUs" -Type DWord -Value 1 -ErrorAction Stop
      Write-Log "Otimizações de latência NVIDIA aplicadas com sucesso no caminho 0000." -Level "INFO" -ConsoleOutput
    }
    elseif (($CheckGPURegistryKey1 -like "*GTX*") -or ($CheckGPURegistryKey1 -like "*RTX*")) {
      Write-Output "Nvidia GTX/RTX Card Registry Path 0001 Detected! Applying Nvidia Latency Tweaks..."
      Write-Log "Placa NVIDIA GTX/RTX detectada no caminho de registro 0001! Aplicando otimizações de latência..." -ConsoleOutput

      $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001"
      Write-Log "Aplicando ajustes de latência no caminho $regPath..." -ConsoleOutput
      Set-ItemProperty -Path $regPath -Name "D3PCLatency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "F1TransitionLatency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "LOWLATENCY" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "Node3DLowLatency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "PciLatencyTimerControl" -Type DWord -Value "0x00000020" -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "RMDeepL1EntryLatencyUsec" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "RmGspcMaxFtuS" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "RmGspcMinFtuS" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "RmGspcPerioduS" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "RMLpwrEiIdleThresholdUs" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "RMLpwrGrIdleThresholdUs" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "RMLpwrGrRgIdleThresholdUs" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "RMLpwrMsIdleThresholdUs" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "VRDirectFlipDPCDelayUs" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "VRDirectFlipTimingMarginUs" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "VRDirectJITFlipMsHybridFlipDelayUs" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "vrrCursorMarginUs" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "vrrDeflickerMarginUs" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "vrrDeflickerMaxUs" -Type DWord -Value 1 -ErrorAction Stop
      Write-Log "Otimizações de latência NVIDIA aplicadas com sucesso no caminho 0001." -Level "INFO" -ConsoleOutput
    }
    elseif (($CheckGPURegistryKey2 -like "*GTX*") -or ($CheckGPURegistryKey2 -like "*RTX*")) {
      Write-Output "Nvidia GTX/RTX Card Registry Path 0002 Detected! Applying Nvidia Latency Tweaks..."
      Write-Log "Placa NVIDIA GTX/RTX detectada no caminho de registro 0002! Aplicando otimizações de latência..." -ConsoleOutput

      $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002"
      Write-Log "Aplicando ajustes de latência no caminho $regPath..." -ConsoleOutput
      Set-ItemProperty -Path $regPath -Name "D3PCLatency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "F1TransitionLatency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "LOWLATENCY" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "Node3DLowLatency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "PciLatencyTimerControl" -Type DWord -Value "0x00000020" -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "RMDeepL1EntryLatencyUsec" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "RmGspcMaxFtuS" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "RmGspcMinFtuS" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "RmGspcPerioduS" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "RMLpwrEiIdleThresholdUs" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "RMLpwrGrIdleThresholdUs" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "RMLpwrGrRgIdleThresholdUs" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "RMLpwrMsIdleThresholdUs" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "VRDirectFlipDPCDelayUs" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "VRDirectFlipTimingMarginUs" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "VRDirectJITFlipMsHybridFlipDelayUs" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "vrrCursorMarginUs" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "vrrDeflickerMarginUs" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "vrrDeflickerMaxUs" -Type DWord -Value 1 -ErrorAction Stop
      Write-Log "Otimizações de latência NVIDIA aplicadas com sucesso no caminho 0002." -Level "INFO" -ConsoleOutput
    }
    elseif (($CheckGPURegistryKey3 -like "*GTX*") -or ($CheckGPURegistryKey3 -like "*RTX*")) {
      Write-Output "Nvidia GTX/RTX Card Registry Path 0003 Detected! Applying Nvidia Latency Tweaks..."
      Write-Log "Placa NVIDIA GTX/RTX detectada no caminho de registro 0003! Aplicando otimizações de latência..." -ConsoleOutput

      $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003"
      Write-Log "Aplicando ajustes de latência no caminho $regPath..." -ConsoleOutput
      Set-ItemProperty -Path $regPath -Name "D3PCLatency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "F1TransitionLatency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "LOWLATENCY" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "Node3DLowLatency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "PciLatencyTimerControl" -Type DWord -Value "0x00000020" -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "RMDeepL1EntryLatencyUsec" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "RmGspcMaxFtuS" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "RmGspcMinFtuS" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "RmGspcPerioduS" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "RMLpwrEiIdleThresholdUs" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "RMLpwrGrIdleThresholdUs" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "RMLpwrGrRgIdleThresholdUs" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "RMLpwrMsIdleThresholdUs" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "VRDirectFlipDPCDelayUs" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "VRDirectFlipTimingMarginUs" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "VRDirectJITFlipMsHybridFlipDelayUs" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "vrrCursorMarginUs" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "vrrDeflickerMarginUs" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "vrrDeflickerMaxUs" -Type DWord -Value 1 -ErrorAction Stop
      Write-Log "Otimizações de latência NVIDIA aplicadas com sucesso no caminho 0003." -Level "INFO" -ConsoleOutput
    }
    else {
      Write-Output "No NVIDIA GTX/RTX Card Registry entry Found! Skipping..."
      Write-Log "Nenhuma entrada de registro NVIDIA GTX/RTX encontrada! Pulando otimizações de latência..." -Level "INFO" -ConsoleOutput
    }
  }
  catch {
    $errorMessage = "Erro na função NvidiaTweaks: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    throw  # Repropaga o erro
  }
  finally {
    Write-Log "Finalizando função NvidiaTweaks." -Level "INFO" -ConsoleOutput
  }
}

#Applying AMD Tweaks If Detected!
Function AMDGPUTweaks {
  Write-Log "Iniciando função AMDGPUTweaks para aplicar otimizações em GPUs AMD." -ConsoleOutput

  try {
    $errpref = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"
    Write-Log "Alterando ErrorActionPreference para SilentlyContinue temporariamente." -ConsoleOutput

    Write-Log "Verificando entradas de registro para GPUs AMD..." -ConsoleOutput
    $CheckGPURegistryKey0 = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -ErrorAction Stop).DriverDesc
    $CheckGPURegistryKey1 = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -ErrorAction Stop).DriverDesc
    $CheckGPURegistryKey2 = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -ErrorAction Stop).DriverDesc
    $CheckGPURegistryKey3 = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -ErrorAction Stop).DriverDesc
    Write-Log "Entradas de registro verificadas: 0000=$CheckGPURegistryKey0, 0001=$CheckGPURegistryKey1, 0002=$CheckGPURegistryKey2, 0003=$CheckGPURegistryKey3" -ConsoleOutput

    $ErrorActionPreference = $errpref
    Write-Log "Restaurando ErrorActionPreference para $errpref após verificação de registro." -ConsoleOutput

    if ($CheckGPURegistryKey0 -like "*amd*") {
      Write-Output "AMD GPU Registry Path 0000 Detected! Applying AMD Latency Tweaks..."
      Write-Log "GPU AMD detectada no caminho de registro 0000! Aplicando otimizações de latência..." -ConsoleOutput

      $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000"
      Write-Log "Aplicando ajustes de latência no caminho $regPath..." -ConsoleOutput
      Set-ItemProperty -Path $regPath -Name "LTRSnoopL1Latency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "LTRSnoopL0Latency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "LTRNoSnoopL1Latency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "LTRMaxNoSnoopLatency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "KMD_RpmComputeLatency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "DalUrgentLatencyNs" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "memClockSwitchLatency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "PP_RTPMComputeF1Latency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "PP_DGBMMMaxTransitionLatencyUvd" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "PP_DGBPMMaxTransitionLatencyGfx" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "DalNBLatencyForUnderFlow" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "DalDramClockChangeLatencyNs" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "BGM_LTRSnoopL1Latency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "BGM_LTRSnoopL0Latency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "BGM_LTRNoSnoopL1Latency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "BGM_LTRNoSnoopL0Latency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "BGM_LTRMaxSnoopLatencyValue" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "BGM_LTRMaxNoSnoopLatencyValue" -Type DWord -Value 1 -ErrorAction Stop
      Write-Log "Otimizações de latência AMD aplicadas com sucesso no caminho 0000." -Level "INFO" -ConsoleOutput
    }
    elseif ($CheckGPURegistryKey1 -like "*amd*") {
      Write-Output "AMD GPU Registry Path 0001 Detected! Applying AMD Latency Tweaks..."
      Write-Log "GPU AMD detectada no caminho de registro 0001! Aplicando otimizações de latência..." -ConsoleOutput

      $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001"
      Write-Log "Aplicando ajustes de latência no caminho $regPath..." -ConsoleOutput
      Set-ItemProperty -Path $regPath -Name "LTRSnoopL1Latency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "LTRSnoopL0Latency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "LTRNoSnoopL1Latency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "LTRMaxNoSnoopLatency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "KMD_RpmComputeLatency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "DalUrgentLatencyNs" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "memClockSwitchLatency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "PP_RTPMComputeF1Latency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "PP_DGBMMMaxTransitionLatencyUvd" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "PP_DGBPMMaxTransitionLatencyGfx" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "DalNBLatencyForUnderFlow" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "DalDramClockChangeLatencyNs" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "BGM_LTRSnoopL1Latency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "BGM_LTRSnoopL0Latency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "BGM_LTRNoSnoopL1Latency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "BGM_LTRNoSnoopL0Latency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "BGM_LTRMaxSnoopLatencyValue" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "BGM_LTRMaxNoSnoopLatencyValue" -Type DWord -Value 1 -ErrorAction Stop
      Write-Log "Otimizações de latência AMD aplicadas com sucesso no caminho 0001." -Level "INFO" -ConsoleOutput
    }
    elseif ($CheckGPURegistryKey2 -like "*amd*") {
      Write-Output "AMD GPU Registry Path 0002 Detected! Applying AMD Latency Tweaks..."
      Write-Log "GPU AMD detectada no caminho de registro 0002! Aplicando otimizações de latência..." -ConsoleOutput

      $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002"
      Write-Log "Aplicando ajustes de latência no caminho $regPath..." -ConsoleOutput
      Set-ItemProperty -Path $regPath -Name "LTRSnoopL1Latency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "LTRSnoopL0Latency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "LTRNoSnoopL1Latency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "LTRMaxNoSnoopLatency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "KMD_RpmComputeLatency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "DalUrgentLatencyNs" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "memClockSwitchLatency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "PP_RTPMComputeF1Latency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "PP_DGBMMMaxTransitionLatencyUvd" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "PP_DGBPMMaxTransitionLatencyGfx" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "DalNBLatencyForUnderFlow" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "DalDramClockChangeLatencyNs" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "BGM_LTRSnoopL1Latency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "BGM_LTRSnoopL0Latency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "BGM_LTRNoSnoopL1Latency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "BGM_LTRNoSnoopL0Latency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "BGM_LTRMaxSnoopLatencyValue" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "BGM_LTRMaxNoSnoopLatencyValue" -Type DWord -Value 1 -ErrorAction Stop
      Write-Log "Otimizações de latência AMD aplicadas com sucesso no caminho 0002." -Level "INFO" -ConsoleOutput
    }
    elseif ($CheckGPURegistryKey3 -like "*amd*") {
      Write-Output "AMD GPU Registry Path 0003 Detected! Applying AMD Latency Tweaks..."
      Write-Log "GPU AMD detectada no caminho de registro 0003! Aplicando otimizações de latência..." -ConsoleOutput

      $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003"
      Write-Log "Aplicando ajustes de latência no caminho $regPath..." -ConsoleOutput
      Set-ItemProperty -Path $regPath -Name "LTRSnoopL1Latency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "LTRSnoopL0Latency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "LTRNoSnoopL1Latency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "LTRMaxNoSnoopLatency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "KMD_RpmComputeLatency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "DalUrgentLatencyNs" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "memClockSwitchLatency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "PP_RTPMComputeF1Latency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "PP_DGBMMMaxTransitionLatencyUvd" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "PP_DGBPMMaxTransitionLatencyGfx" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "DalNBLatencyForUnderFlow" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "DalDramClockChangeLatencyNs" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "BGM_LTRSnoopL1Latency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "BGM_LTRSnoopL0Latency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "BGM_LTRNoSnoopL1Latency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "BGM_LTRNoSnoopL0Latency" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "BGM_LTRMaxSnoopLatencyValue" -Type DWord -Value 1 -ErrorAction Stop
      Set-ItemProperty -Path $regPath -Name "BGM_LTRMaxNoSnoopLatencyValue" -Type DWord -Value 1 -ErrorAction Stop
      Write-Log "Otimizações de latência AMD aplicadas com sucesso no caminho 0003." -Level "INFO" -ConsoleOutput
    }
    else {
      Write-Output "No AMD GPU Registry entry Found! Skipping..."
      Write-Log "Nenhuma entrada de registro AMD GPU encontrada! Pulando otimizações de latência..." -Level "INFO" -ConsoleOutput
    }
  }
  catch {
    $errorMessage = "Erro na função AMDGPUTweaks: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    throw  # Repropaga o erro
  }
  finally {
    Write-Log "Finalizando função AMDGPUTweaks." -Level "INFO" -ConsoleOutput
  }
}

#Optimizing Network and applying Tweaks for no throttle and maximum speed!
function NetworkOptimizations {
  Write-Log "Iniciando função NetworkOptimizations para otimizar a rede e aplicar ajustes de desempenho máximo." -ConsoleOutput

  try {
      # Salvar e ajustar ErrorActionPreference
      $errpref = $ErrorActionPreference
      $ErrorActionPreference = "SilentlyContinue"
      Write-Log "Alterando ErrorActionPreference para SilentlyContinue temporariamente." -ConsoleOutput

      Write-Output "Otimizando a rede e aplicando ajustes para máximo desempenho..."
      Write-Log "Otimizando a rede e aplicando ajustes para máximo desempenho..." -ConsoleOutput

      # Verificar se há adaptadores de rede
      Write-Log "Obtendo adaptadores de rede ativos..." -ConsoleOutput
      $adapters = Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq "Up" -and $_.InterfaceDescription -notmatch "Loopback" }
      if (-not $adapters) {
          Write-Log "Nenhum adaptador de rede ativo encontrado. Pulando otimizações..." -Level "WARNING" -ConsoleOutput
          Write-Output "Nenhum adaptador de rede ativo encontrado. Pulando otimizações..."
          return
      }

      # Criar chaves de registro se não existirem
      $regPaths = @(
          "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched",
          "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\QoS",
          "HKLM:\SOFTWARE\Microsoft\MSMQ\Parameters",
          "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
          "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
          "HKLM:\SYSTEM\ControlSet001\Control\Lsa",
          "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
      )

      foreach ($path in $regPaths) {
          if (-not (Test-Path $path)) {
              Write-Log "Criando chave de registro $path..." -ConsoleOutput
              New-Item -Path $path -Force -ErrorAction Stop | Out-Null
              Write-Log "Chave $path criada ou verificada com sucesso." -Level "INFO" -ConsoleOutput
          }
      }

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

      Write-Log "Configurações de registro definidas para otimização de rede." -ConsoleOutput

      foreach ($path in $regConfigs.Keys) {
          foreach ($setting in $regConfigs[$path]) {
              Write-Log "Configurando $path - $($setting[0]) para $($setting[1])..." -ConsoleOutput
              try {
                  Set-ItemProperty -Path $path -Name $setting[0] -Type DWord -Value $setting[1] -ErrorAction Stop
                  Write-Log "$($setting[0]) configurado com sucesso em $path." -Level "INFO" -ConsoleOutput
              }
              catch {
                  Write-Log "Falha ao configurar $path - $($setting[0]). Erro: $_" -Level "WARNING" -ConsoleOutput
              }
          }
      }

      # Ajustes de TCP/IP
      Write-Log "Aplicando ajustes de TCP/IP..." -ConsoleOutput
      try {
          Set-NetTCPSetting -SettingName internet -EcnCapability disabled -ErrorAction Stop | Out-Null
          Set-NetTCPSetting -SettingName internet -Timestamps disabled -ErrorAction Stop | Out-Null
          Set-NetTCPSetting -SettingName internet -MaxSynRetransmissions 2 -ErrorAction Stop | Out-Null
          Set-NetTCPSetting -SettingName internet -NonSackRttResiliency disabled -ErrorAction Stop | Out-Null
          Set-NetTCPSetting -SettingName internet -InitialRto 2000 -ErrorAction Stop | Out-Null
          Set-NetTCPSetting -SettingName internet -MinRto 300 -ErrorAction Stop | Out-Null
          Set-NetTCPSetting -SettingName Internet -AutoTuningLevelLocal normal -ErrorAction Stop | Out-Null
          Set-NetTCPSetting -SettingName internet -ScalingHeuristics disabled -ErrorAction Stop | Out-Null
          Write-Log "Ajustes de TCP/IP aplicados com sucesso." -Level "INFO" -ConsoleOutput
      }
      catch {
          Write-Log "Erro ao aplicar ajustes de TCP/IP: $_" -Level "ERROR" -ConsoleOutput
      }

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

      Write-Log "Executando comandos Netsh para otimizações de rede..." -ConsoleOutput
      foreach ($cmd in $netshCommands) {
          Write-Log "Executando comando Netsh: $cmd..." -ConsoleOutput
          try {
              netsh $cmd -ErrorAction Stop | Out-Null
              Write-Log "Comando $cmd executado com sucesso." -Level "INFO" -ConsoleOutput
          }
          catch {
              Write-Log "Falha ao executar comando Netsh $cmd. Erro: $_" -Level "WARNING" -ConsoleOutput
          }
      }

      # Ajustes globais de offload
      Write-Log "Aplicando ajustes globais de offload..." -ConsoleOutput
      try {
          Set-NetOffloadGlobalSetting -ReceiveSegmentCoalescing disabled -ErrorAction Stop | Out-Null
          Set-NetOffloadGlobalSetting -ReceiveSideScaling enabled -ErrorAction Stop | Out-Null
          Write-Log "Ajustes globais de offload aplicados com sucesso." -Level "INFO" -ConsoleOutput
      }
      catch {
          Write-Log "Erro ao aplicar ajustes globais de offload: $_" -Level "ERROR" -ConsoleOutput
      }

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

      Write-Log "Aplicando ajustes avançados em adaptadores de rede..." -ConsoleOutput
      foreach ($adapter in $adapters) {
          foreach ($prop in $advancedProperties) {
              Write-Log "Tentando desativar propriedade avançada $prop no adaptador $($adapter.Name)..." -ConsoleOutput
              try {
                  $existingProps = Get-NetAdapterAdvancedProperty -Name $adapter.Name -ErrorAction Stop | Where-Object { $_.DisplayName -like "*$prop*" }
                  if ($existingProps) {
                      Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName $prop -DisplayValue "Disabled" -ErrorAction Stop
                      Write-Log "Propriedade $prop desativada com sucesso no adaptador $($adapter.Name)." -Level "INFO" -ConsoleOutput
                  } else {
                      Write-Log "Propriedade $prop não encontrada no adaptador $($adapter.Name). Pulando..." -Level "WARNING" -ConsoleOutput
                  }
              }
              catch {
                  Write-Log "Falha ao desativar propriedade $prop no adaptador $($adapter.Name). Erro: $_" -Level "WARNING" -ConsoleOutput
              }
          }
      }

      Write-Log "Otimizações de rede concluídas com sucesso!" -Level "INFO" -ConsoleOutput
      Write-Output "Otimizações de rede concluídas com sucesso!"
  }
  catch {
      $errorMessage = "Erro na função NetworkOptimizations: $_"
      Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
      throw  # Repropaga o erro para ser tratado externamente, se necessário
  }
  finally {
      $ErrorActionPreference = $errpref
      Write-Log "Restaurando ErrorActionPreference para $errpref." -ConsoleOutput
      Write-Log "Finalizando função NetworkOptimizations." -Level "INFO" -ConsoleOutput
  }
}

function Disable-LSO {
  Write-Log "Iniciando função Disable-LSO para desativar Large Send Offload (LSO) em adaptadores de rede." -ConsoleOutput

  try {
    Write-Log "Obtendo adaptadores de rede ativos (exceto Loopback)..." -ConsoleOutput
    $adapters = Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq "Up" -and $_.InterfaceDescription -notmatch "Loopback" }
    Write-Log "Adaptadores de rede detectados: $($adapters.Name -join ', ')" -ConsoleOutput

    foreach ($adapter in $adapters) {
      Write-Output "Desativando Large Send Offload (LSO) para: $($adapter.Name)"
      Write-Log "Desativando Large Send Offload (LSO) para o adaptador: $($adapter.Name)..." -ConsoleOutput

      # Verifica se há suporte ao LSO antes de tentar desativar
      Write-Log "Verificando suporte ao LSO para $($adapter.Name)..." -ConsoleOutput
      $lsoSupport = Get-NetAdapterAdvancedProperty -Name $adapter.Name -RegistryKeyword "*LsoV2IPv4" -ErrorAction Stop
      if ($lsoSupport) {
        Write-Log "Suporte ao LSO detectado para $($adapter.Name). Tentando desativar..." -ConsoleOutput
        try {
          Write-Log "Desativando LSO para IPv4 no adaptador $($adapter.Name)..." -ConsoleOutput
          Disable-NetAdapterLso -Name $adapter.Name -IPv4 -ErrorAction Stop
          Write-Log "LSO para IPv4 desativado com sucesso." -Level "INFO" -ConsoleOutput

          Write-Log "Desativando LSO para IPv6 no adaptador $($adapter.Name)..." -ConsoleOutput
          Disable-NetAdapterLso -Name $adapter.Name -IPv6 -ErrorAction Stop
          Write-Log "LSO para IPv6 desativado com sucesso." -Level "INFO" -ConsoleOutput

          Write-Output "LSO desativado para: $($adapter.Name)"
          Write-Log "LSO desativado com sucesso para o adaptador: $($adapter.Name)." -Level "INFO" -ConsoleOutput
        }
        catch {
          $errorMessage = "Falha ao desativar LSO para $($adapter.Name). Motivo: $($_.Exception.Message)"
          Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
          Write-Warning $errorMessage
        }
      }
      else {
        Write-Log "LSO não suportado para $($adapter.Name). Ignorando..." -Level "WARNING" -ConsoleOutput
        Write-Warning "LSO não suportado para: $($adapter.Name), ignorando."
      }
    }

    Write-Log "Processo de desativação de LSO concluído com sucesso para todos os adaptadores aplicáveis." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função Disable-LSO: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    throw  # Repropaga o erro
  }
  finally {
    Write-Log "Finalizando função Disable-LSO." -Level "INFO" -ConsoleOutput
  }
}

# Disable Nagle's Algorithm
Function DisableNagle {
  Write-Log "Iniciando função DisableNagle para desativar o algoritmo de Nagle." -ConsoleOutput

  try {
    $errpref = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"
    Write-Log "Alterando ErrorActionPreference para SilentlyContinue temporariamente." -ConsoleOutput

    Write-Log "Obtendo IDs de interfaces de rede..." -ConsoleOutput
    $NetworkIDS = @(
          (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\*" -ErrorAction Stop).PSChildName
    )
    Write-Log "IDs de interfaces de rede detectados: $($NetworkIDS -join ', ')" -ConsoleOutput

    foreach ($NetworkID in $NetworkIDS) {
      Write-Output "Disabling Nagle's Algorithm..."
      Write-Log "Desativando o algoritmo de Nagle para a interface: $NetworkID..." -ConsoleOutput

      $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$NetworkID"
      Write-Log "Configurando TcpAckFrequency para 1 em $regPath..." -ConsoleOutput
      Set-ItemProperty -Path $regPath -Name "TcpAckFrequency" -Type DWord -Value 1 -ErrorAction Stop
      Write-Log "TcpAckFrequency configurado com sucesso para $NetworkID." -Level "INFO" -ConsoleOutput

      Write-Log "Configurando TCPNoDelay para 1 em $regPath..." -ConsoleOutput
      Set-ItemProperty -Path $regPath -Name "TCPNoDelay" -Type DWord -Value 1 -ErrorAction Stop
      Write-Log "TCPNoDelay configurado com sucesso para $NetworkID." -Level "INFO" -ConsoleOutput
    }

    Write-Log "Algoritmo de Nagle desativado com sucesso para todas as interfaces de rede." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função DisableNagle: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    throw  # Repropaga o erro
  }
  finally {
    $ErrorActionPreference = $errpref
    Write-Log "Restaurando ErrorActionPreference para $errpref." -ConsoleOutput
    Write-Log "Finalizando função DisableNagle." -Level "INFO" -ConsoleOutput
  }
}

#setting network adabter optimal rss
Function NetworkAdapterRSS {
  Write-Log "Iniciando função NetworkAdapterRSS para configurar RSS em adaptadores de rede." -ConsoleOutput

  try {
    $errpref = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"
    Write-Log "Alterando ErrorActionPreference para SilentlyContinue temporariamente." -ConsoleOutput

    Write-Output "Setting network adapter RSS..."
    Write-Log "Configurando RSS para adaptadores de rede..." -ConsoleOutput

    Write-Log "Obtendo adaptadores físicos de rede..." -ConsoleOutput
    $PhysicalAdapters = Get-WmiObject -Class Win32_NetworkAdapter -ErrorAction Stop | Where-Object { 
      $_.PNPDeviceID -notlike "ROOT\*" -and 
      $_.Manufacturer -ne "Microsoft" -and 
      $_.ConfigManagerErrorCode -eq 0 -and 
      $_.ConfigManagerErrorCode -ne 22 
    }
    Write-Log "Adaptadores físicos detectados: $($PhysicalAdapters.Name -join ', ')" -ConsoleOutput

    foreach ($PhysicalAdapter in $PhysicalAdapters) {
      $DeviceID = $PhysicalAdapter.DeviceID
      Write-Log "Processando adaptador com DeviceID: $DeviceID..." -ConsoleOutput

      If ([Int32]$DeviceID -lt 10) {
        $AdapterDeviceNumber = "000" + $DeviceID
      }
      Else {
        $AdapterDeviceNumber = "00" + $DeviceID
      }
      Write-Log "Número do dispositivo ajustado para: $AdapterDeviceNumber" -ConsoleOutput

      $KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\$AdapterDeviceNumber"
      $KeyPath2 = "$KeyPath\Ndi\params\*RSS\Enum"
      $KeyPath3 = "$KeyPath\Ndi\params\*RSS"
      $KeyPath4 = "$KeyPath\Ndi\params\*NumRssQueues\Enum"
      $KeyPath5 = "$KeyPath\Ndi\params\*NumRssQueues"
      $KeyPath6 = "$KeyPath\Ndi\params\*ReceiveBuffers"
      $KeyPath7 = "$KeyPath\Ndi\params\*TransmitBuffers"

      If (Test-Path -Path $KeyPath) {
        Write-Log "Caminho $KeyPath encontrado. Aplicando configurações RSS..." -ConsoleOutput

        Write-Log "Criando subchave $KeyPath2..." -ConsoleOutput
        New-Item -Path $KeyPath2 -Force -ErrorAction Stop | Out-Null
        Write-Log "Subchave $KeyPath2 criada com sucesso." -Level "INFO" -ConsoleOutput

        Write-Log "Criando subchave $KeyPath4..." -ConsoleOutput
        New-Item -Path $KeyPath4 -Force -ErrorAction Stop | Out-Null
        Write-Log "Subchave $KeyPath4 criada com sucesso." -Level "INFO" -ConsoleOutput

        Write-Log "Configurando *NumRssQueues para 2 em $KeyPath..." -ConsoleOutput
        Set-ItemProperty -Path $KeyPath -Name "*NumRssQueues" -Type String -Value 2 -ErrorAction Stop | Out-Null
        Write-Log "*NumRssQueues configurado com sucesso." -Level "INFO" -ConsoleOutput

        Write-Log "Configurando *RSS para 1 em $KeyPath..." -ConsoleOutput
        Set-ItemProperty -Path $KeyPath -Name "*RSS" -Type String -Value 1 -ErrorAction Stop | Out-Null
        Write-Log "*RSS configurado com sucesso." -Level "INFO" -ConsoleOutput

        Write-Log "Configurando *RSSProfile para 4 em $KeyPath..." -ConsoleOutput
        Set-ItemProperty -Path $KeyPath -Name "*RSSProfile" -Type String -Value 4 -ErrorAction Stop | Out-Null
        Write-Log "*RSSProfile configurado com sucesso." -Level "INFO" -ConsoleOutput

        Write-Log "Configurando *RssBaseProcNumber para 2 em $KeyPath..." -ConsoleOutput
        Set-ItemProperty -Path $KeyPath -Name "*RssBaseProcNumber" -Type String -Value 2 -ErrorAction Stop | Out-Null
        Write-Log "*RssBaseProcNumber configurado com sucesso." -Level "INFO" -ConsoleOutput

        Write-Log "Configurando *MaxRssProcessors para 4 em $KeyPath..." -ConsoleOutput
        Set-ItemProperty -Path $KeyPath -Name "*MaxRssProcessors" -Type String -Value 4 -ErrorAction Stop | Out-Null
        Write-Log "*MaxRssProcessors configurado com sucesso." -Level "INFO" -ConsoleOutput

        Write-Log "Configurando *NumaNodeId para 0 em $KeyPath..." -ConsoleOutput
        Set-ItemProperty -Path $KeyPath -Name "*NumaNodeId" -Type String -Value 0 -ErrorAction Stop | Out-Null
        Write-Log "*NumaNodeId configurado com sucesso." -Level "INFO" -ConsoleOutput

        Write-Log "Configurando *RssBaseProcGroup para 0 em $KeyPath..." -ConsoleOutput
        Set-ItemProperty -Path $KeyPath -Name "*RssBaseProcGroup" -Type String -Value 0 -ErrorAction Stop | Out-Null
        Write-Log "*RssBaseProcGroup configurado com sucesso." -Level "INFO" -ConsoleOutput

        Write-Log "Configurando *RssMaxProcNumber para 4 em $KeyPath..." -ConsoleOutput
        Set-ItemProperty -Path $KeyPath -Name "*RssMaxProcNumber" -Type String -Value 4 -ErrorAction Stop | Out-Null
        Write-Log "*RssMaxProcNumber configurado com sucesso." -Level "INFO" -ConsoleOutput

        Write-Log "Configurando *RssMaxProcGroup para 0 em $KeyPath..." -ConsoleOutput
        Set-ItemProperty -Path $KeyPath -Name "*RssMaxProcGroup" -Type String -Value 0 -ErrorAction Stop | Out-Null
        Write-Log "*RssMaxProcGroup configurado com sucesso." -Level "INFO" -ConsoleOutput

        Write-Log "Configurando *ReceiveBuffers para 2048 em $KeyPath..." -ConsoleOutput
        Set-ItemProperty -Path $KeyPath -Name "*ReceiveBuffers" -Type String -Value 2048 -ErrorAction Stop | Out-Null
        Write-Log "*ReceiveBuffers configurado com sucesso." -Level "INFO" -ConsoleOutput

        Write-Log "Configurando *TransmitBuffers para 4096 em $KeyPath..." -ConsoleOutput
        Set-ItemProperty -Path $KeyPath -Name "*TransmitBuffers" -Type String -Value 4096 -ErrorAction Stop | Out-Null
        Write-Log "*TransmitBuffers configurado com sucesso." -Level "INFO" -ConsoleOutput

        Write-Log "Criando propriedade 'default' em $KeyPath3 com valor 1..." -ConsoleOutput
        New-ItemProperty -Path $KeyPath3 -Name "default" -Type String -Value 1 -ErrorAction Stop | Out-Null
        Write-Log "Propriedade 'default' criada com sucesso." -Level "INFO" -ConsoleOutput

        Write-Log "Criando propriedade 'ParamDesc' em $KeyPath3 com valor 'Receive Side Scaling'..." -ConsoleOutput
        New-ItemProperty -Path $KeyPath3 -Name "ParamDesc" -Type String -Value "Receive Side Scaling" -ErrorAction Stop | Out-Null
        Write-Log "Propriedade 'ParamDesc' criada com sucesso." -Level "INFO" -ConsoleOutput

        Write-Log "Criando propriedade 'type' em $KeyPath3 com valor 'enum'..." -ConsoleOutput
        New-ItemProperty -Path $KeyPath3 -Name "type" -Type String -Value "enum" -ErrorAction Stop | Out-Null
        Write-Log "Propriedade 'type' criada com sucesso." -Level "INFO" -ConsoleOutput

        Write-Log "Criando propriedade '0' em $KeyPath2 com valor 'Disabled'..." -ConsoleOutput
        New-ItemProperty -Path $KeyPath2 -Name "0" -Type String -Value "Disabled" -ErrorAction Stop | Out-Null
        Write-Log "Propriedade '0' criada com sucesso." -Level "INFO" -ConsoleOutput

        Write-Log "Criando propriedade '1' em $KeyPath2 com valor 'Enabled'..." -ConsoleOutput
        New-ItemProperty -Path $KeyPath2 -Name "1" -Type String -Value "Enabled" -ErrorAction Stop | Out-Null
        Write-Log "Propriedade '1' criada com sucesso." -Level "INFO" -ConsoleOutput

        Write-Log "Criando propriedade '1' em $KeyPath4 com valor '1 Queue'..." -ConsoleOutput
        New-ItemProperty -Path $KeyPath4 -Name "1" -Type String -Value "1 Queue" -ErrorAction Stop | Out-Null
        Write-Log "Propriedade '1' criada com sucesso." -Level "INFO" -ConsoleOutput

        Write-Log "Criando propriedade '2' em $KeyPath4 com valor '2 Queue'..." -ConsoleOutput
        New-ItemProperty -Path $KeyPath4 -Name "2" -Type String -Value "2 Queue" -ErrorAction Stop | Out-Null
        Write-Log "Propriedade '2' criada com sucesso." -Level "INFO" -ConsoleOutput

        Write-Log "Criando propriedade '3' em $KeyPath4 com valor '3 Queue'..." -ConsoleOutput
        New-ItemProperty -Path $KeyPath4 -Name "3" -Type String -Value "3 Queue" -ErrorAction Stop | Out-Null
        Write-Log "Propriedade '3' criada com sucesso." -Level "INFO" -ConsoleOutput

        Write-Log "Criando propriedade '4' em $KeyPath4 com valor '4 Queue'..." -ConsoleOutput
        New-ItemProperty -Path $KeyPath4 -Name "4" -Type String -Value "4 Queue" -ErrorAction Stop | Out-Null
        Write-Log "Propriedade '4' criada com sucesso." -Level "INFO" -ConsoleOutput

        Write-Log "Criando propriedade 'default' em $KeyPath5 com valor '2'..." -ConsoleOutput
        New-ItemProperty -Path $KeyPath5 -Name "default" -Type String -Value "2" -ErrorAction Stop | Out-Null
        Write-Log "Propriedade 'default' criada com sucesso." -Level "INFO" -ConsoleOutput

        Write-Log "Criando propriedade 'ParamDesc' em $KeyPath5 com valor 'Maximum Number of RSS Queues'..." -ConsoleOutput
        New-ItemProperty -Path $KeyPath5 -Name "ParamDesc" -Type String -Value "Maximum Number of RSS Queues" -ErrorAction Stop | Out-Null
        Write-Log "Propriedade 'ParamDesc' criada com sucesso." -Level "INFO" -ConsoleOutput

        Write-Log "Criando propriedade 'type' em $KeyPath5 com valor 'enum'..." -ConsoleOutput
        New-ItemProperty -Path $KeyPath5 -Name "type" -Type String -Value "enum" -ErrorAction Stop | Out-Null
        Write-Log "Propriedade 'type' criada com sucesso." -Level "INFO" -ConsoleOutput

        Write-Log "Configurando 'Max' para 6144 em $KeyPath6..." -ConsoleOutput
        Set-ItemProperty -Path $KeyPath6 -Name "Max" -Type String -Value 6144 -ErrorAction Stop | Out-Null
        Write-Log "'Max' configurado com sucesso em $KeyPath6." -Level "INFO" -ConsoleOutput

        Write-Log "Configurando 'Default' para 2048 em $KeyPath6..." -ConsoleOutput
        Set-ItemProperty -Path $KeyPath6 -Name "Default" -Type String -Value 2048 -ErrorAction Stop | Out-Null
        Write-Log "'Default' configurado com sucesso em $KeyPath6." -Level "INFO" -ConsoleOutput

        Write-Log "Configurando 'Max' para 6144 em $KeyPath7..." -ConsoleOutput
        Set-ItemProperty -Path $KeyPath7 -Name "Max" -Type String -Value 6144 -ErrorAction Stop | Out-Null
        Write-Log "'Max' configurado com sucesso em $KeyPath7." -Level "INFO" -ConsoleOutput

        Write-Log "Configurando 'Default' para 4096 em $KeyPath7..." -ConsoleOutput
        Set-ItemProperty -Path $KeyPath7 -Name "Default" -Type String -Value 4096 -ErrorAction Stop | Out-Null
        Write-Log "'Default' configurado com sucesso em $KeyPath7." -Level "INFO" -ConsoleOutput

        Write-Log "Configurações RSS aplicadas com sucesso para o adaptador $AdapterDeviceNumber." -Level "INFO" -ConsoleOutput
      }
      else {
        Write-Log "Caminho $KeyPath não encontrado para o adaptador $AdapterDeviceNumber." -Level "WARNING" -ConsoleOutput
        Write-Colored "Caminho ($KeyPath) Não encontrado." "Vermelho"
      }
    }

    Write-Log "Configuração RSS concluída para todos os adaptadores físicos aplicáveis." -Level "INFO" -ConsoleOutput
  }
  catch {
    $errorMessage = "Erro na função NetworkAdapterRSS: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    throw  # Repropaga o erro
  }
  finally {
    $ErrorActionPreference = $errpref
    Write-Log "Restaurando ErrorActionPreference para $errpref." -ConsoleOutput
    Write-Log "Finalizando função NetworkAdapterRSS." -Level "INFO" -ConsoleOutput
  }
}

function Download-GPUFiles {
  Write-Log "Iniciando função Download-GPUFiles para identificar GPU, criar pasta e baixar arquivos." -ConsoleOutput

  try {
    # Identificar a placa de vídeo ativa
    Write-Log "Obtendo informações da placa de vídeo ativa..." -ConsoleOutput
    $gpuInfo = Get-CimInstance -ClassName Win32_VideoController -ErrorAction Stop | Where-Object { $_.CurrentBitsPerPixel -and $_.AdapterDACType } | Select-Object -First 1
    $gpuName = $gpuInfo.Name
    Write-Log "Placa de vídeo detectada: $gpuName" -ConsoleOutput

    # Definir o caminho da pasta em C:\
    $folderPath = "C:\DownloadsGPU"
    Write-Log "Definindo caminho da pasta como: $folderPath" -ConsoleOutput

    # Verificar se a pasta existe, caso contrário, criá-la
    if (-not (Test-Path -Path $folderPath)) {
      Write-Log "Pasta $folderPath não existe. Criando..." -ConsoleOutput
      New-Item -Path $folderPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
      Write-Log "Pasta $folderPath criada com sucesso." -Level "INFO" -ConsoleOutput
    }
    else {
      Write-Log "Pasta $folderPath já existe. Prosseguindo com os downloads..." -ConsoleOutput
    }

    # Definir os downloads base (comuns a ambas as GPUs)
    $baseDownloads = @(
      @{
        Url      = "https://github.com/wesscd/WindowsGaming/raw/refs/heads/main/MSI_util_v3.exe"
        FileName = "MSI_util_v3.exe"
      },
      @{
        Url      = "https://github.com/wesscd/WindowsGaming/raw/refs/heads/main/IObit.Driver.Booster.Pro.8.1.0.276.Portable.rar"
        FileName = "IObit.Driver.Booster.Pro.8.1.0.276.Portable.rar"
      }
    )

    # Definir downloads específicos por GPU
    if ($gpuName -like "*NVIDIA*" -or $gpuName -like "*GTX*" -or $gpuName -like "*RTX*") {
      Write-Log "Placa NVIDIA detectada. Adicionando driver NVIDIA à lista de downloads..." -ConsoleOutput
      $downloads = $baseDownloads + @(
        @{
          Url      = "https://us.download.nvidia.com/nvapp/client/11.0.3.218/NVIDIA_app_v11.0.3.218.exe"
          FileName = "NVIDIA_app_v11.0.3.218.exe"
        }
      )
    }
    elseif ($gpuName -like "*AMD*" -or $gpuName -like "*Radeon*") {
      Write-Log "Placa AMD detectada. Adicionando driver AMD à lista de downloads..." -ConsoleOutput
      $downloads = $baseDownloads + @(
        @{
          Url      = "https://drivers.amd.com/drivers/installer/24.30/whql/amd-software-adrenalin-edition-25.3.1-minimalsetup-250312_web.exe"
          FileName = "amd-software-adrenalin-edition-25.3.1-minimalsetup-250312_web.exe"
        }
      )
    }
    else {
      Write-Log "Nenhuma placa NVIDIA ou AMD reconhecida. Baixando apenas arquivos base..." -Level "WARNING" -ConsoleOutput
      $downloads = $baseDownloads
    }

    Write-Log "Lista de downloads definida: $($downloads | ForEach-Object { $_.FileName } -join ', ')" -ConsoleOutput

    # Fazer o download de cada arquivo
    foreach ($item in $downloads) {
      $downloadUrl = $item.Url
      $filePath = Join-Path -Path $folderPath -ChildPath $item.FileName
      Write-Log "Iniciando download de $downloadUrl para $filePath..." -ConsoleOutput
      Invoke-WebRequest -Uri $downloadUrl -OutFile $filePath -ErrorAction Stop
      Write-Log "Download de $item.FileName concluído com sucesso em $filePath." -Level "INFO" -ConsoleOutput
    }

    Write-Log "Todos os downloads foram concluídos com sucesso em $folderPath." -Level "INFO" -ConsoleOutput
    Write-Output "Downloads concluídos em: $folderPath"
  }
  catch {
    $errorMessage = "Erro na função Download-GPUFiles: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
    Write-Output $errorMessage
    throw  # Repropaga o erro
  }
  finally {
    Write-Log "Finalizando função Download-GPUFiles." -Level "INFO" -ConsoleOutput
  }
}

function Finished {
  Write-Log "Iniciando função Finished para finalizar o processo de otimização." -ConsoleOutput

  try {
    Clear-Host
    Write-Log "Limpando a tela para exibir mensagem de conclusão." -ConsoleOutput

    Write-Colored "" "Azul"
    Write-Colored "================ Otimização Concluída ================" "Verde"
    Write-Colored "O sistema foi otimizado para desempenho em jogos." "Azul"
    Write-Colored "Reinicie o computador para aplicar todas as alterações." "Amarelo"
    Write-Log "Exibindo mensagem de conclusão: Otimização concluída e instruções para reiniciar." -ConsoleOutput

    do {
      Write-Colored "Deseja reiniciar agora? (S/N)" "Azul"
      Write-Log "Solicitando escolha do usuário para reiniciar (S/N)..." -ConsoleOutput
      $resposta = Read-Host "Digite 'S' para reiniciar agora ou 'N' para sair"
      $resposta = $resposta.Trim().ToUpper()
      Write-Log "Usuário respondeu: $resposta" -ConsoleOutput
    } while ($resposta -ne 'S' -and $resposta -ne 'N')

    if ($resposta -eq 'S') {
      Write-Colored "Reiniciando o computador..." "Vermelho"
      Write-Log "Usuário escolheu reiniciar. Reiniciando o computador..." -ConsoleOutput
      Restart-Computer -Force -ErrorAction Stop
      Write-Log "Comando de reinicialização executado com sucesso." -Level "INFO" -ConsoleOutput
    }
    else {
      Write-Colored "Pressione qualquer tecla para sair..." "Azul"
      Write-Log "Usuário escolheu não reiniciar. Aguardando pressionamento de tecla para sair..." -ConsoleOutput
      [Console]::ReadKey($true) | Out-Null
      Write-Log "Tecla pressionada. Encerrando função." -Level "INFO" -ConsoleOutput
    }
  }
  catch {
    $errorMessage = "Erro na função Finished: $_"
    Write-Log $errorMessage -Level "ERROR" -ConsoleOutput
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

foreach ($tweak in $tweaks) {
  $currentStep++
  $tweakName = $tweak.Split()[0]
  
  Show-ProgressBar -CurrentStep $currentStep -TotalSteps $totalTweaks -TaskName $tweakName
  
  if ($tweakFunctions.ContainsKey($tweakName)) {
    try {
      Invoke-Expression $tweak
    }
    catch {
      Write-Log "Erro ao executar o tweak $tweakName $_" -Level "ERROR" -ConsoleOutput
      Write-Colored "`nErro ao executar $tweakName. Veja o log para detalhes." -Color "VermelhoClaro"
    }
  }
  else {
    Write-Log "Tweak não encontrado: $tweak" -Level "WARNING" -ConsoleOutput
    Write-Colored "`nTweak não encontrado: $tweak" -Color "VermelhoClaro"
  }
  
  Start-Sleep -Milliseconds 100 # Pequena pausa para visualização
}
Write-Host "" # Nova linha após o progresso
