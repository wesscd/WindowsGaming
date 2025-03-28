# Modules\PerformanceTweaks.ps1

# Função para escrever texto colorido (se não for movida para outro módulo)
function Write-Colored {
  param (
    [string]$Text,
    [ConsoleColor]$Color = 'White'
  )
  Write-Host $Text -ForegroundColor $Color
}

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

# Set ram value on Threshold no regedit
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

# Caminho do registro
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control"
$regName = "SvcHostSplitThresholdInKB"

# Converte para decimal antes de gravar no registro
$value = [int]$value

# Verifica se a chave já existe
if (-not (Get-ItemProperty -Path "$regPath" -Name "$regName" -ErrorAction SilentlyContinue)) {
  # Se não existir, cria a propriedade no registro
  New-ItemProperty -Path "$regPath" -Name "$regName" -Value $value -PropertyType DWord | Out-Null
  Escrever-Colorido "Registro criado com o valor correto: 0x$($value.ToString("X"))" "Verde"
}
else {
  # Se já existir, apenas atualiza o valor
  Set-ItemProperty -Path "$regPath" -Name "$regName" -Value $value
  Escrever-Colorido "Registro atualizado com o valor correto: 0x$($value.ToString("X"))" "Verde"
}

# Verifica o valor após a modificação
$newValue = Get-ItemProperty -Path "$regPath" -Name "$regName"
Escrever-Colorido "Novo valor do registro: 0x$($newValue.$regName.ToString("X"))" "Verde"
}

# Set virtual memory on regedit
function Set-MemoriaVirtual-Registry {
  Write-Host "Informe a letra do drive (ex: C) para configurar a memória virtual:" -ForegroundColor Cyan
  $Drive = Read-Host
  $DrivePath = "${Drive}:"
  # Validação do drive
  if (-not (Test-Path $DrivePath)) {
    Write-Host "Drive $DrivePath não encontrado." -ForegroundColor Red
    return
  }
  # Cálculo da memória RAM total em MB
  $TotalRAM = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1MB)
  $InitialSize = 9081  # Valor fixo conforme comum em scripts originais
  $MaxSize = [math]::Round($TotalRAM * 1.5)  # Máximo como 1,5x a RAM
  $RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
  try {
    Set-ItemProperty -Path $RegPath -Name "PagingFiles" -Value "$DrivePath\pagefile.sys $InitialSize $MaxSize" -ErrorAction Stop
    Set-ItemProperty -Path $RegPath -Name "AutomaticManagedPagefile" -Value 0 -ErrorAction Stop
    Write-Host "Memória virtual configurada para $DrivePath com inicial $InitialSize MB e máximo $MaxSize MB." -ForegroundColor Green
    Write-Host "Reinicie o computador para aplicar as mudanças."
  }
  catch {
    Write-Host "Erro ao configurar memória virtual: $_" -ForegroundColor Red
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
  Escrever-Colorido "Iniciando o download do arquivo..." "Verde"
  try {
    Invoke-WebRequest -Uri $downloadUrl -OutFile $downloadPath
    Escrever-Colorido "Arquivo baixado com sucesso!" "Verde"
  }
  catch {
    Escrever-Colorido "Erro ao baixar o arquivo: $_" "Vermelho"
    return
  }

  # Verificar se a pasta de extração existe, caso contrário, criar
  if (-Not (Test-Path -Path $extractPath)) {
    Escrever-Colorido "Criando a pasta de extração..." "Verde"
    New-Item -ItemType Directory -Path $extractPath
  }

  # Caminho do 7z.exe
  $sevenZipPath = "C:\Program Files\7-Zip\7z.exe"  # Altere conforme o local do seu 7z.exe

  # Verificar se o 7z está instalado
  if (Test-Path -Path $sevenZipPath) {
    Escrever-Colorido "Extraindo o conteudo do arquivo usando 7-Zip..." "Verde"
    try {
      # Extrair diretamente na pasta ISLC
      & $sevenZipPath x $downloadPath -o"$extractPath" -y
      Escrever-Colorido "Arquivo extraido com sucesso para $extractPath" "Verde"
          
      # Renomear a pasta extraída para MEM
      $extractedFolderPath = "$extractPath\ISLC v1.0.3.4"

      if (Test-Path -Path $extractedFolderPath) {
        Rename-Item -Path $extractedFolderPath -NewName $newFolderName
        Escrever-Colorido "Pasta renomeada para '$newFolderName'." "Verde"
      }
      else {
        Escrever-Colorido "Pasta extraída não encontrada." "Vermelho"
      }
    }
    catch {
      Escrever-Colorido "Erro ao extrair o arquivo: $_" "Vermelho"
    }
  }
  else {
    Escrever-Colorido "7-Zip não encontrado no caminho especificado." "Amarelo"
  }

  Remove-Item -Path $downloadPath -Force
  Escrever-Colorido "Excluindo $downloadPath" "Verde"

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
    Escrever-Colorido "Arquivo de configuracao encontrado. Atualizando..." "Verde"

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
      Escrever-Colorido "Arquivo de configuracao atualizado com sucesso!" "Verde"
    }
    catch {
      Escrever-Colorido "Erro ao atualizar o arquivo de configuracao: $_" "Vermelho"
    }
  }
  else {
    Escrever-Colorido "Arquivo de configuracao nao encontrado em $configFilePath" "Amarelo"
  }
}

#Apply PC Optimizations
Function ApplyPCOptimizations {
  Write-Output "Aplicando otimizacoes..."
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -Type DWord -Value 0
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Type DWord -Value 10
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "AlwaysOn" -Type DWord -Value 1
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "LazyMode" -Type DWord -Value 1
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "LazyModeTimeout" -Type DWord -Value 25000
}

#Enable Or Disable MSI Mode For Supported Cards, WARNING ENABLING MSI MODE MIGHT CRUSH YOUR SYSTEM! IF IT HAPPENS PLEASE RESTORE LAST WORKING SYSTEM RESTORE POINT AND DON'T ENABLE MSI MODE ON THIS SYSTEM AGAIN!
Function MSIMode {
  $errpref = $ErrorActionPreference #save actual preference
  $ErrorActionPreference = "silentlycontinue"
  $GPUIDS = @(
(Get-CimInstance -ClassName Win32_VideoController | Select-Object -ExpandProperty PNPDeviceID | Select-Object -Skip 2 | Format-List | Out-String).Trim()
  )
  foreach ($GPUID in $GPUIDS) {
    $CheckDeviceDes = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\$GPUID").DeviceDesc
  } if (($CheckDeviceDes -like "*GTX*") -or ($CheckDeviceDes -like "*RTX*") -or ($CheckDeviceDes -like "*AMD*")) {
    'GTX/RTX/AMD Compatible Card Found! Enabling MSI Mode...'
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\$GPUID\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties\" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\$GPUID\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties\" -Name "MSISupported" -Type DWord -Value 1
  }
  else {
    'No GTX/RTX/AMD Compatible Card Found! Skiping...'
  }
  $ErrorActionPreference = $errpref #restore previous preference	
}

#Applying Nvidia Tweaks if GTX/RTX Card Detected!
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
  Disable-NetAdapterLso -Name "*"  | Out-Null

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
      Escrever-Colorido "Caminho ($KeyPath) Nao encontrado." "Vermelho"
    }
  }
  $ErrorActionPreference = $errpref #restore previous preference
}

# Exportar funções para uso externo
Export-ModuleMember -Function SlowUpdatesTweaks, Set-RamThreshold, Set-MemoriaVirtual-Registry, DownloadAndExtractISLC, UpdateISLCConfig, ApplyPCOptimizations, MSIMode, NvidiaTweaks, AMDGPUTweaks, NetworkOptimizations, DisableNagle, NetworkAdapterRSS