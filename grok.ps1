# TechRemote Ultimate Windows Debloater Gaming v.0.7.0.2
# Otimizado por Grok 3 em 27/03/2025
# Fonte Original: https://github.com/wesscd/WindowsGaming

# Configuração inicial
[Console]::OutputEncoding = [System.Text.Encoding]::GetEncoding(860)
$ErrorActionPreference = "SilentlyContinue"
$host.ui.RawUI.WindowTitle = "-- TechRemote Ultimate Windows Debloater Gaming v.0.7.0.2 (VIA GROK) --"

# Função para escrita colorida
function Write-Colored {
    param (
        [string]$Text,
        [ConsoleColor]$Color
    )
    $previousColor = $host.UI.RawUI.ForegroundColor
    $host.UI.RawUI.ForegroundColor = $Color
    [Console]::WriteLine($Text)
    $host.UI.RawUI.ForegroundColor = $previousColor
}

# Exibição inicial
function Show-Intro {
    Clear-Host
    $intro = @(
        "", "████████╗███████╗ ██████╗██╗  ██╗    ██████╗ ███████╗███╗   ███╗ ██████╗ ████████╗███████╗",
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
    $colors = @("Green", "Green", "Green", "Green", "Green", "Green", "Green", "Blue", "Yellow", "Yellow", "Red")
    for ($i = 0; $i -lt $intro.Length; $i++) {
        Write-Colored $intro[$i] $colors[$i]
    }
    [Console]::ReadKey($true) | Out-Null
}

# Lista de tweaks atualizada
$tweaks = @(
    "RequireAdmin", "CreateRestorePoint", "InstallEssentialTools", "OptimizeUpdates",
    "InstallOptimizationTools", "CleanSystem", "OptimizeMemory", "InstallISLC",
    "ConfigureISLC", "CheckWindowsActivation", "OptimizePerformance",
    "HandleXboxFeatures", "EnableMSIMode", "ApplyPrivacyTweaks", "OptimizeNetwork",
    "EnableEssentialServices", "OptimizePowerPlan", "DisableVisualEffects",
    "OptimizeStorage", "ReduceStartupLoad", "CleanRegistry", "FinalizeSetup"
)

# Funções existentes (mantidas)
function RequireAdmin {
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Start-Process Powershell -ArgumentList "-ExecutionPolicy bypass -NoProfile -File `"$PSCommandPath`"" -Verb RunAs
        Exit
    }
}

function CreateRestorePoint {
    Write-Colored "Criando ponto de restauração..." "Yellow"
    Enable-ComputerRestore -Drive $env:SystemDrive -ErrorAction SilentlyContinue
    Checkpoint-Computer -Description "TechRemote Optimization" -RestorePointType "MODIFY_SETTINGS" -ErrorAction SilentlyContinue
}

function InstallEssentialTools {
    Write-Colored "Instalando ferramentas essenciais..." "Yellow"
    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    }
    choco install -y 7zip vcredist2010 --force
}

function OptimizeUpdates {
    Write-Colored "Otimizando Windows Update..." "Yellow"
    $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
    $settings = @{
        "DeferFeatureUpdates" = 1
        "DeferQualityUpdates" = 1
        "DeferFeatureUpdatesPeriodInDays" = 30
        "DeferQualityUpdatesPeriodInDays" = 4
    }
    foreach ($key in $settings.Keys) {
        Set-ItemProperty -Path $path -Name $key -Value $settings[$key] -Type DWord
    }
}

function InstallOptimizationTools {
    Write-Colored "Instalando ferramentas de otimização..." "Yellow"
    $temp = $env:TEMP
    $urls = @{
        "config" = "https://raw.githubusercontent.com/wesscd/WindowsGaming/master/ooshutup10.cfg"
        "exe" = "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe"
    }
    foreach ($item in $urls.Keys) {
        Invoke-WebRequest -Uri $urls[$item] -OutFile "$temp\$item" -ErrorAction Stop
    }
    & "$temp\exe" "$temp\config" /quiet
    Start-Sleep -Seconds 5
    Remove-Item "$temp\config", "$temp\exe" -Force
}

function CleanSystem {
    Write-Colored "Limpando sistema..." "Yellow"
    $commands = @(
        "netsh winsock reset", "netsh int ip reset", "ipconfig /release",
        "ipconfig /renew", "ipconfig /flushdns"
    )
    foreach ($cmd in $commands) { cmd /c "$cmd 2>nul" | Out-Null }
    Get-ChildItem -Path $env:TEMP -Exclude "dmtmp" -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse
    Dism /Online /Cleanup-Image /StartComponentCleanup | Out-Null
}

function OptimizeMemory {
    Write-Colored "Otimizando memória..." "Yellow"
    $ram = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB)
    $thresholds = @{4=0x400000; 8=0x800000; 16=0x1000000; 32=0x2000000}
    $value = $thresholds[[math]::Min($ram, 32)]
    if ($value) {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -Value $value -Type DWord
    }
}

function InstallISLC {
    Write-Colored "Instalando ISLC..." "Yellow"
    $url = "https://raw.githubusercontent.com/wesscd/WindowsGaming/main/ISLC%20v1.0.3.4.exe"
    Invoke-WebRequest -Uri $url -OutFile "C:\ISLC.exe"
    if (Test-Path "C:\Program Files\7-Zip\7z.exe") {
        & "C:\Program Files\7-Zip\7z.exe" x "C:\ISLC.exe" -o"C:\" -y
        Rename-Item "C:\ISLC v1.0.3.4" "ISLC" -ErrorAction SilentlyContinue
    }
    Remove-Item "C:\ISLC.exe" -Force -ErrorAction SilentlyContinue
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\ISLC.lnk")
    $shortcut.TargetPath = "C:\ISLC\Intelligent standby list cleaner ISLC.exe"
    $shortcut.Save()
}

function ConfigureISLC {
    Write-Colored "Configurando ISLC..." "Yellow"
    $configPath = "C:\ISLC\Intelligent standby list cleaner ISLC.exe.Config"
    if (Test-Path $configPath) {
        $config = [xml](Get-Content $configPath)
        $ram = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1MB / 2)
        $settings = @{"Free memory"=$ram; "Start minimized"="True"; "Wanted timer"="0.50"; "Custom timer"="True"; "TaskScheduler"="True"}
        foreach ($key in $settings.Keys) {
            $node = $config.configuration.appSettings.add | Where-Object {$_.key -eq $key}
            if ($node) { $node.value = $settings[$key] }
        }
        $config.Save($configPath)
    }
}

function CheckWindowsActivation {
    Write-Colored "Verificando ativação do Windows..." "Yellow"
    $status = (Get-CimInstance -ClassName SoftwareLicensingProduct -Filter "Name like 'Windows%'" | Where-Object {$_.PartialProductKey}).LicenseStatus
    if ($status -ne 1) {
        Write-Colored "Windows não ativado. Tentando ativar..." "Red"
        irm https://get.activated.win | iex
    }
}

function OptimizePerformance {
    Write-Colored "Aplicando otimizações de desempenho..." "Yellow"
    $settings = @(
        @{"Path"="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"; "Name"="SystemResponsiveness"; "Value"=0},
        @{"Path"="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"; "Name"="NetworkThrottlingIndex"; "Value"=10}
    )
    foreach ($item in $settings) {
        Set-ItemProperty -Path $item.Path -Name $item.Name -Value $item.Value -Type DWord
    }
}

function HandleXboxFeatures {
    Write-Colored "Configurando recursos do Xbox..." "Yellow"
    do {
        Clear-Host
        Write-Colored "================ Configurar Recursos do Xbox ================" "Blue"
        Write-Colored "AVISO: Remover aplicativos do Xbox desativará o Win+G!" "Red"
        Write-Colored "D: Desabilitar recursos do Xbox" "Blue"
        Write-Colored "H: Habilitar recursos do Xbox" "Blue"
        Write-Colored "P: Pular esta configuração" "Blue"
        $choice = Read-Host "Escolha uma opção (D/H/P)"
    } until ($choice -match "^[dDhHpP]$")
    
    if ($choice -eq "D" -or $choice -eq "d") {
        $xboxApps = @("Microsoft.XboxApp", "Microsoft.XboxIdentityProvider", "Microsoft.XboxSpeechToTextOverlay", "Microsoft.XboxGameOverlay", "Microsoft.Xbox.TCUI")
        foreach ($app in $xboxApps) { Get-AppxPackage $app | Remove-AppxPackage -ErrorAction SilentlyContinue }
        Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Value 0 -Type DWord
        $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR"
        if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        Set-ItemProperty -Path $path -Name "AllowGameDVR" -Value 0 -Type DWord
        Write-Colored "Recursos do Xbox desabilitados." "Green"
    }
    elseif ($choice -eq "H" -or $choice -eq "h") {
        $xboxApps = @("Microsoft.XboxApp", "Microsoft.XboxIdentityProvider", "Microsoft.XboxSpeechToTextOverlay", "Microsoft.XboxGameOverlay", "Microsoft.Xbox.TCUI")
        foreach ($app in $xboxApps) {
            $pkg = Get-AppxPackage -AllUsers $app
            if ($pkg) { Add-AppxPackage -DisableDevelopmentMode -Register "$($pkg.InstallLocation)\AppXManifest.xml" -ErrorAction SilentlyContinue }
        }
        Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Value 1 -Type DWord
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -ErrorAction SilentlyContinue
        Write-Colored "Recursos do Xbox habilitados." "Green"
    }
    else {
        Write-Colored "Configuração do Xbox pulada." "Yellow"
    }
    Start-Sleep -Seconds 2
}

function EnableMSIMode {
    Write-Colored "Habilitando MSI Mode (cuidado: pode causar instabilidade)..." "Yellow"
    $gpu = Get-CimInstance -ClassName Win32_VideoController | Where-Object {$_.PNPDeviceID -notlike "ROOT\*"}
    if ($gpu.PNPDeviceID -and ($gpu.Name -like "*GTX*" -or $gpu.Name -like "*RTX*" -or $gpu.Name -like "*AMD*")) {
        $path = "HKLM:\SYSTEM\CurrentControlSet\Enum\$($gpu.PNPDeviceID)\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties"
        if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        Set-ItemProperty -Path $path -Name "MSISupported" -Value 1 -Type DWord
        Write-Colored "MSI Mode habilitado para $($gpu.Name)." "Green"
    }
    else {
        Write-Colored "Nenhuma GPU compatível encontrada para MSI Mode." "Yellow"
    }
}

function ApplyPrivacyTweaks {
    Write-Colored "Aplicando ajustes de privacidade..." "Yellow"
    $privacy = @(
        @{"Path"="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"; "Name"="AllowTelemetry"; "Value"=0},
        @{"Path"="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; "Name"="EnableSmartScreen"; "Value"=0},
        @{"Path"="HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"; "Name"="DisabledByGroupPolicy"; "Value"=1}
    )
    foreach ($item in $privacy) {
        if (-not (Test-Path $item.Path)) { New-Item -Path $item.Path -Force | Out-Null }
        Set-ItemProperty -Path $item.Path -Name $item.Name -Value $item.Value -Type DWord
    }
}

function OptimizeNetwork {
    Write-Colored "Otimizando rede..." "Yellow"
    $tcpSettings = @(
        "EcnCapability=disabled", "Timestamps=disabled", "MaxSynRetransmissions=2",
        "InitialRto=2000", "MinRto=300", "CongestionProvider=CTCP"
    )
    foreach ($setting in $tcpSettings) { 
        $key, $value = $setting.Split('=')
        Set-NetTCPSetting -SettingName "internet" -$key $value -ErrorAction SilentlyContinue
    }
    netsh int tcp set global rss=enabled | Out-Null
    netsh int tcp set global autotuninglevel=normal | Out-Null
}

function EnableEssentialServices {
    Write-Colored "Configurando serviços essenciais..." "Yellow"
    $services = @(
        @{Name="SysMain"; Desc="Acelera o carregamento de programas frequentes"},
        @{Name="PcaSvc"; Desc="Assistente de compatibilidade de programas"},
        @{Name="WSearch"; Desc="Indexação para busca rápida"}
    )
    
    foreach ($service in $services) {
        do {
            Clear-Host
            Write-Colored "================ Configurar Serviço: $($service.Name) ================" "Blue"
            Write-Colored "Descrição: $($service.Desc)" "White"
            Write-Colored "S: Ativar o serviço $($service.Name)" "Blue"
            Write-Colored "N: Pular este serviço" "Blue"
            $choice = Read-Host "Deseja ativar $($service.Name)? (S/N)"
        } until ($choice -match "^[sSnN]$")
        
        if ($choice -eq "S" -or $choice -eq "s") {
            $svc = Get-Service -Name $service.Name -ErrorAction SilentlyContinue
            if ($svc) {
                if ($svc.Status -ne "Running") {
                    Start-Service -Name $service.Name -ErrorAction SilentlyContinue
                    Set-Service -Name $service.Name -StartupType Automatic -ErrorAction SilentlyContinue
                    Write-Colored "Serviço $($service.Name) ativado." "Green"
                }
                else {
                    Write-Colored "Serviço $($service.Name) já está em execução." "Green"
                }
            }
            else {
                Write-Colored "Serviço $($service.Name) não encontrado." "Red"
            }
        }
        else {
            Write-Colored "Serviço $($service.Name) pulado." "Yellow"
        }
        Start-Sleep -Seconds 1
    }
}

# Novas funções para maior performance
function OptimizePowerPlan {
    Write-Colored "Otimizando plano de energia..." "Yellow"
    $gamingPlan = powercfg /l | Select-String "High performance" -ErrorAction SilentlyContinue
    if ($gamingPlan) {
        $guid = $gamingPlan -replace ".*GUID: ([a-z0-9-]+).*", '$1'
        powercfg /setactive $guid
    }
    else {
        powercfg /duplicatescheme 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
        $newPlan = powercfg /l | Select-String "High performance" | Select-Object -First 1
        $guid = $newPlan -replace ".*GUID: ([a-z0-9-]+).*", '$1'
        powercfg /setactive $guid
    }
    powercfg /change monitor-timeout-ac 0
    powercfg /change standby-timeout-ac 0
    powercfg /change hibernate-timeout-ac 0
    Write-Colored "Plano de energia configurado para Alto Desempenho." "Green"
}

function DisableVisualEffects {
    Write-Colored "Desativando efeitos visuais desnecessários..." "Yellow"
    $path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects"
    if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
    Set-ItemProperty -Path $path -Name "VisualFXSetting" -Value 2 -Type DWord
    $settings = @(
        @{"Path"="HKCU:\Control Panel\Desktop"; "Name"="UserPreferencesMask"; "Value"=([byte[]](0x90,0x12,0x03,0x80,0x10,0x00,0x00,0x00))}
    )
    foreach ($item in $settings) {
        Set-ItemProperty -Path $item.Path -Name $item.Name -Value $item.Value -Type Binary
    }
    Write-Colored "Efeitos visuais ajustados para melhor desempenho." "Green"
}

function OptimizeStorage {
    Write-Colored "Otimizando armazenamento..." "Yellow"
    $drives = Get-Disk | Where-Object {$_.PartitionStyle -eq "GPT" -or $_.PartitionStyle -eq "MBR"}
    foreach ($drive in $drives) {
        $partitions = Get-Partition -DiskNumber $drive.Number -ErrorAction SilentlyContinue
        foreach ($partition in $partitions) {
            if ($partition.DriveLetter) {
                # Desativar indexação em drives
                $drivePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
                if (-not (Test-Path $drivePath)) { New-Item -Path $drivePath -Force | Out-Null }
                Set-ItemProperty -Path $drivePath -Name "DisableSearch" -Value 1 -Type DWord
                
                # Verificar se é SSD e desativar desfragmentação automática
                if ((Get-PhysicalDisk | Where-Object {$_.DeviceId -eq $drive.Number}).MediaType -eq "SSD") {
                    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Dfrg\BootOptimizeFunction" -Name "Enable" -Value "N" -Type String
                    Write-Colored "Desfragmentação desativada para SSD em $($partition.DriveLetter):" "Green"
                }
            }
        }
    }
}

function ReduceStartupLoad {
    Write-Colored "Reduzindo carga de inicialização..." "Yellow"
    $path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"
    if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
    
    # Desativar programas comuns desnecessários
    $startupItems = @("OneDrive", "CCleaner", "WindowsDefender")
    foreach ($item in $startupItems) {
        if (Get-ItemProperty -Path $path -Name $item -ErrorAction SilentlyContinue) {
            Set-ItemProperty -Path $path -Name $item -Value ([byte[]](0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)) -Type Binary
        }
    }
    
    # Reduzir tempo de espera do menu de boot
    bcdedit /timeout 5 | Out-Null
    Write-Colored "Carga de inicialização otimizada." "Green"
}

function CleanRegistry {
    Write-Colored "Limpando registro..." "Yellow"
    $extensions = @(".3mf", ".bmp", ".fbx", ".gif", ".jfif", ".jpe", ".jpeg", ".jpg", ".png", ".tif", ".tiff")
    foreach ($ext in $extensions) {
        Remove-ItemProperty -Path "HKCR:\SystemFileAssociations\$ext\Shell\" -Name "3D Edit" -ErrorAction SilentlyContinue
    }
}

function FinalizeSetup {
    Write-Colored "Configuração concluída!" "Green"
    $oemPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation"
    if (-not (Test-Path $oemPath)) { New-Item -Path $oemPath -Force | Out-Null }
    $oemSettings = @{
        "Manufacturer" = "PC Otimizado por Cesar Marques (Barao)"
        "Model" = "Otimização, Hardware, Infra & Redes"
        "SupportURL" = "http://techremote.com.br"
        "SupportPhone" = "+55 16 99263-6487"
    }
    foreach ($key in $oemSettings.Keys) {
        Set-ItemProperty -Path $oemPath -Name $key -Value $oemSettings[$key] -Type String
    }
    Write-Colored "Reinicie o PC para aplicar todas as mudanças." "Green"
    Start-Process "http://techremote.com.br"
}

# Execução principal
Show-Intro
New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT -ErrorAction SilentlyContinue | Out-Null
New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -ErrorAction SilentlyContinue | Out-Null

foreach ($tweak in $tweaks) {
    try {
        Write-Colored "Executando $tweak..." "Cyan"
        Invoke-Expression $tweak
    } catch {
        Write-Colored "Erro ao executar ${tweak}: $_" "Red"
    }
}