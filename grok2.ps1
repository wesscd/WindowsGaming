[Console]::OutputEncoding = [System.Text.Encoding]::GetEncoding(860)
$ErrorActionPreference = "SilentlyContinue"
$host.ui.RawUI.WindowTitle = "-- TechRemote Ultimate Windows Debloater Gaming v.0.7.0.1 --"

function Escrever-Colorido {
    param ([string]$Texto, [ConsoleColor]$Cor)
    $corAnterior = $host.UI.RawUI.ForegroundColor
    $host.UI.RawUI.ForegroundColor = $Cor
    Write-Host $Texto
    $host.UI.RawUI.ForegroundColor = $corAnterior
}

Clear-Host
$intro = @("", "████████╗███████╗ ██████╗██╗  ██╗    ██████╗ ███████╗███╗   ███╗ ██████╗ ████████╗███████╗", "╚══██╔══╝██╔════╝██╔════╝██║  ██║    ██╔══██╗██╔════╝████╗ ████║██╔═══██╗╚══██╔══╝██╔════╝", "   ██║   █████╗  ██║     ███████║    ██████╔╝█████╗  ██╔████╔██║██║   ██║   ██║   █████╗  ", "   ██║   ██╔══╝  ██║     ██╔══██║    ██╔══██╗██╔══╝  ██║╚██╔╝██║██║   ██║   ██║   ██╔══╝  ", "   ██║   ███████╗╚██████╗██║  ██║    ██║  ██║███████╗██║ ╚═╝ ██║╚██████╔╝   ██║   ███████╗", "   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝    ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝ ╚═════╝    ╚═╝   ╚══════╝", "", "Bem vindo ao TechRemote Ultimate Windows Debloater Gaming", "Este script otimizará o desempenho do seu sistema Windows.", "Um ponto de restauração será criado antes de prosseguir.", "DESATIVE SEU ANTIVÍRUS e PRESSIONE QUALQUER TECLA para continuar!")
$cores = @("Green", "Green", "Green", "Green", "Green", "Green", "Green", "Blue", "Yellow", "Yellow", "Red")
for ($i = 0; $i -lt $intro.Length; $i++) { Escrever-Colorido $intro[$i] $cores[$i] }
[Console]::ReadKey($true) | Out-Null

$tweaks = @("RequireAdmin", "CreateRestorePoint", "InstallMVC", "Install7Zip", "OptimizeUpdates", "InstallOptimizationTools", "CleanSystem", "OptimizeMemory", "Setar-MemoriaVirtual", "InstallISLC", "ConfigureISLC", "CheckWindowsActivation", "OptimizePerformance", "askXBOX", "EnableMSIMode", "NvidiaTweaks", "AMDTweaks", "Ativar-Servicos", "OptimizeNetwork", "UltimateCleaner", "CleanRegistry", "FinalizeSetup")

function RequireAdmin {
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Start-Process Powershell -ArgumentList '-ExecutionPolicy bypass -NoProfile -File "$PSCommandPath"' -Verb RunAs
        Exit
    }
}

function CreateRestorePoint {
    Escrever-Colorido "Criando ponto de restauração..." "Yellow"
    Enable-ComputerRestore -Drive $env:SystemDrive
    Checkpoint-Computer -Description "TechRemote Optimization" -RestorePointType "MODIFY_SETTINGS"
}

function InstallMVC {
    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    }
    choco install -y vcredist2010
}

function Install7Zip {
    choco install -y 7zip
}

function OptimizeUpdates {
    Escrever-Colorido "Otimizando Windows Update..." "Yellow"
    $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    if (-not (Test-Path $path)) { New-Item -Path $path -Force }
    Set-ItemProperty -Path $path -Name "DeferFeatureUpdates" -Value 1 -Type DWord
    Set-ItemProperty -Path $path -Name "DeferQualityUpdates" -Value 1 -Type DWord
    Set-ItemProperty -Path $path -Name "DeferFeatureUpdatesPeriodInDays" -Value 30 -Type DWord
    Set-ItemProperty -Path $path -Name "DeferQualityUpdatesPeriodInDays" -Value 4 -Type DWord
}

function InstallOptimizationTools {
    Escrever-Colorido "Instalando ferramentas de otimização..." "Yellow"
    $temp = $env:TEMP
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/wesscd/WindowsGaming/master/ooshutup10.cfg" -OutFile "$temp\ooshutup10.cfg"
    Invoke-WebRequest -Uri "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe" -OutFile "$temp\OOSU10.exe"
    & "$temp\OOSU10.exe" "$temp\ooshutup10.cfg" /quiet
    Remove-Item "$temp\ooshutup10.cfg"
    Remove-Item "$temp\OOSU10.exe"
}

function CleanSystem {
    Escrever-Colorido "Limpando sistema..." "Yellow"
    cmd /c "netsh winsock reset 2>nul"
    cmd /c "netsh int ip reset 2>nul"
    cmd /c "ipconfig /release 2>nul"
    cmd /c "ipconfig /renew 2>nul"
    cmd /c "ipconfig /flushdns 2>nul"
    Get-ChildItem -Path $env:TEMP -Exclude "dmtmp" -Recurse | Remove-Item -Force -Recurse
}

function OptimizeMemory {
    $ram = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB)
    if ($ram -le 4) { $value = 0x400000 } elseif ($ram -le 8) { $value = 0x800000 } elseif ($ram -le 16) { $value = 0x1000000 } else { $value = 0x2000000 }
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -Value $value -Type DWord
}

function Setar-MemoriaVirtual {
    Escrever-Colorido "Configurando memória virtual..." "Yellow"
    $ram = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB
    $minSize = [math]::Round($ram * 1024 * 1.5)
    $maxSize = [math]::Round($ram * 1024 * 3)
    wmic computersystem where name="%computername%" set AutomaticManagedPagefile=False
    wmic pagefileset where name="C:\\pagefile.sys" set InitialSize=$minSize,MaximumSize=$maxSize
}

function InstallISLC {
    Escrever-Colorido "Instalando ISLC..." "Yellow"
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/wesscd/WindowsGaming/main/ISLC%20v1.0.3.4.exe" -OutFile "C:\ISLC.exe"
    & "C:\Program Files\7-Zip\7z.exe" x "C:\ISLC.exe" -o"C:\" -y
    Rename-Item "C:\ISLC v1.0.3.4" "ISLC"
    Remove-Item "C:\ISLC.exe" -Force
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\ISLC.lnk")
    $shortcut.TargetPath = "C:\ISLC\Intelligent standby list cleaner ISLC.exe"
    $shortcut.Save()
}

function ConfigureISLC {
    Escrever-Colorido "Configurando ISLC..." "Yellow"
    $config = [xml](Get-Content "C:\ISLC\Intelligent standby list cleaner ISLC.exe.Config")
    $ram = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1MB / 2
    ($config.configuration.appSettings.add | Where-Object {$_.key -eq "Free memory"}).value = $ram
    ($config.configuration.appSettings.add | Where-Object {$_.key -eq "Start minimized"}).value = "True"
    ($config.configuration.appSettings.add | Where-Object {$_.key -eq "Wanted timer"}).value = "0.50"
    ($config.configuration.appSettings.add | Where-Object {$_.key -eq "Custom timer"}).value = "True"
    ($config.configuration.appSettings.add | Where-Object {$_.key -eq "TaskScheduler"}).value = "True"
    $config.Save("C:\ISLC\Intelligent standby list cleaner ISLC.exe.Config")
}

function CheckWindowsActivation {
    Escrever-Colorido "Verificando ativação do Windows..." "Yellow"
    if ((Get-CimInstance -ClassName SoftwareLicensingProduct -Filter "Name like 'Windows%'" | Where-Object {$_.PartialProductKey}).LicenseStatus -ne 1) {
        Escrever-Colorido "Windows não ativado. Tentando ativar..." "Red"
        irm https://get.activated.win | iex
    }
}

function OptimizePerformance {
    Escrever-Colorido "Aplicando otimizações de desempenho..." "Yellow"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -Value 0 -Type DWord
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Value 10 -Type DWord
}

function askXBOX {
    do {
        Clear-Host
        Escrever-Colorido "================ Configurar Recursos do Xbox ================" "Blue"
        Escrever-Colorido "AVISO: Remover aplicativos do Xbox desativará o Win+G!" "Red"
        Escrever-Colorido "D: Desabilitar recursos do Xbox" "Blue"
        Escrever-Colorido "H: Habilitar recursos do Xbox" "Blue"
        Escrever-Colorido "P: Pular esta configuração" "Blue"
        $choice = Read-Host "Escolha uma opção (D/H/P)"
    } until ($choice -match "^[dDhHpP]$")
    if ($choice -eq "D" -or $choice -eq "d") {
        Get-AppxPackage "Microsoft.XboxApp" | Remove-AppxPackage
        Get-AppxPackage "Microsoft.XboxIdentityProvider" | Remove-AppxPackage
        Get-AppxPackage "Microsoft.XboxSpeechToTextOverlay" | Remove-AppxPackage
        Get-AppxPackage "Microsoft.XboxGameOverlay" | Remove-AppxPackage
        Get-AppxPackage "Microsoft.Xbox.TCUI" | Remove-AppxPackage
        Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Value 0 -Type DWord
        $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR"
        if (-not (Test-Path $path)) { New-Item -Path $path -Force }
        Set-ItemProperty -Path $path -Name "AllowGameDVR" -Value 0 -Type DWord
        Escrever-Colorido "Recursos do Xbox desabilitados." "Green"
    }
    elseif ($choice -eq "H" -or $choice -eq "h") {
        $apps = @("Microsoft.XboxApp", "Microsoft.XboxIdentityProvider", "Microsoft.XboxSpeechToTextOverlay", "Microsoft.XboxGameOverlay", "Microsoft.Xbox.TCUI")
        foreach ($app in $apps) {
            $pkg = Get-AppxPackage -AllUsers $app
            if ($pkg) { Add-AppxPackage -DisableDevelopmentMode -Register "$($pkg.InstallLocation)\AppXManifest.xml" }
        }
        Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Value 1 -Type DWord
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR"
        Escrever-Colorido "Recursos do Xbox habilitados." "Green"
    }
    Start-Sleep -Seconds 2
}

function EnableMSIMode {
    Escrever-Colorido "Habilitando MSI Mode (cuidado: pode causar instabilidade)..." "Yellow"
    $gpu = Get-CimInstance -ClassName Win32_VideoController | Where-Object {$_.PNPDeviceID -notlike "ROOT\*"}
    if ($gpu.PNPDeviceID -and ($gpu.Name -like "*GTX*" -or $gpu.Name -like "*RTX*" -or $gpu.Name -like "*AMD*")) {
        $path = "HKLM:\SYSTEM\CurrentControlSet\Enum\$($gpu.PNPDeviceID)\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties"
        if (-not (Test-Path $path)) { New-Item -Path $path -Force }
        Set-ItemProperty -Path $path -Name "MSISupported" -Value 1 -Type DWord
    }
}

function NvidiaTweaks {
    Escrever-Colorido "Aplicando tweaks para GPUs NVIDIA..." "Yellow"
    $path = "HKLM:\SYSTEM\CurrentControlSet\Services\nvlddmkm"
    if (Test-Path $path) {
        Set-ItemProperty -Path $path -Name "DisableWriteCombining" -Value 1 -Type DWord
        Set-ItemProperty -Path $path -Name "EnableTiledDisplay" -Value 0 -Type DWord
    }
}

function AMDTweaks {
    Escrever-Colorido "Aplicando tweaks para GPUs AMD..." "Yellow"
    $path = "HKLM:\SYSTEM\CurrentControlSet\Services\amdkmdag"
    if (Test-Path $path) {
        Set-ItemProperty -Path $path -Name "DisableBlockWrite" -Value 0 -Type DWord
        Set-ItemProperty -Path $path -Name "PP_SclkDeepSleepDisable" -Value 1 -Type DWord
    }
}

function Ativar-Servicos {
    Escrever-Colorido "Configurando serviços essenciais..." "Yellow"
    $servicos = @("SysMain", "PcaSvc", "DiagTrack")
    foreach ($servico in $servicos) {
        do {
            Clear-Host
            Escrever-Colorido "================ Configurar Serviço: $servico ================" "Blue"
            Escrever-Colorido "S: Ativar o serviço $servico" "Blue"
            Escrever-Colorido "N: Pular este serviço" "Blue"
            $choice = Read-Host "Deseja ativar $servico? (S/N)"
        } until ($choice -match "^[sSnN]$")
        if ($choice -eq "S" -or $choice -eq "s") {
            $svc = Get-Service -Name $servico
            if ($svc.Status -ne "Running") {
                Start-Service -Name $servico
                Set-Service -Name $servico -StartupType Automatic
                Escrever-Colorido "Serviço $servico ativado." "Green"
            }
        }
        Start-Sleep -Seconds 1
    }
}

function OptimizeNetwork {
    Escrever-Colorido "Otimizando rede..." "Yellow"
    Set-NetTCPSetting -SettingName "internet" -EcnCapability disabled
    Set-NetTCPSetting -SettingName "internet" -Timestamps disabled
    Set-NetTCPSetting -SettingName "internet" -MaxSynRetransmissions 2
    netsh int tcp set global rss=enabled
}

function UltimateCleaner {
    Escrever-Colorido "Executando limpeza avançada..." "Yellow"
    Remove-Item -Path "$env:WinDir\Prefetch\*" -Force -Recurse
    Remove-Item -Path "$env:WinDir\Temp\*" -Force -Recurse
    Remove-Item -Path "$env:LocalAppData\Temp\*" -Force -Recurse
}

function CleanRegistry {
    Escrever-Colorido "Limpando registro..." "Yellow"
    $extensoes = @(".3mf", ".bmp", ".fbx", ".gif", ".jfif", ".jpe", ".jpeg", ".jpg", ".png", ".tif", ".tiff")
    foreach ($ext in $extensoes) { Remove-ItemProperty -Path "HKCR:\SystemFileAssociations\$ext\Shell\" -Name "3D Edit" }
}

function FinalizeSetup {
    Escrever-Colorido "Configuração concluída! Reinicie o PC." "Green"
    Start-Process "http://techremote.com.br"
}

New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT -ErrorAction SilentlyContinue
New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -ErrorAction SilentlyContinue

foreach ($tweak in $tweaks) {
    try { Invoke-Expression $tweak } catch { Escrever-Colorido "Erro ao executar ${tweak}: $_" "Red" }
}