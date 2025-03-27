chcp 860

function Escrever-Colorido {
    param (
        [string]$Texto,
        [string]$Cor
    )
    $cores = @{
        'Preto'        = 'Black'
        'Azul'         = 'DarkBlue'
        'Verde'        = 'DarkGreen'
        'Ciano'        = 'DarkCyan'
        'Vermelho'     = 'DarkRed'
        'Magenta'      = 'DarkMagenta'
        'Amarelo'      = 'DarkYellow'
        'CinzaClaro'   = 'Gray'
        'CinzaEscuro'  = 'DarkGray'
        'AzulClaro'    = 'Blue'
        'VerdeClaro'   = 'Green'
        'CianoClaro'   = 'Cyan'
        'VermelhoClaro'= 'Red'
        'MagentaClaro' = 'Magenta'
        'AmareloClaro' = 'Yellow'
        'Branco'       = 'White'
    }
    Write-Host $Texto -ForegroundColor $cores[$Cor]
}

$host.ui.RawUI.WindowTitle = "-- TechRemote Ultimate Windows Debloater Gaming v.0.7.0.1 --"
Clear-Host
Escrever-Colorido "" "Verde"
Escrever-Colorido "████████╗███████╗ ██████╗██╗  ██╗    ██████╗ ███████╗███╗   ███╗ ██████╗ ████████╗███████╗" "Verde"
Escrever-Colorido "╚══██╔══╝██╔════╝██╔════╝██║  ██║    ██╔══██╗██╔════╝████╗ ████║██╔═══██╗╚══██╔══╝██╔════╝" "Verde"
Escrever-Colorido "   ██║   █████╗  ██║     ███████║    ██████╔╝█████╗  ██╔████╔██║██║   ██║   ██║   █████╗  " "Verde"
Escrever-Colorido "   ██║   ██╔══╝  ██║     ██╔══██║    ██╔══██╗██╔══╝  ██║╚██╔╝██║██║   ██║   ██║   ██╔══╝  " "Verde"
Escrever-Colorido "   ██║   ███████╗╚██████╗██║  ██║    ██║  ██║███████╗██║ ╚═╝ ██║╚██████╔╝   ██║   ███████╗" "Verde"
Escrever-Colorido "   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝    ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝ ╚═════╝    ╚═╝   ╚══════╝" "Verde"
Escrever-Colorido "" "Verde"
Escrever-Colorido "Bem vindo ao TechRemote Ultimate Windows Debloater Gaming" "Azul"
Escrever-Colorido "" "Azul"
Escrever-Colorido "Este script ira otimizar o desempenho do seu sistema operacional Windows." "Amarelo"
Escrever-Colorido "Durante o processo, alguns servicos Microsoft que rodam em segundo plano serao desinstalados." "Amarelo"
Escrever-Colorido "Um ponto de restauracao sera criado automaticamente antes de prosseguir." "Amarelo"
Escrever-Colorido "" "Verde"
Escrever-Colorido "Barao (Cesar Marques)" "Verde"
Escrever-Colorido "Script utilizado pela TechRemote para otimizacoes." "AmareloClaro"
Escrever-Colorido "" "AmareloClaro"
Escrever-Colorido "DESATIVE seu ANTIVIRUS para evitar problemas e PRESSIONE QUALQUER TECLA para continuar!" "Vermelho"

$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')

New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null

$currentexename = (([Diagnostics.Process]::GetCurrentProcess().ProcessName) + '.exe')
if ($currentexename -eq "pwsh.exe") {
    Start-Process Powershell -Argumentlist '-ExecutionPolicy bypass -NoProfile -command "irm "https://raw.githubusercontent.com/wesscd/WindowsGaming/master/windowsdebloatandgamingtweaks.ps1" | iex"' -Verb RunAs
    exit
}
Clear-Host

$tweaks = @(
    "RequireAdmin", "CreateRestorePoint", "InstallMVC", "Install7Zip", "SlowUpdatesTweaks", "Write-ColorOutput", 
    "InstallTitusProgs", "check-Windows", "Execute-BatchScript", "Set-RamThreshold", "Set-MemoriaVirtual-Registry",
    "DownloadAndExtractISLC", "UpdateISLCConfig", "InstallChocoUpdates", "EnableUlimatePower", "MSIMode",
    "askDefender", "DorEOneDrive", "askXBOX", "Windows11Extra", "DebloatAll", "DisableTelemetry", "DisableWiFiSense",
    "DisableSmartScreen", "DisableWebSearch", "DisableAppSuggestions", "DisableActivityHistory", "EnableBackgroundApps",
    "DisableLocationTracking", "DisableMapUpdates", "DisableFeedback", "DisableTailoredExperiences", "DisableAdvertisingID",
    "DisableCortana", "DisableErrorReporting", "SetP2PUpdateLocal", "DisableWAPPush", "DisableNewsFeed", "SetUACLow",
    "DisableSMB1", "SetCurrentNetworkPrivate", "SetUnknownNetworksPrivate", "DisableNetDevicesAutoInst", "EnableF8BootMenu",
    "DisableMeltdownCompatFlag", "EnableUpdateMSRT", "EnableUpdateDriver", "DisableUpdateRestart", "DisableHomeGroups",
    "EnableSharedExperiences", "DisableRemoteAssistance", "EnableRemoteDesktop", "DisableAutoplay", "DisableAutorun",
    "DisableStorageSense", "DisableDefragmentation", "EnableIndexing", "SetBIOSTimeUTC", "DisableHibernation",
    "EnableSleepButton", "DisableSleepTimeout", "DisableFastStartup", "DISGaming", "PowerThrottlingOff", "Win32PrioritySeparation",
    "DisableAERO", "BSODdetails", "Disablelivetiles", "wallpaperquality", "DisableShistory", "Disableshortcutword",
    "DisableMouseKKS", "DisableTransparency", "TurnOffSafeSearch", "DisableCloudSearch", "DisableDeviceHistory",
    "DisableSearchHistroy", "RemoveMeet", "EnableActionCenter", "EnableLockScreen", "EnableLockScreenRS1", "DisableStickyKeys",
    "ShowTaskManagerDetails", "ShowFileOperationsDetails", "DisableFileDeleteConfirm", "HideTaskbarSearch", "HideTaskView",
    "HideTaskbarPeopleIcon", "DisableSearchAppInStore", "DisableNewAppPrompt", "SetVisualFXPerformance", "EnableNumlock",
    "EnableDarkMode", "ShowKnownExtensions", "HideHiddenFiles", "HideSyncNotifications", "HideRecentShortcuts",
    "SetExplorerThisPC", "ShowThisPCOnDesktop", "ShowUserFolderOnDesktop", "Hide3DObjectsFromThisPC", "Hide3DObjectsFromExplorer",
    "EnableThumbnails", "EnableThumbsDB", "UninstallInternetExplorer", "UninstallWorkFolders", "UninstallLinuxSubsystem",
    "SetPhotoViewerAssociation", "AddPhotoViewerOpenWith", "InstallPDFPrinter", "SVCHostTweak", "UnpinStartMenuTiles",
    "QOL", "FullscreenOptimizationFIX", "GameOptimizationFIX", "ApplyPCOptimizations", "RawMouseInput", "DetectnApplyMouseFIX",
    "DisableHPET", "EnableGameMode", "EnableHAGS", "DisableCoreParking", "DisableDMA", "DisablePKM", "DisallowDIP",
    "UseBigM", "ForceContiguousM", "DecreaseMKBuffer", "StophighDPC", "NvidiaTweaks", "AMDGPUTweaks", "NetworkAdapterRSS",
    "NetworkOptimizations", "DisableNagle", "Ativar-Servicos", "RemoveEdit3D", "FixURLext", "UltimateCleaner",
    "Clear-PSHistory", "Finished"
)

$mobiletweaks = @(
    "RequireAdmin", "CreateRestorePoint", "InstallMVC", "Install7Zip", "SlowUpdatesTweaks", "Write-ColorOutput",
    "InstallTitusProgs", "check-Windows", "Execute-BatchScript", "Set-RamThreshold", "Set-MemoriaVirtual-Registry",
    "DownloadAndExtractISLC", "UpdateISLCConfig", "InstallChocoUpdates", "EnableUlimatePower", "MSIMode",
    "askDefender", "DorEOneDrive", "askXBOX", "Windows11Extra", "DebloatAll", "DisableTelemetry", "DisableWiFiSense",
    "DisableSmartScreen", "DisableWebSearch", "DisableAppSuggestions", "DisableActivityHistory", "EnableBackgroundApps",
    "DisableLocationTracking", "DisableMapUpdates", "DisableFeedback", "DisableTailoredExperiences", "DisableAdvertisingID",
    "DisableCortana", "DisableErrorReporting", "SetP2PUpdateLocal", "DisableWAPPush", "DisableNewsFeed", "SetUACLow",
    "DisableSMB1", "SetCurrentNetworkPrivate", "SetUnknownNetworksPrivate", "DisableNetDevicesAutoInst", "EnableF8BootMenu",
    "DisableMeltdownCompatFlag", "EnableUpdateMSRT", "EnableUpdateDriver", "DisableUpdateRestart", "DisableHomeGroups",
    "EnableSharedExperiences", "DisableRemoteAssistance", "EnableRemoteDesktop", "DisableAutoplay", "DisableAutorun",
    "DisableStorageSense", "DisableDefragmentation", "EnableIndexing", "SetBIOSTimeUTC", "DisableHibernation",
    "EnableSleepButton", "DisableSleepTimeout", "DisableFastStartup", "DISGaming", "PowerThrottlingOff", "Win32PrioritySeparation",
    "DisableAERO", "BSODdetails", "Disablelivetiles", "wallpaperquality", "DisableShistory", "Disableshortcutword",
    "DisableMouseKKS", "DisableTransparency", "TurnOffSafeSearch", "DisableCloudSearch", "DisableDeviceHistory",
    "DisableSearchHistroy", "RemoveMeet", "EnableActionCenter", "EnableLockScreen", "EnableLockScreenRS1", "DisableStickyKeys",
    "ShowTaskManagerDetails", "ShowFileOperationsDetails", "DisableFileDeleteConfirm", "HideTaskbarSearch", "HideTaskView",
    "HideTaskbarPeopleIcon", "DisableSearchAppInStore", "DisableNewAppPrompt", "SetVisualFXPerformance", "EnableNumlock",
    "EnableDarkMode", "ShowKnownExtensions", "HideHiddenFiles", "HideSyncNotifications", "HideRecentShortcuts",
    "SetExplorerThisPC", "ShowThisPCOnDesktop", "ShowUserFolderOnDesktop", "Hide3DObjectsFromThisPC", "Hide3DObjectsFromExplorer",
    "EnableThumbnails", "EnableThumbsDB", "UninstallInternetExplorer", "UninstallWorkFolders", "UninstallLinuxSubsystem",
    "SetPhotoViewerAssociation", "AddPhotoViewerOpenWith", "InstallPDFPrinter", "SVCHostTweak", "UnpinStartMenuTiles",
    "QOL", "FullscreenOptimizationFIX", "GameOptimizationFIX", "ApplyPCOptimizations", "RawMouseInput", "DetectnApplyMouseFIX",
    "DisableHPET", "EnableGameMode", "EnableHAGS", "DisableCoreParking", "DisableDMA", "DisablePKM", "DisallowDIP",
    "UseBigM", "ForceContiguousM", "DecreaseMKBuffer", "StophighDPC", "NvidiaTweaks", "AMDGPUTweaks", "NetworkAdapterRSS",
    "NetworkOptimizations", "DisableNagle", "Ativar-Servicos", "RemoveEdit3D", "FixURLext", "UltimateCleaner",
    "Clear-PSHistory", "Finished"
)

function Show-Choco-Menu {
    param(
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$ChocoInstall
    )
    do {
        Clear-Host
        Escrever-Colorido "================ $Title ================" "Azul"
        Escrever-Colorido "Y: Press 'Y' to do this." "Azul"
        Escrever-Colorido "2: Press 'N' to skip this." "Azul"
        Escrever-Colorido "Q: Press 'Q' to stop the entire script." "Azul"
        $selection = Read-Host "Please make a selection"
        switch ($selection) {
            'y' { choco install $ChocoInstall -y }
            'n' { Break }
            'q' { Exit }
        }
    } until ($selection -match "y" -or $selection -match "n" -or $selection -match "q")
}

Function SlowUpdatesTweaks {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdates" -Type DWord -Value 1 -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdates" -Type DWord -Value 1 -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdatesPeriodInDays" -Type DWord -Value 30d -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdatesPeriodInDays" -Type DWord -Value 4d -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "PauseFeatureUpdatesStartTime" -Type String -Value "" -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "PauseQualityUpdatesStartTime" -Type String -Value "" -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "ActiveHoursEnd" -Type DWord -Value 2 -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "ActiveHoursStart" -Type DWord -Value 8 -ErrorAction SilentlyContinue | Out-Null
}

function Write-ColorOutput {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False,Position=1,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)][Object] $Object,
        [Parameter(Mandatory=$False,Position=2,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)][ConsoleColor] $ForegroundColor,
        [Parameter(Mandatory=$False,Position=3,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)][ConsoleColor] $BackgroundColor,
        [Switch]$NoNewline
    )
    $previousForegroundColor = $host.UI.RawUI.ForegroundColor
    $previousBackgroundColor = $host.UI.RawUI.BackgroundColor
    if($BackgroundColor -ne $null) { $host.UI.RawUI.BackgroundColor = $BackgroundColor }
    if($ForegroundColor -ne $null) { $host.UI.RawUI.ForegroundColor = $ForegroundColor }
    if($null -eq $Object) { $Object = "" }
    if($NoNewline) { [Console]::Write($Object) } else { Write-Output $Object }
    $host.UI.RawUI.ForegroundColor = $previousForegroundColor
    $host.UI.RawUI.BackgroundColor = $previousBackgroundColor
}

Function InstallTitusProgs {
    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    }
    choco install chocolatey-core.extension -y
    Import-Module BitsTransfer
    $configUrl = "https://raw.githubusercontent.com/wesscd/WindowsGaming/master/ooshutup10.cfg"
    $exeUrl = "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe"
    $configFile = "$env:TEMP\ooshutup10.cfg"
    $exeFile = "$env:TEMP\OOSU10.exe"
    Start-BitsTransfer -Source $configUrl -Destination $configFile
    Start-BitsTransfer -Source $exeUrl -Destination $exeFile
    & $exeFile $configFile /quiet
    Start-Sleep -Seconds 10
    Remove-Item -Path $configFile, $exeFile -Force -ErrorAction Stop
}

Function Execute-BatchScript {
    Clear-Host
    Escrever-Colorido "" "Azul"
    Escrever-Colorido "Realizando limpeza de cache dos navegadores" "Verde"
    $url = "https://raw.githubusercontent.com/wesscd/WindowsGaming/master/script-ccleaner.bat"
    $localPath = "$env:temp\script-ccleaner.bat"
    Invoke-WebRequest -Uri $url -OutFile $localPath
    Start-Process -FilePath $localPath -ArgumentList "/c $localPath" -Wait
    Remove-Item -Path $localPath -Force
}

function Set-RamThreshold {
    $ramGB = [math]::round((Get-WmiObject -Class Win32_ComputerSystem).TotalPhysicalMemory / 1GB)
    $value = switch ($ramGB) {
        4   { 0x400000 }
        6   { 0x600000 }
        8   { 0x800000 }
        12  { 0xC00000 }
        16  { 0x1000000 }
        19  { 0x1300000 }
        20  { 0x1400000 }
        24  { 0x1800000 }
        32  { 0x2000000 }
        64  { 0x4000000 }
        128 { 0x8000000 }
        default { Escrever-Colorido "Memoria RAM nao suportada para esta configuracao." "Vermelho"; exit }
    }
    $value = [int]$value
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control"
    $regName = "SvcHostSplitThresholdInKB"
    if (-not (Get-ItemProperty -Path "$regPath" -Name "$regName" -ErrorAction SilentlyContinue)) {
        New-ItemProperty -Path "$regPath" -Name "$regName" -Value $value -PropertyType DWord | Out-Null
    } else {
        Set-ItemProperty -Path "$regPath" -Name "$regName" -Value $value
    }
}

function Set-MemoriaVirtual-Registry {
    Clear-Host
    Escrever-Colorido "" "Azul"
    Escrever-Colorido "================ Digite a letra do drive para armazenar memoria virtual ================" "Azul"
    Escrever-Colorido "" "Azul"
    $Drive = Read-Host "Informe a letra do drive (ex: C) para configurar a memoria virtual"
    $DrivePath = "${Drive}:"
    $TotalRAM = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1MB)
    $MaxSize = [math]::Round($TotalRAM * 1.5)
    $InitialSize = 9081
    $RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
    Set-ItemProperty -Path $RegPath -Name "PagingFiles" -Value "$DrivePath\pagefile.sys $InitialSize $MaxSize"
    Set-ItemProperty -Path $RegPath -Name "AutomaticManagedPagefile" -Value 0
}

function DownloadAndExtractISLC {
    $downloadUrl = "https://raw.githubusercontent.com/wesscd/WindowsGaming/main/ISLC%20v1.0.3.4.exe"
    $downloadPath = "C:\ISLC_v1.0.3.4.exe"
    $extractPath = "C:\"
    $newFolderName = "ISLC"
    Invoke-WebRequest -Uri $downloadUrl -OutFile $downloadPath
    $sevenZipPath = "C:\Program Files\7-Zip\7z.exe"
    if (Test-Path -Path $sevenZipPath) {
        & $sevenZipPath x $downloadPath -o"$extractPath" -y
        $extractedFolderPath = "$extractPath\ISLC v1.0.3.4"
        if (Test-Path -Path $extractedFolderPath) {
            Rename-Item -Path $extractedFolderPath -NewName $newFolderName
        }
    }
    Remove-Item -Path $downloadPath -Force
    $origem = "C:\ISLC\Intelligent standby list cleaner ISLC.exe"
    $atalhoNome = "Intelligent standby list cleaner ISLC.lnk"
    $destino = [System.IO.Path]::Combine($env:APPDATA, "Microsoft\Windows\Start Menu\Programs\Startup", $atalhoNome)
    $shell = New-Object -ComObject WScript.Shell
    $atalho = $shell.CreateShortcut($destino)
    $atalho.TargetPath = $origem
    $atalho.Save()
}

function UpdateISLCConfig {
    $configFilePath = "C:\ISLC\Intelligent standby list cleaner ISLC.exe.Config"
    if (Test-Path -Path $configFilePath) {
        [xml]$configXml = Get-Content -Path $configFilePath -Raw
        $totalMemory = (Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1MB
        $freeMemory = [math]::Round($totalMemory / 2)
        $configXml.configuration.appSettings.add | Where-Object { $_.key -eq "Free memory" } | ForEach-Object { $_.value = "$freeMemory" }
        $configXml.configuration.appSettings.add | Where-Object { $_.key -eq "Start minimized" } | ForEach-Object { $_.value = "True" }
        $configXml.configuration.appSettings.add | Where-Object { $_.key -eq "Wanted timer" } | ForEach-Object { $_.value = "0.50" }
        $configXml.configuration.appSettings.add | Where-Object { $_.key -eq "Custom timer" } | ForEach-Object { $_.value = "True" }
        $configXml.configuration.appSettings.add | Where-Object { $_.key -eq "TaskScheduler" } | ForEach-Object { $_.value = "True" }
        $configXml.Save($configFilePath)
    }
}

function check-Windows {
    $activationStatus = (Get-CimInstance -ClassName SoftwareLicensingProduct -Filter "Name like 'Windows%'" | Where-Object { $_.PartialProductKey }).LicenseStatus
    if ($activationStatus -eq 1) {
        Clear-Host
        Escrever-Colorido "" "Azul"
        Escrever-Colorido "O Windows está ativado." "Azul"
    } else {
        Clear-Host
        Escrever-Colorido "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*" "Vermelho"
        Escrever-Colorido "| O Windows NÃO está ativado. Executando o comando de ativação. |" "Vermelho"
        Escrever-Colorido "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*" "Vermelho"
        irm https://get.activated.win | iex
    }
}

Function InstallMVC {
    choco install -y vcredist2010 | Out-Null
}

Function Install7Zip {
    choco install 7zip -y
}

Function InstallChocoUpdates {
    Clear-Host
    choco upgrade all -y
}

Function ApplyPCOptimizations {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Type DWord -Value 10
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "AlwaysOn" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "LazyMode" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "LazyModeTimeout" -Type DWord -Value 25000
}

Function askXBOX {
    $winVer = [System.Environment]::OSVersion.Version
    $isWin11 = $winVer.Major -eq 10 -and $winVer.Build -ge 22000
    do {
        Clear-Host
        Escrever-Colorido "" "Azul"
        Escrever-Colorido "================ Desabilitar os recursos do XBOX e todos os aplicativos relacionados? ================" "Azul"
        Escrever-Colorido "" "Azul"
        Escrever-Colorido "AVISO: REMOVER OS APLICATIVOS DO XBOX fara com que o Win+G nao funcione!" "Vermelho"
        Escrever-Colorido "Pressione 'D' para desabilitar os recursos do XBOX." "Azul"
        Escrever-Colorido "Pressione 'H' para habilitar os recursos do XBOX." "Azul"
        Escrever-Colorido "Pressione 'P' para pular isso." "Azul"
        $selection = Read-Host "Por favor, escolha"
    } until ($selection -match "(?i)^(d|h|p)$")
    if ($selection -match "(?i)^d$") {
        $ErrorActionPreference = "SilentlyContinue"
        $xboxApps = @("Microsoft.XboxApp", "Microsoft.XboxIdentityProvider", "Microsoft.XboxSpeechToTextOverlay", "Microsoft.XboxGameOverlay", "Microsoft.Xbox.TCUI")
        if ($isWin11) { $xboxApps += "Microsoft.XboxGamingOverlay" }
        foreach ($app in $xboxApps) {
            $pkg = Get-AppxPackage $app
            if ($pkg) { $pkg | Remove-AppxPackage }
        }
        Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 0
        if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR")) { New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Force | Out-Null }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0
    }
    elseif ($selection -match "(?i)^h$") {
        $ErrorActionPreference = "SilentlyContinue"
        $xboxApps = @("Microsoft.XboxApp", "Microsoft.XboxIdentityProvider", "Microsoft.XboxSpeechToTextOverlay", "Microsoft.XboxGameOverlay", "Microsoft.Xbox.TCUI")
        if ($isWin11) { $xboxApps += "Microsoft.XboxGamingOverlay" }
        foreach ($app in $xboxApps) {
            $pkg = Get-AppxPackage -AllUsers $app
            if ($pkg) { $pkg | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"} }
        }
        Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 1
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -ErrorAction SilentlyContinue
    }
}

Function MSIMode {
    $ErrorActionPreference = "SilentlyContinue"
    $GPUIDS = @((Get-CimInstance -ClassName Win32_VideoController | Select-Object -ExpandProperty PNPDeviceID | Select-Object -Skip 2 | Format-List | Out-String).Trim())
    foreach ($GPUID in $GPUIDS) {
        $CheckDeviceDes = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\$GPUID").DeviceDesc
        if (($CheckDeviceDes -like "*GTX*") -or ($CheckDeviceDes -like "*RTX*") -or ($CheckDeviceDes -like "*AMD*")) {
            New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\$GPUID\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties\" -Force | Out-Null
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\$GPUID\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties\" -Name "MSISupported" -Type DWord -Value 1
        }
    }
}

Function DisableTelemetry {
    $ErrorActionPreference = "SilentlyContinue"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null
}

Function DisableWiFiSense {
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Type Dword -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "WiFISenseAllowed" -Type Dword -Value 0
}

Function DisableSmartScreen {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Type DWord -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -Type DWord -Value 0
}

Function DisableWebSearch {
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Type DWord -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Type DWord -Value 1
}

Function DisableAppSuggestions {
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1
}

Function DisableActivityHistory {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0
}

Function EnableBackgroundApps {
    Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Exclude "Microsoft.Windows.Cortana*" | ForEach-Object {
        Remove-ItemProperty -Path $_.PsPath -Name "Disabled" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $_.PsPath -Name "DisabledByUser" -ErrorAction SilentlyContinue
    }
}

Function DisableLocationTracking {
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -Type DWord -Value 1
}

Function DisableMapUpdates {
    Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0
}

Function DisableFeedback {
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null
}

Function DisableTailoredExperiences {
    If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
        New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1
}

Function DisableAdvertisingID {
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1
}

Function DisableCortana {
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "AllowInputPersonalization" -Type DWord -Value 0
}

Function DisableErrorReporting {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null
}

Function SetP2PUpdateLocal {
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -Type DWord -Value 1
}

Function DisableWAPPush {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dmwappushservice" -Name "Start" -Type DWord -Value 4
    Stop-Service -Name "dmwappushservice" -Force -ErrorAction SilentlyContinue
}

Function DisableNewsFeed {
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Type DWord -Value 0
}

Function SetUACLow {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 0
}

Function DisableSMB1 {
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
}

Function SetCurrentNetworkPrivate {
    $NetworkListManager = [Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]"{DCB00C01-570F-4A9B-8D69-199FDBA5723B}"))
    $Connections = $NetworkListManager.GetNetworkConnections()
    $Connections | ForEach-Object { $_.GetNetwork().SetCategory(1) }
}

Function SetUnknownNetworksPrivate {
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103" -Name "Category" -Type DWord -Value 1
}

Function DisableNetDevicesAutoInst {
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name "AutoSetup" -Type DWord -Value 0
}

Function EnableF8BootMenu {
    cmd /c "bcdedit /set `{current`} bootmenupolicy legacy" | Out-Null
}

Function DisableMeltdownCompatFlag {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" -Name "cadca5fe-87d3-4b96-b7fb-a231484277cc" -Type DWord -Value 0
}

Function EnableUpdateMSRT {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontOfferThroughWUAU" -Type DWord -Value 0
}

Function EnableUpdateDriver {
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -ErrorAction SilentlyContinue
}

Function DisableUpdateRestart {
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -Type DWord -Value 0
}

Function DisableHomeGroups {
    Stop-Service -Name "HomeGroupListener" -WarningAction SilentlyContinue
    Set-Service -Name "HomeGroupListener" -StartupType Disabled
    Stop-Service -Name "HomeGroupProvider" -WarningAction SilentlyContinue
    Set-Service -Name "HomeGroupProvider" -StartupType Disabled
}

Function EnableSharedExperiences {
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP" -Name "RomeSdkChannelUserAuthzPolicy" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP" -Name "CdpSessionUserAuthzPolicy" -ErrorAction SilentlyContinue
}

Function DisableRemoteAssistance {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0
}

Function EnableRemoteDesktop {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 0
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
}

Function DisableAutoplay {
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 1
}

Function DisableAutorun {
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 255
}

Function DisableStorageSense {
    Remove-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Recurse -ErrorAction SilentlyContinue
}

Function DisableDefragmentation {
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Defrag\ScheduledDefrag" | Out-Null
}

Function EnableIndexing {
    Enable-ScheduledTask -TaskName "Microsoft\Windows\Shell\Indexer" | Out-Null
}

Function SetBIOSTimeUTC {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -Name "RealTimeIsUniversal" -Type DWord -Value 1
}

Function DisableHibernation {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "HibernateEnabled" -Type DWord -Value 0
    cmd /c "powercfg /hibernate off" | Out-Null
}

Function EnableSleepButton {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "SleepButtonEnabled" -Type DWord -Value 1
}

Function DisableSleepTimeout {
    cmd /c "powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_SLEEP STANDBYIDLE 0" | Out-Null
    cmd /c "powercfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_SLEEP STANDBYIDLE 0" | Out-Null
}

Function DisableFastStartup {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 0
}

Function DISGaming {
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0
}

Function PowerThrottlingOff {
    If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling")) {
        New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" -Name "PowerThrottlingOff" -Type DWord -Value 1
}

Function Win32PrioritySeparation {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Type DWord -Value 38
}

Function DisableAERO {
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type DWord -Value 0
}

Function BSODdetails {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "DisplayParameters" -Type DWord -Value 1
}

Function Disablelivetiles {
    If (!(Test-Path "HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications")) {
        New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoTileApplicationNotification" -Type DWord -Value 1
}

Function wallpaperquality {
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "JPEGImportQuality" -Type DWord -Value 100
}

Function DisableShistory {
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackDocs" -Type DWord -Value 0
}

Function Disableshortcutword {
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "link" -Type Binary -Value ([byte[]](0,0,0,0))
}

Function DisableMouseKKS {
    Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseHoverTime" -Type String -Value "0"
}

Function DisableTransparency {
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Type DWord -Value 0
}

Function TurnOffSafeSearch {
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" -Name "SafeSearch" -Type DWord -Value 0
}

Function DisableCloudSearch {
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCloudSearch" -Type DWord -Value 0
}

Function DisableDeviceHistory {
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace" -Name "{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -Type DWord -Value 0
}

Function DisableSearchHistroy {
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "HistoryViewEnabled" -Type DWord -Value 0
}

Function RemoveMeet {
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace" -Force | Out-Null
    }
    Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}" -ErrorAction SilentlyContinue
}

Function EnableActionCenter {
    Remove-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -ErrorAction SilentlyContinue
}

Function EnableLockScreen {
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -ErrorAction SilentlyContinue
}

Function EnableLockScreenRS1 {
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\SessionData" -Name "AllowLockScreen" -ErrorAction SilentlyContinue
}

Function DisableStickyKeys {
    Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "506"
}

Function ShowTaskManagerDetails {
  $taskmgr = Start-Process -FilePath "taskmgr.exe" -PassThru -WindowStyle Hidden
  Start-Sleep -Milliseconds 500
  $preferences = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -ErrorAction SilentlyContinue
  if ($preferences) {
      Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -Type Binary -Value $preferences.Preferences
  }
  Stop-Process -Id $taskmgr.Id -Force
}

Function ShowFileOperationsDetails {
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Type DWord -Value 1
}

Function DisableFileDeleteConfirm {
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ConfirmFileDelete" -Type DWord -Value 0
}

Function HideTaskbarSearch {
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0
}

Function HideTaskView {
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0
}

Function HideTaskbarPeopleIcon {
  If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {
      New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0
}

Function DisableSearchAppInStore {
  If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
      New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Type DWord -Value 1
}

Function DisableNewAppPrompt {
  If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
      New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoNewAppAlert" -Type DWord -Value 1
}

Function SetVisualFXPerformance {
  Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Type Binary -Value ([byte[]](0x90,0x12,0x03,0x80,0x10,0x00,0x00,0x00))
  Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "VisualFXSetting" -Type DWord -Value 3
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value 3
}

Function EnableNumlock {
  Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value 2
}

Function EnableDarkMode {
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Type DWord -Value 0
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Type DWord -Value 0
}

Function ShowKnownExtensions {
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0
}

Function HideHiddenFiles {
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 2
}

Function HideSyncNotifications {
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Type DWord -Value 0
}

Function HideRecentShortcuts {
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -Type DWord -Value 0
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -Type DWord -Value 0
}

Function SetExplorerThisPC {
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1
}

Function ShowThisPCOnDesktop {
  If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{20D04FE0-3AEA-1069-A2D8-08002B30309D}")) {
      New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Force | Out-Null
  }
}

Function ShowUserFolderOnDesktop {
  If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{59031a47-3f72-44a7-89c5-5595fe6b30ee}")) {
      New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -Force | Out-Null
  }
}

Function Hide3DObjectsFromThisPC {
  Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue
}

Function Hide3DObjectsFromExplorer {
  If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag")) {
      New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
}

Function EnableThumbnails {
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "IconsOnly" -Type DWord -Value 0
}

Function EnableThumbsDB {
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbnailCache" -Type DWord -Value 0
}

Function UninstallInternetExplorer {
  Disable-WindowsOptionalFeature -Online -FeatureName "Internet-Explorer-Optional-$env:PROCESSOR_ARCHITECTURE" -NoRestart -ErrorAction SilentlyContinue | Out-Null
}

Function UninstallWorkFolders {
  Disable-WindowsOptionalFeature -Online -FeatureName "WorkFolders-Client" -NoRestart -ErrorAction SilentlyContinue | Out-Null
}

Function UninstallLinuxSubsystem {
  Disable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-Subsystem-Linux" -NoRestart -ErrorAction SilentlyContinue | Out-Null
}

Function SetPhotoViewerAssociation {
  If (!(Test-Path "HKCR:\Paint.Picture")) {
      New-Item -Path "HKCR:\Paint.Picture" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKCR:\Paint.Picture" -Name "(Default)" -Type String -Value "PhotoViewer.FileAssoc.Bitmap"
}

Function AddPhotoViewerOpenWith {
  If (!(Test-Path "HKCR:\Applications\photoviewer.dll")) {
      New-Item -Path "HKCR:\Applications\photoviewer.dll" -Force | Out-Null
  }
  If (!(Test-Path "HKCR:\Applications\photoviewer.dll\shell\open")) {
      New-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open" -Name "MuiVerb" -Type String -Value "@photoviewer.dll,-3043"
  If (!(Test-Path "HKCR:\Applications\photoviewer.dll\shell\open\command")) {
      New-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open\command" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open\command" -Name "(Default)" -Type ExpandString -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1"
}

Function InstallPDFPrinter {
  Enable-WindowsOptionalFeature -Online -FeatureName "Printing-XPSServices-Features" -NoRestart -ErrorAction SilentlyContinue | Out-Null
}

Function SVCHostTweak {
  $ram = (Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1GB
  $threshold = [math]::Round($ram * 1024 * 0.5)
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -Type DWord -Value $threshold
}

Function UnpinStartMenuTiles {
  $key = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\*$windows.data.start.tilegrid\windows.data.start.tilegrid" -ErrorAction SilentlyContinue
  if ($key) {
      Remove-Item -Path $key.PSPath -Recurse -Force
  }
}

Function QOL {
  Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name "sShortDate" -Type String -Value "dd/MM/yyyy"
  Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name "sTimeFormat" -Type String -Value "HH:mm:ss"
}

Function FullscreenOptimizationFIX {
  Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_DXGIHonorFSEWindowsCompatible" -Type DWord -Value 1
  Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehavior" -Type DWord -Value 2
  Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_HonorUserFSEBehaviorMode" -Type DWord -Value 1
}

Function GameOptimizationFIX {
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Priority" -Type DWord -Value 6
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Scheduling Category" -Type String -Value "High"
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "SFIO Priority" -Type String -Value "High"
}

Function ApplyPCOptimizations {
  # Já implementada anteriormente no código fornecido, mas repetida aqui para consistência
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -Type DWord -Value 0
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Type DWord -Value 10
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "AlwaysOn" -Type DWord -Value 1
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "LazyMode" -Type DWord -Value 1
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "LazyModeTimeout" -Type DWord -Value 25000
}

Function RawMouseInput {
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" -Name "MouseDataQueueSize" -Type DWord -Value 50
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" -Name "KeyboardDataQueueSize" -Type DWord -Value 50
}

Function DetectnApplyMouseFIX {
  $mice = Get-WmiObject Win32_PnPEntity | Where-Object { $_.Name -like "*mouse*" -and $_.Status -eq "OK" }
  foreach ($mouse in $mice) {
      $deviceID = $mouse.DeviceID
      Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\$deviceID" -Name "FlipFlopWheel" -Type DWord -Value 0 -ErrorAction SilentlyContinue
  }
}

Function DisableHPET {
  cmd /c "bcdedit /set useplatformclock false" | Out-Null
  cmd /c "bcdedit /set disabledynamictick yes" | Out-Null
}

Function EnableGameMode {
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AllowAutoGameMode" -Type DWord -Value 1
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AutoGameModeEnabled" -Type DWord -Value 1
}

Function EnableHAGS {
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "HwSchMode" -Type DWord -Value 2
}

Function DisableCoreParking {
  powercfg -setacvalueindex SCHEME_CURRENT SUB_PROCESSOR CPMINCORES 100
  powercfg -setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR CPMINCORES 100
  powercfg -setactive SCHEME_CURRENT
}

Function DisableDMA {
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "DmaRemappingCompatible" -Type DWord -Value 0
}

Function DisablePKM {
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "PlatformAoAcOverride" -Type DWord -Value 0
}

Function DisallowDIP {
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowDomainPinCode" -Type DWord -Value 0
}

Function UseBigM {
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "LargeSystemCache" -Type DWord -Value 1
}

Function ForceContiguousM {
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "PhysicalAddressExtension" -Type DWord -Value 1
}

Function DecreaseMKBuffer {
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" -Name "MouseDataQueueSize" -Type DWord -Value 20
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" -Name "KeyboardDataQueueSize" -Type DWord -Value 20
}

Function StophighDPC {
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NDIS\Parameters" -Name "MaxNumRssCpus" -Type DWord -Value 4
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0000" -Name "RSS" -Type DWord -Value 1 -ErrorAction SilentlyContinue
}

Function NvidiaTweaks {
  $nvidiaKey = "HKLM:\SYSTEM\CurrentControlSet\Services\nvlddmkm"
  if (Test-Path $nvidiaKey) {
      Set-ItemProperty -Path $nvidiaKey -Name "DisablePreemption" -Type DWord -Value 1
      Set-ItemProperty -Path $nvidiaKey -Name "EnableTiledDisplay" -Type DWord -Value 0
      Set-ItemProperty -Path $nvidiaKey -Name "PowerMizerEnable" -Type DWord -Value 0
  }
}

Function AMDGPUTweaks {
  $amdKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000"
  if (Test-Path $amdKey) {
      Set-ItemProperty -Path $amdKey -Name "DisableBlockWrite" -Type DWord -Value 0
      Set-ItemProperty -Path $amdKey -Name "PP_ThermalAutoThrottlingEnable" -Type DWord -Value 0
      Set-ItemProperty -Path $amdKey -Name "EnableULPS" -Type DWord -Value 0
  }
}

Function NetworkAdapterRSS {
  $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
  foreach ($adapter in $adapters) {
      Set-NetAdapterRss -Name $adapter.Name -Enabled $true -ErrorAction SilentlyContinue
  }
}

Function NetworkOptimizations {
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DefaultTTL" -Type DWord -Value 64
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "TcpMaxDataRetransmissions" -Type DWord -Value 5
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "MaxUserPort" -Type DWord -Value 65534
}

Function DisableNagle {
  $tcpKey = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
  Get-ChildItem $tcpKey | ForEach-Object {
      Set-ItemProperty -Path "$tcpKey\$($_.PSChildName)" -Name "TcpAckFrequency" -Type DWord -Value 1 -ErrorAction SilentlyContinue
      Set-ItemProperty -Path "$tcpKey\$($_.PSChildName)" -Name "TCPNoDelay" -Type DWord -Value 1 -ErrorAction SilentlyContinue
  }
}

Function Ativar-Servicos {
  $services = @("wuauserv", "bits", "cryptsvc")
  foreach ($service in $services) {
      Set-Service -Name $service -StartupType Automatic
      Start-Service -Name $service -ErrorAction SilentlyContinue
  }
}

Function RemoveEdit3D {
  Remove-ItemProperty -Path "HKCR:\SystemFileAssociations\.3mf\Shell\Edit" -Name "(Default)" -ErrorAction SilentlyContinue
  Remove-ItemProperty -Path "HKCR:\SystemFileAssociations\.stl\Shell\Edit" -Name "(Default)" -ErrorAction SilentlyContinue
}

Function FixURLext {
  Set-ItemProperty -Path "HKCR:\.url" -Name "(Default)" -Type String -Value "InternetShortcut"
  Set-ItemProperty -Path "HKCR:\InternetShortcut" -Name "IsShortcut" -Type String -Value ""
}

Function UltimateCleaner {
  Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
  Remove-Item -Path "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
  cmd /c "cleanmgr /sagerun:1" | Out-Null
}

Function Clear-PSHistory {
  Remove-Item -Path (Get-PSReadLineOption).HistorySavePath -Force -ErrorAction SilentlyContinue
}

Function Finished {
  Clear-Host
  Escrever-Colorido "Otimização concluída com sucesso!" "Verde"
  Escrever-Colorido "Reinicie o sistema para aplicar todas as alterações." "Amarelo"
  $restart = Read-Host "Deseja reiniciar agora? (S/N)"
  if ($restart -eq "S" -or $restart -eq "s") {
      Restart-Computer -Force
  }
}

# Executar as otimizações
foreach ($tweak in $tweaks) {
  Invoke-Expression $tweak
}