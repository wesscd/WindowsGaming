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

$host.ui.RawUI.WindowTitle = "-- TechRemote Ultimate Windows Debloater Gaming v.0.7.0.3 (GROK) --"
Clear-Host
Escrever-Colorido "████████╗███████╗ ██████╗██╗  ██╗    ██████╗ ███████╗███╗   ███╗ ██████╗ ████████╗███████╗" "Verde"
Escrever-Colorido "╚══██╔══╝██╔════╝██╔════╝██║  ██║    ██╔══██╗██╔════╝████╗ ████║██╔═══██╗╚══██╔══╝██╔════╝" "Verde"
Escrever-Colorido "   ██║   █████╗  ██║     ███████║    ██████╔╝█████╗  ██╔████╔██║██║   ██║   ██║   █████╗  " "Verde"
Escrever-Colorido "   ██║   ██╔══╝  ██║     ██╔══██║    ██╔══██╗██╔══╝  ██║╚██╔╝██║██║   ██║   ██║   ██╔══╝  " "Verde"
Escrever-Colorido "   ██║   ███████╗╚██████╗██║  ██║    ██║  ██║███████╗██║ ╚═╝ ██║╚██████╔╝   ██║   ███████╗" "Verde"
Escrever-Colorido "   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝    ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝ ╚═════╝    ╚═╝   ╚══════╝" "Verde"
Escrever-Colorido "`nBem vindo ao TechRemote Ultimate Windows Debloater Gaming" "Azul"
Escrever-Colorido "`nEste script ira otimizar o desempenho do seu sistema operacional Windows." "Amarelo"
Escrever-Colorido "Durante o processo, alguns servicos Microsoft que rodam em segundo plano serao desinstalados." "Amarelo"
Escrever-Colorido "Um ponto de restauracao sera criado automaticamente antes de prosseguir." "Amarelo"
Escrever-Colorido "`nBarao (Cesar Marques)" "Verde"
Escrever-Colorido "Script utilizado pela TechRemote para otimizacoes." "AmareloClaro"
Escrever-Colorido "`nDESATIVE seu ANTIVIRUS para evitar problemas e PRESSIONE QUALQUER TECLA para continuar!" "Vermelho"

$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')

New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null

$currentexename = ([Diagnostics.Process]::GetCurrentProcess().ProcessName + '.exe')
if ($currentexename -eq "pwsh.exe") {
    Start-Process Powershell -Argumentlist '-ExecutionPolicy bypass -NoProfile -command "irm \"https://raw.githubusercontent.com/wesscd/WindowsGaming/master/windowsdebloatandgamingtweaks.ps1\" | iex"' -Verb RunAs
    exit
}

# Lista única de tweaks (removida a duplicata $mobiletweaks)
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

# Funções consolidadas e otimizadas
function Show-Choco-Menu {
    param([string]$Title, [string]$ChocoInstall)
    do {
        Clear-Host
        Escrever-Colorido "================ $Title ================" "Azul"
        Escrever-Colorido "Y: Press 'Y' to do this.`nN: Press 'N' to skip this.`nQ: Press 'Q' to stop the entire script." "Azul"
        $selection = Read-Host "Please make a selection"
    } until ($selection -match '^[ynq]$')
    switch ($selection) {
        'y' { choco install $ChocoInstall -y }
        'q' { Exit }
    }
}

function SlowUpdatesTweaks {
    $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    if (!(Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
    $updates = @{
        "DeferFeatureUpdates" = 1
        "DeferQualityUpdates" = 1
        "DeferFeatureUpdatesPeriodInDays" = 30
        "DeferQualityUpdatesPeriodInDays" = 4
    }
    foreach ($key in $updates.Keys) {
        Set-ItemProperty -Path $path -Name $key -Type DWord -Value $updates[$key] -ErrorAction SilentlyContinue
    }
    $uxPath = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"
    Set-ItemProperty -Path $uxPath -Name "ActiveHoursEnd" -Type DWord -Value 2 -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $uxPath -Name "ActiveHoursStart" -Type DWord -Value 8 -ErrorAction SilentlyContinue
}

function Write-ColorOutput {
    param([Object]$Object="", [ConsoleColor]$ForegroundColor, [ConsoleColor]$BackgroundColor, [switch]$NoNewline)
    $prevFg = $host.UI.RawUI.ForegroundColor
    $prevBg = $host.UI.RawUI.BackgroundColor
    if ($ForegroundColor) { $host.UI.RawUI.ForegroundColor = $ForegroundColor }
    if ($BackgroundColor) { $host.UI.RawUI.BackgroundColor = $BackgroundColor }
    if ($NoNewline) { [Console]::Write($Object) } else { Write-Output $Object }
    $host.UI.RawUI.ForegroundColor = $prevFg
    $host.UI.RawUI.BackgroundColor = $prevBg
}

function InstallTitusProgs {
    if (!(Get-Command choco -ErrorAction SilentlyContinue)) {
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    }
    choco install chocolatey-core.extension -y
    $urls = @{
        config = "https://raw.githubusercontent.com/wesscd/WindowsGaming/master/ooshutup10.cfg"
        exe = "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe"
    }
    $tempFiles = @{}
    foreach ($key in $urls.Keys) {
        $tempFiles[$key] = "$env:TEMP\$key.cfg"
        Start-BitsTransfer -Source $urls[$key] -Destination $tempFiles[$key]
    }
    & $tempFiles["exe"] $tempFiles["config"] /quiet
    Start-Sleep -Seconds 10
    $tempFiles.Values | Remove-Item -Force -ErrorAction SilentlyContinue
}

function Execute-BatchScript {
    Clear-Host
    Escrever-Colorido "`nRealizando limpeza de cache dos navegadores" "Verde"
    $url = "https://raw.githubusercontent.com/wesscd/WindowsGaming/master/script-ccleaner.bat"
    $path = "$env:temp\script-ccleaner.bat"
    Invoke-WebRequest -Uri $url -OutFile $path
    Start-Process -FilePath $path -ArgumentList "/c $path" -Wait
    Remove-Item -Path $path -Force
}

function Set-RamThreshold {
    $ramGB = [math]::Round((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1GB)
    $value = switch ($ramGB) {
        {$_ -in 4..8}  { $_ * 0x100000 }
        {$_ -in 12..24}{ $_ * 0x100000 }
        32  { 0x2000000 }
        64  { 0x4000000 }
        128 { 0x8000000 }
        default { Escrever-Colorido "Memoria RAM nao suportada para esta configuracao." "Vermelho"; return }
    }
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -Type DWord -Value $value -ErrorAction SilentlyContinue
}

function Set-MemoriaVirtual-Registry {
    Clear-Host
    Escrever-Colorido "`n================ Digite a letra do drive para armazenar memoria virtual ================" "Azul"
    $drive = Read-Host "Informe a letra do drive (ex: C)"
    $totalRAM = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1MB)
    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
    Set-ItemProperty -Path $path -Name "PagingFiles" -Value "$($drive):\pagefile.sys 9081 $($totalRAM * 1.5)"
    Set-ItemProperty -Path $path -Name "AutomaticManagedPagefile" -Value 0
}

function DownloadAndExtractISLC {
    $url = "https://raw.githubusercontent.com/wesscd/WindowsGaming/main/ISLC%20v1.0.3.4.exe"
    $path = "C:\ISLC_v1.0.3.4.exe"
    Invoke-WebRequest -Uri $url -OutFile $path
    if (Test-Path "C:\Program Files\7-Zip\7z.exe") {
        & "C:\Program Files\7-Zip\7z.exe" x $path -o"C:\" -y
        Rename-Item "C:\ISLC v1.0.3.4" "ISLC" -ErrorAction SilentlyContinue
    }
    Remove-Item $path -Force
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\Intelligent standby list cleaner ISLC.lnk")
    $shortcut.TargetPath = "C:\ISLC\Intelligent standby list cleaner ISLC.exe"
    $shortcut.Save()
}

function UpdateISLCConfig {
    $path = "C:\ISLC\Intelligent standby list cleaner ISLC.exe.Config"
    if (Test-Path $path) {
        [xml]$xml = Get-Content $path -Raw
        $settings = @{
            "Free memory" = [math]::Round((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 2MB)
            "Start minimized" = "True"
            "Wanted timer" = "0.50"
            "Custom timer" = "True"
            "TaskScheduler" = "True"
        }
        $xml.configuration.appSettings.add | ForEach-Object { if ($settings[$_.key]) { $_.value = $settings[$_.key] } }
        $xml.Save($path)
    }
}

function check-Windows {
    Clear-Host
    $status = (Get-CimInstance SoftwareLicensingProduct -Filter "Name like 'Windows%'" | Where-Object { $_.PartialProductKey }).LicenseStatus
    Escrever-Colorido "`n$(if ($status -eq 1) { "O Windows está ativado." } else { "O Windows NÃO está ativado. Executando o comando de ativação." })" "$($status -eq 1 ? 'Azul' : 'Vermelho')"
    if ($status -ne 1) { irm https://get.activated.win | iex }
}

function InstallMVC { choco install vcredist2010 -y | Out-Null }
function Install7Zip { choco install 7zip -y }
function InstallChocoUpdates { Clear-Host; choco upgrade all -y }

function ApplyPCOptimizations {
    $path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"
    $settings = @{
        "SystemResponsiveness" = 0
        "NetworkThrottlingIndex" = 10
        "AlwaysOn" = 1
        "LazyMode" = 1
        "LazyModeTimeout" = 25000
    }
    foreach ($key in $settings.Keys) {
        Set-ItemProperty -Path $path -Name $key -Type DWord -Value $settings[$key]
    }
}

function askXBOX {
    $winVer = [System.Environment]::OSVersion.Version
    $isWin11 = $winVer.Major -eq 10 -and $winVer.Build -ge 22000
    do {
        Clear-Host
        Escrever-Colorido "`n================ Desabilitar os recursos do XBOX e todos os aplicativos relacionados? ================" "Azul"
        Escrever-Colorido "AVISO: REMOVER OS APLICATIVOS DO XBOX fara com que o Win+G nao funcione!`nD: Desabilitar`nH: Habilitar`nP: Pular" "Vermelho"
        $selection = Read-Host "Escolha"
    } until ($selection -match '(?i)^[dhp]$')
    $apps = @("Microsoft.XboxApp", "Microsoft.XboxIdentityProvider", "Microsoft.XboxSpeechToTextOverlay", "Microsoft.XboxGameOverlay", "Microsoft.Xbox.TCUI") + $(if ($isWin11) { "Microsoft.XboxGamingOverlay" })
    if ($selection -ieq 'd') {
        $apps | ForEach-Object { Get-AppxPackage $_ -ErrorAction SilentlyContinue | Remove-AppxPackage }
        Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 0
        $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR"
        if (!(Test-Path $path)) { New-Item $path -Force | Out-Null }
        Set-ItemProperty -Path $path -Name "AllowGameDVR" -Type DWord -Value 0
    } elseif ($selection -ieq 'h') {
        $apps | ForEach-Object { Get-AppxPackage -AllUsers $_ -ErrorAction SilentlyContinue | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" } }
        Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 1
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -ErrorAction SilentlyContinue
    }
}

function MSIMode {
    Get-CimInstance Win32_VideoController | 
        Where-Object { $_.PNPDeviceID -and ($_.DeviceDesc -match "GTX|RTX|AMD") } | 
        ForEach-Object {
            $path = "HKLM:\SYSTEM\CurrentControlSet\Enum\$($_.PNPDeviceID)\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties"
            if (!(Test-Path $path)) { New-Item $path -Force | Out-Null }
            Set-ItemProperty -Path $path -Name "MSISupported" -Type DWord -Value 1
        }
}

function DisableTelemetry {
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection",
    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" | 
        ForEach-Object { Set-ItemProperty -Path $_ -Name "AllowTelemetry" -Type DWord -Value 0 -ErrorAction SilentlyContinue }
    "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
    "Microsoft\Windows\Application Experience\ProgramDataUpdater",
    "Microsoft\Windows\Autochk\Proxy",
    "Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
    "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
    "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | 
        ForEach-Object { Disable-ScheduledTask -TaskName $_ -ErrorAction SilentlyContinue | Out-Null }
}

function DisableWiFiSense {
    $paths = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi", "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"
    foreach ($path in $paths) { if (!(Test-Path $path)) { New-Item $path -Force | Out-Null } }
    Set-ItemProperty -Path $paths[0] -Name "AllowWiFiHotSpotReporting" -Value 0 -Type DWord
    Set-ItemProperty -Path $paths[0] -Name "AllowAutoConnectToWiFiSenseHotspots" -Value 0 -Type DWord
    Set-ItemProperty -Path $paths[1] -Name "AutoConnectAllowedOEM" -Value 0 -Type DWord
    Set-ItemProperty -Path $paths[1] -Name "WiFISenseAllowed" -Value 0 -Type DWord
}

function DisableSmartScreen {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Type DWord -Value 0
    $path = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter"
    if (!(Test-Path $path)) { New-Item $path -Force | Out-Null }
    Set-ItemProperty -Path $path -Name "EnabledV9" -Type DWord -Value 0
}

function DisableWebSearch {
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Type DWord -Value 0
    $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    if (!(Test-Path $path)) { New-Item $path -Force | Out-Null }
    Set-ItemProperty -Path $path -Name "DisableWebSearch" -Type DWord -Value 1
}

function DisableAppSuggestions {
    $path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    "ContentDeliveryAllowed", "OemPreInstalledAppsEnabled", "PreInstalledAppsEnabled", "PreInstalledAppsEverEnabled", 
    "SilentInstalledAppsEnabled", "SubscribedContent-338387Enabled", "SubscribedContent-338388Enabled", 
    "SubscribedContent-338389Enabled", "SubscribedContent-353698Enabled", "SystemPaneSuggestionsEnabled" | 
        ForEach-Object { Set-ItemProperty -Path $path -Name $_ -Type DWord -Value 0 }
    $cloudPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
    if (!(Test-Path $cloudPath)) { New-Item $cloudPath -Force | Out-Null }
    Set-ItemProperty -Path $cloudPath -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1
}

function DisableActivityHistory {
    "EnableActivityFeed", "PublishUserActivities", "UploadUserActivities" | 
        ForEach-Object { Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name $_ -Type DWord -Value 0 }
}

function EnableBackgroundApps {
    Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Exclude "Microsoft.Windows.Cortana*" | 
        ForEach-Object { Remove-ItemProperty -Path $_.PsPath -Name "Disabled", "DisabledByUser" -ErrorAction SilentlyContinue }
}

function DisableLocationTracking {
    $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"
    if (!(Test-Path $path)) { New-Item $path -Force | Out-Null }
    Set-ItemProperty -Path $path -Name "DisableLocation" -Type DWord -Value 1
    Set-ItemProperty -Path $path -Name "DisableLocationScripting" -Type DWord -Value 1
}

function DisableMapUpdates { Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0 }

function DisableFeedback {
    $path = "HKCU:\SOFTWARE\Microsoft\Siuf\Rules"
    if (!(Test-Path $path)) { New-Item $path -Force | Out-Null }
    Set-ItemProperty -Path $path -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
    "Microsoft\Windows\Feedback\Siuf\DmClient", "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" | 
        ForEach-Object { Disable-ScheduledTask -TaskName $_ -ErrorAction SilentlyContinue | Out-Null }
}

function DisableTailoredExperiences {
    $path = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
    if (!(Test-Path $path)) { New-Item $path -Force | Out-Null }
    Set-ItemProperty -Path $path -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1
}

function DisableAdvertisingID {
    $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"
    if (!(Test-Path $path)) { New-Item $path -Force | Out-Null }
    Set-ItemProperty -Path $path -Name "DisabledByGroupPolicy" -Type DWord -Value 1
}

function DisableCortana {
    $searchPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    if (!(Test-Path $searchPath)) { New-Item $searchPath -Force | Out-Null }
    Set-ItemProperty -Path $searchPath -Name "AllowCortana" -Type DWord -Value 0
    $paths = @{
        "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" = @{"AcceptedPrivacyPolicy"=0}
        "HKCU:\SOFTWARE\Microsoft\InputPersonalization" = @{"RestrictImplicitTextCollection"=1;"RestrictImplicitInkCollection"=1}
        "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" = @{"HarvestContacts"=0}
        "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" = @{"AllowInputPersonalization"=0}
    }
    foreach ($path in $paths.Keys) {
        if (!(Test-Path $path)) { New-Item $path -Force | Out-Null }
        foreach ($key in $paths[$path].Keys) {
            Set-ItemProperty -Path $path -Name $key -Type DWord -Value $paths[$path][$key]
        }
    }
}

function DisableErrorReporting {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" -ErrorAction SilentlyContinue | Out-Null
}

function SetP2PUpdateLocal {
    $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
    if (!(Test-Path $path)) { New-Item $path -Force | Out-Null }
    Set-ItemProperty -Path $path -Name "DODownloadMode" -Type DWord -Value 1
}

function DisableWAPPush {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dmwappushservice" -Name "Start" -Type DWord -Value 4
    Stop-Service "dmwappushservice" -Force -ErrorAction SilentlyContinue
}

function DisableNewsFeed {
    $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds"
    if (!(Test-Path $path)) { New-Item $path -Force | Out-Null }
    Set-ItemProperty -Path $path -Name "EnableFeeds" -Type DWord -Value 0
}

function SetUACLow {
    "ConsentPromptBehaviorAdmin", "PromptOnSecureDesktop" | 
        ForEach-Object { Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name $_ -Type DWord -Value 0 }
}

function DisableSMB1 { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force }

function SetCurrentNetworkPrivate {
    $NetworkListManager = [Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]"{DCB00C01-570F-4A9B-8D69-199FDBA5723B}"))
    $NetworkListManager.GetNetworkConnections() | ForEach-Object { $_.GetNetwork().SetCategory(1) }
}

function SetUnknownNetworksPrivate {
    $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103"
    if (!(Test-Path $path)) { New-Item $path -Force | Out-Null }
    Set-ItemProperty -Path $path -Name "Category" -Type DWord -Value 1
}

function DisableNetDevicesAutoInst {
    $path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private"
    if (!(Test-Path $path)) { New-Item $path -Force | Out-Null }
    Set-ItemProperty -Path $path -Name "AutoSetup" -Type DWord -Value 0
}

function EnableF8BootMenu { cmd /c "bcdedit /set `{current`} bootmenupolicy legacy" | Out-Null }

function DisableMeltdownCompatFlag {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" -Name "cadca5fe-87d3-4b96-b7fb-a231484277cc" -Type DWord -Value 0
}

function EnableUpdateMSRT { Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontOfferThroughWUAU" -Type DWord -Value 0 }

function EnableUpdateDriver { 
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -ErrorAction SilentlyContinue 
}

function DisableUpdateRestart {
    $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    if (!(Test-Path $path)) { New-Item $path -Force | Out-Null }
    Set-ItemProperty -Path $path -Name "NoAutoRebootWithLoggedOnUsers" -Type DWord -Value 1
    Set-ItemProperty -Path $path -Name "AUPowerManagement" -Type DWord -Value 0
}

function DisableHomeGroups {
    "HomeGroupListener", "HomeGroupProvider" | ForEach-Object {
        Stop-Service $_ -WarningAction SilentlyContinue
        Set-Service $_ -StartupType Disabled
    }
}

function EnableSharedExperiences { 
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP" -Name "RomeSdkChannelUserAuthzPolicy", "CdpSessionUserAuthzPolicy" -ErrorAction SilentlyContinue 
}

function DisableRemoteAssistance { 
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0 
}

function EnableRemoteDesktop { 
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 0 
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop" 
}

function DisableAutoplay { 
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 1 
}

function DisableAutorun { 
    $path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    if (!(Test-Path $path)) { New-Item $path -Force | Out-Null }
    Set-ItemProperty -Path $path -Name "NoDriveTypeAutoRun" -Type DWord -Value 255 
}

function DisableStorageSense { 
    Remove-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Recurse -ErrorAction SilentlyContinue 
}

function DisableDefragmentation { 
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Defrag\ScheduledDefrag" -ErrorAction SilentlyContinue | Out-Null 
}

function EnableIndexing { 
    Enable-ScheduledTask -TaskName "Microsoft\Windows\Shell\Indexer" -ErrorAction SilentlyContinue | Out-Null 
}

function SetBIOSTimeUTC { 
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -Name "RealTimeIsUniversal" -Type DWord -Value 1 
}

function DisableHibernation { 
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "HibernateEnabled" -Type DWord -Value 0 
    cmd /c "powercfg /hibernate off" | Out-Null 
}

function EnableSleepButton { 
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "SleepButtonEnabled" -Type DWord -Value 1 
}

function DisableSleepTimeout { 
    cmd /c "powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_SLEEP STANDBYIDLE 0" | Out-Null 
    cmd /c "powercfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_SLEEP STANDBYIDLE 0" | Out-Null 
}

function DisableFastStartup { 
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 0 
}

function DISGaming { 
    $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR"
    if (!(Test-Path $path)) { New-Item $path -Force | Out-Null }
    Set-ItemProperty -Path $path -Name "AllowGameDVR" -Type DWord -Value 0 
}

function PowerThrottlingOff { 
    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling"
    if (!(Test-Path $path)) { New-Item $path -Force | Out-Null }
    Set-ItemProperty -Path $path -Name "PowerThrottlingOff" -Type DWord -Value 1 
}

function Win32PrioritySeparation { 
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Type DWord -Value 38 
}

function DisableAERO { 
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type DWord -Value 0 
}

function BSODdetails { 
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "DisplayParameters" -Type DWord -Value 1 
}

function Disablelivetiles { 
    $path = "HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
    if之心Path $path)) { New-Item $path -Force | Out-Null }
    Set-ItemProperty -Path $path -Name "NoTileApplicationNotification" -Type DWord -Value 1 
}

function wallpaperquality { 
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "JPEGImportQuality" -Type DWord -Value 100 
}

function DisableShistory { 
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackDocs" -Type DWord -Value 0 
}

function Disableshortcutword { 
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "link" -Type Binary -Value ([byte[]](0,0,0,0)) 
}

function DisableMouseKKS { 
    Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseHoverTime" -Type String -Value "0" 
}

function DisableTransparency { 
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Type DWord -Value 0 
}

function TurnOffSafeSearch { 
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" -Name "SafeSearch" -Type DWord -Value 0 
}

function DisableCloudSearch { 
    $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    if (!(Test-Path $path)) { New-Item $path -Force | Out-Null }
    Set-ItemProperty -Path $path -Name "AllowCloudSearch" -Type DWord -Value 0 
}

function DisableDeviceHistory { 
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace" -Name "{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -Type DWord -Value 0 
}

function DisableSearchHistroy { 
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "HistoryViewEnabled" -Type DWord -Value 0 
}

function RemoveMeet { 
    $path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace"
    if (!(Test-Path $path)) { New-Item $path -Force | Out-Null }
    Remove-Item -Path "$path\{088e3905-0323-4b02-9826-5d99428e115f}" -ErrorAction SilentlyContinue 
}

function EnableActionCenter { 
    Remove-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -ErrorAction SilentlyContinue 
}

function EnableLockScreen { 
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -ErrorAction SilentlyContinue 
}

function EnableLockScreenRS1 { 
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\SessionData" -Name "AllowLockScreen" -ErrorAction SilentlyContinue 
}

function DisableStickyKeys { 
    Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "506" 
}

function ShowTaskManagerDetails {
    $taskmgr = Start-Process "taskmgr.exe" -PassThru -WindowStyle Hidden
    Start-Sleep -Milliseconds 500
    $prefs = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -ErrorAction SilentlyContinue
    if ($prefs) { Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -Type Binary -Value $prefs.Preferences }
    Stop-Process -Id $taskmgr.Id -Force
}

function ShowFileOperationsDetails { 
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Type DWord -Value 1 
}

function DisableFileDeleteConfirm { 
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ConfirmFileDelete" -Type DWord -Value 0 
}

function HideTaskbarSearch { 
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0 
}

function HideTaskView { 
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0 
}

function HideTaskbarPeopleIcon { 
    $path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People"
    if (!(Test-Path $path)) { New-Item $path -Force | Out-Null }
    Set-ItemProperty -Path $path -Name "PeopleBand" -Type DWord -Value 0 
}

function DisableSearchAppInStore { 
    $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
    if (!(Test-Path $path)) { New-Item $path -Force | Out-Null }
    Set-ItemProperty -Path $path -Name "NoUseStoreOpenWith" -Type DWord -Value 1 
}

function DisableNewAppPrompt { 
    $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
    if (!(Test-Path $path)) { New-Item $path -Force | Out-Null }
    Set-ItemProperty -Path $path -Name "NoNewAppAlert" -Type DWord -Value 1 
}

function SetVisualFXPerformance { 
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Type Binary -Value ([byte[]](0x90,0x12,0x03,0x80,0x10,0x00,0x00,0x00))
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "VisualFXSetting" -Type DWord -Value 3
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value 3
}

function EnableNumlock { 
    Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value 2 
}

function EnableDarkMode { 
    "AppsUseLightTheme", "SystemUsesLightTheme" | 
        ForEach-Object { Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name $_ -Type DWord -Value 0 }
}

function ShowKnownExtensions { 
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0 
}

function HideHiddenFiles { 
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 2 
}

function HideSyncNotifications { 
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Type DWord -Value 0 
}

function HideRecentShortcuts { 
    "ShowRecent", "ShowFrequent" | 
        ForEach-Object { Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name $_ -Type DWord -Value 0 }
}

function SetExplorerThisPC { 
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1 
}

function ShowThisPCOnDesktop { 
    $path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
    if (!(Test-Path $path)) { New-Item $path -Force | Out-Null }
}

function ShowUserFolderOnDesktop { 
    $path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{59031a47-3f72-44a7-89c5-5595fe6b30ee}"
    if (!(Test-Path $path)) { New-Item $path -Force | Out-Null }
}

function Hide3DObjectsFromThisPC { 
    Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue 
}

function Hide3DObjectsFromExplorer { 
    $path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag"
    if (!(Test-Path $path)) { New-Item $path -Force | Out-Null }
    Set-ItemProperty -Path $path -Name "ThisPCPolicy" -Type String -Value "Hide" 
}

function EnableThumbnails { 
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "IconsOnly" -Type DWord -Value 0 
}

function EnableThumbsDB { 
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbnailCache" -Type DWord -Value 0 
}

function UninstallInternetExplorer { 
    Disable-WindowsOptionalFeature -Online -FeatureName "Internet-Explorer-Optional-$env:PROCESSOR_ARCHITECTURE" -NoRestart -ErrorAction SilentlyContinue | Out-Null 
}

function UninstallWorkFolders { 
    Disable-WindowsOptionalFeature -Online -FeatureName "WorkFolders-Client" -NoRestart -ErrorAction SilentlyContinue | Out-Null 
}

function UninstallLinuxSubsystem { 
    Disable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-Subsystem-Linux" -NoRestart -ErrorAction SilentlyContinue | Out-Null 
}

function SetPhotoViewerAssociation { 
    if (!(Test-Path "HKCR:\Paint.Picture")) { New-Item "HKCR:\Paint.Picture" -Force | Out-Null }
    Set-ItemProperty -Path "HKCR:\Paint.Picture" -Name "(Default)" -Type String -Value "PhotoViewer.FileAssoc.Bitmap" 
}

function AddPhotoViewerOpenWith { 
    $path = "HKCR:\Applications\photoviewer.dll\shell\open"
    if (!(Test-Path $path)) { New-Item $path -Force | Out-Null }
    Set-ItemProperty -Path $path -Name "MuiVerb" -Type String -Value "@photoviewer.dll,-3043"
    $cmdPath = "$path\command"
    if (!(Test-Path $cmdPath)) { New-Item $cmdPath -Force | Out-Null }
    Set-ItemProperty -Path $cmdPath -Name "(Default)" -Type ExpandString -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1"
}

function InstallPDFPrinter { 
    Enable-WindowsOptionalFeature -Online -FeatureName "Printing-XPSServices-Features" -NoRestart -ErrorAction SilentlyContinue | Out-Null 
}

function SVCHostTweak { 
    $threshold = [math]::Round((Get-CimInstance Win32_PhysicalMemory | Measure-Object Capacity -Sum).Sum / 2KB)
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -Type DWord -Value $threshold 
}

function UnpinStartMenuTiles { 
    $key = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\*$windows.data.start.tilegrid\windows.data.start.tilegrid" -ErrorAction SilentlyContinue
    if ($key) { Remove-Item $key.PSPath -Recurse -Force }
}

function QOL { 
    Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name "sShortDate" -Type String -Value "dd/MM/yyyy"
    Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name "sTimeFormat" -Type String -Value "HH:mm:ss"
}

function FullscreenOptimizationFIX { 
    "GameDVR_DXGIHonorFSEWindowsCompatible", "GameDVR_HonorUserFSEBehaviorMode" | 
        ForEach-Object { Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name $_ -Type DWord -Value 1 }
    Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehavior" -Type DWord -Value 2
}

function GameOptimizationFIX { 
    $path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"
    Set-ItemProperty -Path $path -Name "Priority" -Type DWord -Value 6
    Set-ItemProperty -Path $path -Name "Scheduling Category" -Type String -Value "High"
    Set-ItemProperty -Path $path -Name "SFIO Priority" -Type String -Value "High"
}

function RawMouseInput { 
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" -Name "MouseDataQueueSize" -Type DWord -Value 50
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" -Name "KeyboardDataQueueSize" -Type DWord -Value 50
}

function DetectnApplyMouseFIX { 
    Get-WmiObject Win32_PnPEntity | Where-Object { $_.Name -like "*mouse*" -and $_.Status -eq "OK" } | 
        ForEach-Object { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\$($_.DeviceID)" -Name "FlipFlopWheel" -Type DWord -Value 0 -ErrorAction SilentlyContinue }
}

function DisableHPET { 
    cmd /c "bcdedit /set useplatformclock false" | Out-Null
    cmd /c "bcdedit /set disabledynamictick yes" | Out-Null
}

function EnableGameMode { 
    "AllowAutoGameMode", "AutoGameModeEnabled" | 
        ForEach-Object { Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name $_ -Type DWord -Value 1 }
}

function EnableHAGS { 
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "HwSchMode" -Type DWord -Value 2 
}

function DisableCoreParking { 
    powercfg -setacvalueindex SCHEME_CURRENT SUB_PROCESSOR CPMINCORES 100
    powercfg -setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR CPMINCORES 100
    powercfg -setactive SCHEME_CURRENT
}

function DisableDMA { 
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "DmaRemappingCompatible" -Type DWord -Value 0 
}

function DisablePKM { 
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "PlatformAoAcOverride" -Type DWord -Value 0 
}

function DisallowDIP { 
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowDomainPinCode" -Type DWord -Value 0 
}

function UseBigM { 
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "LargeSystemCache" -Type DWord -Value 1 
}

function ForceContiguousM { 
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "PhysicalAddressExtension" -Type DWord -Value 1 
}

function DecreaseMKBuffer { 
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" -Name "MouseDataQueueSize" -Type DWord -Value 20
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" -Name "KeyboardDataQueueSize" -Type DWord -Value 20
}

function StophighDPC { 
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NDIS\Parameters" -Name "MaxNumRssCpus" -Type DWord -Value 4
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0000" -Name "RSS" -Type DWord -Value 1 -ErrorAction SilentlyContinue
}

function NvidiaTweaks { 
    $path = "HKLM:\SYSTEM\CurrentControlSet\Services\nvlddmkm"
    if (Test-Path $path) {
        Set-ItemProperty -Path $path -Name "DisablePreemption" -Type DWord -Value 1
        Set-ItemProperty -Path $path -Name "EnableTiledDisplay" -Type DWord -Value 0
        Set-ItemProperty -Path $path -Name "PowerMizerEnable" -Type DWord -Value 0
    }
}

function AMDGPUTweaks { 
    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000"
    if (Test-Path $path) {
        Set-ItemProperty -Path $path -Name "DisableBlockWrite" -Type DWord -Value 0
        Set-ItemProperty -Path $path -Name "PP_ThermalAutoThrottlingEnable" -Type DWord -Value 0
        Set-ItemProperty -Path $path -Name "EnableULPS" -Type DWord -Value 0
    }
}

function NetworkAdapterRSS { 
    Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | ForEach-Object { Set-NetAdapterRss -Name $_.Name -Enabled $true -ErrorAction SilentlyContinue }
}

function NetworkOptimizations { 
    $path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    Set-ItemProperty -Path $path -Name "DefaultTTL" -Type DWord -Value 64
    Set-ItemProperty -Path $path -Name "TcpMaxDataRetransmissions" -Type DWord -Value 5
    Set-ItemProperty -Path $path -Name "MaxUserPort" -Type DWord -Value 65534
}

function DisableNagle { 
    Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" | ForEach-Object {
        Set-ItemProperty -Path $_.PSPath -Name "TcpAckFrequency" -Type DWord -Value 1 -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $_.PSPath -Name "TCPNoDelay" -Type DWord -Value 1 -ErrorAction SilentlyContinue
    }
}

function Ativar-Servicos { 
    "wuauserv", "bits", "cryptsvc" | ForEach-Object { 
        Set-Service $_ -StartupType Automatic
        Start-Service $_ -ErrorAction SilentlyContinue 
    }
}

function RemoveEdit3D { 
    Remove-ItemProperty -Path "HKCR:\SystemFileAssociations\.3mf\Shell\Edit" -Name "(Default)" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKCR:\SystemFileAssociations\.stl\Shell\Edit" -Name "(Default)" -ErrorAction SilentlyContinue
}

function FixURLext { 
    Set-ItemProperty -Path "HKCR:\.url" -Name "(Default)" -Type String -Value "InternetShortcut"
    Set-ItemProperty -Path "HKCR:\InternetShortcut" -Name "IsShortcut" -Type String -Value ""
}

function UltimateCleaner { 
    Remove-Item -Path "$env:TEMP\*", "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
    cmd /c "cleanmgr /sagerun:1" | Out-Null
}

function Clear-PSHistory { 
    Remove-Item -Path (Get-PSReadLineOption).HistorySavePath -Force -ErrorAction SilentlyContinue 
}

function Finished { 
    Clear-Host
    Escrever-Colorido "Otimização concluída com sucesso!`nReinicie o sistema para aplicar todas as alterações." "Verde"
    if ((Read-Host "Deseja reiniciar agora? (S/N)") -imatch '^s$') { Restart-Computer -Force }
}

# Executar tweaks
foreach ($tweak in $tweaks) { Invoke-Expression $tweak }