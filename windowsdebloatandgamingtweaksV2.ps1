##########
# Master Branch : https://github.com/ChrisTitusTech/win10script
# Current Author : Daddy Madu 
# Current Author Source: https://github.com/DaddyMadu/Windows10GamingFocus
# Current Modifier Source: https://github.com/wesscd/WindowsGaming
#
##########

chcp 860

function Escrever-Colorido {
	param (
		[string]$Texto,
		[string]$Cor
	)
	$cores = @{
		'Preto'         = 'Black'
		'Azul'          = 'DarkBlue'
		'Verde'         = 'DarkGreen'
		'Ciano'         = 'DarkCyan'
		'Vermelho'      = 'DarkRed'
		'Magenta'       = 'DarkMagenta'
		'Amarelo'       = 'DarkYellow'
		'CinzaClaro'    = 'Gray'
		'CinzaEscuro'   = 'DarkGray'
		'AzulClaro'     = 'Blue'
		'VerdeClaro'    = 'Green'
		'CianoClaro'    = 'Cyan'
		'VermelhoClaro' = 'Red'
		'MagentaClaro'  = 'Magenta'
		'AmareloClaro'  = 'Yellow'
		'Branco'        = 'White'
	}
	Write-Host $Texto -ForegroundColor $cores[$Cor]
}

$host.ui.RawUI.WindowTitle = "-- TechRemote Ultimate Windows Debloater Gaming v.0.7.0.4 (VM GROK) --"
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

New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT -ErrorAction SilentlyContinue | Out-Null
New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -ErrorAction SilentlyContinue | Out-Null

$currentexename = (([Diagnostics.Process]::GetCurrentProcess().ProcessName) + '.exe')
if ($currentexename -eq "pwsh.exe") {
	Start-Process Powershell -Argumentlist '-ExecutionPolicy bypass -NoProfile -command "irm "https://raw.githubusercontent.com/wesscd/WindowsGaming/master/windowsdebloatandgamingtweaks.ps1" | iex"' -Verb RunAs
	exit
}
Clear-Host

# Carregar módulos
Import-Module ".\Modules\PrivacyTweaks.ps1" -Force
Import-Module ".\Modules\PerformanceTweaks.ps1" -Force

#Desktop Devices presets.
$tweaks = @(
	"RequireAdmin",
	"CreateRestorePoint",
	"InstallMVC",
	"Install7Zip",
	"SlowUpdatesTweaks",
	"Write-ColorOutput", 
	"InstallTitusProgs",
	"check-Windows",
	"Execute-BatchScript", 
	"Set-RamThreshold",
	"Set-MemoriaVirtual-Registry",
	"DownloadAndExtractISLC",
	"UpdateISLCConfig",
	"InstallChocoUpdates",
	"EnableUlimatePower",
	"MSIMode",
	"askDefender",
	"DorEOneDrive",
	"askXBOX",
	"Windows11Extra",
	"DebloatAll",
	"RemoveBloatRegistry",
	"UninstallOneDrive",
	#"InstallOneDrive",  # Opcional, só se quiser oferecer a reversão
	"UninstallMsftBloat",
	"DisableXboxFeatures",
	"DisableTelemetry",
	"DisableWiFiSense",
	"DisableSmartScreen",
	"DisableWebSearch",
	"DisableAppSuggestions",
	"DisableActivityHistory",
	"EnableBackgroundApps",
	"DisableLocationTracking",
	"DisableMapUpdates",
	"DisableFeedback",
	"DisableTailoredExperiences",
	"DisableAdvertisingID",
	"DisableCortana",
	"DisableErrorReporting",
	"SetP2PUpdateLocal",
	"DisableWAPPush",
	"DisableNewsFeed",
	"SetUACLow",
	"DisableSMB1",
	"SetCurrentNetworkPrivate",
	"SetUnknownNetworksPrivate",
	"DisableNetDevicesAutoInst",
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
	"DISGaming",
	"PowerThrottlingOff",
	"Win32PrioritySeparation",
	"DisableAERO",
	"BSODdetails",
	"Disablelivetiles",
	"wallpaperquality",
	"DisableShistory",
	"Disableshortcutword",
	"DisableMouseKKS",
	"DisableTransparency",
	"TurnOffSafeSearch",
	"DisableCloudSearch",
	"DisableDeviceHistory",
	"DisableSearchHistroy",
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
	"ApplyPCOptimizations",
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
	"NvidiaTweaks",
	"AMDGPUTweaks",
	"NetworkAdapterRSS",
	"NetworkOptimizations",
	"DisableNagle",
	"Ativar-Servicos",
	"RemoveEdit3D",
	"FixURLext",
	"UltimateCleaner",
	"Clear-PSHistory",
	"Finished"
)

#########
# Pre Customizations
#########

function Show-Choco-Menu {
	param(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[string]$Title,
    
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[string]$ChocoInstall
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
 }
 until ($selection -match "y" -or $selection -match "n" -or $selection -match "q")
}



#Utilizing Clolors For Better Warning Messages!
function Write-ColorOutput {
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $False, Position = 1, ValueFromPipeline = $True, ValueFromPipelinebyPropertyName = $True)][Object] $Object,
		[Parameter(Mandatory = $False, Position = 2, ValueFromPipeline = $True, ValueFromPipelinebyPropertyName = $True)][ConsoleColor] $ForegroundColor,
		[Parameter(Mandatory = $False, Position = 3, ValueFromPipeline = $True, ValueFromPipelinebyPropertyName = $True)][ConsoleColor] $BackgroundColor,
		[Switch]$NoNewline
	)    

	# Save previous colors
	$previousForegroundColor = $host.UI.RawUI.ForegroundColor
	$previousBackgroundColor = $host.UI.RawUI.BackgroundColor

	# Set BackgroundColor if available
	if ($BackgroundColor -ne $null) { 
		$host.UI.RawUI.BackgroundColor = $BackgroundColor
	}

	# Set $ForegroundColor if available
	if ($ForegroundColor -ne $null) {
		$host.UI.RawUI.ForegroundColor = $ForegroundColor
	}

	# Always write (if we want just a NewLine)
	if ($null -eq $Object) {
		$Object = ""
	}

	if ($NoNewline) {
		[Console]::Write($Object)
	}
	else {
		Write-Output $Object
	}

	# Restore previous colors
	$host.UI.RawUI.ForegroundColor = $previousForegroundColor
	$host.UI.RawUI.BackgroundColor = $previousBackgroundColor
}

Function InstallTitusProgs {

	Write-Output "Verificando e instalando Chocolatey, se necessario..."
    
	# Verifica se o Chocolatey está instalado
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
		Write-Output "Chocolatey ja esta instalado."
	}
    
	# Instala o pacote chocolatey-core.extension
	try {
		choco install chocolatey-core.extension -y
	}
 catch {
		Write-Output "Erro ao instalar chocolatey-core.extension: $_"
	}
    
	Write-Output "Executando O&O ShutUp10 com as configuracoes recomendadas..."
    
	# Importa módulo para transferência de arquivos
	Import-Module BitsTransfer
    
	try {
		# Define URLs dos arquivos
		$configUrl = "https://raw.githubusercontent.com/wesscd/WindowsGaming/master/ooshutup10.cfg"
		$exeUrl = "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe"
        
		# Define caminhos locais
		$configFile = "$env:TEMP\ooshutup10.cfg"
		$exeFile = "$env:TEMP\OOSU10.exe"
        
		# Baixa os arquivos para o diretório temporário
		Start-BitsTransfer -Source $configUrl -Destination $configFile
		Start-BitsTransfer -Source $exeUrl -Destination $exeFile
        
		# Executa o O&O ShutUp10 com a configuração baixada
		& $exeFile $configFile /quiet
		Start-Sleep -Seconds 10
        
		# Remove os arquivos baixados
		Remove-Item -Path $configFile, $exeFile -Force -ErrorAction Stop
		Write-Output "O&O ShutUp10 executado e arquivos temporarios removidos."
	}
 catch {
		Write-Output "Erro ao executar O&O ShutUp10: $_"
	}
}

# Ccleaner
Function Execute-BatchScript {
	Clear-Host
	Escrever-Colorido "" "Azul"
	Escrever-Colorido "Realizando limpeza de cache dos navegadores" "Verde"

	$url = "https://raw.githubusercontent.com/wesscd/WindowsGaming/master/script-ccleaner.bat"
	$localPath = "$env:temp\script-ccleaner.bat"
  
	# Baixa o arquivo .bat
	Invoke-WebRequest -Uri $url -OutFile $localPath
  
	# Executa o script .bat
	Start-Process -FilePath $localPath -ArgumentList "/c $localPath" -Wait

	# Opcional: Remove o arquivo .bat após execução
	Remove-Item -Path $localPath -Force
	Write-Output "Script .bat executado e removido com sucesso."
}


function check-Windows {
	# Verifica o status de ativação do Windows
	$activationStatus = (Get-CimInstance -ClassName SoftwareLicensingProduct -Filter "Name like 'Windows%'" | Where-Object { $_.PartialProductKey }).LicenseStatus

	if ($activationStatus -eq 1) {
		Clear-Host
		Escrever-Colorido "" "Azul"
		Escrever-Colorido "O Windows está ativado." "Azul"
	}
 else {
		Clear-Host
		Escrever-Colorido "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*" "Vermelho"
		Escrever-Colorido "| O Windows NÃO está ativado. Executando o comando de ativação. |" "Vermelho"
		Escrever-Colorido "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*" "Vermelho"
		# Executa o comando de ativação
		irm https://get.activated.win | iex

	}

	
}

# Install the latest Microsoft Visual C++ 2010-2019 Redistributable Packages and Silverlight
Function InstallMVC {
	choco install -y vcredist2010 | Out-Null
}
Function Install7Zip {
	Choco Install 7zip -y
}

Function InstallChocoUpdates {
	Clear-Host
	choco upgrade all -y
}



#Enable or Disable and remove xbox related apps
Function askXBOX {
	# Detectar versão do Windows
	$winVer = [System.Environment]::OSVersion.Version
	$isWin11 = $winVer.Major -eq 10 -and $winVer.Build -ge 22000  # Windows 11 começa no build 22000

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

	} until ($selection -match "(?i)^(d|h|p)$") # Aceita letras maiúsculas ou minúsculas

	if ($selection -match "(?i)^d$") {
  # Desabilitar Xbox
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

			# Windows 11 tem esse aplicativo adicional
			if ($isWin11) {
				$xboxApps += "Microsoft.XboxGamingOverlay"
			}

			foreach ($app in $xboxApps) {
				$pkg = Get-AppxPackage $app
				if ($pkg) {
					$pkg | Remove-AppxPackage
				}
			}

			Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 0

			if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR")) {
				New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Force | Out-Null
			}

			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0
		}
		finally {
			$ErrorActionPreference = $errpref  # Restaura a preferência de erro
		}
	}

	elseif ($selection -match "(?i)^h$") {
  # Habilitar Xbox
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

			if ($isWin11) {
				$xboxApps += "Microsoft.XboxGamingOverlay"
			}

			foreach ($app in $xboxApps) {
				$pkg = Get-AppxPackage -AllUsers $app
				if ($pkg) {
					$pkg | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
				}
			}

			Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 1
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -ErrorAction SilentlyContinue
		}
		finally {
			$ErrorActionPreference = $errpref  # Restaura a preferência de erro
		}
	}
}

##########
# Privacy Tweaks
##########





# Enable Feedback
Function EnableFeedback {
	Write-Output "Enabling Feedback..."
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -ErrorAction SilentlyContinue
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null
}



# Enable Tailored Experiences
Function EnableTailoredExperiences {
	Write-Output "Enabling Tailored Experiences..."
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -ErrorAction SilentlyContinue
}



# Enable Advertising ID
Function EnableAdvertisingID {
	Write-Output "Enabling Advertising ID..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -ErrorAction SilentlyContinue
}



# Enable Cortana
Function EnableCortana {
	Write-Output "Enabling Cortana..."
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -ErrorAction SilentlyContinue
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 0
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -ErrorAction SilentlyContinue
}


# Enable Error reporting
Function EnableErrorReporting {
	Write-Output "Enabling Error reporting..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -ErrorAction SilentlyContinue
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null
}



# Unrestrict Windows Update P2P
Function SetP2PUpdateInternet {
	Write-Output "Unrestricting Windows Update P2P to internet..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -ErrorAction SilentlyContinue
}



# Enable and start WAP Push Service
Function EnableWAPPush {
	Write-Output "Enabling and starting WAP Push Service..."
	Set-Service "dmwappushservice" -StartupType Automatic
	Start-Service "dmwappushservice" -WarningAction SilentlyContinue
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushservice" -Name "DelayedAutoStart" -Type DWord -Value 1
}

# Disable New Windows 10 21h1 News Feed
Function DisableNewsFeed {
	Write-Output "Disabling Windows 10 News and Interests Feed..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds" -Name "ShellFeedsTaskbarViewMode" -Type DWord -Value 2
}

##########
# Security Tweaks
##########

# Lower UAC level (disabling it completely would break apps)
Function SetUACLow {
	Write-Output "Lowering UAC level..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 0
}

# Raise UAC level
Function SetUACHigh {
	Write-Output "Raising UAC level..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 5
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 1
}

# Enable sharing mapped drives between users
Function EnableSharingMappedDrives {
	Write-Output "Enabling sharing mapped drives between users..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLinkedConnections" -Type DWord -Value 1
}

# Disable sharing mapped drives between users
Function DisableSharingMappedDrives {
	Write-Output "Disabling sharing mapped drives between users..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLinkedConnections" -ErrorAction SilentlyContinue
}

# Disable implicit administrative shares
Function DisableAdminShares {
	Write-Output "Disabling implicit administrative shares..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareWks" -Type DWord -Value 0
}

# Enable implicit administrative shares
Function EnableAdminShares {
	Write-Output "Enabling implicit administrative shares..."
	Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareWks" -ErrorAction SilentlyContinue
}

# Disable obsolete SMB 1.0 protocol - Disabled by default since 1709
Function DisableSMB1 {
	Write-Output "Disabling SMB 1.0 protocol..."
	Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
}

# Enable obsolete SMB 1.0 protocol - Disabled by default since 1709
Function EnableSMB1 {
	Write-Output "Enabling SMB 1.0 protocol..."
	Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force
}

# Disable SMB Server - Completely disables file and printer sharing, but leaves the system able to connect to another SMB server as a client
Function DisableSMBServer {
	Write-Output "Disabling SMB Server..."
	Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
	Set-SmbServerConfiguration -EnableSMB2Protocol $false -Force
}

# Enable SMB Server
Function EnableSMBServer {
	Write-Output "Enabling SMB Server..."
	Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force
}

# Disable Link-Local Multicast Name Resolution (LLMNR) protocol
Function DisableLLMNR {
	Write-Output "Disabling LLMNR..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Type DWord -Value 0
}

# Enable Link-Local Multicast Name Resolution (LLMNR) protocol
Function EnableLLMNR {
	Write-Output "Enabling LLMNR..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue
}

# Set current network profile to private (allow file sharing, device discovery, etc.)
Function SetCurrentNetworkPrivate {
	Write-Output "Setting current network profile to private..."
	Set-NetConnectionProfile -NetworkCategory Private
}

# Set current network profile to public (deny file sharing, device discovery, etc.)
Function SetCurrentNetworkPublic {
	Write-Output "Setting current network profile to public..."
	Set-NetConnectionProfile -NetworkCategory Public
}

# Set unknown networks profile to private (allow file sharing, device discovery, etc.)
Function SetUnknownNetworksPrivate {
	Write-Output "Setting unknown networks profile to private..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" -Name "Category" -Type DWord -Value 1
}

# Set unknown networks profile to public (deny file sharing, device discovery, etc.)
Function SetUnknownNetworksPublic {
	Write-Output "Setting unknown networks profile to public..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" -Name "Category" -ErrorAction SilentlyContinue
}

# Disable automatic installation of network devices
Function DisableNetDevicesAutoInst {
	Write-Output "Disabling automatic installation of network devices..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name "AutoSetup" -Type DWord -Value 0
}

# Enable automatic installation of network devices
Function EnableNetDevicesAutoInst {
	Write-Output "Enabling automatic installation of network devices..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name "AutoSetup" -ErrorAction SilentlyContinue
}

#Ask User If He Want to Enable Or Disable Windows Defender
Function askDefender {
	# Verifica a versão do Windows
	$osVersion = [System.Environment]::OSVersion.Version
	$isWindows11 = $osVersion.Build -ge 22000  # Windows 11 tem build 22000+

	# Verifica se o script está rodando como administrador
	function Test-Admin {
		$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
		$principal = New-Object Security.Principal.WindowsPrincipal $currentUser
		return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
	}

	if (-not (Test-Admin)) {
		Escrever-Colorido "Este script precisa ser executado como Administrador. Por favor, execute-o novamente como Administrador." "Vermelho"
		break;
	}

	do {
		Clear-Host
		Escrever-Colorido "" "Azul"
		Escrever-Colorido "================ Desabilitar o Microsoft Windows Defender? ================" "Azul"
		Escrever-Colorido "" "Azul"
		Escrever-Colorido "Pressione 'D' para desabilitar o Microsoft Windows Defender." "Azul"
		Escrever-Colorido "Pressione 'H' para habilitar o Microsoft Windows Defender." "Azul"
		Escrever-Colorido "Pressione 'P' para pular isso." "Azul"
			
		$selection = Read-Host "Por favor, escolha."

	} until ($selection -match "(?i)^(d|h|p)$") # Entrada case-insensitive

	if ($selection -match "(?i)^d$") {
  # Desativar Windows Defender
		Write-Output "Desativando Microsoft Windows Defender e processos relacionados..."

		# Desativa o Firewall
		if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile") {
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -Name "EnableFirewall" -Type DWord -Value 0
		}

		# Desativa o Windows Defender
		if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender")) {
			New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 1

		# Remove do registro o lançamento do Defender na inicialização
		if ($osVersion.Build -eq 14393) {
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsDefender" -ErrorAction SilentlyContinue
		}
		elseif ($osVersion.Build -ge 15063) {
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -ErrorAction SilentlyContinue
		}

		# Desativa envio de relatórios do Defender
		if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet")) {
			New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Type DWord -Value 0
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Type DWord -Value 2

		# Desativa proteção potencialmente indesejada (PUA)
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "PUAProtection" -ErrorAction SilentlyContinue

		# Desativa pastas protegidas (Controlled Folder Access)
		Set-MpPreference -EnableControlledFolderAccess Disabled -ErrorAction SilentlyContinue

		# Desativa tarefas do Defender
		$tasks = @(
			"\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance",
			"\Microsoft\Windows\Windows Defender\Windows Defender Cleanup",
			"\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan",
			"\Microsoft\Windows\Windows Defender\Windows Defender Verification"
		)

		foreach ($task in $tasks) {
			Disable-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
		}
	}

	elseif ($selection -match "(?i)^h$") {
  # Habilitar Windows Defender
		Write-Output "Ativando Microsoft Windows Defender e processos relacionados..."

		# Reativa o Firewall
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -Name "EnableFirewall" -ErrorAction SilentlyContinue

		# Reativa o Windows Defender
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -ErrorAction SilentlyContinue

		# Reativa inicialização do Defender
		if ($osVersion.Build -eq 14393) {
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsDefender" -Type ExpandString -Value "`"%ProgramFiles%\Windows Defender\MSASCuiL.exe`""
		}
		elseif ($osVersion.Build -ge 15063) {
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -Type ExpandString -Value "%windir%\system32\SecurityHealthSystray.exe"
		}

		# Remove restrições do Defender
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -ErrorAction SilentlyContinue
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -ErrorAction SilentlyContinue
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "PUAProtection" -Type DWord -Value 1

		# Reativa tarefas agendadas do Defender
		foreach ($task in $tasks) {
			Enable-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
		}
	}
}


# Enable F8 boot menu options
Function EnableF8BootMenu {
	Write-Output "Enabling F8 boot menu options..."
	bcdedit /set bootmenupolicy Legacy | Out-Null
}

# Disable F8 boot menu options
Function DisableF8BootMenu {
	Write-Output "Disabling F8 boot menu options..."
	bcdedit /set bootmenupolicy Standard | Out-Null
}

# Set Data Execution Prevention (DEP) policy to OptOut
Function SetDEPOptOut {
	Write-Output "Setting Data Execution Prevention (DEP) policy to OptOut..."
	bcdedit /set nx OptOut | Out-Null
}

# Set Data Execution Prevention (DEP) policy to OptIn
Function SetDEPOptIn {
	Write-Output "Setting Data Execution Prevention (DEP) policy to OptIn..."
	bcdedit /set nx OptIn | Out-Null
}

# Enable Core Isolation Memory Integrity - Part of Windows Defender System Guard virtualization-based security - Supported from 1803
Function EnableCIMemoryIntegrity {
	Write-Output "Enabling Core Isolation Memory Integrity..."
	If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity")) {
		New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Type DWord -Value 1
}

# Disable Core Isolation Memory Integrity - 
Function DisableCIMemoryIntegrity {
	Write-Output "Disabling Core Isolation Memory Integrity..."
	Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -ErrorAction SilentlyContinue
}

# Disable Windows Script Host (execution of *.vbs scripts and alike)
Function DisableScriptHost {
	Write-Output "Disabling Windows Script Host..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Type DWord -Value 0
}

# Enable Windows Script Host
Function EnableScriptHost {
	Write-Output "Enabling Windows Script Host..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -ErrorAction SilentlyContinue
}

# Enable strong cryptography for .NET Framework (version 4 and above)
# https://stackoverflow.com/questions/36265534/invoke-webrequest-ssl-fails
Function EnableDotNetStrongCrypto {
	Write-output "Enabling .NET strong cryptography..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Type DWord -Value 1
}

# Disable strong cryptography for .NET Framework (version 4 and above)
Function DisableDotNetStrongCrypto {
	Write-output "Disabling .NET strong cryptography..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -ErrorAction SilentlyContinue
}

# Enable Meltdown (CVE-2017-5754) compatibility flag - Required for January 2018 and all subsequent Windows updates
# This flag is normally automatically enabled by compatible antivirus software (such as Windows Defender).
# Use the tweak only if you have confirmed that your AV is compatible but unable to set the flag automatically or if you don't use any AV at all.
# See https://support.microsoft.com/en-us/help/4072699/january-3-2018-windows-security-updates-and-antivirus-software for details.
Function EnableMeltdownCompatFlag {
	Write-Output "Enabling Meltdown (CVE-2017-5754) compatibility flag..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" -Name "cadca5fe-87d3-4b96-b7fb-a231484277cc" -Type DWord -Value 0
}

# Disable Meltdown (CVE-2017-5754) compatibility flag
Function DisableMeltdownCompatFlag {
	Write-Output "Disabling Meltdown (CVE-2017-5754) compatibility flag..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" -Name "cadca5fe-87d3-4b96-b7fb-a231484277cc" -ErrorAction SilentlyContinue
}



##########
# Service Tweaks
##########
#Disabling Un nessessary Services For Gaming
Function DISGaming {
	Write-Output "Stopping and disabling Un nessessary Services For Gaming..."
	$errpref = $ErrorActionPreference #save actual preference
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
	$ErrorActionPreference = $errpref #restore previous preference
}

# Disable offering of Malicious Software Removal Tool through Windows Update
Function DisableUpdateMSRT {
	Write-Output "Disabling Malicious Software Removal Tool offering..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontOfferThroughWUAU" -Type DWord -Value 1
}

# Enable offering of Malicious Software Removal Tool through Windows Update
Function EnableUpdateMSRT {
	Write-Output "Enabling Malicious Software Removal Tool offering..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontOfferThroughWUAU" -ErrorAction SilentlyContinue
}

# Disable offering of drivers through Windows Update
# Note: This doesn't work properly if you use a driver intended for another hardware model. E.g. Intel I219-V on WinServer works only with I219-LM driver.
# Therefore Windows update will repeatedly try and fail to install I219-V driver indefinitely even if you use the tweak.
Function DisableUpdateDriver {
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

# Enable offering of drivers through Windows Update
Function EnableUpdateDriver {
	Write-Output "Enabling driver offering through Windows Update..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontPromptForWindowsUpdate" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchWindowsUpdate" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DriverUpdateWizardWuSearchEnabled" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -ErrorAction SilentlyContinue
}

# Disable Windows Update automatic restart
# Note: This doesn't disable the need for the restart but rather tries to ensure that the restart doesn't happen in the least expected moment. Allow the machine to restart as soon as possible anyway.
Function DisableUpdateRestart {
	Write-Output "Disabling Windows Update automatic restart..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -Type DWord -Value 0
}

# Enable Windows Update automatic restart
Function EnableUpdateRestart {
	Write-Output "Enabling Windows Update automatic restart..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -ErrorAction SilentlyContinue
}

# Stop and disable Home Groups services - Not applicable to 1803 and newer or Server
Function DisableHomeGroups {
	Write-Output "Stopping and disabling Home Groups services..."
	$errpref = $ErrorActionPreference #save actual preference
	$ErrorActionPreference = "silentlycontinue"
	Stop-Service "HomeGroupListener" -WarningAction SilentlyContinue
	Set-Service "HomeGroupListener" -StartupType Disabled
	Stop-Service "HomeGroupProvider" -WarningAction SilentlyContinue
	Set-Service "HomeGroupProvider" -StartupType Disabled
	$ErrorActionPreference = $errpref #restore previous preference
}

# Enable and start Home Groups services - Not applicable to 1803 and newer or Server
Function EnableHomeGroups {
	Write-Output "Starting and enabling Home Groups services..."
	$errpref = $ErrorActionPreference #save actual preference
	$ErrorActionPreference = "silentlycontinue"
	Set-Service "HomeGroupListener" -StartupType Manual
	Set-Service "HomeGroupProvider" -StartupType Manual
	Start-Service "HomeGroupProvider" -WarningAction SilentlyContinue
	$ErrorActionPreference = $errpref #restore previous preference
}

# Disable Shared Experiences - Not applicable to Server
Function DisableSharedExperiences {
	Write-Output "Disabling Shared Experiences..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableCdp" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableMmx" -Type DWord -Value 0
}

# Enable Shared Experiences - Not applicable to Server
Function EnableSharedExperiences {
	Write-Output "Enabling Shared Experiences..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableCdp" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableMmx" -ErrorAction SilentlyContinue
}

# Enable Remote Assistance - Not applicable to Server (unless Remote Assistance is explicitly installed)
Function EnableRemoteAssistance {
	Write-Output "Enabling Remote Assistance..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 1
}

# Enable Remote Desktop w/o Network Level Authentication
Function EnableRemoteDesktop {
	Write-Output "Enabling Remote Desktop w/o Network Level Authentication..."
	$errpref = $ErrorActionPreference #save actual preference
	$ErrorActionPreference = "silentlycontinue"
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Type DWord -Value 0
	Enable-NetFirewallRule -Name "RemoteDesktop*" | Out-Null
	$ErrorActionPreference = $errpref #restore previous preference
}

# Disable Remote Desktop
Function DisableRemoteDesktop {
	Write-Output "Disabling Remote Desktop..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Type DWord -Value 1
	Disable-NetFirewallRule -Name "RemoteDesktop*"
}

# Disable Autoplay
Function DisableAutoplay {
	Write-Output "Disabling Autoplay..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 1
}

# Enable Autoplay
Function EnableAutoplay {
	Write-Output "Enabling Autoplay..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 0
}

# Disable Autorun for all drives
Function DisableAutorun {
	Write-Output "Disabling Autorun for all drives..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 255
}

# Enable Autorun for removable drives
Function EnableAutorun {
	Write-Output "Enabling Autorun for all drives..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
}

# Enable Storage Sense - automatic disk cleanup - Not applicable to Server
Function EnableStorageSense {
	Write-Output "Enabling Storage Sense..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "01" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "04" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "08" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "32" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "StoragePoliciesNotified" -Type DWord -Value 1
}

# Disable Storage Sense - Not applicable to Server
Function DisableStorageSense {
	Write-Output "Disabling Storage Sense..."
	Remove-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Recurse -ErrorAction SilentlyContinue
}

# Disable scheduled defragmentation task
Function DisableDefragmentation {
	Write-Output "Disabling scheduled defragmentation..."
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Defrag\ScheduledDefrag" | Out-Null
}

# Enable scheduled defragmentation task
Function EnableDefragmentation {
	Write-Output "Enabling scheduled defragmentation..."
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Defrag\ScheduledDefrag" | Out-Null
}

# Stop and disable Windows Search indexing service
Function DisableIndexing {
	Write-Output "Stopping and disabling Windows Search indexing service..."
	Stop-Service "WSearch" -WarningAction SilentlyContinue
	Set-Service "WSearch" -StartupType Disabled
}

# Start and enable Windows Search indexing service
Function EnableIndexing {
	Write-Output "Starting and enabling Windows Search indexing service..."
	Set-Service "WSearch" -StartupType Automatic
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WSearch" -Name "DelayedAutoStart" -Type DWord -Value 1
	Start-Service "WSearch" -WarningAction SilentlyContinue
}

# Set BIOS time to UTC #sc.exe config w32time start= delayed-auto#
Function SetBIOSTimeUTC {
	Write-Output "Setting BIOS time to UTC..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -Name "RealTimeIsUniversal" -Type DWord -Value 1
	Push-Location
	Set-Location HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DateTime\Servers
	Set-ItemProperty . 0 "time.google.com"
	Set-ItemProperty . "(Default)" "0"
	Set-Location HKLM:\SYSTEM\CurrentControlSet\services\W32Time\Parameters
	Set-ItemProperty . NtpServer "time.google.com"
	Pop-Location
	Stop-Service w32time
	sc.exe config w32time start= auto
	Start-Service w32time
	W32tm /resync /force /nowait
}

# Set BIOS time to local time
Function SetBIOSTimeLocal {
	Write-Output "Setting BIOS time to Local time..."
	Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -Name "RealTimeIsUniversal" -ErrorAction SilentlyContinue
	Push-Location
	Set-Location HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DateTime\Servers
	Set-ItemProperty . 0 "time.google.com"
	Set-ItemProperty . "(Default)" "0"
	Set-Location HKLM:\SYSTEM\CurrentControlSet\services\W32Time\Parameters
	Set-ItemProperty . NtpServer "time.google.com"
	Pop-Location
	Stop-Service w32time
	sc.exe config w32time start= auto
	Start-Service w32time
	W32tm /resync /force /nowait
}

# Enable Hibernation - Do not use on Server with automatically started Hyper-V hvboot service as it may lead to BSODs (Win10 with Hyper-V is fine)
Function EnableHibernation {
	Write-Output "Enabling Hibernation..."
	Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernteEnabled" -Type Dword -Value 1
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type Dword -Value 1
}

# Disable Hibernation
Function DisableHibernation {
	Write-Output "Disabling Hibernation..."
	Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernteEnabled" -Type Dword -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type Dword -Value 0
}

# Disable Sleep start menu and keyboard button
Function DisableSleepButton {
	Write-Output "Disabling Sleep start menu and keyboard button..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowSleepOption" -Type Dword -Value 0
	powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 0
	powercfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 0
}

# Enable Sleep start menu and keyboard button
Function EnableSleepButton {
	Write-Output "Enabling Sleep start menu and keyboard button..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowSleepOption" -Type Dword -Value 1
	powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 1
	powercfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 1
}

# Disable display and sleep mode timeouts
Function DisableSleepTimeout {
	Write-Output "Disabling display and sleep mode timeouts..."
	powercfg /X monitor-timeout-ac 0
	powercfg /X monitor-timeout-dc 0
	powercfg /X standby-timeout-ac 0
	powercfg /X standby-timeout-dc 0
}

# Enable display and sleep mode timeouts
Function EnableSleepTimeout {
	Write-Output "Enabling display and sleep mode timeouts..."
	powercfg /X monitor-timeout-ac 10
	powercfg /X monitor-timeout-dc 5
	powercfg /X standby-timeout-ac 30
	powercfg /X standby-timeout-dc 15
}

# Disable Fast Startup
Function DisableFastStartup {
	Write-Output "Disabling Fast Startup..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 0
}

# Enable Fast Startup
Function EnableFastStartup {
	Write-Output "Enabling Fast Startup..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 1
}


##########
# Windows Tweaks
##########
#Disabling power throttling.
Function PowerThrottlingOff {
	Write-Output "Disabling power throttling..."
	New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" -Force | Out-Null
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" -Name "PowerThrottlingOff" -Type DWord -Value 1
}

#Setting Processor scheduling.
Function Win32PrioritySeparation {
	Write-Output "Setting Processor scheduling..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Type DWord -Value 0x00000028
}

#Disabling aero shake.
Function DisableAERO {
	Write-Output "Disabling aero shake..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisallowShaking" -Type DWord -Value 0
}

#Show BSOD details instead of the sad smiley.
Function BSODdetails {
	Write-Output "Show BSOD details instead of the sad smiley..."
	Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\CrashControl" -Name "DisplayParameters" -Type DWord -Value 1
}

#Disabling live tiles.
Function Disablelivetiles {
	Write-Output "Disabling live tiles..."
	New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -ErrorAction SilentlyContinue | Out-Null
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoTileApplicationNotification" -Type DWord -Value 1
}

#Setting Wallpaper Quality to 100%.
Function wallpaperquality {
	Write-Output "Setting Wallpaper Quality to 100%..."
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "JPEGImportQuality" -Type DWord -Value 100
}

#Disabling search history.
Function DisableShistory {
	Write-Output "Disabling search history..."
	New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -ErrorAction SilentlyContinue | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableSearchBoxSuggestions" -Type DWord -Value 1
}

#Disabling "- Shortcut" Word.
Function Disableshortcutword {
	Write-Output "Disabling - Shortcut Word..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "link" -Type Binary -Value ([byte[]](0, 0, 0, 0))
}

#Disabling Mouse Keys Keyboard Shortcut.
Function DisableMouseKKS {
	Write-Output "Disabling Mouse Keys Keyboard Shortcut..."
	Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\MouseKeys" -Name "Flags" -Type String -Value "186"
	Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\MouseKeys" -Name "MaximumSpeed" -Type String -Value "40"
	Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\MouseKeys" -Name "TimeToMaximumSpeed" -Type String -Value "3000"
}

#Disabling Windows Transparency.
Function DisableTransparency {
	Write-Output "Disabling Windows Transparency..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Type DWord -Value 0
}

#Turning Off Safe Search.
Function TurnOffSafeSearch {
	Write-Output "Turning Off Safe Search..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" -Name "SafeSearchMode" -Type DWord -Value 0
}

#Disabling Cloud Search.
Function DisableCloudSearch {
	Write-Output "Disabling Cloud Search..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCloudSearch" -Type DWord -Value 0
}

#Disabling Device History.
Function DisableDeviceHistory {
	Write-Output "Disabling Device History..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "DeviceHistoryEnabled" -Type DWord -Value 0
}

#Disabling Windows Remote Assistance.
Function DisableRemoteAssistance {
	Write-Output "Disabling Windows Remote Assistance..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowFullControl" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0
}

#Disabling Search Histroy.
Function DisableSearchHistroy {
	Write-Output "Disabling Search Histroy..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" -Name "IsDeviceSearchHistoryEnabled" -Type DWord -Value 0
}

#Removing Microsoft MeetNow
Function RemoveMeet {
	Write-Output "Disabling Microsoft MeetNow..."
	$errpref = $ErrorActionPreference #save actual preference
	$ErrorActionPreference = "silentlycontinue"
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Type DWord -Value 1
	$ErrorActionPreference = $errpref #restore previous preference
}
##########
# UI Tweaks
##########

# Disable Action Center
Function DisableActionCenter {
	Write-Output "Disabling Action Center..."
	If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
		New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -Type DWord -Value 0
}

# Enable Action Center
Function EnableActionCenter {
	Write-Output "Enabling Action Center..."
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -ErrorAction SilentlyContinue
}

# Disable Lock screen
Function DisableLockScreen {
	Write-Output "Disabling Lock screen..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -Type DWord -Value 1
}

# Enable Lock screen
Function EnableLockScreen {
	Write-Output "Enabling Lock screen..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -ErrorAction SilentlyContinue
}

# Disable Lock screen (Anniversary Update workaround) - Applicable to 1607 - 1803 (The GPO used in DisableLockScreen has been fixed again in 1803)
Function DisableLockScreenRS1 {
	Write-Output "Disabling Lock screen using scheduler workaround..."
	$service = New-Object -com Schedule.Service
	$service.Connect()
	$task = $service.NewTask(0)
	$task.Settings.DisallowStartIfOnBatteries = $false
	$trigger = $task.Triggers.Create(9)
	$trigger = $task.Triggers.Create(11)
	$trigger.StateChange = 8
	$action = $task.Actions.Create(0)
	$action.Path = "reg.exe"
	$action.Arguments = "add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\SessionData /t REG_DWORD /v AllowLockScreen /d 0 /f"
	$service.GetFolder("\").RegisterTaskDefinition("Disable LockScreen", $task, 6, "NT AUTHORITY\SYSTEM", $null, 4) | Out-Null
}

# Enable Lock screen (Anniversary Update workaround) - Applicable to 1607 - 1803
Function EnableLockScreenRS1 {
	Write-Output "Enabling Lock screen (removing scheduler workaround)..."
	Unregister-ScheduledTask -TaskName "Disable LockScreen" -Confirm:$false -ErrorAction SilentlyContinue
}

# Hide network options from Lock Screen
Function HideNetworkFromLockScreen {
	Write-Output "Hiding network options from Lock Screen..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -Type DWord -Value 1
}

# Show network options on lock screen
Function ShowNetworkOnLockScreen {
	Write-Output "Showing network options on Lock Screen..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -ErrorAction SilentlyContinue
}

# Hide shutdown options from Lock Screen
Function HideShutdownFromLockScreen {
	Write-Output "Hiding shutdown options from Lock Screen..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ShutdownWithoutLogon" -Type DWord -Value 0
}

# Show shutdown options on lock screen
Function ShowShutdownOnLockScreen {
	Write-Output "Showing shutdown options on Lock Screen..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ShutdownWithoutLogon" -Type DWord -Value 1
}

# Disable Sticky keys prompt
Function DisableStickyKeys {
	Write-Output "Disabling Sticky keys prompt..."
	Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "506"
}

# Enable Sticky keys prompt
Function EnableStickyKeys {
	Write-Output "Enabling Sticky keys prompt..."
	Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "510"
}

# Show Task Manager details - Applicable to 1607 and later - Although this functionality exist even in earlier versions, the Task Manager's behavior is different there and is not compatible with this tweak
Function ShowTaskManagerDetails {
	If ([System.Environment]::OSVersion.Version.Build -ge 22000) {
	}
 Else {
		Write-Output "Showing task manager details..."
		$taskmgr = Start-Process -WindowStyle Hidden -FilePath taskmgr.exe -PassThru
		Do {
			Start-Sleep -Milliseconds 100
			$preferences = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -ErrorAction SilentlyContinue
		} Until ($preferences)
		Stop-Process $taskmgr
		$preferences.Preferences[28] = 0
		Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -Type Binary -Value $preferences.Preferences
	}
}

# Hide Task Manager details
Function HideTaskManagerDetails {
	Write-Output "Hiding task manager details..."
	$preferences = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -ErrorAction SilentlyContinue
	If ($preferences) {
		$preferences.Preferences[28] = 1
		Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -Type Binary -Value $preferences.Preferences
	}
}

# Show file operations details
Function ShowFileOperationsDetails {
	Write-Output "Showing file operations details..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Type DWord -Value 1
}

# Hide file operations details
Function HideFileOperationsDetails {
	Write-Output "Hiding file operations details..."
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -ErrorAction SilentlyContinue
}

# Enable file delete confirmation dialog
Function EnableFileDeleteConfirm {
	Write-Output "Enabling file delete confirmation dialog..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ConfirmFileDelete" -Type DWord -Value 1
}

# Disable file delete confirmation dialog
Function DisableFileDeleteConfirm {
	Write-Output "Disabling file delete confirmation dialog..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ConfirmFileDelete" -ErrorAction SilentlyContinue
}

# Hide Taskbar Search icon / box
Function HideTaskbarSearch {
	Write-Output "Hiding Taskbar Search icon / box..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0
}

# Show Taskbar Search icon
Function ShowTaskbarSearchIcon {
	Write-Output "Showing Taskbar Search icon..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 1
}

# Show Taskbar Search box
Function ShowTaskbarSearchBox {
	Write-Output "Showing Taskbar Search box..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 2
}

# Hide Task View button
Function HideTaskView {
	Write-Output "Hiding Task View button..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0
}

# Show Task View button
Function ShowTaskView {
	Write-Output "Showing Task View button..."
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -ErrorAction SilentlyContinue
}

# Show small icons in taskbar
Function ShowSmallTaskbarIcons {
	Write-Output "Showing small icons in taskbar..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -Type DWord -Value 1
}

# Show large icons in taskbar
Function ShowLargeTaskbarIcons {
	Write-Output "Showing large icons in taskbar..."
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -ErrorAction SilentlyContinue
}

# Set taskbar buttons to show labels and combine when taskbar is full
Function SetTaskbarCombineWhenFull {
	Write-Output "Setting taskbar buttons to combine when taskbar is full..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -Type DWord -Value 1
}

# Set taskbar buttons to show labels and never combine
Function SetTaskbarCombineNever {
	Write-Output "Setting taskbar buttons to never combine..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -Type DWord -Value 2
}

# Set taskbar buttons to always combine and hide labels
Function SetTaskbarCombineAlways {
	Write-Output "Setting taskbar buttons to always combine, hide labels..."
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -ErrorAction SilentlyContinue
}

# Hide Taskbar People icon
Function HideTaskbarPeopleIcon {
	Write-Output "Hiding People icon..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0
}

# Show Taskbar People icon
Function ShowTaskbarPeopleIcon {
	Write-Output "Showing People icon..."
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -ErrorAction SilentlyContinue
}

# Show all tray icons
Function ShowTrayIcons {
	Write-Output "Showing all tray icons..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Type DWord -Value 0
}

# Hide tray icons as needed
Function HideTrayIcons {
	Write-Output "Hiding tray icons..."
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -ErrorAction SilentlyContinue
}

# Disable search for app in store for unknown extensions
Function DisableSearchAppInStore {
	Write-Output "Disabling search for app in store for unknown extensions..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Type DWord -Value 1
}

# Enable search for app in store for unknown extensions
Function EnableSearchAppInStore {
	Write-Output "Enabling search for app in store for unknown extensions..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -ErrorAction SilentlyContinue
}

# Disable 'How do you want to open this file?' prompt
Function DisableNewAppPrompt {
	Write-Output "Disabling 'How do you want to open this file?' prompt..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoNewAppAlert" -Type DWord -Value 1
}

# Enable 'How do you want to open this file?' prompt
Function EnableNewAppPrompt {
	Write-Output "Enabling 'How do you want to open this file?' prompt..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoNewAppAlert" -ErrorAction SilentlyContinue
}

# Set Control Panel view to Small icons (Classic)
Function SetControlPanelSmallIcons {
	Write-Output "Setting Control Panel view to small icons..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -Type DWord -Value 1
}

# Set Control Panel view to Large icons (Classic)
Function SetControlPanelLargeIcons {
	Write-Output "Setting Control Panel view to large icons..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -Type DWord -Value 0
}

# Set Control Panel view to categories
Function SetControlPanelCategories {
	Write-Output "Setting Control Panel view to categories..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -ErrorAction SilentlyContinue
}

# Adjusts visual effects for performance - Disables animations, transparency etc. but leaves font smoothing and miniatures enabled
Function SetVisualFXPerformance {
	Write-Output "Adjusting visual effects for performance..."
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -Type String -Value 0
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Type String -Value 200
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Type Binary -Value ([byte[]](144, 18, 3, 128, 16, 0, 0, 0))
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Type String -Value 0
	Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "KeyboardDelay" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value 3
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "FontSmoothing" -Type String -Value 2
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type DWord -Value 0
}

# Adjusts visual effects for appearance
Function SetVisualFXAppearance {
	Write-Output "Adjusting visual effects for appearance..."
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -Type String -Value 1
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Type String -Value 200
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Type Binary -Value ([byte[]](158, 30, 7, 128, 18, 0, 0, 0))
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Type String -Value 1
	Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "KeyboardDelay" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value 3
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type DWord -Value 1
}

# Add secondary en-US keyboard
Function AddENKeyboard {
	Write-Output "Adding secondary en-US keyboard..."
	$langs = Get-WinUserLanguageList
	$langs.Add("en-US")
	Set-WinUserLanguageList $langs -Force
}

# Remove secondary en-US keyboard
Function RemoveENKeyboard {
	Write-Output "Removing secondary en-US keyboard..."
	$langs = Get-WinUserLanguageList
	Set-WinUserLanguageList ($langs | Where-Object { $_.LanguageTag -ne "en-US" }) -Force
}

# Enable NumLock after startup
Function EnableNumlock {
	Write-Output "Enabling NumLock after startup..."
	If (!(Test-Path "HKU:")) {
		New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
	}
	Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value 2147483650
	Add-Type -AssemblyName System.Windows.Forms
	If (!([System.Windows.Forms.Control]::IsKeyLocked('NumLock'))) {
		$wsh = New-Object -ComObject WScript.Shell
		$wsh.SendKeys('{NUMLOCK}')
	}
}

# Disable NumLock after startup
Function DisableNumlock {
	Write-Output "Disabling NumLock after startup..."
	If (!(Test-Path "HKU:")) {
		New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
	}
	Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value 2147483648
	Add-Type -AssemblyName System.Windows.Forms
	If ([System.Windows.Forms.Control]::IsKeyLocked('NumLock')) {
		$wsh = New-Object -ComObject WScript.Shell
		$wsh.SendKeys('{NUMLOCK}')
	}
}



##########
# Explorer UI Tweaks
##########

# Show known file extensions
Function ShowKnownExtensions {
	Write-Output "Showing known file extensions..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0
}

# Hide known file extensions
Function HideKnownExtensions {
	Write-Output "Hiding known file extensions..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 1
}

# Show hidden files
Function ShowHiddenFiles {
	Write-Output "Showing hidden files..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 1
}

# Hide hidden files
Function HideHiddenFiles {
	Write-Output "Hiding hidden files..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 2
}

# Hide sync provider notifications
Function HideSyncNotifications {
	Write-Output "Hiding sync provider notifications..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Type DWord -Value 0
}

# Show sync provider notifications
Function ShowSyncNotifications {
	Write-Output "Showing sync provider notifications..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Type DWord -Value 1
}

# Hide recently and frequently used item shortcuts in Explorer
Function HideRecentShortcuts {
	Write-Output "Hiding recent shortcuts..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -Type DWord -Value 0
}

# Show recently and frequently used item shortcuts in Explorer
Function ShowRecentShortcuts {
	Write-Output "Showing recent shortcuts..."
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -ErrorAction SilentlyContinue
}

# Change default Explorer view to This PC
Function SetExplorerThisPC {
	Write-Output "Changing default Explorer view to This PC..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1
}

# Change default Explorer view to Quick Access
Function SetExplorerQuickAccess {
	Write-Output "Changing default Explorer view to Quick Access..."
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -ErrorAction SilentlyContinue
}

# Show This PC shortcut on desktop
Function ShowThisPCOnDesktop {
	Write-Output "Showing This PC shortcut on desktop..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0
}

# Hide This PC shortcut from desktop
Function HideThisPCFromDesktop {
	Write-Output "Hiding This PC shortcut from desktop..."
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -ErrorAction SilentlyContinue
}

# Show User Folder shortcut on desktop
Function ShowUserFolderOnDesktop {
	Write-Output "Showing User Folder shortcut on desktop..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -Type DWord -Value 0
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -Type DWord -Value 0
}

# Hide User Folder shortcut from desktop
Function HideUserFolderFromDesktop {
	Write-Output "Hiding User Folder shortcut from desktop..."
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -ErrorAction SilentlyContinue
}

# Hide 3D Objects icon from This PC - The icon remains in personal folders and open/save dialogs
Function Hide3DObjectsFromThisPC {
	Write-Output "Hiding 3D Objects icon from This PC..."
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue
}

# Show 3D Objects icon in This PC
Function Show3DObjectsInThisPC {
	Write-Output "Showing 3D Objects icon in This PC..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" | Out-Null
	}
}

# Hide 3D Objects icon from Explorer namespace - Hides the icon also from personal folders and open/save dialogs
Function Hide3DObjectsFromExplorer {
	Write-Output "Hiding 3D Objects icon from Explorer namespace..."
	$errpref = $ErrorActionPreference #save actual preference
	$ErrorActionPreference = "silentlycontinue"
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
	If (!(Test-Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag")) {
		New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
	$ErrorActionPreference = $errpref #restore previous preference
}

# Show 3D Objects icon in Explorer namespace
Function Show3DObjectsInExplorer {
	Write-Output "Showing 3D Objects icon in Explorer namespace..."
	Write-Output "Hiding 3D Objects icon from Explorer namespace..."
	$errpref = $ErrorActionPreference #save actual preference
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -ErrorAction SilentlyContinue
	$ErrorActionPreference = $errpref #restore previous preference
}

# Disable thumbnails, show only file extension icons
Function DisableThumbnails {
	Write-Output "Disabling thumbnails..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "IconsOnly" -Type DWord -Value 1
}

# Enable thumbnails
Function EnableThumbnails {
	Write-Output "Enabling thumbnails..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "IconsOnly" -Type DWord -Value 0
}

# Disable creation of Thumbs.db thumbnail cache files
Function DisableThumbsDB {
	Write-Output "Disabling creation of Thumbs.db..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbnailCache" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbsDBOnNetworkFolders" -Type DWord -Value 1
}

# Enable creation of Thumbs.db thumbnail cache files
Function EnableThumbsDB {
	Write-Output "Enable creation of Thumbs.db..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbnailCache" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbsDBOnNetworkFolders" -ErrorAction SilentlyContinue
}



##########
# Application Tweaks
##########
# Option To Uninstall Or install OneDrive 
Function DorEOneDrive {
	# Verifica a versão do Windows
	$osVersion = [System.Environment]::OSVersion.Version
	$isWindows11 = $osVersion.Build -ge 22000  # Windows 11 tem build 22000+

	# Verifica se o script está rodando como administrador
	function Test-Admin {
		$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
		$principal = New-Object Security.Principal.WindowsPrincipal $currentUser
		return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
	}

	if (-not (Test-Admin)) {
		Escrever-Colorido "Este script precisa ser executado como Administrador. Por favor, execute-o novamente como Administrador." "Vermelho"
		Break;
	}

	do {
		Clear-Host
		Escrever-Colorido "" "Azul"
		Escrever-Colorido "================ Desabilitar o Microsoft OneDrive? ================" "Azul"
		Escrever-Colorido "" "Azul"
		Escrever-Colorido "Pressione 'D' para desabilitar o OneDrive." "Azul"
		Escrever-Colorido "Pressione 'H' para habilitar o OneDrive." "Azul"
		Escrever-Colorido "Pressione 'P' para pular isso." "Azul"
			
		$selection = Read-Host "Por favor, escolha"

	} until ($selection -match "(?i)^(d|h|p)$") # Torna a entrada case-insensitive

	if ($selection -match "(?i)^d$") {
  # Desabilitar OneDrive
		Write-Output "Desativando Microsoft OneDrive e processos relacionados..."

		$errpref = $ErrorActionPreference
		$ErrorActionPreference = "SilentlyContinue"

		# Cria chave de política para bloquear o OneDrive
		if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive")) {
			New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1

		# Finaliza processos do OneDrive se estiverem em execução
		$oneDriveProcess = Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue
		if ($oneDriveProcess) {
			Stop-Process -Name "OneDrive" -Force
		}
		Start-Sleep -s 2

		# Localiza e executa o desinstalador
		$onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
		if (!(Test-Path $onedrive)) {
			$onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
		}

		if (Test-Path $onedrive) {
			Start-Process $onedrive "/uninstall" -NoNewWindow -Wait
			Start-Sleep -s 2
		}

		# Remove pastas e arquivos do OneDrive
		Remove-Item -Path "$env:USERPROFILE\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse -ErrorAction SilentlyContinue

		# Remove OneDrive do Explorer
		if (!(Test-Path "HKCR:")) {
			New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
		}
		Remove-Item -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue

		# Remove OneDrive da inicialização automática
		reg load "hku\Default" "C:\Users\Default\NTUSER.DAT"
		reg delete "HKEY_USERS\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f
		reg unload "hku\Default"

		# Remove atalhos
		Remove-Item -Force -ErrorAction SilentlyContinue "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk"

		# Remove tarefas agendadas do OneDrive
		Get-ScheduledTask -TaskPath '\' -TaskName 'OneDrive*' -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false

		$ErrorActionPreference = $errpref
	}

	elseif ($selection -match "(?i)^h$") {
  # Habilitar OneDrive
		Write-Output "Ativando Microsoft OneDrive e processos relacionados..."

		$errpref = $ErrorActionPreference
		$ErrorActionPreference = "SilentlyContinue"

		# Remove restrição do OneDrive
		if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive") {
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -ErrorAction SilentlyContinue
		}

		# Reinstala o OneDrive
		$onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
		if (!(Test-Path $onedrive)) {
			$onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
		}

		if (Test-Path $onedrive) {
			Start-Process $onedrive -NoNewWindow
		}
		elseif ($isWindows11) {
			# No Windows 11, OneDrive pode ser instalado como Feature Opcional
			Start-Process "powershell" -ArgumentList "Add-WindowsFeature OneDrive" -NoNewWindow -Wait
		}

		$ErrorActionPreference = $errpref
	}
}


# Uninstall Windows Media Player
Function UninstallMediaPlayer {
	Write-Output "Uninstalling Windows Media Player..."
	Disable-WindowsOptionalFeature -Online -FeatureName "WindowsMediaPlayer" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Install Windows Media Player
Function InstallMediaPlayer {
	Write-Output "Installing Windows Media Player..."
	Enable-WindowsOptionalFeature -Online -FeatureName "WindowsMediaPlayer" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Uninstall Internet Explorer
Function UninstallInternetExplorer {
	Write-Output "Uninstalling Internet Explorer..."
	If ([System.Environment]::OSVersion.Version.Build -ge 22000) {
	}
 Else {
		Disable-WindowsOptionalFeature -Online -FeatureName "Internet-Explorer-Optional-$env:PROCESSOR_ARCHITECTURE" -NoRestart -WarningAction SilentlyContinue | Out-Null
	}
}

# Install Internet Explorer
Function InstallInternetExplorer {
	Write-Output "Installing Internet Explorer..."
	Enable-WindowsOptionalFeature -Online -FeatureName "Internet-Explorer-Optional-$env:PROCESSOR_ARCHITECTURE" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Uninstall Work Folders Client - Not applicable to Server
Function UninstallWorkFolders {
	Write-Output "Uninstalling Work Folders Client..."
	Disable-WindowsOptionalFeature -Online -FeatureName "WorkFolders-Client" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Install Work Folders Client - Not applicable to Server
Function InstallWorkFolders {
	Write-Output "Installing Work Folders Client..."
	Enable-WindowsOptionalFeature -Online -FeatureName "WorkFolders-Client" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Install Linux Subsystem - Applicable to 1607 or newer
Function InstallLinuxSubsystem {
	Write-Output "Installing Linux Subsystem..."
	If ([System.Environment]::OSVersion.Version.Build -eq 14393) {
		# 1607 needs developer mode to be enabled
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowDevelopmentWithoutDevLicense" -Type DWord -Value 1
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowAllTrustedApps" -Type DWord -Value 1
	}
	Enable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-Subsystem-Linux" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Uninstall Linux Subsystem - Applicable to 1607 or newer
Function UninstallLinuxSubsystem {
	Write-Output "Uninstalling Linux Subsystem..."
	$errpref = $ErrorActionPreference #save actual preference
	$ErrorActionPreference = "silentlycontinue"
	If ([System.Environment]::OSVersion.Version.Build -eq 14393) {
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowDevelopmentWithoutDevLicense" -Type DWord -Value 0
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowAllTrustedApps" -Type DWord -Value 0
	}
	Disable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-Subsystem-Linux" -NoRestart -WarningAction SilentlyContinue | Out-Null
	$ErrorActionPreference = $errpref #restore previous preference
}

# Install Hyper-V - Not applicable to Home
Function InstallHyperV {
	Write-Output "Installing Hyper-V..."
	If ((Get-WmiObject -Class "Win32_OperatingSystem").Caption -like "*Server*") {
		Install-WindowsFeature -Name "Hyper-V" -IncludeManagementTools -WarningAction SilentlyContinue | Out-Null
	}
 Else {
		Enable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V-All" -NoRestart -WarningAction SilentlyContinue | Out-Null
	}
}

# Uninstall Hyper-V - Not applicable to Home
Function UninstallHyperV {
	Write-Output "Uninstalling Hyper-V..."
	If ((Get-WmiObject -Class "Win32_OperatingSystem").Caption -like "*Server*") {
		Uninstall-WindowsFeature -Name "Hyper-V" -IncludeManagementTools -WarningAction SilentlyContinue | Out-Null
	}
 Else {
		Disable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V-All" -NoRestart -WarningAction SilentlyContinue | Out-Null
	}
}

# Set Photo Viewer association for bmp, gif, jpg, png and tif
Function SetPhotoViewerAssociation {
	Write-Output "Setting Photo Viewer association for bmp, gif, jpg, png and tif..."
	If (!(Test-Path "HKCR:")) {
		New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
	}
	ForEach ($type in @("Paint.Picture", "giffile", "jpegfile", "pngfile")) {
		New-Item -Path $("HKCR:\$type\shell\open") -Force | Out-Null
		New-Item -Path $("HKCR:\$type\shell\open\command") | Out-Null
		Set-ItemProperty -Path $("HKCR:\$type\shell\open") -Name "MuiVerb" -Type ExpandString -Value "@%ProgramFiles%\Windows Photo Viewer\photoviewer.dll,-3043"
		Set-ItemProperty -Path $("HKCR:\$type\shell\open\command") -Name "(Default)" -Type ExpandString -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1"
	}
}

# Unset Photo Viewer association for bmp, gif, jpg, png and tif
Function UnsetPhotoViewerAssociation {
	Write-Output "Unsetting Photo Viewer association for bmp, gif, jpg, png and tif..."
	If (!(Test-Path "HKCR:")) {
		New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
	}
	Remove-Item -Path "HKCR:\Paint.Picture\shell\open" -Recurse -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCR:\giffile\shell\open" -Name "MuiVerb" -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "HKCR:\giffile\shell\open" -Name "CommandId" -Type String -Value "IE.File"
	Set-ItemProperty -Path "HKCR:\giffile\shell\open\command" -Name "(Default)" -Type String -Value "`"$env:SystemDrive\Program Files\Internet Explorer\iexplore.exe`" %1"
	Set-ItemProperty -Path "HKCR:\giffile\shell\open\command" -Name "DelegateExecute" -Type String -Value "{17FE9752-0B5A-4665-84CD-569794602F5C}"
	Remove-Item -Path "HKCR:\jpegfile\shell\open" -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "HKCR:\pngfile\shell\open" -Recurse -ErrorAction SilentlyContinue
}

# Add Photo Viewer to "Open with..."
Function AddPhotoViewerOpenWith {
	Write-Output "Adding Photo Viewer to `"Open with...`""
	If (!(Test-Path "HKCR:")) {
		New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
	}
	New-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open\command" -Force | Out-Null
	New-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open\DropTarget" -Force | Out-Null
	Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open" -Name "MuiVerb" -Type String -Value "@photoviewer.dll,-3043"
	Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open\command" -Name "(Default)" -Type ExpandString -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1"
	Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open\DropTarget" -Name "Clsid" -Type String -Value "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}"
}

# Remove Photo Viewer from "Open with..."
Function RemovePhotoViewerOpenWith {
	Write-Output "Removing Photo Viewer from `"Open with...`""
	If (!(Test-Path "HKCR:")) {
		New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
	}
	Remove-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open" -Recurse -ErrorAction SilentlyContinue
}

# Uninstall Microsoft Print to PDF
Function UninstallPDFPrinter {
	Write-Output "Uninstalling Microsoft Print to PDF..."
	Disable-WindowsOptionalFeature -Online -FeatureName "Printing-PrintToPDFServices-Features" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Install Microsoft Print to PDF
Function InstallPDFPrinter {
	Write-Output "Installing Microsoft Print to PDF..."
	Enable-WindowsOptionalFeature -Online -FeatureName "Printing-PrintToPDFServices-Features" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Add SVCHost Tweak
Function SVCHostTweak {
	Write-Output "Adding SVCHost Tweak..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -Type DWord -Value 4194304
}

##########
# Unpinning
##########

# Unpin all Start Menu tiles - Note: This function has no counterpart. You have to pin the tiles back manually.
Function UnpinStartMenuTiles {
	Write-Output "Unpinning all Start Menu tiles..."
	$errpref = $ErrorActionPreference #save actual preference
	$ErrorActionPreference = "silentlycontinue"
	If ([System.Environment]::OSVersion.Version.Build -ge 22000) {
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecentDocsHistory" -Type DWord -Value 0 | Out-Null -ErrorAction SilentlyContinue
		Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackDocs" -Type DWord -Value 0 | Out-Null -ErrorAction SilentlyContinue
		Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoStartMenuMorePrograms" | Out-Null -ErrorAction SilentlyContinue
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoStartMenuMorePrograms" | Out-Null -ErrorAction SilentlyContinue
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "LockedStartLayout" | Out-Null -ErrorAction SilentlyContinue
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "StartLayoutFile" | Out-Null -ErrorAction SilentlyContinue
		Remove-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "LockedStartLayout" | Out-Null -ErrorAction SilentlyContinue
		Remove-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "StartLayoutFile" | Out-Null -ErrorAction SilentlyContinue
		Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_Layout" -Type DWord -Value 1 | Out-Null -ErrorAction SilentlyContinue
	}
 Else {
	
		$url_startlayout = "https://raw.githubusercontent.com/wesscd/WindowsGaming/main/StartLayout.xml"

		Invoke-WebRequest -Uri $url_startlayout -OutFile "$env:UserProfile\StartLayout.xml" -ErrorAction SilentlyContinue

		Import-StartLayout -layoutpath "$env:UserProfile\StartLayout.xml" -MountPath "$env:SystemDrive\"
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "LockedStartLayout" -Type DWord -Value 1 | Out-Null -ErrorAction SilentlyContinue
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "StartLayoutFile" -Type ExpandString -Value "%USERPROFILE%\StartLayout.xml" | Out-Null -ErrorAction SilentlyContinue
		Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoStartMenuMorePrograms" -Type DWord -Value 0 | Out-Null -ErrorAction SilentlyContinue
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoStartMenuMorePrograms" -Type DWord -Value 0 | Out-Null -ErrorAction SilentlyContinue
		Start-Sleep -s 3
		$wshell = New-Object -ComObject wscript.shell; $wshell.SendKeys('^{ESCAPE}')
		Start-Sleep -s 3
		function get-itemproperty2 {
			# get-childitem skips top level key, use get-item for that
			# set-alias gp2 get-itemproperty2
			param([parameter(ValueFromPipeline)]$key)
			process {
    $key.getvaluenames() | foreach-object {
					$value = $_
					[pscustomobject] @{
						Path  = $Key -replace 'HKEY_CURRENT_USER',
						'HKCU:' -replace 'HKEY_LOCAL_MACHINE', 'HKLM:'
						Name  = $Value
						Value = $Key.GetValue($Value)
						Type  = $Key.GetValueKind($Value)
					}
				}
			}
  }
	}

	$YourInputStart = "02,00,00,00,e6,d9,21,ac,f8,e0,d6,01,00,00,00,00,43,42,01,00,c2,14,01,cb,32,0a,03,05,ce,ab,d3,e9,02,24,da,f4,03,44,c3,8a,01,66,82,e5,8b,b1,ae,fd,fd,bb,3c,00,05,a0,8f,fc,c1,03,24,8a,d0,03,44,80,99,01,66,b0,b5,99,dc,cd,b0,97,de,4d,00,05,86,91,cc,93,05,24,aa,a3,01,44,c3,84,01,66,9f,f7,9d,b1,87,cb,d1,ac,d4,01,00,c2,3c,01,c5,5a,01,00"
	$hexifiedStart = $YourInputStart.Split(',') | ForEach-Object { "0x$_" }
	Get-ChildItem -r "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\" | get-itemproperty2 | Where-Object { $_ -like '*windows.data.unifiedtile.startglobalproperties*' } | set-itemproperty -value (([byte[]]$hexifiedStart))
	Stop-Process -name explorer | Out-Null
	$ErrorActionPreference = $errpref #restore previous preference
}

##########
# Quality Of Life Tweaks
##########
# Windows 11 Extra Tweaks
function Windows11Extra {
	If ([System.Environment]::OSVersion.Version.Build -ge 22000) {
		Write-Output "Restoring windows 10 context menu and disabling start menu recommended section..."
		New-Item -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -ErrorAction SilentlyContinue | Out-Null #context menu setup
		reg add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /f /ve
		Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Type DWord -Value 0 #set taskbar icons to the left
		Get-appxpackage -all *shellexperience* -packagetype bundle | ForEach-Object { add-appxpackage -register -disabledevelopmentmode ($_.installlocation + '\appxmetadata\appxbundlemanifest.xml') }
		Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Type DWord -Value 0 #disable widget icon from taskbar
		Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarMn" -Type DWord -Value 0 #disable chat icon from taskbar
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HideRecentlyAddedApps" -Type DWord -Value 1 #Disable start menu RecentlyAddedApps
		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "ThreadDpcEnable" -Type DWord -Value 0 | Out-Null -ErrorAction SilentlyContinue
		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "GlobalTimerResolutionRequests" -Type DWord -Value 1 | Out-Null -ErrorAction SilentlyContinue
		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "UnlimitDpcQueue" -Type DWord -Value 1 | Out-Null -ErrorAction SilentlyContinue
	}
}
# Enable Quality Of Life Tweaks
Function QOL {
	Write-Output "Enabling Quality of Life Tweaks..."
	$errpref = $ErrorActionPreference #save actual preference
	$ErrorActionPreference = "silentlycontinue"
	New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -ErrorAction SilentlyContinue | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Name "ScoobeSystemSettingEnabled" -Type DWord -Value 0 | Out-Null -ErrorAction SilentlyContinue #disable annoying Get even more out of Windows
	Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility" -Name "DynamicScrollbars" -Type DWord -Value 0 #disable Hide Scroll bars
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "SmoothScroll" -Type DWord -Value 0 #disable smooth scrolling 
	If ([System.Environment]::OSVersion.Version.Build -ge 22000) {
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoInstrumentation" -Type DWord -Value 1 #disable microsoft usertracking
	}
 Else {
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoInstrumentation" -Type DWord -Value 1 #disable microsoft usertracking
	}
	Remove-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "TaskbarNoMultimon" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "TaskbarNoMultimon" -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "MMTaskbarMode" -Type DWord -Value 2 #Show taskbar buttons only on taskbar where window is open
	$ErrorActionPreference = $errpref #restore previous preference
}

##########
# Gaming Tweaks Functions
##########

#Disable Fullscreen Optimizations
Function FullscreenOptimizationFIX {
	param(
		[switch]$Simular  # Parâmetro para ativar o modo de simulação
	)

	$errpref = $ErrorActionPreference # Salva a preferência de erro atual
	$ErrorActionPreference = "SilentlyContinue"
	
	Write-Output "Desabilitando otimizações de tela cheia..."
	
	$regPaths = @(
		"HKCU:\System\GameConfigStore",
		"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR",
		"HKCU:\Software\Microsoft\DirectX\GraphicsSettings",
		"HKCU:\Software\Microsoft\DirectX\UserGpuPreferences",
		"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform",
		"HKLM:\SOFTWARE\Microsoft\Windows\Dwm"
	)

	$properties = @(
		@{"Path" = "HKCU:\System\GameConfigStore"; "Name" = "GameDVR_FSEBehaviorMode"; "Value" = 2 },
		@{"Path" = "HKCU:\System\GameConfigStore"; "Name" = "GameDVR_HonorUserFSEBehaviorMode"; "Value" = 1 },
		@{"Path" = "HKCU:\System\GameConfigStore"; "Name" = "GameDVR_FSEBehavior"; "Value" = 2 },
		@{"Path" = "HKCU:\System\GameConfigStore"; "Name" = "GameDVR_DXGIHonorFSEWindowsCompatible"; "Value" = 1 },
		@{"Path" = "HKCU:\System\GameConfigStore"; "Name" = "GameDVR_EFSEFeatureFlags"; "Value" = 0 },
		@{"Path" = "HKCU:\System\GameConfigStore"; "Name" = "GameDVR_DSEBehavior"; "Value" = 2 },
		@{"Path" = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR"; "Name" = "AppCaptureEnabled"; "Value" = 0 },
		@{"Path" = "HKCU:\Software\Microsoft\DirectX\GraphicsSettings"; "Name" = "SwapEffectUpgradeCache"; "Value" = 1 },
		@{"Path" = "HKCU:\Software\Microsoft\DirectX\UserGpuPreferences"; "Name" = "DirectXUserGlobalSettings"; "Value" = 'SwapEffectUpgradeEnable=1;' },
		@{"Path" = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform"; "Name" = "InactivityShutdownDelay"; "Value" = 4294967295 },
		@{"Path" = "HKLM:\SOFTWARE\Microsoft\Windows\Dwm"; "Name" = "OverlayTestMode"; "Value" = 5 }
	)

	foreach ($prop in $properties) {
		if ($Simular) {
			Write-Output "Simulação: Definiria $($prop.Name) em $($prop.Path) como $($prop.Value)"
		}
		else {
			Set-ItemProperty -Path $prop.Path -Name $prop.Name -Value $prop.Value -Type DWord -ErrorAction SilentlyContinue
		}
	}

	# Verifica o serviço MMAgent e tenta iniciá-lo, caso esteja desativado
	$magentService = Get-Service -Name MMAgent -ErrorAction SilentlyContinue
	if ($magentService.Status -ne 'Running') {
		Write-Output "O serviço MMAgent não está em execução. Tentando iniciar..."
		Start-Service -Name MMAgent -ErrorAction SilentlyContinue
	}

	# Desativando a compressão de memória
	if ($Simular) {
		Write-Output "Simulação: Executaria Disable-MMAgent -MemoryCompression"
	}
 else {
		Disable-MMAgent -MemoryCompression | Out-Null
	}

	# Restaurando a preferência de erro original
	$ErrorActionPreference = $errpref

	Write-Output "Otimizações de tela cheia concluídas!"
}


#Game Optimizations Priority Tweaks -Type String -Value "Deny"
Function GameOptimizationFIX {
	Write-Output "Apply Gaming Optimization Fixs..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "GPU Priority" -Type DWord -Value 8
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Priority" -Type DWord -Value 6
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Scheduling Category" -Type String -Value "High"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "SFIO Priority" -Type String -Value "High"
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "IRQ8Priority" -Type DWord -Value 1
	reg ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v CpuPriorityClass /t REG_DWORD /d 4 /f | Out-Null
	reg ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v IoPriority /t REG_DWORD /d 3 /f | Out-Null
	fsutil behavior set disable8dot3 1
	fsutil behavior set disablelastaccess 1
	$PlatformCheck = (Get-Computerinfo).CsPCSystemType
	if ($PlatformCheck -eq "Desktop") {
		Write-Output "Platform is $PlatformCheck Disabling power saving options on all connected devices..."
		Get-WmiObject MSPower_DeviceEnable -Namespace root\wmi | ForEach-Object { $_.enable = $false; $_.psbase.put(); } | Out-Null
	}
 else {
		Write-Output "Platform is $PlatformCheck No power saving edits has been made."
	}
}

#Forcing Raw Mouse Input
Function RawMouseInput {
	Write-Output "Forcing RAW Mouse Input and Disabling Enhance Pointer Precision..."
	Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSpeed" -Type String -Value "0"
	Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold1" -Type String -Value "0"
	Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold2" -Type String -Value "0"
	Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSensitivity" -Type String -Value "10"
	Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseHoverTime" -Type String -Value "0"
	Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseTrails" -Type String -Value "0"
}

#Detecting Windows Scale Layout Automatically and applying mouse fix according to it!
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

### Disable HPET ###
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
	Get-CimInstance -ClassName Win32_PnPEntity | Where-Object { $_.Name -eq 'High precision event timer' } | ForEach-Object { $_ | Invoke-CimMethod -MethodName Enable }
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

#Enable Windows 10 Gaming Mode
Function EnableGameMode {
	Write-Output "Enabling Gaming Mode..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AllowAutoGameMode" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AutoGameModeEnabled" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "ShowStartupPanel" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "GamePanelStartupTipIndex" -Type DWord -Value 3
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "UseNexusForGameBarEnabled" -Type DWord -Value 0
}

#Enable Hardware-accelerated GPU scheduling
Function EnableHAGS {
	Write-Output "Enabling HAGS..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "HwSchMode" -Type DWord -Value 2
}

#Add Utimate Power Plan And Activate It
Function EnableUlimatePower {
	Write-Output "Enabling and Activating Bitsum Highest Performance Power Plan..."
	$powerSchemes = powercfg /l | ForEach-Object {
		if ($_ -match '^Power Scheme GUID:\s*([-0-9a-f]+)\s*\(([^)]+)\)\s*(\*)?') {
			[PsCustomObject]@{
				GUID       = $matches[1]
				SchemeName = $matches[2]
				Active     = $matches[3] -eq '*'
			}
		}
	}
	$customScheme = ($powerSchemes | Where-Object { $_.SchemeName -eq 'Bitsum Highest Performance' }).GUID
	if ($customScheme -eq 'e6a66b66-d6df-666d-aa66-66f66666eb66') {
		Write-Output "Power Plan already exist! setting it as active..."
		powercfg -setactive e6a66b66-d6df-666d-aa66-66f66666eb66 | Out-Null
	}
 else {
		Write-Output "Enabling and Activating Bitsum Highest Performance Power Plan..."

		$url_bhp = "https://raw.githubusercontent.com/wesscd/WindowsGaming/main/Bitsum-Highest-Performance.pow"

		Invoke-WebRequest -Uri $url_bhp -OutFile "$Env:windir\system32\Bitsum-Highest-Performance.pow" -ErrorAction SilentlyContinue
		powercfg -import "$Env:windir\system32\Bitsum-Highest-Performance.pow" e6a66b66-d6df-666d-aa66-66f66666eb66 | Out-Null
		powercfg -setactive e6a66b66-d6df-666d-aa66-66f66666eb66 | Out-Null
 }
}

#Disable Core Parking on current PowerPlan Ultimate Performance
Function DisableCoreParking {
	Write-Output "Disabling Core Parking on current PowerPlan Ultimate Performance..."
	powercfg -attributes SUB_PROCESSOR CPMINCORES -ATTRIB_HIDE | Out-Null
	Powercfg -setacvalueindex scheme_current sub_processor CPMINCORES 100 | Out-Null
	powercfg /setacvalueindex scheme_current 2a737441-1930-4402-8d77-b2bebba308a3 d4e98f31-5ffe-4ce1-be31-1b38b384c009 0 | Out-Null
	powercfg /setacvalueindex scheme_current 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0 | Out-Null
	powercfg /setacvalueindex scheme_current 7516b95f-f776-4464-8c53-06167f40cc99 3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e 0 | Out-Null
	powercfg /setacvalueindex scheme_current 54533251-82be-4824-96c1-47b60b740d00 4d2b0152-7d5c-498b-88e2-34345392a2c5 5000 | Out-Null
	Powercfg -setactive scheme_current | Out-Null
}

#Disable DMA memory protection and cores isolation ("virtualization-based protection").
Function DisableDMA {
	Write-Output "Disabling DMA memory protection and cores isolation..."
	$errpref = $ErrorActionPreference #save actual preference
	$ErrorActionPreference = "silentlycontinue"
	#bcdedit /set vsmlaunchtype Off | Out-Null
	#bcdedit /set vm No | Out-Null
	bcdedit /deletevalue hypervisorlaunchtype | Out-Null
	bcdedit /deletevalue vsmlaunchtype | Out-Null
	bcdedit /deletevalue vm | Out-Null
	bcdedit /set loadoptions DISABLE-LSA-ISO, DISABLE-VBS | Out-Null
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" | Out-Null -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "DisableExternalDMAUnderLock" -Type DWord -Value 0
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" | Out-Null -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "HVCIMATRequired" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "RequirePlatformSecurityFeatures" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "LsaCfgFlags" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "HVCIMATRequired" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "RequirePlatformSecurityFeatures" -Type DWord -Value 0
	$ErrorActionPreference = $errpref #restore previous preference
}

#Disable Process and Kernel Mitigations
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

#Disallow drivers to get paged into virtual memory.
Function DisallowDIP {
	Write-Output "Disabling drivers get paged into virtual memory..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "DisablePagingExecutive" -Type DWord -Value 1
}

#Use big system memory caching to improve microstuttering.
Function UseBigM {
	Write-Output "Enabling big system memory caching to improve microstuttering..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "LargeSystemCache" -Type DWord -Value 0
}

#Force contiguous memory allocation in the DirectX Graphics Kernel.
Function ForceContiguousM {
	Write-Output "Forcing contiguous memory allocation in the DirectX Graphics Kernel..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "DpiMapIommuContiguous" -Type DWord -Value 1
}

#Tell Windows to stop tolerating high DPC/ISR latencies.
Function StophighDPC {
	Write-Output "Forcing Windows to stop tolerating high DPC/ISR latencies..."
	$errpref = $ErrorActionPreference #save actual preference
	$ErrorActionPreference = "silentlycontinue"
	New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" | Out-Null -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "ExitLatency" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "ExitLatencyCheckEnabled" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "Latency" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "LatencyToleranceDefault" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "LatencyToleranceFSVP" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "LatencyTolerancePerfOverride" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "LatencyToleranceScreenOffIR" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "LatencyToleranceVSyncEnabled" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "RtlCapabilityCheckLatency" -Type DWord -Value 1
	New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" | Out-Null -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultD3TransitionLatencyActivelyUsed" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultD3TransitionLatencyIdleLongTime" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultD3TransitionLatencyIdleMonitorOff" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultD3TransitionLatencyIdleNoContext" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultD3TransitionLatencyIdleShortTime" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultD3TransitionLatencyIdleVeryLongTime" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultLatencyToleranceIdle0" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultLatencyToleranceIdle0MonitorOff" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultLatencyToleranceIdle1" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultLatencyToleranceIdle1MonitorOff" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultLatencyToleranceMemory" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultLatencyToleranceNoContext" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultLatencyToleranceNoContextMonitorOff" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultLatencyToleranceOther" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultLatencyToleranceTimerPeriod" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultMemoryRefreshLatencyToleranceActivelyUsed" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultMemoryRefreshLatencyToleranceMonitorOff" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultMemoryRefreshLatencyToleranceNoContext" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "Latency" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "MaxIAverageGraphicsLatencyInOneBucket" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "MiracastPerfTrackGraphicsLatency" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "MonitorLatencyTolerance" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "MonitorRefreshLatencyTolerance" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "TransitionLatency" -Type DWord -Value 1
	$ErrorActionPreference = $errpref #restore previous preference
}

#Decrease mouse and keyboard buffer sizes.
Function DecreaseMKBuffer {
	Write-Output "Decreasing mouse and keyboard buffer sizes..."
	$errpref = $ErrorActionPreference #save actual preference
	$ErrorActionPreference = "silentlycontinue"
	New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" | Out-Null -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" -Name "MouseDataQueueSize" -Type DWord -Value 0x00000020
	New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" | Out-Null -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" -Name "KeyboardDataQueueSize" -Type DWord -Value 0x00000020
	$ErrorActionPreference = $errpref #restore previous preference
}






function Ativar-Servicos {
	param (
		[string[]]$Servicos = @('SysMain', 'PcaSvc', 'DiagTrack')
	)

	# Exibir banner informativo
	Clear-Host
	Escrever-Colorido "" "Vermelho"
	Escrever-Colorido "======================================================" "Vermelho"
	Escrever-Colorido "===  Servicos Essenciais para Investigacao Forense ===" "Vermelho"
	Escrever-Colorido "======================================================" "Vermelho"
	Escrever-Colorido "" "Vermelho"
	Escrever-Colorido "Este menu auxilia na ativacao dos seguintes servicos:" "CinzaClaro"
	Escrever-Colorido "- SysMain: " "Amarelo"; Escrever-Colorido "O SysMain, anteriormente conhecido como Superfetch, e um servico do Windows que preenche a memoria RAM com aplicativos frequentemente usados para acelerar o carregamento dos programas mais utilizados." "Branco"
	Escrever-Colorido "- PcaSvc: " "Amarelo"; Escrever-Colorido "O PcaSvc (Program Compatibility Assistant Service) e um servico que detecta problemas de compatibilidade em programas legados e aplica correcao para melhorar a estabilidade do sistema." "Branco"
	Escrever-Colorido "- DiagTrack: " "Amarelo"; Escrever-Colorido "O DiagTrack (Connected User Experiences and Telemetry) coleta e envia dados de diagnostico e uso para a Microsoft, auxiliando na melhoria dos servicos e na resolucao de problemas." "Branco"
	Escrever-Colorido "" "CinzaClaro"
	Escrever-Colorido "Estes servicos sao essenciais para a investigacao forense de cheats em servidores de Minecraft, DayZ e FIVEM GTA5 que utilizam o Echo AntiCheat." "Amarelo"
	Escrever-Colorido "" "Amarelo"
	Escrever-Colorido "===============================================" "AmareloClaro"

	# Função interna para ativar um servico
	function Ativar-Servico {
		param (
			[string]$NomeServico
		)
		$servico = Get-Service -Name $NomeServico -ErrorAction SilentlyContinue
		if ($null -eq $servico) {
			Escrever-Colorido "Servico '$NomeServico' nao encontrado." "VermelhoClaro"
			return
		}
		Escrever-Colorido "Servico encontrado: $($servico.DisplayName) ($($servico.Name))" "CinzaClaro"
		if ($servico.Status -eq 'Running') {
			Escrever-Colorido "Servico '$($servico.Name)' ja esta em execucao." "VerdeClaro"
		}
		else {
			Start-Service -Name $servico.Name
			Set-Service -Name $servico.Name -StartupType Automatic
			Escrever-Colorido "Servico '$($servico.Name)' ativado com sucesso." "VerdeClaro"
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
			Escrever-Colorido "Servico '$nomeServico' nao foi ativado." "Amarelo"
		}
	}
}




#Remove Edit with 3D Paint
Function RemoveEdit3D {
	Write-Output "Removing Edit with Paint 3D from context menu..."
	Remove-ItemProperty -Path "HKCR:\SystemFileAssociations\.3mf\Shell\" -Name "3D Edit" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCR:\SystemFileAssociations\.bmp\Shell\" -Name "3D Edit" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCR:\SystemFileAssociations\.fbx\Shell\" -Name "3D Edit" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCR:\SystemFileAssociations\.gif\Shell\" -Name "3D Edit" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCR:\SystemFileAssociations\.jfif\Shell\" -Name "3D Edit" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCR:\SystemFileAssociations\.jpe\Shell\" -Name "3D Edit" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCR:\SystemFileAssociations\.jpeg\Shell\" -Name "3D Edit" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCR:\SystemFileAssociations\.jpg\Shell\" -Name "3D Edit" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCR:\SystemFileAssociations\.png\Shell\" -Name "3D Edit" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCR:\SystemFileAssociations\.tif\Shell\" -Name "3D Edit" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCR:\SystemFileAssociations\.tiff\Shell\" -Name "3D Edit" -ErrorAction SilentlyContinue
}

#fix issue with games shortcut that created by games lunchers turned white!
Function FixURLext {
	Escrever-Colorido "Corrigindo atalhos do White Games criados por inicializadores de jogos..." "Verde"
	choco install -y setuserfta | Out-Null
	Start-Sleep -s 5
	Push-Location
	set-location "$env:ProgramData\chocolatey\lib\setuserfta\tools\SetUserFTA\"
	SetUserFTA.exe del .url | Out-Null
	SetUserFTA.exe .url, InternetShortcut | Out-Null
	Pop-Location
	choco uninstall -y setuserfta | Out-Null
}
    
# Ultimate CLeaner
Function UltimateCleaner {

	Clear-Host
	Escrever-Colorido "" "Verde"
	Escrever-Colorido "Executando o Ultimate Cleaner => Pastas temporarias e limpar DNS + Redefinir IP...." "Verde"
	Escrever-Colorido "" "Verde"
	cmd /c 'netsh winsock reset 2>nul' >$null
	cmd /c 'netsh int ip reset 2>nul' >$null
	cmd /c 'ipconfig /release 2>nul' >$null
	cmd /c 'ipconfig /renew 2>nul' >$null
	cmd /c 'ipconfig /flushdns 2>nul' >$null
	cmd /c 'echo Flush DNS + IP Reset Completed Successfully!'
	cmd /c 'echo Clearing Temp folders....'
	cmd /c 'del /f /s /q %systemdrive%\*.tmp 2>nul' >$null
	cmd /c 'del /f /s /q %systemdrive%\*._mp 2>nul' >$null
	cmd /c 'del /f /s /q %systemdrive%\*.log 2>nul' >$null
	cmd /c 'del /f /s /q %systemdrive%\*.gid 2>nul' >$null
	cmd /c 'del /f /s /q %systemdrive%\*.chk 2>nul' >$null
	cmd /c 'del /f /s /q %systemdrive%\*.old 2>nul' >$null
	cmd /c 'del /f /s /q %systemdrive%\recycled\*.* 2>nul' >$null
	cmd /c 'del /f /s /q %windir%\*.bak 2>nul' >$null
	cmd /c 'del /f /s /q %windir%\prefetch\*.* 2>nul' >$null
	cmd /c 'del /f /q %userprofile%\cookies\*.* 2>nul' >$null
	cmd /c 'del /f /q %userprofile%\recent\*.* 2>nul' >$null
	cmd /c 'del /f /s /q %userprofile%\Local Settings\Temporary Internet Files\*.* 2>nul' >$null
	$errpref = $ErrorActionPreference #save actual preference
	$ErrorActionPreference = "silentlycontinue"
	Get-ChildItem -Path "$env:temp" -Exclude "dmtmp" | ForEach-Object ($_) {
		"CLEANING :" + $_.fullname
		Remove-Item $_.fullname -Force -Recurse
		"CLEANED... :" + $_.fullname
	}
	$ErrorActionPreference = $errpref #restore previous preference
	cmd /c 'del /f /s /q %userprofile%\recent\*.* 2>nul' >$null
	cmd /c 'del /f /s /q %windir%\Temp\*.* 2>nul' >$null
	cmd /c 'echo Temp folders Cleared Successfully!'
}

#Notifying user to reboot!
Function Finished {
	# Verifica se o script está rodando como administrador
	function Test-Admin {
		$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
		$principal = New-Object Security.Principal.WindowsPrincipal $currentUser
		return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
	}

	if (-not (Test-Admin)) {
		Escrever-Colorido "Este script precisa ser executado como Administrador. Por favor, execute-o novamente como Administrador." "Vermelho"
		exit
	}

	# Define URL e destino do logo OEM
	$url_logo = "https://raw.githubusercontent.com/wesscd/WindowsGaming/main/logo.bmp"
	$destino_logo = "C:\Windows\oemlogo.bmp"

	# Verifica a conectividade antes de baixar a imagem
	try {
		$response = Test-Connection -ComputerName "raw.githubusercontent.com" -Count 1 -Quiet
		if ($response) {
			Invoke-WebRequest -Uri $url_logo -OutFile $destino_logo -ErrorAction Stop
		}
		else {
			Escrever-Colorido "Não foi possível baixar o logo. Verifique sua conexão." "Vermelho"
		}
	}
 catch {
		Escrever-Colorido "Erro ao baixar o logo OEM: $_" "Vermelho"
	}

	# Criar permissões MSI Installer (Rodar como Administrador)
	if (!(Test-Path "HKCR:\Msi.Package\shell\runas")) {
		New-Item -Path "HKCR:\Msi.Package\shell\runas" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCR:\Msi.Package\shell\runas" -Name "HasLUAShield" -Type String -Value ""
	Set-ItemProperty -Path "HKCR:\Msi.Package\shell\runas\command" -Name "(Default)" -Type ExpandString -Value '"%SystemRoot%\System32\msiexec.exe" /i "%1" %*"' 

	# Ativa histórico da área de transferência
	if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowClipboardHistory" -Type DWord -Value 1

	# Criar informações OEM
	$oemPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation"
	if (!(Test-Path $oemPath)) {
		New-Item -Path $oemPath -Force | Out-Null
	}
	
	Set-ItemProperty -Path $oemPath -Name "Manufacturer" -Type String -Value "PC Otimizado por Cesar Marques (Barao)"
	Set-ItemProperty -Path $oemPath -Name "Model" -Type String -Value "Otimizacao, Hardware, Infra & Redes"
	Set-ItemProperty -Path $oemPath -Name "SupportURL" -Type String -Value "http://techremote.com.br"
	Set-ItemProperty -Path $oemPath -Name "SupportHours" -Type String -Value "Seg-Sex: 08h-18h"
	Set-ItemProperty -Path $oemPath -Name "SupportPhone" -Type String -Value "+55 16 99263-6487"
	Set-ItemProperty -Path $oemPath -Name "Logo" -Type String -Value $destino_logo

	Start-Sleep -s 5

	# Mensagem final
	Escrever-Colorido "Configuração concluida! Reinicie o PC para aplicar todas as mudancas." "Verde"
	
	# Abre o site sem problemas com navegadores modernos
	Start-Process "http://techremote.com.br"

	Clear-Host
	Send-Color-Text "Otimização concluída com sucesso!`nReinicie o sistema para aplicar todas as alterações." "Verde"
	if ((Read-Host "Deseja reiniciar agora? (S/N)") -imatch '^s$') { Restart-Computer -Force }
	
}


##########
# Auxiliary Functions
##########

# Relaunch the script with administrator privileges
Function RequireAdmin {
	If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
		Start-Process Powershell -Argumentlist '-ExecutionPolicy bypass -NoProfile -command "irm "https://raw.githubusercontent.com/wesscd/WindowsGaming/master/windowsdebloatandgamingtweaks.ps1" | iex"' -Verb RunAs
		Exit
	}
}

###########
# Titus Additions
###########

Function EnableDarkMode {
	Write-Output "Enabling Dark Mode"
	Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name AppsUseLightTheme -Value 0
}

##########
# Debloat Script Additions
##########

#Create Restore Point
Function CreateRestorePoint {
	Write-Output "Criando um ponto de restauracao caso algo ruim aconteca"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name "SystemRestorePointCreationFrequency" -Value 0
	cmd /c 'vssadmin resize shadowstorage /on="%SystemDrive%" /For="%SystemDrive%" /MaxSize=5GB 2>nul' >$null
	Enable-ComputerRestore -Drive "$env:SystemDrive\"
	Checkpoint-Computer -Description "Script Otimizacao TechRemote" -RestorePointType "MODIFY_SETTINGS"
}

# In case you have removed them for good, you can try to restore the files using installation medium as follows
# New-Item C:\Mnt -Type Directory | Out-Null
# dism /Mount-Image /ImageFile:D:\sources\install.wim /index:1 /ReadOnly /MountDir:C:\Mnt
# robocopy /S /SEC /R:0 "C:\Mnt\Program Files\WindowsApps" "C:\Program Files\WindowsApps"
# dism /Unmount-Image /Discard /MountDir:C:\Mnt
# Remove-Item -Path C:\Mnt -Recurse


Function Clear-PSHistory {
	# Remove o histórico atual da sessão (PowerShell 5.1 e versões superiores)
	if (Get-Command -Name 'Clear-PSReadlineHistory' -ErrorAction SilentlyContinue) {
		Clear-PSReadlineHistory
	}

	# Remove o histórico do perfil do usuário (caso o PowerShell use um arquivo de histórico)
	$historyPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"
	if (Test-Path $historyPath) {
		Remove-Item $historyPath -Force -ErrorAction SilentlyContinue
	}

	# Remove histórico do buffer de memória do PowerShell
	$historyPathLegacy = "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"
	if (Test-Path $historyPathLegacy) {
		Remove-Item $historyPathLegacy -Force -ErrorAction SilentlyContinue
	}

	# Garante que o histórico também seja apagado no Windows PowerShell (caso o arquivo seja diferente)
	$historyPathLegacyPS = "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history"
	if (Test-Path $historyPathLegacyPS) {
		Remove-Item $historyPathLegacyPS -Force -ErrorAction SilentlyContinue
	}

	# Limpa o histórico da sessão atual
	$global:history = @()

	# Limpa os itens do histórico com um comando alternativo
	if ($PSVersionTable.PSVersion -lt '5.0') {
		# Para versões abaixo da 5.0, usamos o comando alternativo
		Clear-History -ErrorAction SilentlyContinue
	}
 else {
		# Para versões 5.0 ou superiores, podemos usar o cmdlet `Clear-History`
		Get-History | ForEach-Object { Remove-Item -Path "history:$($_.Id)" -ErrorAction SilentlyContinue }
	}

	# Confirmação visual
	Escrever-Colorido "Histórico do PowerShell completamente apagado!" "Verde"
}

##########
# Parse parameters and apply tweaks
##########

# Normalize path to preset file
$preset = ""
$PSCommandArgs = $args
If ($args -And $args[0].ToLower() -eq "-preset") {
	$preset = Resolve-Path $($args | Select-Object -Skip 1)
	$PSCommandArgs = "-preset `"$preset`""
}

# Load function names from command line arguments or a preset file
If ($args) {
	$tweaks = $args
	If ($preset) {
		$tweaks = Get-Content $preset -ErrorAction Stop | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" -and $_[0] -ne "#" }
	}
}
If ($args) {
	$mobiletweaks = $args
	If ($preset) {
		$mobiletweaks = Get-Content $preset -ErrorAction Stop | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" -and $_[0] -ne "#" }
	}
}


Show-Intro
New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT -ErrorAction SilentlyContinue | Out-Null
New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -ErrorAction SilentlyContinue | Out-Null

foreach ($tweak in $tweaks) { Invoke-Expression $tweak }
