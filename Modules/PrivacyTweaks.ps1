# Modules\PrivacyTweaks.ps1

# Função para escrever texto colorido (se não for movida para outro módulo)
function Write-Colored {
  param (
    [string]$Text,
    [ConsoleColor]$Color = 'White'
  )
  Write-Host $Text -ForegroundColor $Color
}

# Disable Telemetry
# Note: This tweak may cause Enterprise edition to stop receiving Windows updates.
# Windows Update control panel will then show message "Your device is at risk because it's out of date and missing important security and quality updates. Let's get you back on track so Windows can run more securely. Select this button to get going".
# In such case, enable telemetry, run Windows update and then disable telemetry again. See also https://github.com/Disassembler0/Win10-Initial-Setup-Script/issues/57
Function DisableTelemetry {
  Write-Output "Disabling Telemetry..."
  $errpref = $ErrorActionPreference #save actual preference
  $ErrorActionPreference = "silentlycontinue"
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
  Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
  Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
  Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
  Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
  Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
  Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null
  $ErrorActionPreference = $errpref #restore previous preference
}

# Disable Wi-Fi Sense
Function DisableWiFiSense {
  Write-Output "Disabling Wi-Fi Sense..."
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

# Disable SmartScreen Filter
Function DisableSmartScreen {
  Write-Output "Disabling SmartScreen Filter..."
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Type DWord -Value 0
  If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -Type DWord -Value 0
}

# Disable Web Search in Start Menu
Function DisableWebSearch {
  Write-Output "Disabling Bing Search in Start Menu..."
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Type DWord -Value 0
  If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Type DWord -Value 1
}

# Disable Application suggestions and automatic installation
Function DisableAppSuggestions {
  Write-Output "Disabling Application suggestions..."
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

# Disable Activity History feed in Task View - Note: The checkbox "Let Windows collect my activities from this PC" remains checked even when the function is disabled
Function DisableActivityHistory {
  Write-Output "Disabling Activity History..."
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0
}

# Enable Background application access
Function EnableBackgroundApps {
  Write-Output "Enabling Background application access..."
  Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" | ForEach-Object {
    Remove-ItemProperty -Path $_.PsPath -Name "Disabled" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $_.PsPath -Name "DisabledByUser" -ErrorAction SilentlyContinue
  }
}

# Disable Location Tracking
Function DisableLocationTracking {
  Write-Output "Disabling Location Tracking..."
  If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny"
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
  New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Force | Out-Null
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0
}

# Disable automatic Maps updates
Function DisableMapUpdates {
  Write-Output "Disabling automatic Maps updates..."
  Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0
}

# Disable Feedback
Function DisableFeedback {
  Write-Output "Disabling Feedback..."
  If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1
  Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
  Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null
}

# Disable Tailored Experiences
Function DisableTailoredExperiences {
  Write-Output "Disabling Tailored Experiences..."
  If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
    New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1
}

# Disable Advertising ID
Function DisableAdvertisingID {
  Write-Output "Disabling Advertising ID..."
  If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" | Out-Null
  }
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1
}

# Disable Cortana
Function DisableCortana {
  Write-Output "Disabling Cortana..."
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
  If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0
}

# Disable Error reporting
Function DisableErrorReporting {
  Write-Output "Disabling Error reporting..."
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1
  Disable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null
}

# Restrict Windows Update P2P only to local network - Needed only for 1507 as local P2P is the default since 1511
Function SetP2PUpdateLocal {
  Write-Output "Restricting Windows Update P2P only to local network..."
  $errpref = $ErrorActionPreference #save actual preference
  $ErrorActionPreference = "silentlycontinue"
  If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" | Out-Null
  }
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 1 | Out-Null -ErrorAction SilentlyContinue
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -Name "DODownloadMode" -Type DWord -Value 1 -Force | Out-Null
  $ErrorActionPreference = $errpref #restore previous preference
}

# Stop and disable WAP Push Service
Function DisableWAPPush {
  Write-Output "Stopping and disabling WAP Push Service..."
  Stop-Service "dmwappushservice" -WarningAction SilentlyContinue
  Set-Service "dmwappushservice" -StartupType Disabled
}

# Exportar funções para uso externo
Export-ModuleMember -Function DisableTelemetry, DisableWiFiSense, DisableSmartScreen, DisableWebSearch, DisableAppSuggestions, DisableActivityHistory, EnableBackgroundApps, DisableLocationTracking, DisableMapUpdates, DisableFeedback, DisableTailoredExperiences, DisableAdvertisingID, DisableCortana, DisableErrorReporting, SetP2PUpdateLocal, DisableWAPPush