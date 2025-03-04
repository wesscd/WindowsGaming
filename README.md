# Windows Gaming v0.6.7

# How To Use!

Simply Run cmd (Command Prompt) as Administrator and paste the following!
```
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('http://tweaks.techremote.com.br')"
```
if error then use the following!
```
powershell -NoProfile -ExecutionPolicy unrestricted -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; &iex(New-Object Net.WebClient).DownloadString('http://tweaks.techremote.com.br')"
```
Or Run Powershell As Administrator and paste the following!

```
iex(New-Object Net.WebClient).DownloadString('http://tweaks.techremote.com.br')
```
To enable Action Center, put the following into Powershell run As Administrator!

```
Write-Host "Enabling Action Center..."
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -ErrorAction SilentlyContinue 
	Write-Host "Done - Reverted to Stock Settings"
```
## Modifications

```
########## NOTE THE # SIGNS! These disable lines This example shows UACLow being set and Disabling SMB1
### Security Tweaks ###
	"SetUACLow",                  # "SetUACHigh",
	"DisableSMB1",                # "EnableSMB1",

########## NOW LETS SWAP THESE VALUES AND ENABLE SMB1 and Set UAC to HIGH
### Security Tweaks ###
	"SetUACHigh",
	"EnableSMB1",
```
