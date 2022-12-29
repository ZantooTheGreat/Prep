#############################################
#                                           #
# IF YOU WANT TO MAKE CHANGES TO THIS FILE  #
# PLEASE MAKE A COPY AND EDIT THAT          #
# DONT MAKE CHANGES TO THE ORIGINAL WITHOUT #
# MANAGEMENT CONSENT.                       #
#                                           #
#############################################
# Variables
$global:PCNameSuffix = (get-ciminstance -ClassName Win32_ComputerSystemProduct | Select-Object -ExpandProperty IdentifyingNumber)
#PC Name container
$global:FullPCName = "$global:DivisionName - $global:PCNameSuffix"
# Rename PC
function Prep-PC-Name ($global:FullPCName){
    Rename-Computer -NewName "$global:FullPCName"
}
# PC Prep
function Prep-PC {
    # Create Admin directory and hide it from muggles
            Write-Host "Creating directories..." -ForegroundColor Yellow
            New-Item -Path "C:\Admin" -ItemType Directory
            attrib +s +h "C:\Admin"
            Copy-Item -Force "J:\Approved Installers\BGInfo\Settings_Alt.bgi" -Destination "C:\Admin\"
            cd C:\Admin
    # Install WinGet
        Write-Host "Installing Winget... Please Wait"
        Start-Process "ms-appinstaller:?source=https://www.microsoft.com/store/productId/9NBLGGH4NNS1"
        $nid = (Get-Process AppInstaller).Id
        Wait-Process -Id $nid
        Write-Host Winget Installed
        Write-Host "Winget Installed - Ready for Next Task"
        Start-Sleep -Seconds 2
    # Chocolatey
            Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    # Disable UAC
        Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -Type DWord -Value 0
        Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableLUA -Type DWord -Value 0
        Write-Verbose "Disabled UAC" -Verbose
    # Disable Firewall
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
        Write-Verbose "Disabled Firewall" -Verbose
    # Enable RDP
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -name "fDenyTSConnections" -Value 0
        Write-Verbose "RDP Enabled" -Verbose
    # Power settings
        # Set Power Plan to High Performance
            powercfg /s 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
        # hibernate off
            powercfg -h off
        # Specifies the new value, in minutes.
            powercfg /CHANGE monitor-timeout-ac 240
            powercfg /CHANGE monitor-timeout-dc 10
            powercfg /CHANGE disk-timeout-ac 0
            powercfg /CHANGE disk-timeout-dc 0
            powercfg /Change standby-timeout-ac 0
            powercfg /Change standby-timeout-dc 20
        # Disable selective suspend on plugged in laptops/desktops:
            Powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0
            Powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0
        # Set power button action on laptops/desktops (0=Do nothing - 1=Sleep - 2=Hibernate - 3=Shut down - 4=Turn off the display):
            powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 4f971e89-eebd-4455-a8de-9e59040e7347 7648efa3-dd9c-4e3e-b566-50f929386280 3
            powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 4f971e89-eebd-4455-a8de-9e59040e7347 7648efa3-dd9c-4e3e-b566-50f929386280 3
        # Set lid close action on laptops (0=Do nothing - 1=Sleep - 2=Hibernate - 3=Shut down):
            powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 0
            powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 0
    # Disable automatic setup of network devices
        If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private")){
            New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Force | Out-Null}
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name "AutoSetup" -Type DWord -Value 0
    # Remove TEAMS system wide installer
            Start-Process MsiExec.exe -ArgumentList '/X{39AF0813-FA7B-4860-ADBE-93B9B214B914} /qn' -Wait
            Start-Process MsiExec.exe -ArgumentList '/X{731F6BAA-A986-45A4-8936-7C3AAAAA760B} /qn' -Wait
    #Disable scheduled defrags
        schtasks /Change /DISABLE /TN "\Microsoft\Windows\Defrag\ScheduledDefrag"
}
#Tablet prep script as function
function Prep-Tablet {
  [cmdletbinding(SupportsShouldProcess)]
  [alias("iwg")]
  [OutputType("None")]
  [OutputType("Microsoft.Windows.Appx.PackageManager.Commands.AppxPackage")]
  Param(
      [Parameter(HelpMessage = "Display the AppxPackage after installation.")]
      [switch]$Passthru)
  
  Write-Verbose "[$((Get-Date).TimeofDay)] Starting $($myinvocation.mycommand)"
  # Domain Join
    wmic computersystem where name="$ENV:COMPUTERNAME" call joindomainorworkgroup fjoinoptions=3 name="liftsafeinspect" username="liftsafeinspect\administrator" Password="LgocAdmin2430!"
  # Enable RDP
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
  # Add Domain Users to Local Admin
    Add-LocalGroupMember -Group Administrators -Member "$env:USERDNSDOMAIN\Domain Users"
    Write-Host "Domain Users added to Local Admins"
  # Install WinGet
    # Install the latest package from GitHub
    # Check PS Version
    If ($PSVersionTable.PSVersion.Major -eq 7) {Write-Warning "This command does not work in PowerShell 7. You must install in Windows PowerShell."
    Return}
    # Test for requirement
    $Requirement = Get-AppPackage "Microsoft.DesktopAppInstaller"
        If (-Not $requirement) {Write-Verbose "Installing Desktop App Installer requirement"
        Try {Add-AppxPackage -Path "https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx" -erroraction Stop}
        Catch {Throw $_}}
    $uri = "https://api.github.com/repos/microsoft/winget-cli/releases"

    Try {Write-Verbose "[$((Get-Date).TimeofDay)] Getting information from $uri"
    $get = Invoke-RestMethod -uri $uri -Method Get -ErrorAction stop
        Write-Verbose "[$((Get-Date).TimeofDay)] getting latest release"
        #$data = $get | Select-Object -first 1
        $data = $get[0].assets | Where-Object name -Match 'msixbundle'

        $appx = $data.browser_download_url
        #$data.assets[0].browser_download_url
        Write-Verbose "[$((Get-Date).TimeofDay)] $appx"
        If ($pscmdlet.ShouldProcess($appx, "Downloading asset")) {
        $file = Join-Path -path $env:temp -ChildPath $data.name
        Write-Verbose "[$((Get-Date).TimeofDay)] Saving to $file"
        Invoke-WebRequest -Uri $appx -UseBasicParsing -DisableKeepAlive -OutFile $file
        Write-Verbose "[$((Get-Date).TimeofDay)] Adding Appx Package"
        Add-AppxPackage -Path $file -ErrorAction Stop
        If ($passthru) {Get-AppxPackage microsoft.desktopAppInstaller}}} 
    #Try
        Catch {
        Write-Verbose "[$((Get-Date).TimeofDay)] There was an error."
        Throw $_}
        Write-Verbose "[$((Get-Date).TimeofDay)] Ending $($myinvocation.mycommand)"

  # Install Chocolatey
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
  # Whitelist G10 directory (Deprecated but relevant where 2.13 is requested)
    Set-MpPreference -ExclusionPath "C:\Users\$ENV:USERNAME\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\STYLUSOFT INC\"
  # Improve touch sensitivity
    Set-ItemProperty -Path 'HKLM:\Software\Microsoft\TouchPrediction' -Name 'Latency' -Value 2

  <#Tablet Apps#>
      # SQL64CE
      Copy-Item -Force "J:\Approved Installers\Tablet Setup\SQLCEv4x64.exe" -Destination "C:\Admin\G10\"
      # G10 2.20
      Copy-Item -Force "J:\Approved Installers\Tablet Setup\G10 Tablet 2.20.exe" -Destination "C:\Admin\G10\"
      # BGInfo
      Copy-Item -Force "J:\Approved Installers\Tablet Setup\Bginfo64.exe" -Destination "C:\Admin\G10\"
      # BGInfo Config
      Copy-Item -Force "J:\Approved Installers\Tablet Setup\Settings.bgi" -Destination "C:\Admin\G10\"
      # LGOC Wallpaper
      Copy-Item -Force "J:\Approved Installers\Tablet Setup\LGOCWallpaper1920.jpg" -Destination "C:\Admin\G10\"
      # Pulseway Agent
      Copy-Item -Force "J:\Approved Installers\Tablet Setup\LESGC Tablets.msi" -Destination "C:\Admin\G10\"
  
  <# Application Installs #>
      # Install BGInfo with settings
      bginfo c:\admin\g10\settings.bgi /timer:0 /nolicprompt
      # Install SQL software
      Start-Process -FilePath "C:\Admin\G10\SQLCEv4x64.exe" -Wait
      # Install G10 
      Start-Process -FilePath "C:\Admin\G10\G10 Tablet 2.20.exe" -Wait
      # Install Pulseway Agent
      Start-Process -FilePath "C:\Admin\G10\LESGC Tablets.msi" -Wait
}
# Local User as Admin
function Prep-Users-Localadmin {
    Add-LocalGroupMember -Group Administrators -Member "$env:USERDNSDOMAIN\Domain Users"
}
# Prep User experience
function Prep-User {
    #Get-AppxPackage * | Remove-AppxPackage
    Write-Verbose "Removed windows apps"
    Get-AppXPackage -allusers Microsoft.Microsoft3DViewer | Remove-AppxPackage
    Get-AppXPackage -allusers Microsoft.WindowsAlarms | Remove-AppxPackage
    Get-AppXPackage -allusers Microsoft.WindowsFeedbackhub | Remove-AppxPackage
    Get-AppXPackage -allusers Microsoft.OfficeHub | Remove-AppxPackage
    Get-AppXPackage -allusers Microsoft.GetHelp | Remove-AppxPackage
    Get-AppXPackage -allusers Microsoft.GetStarted | Remove-AppxPackage
    Get-AppXPackage -allusers Microsoft.GetHelp | Remove-AppxPackage
    Get-AppXPackage -allusers Microsoft.MixedReality.Portal | Remove-AppxPackage
    Get-AppXPackage -allusers Microsoft.WindowsMaps | Remove-AppxPackage
    Get-AppXPackage -allusers Microsoft.People | Remove-AppxPackage
    Get-AppXPackage -allusers Microsoft.BingWeather | Remove-AppxPackage
    Get-AppXPackage -allusers Microsoft.ZuneMusic | Remove-AppxPackage
    Get-AppXPackage -allusers Microsoft.ZuneVideo | Remove-AppxPackage
    Get-AppxPackage -allusers Microsoft.Office.OneNote | Remove-AppxPackage
    Get-AppxPackage -allusers Microsoft.MicrosoftOfficeHub | Remove-AppxPackage
    # Prevent reinstall of default apps with new user
	Get-AppXProvisionedPackage -Online | Remove-AppxProvisionedPackage -Online
    Clear-Host
    # Start Menu: Disable Bing Search Results
    Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search -Name BingSearchEnabled -Type DWord -Value 0
    # Change Explorer home screen back to "This PC"
    Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -Type DWord -Value 1
    # Hide Cortana Search
    Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search -Name SearchboxTaskbarMode -Type DWord -Value 0
    # Remove TaskView button from taskbar
    Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ShowTaskViewButton -Type DWord -Value 0
    # Remove People button from taskbar
    Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People -Name PeopleBand -Type DWord -Value 0
    # Remove Suggestions from Start Menu
    Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SystemPaneSuggestionsEnabled -Type DWord -Value 0
    # Disable preinstalled apps
    Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name PreInstalledAppsEnabled -Type DWord -Value 0
    # Disable Silent Install Store Apps
    Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SilentInstalledAppsEnabled -Type DWord -Value 0
    # Disable Subscribed Content Apps
    Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-338388Enabled -Type DWord -Value 0
    Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-338389Enabled -Type DWord -Value 0
    # Remove Meet Now Button
    Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name HideSCAMeetNow -Value 1
    # Remove News/Weather Icon from taskbar
    Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds -Name ShellFeedsTaskbarViewMode -Value 2
    # Set Time Zone
    Set-TimeZone -Name "Eastern Standard Time"
    # Disable Action Center
        If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null}
        Set-ItemProperty -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name DisableNotIficationCenter -Type DWord -Value 1
        Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotIfications -Name ToastEnabled -Type DWord -Value 0
    Write-Verbose "Disabling Action Center..." -Verbose
}
# Install .NET Framework
function Prep-DotNET {
    Write-Verbose "Install .NET Framework" -Verbose
    Enable-WindowsOptionalFeature -Online -FeatureName “NetFx3”
    Clear-Host
    Write-Verbose ".NET Framework Install Complete" -Verbose
    Clear-Host
}
###############################
# Application Installs
###############################
# Install Chrome
function Prep-Chrome {
    $ChromeCheck = Test-Path -Path "ChromeStandaloneSetup64.exe"
    If($ChromeCheck -eq $true){Start-Process ".\ChromeStandaloneSetup64.exe" -Wait
        Write-Verbose "Chrome Installed" -Verbose}
    ElseIf($ChromeCheck -eq $false) {Write-Verbose "Local installer not found, installing..." -Verbose
        choco install -y googlechrome}
}
# Install Adobe Reader
function Prep-Adobe {
    $AdobeReaderCheck = Test-Path -Path "C:\Program Files (x86)\Adobe\Adobe Reader DC"
    If($AdobeReaderCheck -eq $true){Start-Process ".\AcroRdrDC_en_US" "/sPB /rs" -wait
        Write-Verbose "Adobe Reader Installed" -Verbose}
    ElseIf($AdobeReaderCheck -eq $false){Write-Verbose "Local installer not found, installing..." -Verbose
        choco install -y adobereader
    Write-Verbose "Adobe Reader installed"}
}
# Install Lenovo System Updater check
function Prep-Updater {
    $global:Manucheck = (Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -Expandproperty Manufacturer)
    If($global:Manucheck -contains "LENOVO") {Write-host "Lenovo System Update will be installed..." -ForegroundColor Green
        choco install -y lenovo-thinkvantage-system-update}
    ElseIf($global:Manucheck -contains "Dell Inc.") {Write-host "Dell Command update will be installed..." -ForegroundColor Green
        choco install -y DellCommandUpdate}
}
# BGInfo Installer
function Prep-BGInfo {
    $BGInfoCheck = Test-path "C:\Admin\BGinfo*"
    iwr -uri https://raw.githubusercontent.com/ZantooTheGreat/Prep/main/LGOCWallpaper_Alt.jpg -OutFile C:\Admin\LGOCWallpaper_Alt.jpg
    Start-sleep -seconds 2
    Copy-Item -Force "J:\Approved Installers\BGInfo\Settings_Alt.bgi" -Destination "C:\Admin\"
    Start-Sleep -seconds 2
    If($BGInfoCheck -eq $true){Write-host "BGInfo is already downloaded in the Admin folder"}
    cd C:\Admin\BGInfo.exe
    .\Bginfo64.exe Settings /silent /timer:0 /nolicprompt
	ElseIf($BGInfoCheck -eq $false){Write-host "BGInfo installer not found -- Downloading"
    choco install --force -y bginfo
    bginfo C:\Admin\Settings_Alt.bgi /timer:0 /nolicprompt}
}
# Install Office365 via WinGet
function Prep-Office {
		choco install -y office365business
}
# Install G10 2.20
function Prep-G10 {
    Write-Host "Downloading G10 for tablets..."
    Invoke-WebRequest -Uri "http://207.188.84.12/web.teamsfa/G10/G10Setup.html" -OutFile "C:\Admin\G10\G10Setup.exe"
    Start-Sleep -Seconds 3
    Invoke-Item -Path "C:\Admin\G10"
}
function Prep-LGOCShortcuts {
    $wshShell = New-Object -ComObject "WScript.Shell"
    #Create shortcut and name it
    $urlShortcut = $wshShell.CreateShortcut((Join-Path $wshShell.SpecialFolders.Item("AllUsersDesktop")"G10 Login.url"))
    # URL
    $urlShortcut.TargetPath = "http://www.724webs.com/Liftsafe/"
    $urlShortcut.Save()
    Invoke-WebRequest -Uri "http://www.724webs.com/Liftsafe/PDFBuilder/publish.htm" -OutFile "C:\Admin\G10\PDFBuilder.exe"

}
# Delete desktop shortcuts (minus Google Chrome)
function Prep-Clean-Shortcuts {
    Remove-Item -path $env:USERPROFILE\desktop\*.lnk -exclude *Chrome*
    Remove-Item -path c:\users\public\desktop\*.lnk -exclude *Chrome*
}
# Windows Updates
function Prep-WU {
    
    Install-Module PSWindowsUpdate
    Add-WUServiceManager -MicrosoftUpdate
    
    Install-WindowsUpdate -AcceptAll -IgnoreReboot | Out-File "C:\Admin\($env.computername-Get-Date -f yyyy-MM-dd)-MSUpdates.log" -Force
<#
    
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    # Enable updates for other microsoft products
    $ServiceManager = New-Object -ComObject "Microsoft.Update.ServiceManager"
    $ServiceManager.ClientApplicationID = "My App"
    $ServiceManager.AddService2( "7971f918-a847-4430-9279-4a52d1efe18d",7,"")
    Write-Verbose "Installing Windows Update Powershell Module" -Verbose
    # Install NuGet
    Install-PackageProvider NuGet -Force
    Import-PackageProvider NuGet -Force
    # Apparently PSWindowsUpdate module comes from the PSGallery and needs to be "trusted"
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
    # Now actually do the update and reboot If necessary
    Install-Module PSWindowsUpdate
    Set-ExecutionPolicy RemoteSigned -force
    Import-Module PSWindowsUpdate
    #Get-Command -module PSWindowsUpdate
    #Add-WUServiceManager -ServiceID 7971f918-a847-4430-9279-4a52d1efe18d -Confirm:$false
    #Get-WUInstall -MicrosoftUpdate -AcceptAll -AutoReboot
    Write-Verbose "Checking, downloading and installing Windows Updates (No Auto Reboot)" -Verbose
    Get-WindowsUpdate -install -acceptall -IgnoreReboot -IgnoreRebootRequired #-autoreboot
    #Write-Verbose "Installing Windows Updates" -Verbose
    #Install-WindowsUpdate
    Write-Verbose "Installing Windows Updates Complete!" -Verbose#>
}
# RMM Installer
Function Prep-RMM-Install {
    $global:Pulsecheck = Test-path -Path "C:\Program Files\Pulseway"
    If($global:Pulsecheck -eq $true){Write-Host "RMM has already been installed"}
    ElseIf($global:Pulsecheck -eq $false){Write-host "RMM not found, downloading..."
    iwr -uri https://liftsafe-my.sharepoint.com/:u:/g/personal/mbusenbark_liftsafegroup_com/EeOKVTSESmlFmBbOo0QRbVQBJXvtIOoJkOw8opaLEVySOw?e=xbOCKW -OutFile C:\Admin\RMM_Prep.msi}
}
# Create user VPN
Function Prep-VPN {
# Variables
$ProfileName = Read-Host -Prompt 'LGOC VPN'
$DnsSuffix = Read-Host -Prompt 'liftsafeinspections.com'
$ServerAddress = Read-Host -Prompt 'VPN.liftsafegroup.com'
$L2tpPsk = Read-Host -Prompt 'LgocVPN'

# Build client VPN profile
# https://docs.microsoft.com/en-us/windows/client-management/mdm/vpnv2-csp

# Define VPN Profile XML
$ProfileNameEscaped = $ProfileName -replace ' ', '%20'
$ProfileXML =
	'<VPNProfile>
		<RememberCredentials>false</RememberCredentials>
		<DnsSuffix>'+$dnsSuffix+'</DnsSuffix>
		<NativeProfile>
			<Servers>' + $ServerAddress + '</Servers>
			<RoutingPolicyType>SplitTunnel</RoutingPolicyType>
			<NativeProtocolType>l2tp</NativeProtocolType>
			<L2tpPsk>'+$L2tpPsk+'</L2tpPsk>
		</NativeProfile>
'
# Routes to include in the VPN
$ProfileXML += "  <Route><Address>192.168.0.0</Address><PrefixSize>24</PrefixSize><ExclusionRoute>false</ExclusionRoute></Route>`n"
$ProfileXML += "  <Route><Address>192.168.1.0</Address><PrefixSize>24</PrefixSize><ExclusionRoute>false</ExclusionRoute></Route>`n"

$ProfileXML += '</VPNProfile>'

# Convert ProfileXML to Escaped Format
$ProfileXML = $ProfileXML -replace '<', '&lt;'
$ProfileXML = $ProfileXML -replace '>', '&gt;'
$ProfileXML = $ProfileXML -replace '"', '&quot;'

# Define WMI-to-CSP Bridge Properties
$nodeCSPURI = './Vendor/MSFT/VPNv2'
$namespaceName = 'root\cimv2\mdm\dmmap'
$className = 'MDM_VPNv2_01'

# Define WMI Session
$session = New-CimSession

# Create VPN Profile
try
{
	$newInstance = New-Object Microsoft.Management.Infrastructure.CimInstance $className, $namespaceName
	$property = [Microsoft.Management.Infrastructure.CimProperty]::Create('ParentID', "$nodeCSPURI", 'String', 'Key')
	$newInstance.CimInstanceProperties.Add($property)
	$property = [Microsoft.Management.Infrastructure.CimProperty]::Create('InstanceID', "$ProfileNameEscaped", 'String', 'Key')
	$newInstance.CimInstanceProperties.Add($property)
	$property = [Microsoft.Management.Infrastructure.CimProperty]::Create('ProfileXML', "$ProfileXML", 'String', 'Property')
	$newInstance.CimInstanceProperties.Add($property)

	$session.CreateInstance($namespaceName, $newInstance, $options) | Out-Null
	Write-Host "Created '$ProfileName' profile."
}
catch [Exception]{Write-Host "Unable to create $ProfileName profile: $_"
exit
}

# Create a desktop shortcut
$WScriptShell = New-Object -ComObject WScript.Shell
$Shortcut = $WScriptShell.CreateShortcut("$env:Public\Desktop\VPN.lnk")
$Shortcut.TargetPath = "rasphone.exe"
$Shortcut.Save()
}
Function Prep-Kill-Office {
    Write-Verbose "Office365 Removed" -Verbose
    Write-Verbose "Removing TEAMS" -Verbose
    Start-Process MsiExec.exe -ArgumentList '/X{39AF0813-FA7B-4860-ADBE-93B9B214B914} /qn' -Wait
    Start-Process MsiExec.exe -ArgumentList '/X{731F6BAA-A986-45A4-8936-7C3AAAAA760B} /qn' -Wait
}
# Re-Map network drives
function Prep-DriveMaps {
    NET USE * /delete /y
    Write-Host "Existing drive maps removed" -ForegroundColor Yellow
    Start-Sleep -Seconds 1
    NET USE J: "\\LESG-DC-01.liftsafeinspections.com\Data" /PERSISTENT:YES /YES
    #New-PSDrive -Name J -PSProvider FileSystem -root "\\LESG-DC-01.liftsafeinspections.com\Data" -Description "Data" -persist
    Start-Sleep -Seconds 1
    NET USE S: "\\PARC-DC-01.liftsafeinspections.com\Simply" /PERSISTENT:YES /YES
    #New-PSDrive -Name S -PSProvider FileSystem -root "\\PARC-DC-01.liftsafeinspections.com\Simply" -Description "Simply" -persist
    Start-Sleep -Seconds 1
    NET USE X: "\\LESG-DC-01.liftsafeinspections.com\StaffFiles" /PERSISTENT:YES /YES
    #New-PSDrive -Name X -PSProvider FileSystem -root "\\LESG-DC-01.liftsafeinspections.com\StaffFiles" -Description "Staff Files" -persist
    Start-Sleep -Seconds 1
    NET USE Z: "\\LESG-ENG-01.liftsafeinspections.com\Engineering" /PERSISTENT:YES /YES
    #New-PSDrive -Name Z -PSProvider FileSystem -root "\\LESG-ENG-01.liftsafeinspections.com\Engineering" -Description "Engineering" -persist
}
function Show-Menu {
    param (
           [string]$Title = 'Workstation Prep Menu'
    )
     Clear-Host
     Write-Host "================= $Title ================="
     Write-Host "                                          "
     Write-Host "[ENTER]: Domain PC Prep (All - No Reboot) "
     Write-Host "                                          "
     Write-Host "[1]: Full PC Prep                         "
     Write-Host "[2]: User Prep                            "
     Write-Host "[3]: Install Software                     "
     Write-Host "[4]: Install .NET Framework 3.5           "
     Write-Host "[5]: Run Windows Update               "
     Write-Host "[6]: Install System Updater               "
     Write-Host "[7]: Install RMM Agent                    "
     Write-Host "                                          "
     Write-Host "           LGOC specific                  "
     Write-Host "[8]: Install BGInfo                       "
     Write-Host "[9]: Install G10                          "
     Write-Host "[S]: LGOC Shortcuts                       "
     Write-Host "[X]: Re-Map Network Drives                "     
     Write-Host "[V]: Setup User VPN                       "
     Write-Host "[Q]: Press 'Q' to quit.                   "
     Write-Host "                                          "
}
do { Show-Menu
    $input = Read-Host "Please make a selection"
    switch ($input){
    default {
    Clear-Host
    $Prep_Select = Read-Host -Prompt "Workstation(W) or Tablet(T)"
    $global:DivisionName = Read-host -prompt "Enter division name:"
    Prep-PC-Name
    Prep-RMM-Install
    If ($Prep_Select -eq "W"){Prep-PC}
    ElseIf($Prep_Select -eq "T"){Prep-Tablet}
    Prep-User
    Prep-Users-Localadmin
    Prep-Updater
    Prep-Chrome
    Prep-Adobe
    Prep-Office
    Prep-USETHIS
    Prep-DotNET
    Prep-WU
    } '1'<# Full PC Prep #> {
    Clear-Host
    $Prep_Select = Read-Host -Prompt "Is this a Workstation(W), or Tablet?(T)"
    $reply_pladmin = Read-Host -Prompt "Add domain users to local admin?[Y/n]"
    $reply_office = Read-Host -Prompt "Install Office?[Y/n]"
    $reply_adobe = Read-Host -Prompt "Install Adobe?[Y/n]"
    $reply_chrome = Read-Host -Prompt "Install Chrome?[Y/n]"
    $reply_Clean = Read-Host -Prompt "Remove all desktop shortcuts minus Chrome?[Y/n]"
    $reply_Defrag = Read-Host -Prompt "Disable Defrag? (For SSDs only!)[Y/n]"
    $reply_wupdates = Read-Host -Prompt "Install Windows Updates?[Y/n]"
    $reply_sysupdate = Read-Host -Prompt "Install System Updater?[Y/n]"
    Prep-RMM-Install
    If($Prep_Select -contains "W"){Prep-PC}
    ElseIf ($Prep_Select -contains "T"){Prep-Tablet}
    Prep-User
    If ( $reply_pladmin -notmatch "[nN]"){Prep-Users-Localadmin}
    If ( $reply_sysupdate -notmatch "[nN]"){Prep-Updater}
    If ( $reply_chrome -notmatch "[nN]"){Prep-Chrome}
    If ( $reply_adobe -notmatch "[nN]"){Prep-Adobe}
    If ( $reply_office -notmatch "[nN]"){Prep-Office}
    If ( $reply_Clean -notmatch "[nN]"){Prep-Clean-Shortcuts}
    If ( $reply_Defrag -notmatch "[nN]"){Prep-USETHIS}
    Prep-DotNET
    If ( $reply_wupdates -notmatch "[nN]"){Prep-WU}
    #Restart-Computer -Force
    Write-Verbose "Installation Complete, please reboot system." -Verbose
    } '2'<# User Prep #> {
    Clear-Host
    $reply_Clean = Read-Host -Prompt "Remove all desktop shortcuts minus Chrome?[Y/n]"
    Prep-User
    If ( $reply_Clean -notmatch "[nN]"){Prep-Clean-Shortcuts}
    logoff
    Clear-Host
    } '3'<# Install Software #> {
    Clear-Host
    $reply_office = Read-Host -Prompt "Install Office?[Y/n]"
    $reply_adobe = Read-Host -Prompt "Install Adobe?[Y/n]"
    $reply_chrome = Read-Host -Prompt "Install Chrome?[Y/n]"
    $reply_sysupdate = Read-Host -Prompt "Install System Updater?[Y/n]"
    $reply_bginfo = Read-host -Prompt "Install BGinfo?[Y/n] "
    If ( $reply_sysupdate -notmatch "[nN]"){Prep-Updater}
    If ( $reply_chrome -notmatch "[nN]"){Prep-Chrome}
    If ( $reply_adobe -notmatch "[nN]"){Prep-Adobe}
    If ( $reply_office -notmatch "[nN]"){Prep-Office}
    if ( $reply_bginfo -notmatch "[nN]") {Prep-BGInfo}
    Prep-Clean-Shortcuts
    Clear-Host
    } '4'<# Install .NET Framework 3.5 #> {
    Clear-Host
    Prep-DotNET
    Clear-Host
    } '5'<# Run Windows Updates #>  {
    Clear-host
    Prep-WU
    Clear-Host
    } '6'<# Install System Update #> {
    Clear-Host
    Prep-Updater
    Clear-Host
    }'7'<# Install RMM Agent #> {
    Clear-Host
    Prep-RMM-Install
    Clear-Host
    }'8'<# Install BGInfo #>{
    Clear-Host
    Prep-BGInfo
    Clear-Host
    }'9'<# Download G10, and run #> {
    Clear-Host
    Prep-G10
    Clear-Host
    } 'X' <# Re-map network drives #>{
    Clear-Host
    Prep-DriveMaps
    Clear-Host
    } 'V' <# Setup user VPN, and create shorcut #> {
    Clear-Host
    Prep-VPN    
    Clear-Host
} 'q' <#To close window#> {
        return
}
}
pause
}
until ($input -eq 'q')
