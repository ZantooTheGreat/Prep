#############################################
#                                           #
#                                           #
# IF YOU WANT TO MAKE CHANGES TO THIS FILE  #
# PLEASE MAKE A COPY AND EDIT THAT          #
# DONT MAKE CHANGES TO THE ORIGINAL WITHOUT #
# MANAGEMENT CONSENT.                       #
#                                           #
#                                           #
#############################################

$global:startmenu = @"
<LayoutModificationTemplate Version="1" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification" xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" xmlns:taskbar="http://schemas.microsoft.com/Start/2014/TaskbarLayout">
<LayoutOptions StartTileGroupCellWidth="6" />
<DefaultLayoutOverride>
 <StartLayoutCollection>
   <defaultlayout:StartLayout GroupCellWidth="6" xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout">
   </defaultlayout:StartLayout>
 </StartLayoutCollection>
</DefaultLayoutOverride>
<CustomTaskbarLayoutCollection PinListPlacement="Replace">
 <defaultlayout:TaskbarLayout>
   <taskbar:TaskbarPinList>
     <taskbar:DesktopApp DesktopApplicationLinkPath="%APPDATA%\Microsoft\Windows\Start Menu\Programs\System Tools\File Explorer.lnk" />
     <taskbar:DesktopApp DesktopApplicationLinkPath="%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Google Chrome.lnk" />
     <taskbar:DesktopApp DesktopApplicationLinkPath="%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Word.lnk" />
     <taskbar:DesktopApp DesktopApplicationLinkPath="%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Excel.lnk" />
     <taskbar:DesktopApp DesktopApplicationLinkPath="%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Outlook.lnk" />
   </taskbar:TaskbarPinList>
 </defaultlayout:TaskbarLayout>
</CustomTaskbarLayoutCollection>
</LayoutModificationTemplate>
"@

$global:office = @"
<Configuration>
  <Add OfficeClientEdition="32">
    <Product ID="O365BusinessRetail">
      <Language ID="en-us" />
      <ExcludeApp ID="Teams" />
    </Product>
  </Add>  
</Configuration>
"@

$global:DefaultAssociations = @"
<?xml version="1.0" encoding="UTF-8"?>
<DefaultAssociations>
  <Association Identifier=".3mf" ProgId="AppXr0rz9yckydawgnrx5df1t9s57ne60yhn" ApplicationName="Print 3D" />
  <Association Identifier=".arw" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".bmp" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".cr2" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".crw" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".dib" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".epub" ProgId="AppXvepbp3z66accmsd0x877zbbxjctkpr6t" ApplicationName="Microsoft Edge" />
  <Association Identifier=".erf" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".fbx" ProgId="AppXmgw6pxxs62rbgfp9petmdyb4fx7rnd4k" ApplicationName="3D Viewer" />
  <Association Identifier=".gif" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".glb" ProgId="AppXmgw6pxxs62rbgfp9petmdyb4fx7rnd4k" ApplicationName="3D Viewer" />
  <Association Identifier=".gltf" ProgId="AppXmgw6pxxs62rbgfp9petmdyb4fx7rnd4k" ApplicationName="3D Viewer" />
  <Association Identifier=".htm" ProgId="ChromeHTML" ApplicationName="Google Chrome" />
  <Association Identifier=".html" ProgId="ChromeHTML" ApplicationName="Google Chrome" />
  <Association Identifier=".jfif" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".jpe" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".jpeg" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".jpg" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".jxr" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".kdc" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".MP2" ProgId="WMP11.AssocFile.MP3" ApplicationName="Windows Media Player" />
  <Association Identifier=".mrw" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".nef" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".nrw" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".obj" ProgId="AppXmgw6pxxs62rbgfp9petmdyb4fx7rnd4k" ApplicationName="3D Viewer" />
  <Association Identifier=".orf" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".pdf" ProgId="AcroExch.Document.DC" ApplicationName="Adobe Acrobat Reader DC" />
  <Association Identifier=".pef" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".ply" ProgId="AppXmgw6pxxs62rbgfp9petmdyb4fx7rnd4k" ApplicationName="3D Viewer" />
  <Association Identifier=".png" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".raf" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".raw" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".rw2" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".rwl" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".sr2" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".srw" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".stl" ProgId="AppXr0rz9yckydawgnrx5df1t9s57ne60yhn" ApplicationName="Print 3D" />
  <Association Identifier=".tif" ProgId="PhotoViewer.FileAssoc.Tiff" ApplicationName="Windows Photo Viewer" />
  <Association Identifier=".tiff" ProgId="PhotoViewer.FileAssoc.Tiff" ApplicationName="Windows Photo Viewer" />
  <Association Identifier=".txt" ProgId="txtfile" ApplicationName="Notepad" />
  <Association Identifier=".url" ProgId="IE.AssocFile.URL" ApplicationName="Internet Browser" />
  <Association Identifier=".wdp" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".website" ProgId="IE.AssocFile.WEBSITE" ApplicationName="Internet Explorer" />
  <Association Identifier="bingmaps" ProgId="AppXp9gkwccvk6fa6yyfq3tmsk8ws2nprk1p" ApplicationName="Maps" />
  <Association Identifier="http" ProgId="ChromeHTML" ApplicationName="Google Chrome" />
  <Association Identifier="https" ProgId="ChromeHTML" ApplicationName="Google Chrome" />
  <Association Identifier="mailto" ProgId="Outlook.URL.mailto.15" ApplicationName="Outlook" />
</DefaultAssociations>
"@

$global:Remove = @"
<Configuration>
<Remove All="TRUE"/>
<Display Level="None" AcceptEULA="TRUE"/>
</Configuration>
"@

# Rename PC
function Prep-PC-Name ($PCName){Rename-Computer -NewName "$PCName"}
# Create User
function Prep-PC-User ($UserName, $UserPass){
    Write-Verbose "Creating new local users" -Verbose
    Start-Sleep -Seconds 10
    Write-Verbose "Creating User $UserName" -Verbose
    New-LocalUser -Name "$UserName" -Password $UserPass -PasswordNeverExpires -UserMayNotChangePassword
    Add-LocalGroupMember -Group "Administrators" -Member "$UserName"
}
# PC Prep
function Prep-PC {
    # Popup
    #$shell = new-object -comobject "WScript.Shell"
    #$choice = $shell.popup("Insert question here",0,"Popup window title",4+32)

    # Create onsys directory and hide it from muggles
    Write-Host "Creating directories..." -ForegroundColor Yellow
    New-Item -Path "C:\onsys" -ItemType Directory

    # Create XML files for various settings
    New-Item -Path C:\startlayout.xml -ItemType File
    Add-Content -Path C:\startlayout.xml $global:startmenu

    New-Item -Path C:\DefaultAssociations.xml -ItemType File
    Add-Content -Path C:\DefaultAssociations.xml $global:DefaultAssociations

    New-Item -Path C:\Remove.xml -ItemType File
    Add-Content -Path C:\Remove.xml $global:RemoveXML

    New-Item -Path C:\Setup.xml -ItemType File
    Add-Content -Path C:\Setup.xml $global:office
    attrib +s +h "C:\onsys"

    # Install WinGet
    # Check if WinGet is installed
        If (Test-Path ~\AppData\Local\Microsoft\WindowsApps\winget.exe){'Winget Already Installed'}
    # Installing winget from the Microsoft Store
        Write-Host "Installing Winget... Please Wait"
        Start-Process "ms-appinstaller:?source=https://aka.ms/getwinget"
        $nid = (Get-Process AppInstaller).Id
        Wait-Process -Id $nid
        Write-Host Winget Installed
        Write-Host "Winget Installed - Ready for Next Task"
    Start-Sleep -Seconds 2

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
    # To disable selective suspend on plugged in laptops/desktops:
    Powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0
    Powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0
    # To set power button action on laptops/desktops (0=Do nothing - 1=Sleep - 2=Hibernate - 3=Shut down - 4=Turn off the display):
    powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 4f971e89-eebd-4455-a8de-9e59040e7347 7648efa3-dd9c-4e3e-b566-50f929386280 2
    powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 4f971e89-eebd-4455-a8de-9e59040e7347 7648efa3-dd9c-4e3e-b566-50f929386280 2
    # To set lid close action on laptops (0=Do nothing - 1=Sleep - 2=Hibernate - 3=Shut down):
    powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 0
    powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 0

    # Disable IPv6
    Get-NetAdapter | ForEach-Object {Disable-NetAdapterBinding -InterfaceAlias $_.Name -ComponentID ms_tcpip6}
    
    # Disable automatic setup of network devices
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private")){
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Force | Out-Null}
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name "AutoSetup" -Type DWord -Value 0

    # Remove TEAMS system wide installer
        Start-Process MsiExec.exe -ArgumentList '/X{39AF0813-FA7B-4860-ADBE-93B9B214B914} /qn' -Wait
        Start-Process MsiExec.exe -ArgumentList '/X{731F6BAA-A986-45A4-8936-7C3AAAAA760B} /qn' -Wait


    $StartLayoutPath = Test-Path -Path ".\startlayout.xml"
    If($StartLayoutPath -eq $true){Import-Startlayout -layoutpath .\startlayout.xml -mountpath $Env:SYSTEMDRIVE\}
    ElseIf($StartLayoutPath -eq $false){Import-StartLayout -LayoutPath C:\startlayout.xml -MountPath $Env:SYSTEMDRIVE}
}
function Prep-Laptop {
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
    # Disable IPv6
    Get-NetAdapter | ForEach-Object {Disable-NetAdapterBinding -InterfaceAlias $_.Name -ComponentID ms_tcpip6}
    
    # Disable automatic setup of network devices
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Force | Out-Null}
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name "AutoSetup" -Type DWord -Value 0

    # Remove TEAMS system wide installer
    Start-Process MsiExec.exe -ArgumentList '/X{39AF0813-FA7B-4860-ADBE-93B9B214B914} /qn' -Wait
    Start-Process MsiExec.exe -ArgumentList '/X{731F6BAA-A986-45A4-8936-7C3AAAAA760B} /qn' -Wait

    # Clear Start Menu for new users
    import-startlayout -layoutpath .\startlayout.xml -mountpath $Env:SYSTEMDRIVE\
}

# User Prep
function Prep-Users-Localadmin {
    Add-LocalGroupMember -Group Administrators -Member "$env:USERDNSDOMAIN\Domain Users"
}
function Prep-User {

    #Get-AppxPackage * | Remove-AppxPackage
    Write-Verbose "Removed windows apps"

    Get-AppXPackage -allusers Microsoft.Microsoft3DViewer | Remove-AppxPackage
    Get-AppXPackage -allusers Microsoft.WindowsAlarms | Remove-AppxPackage
    Get-AppXPackage -allusers Microsoft.WindowsFeedbackhub | Remove-AppxPackage
    Get-AppXPackage -allusers Microsoft.Office.OneNote | Remove-AppxPackage
    Get-AppXPackage -allusers Microsoft.OfficeHub | Remove-AppxPackage
    Get-AppXPackage -allusers Microsoft.GetHelp | Remove-AppxPackage
    Get-AppXPackage -allusers Microsoft.GetStarted | Remove-AppxPackage
    Get-AppXPackage -allusers Microsoft.GetHelp | Remove-AppxPackage
    Get-AppXPackage -allusers Microsoft.MixedReality.Portal | Remove-AppxPackage
    Get-AppXPackage -allusers Microsoft.WindowsMaps | Remove-AppxPackage
    Get-AppXPackage -allusers Microsoft.SkypeApp | Remove-AppxPackage
    Get-AppXPackage -allusers Microsoft.People | Remove-AppxPackage
    Get-AppXPackage -allusers Microsoft.BingWeather | Remove-AppxPackage

    # Prevent reinstall of default apps with new user
    Get-AppXProvisionedPackage -Online | Remove-AppxProvisionedPackage -Online
    
    Clear-Host
    # Start Menu: Disable Bing Search Results
    Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search -Name BingSearchEnabled -Type DWord -Value 0
    # Change Explorer home screen back to "This PC"
    Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -Type DWord -Value 1
    #Write-Verbose "Changed windows explorer from Quick Access to This PC" -Verbose
    # Hide Cortana Search
    Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search -Name SearchboxTaskbarMode -Type DWord -Value 0
    # Remove TaskView button from taskbar
    Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ShowTaskViewButton -Type DWord -Value 0
    # Remove People button from taskbar
    Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People -Name PeopleBand -Type DWord -Value 0
    # Remove Suggestions from Start Menu
    Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SystemPaneSuggestionsEnabled -Type DWord -Value 0
    # Disable Silent Install Store Apps
    Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SilentInstalledAppsEnabled -Type DWord -Value 0
    # Disable Subscribed Content Apps
    Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-338388Enabled -Type DWord -Value 0
    # Remove Meet Now Button
    Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name HideSCAMeetNow -Value 1
    # Remove News/Weather Icon from taskbar
    Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds -Name ShellFeedsTaskbarViewMode -Value 2

    # Set Time Zone
    Set-TimeZone -Name "Eastern Standard Time"
    # Set the locale for the region and language
    #Get-WinSystemLocale
    #Set-WinSystemLocale en-CA
    # Set the locale for the region and language
    Set-Culture -CultureInfo en-CA
    # Set the region options to the current locale
    #Set-WinCultureFromLanguageListOptOut 1
    # Set the region options to "Match current language settings"
    #Set-WinCultureFromLanguageListOptOut 0

    # Disable Action Center
    #Write-Verbose "Disabling Action Center..." -Verbose
    If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
        New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null
    }
    Set-ItemProperty -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name DisableNotIficationCenter -Type DWord -Value 1
    Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotIfications -Name ToastEnabled -Type DWord -Value 0
    # Control Panel to classic icons
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ForceClassicControlPanel" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -Type DWord -Value 0
    Write-Verbose "Control Panel Icons Set" -Verbose
    Write-Verbose "User Prep Complete" -Verbose}

# Install .NET Framework
function Prep-DotNET {
    Write-Verbose "Install .NET Framework" -Verbose
    Add-WindowsCapability -Online -Name NetFx3~~~~
    Clear-Host
    Write-Verbose ".NET Framework Install Complete" -Verbose
    Clear-Host
}
###############################
# Application Installs
###############################
# Examples
#Start-Process msiexec -ArgumentList "/i $PSScriptRoot\whatever.msi /qn"
#Start-Process -FilePath $(Join-Path -Path $PSScriptRoot -ChildPath "Firefox_Setup_49.0.1.exe") -ArgumentList '-ms' -Wait
#Start-Process -WorkingDirectory '.\Firefox_Setup_49.0.1.exe -ArgumentList' '-ms' -Wait
#Start-Process "msiexec.exe" -ArgumentList $MSIArguments -Wait -NoNewWindow 

# Install Chrome
function Prep-Chrome{
    $ChromeCheck = Test-Path -Path ".\ChromeStandaloneSetup64.exe"
    If($ChromeCheck -eq $true){Start-Process ".\ChromeStandaloneSetup64.exe" -Wait
        Write-Verbose "Chrome Installed" -Verbose}
    ElseIf($ChromeCheck -eq $false) {Write-Verbose "Local installer not found, downloading..." -Verbose
        winget install -e --id Google.Chrome}
}
# Install Adobe Reader
function Prep-Adobe{
    $AdobeReaderCheck = Test-Path -Path ".\AcroRdrDC_en_US"
    If($AdobeReaderCheck -eq $true){Start-Process ".\AcroRdrDC_en_US" "/sPB /rs" -wait
        Write-Verbose "Adobe Reader Installed" -Verbose}
    ElseIf($AdobeReaderCheck -eq $false){Write-Verbose "Local installer not found, downloading..." -Verbose
        winget install -e --id Adobe.Acrobat.Reader.64-bit}
}
# Install Dell Command Update
function Prep-DCU-Install{
    $DellCommandCheck = Test-Path -Path ".\Dell-Command-Update"     
    If($DellCommandCheck -eq $true){    Start-Process ".\Dell-Command-Update" "/s" -Wait
        Start-Process "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe" "/configure -userConsent=disable -scheduleManual" -Wait
        Write-Verbose "DCU Installed" -Verbose}
    ElseIf($DellCommandCheck -eq $true) {Write-Verbose "Local installer not found, downloading..." -Verbose
        winget install -e --id Dell.CommandUpdate -Wait
        Start-Process "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe" "/configure -userConsent=disable -scheduleManual" -Wait}
}
# Run Dell Command Update
Function Prep-DCU-Run{
    Start-Process "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe" "/scan" -Wait
    Start-Process "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe" "/applyUpdates" -Wait
    Write-Verbose "Updates Installed" -Verbose
}
# Install Office365 Business Preload
function Prep-Office{
    $OfficeInstaller = Test-path ".\setup.exe"
    If($OfficeInstaller -eq $true){
        Write-Verbose "Removing existing Office365 Installs" -Verbose
        Start-Process ".\setup.exe" "/configure .\remove.xml" -Wait
        Start-Sleep 30
        Start-Process ".\setup.exe" "/configure .\setup.xml" -Wait
        Write-Verbose "Office365 Installed" -Verbose
        Start-Process MsiExec.exe -ArgumentList '/X{39AF0813-FA7B-4860-ADBE-93B9B214B914} /qn' -Wait
        Start-Process MsiExec.exe -ArgumentList '/X{731F6BAA-A986-45A4-8936-7C3AAAAA760B} /qn' -Wait
        Write-Verbose "Office365 TEAMS Removed" -Verbose}
    ElseIf($OfficeInstaller -eq $false){Write-host "O365 Offline installer not found, attempting download"
            winget install -e --id Microsoft.Office}
}
# Update Office365 Business Preload
function Prep-O365-Update{
    Remove-Item -path .\Office\* -recurse -force
    sleep 5
    Start-Process ".\setup.exe" "/download .\setup.xml" -Wait
    Write-Verbose "Office365 Preload Folder Updated" -Verbose
}
# Import file associations
function Prep-File-Assoc{
    # dism /online /Import-DefaultAppAssociations:"$PSScriptRoot\DefaultAssociations.xml"
    $DefaultApps = Test-Path -Path ".\DefaultAssociations.xml"
    If($DefaultApps -eq $true){dism /online /Import-DefaultAppAssociations:".\DefaultAssociations.xml"}
    ElseIf($DefaultApps -eq $false){dism /online /Import-DefaultAppAssociations:"C:\DefaultAssociations.xml"}
}
# Install Intronis and ask for reboot
function Prep-Intronis{
    # Start-Process "$PSScriptRoot\ConsysManagedBackup-Setup.exe" "/Silent"
    Start-Process ".\ConsysManagedBackup-Setup.exe" "/Silent"
    sleep 120
    Write-Verbose "Intronis Installed" -Verbose
    # Install Intronis and auto reboot
    #Start-Process ".\ConsysManagedBackup-Setup.exe" "/Silent /SuppressMsgBoxes" -wait
    #Write-Verbose "Intronis Installed" -Verbose
}
# Delete desktop shortcuts (minus Google Chrome)
function Prep-Clean-Shortcuts {
    Remove-Item -path $env:USERPROFILE\desktop\*.lnk -exclude *Chrome*
    Remove-Item -path c:\users\public\desktop\*.lnk -exclude *Chrome*
}
# Windows Updates
function Prep-WU {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    # Enable updates for other microsoft products
    $ServiceManager = New-Object -ComObject "Microsoft.Update.ServiceManager"
    $ServiceManager.ClientApplicationID = "My App"
    $ServiceManager.AddService2( "7971f918-a847-4430-9279-4a52d1efe18d",7,"")
    Write-Verbose "Installing Windows Update Powershell Module" -Verbose
    # Install NuGet
    Install-PackageProvider NuGet -Force
    Import-PackageProvider NuGet -Force
    # Apparently PSWindowsUpdate module comes from the PSGallery and needs to be trusted
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
    # Now actually do the update and reboot If necessary
    Install-Module PSWindowsUpdate
    Set-ExecutionPolicy RemoteSigned -force
    Import-Module PSWindowsUpdate
    #Get-Command -module PSWindowsUpdate
    #Add-WUServiceManager -ServiceID 7971f918-a847-4430-9279-4a52d1efe18d -Confirm:$false
    #Get-WUInstall -MicrosoftUpdate -AcceptAll -AutoReboot
    Write-Verbose "Checking for, downloading and installing Windows Updates (No Auto Reboot)" -Verbose
    Get-WindowsUpdate -install -acceptall -IgnoreReboot -IgnoreRebootRequired #-autoreboot
    #Write-Verbose "Installing Windows Updates" -Verbose
    #Install-WindowsUpdate
    Write-Verbose "Installing Windows Updates Complete!" -Verbose
}
# Copy Files
function Prep-Copy {
    New-Item -Path "C:\Temp\" -ItemType Directory
    Write-Verbose "Copy of Workstation Prep files to c:\temp" -Verbose
    Copy-Item -Force -Path .\..\Workstation_Prep -Destination c:\temp\ -Recurse
    # Copy-Item -Force -Path $PSScriptRoot\..\Workstations_Prep -Destination c:\temp\ -Recurse
    # Copy-Item -Force -Path '$PSScriptRoot\..\Menu - Shortcut.lnk' -Destination c:\temp\
    # Copy-Item -Force -Path '$PSScriptRoot\..\Menu - C Drive Shortcut.lnk' -Destination c:\temp\
    # Copy-Item -Force -Path '.\..\Menu - C Drive Shortcut.lnk' -Destination c:\temp\
}
function Prep-BGInfo {
    #New-Item -Path "C:\BGInfo\" -ItemType Directory
    Copy-Item -Force -Path .\..\Workstation_Prep\BGInfo -Destination c:\ -Recurse
    #Copy-Item .\..\Workstation_Prep\BGInfo\bginfo64.exe -Destination "C:\BGInfo\"
    #Copy-Item .\..\Workstation_Prep\BGInfo\HostName.bgi -Destination "C:\BGInfo\"
    Copy-Item c:\BGInfo\BGInfo.lnk -Destination "C:\programdata\Microsoft\Windows\Start Menu\Programs\StartUp"
}
Function Prep-MAV-Preload {
    New-Item -Path "C:\ProgramData\ManagedAntivirus" -ItemType directory
    New-Item -Path "C:\ProgramData\ManagedAntivirus\Downloads" -ItemType directory
    Copy-Item -Force -Path .\..\Workstation_Prep\AV\*.* -Destination C:\ProgramData\ManagedAntivirus\Downloads -Recurse
}
Function Prep-Kill-Defrag {
    schtasks /Change /DISABLE /TN "\Microsoft\Windows\Defrag\ScheduledDefrag"
}
Function Prep-Kill-Office {
    Write-Verbose "Removing existing Office365 Installs" -Verbose
    Start-Process ".\setup.exe" "/configure .\remove.xml" -Wait
    Write-Verbose "Office365 Removed" -Verbose
    Write-Verbose "Removing TEAMS" -Verbose
    Start-Process MsiExec.exe -ArgumentList '/X{39AF0813-FA7B-4860-ADBE-93B9B214B914} /qn' -Wait
    Start-Process MsiExec.exe -ArgumentList '/X{731F6BAA-A986-45A4-8936-7C3AAAAA760B} /qn' -Wait
    Write-Verbose "Office365 TEAMS Removed" -Verbose
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
     Write-Host "[1]: Full PC Prep (Optional Selections)   "
     Write-Host "[2]: User Prep (Ex. Dental)               "
     Write-Host "[3]: Install Software                     "
     Write-Host "[4]: Install .NET Framework 3.5           "
     Write-Host "[5]: Install Windows Updates              "
     Write-Host "[6]: Install Dell Command Update          "
     Write-Host "[7]: Run Dell Command Update              "
     Write-Host "[8]: Update Office 365 Offline Installer  "
     Write-Host "[9]: Pre-Load Managed AV                  "
     Write-Host "[10]: Add Domain Users to local admin     "
     Write-Host "[11]: Add BGInfo (Hostname on desktop)    "
     Write-Host "[12]: Disable Defrag (For SSDs)           "
     Write-Host "[13]: Remove All Office Installs          "
     Write-Host "                                          "
     Write-Host "[C]: Copy Prep Files to c:\temp\          "
     Write-Host "[Q]: Press 'Q' to quit.                   "
     Write-Host "                                          "}
do { Show-Menu
    $input = Read-Host "Please make a selection"
    switch ($input){
    default {
        Clear-Host
        $reply_laptop = Read-Host -Prompt "Is this a laptop?[y/N]"
        Write-Verbose "Enter New PC Name:" -Verbose
        $PCName = Read-Host -AsString
        Prep-PC-Name $PCName
        #Write-Verbose "Enter New Username:" -Verbose
        #$UserName = Read-Host -AsString
        #Write-Verbose "Enter New User Password:" -Verbose
        #$UserPassPlain = Read-Host -AsString
        #$UserPass = ConvertTo-SecureString -String $UserPassPlain -AsPlainText -Force
        #Prep-PC-User $UserName $UserPass
        Prep-MAV-Preload
        If ( $reply_laptop -notmatch "[yY]"){Prep-PC}
        Else{Prep-Laptop}
        Prep-User
        Prep-Users-Localadmin
        Prep-DCU-Install
        Prep-Chrome
        Prep-Adobe
        Prep-Office
        Prep-File-Assoc
        Prep-Kill-Defrag                
        Prep-Intronis
        #Prep-Clean-Shortcuts
        Prep-DotNET
        Prep-DCU-Run
        Prep-WU
        #Restart-Computer -Force
    } '1'<# Full PC Prep #> {
        Clear-Host
        $reply_laptop = Read-Host -Prompt "Is this a laptop?[y/N]"
        $reply_pcrename = Read-Host -Prompt "Re-name PC?[Y/n]"
        $reply_newuser = Read-Host -Prompt "Create new user?[Y/n]"
        $reply_pladmin = Read-Host -Prompt "Add domain users to local admin?[Y/n]"
        $reply_office = Read-Host -Prompt "Install Office?[Y/n]"
        $reply_adobe = Read-Host -Prompt "Install Adobe?[Y/n]"
        $reply_chrome = Read-Host -Prompt "Install Chrome?[Y/n]"
        $reply_intronis = Read-Host -Prompt "Install Intronis?[Y/n]"
        $reply_Clean = Read-Host -Prompt "Remove all desktop shortcuts minus Chrome?[Y/n]"
        $reply_Defrag = Read-Host -Prompt "Disable Defrag? (For SSDs only!)[Y/n]"
        $reply_wupdates = Read-Host -Prompt "Install Windows Updates?[Y/n]"
        $reply_dcu = Read-Host -Prompt "Install Dell Command Update?[Y/n]"
        $reply_rundcu = Read-Host -Prompt "Run Dell Command Update?[Y/n]"
        If ( $reply_pcrename -notmatch "[nN]"){Write-Verbose "Enter New PC Name:" -Verbose
        $PCName = Read-Host -AsString
        Prep-PC-Name $PCName}
        If ( $reply_newuser -notmatch "[nN]"){ 
            Write-Verbose "Enter New Username:" -Verbose
            $UserName = Read-Host -AsString
            Write-Verbose "Enter New User Password:" -Verbose
            $UserPassPlain = Read-Host -AsString
            $UserPass = ConvertTo-SecureString -String $UserPassPlain -AsPlainText -Force
            Prep-PC-User $UserName $UserPass}
        Prep-MAV-Preload
        If ( $reply_laptop -notmatch "[yY]"){Prep-PC}
        Else {Prep-Laptop}
        Prep-User
        If ( $reply_pladmin -notmatch "[nN]"){Prep-Users-Localadmin}
        If ( $reply_dcu -notmatch "[nN]"){Prep-DCU-Install}
        If ( $reply_chrome -notmatch "[nN]"){Prep-Chrome}
        If ( $reply_adobe -notmatch "[nN]"){Prep-Adobe}
        If ( $reply_office -notmatch "[nN]"){Prep-Office}
        Prep-File-Assoc
        If ( $reply_intronis -notmatch "[nN]"){Prep-Intronis}
        If ( $reply_Clean -notmatch "[nN]"){Prep-Clean-Shortcuts}
        If ( $reply_Defrag -notmatch "[nN]"){Prep-Kill-Defrag}
        Prep-DotNET
        If ( $reply_rundcu -notmatch "[nN]"){Prep-DCU-Run}
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
        $reply_intronis = Read-Host -Prompt "Install Intronis?[Y/n]"
        $reply_dcu = Read-Host -Prompt "Install Dell Command Update?[Y/n]"
        If ( $reply_dcu -notmatch "[nN]"){Prep-DCU-Install}
        If ( $reply_chrome -notmatch "[nN]"){Prep-Chrome}
        If ( $reply_adobe -notmatch "[nN]"){Prep-Adobe}
        If ( $reply_office -notmatch "[nN]"){Prep-Office}
        Prep-File-Assoc
        If ( $reply_intronis -notmatch "[nN]"){Prep-Intronis}
        Prep-Clean-Shortcuts
        Clear-Host
    } '4'<# Install .NET Framework 3.5 #> {
        Clear-Host
        Prep-DotNET
        Clear-Host
    } '5'<# Install Windows Updates #> {
        Clear-Host
        Prep-WU
        Clear-Host
        #Restart-Computer -Force
    } '6'<# Install Dell Command Update #> {
        Clear-Host
        Prep-DCU-Install
        Clear-Host
        #Restart-Computer -Force
    } '7'<# Run Dell Command Update #> {
        Clear-Host
        Prep-DCU-Run
        Clear-Host
        #Restart-Computer -Force
    } '8'<# Update Office 365 Offline Installer #> {
        Clear-Host
        Prep-O365-Update
        Clear-Host
    } '9'<# Pre-Load Managed AV #> {
        Clear-Host
        Prep-MAV-Preload
        Clear-Host
    } '10'<# Add Domain Users to local admin #> {
        Clear-Host
        Prep-Users-Localadmin
        Clear-Host
    } '11'<# Add BGInfo (Hostname on desktop) #> {
        Clear-Host
        Prep-BGInfo
        Clear-Host
    } '12'<# Disable Defrag (For SSDs) #> {
        Clear-Host
        Prep-Kill-Defrag                
        Clear-Host
    } '13'<# Remove All Office Installs #> {
        Clear-Host
        Prep-Kill-Office
        Clear-Host
    } 'c' <# Copy Prep Files #> {
        Clear-Host
        Prep-Copy
        Clear-Host
    } 'q' {
        return
}
}
pause
}
until ($input -eq 'q')
