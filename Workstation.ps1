#############################################
#                                           #
# IF YOU WANT TO MAKE CHANGES TO THIS FILE  #
# PLEASE MAKE A COPY AND EDIT THAT          #
# DONT MAKE CHANGES TO THE ORIGINAL WITHOUT #
# MANAGEMENT CONSENT.                       #
#                                           #
#############################################

# Rename PC
function Prep-PC-Name {
    #PC Serial
        $global:PCNameSuffix = (get-ciminstance -ClassName Win32_ComputerSystemProduct | Select-Object -ExpandProperty IdentifyingNumber)
    #PC Name prefix prompt
        $global:DivisionName = Read-host -prompt "Enter division name"
        $global:FullPCName = "$global:DivisionName-$global:PCNameSuffix"
        Rename-Computer -NewName "$global:FullPCName"
        Write-host "Computer name changed to: $global:FullPCName"}
# PC Prep
function Prep-PC {
    # Create Admin directory and hide it from muggles
            Write-Host "Creating directories..." -ForegroundColor Yellow
            New-Item -Path "C:\Admin" -ItemType Directory
            attrib +s +h "C:\Admin"
            Copy-Item -Force "J:\Approved Installers\BGInfo\Settings_Alt.bgi" -Destination "C:\Admin\"
            cd C:\Admin
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
    # # # Power settings 
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
function Prep-Pulseway {
    # Pulseway Prep
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name ComputerName -Value "LGOC - $global:PCNameSuffix ()"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name GroupName    -Value "Liftsafe Group - Systems - Prep"
    # Custom Pulseway Settings
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name UseCustomServer -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name EnableSystemTrayIcon -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name MonitorAD -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name MonitorIIS -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name EnableLock -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name EnableLogin -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name EnableLogoff -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name EnableRestart -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name EnableShutDown -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name EnablePowerOff -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name EnableSuspend -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name EnableHibernate -Value "0"
    # Force commands
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name ForceLogoff -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name ForceRestart -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name ForceShutDown -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name ForcePowerOff -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name ForceSuspend -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name ForceHibernate -Value "1"
        
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name ExcludeKnownSystemProcesses -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name EventsPerPage -Value "50"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name UnitOfMeasure -Value "1"
    # Notifications
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SendNotificationWhenOffline -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SendNotificationWhenIPChanged -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SendNotificationOnStartUp -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SendNotificationOnShutDown -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SendNotificationOnSuspend -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SendNotificationOnWakeUp -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SendNotificationOnLowBattery -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SendNotificationOnServiceStop -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name NotificationOnServiceStopMinutes -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SendNotificationOnLowMemory -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name LowMemoryPercentage -Value "10"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name LowMemoryTimeInterval -Value "10"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SendNotificationOnCPUUsage -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name CPUUsagePercentage -Value "90"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name CPUUsageTimeInterval -Value "5"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SendNotificationOnBelowCPUUsage -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name BelowCPUUsagePercentage -Value "10"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name BelowCPUUsageTimeInterval -Value "5"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SendNotificationOnLowHDDSpace -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SendNotificationOnUserLogin -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SendNotificationOnUserLogout -Value "0"
    # Connectivity
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name MonitorPing -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name PingServer -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SendNotificationOnSSLCertificateExpiration -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name NotificationOnSSLCertificateExpirationDays -Value "7"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SendNotificationOnWebSiteNotAvailable -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name NotificationOnWebSiteNotAvailableMinutes -Value "5"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SendNotificationOnPortNotAccessible -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name PortInterval -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name AutoUpdate -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name IncreaseProcessPriority -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name UseHighPriority -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name ErrorReporting -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name PluginDebugLog -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name KeepHardwareHistory -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SendNotificationOnHardware -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisableHardDiskMonitoring -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SendNotificationOnEventLogFilters -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SendNotificationOnPingResponses -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SendNotificationOnWindowsUpdates -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SendNotificationOnWindowsUpdatesIgnoreImportant -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SendNotificationOnApplicationInstall -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SendNotificationOnApplicationUninstall -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SendNotificationOnUSBDeviceInsert -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SendNotificationOnUSBDeviceRemove -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SendNotificationOnSMARTWarning -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SendNotificationOnAntivirusDisabled -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SendNotificationOnAntivirusOutOfDate -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SendNotificationOnFirewallDisabled -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name OptimizeMemory -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name WakeOnWANOverInternet -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name WakeOnWANOverInternetPort -Value "9"
    # AD Configs
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SendNotificationOnADUserLocked -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name ADRequireChangePasswordOnReset -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name KeepPerformanceCountersHistory -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SendNotificationOnPerformanceCounters -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SendNotificationOnProcesses -Value "0"
    # SQL and SNMP Settings
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name MonitorSqlServer -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SqlServerServerName -Value "7R"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SqlServerInstanceName -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SqlServerUseWindowsAuthentication -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SqlServerUsername -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SqlServerUsernameCtrl -Value "C5"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SqlServerPassword -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SqlServerPasswordCtrl -Value "63"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SqlServerShowSystemDatabases -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SendNotificationOnSqlServerLongQueryExecutionTime -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SendNotificationOnSqlServerHighDatabaseSize -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SqlServerLongQueryExecutionTime -Value "30"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SqlServerHighDatabaseSize -Value "75"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SendNotificationOnSqlQueryFilter -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SendFileWatchNotifications -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name MonitorSNMP -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SendSNMPNotifications -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name MonitorWindowsServerBackup -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SendNotificationOnBackupFailure -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SendNotificationOnBackupSuccess -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name MonitorWSUS -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name WSUSIncludeDownstreamComputers -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SendNotificationOnWSUSSynchronization -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name PrioritySendNotificationOnWSUSSynchronization -Value "1"
    # File Browser Settings
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name FileBrowsingEnabled -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name FileBrowsingIncludeHiddenFolders -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name FileBrowsingIncludeHiddenFiles -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name FilePreviewEnabled -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name EmailFilesEnabled -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name ZipEmailedFile -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name FileDeleteEnabled -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name EmailServerAddress -Value "smtp.office365.com"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name EmailServerPort -Value "587"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name EmailUseSSL -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name EmailAccountUsername -Value "helpdesk@liftsafeinspections.com"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name EmailAccountPassword -Value "q419Ox8udVSzSq"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name EmailAccountPasswordCtrl -Value "30"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name EmailFromEmailAddress -Value "helpdesk@liftsafeinspections.com"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name EmailFromName -Value "Liftsafe Group Support"
    # RDP, PS, and Display Settings
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name EnableRemoteDesktop -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name RemoteDesktopAskUserPermission -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name RemoteDesktopUserPermissionDefaultAllow -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name EnableLiveScreen -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name EnableWebCam -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name EnableUserChat -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name EnableUserSupportRequest -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name RemoteControlAllowDisable -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisableUserSessionTask -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name PowerShellUserImpersonation -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name PowerShellUserImpersonationUsername -Value "administrator"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name PowerShellUserImpersonationPassword -Value "LgocAdmin2430!"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name PowerShellUserImpersonationPasswordCtrl -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name PowerShellUserImpersonationDomain -Value "LIFTSAFEINSPECTIONS"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisplayCPU -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisplayMemory -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisplayIPAddress -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisplayPing -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisplayAssets -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisplayNotes -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisplayHardwareInformation -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisplayNetwork -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisplayPorts -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisplayPingResponses -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisplayHardDisks -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisplayPrinters -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisplayServices -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisplayProcesses -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisplayCertificates -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisplayWebSites -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisplayScheduledTasks -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisplayPerformanceCounters -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisplayUsers -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisplayUserChats -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisplayLiveScreen -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisplayWebCam -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisplayEventLog -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisplayTerminal -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisplayPowerShell -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisplayScripts -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisplayRemoteDesktop -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisplayActiveDirectory -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisplayExchange -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisplayHyperV -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisplayIIS -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisplaySCOM -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisplaySqlServer -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisplayWindowsServerBackup -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisplayVMware -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisplayXenServer -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisplayAmazon -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisplayAzure -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisplaySNMP -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisplayWSUS -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisplayWindowsUpdates -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisplaySecurity -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisplayInstalledApplications -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisplayPCMonitorVersion -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisplayLock -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisplayLogoff -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisplayRestart -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisplayShutDown -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisplayPowerOff -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisplaySuspend -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisplayHibernate -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisplayWakeUp -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name DisplayMaintenanceMode -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name EnableSyslog -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SyslogServer -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SyslogPort -Value "14"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name EnableSyslogReport -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SyslogReportIntervalMinutes -Value "60"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name EnableSyslogProcessorReport -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name EnableSyslogMemoryReport -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name EnableSyslogDiskReport -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name EnableSyslogUsersReport -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name EnableSyslogNetworkReport -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name EnableSyslogPingReport -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name EnableSyslogPingResponseReport -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SyslogReportUseCustomServer -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SyslogReportCustomServer -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name SyslogReportCustomServerPort -Value "14"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name KAVLogLevel -Value "4"
    # Priority Notifications
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name PrioritySendNotificationOnStartUp -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name PrioritySendNotificationOnShutDown -Value "2"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name PrioritySendNotificationOnSuspend -Value "2"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name PrioritySendNotificationOnWakeUp -Value "2"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name PrioritySendNotificationOnLowBattery -Value "2"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name PrioritySendNotificationOnUserLogin -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name PrioritySendNotificationOnUserLogout -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name PrioritySendNotificationOnWindowsUpdates -Value "4"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name PrioritySendNotificationOnApplicationInstall -Value "2"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name PrioritySendNotificationOnApplicationUninstall -Value "2"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name PrioritySendNotificationOnUSBDeviceInsert -Value "2"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name PrioritySendNotificationOnUSBDeviceRemove -Value "2"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name PrioritySendNotificationOnSMARTWarning -Value "3"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name PrioritySendNotificationOnFirewallDisabled -Value "2"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name PrioritySendNotificationOnAntivirusDisabled -Value "2"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name PrioritySendNotificationOnAntivirusOutOfDate -Value "2"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name PrioritySendNotificationOnLowMemory -Value "2"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name PrioritySendNotificationOnCPUUsage -Value "2"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name PrioritySendNotificationOnBelowCPUUsage -Value "2"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name PrioritySendNotificationOnPortNotAccessible -Value "3"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name PrioritySendNotificationOnServiceStop -Value "3"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name PrioritySendNotificationOnSSLCertificateExpiration -Value "2"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name PrioritySendNotificationOnWebSiteNotAvailable -Value "3"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name PrioritySendNotificationOnADUserLocked -Value "2"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name PrioritySendNotificationOnBackupSuccess -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name PrioritySendNotificationOnBackupFailure -Value "3"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name PriorityMonitorVMwareAlarms -Value "2"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name PrioritySendNotificationOnVMwareWarnings -Value "2"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name PrioritySendNotificationOnAmazonAlarmsTriggered -Value "2"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name PrioritySendNotificationOnERAClientThreat -Value "2"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name PrioritySendNotificationOnSqlServerLongQueryExecutionTime -Value "2"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name PrioritySendNotificationOnSqlServerHighDatabaseSize -Value "2"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor" -Name WatchdogUninstallAttempted -Value "0"
    # Help desk Widget
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor\Branding" -Name DisplayDetails -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor\Branding" -Name CustomTrayIcon -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor\Branding" -Name SupportInfoName -Value "Liftsafe Group Support"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor\Branding" -Name SupportInfoEmail -Value "helpdesk@liftsafegroup.com"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor\Branding" -Name SupportInfoPhone -Value "226-240-1514"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor\Branding" -Name SupportInfoWebsite -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor\Branding\CustomTrayMenuEntries" -Name Count -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor\Branding\CustomTrayMenuEntries\Entry0" -Name Label -Value "Troubleshoot my issue"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor\Branding\CustomTrayMenuEntries\Entry0" -Name Type -Value "0"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\MMSOFT Design\PC Monitor\Branding\CustomTrayMenuEntries\Entry0" -Name Value -Value "https://liftsafegroup.pulseway.com/clientportal"
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

    #Enable mapped drives on W11
    Set-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableLinkedConnections -Type Dword -Value 1 
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
    Add-WindowsCapability -Online -Name NetFx3~~~~
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
        choco install -y DellCommandUpdate
    
    Start-Process ".\Dell-Command-Update" "/s" -Wait
    Start-Process "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe" "/configure -userConsent=disable -scheduleManual" -Wait
    Start-Process "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe" "/scan" -Wait
    Start-Process "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe" "/applyUpdates" -Wait
}
}
# BGInfo Installer
function Prep-BGInfo {
    $ErrorActionPreference = 'silentlycontinue'
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
    # Install update module
    # Install-Module PSWindowsUpdate
    # Add Windows update service man
    # Add-WUServiceManager -MicrosoftUpdate
    # Install all available Windows update and create log file in Admin dir
    # Install-WindowsUpdate -AcceptAll -IgnoreReboot | Out-File "C:\Admin\($env.computername-Get-Date -f yyyy-MM-dd)-MSUpdates.log" -Force
    # Review Windows updates
    # Get-WindowsUpdate

<# [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
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
    iwr -uri "https://liftsafe-my.sharepoint.com/:u:/g/personal/mbusenbark_liftsafegroup_com/EeOKVTSESmlFmBbOo0QRbVQBJXvtIOoJkOw8opaLEVySOw?e=xbOCKW" -OutFile C:\Admin\RMM_Prep.msi}
}
# Create user VPN
Function Prep-VPN {

    $VPNName = Read-Host -Prompt 'Enter VPN Name' <# LGOC VPN #>
    $VPNKey = Read-Host -Prompt 'Enter VPN Key'<# LgocVPN #>
    $VPNAddress = Read-Host -Prompt 'VPN Address'<# VPN.liftsafegroup.com #>
    $VPNDns = Read-Host -Prompt 'VPN DNS' <# liftsafeinspections.com #>
    $TunType = "L2tp"
    $VPNAuth = "Psk"
    $LoginCreds = "True"
    
    # Create VPN Connection
    Add-VpnConnection -Name $VPNName -ServerAddress $VPNAddress -TunnelType $TunType -EncryptionLevel Required -L2tppsk $VPNAuth <#-UseWinlogonCredential $LoginCreds#> -AuthenticationMethod Chap, MsChapv2, Pap -SplitTunneling -Force
    
    # Create a desktop shortcut
    $WScriptShell = New-Object -ComObject WScript.Shell
    $VPNShortcut = $WScriptShell.CreateShortcut("$env:Public\Desktop\$VPNName.lnk")
    $VPNShortcut.TargetPath = "rasphone.exe"
    $VPNShortcut.Save()
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
           [string]$Title = 'Workstation Prep Tool'
    )
     Clear-Host
     Write-Host "================= $Title ================="
     Write-Host "               System Prep:               "
     Write-Host "[ENTER]: Domain PC Prep (All - No Reboot) "
     Write-Host "[W]: Full PC Prep                         "
     Write-Host "[3]: Install Software                     "
     Write-Host "[4]: Install .NET Framework 3.5           "
     Write-Host "[5]: Run Windows Update                   "
     Write-Host "[6]: Install System Updater               "
     Write-Host "[7]: Install RMM Agent                    "
     Write-Host "               User Prep:                 "
     Write-Host "[U]: User Prep                            "
     Write-Host "                                          "
     Write-Host "           LGOC specific                  "
     Write-Host "[8]: Install BGInfo                       "
     Write-Host "[9]: Install G10                          "
     Write-Host "[P]: Prep Pulseway                        "
     Write-Host "[R]: Rename PC                            "
     Write-Host "[S]: LGOC Shortcuts                       "
     Write-Host "[X]: Re-Map Network Drives                "     
     Write-Host "[V]: Setup User VPN                       "
     Write-Host "[Q]: Press 'Q' to quit.                   "
     Write-Host "                                          "
}
do {Show-Menu
        $input = Read-Host "Please make a selection"
        switch ($input){
        default {
        Clear-Host
        $Prep_Select = Read-Host -Prompt "Workstation(W) or Tablet(T)"        
        If ($Prep_Select -eq "W"){Prep-PC}
        ElseIf($Prep_Select -eq "T"){Prep-Tablet}
        Prep-User
        Prep-RMM-Install
        Prep-Users-Localadmin
        Prep-Updater
        Prep-Chrome
        Prep-Adobe
        Prep-DotNET
        Prep-Office
        Prep-PC-Name
        Prep-WU
} 'w'<# Full PC Prep #> {
    Clear-Host
    Prep-PC-Name
    Prep-User
    Prep-PC
    $Prep_Select = Read-Host -Prompt "Is this a Workstation(W), or Tablet?(T)"
    $reply_adobe = Read-Host -Prompt "Install Adobe?[Y/n]"
    $reply_chrome = Read-Host -Prompt "Install Chrome?[Y/n]"
    $reply_office = Read-Host -Prompt "Install Office?[Y/n]"
    $reply_Clean = Read-Host -Prompt "Remove all desktop shortcuts minus Chrome?[Y/n]"
    $reply_wupdates = Read-Host -Prompt "Install Windows Updates?[Y/n]"
    $reply_sysupdate = Read-Host -Prompt "Install System Updater?[Y/n]"
    $reply_VPN = Read-Host -Prompt "Setup VPN?[Y/n]"
    If($Prep_Select -contains "W"){Prep-PC}
    ElseIf($Prep_Select -contains "T"){Prep-Tablet}
    Prep-RMM-Install
    Prep-DotNET
    Prep-Users-Localadmin
    Prep-BGInfo
    If ($reply_sysupdate -notmatch "[nN]"){Prep-Updater}
    If ($reply_chrome -notmatch "[nN]"){Prep-Chrome}
    If ($reply_adobe -notmatch "[nN]"){Prep-Adobe}
    If ($reply_office -notmatch "[nN]"){Prep-Office}
    If ($reply_Clean -notmatch "[nN]"){Prep-Clean-Shortcuts}
    If ($reply_VPN -notmatch "[nN]"){Prep-VPN}
    If ($reply_wupdates -notmatch "[nN]"){Prep-WU}
    Write-Verbose "Installation Complete, please reboot system." -Verbose

} 'u'<# User Prep #> {
    Clear-Host
    $reply_Clean = Read-Host -Prompt "Remove all desktop shortcuts minus Chrome?[Y/n]"
    If ($reply_Clean -notmatch "[nN]"){Prep-Clean-Shortcuts}
    Prep-User
    Clear-Host
} '3'<# Install Software #> {
    Clear-Host
    $reply_adobe = Read-Host -Prompt "Install Adobe?[Y/n]"
    $reply_chrome = Read-Host -Prompt "Install Chrome?[Y/n]"
    $reply_sysupdate = Read-Host -Prompt "Install System Updater?[Y/n]"
    $reply_bginfo = Read-host -Prompt "Install BGinfo?[Y/n]"
    $reply_office = Read-Host -Prompt "Install Office?[Y/n]"
    If ( $reply_sysupdate -notmatch "[nN]"){Prep-Updater}
    If ( $reply_chrome -notmatch "[nN]"){Prep-Chrome}
    If ( $reply_adobe -notmatch "[nN]"){Prep-Adobe}
    if ( $reply_bginfo -notmatch "[nN]") {Prep-BGInfo}
    If ( $reply_office -notmatch "[nN]"){Prep-Office}
    Prep-Clean-Shortcuts
    Clear-Host
} '4'<# Install .NET Framework 3.5 #> {
    Clear-Host
    Prep-DotNET
    Clear-Host
} '5'<# Run Windows Updates #>  {
    Clear-Host
    Prep-WU
    Clear-Host
} '6'<# Install System Update #> {
    Clear-Host
    Prep-Updater
    Clear-Host
} '7'<# Install RMM Agent #> {
    Clear-Host
    Prep-RMM-Install
    Clear-Host
} '8'<# Install BGInfo #>{
    Clear-Host
    Prep-BGInfo
    Clear-Host
} '9'<# Download G10, and run #> {
    Clear-Host
    Prep-G10
    Clear-Host
} 's' <# Create G10 shorcuts#>{
    Clear-Host
    Prep-LGOCShortcuts
    Clear-Host
} 'x' <# Re-map network drives #>{
    Clear-Host
    Prep-DriveMaps
    Clear-Host
} 'v' <# Setup user VPN, and create shorcut #> {
    Clear-Host
    Prep-VPN    
    Clear-Host
} 'r' <# Prompt user for Prefix and rename PC #>{
    Prep-PC-Name
} 'p' <# Pulseway configurations #> {
    Prep-Pulseway
} 'q' <#To close window#> {
            return
    }
}
pause
}
until ($input -eq 'q')
