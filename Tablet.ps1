[cmdletbinding(SupportsShouldProcess)]
[alias("iwg")]
[OutputType("None")]
[OutputType("Microsoft.Windows.Appx.PackageManager.Commands.AppxPackage")]
Param(
    [Parameter(HelpMessage = "Display the AppxPackage after installation.")]
    [switch]$Passthru)

Write-Verbose "[$((Get-Date).TimeofDay)] Starting $($myinvocation.mycommand)"

# Run as admin
Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy Unrestricted

# If not run as admin, Powershell will close and relaunch as an elevated process:
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    Write-Host "You didn't run this script as an Administrator. This script will self elevate to run as an Administrator and continue."
    Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs 
Exit}

<# System Prep #>
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
    
    # OneDrive
    Install-Module onedrivecmdlets
    

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

    # G10 Support
    Copy-Item -Force -Path "\\192.168.0.15\Liftsafe Group Of Companies\Installers\How-To Guides\Tablet Setup\G10-SUPPORT" -Destination "C:\G10 Assets"
    # Manuals
    Copy-Item -Force -Path "\\192.168.0.15\Liftsafe Group Of Companies\Installers\How-To Guides\Tablet Setup\Manual" -Destination "C:\G10 Assets"
    # Wallpaper
    Copy-Item -Force -Path "\\192.168.0.15\Liftsafe Group Of Companies\Installers\How-To Guides\Tablet Setup\4. Wallpaper" -Destination "C:\G10 Assets"

<# Application Installs #>
    # Install BGInfo with settings
    bginfo c:\admin\g10\settings.bgi /timer:0 /nolicprompt
    # Install SQL software
    Start-Process -FilePath "C:\Admin\G10\SQLCEv4x64.exe" -Wait
    # Install G10 
    Start-Process -FilePath "C:\Admin\G10\G10 Tablet 2.20.exe" -Wait
    # Install Pulseway Agent
    Start-Process -FilePath "C:\Admin\G10\LESGC Tablets.msi" -Wait
