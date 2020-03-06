<#
    .DESCRIPTION 
    ISA (Image Security Assessment) is a PoC for autocompleting image security assessment.    
    Author: caabv

#>

#Functions for coloring

function Invoke-Alternative{
    Write-Host "Alternative" -ForegroundColor Yellow
}

function Get-systeminfo {
    Write-Host "==================================================="
    Write-Host "System Information"
    Write-Host "==================================================="
    Invoke-Command { systeminfo }
    "`n"
    Write-Host "==================================================="
    "`n"
    Get-Hotfix
    "`n"    
}

function Get-Hotfix {
    Invoke-Command { wmic qfe }
}

function Invoke-FWStatus {
    Write-Host "==================================================="
    Write-Host "Checking status of Windows Firewall"
    Write-Host "==================================================="
    Get-FWStatus
    "`n"
    Start-Sleep -s 3
    Invoke-DisableFW
}

function Get-FwStatus{
    #Issue with SMB running in cmd works.
    #Get-NetFirewallProfile  | select -Property Name, Enabled
    Invoke-Command { netsh advfirewall show allprofiles state }
}

function Invoke-DisableFW {
    Write-Host "==================================================="
    Write-Host "Disabling Windows Firewall"
    Write-Host "==================================================="
    "`n"
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
    "`n"
    Start-Sleep -s 5
}

function Get-FolderPermissions{
    Write-Host "==================================================="
    Write-Host "Checking folder permissions"
    Write-Host "==================================================="
    "`n"
    Write-Host "Avaiable folders:"
    Get-ChildItem -Path C:\Users\ -Force -Exclude *.* | ft
    "`n"
    Write-Host "Checking permission for each folder:"
    "`n"
    Invoke-FolderPermission
    "`n"
    Start-Sleep -s 5
}

function Invoke-FolderPermission {
    Get-ChildItem -Path C:\Users\* -Force -Exclude *.* | foreach { (get-acl).access | ft IdentityReference,FileSystemRights,AccessControlType,IsInherited,InheritanceFlags -auto } | sls -Pattern "PermissinDenied"
}

function Get-Permissions{
    Write-Host "==================================================="
    Write-Host "Checking groupmembership"
    Write-Host "==================================================="
    "`n"
    Write-Host "User:" $env:USERNAME
    Get-LocalGroup | ft Name
    Invoke-Alternative
    Get-GroupMemberShip
    Start-Sleep -s 3
    "`n"
    Write-Host "==================================================="
    Write-Host "Any of the users member of the administrators group"
    Write-Host "==================================================="
    Get-LocalGroupMember Administrators | ft Name, PrincipalSource
    Invoke-Alternative
    "`n"
    Get-LocalAdministrators
    "`n"
    Start-Sleep -s 5
}

function Get-GroupMemberShip {
    $tableLayout = @{Expression={((New-Object System.Security.Principal.SecurityIdentifier($_.Value)).Translate([System.Security.Principal.NTAccount])).Value};Label="Group Name";Width=60},@{Expression={$_.Value};Label="Group SID";Width=45},@{Expression={$_.Type};Label="Group Type";Width=75}
    ([Security.Principal.WindowsIdentity]::GetCurrent()).Claims | FT $tableLayout
}

function Get-LocalAdministrators {
    Invoke-command {net localgroup administrators}
}

function Get-RunAs{
    Write-Host "==================================================="
    Write-Host "Privilege escalation - Run as"
    Write-Host "==================================================="
    Invoke-RunAs
    Write-Host "Check the cmd.exe window" -ForegroundColor Yellow
    "`n"
    Start-Sleep -s 5
}

function Invoke-RunAs {
    Start-Process powershell -FilePath "cmd.exe" -Verb runAs
}

function Get-ScheduledTasks{
    Write-Host "==================================================="
    Write-Host "Scheduled Tasks"
    Write-Host "==================================================="
    Invoke-ScheduledTasks
    "`n"
    Start-Sleep -s 3
}

function Invoke-ScheduledTasks {
    Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State
}


function Invoke-AccessCheck {
    Write-Host "==================================================="
    Write-Host "Access check"
    Write-Host "==================================================="
    Get-AccessCheck
    Get-Service * | select Displayname,Status,Can*
    Invoke-Alternative
    Invoke-AccessCheckAlt
    "`n"
    Write-Host "Unquoted service paths:" -ForegroundColor DarkYellow
    Get-UnquotedPaths
    "`n"
}

function Get-AccessCheck {
    $WebClient = New-Object System.Net.WebClient
    $WebClient.DownloadFile("https://live.sysinternals.com/accesschk.exe","C:\Temp\accesschk.exe")
    & 'C:\Temp\accesschk.exe' -uwcqv "Authenticated Users" * /accepteula''
}

function Invoke-AccessCheckAlt {
    Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*','C:\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} |fl } catch {}}
}

function Get-UnquotedPaths {
    Invoke-Command { gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name }
}

function Get-PSVersion2{
    Write-Host "==================================================="
    Write-Host "Powershell version"
    Write-Host "==================================================="
    Get-Host | select version
    Start-Sleep -s 5
    "`n"
    Write-Host "Downgrade powershell version 2 attempt:" 
    Invoke-PSVersion2
    "`n"
    Write-Host "Check PopUp window" -ForegroundColor Yellow
    "`n"
    Start-Sleep -s 5
}

function Invoke-PSVersion2 {
    Start-Process powershell -ArgumentList '-noexit -command "powershell -version 2, host"'
}

function Get-CacheCredentials{
    Write-Host "==================================================="
    Write-Host "Cache credentials"
    Write-Host "==================================================="
    Get-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" | select CachedLogonsCount | fl
    "`n"
    Start-Sleep -s 3
}

function Get-IESettings {
    Write-Host "==================================================="
    Write-Host "Internet Explorer Security Settings"
    Write-Host "==================================================="
    Write-Host "Work In Progress" -Foregroundcolor Yellow
    #IExplorer Options | Missing specific level
    Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" 
    "`n"
}

function Get-MacroSettings {
    Write-Host "==================================================="
    Write-Host "Macro Settings - Office | Check for value '1'"
    Write-Host "==================================================="
    "`n"
    Write-Host "Work In Progress" -ForegroundColor Yellow
    # Macro settings
    # Find office version:
    Invoke-Command { wmic product where "Name like 'Microsoft Office%'" get name,version } # Should select afterwards and then run rest of commands
    Start-Sleep -s 15
    Write-Host "Excel:"
    Get-ItemProperty "HKCU:\Software\Policies\microsoft\office\16.0\excel\security" | select vbawarnings
    Write-Host "Word"
    Get-ItemProperty "HKCU:\Software\Policies\microsoft\office\16.0\word\security" | select vbawarnings
    "`n"
}

function Get-WPAD{
    Write-Host "==================================================="
    Write-Host "WPAD"
    Write-Host "==================================================="
    $WPAD = $null
    $WPAD = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad"
    If ($WPAD -ne $null)
    {
        $WPAD
    }
    Else
    {
        Write-Host "WPAD" -ForegroundColor Yellow;
    }
    "`n"
    Start-Sleep -s 2
}

function Get-LLNMR{
    Write-Host "==================================================="
    Write-Host "LLMNR - Check for 'Enable Multicast'"
    Write-Host "==================================================="
    "`n"
    $LLMNR = $null
    $LLMNR = Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient"
    If ($LLMNR -ne $null)
    {
        $LLMNR
    }
    Else
    {
        Write-Host "Seems like LLMNR is set to default, verify with wireshark" -ForegroundColor Yellow
    }
    "`n"
    Start-Sleep -s 2
}

function Invoke-NetBiosSettings{
    Write-Host "==================================================="
    Write-Host "NetBIOS Check for the value 0 or 1"
    Write-Host "TcpipNetbiosOptions"
    Write-Host "==================================================="
    Get-NetBiosSettings
    "`n"
    Start-Sleep -s 3
    #Invoke-Alternative
    "`n"
    #Get-NetBiosSettingsAlt # Missing output - But cmd works
    "`n"
    Start-Sleep -s 3
}

function Get-NetBiosSettings {
    Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=TRUE -ComputerName . | Select-Object -Property Description,TcpipNetbiosOptions -ExcludeProperty IPX*,WINS*
}

function Get-NetBiosSettingsAlt {
    $i = 'HKLM:\SYSTEM\CurrentControlSet\Services\netbt\Parameters\interfaces'  
    Get-ChildItem $i | Foreach {  
        Get-ItemProperty -Path "$i\$($_.pschildname)" -name NetBiosOptions | select PSPath,NetbiosOptions
    }
}

function Get-SMBversion {
    Write-Host "==================================================="
    Write-Host "SMB"
    Write-Host "==================================================="
    "`n"
    if ((Get-Service mrxsmb10).Status -eq 'Running') 
    {
        "SMB1 is enabled"
        "`n"
    }
    else 
    {
        "SMB1 is not enabled"
        "`n"
    }
    Start-Sleep -s 3
    if ((Get-Service mrxsmb20).Status -eq 'Running') 
    {
        "SMB2 is enabled"
        "`n"
    }
    else 
    {
        "SMB2 is not enabled"
        "`n"
    }
    #Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol,EnableSMB2Protocol # Missing output but cmd works
    Start-Sleep -s 5
}

function Get-AttackSurfaceReduction {
    Write-Host "==================================================="
    Write-Host "Attack surface reduction"
    Write-Host "==================================================="
    $ASR = $null
    $ASR = Get-MpPreference | select AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Action, AttackSurfaceReductionOnlyExclusions
    If ($ASR -ne $null)
    {
        $ASR
    }
    Else
    {
        Write-Host "Seems like Attack Surface Reduction is not set" -ForegroundColor Yellow
    }
    "`n"
    Start-Sleep -s 3
}

function Get-BitLockerStatus {
    Write-Host "==================================================="
    Write-Host "Bitlocker"
    Write-Host "==================================================="
    Invoke-Command { & 'manage-bde.exe' -status }
    "`n"
    Start-Sleep -s 3
}

function Get-TokenFilterPolicyAdminApproval{
    Write-Host "==================================================="
    Write-Host "Local Account Token Filter Policy"
    Write-Host "==================================================="
    Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy" | select LocalAccountTokenFilterPolicy
    "`n"
    Write-Host "==================================================="
    Write-Host "Admin Approval Mode - Check for value '1'"
    Write-Host "==================================================="
    Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy" | select FilterAdministratorToken
    "`n"
}

function Get-AlwaysElevated{
    Write-Host "==================================================="
    Write-Host "Always install elevated"
    Write-Host "==================================================="
    Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" | select "AlwaysInstallElevated" | fl
    Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" | select "AlwaysInstallElevated" | fl
}

function Get-ThirdPartyApps{
    Write-Host "==================================================="
    Write-Host "Checking versions of installed third party software"
    Write-Host "==================================================="
    Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime      
    Start-Sleep -s 10
    Invoke-Command { wmic product get name,version }
    Start-Sleep -s 10
    "`n"
}

function Get-RegistryPasswords {
    Write-Host "==================================================="
    Write-Host "Checking registry editor for 'password'"
    Write-Host "==================================================="
    Invoke-Command { reg query HKCU /f "password=" /t REG_SZ /s }
    Invoke-Command { reg query HKLM /f "password=" /t REG_SZ /s }
    Start-Sleep -s 20
    "`n"
}

function Get-Sysprep {
    Write-Host "==================================================="
    Write-Host "Checking for sysprep or unattended files"
    Write-Host "==================================================="
    Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
    Start-Sleep -s 20
}

function Get-IntFiles{
    Write-Host "==================================================="
    Write-Host "Checking for passwords, config files etc."
    Write-Host "==================================================="
    Invoke-IntFiles
    "`n"
    Start-Sleep -s 20
}

function Invoke-IntFiles {
    $folders = ('C:\Users\','C:\Program Files\','C:\Program Files (x86)\')
    foreach($folder in $folders){
    Write-Host "Checking" $folder -ForegroundColor DarkYellow; 
    # Update include
    Get-Childitem –Path $folder -Include *password*,*vnc*,*.config -File -Recurse -ErrorAction SilentlyContinue #| Select-String -Pattern "password" -CaseSensitive #Checks for passwords in selected paths
    }
}

function Invoke-All{
    Get-systeminfo
    Invoke-FWStatus
    Get-FolderPermissions
    Get-RunAs
    Get-ScheduledTasks
    #Invoke-AccessCheck
    Get-PSVersion2
    Get-CacheCredentials
    #Get-IESettings
    #Get-MacroSettings
    Get-WPAD
    Get-LLNMR
    Invoke-NetBiosSettings
    Get-SMBversion
    Get-AttackSurfaceReduction
    Get-BitLockerStatus
    Get-TokenFilterPolicyAdminApproval
    #Get-AlwaysElevated
    Get-ThirdPartyApps
    Get-RegistryPasswords
    #Get-Sysprep
    Get-IntFiles
    Write-Host "==================================================="
    "`n"
    Write-Host "Script finised successfully" -ForegroundColor Green
}
Invoke-All
