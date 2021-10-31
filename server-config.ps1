## Windows Server Build Checklist
## Chris Shearer October 2015 - October 2021

## replace 'your.local' with your AD domain.


## Set the users or groups that will be added as local admins here
## DON'T FORGET COMMAS after all entries except the last.
	$groups = ( 
                "your.local\Domain Admins",
				"your.local\Server Admins"
              )

###################
#### Functions ####
###################

## Function to adjust visual effects for best performance 
    function Set-BestPerformance   
		{   $path = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects'
			    try {
				    $s = (Get-ItemProperty -ErrorAction stop -Name visualfxsetting -Path $path).visualfxsetting 
				    if ($s -ne 2) { Set-ItemProperty -Path $path -Name 'VisualFXSetting' -Value 2  }
				    }
			catch { New-ItemProperty -Path $path -Name 'VisualFXSetting' -Value 2 -PropertyType 'DWORD'}
		}                    

## Function to install SNMP Service Server OS only, also sets allowed SNMP servers and community string (insert your values)
    function Install-SNMPService
        {
            Import-Module ServerManager
            Get-WindowsFeature -name *SNMP* | Add-WindowsFeature -includeallsubfeature

            write-host -f Cyan "Configuring permitted SNMP managers"
            ## set allowed snmp access
                $mKey = "hklm:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers"

                if (!$mkey -or !$mkey.1 -or !$mkey.2 -or ($mkey.2 -ne '10.1.1.11') -or ($mkey.3 -ne '10.1.1.12') -or ($mkey.4 -ne '10.1.1.13'))
                    {
                        New-ItemProperty -path $mkey -name 1 -value 'localhost' -Force | Out-Null
                        New-ItemProperty -path $mkey -name 2 -value '10.1.1.11' -Force | Out-Null
                        New-ItemProperty -path $mkey -name 3 -value '10.1.1.12' -Force | Out-Null
                        New-ItemProperty -path $mkey -name 4 -value '10.1.1.13' -Force | Out-Null
                    }

            ## set allowed snmp communities
                write-host -f Cyan "Configuring permitted SNMP community"
                $cKey = "hklm:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities"
                if (!$cKey -or ($cKey.AAAAAAAAAAAAAAA -ne '4')) {New-ItemProperty -path $cKey -name "AAAAAAAAAAAAAAA" -value 4 -Force | Out-Null}
        }

## Function to enable RDP and require Network Level Authentication
    function Enable-RDPandNLA        
        {
        (Get-WmiObject -Class "Win32_TerminalServiceSetting" -Namespace root\cimv2\terminalservices).SetAllowTsConnections(1) 
            write-host -ForegroundColor Green "Done enabling RDP"
        ## Enable Network Level Authentication for RDP
        (Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'").SetUserAuthenticationRequired(1) #1 for required 0 for not required.
        }

## Function to add local admins
    function Add-LocalAdmins 
        {	
        $ErrorActionPreference = "SilentlyContinue"
        ForEach ($group in $groups) 
		    {   
			    write-host -ForegroundColor Green "Adding group $group"
			    net localgroup administrators $group /add
                write-host "Done"
		    }
        }

## Function to set folder preferences 
    function Set-FolderPreferences
        {   $key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
	        Set-ItemProperty $key Hidden 1
	        Set-ItemProperty $key HideFileExt 0
		    #Stop-Process -Name Explorer -force # Kill Explorer for the change to take effect this will happen later after IEESC disable
        }

## Function to clear page file at shutdown
    function Set-ClearPageAtShutdown
        {   $ClearPFKey = "HKLM:\SYSTEM\CurrentControlSet\control\session Manager\Memory Management"
            Set-ItemProperty -Path $ClearPFKey -name ClearPageFileAtShutdown -Value 1
        }

## Function to disable the spooler service
    function disable-SpoolerService 
        {
            Stop-Service -Name Spooler
            Set-Service -Name Spooler -StartupType Disabled
        }

## Function to disable drive indexing on C:
    function Disable-Indexing 
        {   Param($Drive)
            $obj = Get-WmiObject -Class Win32_Volume -Filter "DriveLetter='$Drive'"
            $indexing = $obj.IndexingEnabled
            # sleep 2
            if("$indexing" -eq $True)
            {   $obj | Set-WmiInstance -Arguments @{IndexingEnabled=$False} | Out-Null }
        }

## Function to disable RDP Printer Mapping to this server
    function Disable-RDPPrinterMapping
        {   $RDPPrinterMapping = "HKLM:\software\Policies\Microsoft\Windows NT\Terminal Services"
            Set-ItemProperty -path $RDPPrinterMapping -name fDisableCpm -value 1
        # sleep 2
        }

## Function to install PowerShell ISE
    function Install-PowerShellISE
        {   Import-Module ServerManager -ErrorAction SilentlyContinue
            Add-WindowsFeature PowerShell-ISE
        }

## Function to disable Windows Audio Service
    function disable-WindowsAudio
        {
            Stop-Service -Name AudioSRV
            Set-Service  -Name AudioSRV -StartupType Disabled
        }

## Function to disable Internet Explorer Enhanced Security Configuration (IEESC) for admins
    function Disable-InternetExplorerESC 
        {   $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
		    $UserKey  = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
		    Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0 #for admins, 1 for on and 0 for off
		    Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 1  #for users,  1 for on and 0 for off
            Stop-Process -Name Explorer -force  ## Kill Explorer for the change to take effect
        }

## Function to disable shutdown event tracker
    function Disable-ShutdownEventTracker
        {   
            $EvtTrackerKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Reliability"
            $ReasonUICode = Get-ItemProperty -Path $EvtTrackerKey
            if (!($ReasonUICode))
                {New-ItemProperty -path $EvtTrackerKey -name 'ShutdownReasonUI' -PropertyType DWord -Value 0}
            if ($ReasonUICode.ShutdownReasonUI -ne 0)
                {Set-ItemProperty -path $EvtTrackerKey -name 'ShutdownReasonUI' -Value 0
			write-host "2" }
        }

## Function to disable Windows Computer Browser Service and WPAD service
    function disable-browserservice
        {
            Stop-Service -Name browser
            Set-Service  -Name browser -StartupType Disabled
        }

## Function to disable WPAD service (requires a reboot)
    function disable-wpadService
        {
            ## REBOOT NECESSARY to complete disabling WPAD
            write-host "Disabling WPAD: 3 is enabled, 4 is disabled "
            if ((Get-ItemProperty -path "HKLM:\\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc" -name Start).start -ne 4)
                {Set-ItemProperty -path "HKLM:\\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc" -name Start -value 4
                Write-Host "WPAD has been disabled."}
            else {Write-Host "WPAD was already disabled."}
        }

## Function to disable side-channel vulnerabilities
    function disable-sideChanVulns
        {
            ## https://support.microsoft.com/en-us/topic/windows-server-guidance-to-protect-against-speculative-execution-side-channel-vulnerabilities-2f965763-00e2-8f98-b632-0d96f30c8c8e
                Set-ItemProperty -Path "HKLM:\\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -name FeatureSettingsOverride -Value 0
                Set-ItemProperty -Path "HKLM:\\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -name FeatureSettingsOverrideMask -Value 3
        }

## Function to disable LMHash
function set-lmhash
{
    $lsa = $null
    $lsa = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\lsa\" -ErrorAction SilentlyContinue

    if (!($lsa.nolmhash) -or ($lsa.nolmhash -ne 1)) 
        {
            New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -name 'NoLMHash' -value '1' -PropertyType 'DWord' -Force | Out-Null
            write-host "lmhash 1"
        } 
    else {write-host "lmhash 1" -f green}

    if (!($lsa.LMCompatibilityLevel) -or ($lsa.LMCompatibilityLevel -ne 5)) 
        {
            New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -name 'LMCompatibilityLevel' -value '5' -PropertyType 'DWord' -Force | Out-Null
            write-host "lmcompat 5"
        } 
    else {write-host "lmcompat 5" -f green}
}

## Function to set reg key for Microsoft CVE-2017-8529
Function set-cve20178529
{
    $disclosureFix = $null
    $disclosureFix = Get-ItemProperty "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\" -ErrorAction SilentlyContinue

    if (!($disclosureFix.FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX) -or ($disclosureFix.FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX -ne 1))
        {
            New-ItemProperty -path "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\" -name 'FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX' -value '1' -PropertyType 'DWord' -force | Out-null
            write-host "FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX: " -NoNewline; write-host -f green "set"
        }
    else {write-host "FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX: " -NoNewline; write-host -f green "already correct"}    
}

## Function to disable smbv1
function Disable-SMBv1
{
    $SMBconfig = Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol,RequireSecuritySignature

    #if smb1 is on then disable it
    if ($SMBconfig.enablesmb1protocol -eq $true)
    {
        write-host "SMBv1 State: " -nonewline; write-host -f red $SMBconfig.enablesmb1protocol
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -force
        $NewSMBv1status = Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol
        write-host "New SMBv1 State: " $newSMBv1status.enablesmb1protocol
    }
    else { write-host "SMBv1 State: " -nonewline; write-host -f green $SMBconfig.enablesmb1protocol }

    Write-Host "SMB Signing Status: "  (Get-SmbServerConfiguration).RequireSecuritySignature

    # if signature is not required, then require it
    if ( $SMBconfig.RequireSecuritySignature -eq $false)
    {
        Write-Host "Forcing SMB Signing..."
        set-SmbServerConfiguration -RequireSecuritySignature $TRUE -force
    }
    Write-Host "SMB Signing Status: "  $SMBconfig.RequireSecuritySignature
}

## Function to enable Windows Update Service
    function enable-WindowsUpdateService
        {
            Set-Service   -Name wuauserv -StartupType automatic
            Start-Service -Name wuauserv
        }

## Function to disable anonymous access 
    function enable-restrictAnonEnum
        {
            set-ItemProperty "hklm:\SYSTEM\CurrentControlSet\Control\Lsa" -name everyoneincludesanonymous 1
            set-ItemProperty "hklm:\SYSTEM\CurrentControlSet\Control\Lsa" -name restrictAnonymous 0 
            set-ItemProperty "hklm:\SYSTEM\CurrentControlSet\Control\Lsa" -name restrictAnonymousSAM 0
        }

## Function to disable IPV6
    function disable-ipv6 {Disable-NetAdapterBinding -name "*" -ComponentID ms_tcpip6}

## Function to Disable NetBIOS / WINS
    function Disable-NetBIOSWins
        {
        $NetBios = Get-WmiObject -Class Win32_NetworkAdapterConfiguration
        foreach ($net in $NETBios)
            {   
                $NetBios.setWINSServer("$Null","$Null") | Out-Null
                $NetBios.SetTcpipNetbios("2") | Out-Null
            }
        }


## Function to disable XBox Live services if installed
function disable-XboxServices
{
    $xbl1 = get-service XblAuthManager -ErrorAction SilentlyContinue
    $xbl2 = get-service XblGameSave    -ErrorAction SilentlyContinue
    
    if ($xbl1) 
        {
            stop-service -Name XblAuthManager
            set-service  -Name XblAuthManager -StartupType Disabled
        }

    if ($xbl2) 
        {
            stop-service -Name XblGameSave
            set-service  -Name XblGameSave -StartupType Disabled
        }
}        

###############################
#### Software installation ####
###############################

function Install-StandardSoftware 
    {         
        write-host "=== Software Installation ==="
    ## Labtech
        write-host -ForegroundColor Green "Installing Labtech"
	        msiexec /i \\your.local\SYSVOL\your.local\scripts\Agent_Install.MSI /quiet /norestart
        write-host -ForegroundColor Green "Done installing Labtech"
        write-host "===================="
    }

    
#######################            
#### Run Functions ####
#######################
function Invoke-Settings
    {
    write-host "=== Settings and Services ==="
## Call  function to adjust visual effects for best performance
    write-host -ForegroundColor Green "Adjusting visual Effects for best performance"
        Set-BestPerformance
    write-host -ForegroundColor Green "Done adjusting visual Effects for best performance"
    write-host "===================="

## Call function to install SNMP Service
    write-host -ForegroundColor Green "Beginning installation of SNMP Service"
        Install-SNMPService    
    write-host -ForegroundColor Green "Done with installation of SNMP Service"
    write-host "===================="

## Call function to enable RDP and Network Level Authentication
    write-host -ForegroundColor Green "Enabling RDP & Network Level Authentication"
        Enable-RDPandNLA
    write-host -ForegroundColor Green "Done setting Network Level Authentication for RDP"
    write-host "====================" 

## Call function to disable IE ESC for admins
    write-host -ForegroundColor Green "Disabling Internet Explorer Enhanced Security Configuration (IEESC) for admins"
	    Disable-InternetExplorerESC 
    write-host -ForegroundColor Green "Done disabling IEESC for admins"
    write-host "===================="

## Call function to add Local Admins
    write-host -ForegroundColor Green "Adding local admins"
        Add-LocalAdmins
    write-host -ForegroundColor Green "Done adding local admins"
    write-host "===================="

## Call function to set Folder preferences to view hidden files, show file extentions, 
    write-host -ForegroundColor Green "Setting folder view preferences"
        Set-FolderPreferences
    write-host -ForegroundColor Green "Done setting folder view preferences"
    write-host "===================="

## Call function to set clear page file at shutdown key
    write-host -ForegroundColor Green "Setting registry to clear pagefile at shutdown"
        Set-ClearPageAtShutdown
    write-host -ForegroundColor Green "Done setting registry to clear pagefile at shutdown"
    write-host "===================="

## Call function to stop and disable print spooler service
    write-host -ForegroundColor Green "Stopping and disabling the Print Spooler service"
        Disable-SpoolerService
    write-host -ForegroundColor Green "Done stopping and disabling the Print Spooler service"
    write-host "===================="

## Call function to disable Drive indexing on C
    write-host -ForegroundColor Green "Disabling drive indexing on C:"
        Disable-Indexing "C:"
    write-host -ForegroundColor Green "Done disabling drive indexing on C:"
    write-host "===================="

## Call function to disable RDP printer mapping
    write-host -ForegroundColor Green "Disabling RDP Printer Mapping"
        Disable-RDPPrinterMapping
    write-host -ForegroundColor Green "Done disabling RDP Printer Mapping"
    write-host "===================="

## Call function to disable RDP printer mapping
    write-host -ForegroundColor Green "Installing Powershell ISE"
        Install-PowerShellISE
    write-host -ForegroundColor Green "Done installing Powershell ISE"
    write-host "===================="    

## Call function to stop and disable Windows Audio service
    write-host -ForegroundColor Green "Stopping and disabling the Windows Audio service"
        Disable-WindowsAudio
    write-host -ForegroundColor Green "Done stopping and disabling the Windows Audio service"
    write-host "===================="

## Call function to disable shutdown event tracker
    Write-host -ForegroundColor Green "Setting registry to disable the shutdown event tracker"
        Disable-ShutdownEventTracker
    write-host -ForegroundColor Green "Done setting registry to disale the shutdown event tracker"
    write-host "===================="

## Call function to disable the WPAD service
    Write-host -ForegroundColor Green "Setting registry to disable the WPAD service"
        disable-wpadService
    write-host -ForegroundColor Green "Done setting registry to disable the WPAD service"
    write-host "===================="

## Call function to disable sidechannel vulns
    Write-host -ForegroundColor Green "Setting registry to disable sidechannel vulns"
        disable-sideChanVulns
    write-host -ForegroundColor Green "Done setting registry to disable sidechannel vulns"
    write-host "===================="

## Call function to set LM Hash compatibility
    Write-host -ForegroundColor Green "Setting registry to set LM Hash compatibility"
        set-lmhash
    write-host -ForegroundColor Green "Done setting registry to set LM Hash compatibility"
    write-host "===================="

## Call function to set CVE-2017-8529
    Write-host -ForegroundColor Green "Setting registry to mitigate CVE-2017-8529"
        set-cve20178529
    write-host -ForegroundColor Green "Done setting registry to mitigate CVE-2017-8529"
    write-host "===================="

## Call function to disable SMBv1
    write-host -ForegroundColor Green "Disabling SMBv1 and requiring SMB signatures"
        Disable-SMBv1
    write-host -f green "Done disabling SMBv1 and requiring SMB signatures"
    write-host "===================="

## Call function to disable NetBIOS and WINS
    write-host -ForegroundColor Green "Disabling NetBIOS and WINS"
        Disable-NetBIOSWins
    write-host -f green "Done disabling NetBIOS and WINS"
    write-host "===================="

## Call function to restrict anonymous enumeration
    write-host -ForegroundColor Green "Disabling anonymous enumeration"
        enable-restrictAnonEnum
    write-host -f green "Done disabling anonymous enumeration"
    write-host "===================="

## Call function to disable IPv6
    write-host -ForegroundColor Green "Disabling IPv6"
        disable-ipv6
    write-host -f green "Done disabling IPv6"
    write-host "===================="

## Call function to stop and disable Computer browser service
    write-host -ForegroundColor Green "Stopping and disabling the Windows Computer Browser service"
        Disable-BrowserService
    write-host -ForegroundColor Green "Done stopping and disabling the Windows Computer Browser service"
    write-host "===================="

## Call function to enable and set to automatic Windows Update Service
    write-host -ForegroundColor Green "Starting and setting to Automatic the Windows Update service"
        enable-WindowsUpdateService
    write-host -ForegroundColor Green "Done starting and setting to Automatic the Windows Update service"
    write-host "===================="

    ## Call function to stop and disable Xbox services
write-host -ForegroundColor Green "Stopping and disabling Xbox services"
        disable-XboxServices
        write-host -ForegroundColor Green "Done stopping and disabling Xbox services"
        write-host "===================="
    }

########################################
#### Application installation check ####
########################################
function Confirm-AppsAndSettings
    {
# write-host "=== Application Installation Check ==="

# Labtech
    $LTsvc = get-service LTservice
    $LTswd = get-service LTSvcMon
    $LTsvcMode = Get-WmiObject -Class Win32_Service -Property StartMode -Filter "Name='LTservice'"
    $LTswdMode = Get-WmiObject -Class Win32_Service -Property StartMode -Filter "Name='LTSvcMon'"

## Existence / status checks
    If (!$LTsvc)
        { write-host -f Red $LTsvc.Name "does not exist."}
    elseif ($LTsvc.status -eq "Running")
        { write-host -f Green $LTsvc.displayname $LTsvc.status}
    else { write-host -f Red   $LTsvc.displayname " not running"}

    If (!$LTswd)
        { write-host -f Red $LTswd.Name "does not exist."}
    elseif ($LTswd.Status -eq "Running")
        { write-host -f Green $LTswd.displayname $LTswd.status}
    else { write-host -f Red   $LTswd.displayname " not running"}

## Startup type checks
    If ($LTsvcMode.startmode)
        {write-host -f Green "Labtech service start mode: " -NoNewline; write-host -f cyan $LTsvcMode.StartMode}
    If ($LTswdMode.startmode)
        {write-host -f Green "Labtech service start mode: " -NoNewline; write-host -f cyan $LTswdMode.StartMode}
    write-host "===================="

#####################################
#### Service configuration Check ####
#####################################
## If service is running, output will state so
## If service is not running, output will state as such and the service status
## If Service does not exist, output will state as such
## If a startmode exists output will state the start mode

write-host "=== Service Configuration Check ===="


## services we want to be running
$servicesR = @("snmp","wuauserv")

## services we want to be running
foreach ($serviceR in $servicesR)
{
    $serviceProperties = get-service $servicer -ErrorAction SilentlyContinue
    $serviceMode = get-WmiObject -class Win32_Service -property StartMode -filter "name='$servicer'"

    if ($serviceProperties)
    {
        ## make sure the service is running
            if ($serviceProperties.status -eq 'Running') {write-host -f green $serviceProperties.displayname -NoNewline; write-host " service is running."}
            else {write-host -f Yellow $serviceProperties.DisplayName -nonewline; write-host " service is not running. Service status is: " -NoNewline; write-host -f cyan $serviceProperties.status}

        ## make sure the service  is set to autorun
            if ($serviceMode.startmode -eq 'Auto') {write-host -f green $serviceProperties.displayname -NoNewline; write-host " startup type:" $serviceMode.startmode}
            else {write-host -f red $serviceProperties.displayname -NoNewline; write-host " startup type:" $serviceMode.startmode}
    
    }

    else {write-host -f Red $serviceR -NoNewline; write-host " service does not exist"}

    write-host "===================="
}

## services we want stopped
$servicesS = @("spooler","AudioSRV","browser","WinHttpAutoProxySvc","XblGameSave","XblAuthManager")

## services we want stopped
foreach ($serviceS in $servicesS)
{
    $serviceProperties = get-service $serviceS -ErrorAction SilentlyContinue
    $serviceMode = get-WmiObject -class Win32_Service -property StartMode -filter "name='$serviceS'"
    
    if ($serviceProperties) 
    {
        ## make sure services are stopped
            if ($serviceProperties.status -eq 'Stopped') {write-host -f green $serviceProperties.DisplayName -NoNewline; write-host " service is stopped"}
            else {write-host -f Yellow $serviceProperties.DisplayName -nonewline; write-host " service is running. Service status is: " -NoNewline; write-host -f cyan $serviceProperties.status}

        ## make sure the service isn't set to autorun
            if ($serviceMode.startmode) {write-host -f green $serviceProperties.displayname -NoNewline; write-host " startup type:" $serviceMode.startmode}
            else {write-host -f red $serviceProperties.displayname -NoNewline; write-host " startup type:" $serviceMode.startmode}
    }
    
    else {write-host -f Red $serviceR -NoNewline; write-host " service does not exist"}
    
    write-host "===================="
}
    


# Shutdown tracker
    $EvtTrackerKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Reliability"
    $ReasonUICode = Get-ItemProperty -Path $EvtTrackerKey

    If ($ReasonUICode.ShutdownReasonUI -eq 0)
        {write-host -ForegroundColor Green "Event Tracker Disabled"}
    If ($ReasonUICode.ShutdownReasonUI -ne 0 -or (!($ReasonUICode)))
        {write-host -f Red "Shutdown tracker not disabled"}
    }
function byebye
    {
        Clear-Host
        write-host "Have a nice day." `n
        exit
    }

#####################
##### Main Menu #####
#####################

## The main menu has 3 selections, plus exit
## once a selection is made, the user is taken to a summary / confirmation screen that will allow them to confirm or go back to the main menu
## if they confirm, then the selected function is executed
## after the execution, there is a selection to go to main menu, run again or exit

function Invoke-Menu {
Clear-Host
[int]$menuChoice = 0
while ( $menuChoice -lt 1 -or $menuChoice -gt 4 )
    {
        write-host ""
        Write-host " Main Menu"
        write-host ""
        write-host "Choose an option:"
        Write-host -ForegroundColor Yellow "  1. Install standard software"
        Write-host -ForegroundColor Yellow "  2. Configure system settings"
        Write-host -ForegroundColor Cyan   "  3. Check applications and settings"
        Write-host -ForegroundColor Green  "  4. Exit`
        "
        [Int]$menuChoice = read-host "Option" 
    }

Switch( $menuChoice )
{
    1{
    write-host ""
    write-host "Continuing will install the following applications:"
    write-host -ForegroundColor Green "`
        LabTech`
        "

        $value = read-host "Do you want to continue? (Y/N)"
        Switch ($value)
            {
            'Y' {Install-StandardSoftware
                #start of sub-menu after task is completed
                write-host -foregroundcolor Green "Application installation complete"
                write-host "     1. Return to Main Menu"
                write-host "     2. Run again"
                write-host "     3. Exit"
                $anykey = read-host "Selection"
                Switch ($anykey)
                    {
                    '1' {Invoke-Menu}
                    '2' {Install-StandardSoftware
                         Invoke-Menu}
                    '3' {byebye}
                    default {Invoke-Menu}}
                    }
            default {Invoke-Menu}
            }
        }
    2{
    write-host ""
    write-host "Continuing will configure the following system settings:"
    write-host -ForegroundColor Green "`
        Install SNMP Service (Server OS only)`
        Add the following groups to local admins`
                $groups`
        Enable the following settings:`
	        Visual effects for best performance`
	        Folder preferences to view hidden files, show file extentions`
	        Clear page file at shutdown`
	        Enable RDP and Network Level Authentication`
            Windows Update Service (required for altiris)`
            Set LM Hash compatibility`
        Stop and disable the following services:`
	        Print Spooler`
	        Windows Audio`
	        Network Computer Browser`
            WPAD`
            SMBv1`
            NetBIOS`
            WINS`
            IPv6`
        Disable the following settings:`
            IE ESC for admins`
	        Drive indexing on C`
	        RDP Printer mapping`
	        Shutdown Event Tracker`
            Sidechannel vulnerabilities`
            mitigate CVE-2017-8529`
            require SMB signatures`
            restrict anonymous enumeration`
            "
        $value = read-host "Do you want to continue? (Y/N)"
        Switch ($value)
            {
            'Y' {Invoke-Settings
                    write-host -ForegroundColor Green "System setting configuration complete"
                    write-host "     1. Return to Main Menu"
                    write-host "     2. Run again"
                    write-host "     3. Exit"
                    $anykey = read-host "Selection"
                    Switch ($anykey)
                        {
                        '1' {Invoke-Menu}
                        '2' {Invoke-Settings
                             Invoke-Menu}
                        '3' {byebye}
                        default {Invoke-Menu}} #this was the last line of the sub-menu after task completed
                        }
            default {Invoke-Menu}
            }
        }

    3{
    write-host ""
    write-host "Continuing will check the following applications and settings"
    write-host -ForegroundColor Green "`
        Confirm application installation:`
	        Labtech`
        Confirm service settings:`
	        SNMP`
	        Print Spooler`
	        Audio Service`
	        Network Computer Browser`
	        Windows Update`
            "
        $value = read-host "Do you want to continue? (Y/N)"
        Switch ($value)
            {
            'Y' {Confirm-AppsAndSettings
                    #start of sub-menu after task is completed
                    write-host -ForegroundColor Green "Application and setting check complete"
                    write-host "     1. Return to Main Menu"
                    write-host "     2. Run again"
                    write-host "     3. Exit"
                    $anykey = read-host "Selection"
                    Switch ($anykey)
                    {
                    '1' {Invoke-Menu}
                    '2' {Confirm-AppsAndSettings
                         Invoke-Menu}
                    '3' {byebye}
                    default {Invoke-Menu}
                } #this was the last line of the sub-menu after task completed
            }
              default {Invoke-Menu}
        }
    }

    4{
    write-host "Exiting..."
    byebye
            }
        } 
    }
Invoke-Menu
