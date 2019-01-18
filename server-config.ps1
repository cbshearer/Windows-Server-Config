## Windows Server 2008 R2 Build Checklist
## Chris Shearer October 2015 - December 2018

## replace 'your.local' with your AD domain.


## Set the users or groups that will be added as local admins here
## DON'T FORGET COMMAS after all entries except the last.
	$groups = ( 
                "your.local\domain admins",
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

## Function to install SNMP Service Server OS only
    function Install-SNMPService
        {
            Import-Module ServerManager
            Get-WindowsFeature -name *SNMP* | Add-WindowsFeature -includeallsubfeature
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

## Function to disable Windows Computer Browser Service
    function disable-browserservice
        {
            Stop-Service -Name browser
            Set-Service  -Name browser -StartupType Disabled
        }

## Function to enable Windows Update Service
    function enable-WindowsUpdateService
        {
            Set-Service   -Name wuauserv -StartupType automatic
            Start-Service -Name wuauserv
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
function Configure-settings
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
function Check-AppsAndSettings
    {
# write-host "=== Application Installation Check ==="

#Labtech
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
# SNMP Service
$SNMPSvc = Get-Service snmp -ErrorAction SilentlyContinue
$SNMPmode = Get-WmiObject -Class Win32_Service -Property StartMode -Filter "Name='snmp'"

If (!($SNMPSvc))
    {write-host -ForegroundColor Red "SNMP service does not exist."}
elseif ($SNMPSvc.status -eq 'Running')
    {write-host -ForegroundColor Green "SNMP service is $SNMPSvc.status."}
elseif ($SNMPSvc.status -ne 'Running')
    {write-host -ForegroundColor Yellow "SNMP service not running."}

If ($SNMPmode.startmode)
    {write-host -ForegroundColor Green "SNMP service start mode: " -nonewLine; write-host -f cyan $SNMPMode.startmode}
write-host "===================="

# Spooler Service
$SpoolSVC = Get-Service spooler -ErrorAction SilentlyContinue
$SpoolMode = Get-WmiObject -Class Win32_Service -Property StartMode -Filter "Name='spooler'"

If ($SpoolSVC.status -eq 'Stopped')
    {write-host -ForegroundColor Green "Spooler service is not running."}
If ($SpoolSVC.status -ne 'Stopped') 
    {write-host -ForegroundColor Yellow "Spooler service is not stopped. Service status is: " -NoNewLine; write-host -f cyan $SpoolSVC.status}
If (!($SpoolSVC))
    {write-host -ForegroundColor Green "Spooler service does not exist."}
If ($SpoolMode.startmode)
    {write-host -ForegroundColor Green "Spooler service start mode: " -NoNewLine; write-host -f Cyan $SpoolMode.startmode}
write-host "===================="

# Audio Service
$AudioSVC = Get-Service AudioSRV -ErrorAction SilentlyContinue
$AudioMode = Get-WmiObject -Class Win32_Service -Property StartMode -Filter "Name='AudioSRV'"

If ($AudioSVC.status -eq 'Stopped')
    {write-host -ForegroundColor Green "Audio service is not running."}
If ($AudioSVC.status -ne 'Stopped') 
    {write-host -ForegroundColor Yellow "Audio service is not stopped. Service status is: " -NoNewLine; write-host -f cyan $AudioSVC.status}
If (!($AudioSVC))
    {write-host -ForegroundColor Green "Audio service does not exist."}
If ($AudioMode.startmode)
    {write-host -ForegroundColor Green "Audio service start mode: " -NoNewLine; write-host -f Cyan $AudioMode.startmode}
write-host "===================="

# Computer Browser Service
$BrowserSVC = Get-Service Browser -ErrorAction SilentlyContinue
$BrowserMode = Get-WmiObject -Class Win32_Service -Property StartMode -Filter "Name='Browser'"

If ($BrowserSVC.status -eq 'Stopped')
    {write-host -ForegroundColor Green "Browser service is not running."}
If ($BrowserSVC.status -ne 'Stopped') 
    {write-host -ForegroundColor Yellow "Browser service is not stopped. Service status is: " -NoNewLine; write-host -f cyan $BrowserSVC.status}
If (!($BrowserSVC))
    {write-host -ForegroundColor Green "Browser service does not exist."}
If ($BrowserMode.startmode)
    {write-host -ForegroundColor Green "Browser service start mode: " -NoNewLine; write-host -f Cyan $BrowserMode.startmode}
write-host "===================="

# Windows Update Service
$WUAUSVC = Get-Service wuauserv -ErrorAction SilentlyContinue
$WUAUMode = Get-WmiObject -Class Win32_Service -Property StartMode -Filter "Name='wuauserv'"

If ($WUAUSVC.status -eq 'running')
    {write-host -ForegroundColor Green "Windows Update service is running."}
If ($WUAUSVC.status -ne 'running') 
    {write-host -ForegroundColor Yellow "Windows Update service is not running. Service status is: " -NoNewLine; write-host -f cyan $BrowserSVC.status}
If (!(!($WUAUSVC)))
    {write-host -ForegroundColor Green "Windows Update service exists."}
If ($WUAUMode.startmode)
    {write-host -ForegroundColor Green "Windows Update service start mode: " -NoNewLine; write-host -f Cyan $WUAUMode.startmode}
write-host "===================="
    }

# Shutdown tracker
$EvtTrackerKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Reliability"
$ReasonUICode = Get-ItemProperty -Path $EvtTrackerKey

If ($ReasonUICode.ShutdownReasonUI -eq 0)
    {write-host -ForegroundColor Green "Event Tracker Disabled"}
If ($ReasonUICode.ShutdownReasonUI -ne 0 -or (!($ReasonUICode)))
    {write-host -f Red "Shutdown tracker not disabled"}

function byebye
    {
        cls
        write-host "Have a nice day.`
        "
        exit
    }

#####################
##### Main Menu #####
#####################

## The main menu has 3 selections, plus exit
## once a selection is made, the user is taken to a summary / confirmation screen that will allow them to confirm or go back to the main menu
## if they confirm, then the selected function is executed
## after the execution, there is a selection to go to main menu, run again or exit

function Main-Menu {
cls
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
                    '1' {main-menu}
                    '2' {Install-StandardSoftware
                         main-menu}
                    '3' {byebye}
                    default {main-menu}} #this was the last line of the sub-menu after task completed
                    }
            default {main-menu}
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
        Stop and disable the following services:`
	        Print Spooler`
	        Windows Audio`
	        Network Computer Browser`
        Disable the following settings:`
            IE ESC for admins`
	        Drive indexing on C`
	        RDP Printer mapping`
	        Shutdown Event Tracker`
            "
        $value = read-host "Do you want to continue? (Y/N)"
        Switch ($value)
            {
            'Y' {Configure-settings
                    write-host -ForegroundColor Green "System setting configuration complete"
                    write-host "     1. Return to Main Menu"
                    write-host "     2. Run again"
                    write-host "     3. Exit"
                    $anykey = read-host "Selection"
                    Switch ($anykey)
                        {
                        '1' {main-menu}
                        '2' {Configure-settings
                             Main-Menu}
                        '3' {byebye}
                        default {main-menu}} #this was the last line of the sub-menu after task completed
                        }
            default {main-menu}
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
            'Y' {Check-AppsAndSettings
                    #start of sub-menu after task is completed
                    write-host -ForegroundColor Green "Application and setting check complete"
                    write-host "     1. Return to Main Menu"
                    write-host "     2. Run again"
                    write-host "     3. Exit"
                    $anykey = read-host "Selection"
                    Switch ($anykey)
                    {
                    '1' {main-menu}
                    '2' {Check-AppsAndSettings
                         Main-Menu}
                    '3' {byebye}
                    default {main-menu}
                } #this was the last line of the sub-menu after task completed
            }
              default {main-menu}
        }
    }

    4{
    write-host "Exiting..."
    byebye
            }
        } 
    }
Main-Menu
