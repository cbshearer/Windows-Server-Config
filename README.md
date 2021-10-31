# Windows-Server-Config
This is a script I have been building and tweaking over several years.

Configure the following services
  1) Enable the Windows Update Service
  2) Stop and disable Print Spooler service
  3) Stop and disable Windows Audio Service
  4) Install SNMP service
  5) Check for, stop and disable Xbox services
  6) Stop and disable Computer Browser service
  7) Disable the WinHTTPAutoProxySvc (to mitigate WPAD vulnerabilities) 
  8) Disable SMBv1
  9) Disable NetBIOS
  10) Disable WINS
  11) Disable IPv6
  
Settings  
  1) Adjust visual performance setting for all users (HKLM key)
  2) Disable Shutdown Event Tracker
  3) Clear page file at shutdown
  4) Disable indexing on c
  5) Disable RDP printer mapping
  6) Enable RDP and set Network Level Authentication
  7) Disable IEESC for Admins (leave enabled for non-admins)
  8) Add domain groups to local Administrators group
  9) Set the folder view to show file extenstions and hidden files and folders (user only preference)
  10) Mitigate CVE-2017-8529
  11) Require SMB signatures
  12) Restrict anonymous enumeration

Installations
  1) Powershell ISE
  2) LabTech application
