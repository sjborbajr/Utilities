################################
Nessus Audit Tool:
################################
Open Powershell as an admin (elevated past uac)

Get script:
wget -Uri "https://raw.githubusercontent.com/sjborbajr/Utilities/master/Windows/Compare-NessusAudit.ps1" -OutFile "Compare-NessusAudit.ps1"

Get Comparison only
.\Compare-NessusAudit.ps1

Then open NessusToConfig_USERNAME_COMPUTERNAME_DATE_TIME.csv

Compare and apply settings:
.\Compare-NessusAudit.ps1 -fix
################################
################################

