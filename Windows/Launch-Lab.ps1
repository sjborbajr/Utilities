### Get variables for Date and set logfile append name
  $ScriptName = ($MyInvocation.MyCommand.Name).Replace(".ps1","")
  $DeviceFile = "$PSScriptRoot\$ScriptName.txt"
  $FileNameAppend= "_"+(get-date -UFormat '%m%d%Y')+".log"
  $RegistryPath = "HKCU:\Software\SimonTatham\PuTTY\Sessions\$ScriptName"
    $Temp = Get-Item -Path $RegistryPath -ErrorAction SilentlyContinue
    if (-not $Temp) { $Temp = New-Item -Path $RegistryPath -Force }


### Set Common Putty Session Settings
  $RegistryValues = @(@()
                     ,(@("LogFileClash",       "DWORD", 0 ))
                     ,(@("LogFlush",           "DWORD", 1 ))
                     ,(@("SSHLogOmitPasswords","DWORD", 1 ))
                     ,(@("SSHLogOmitData",     "DWORD", 0 ))
                     ,(@("NoRemoteWinTitle",   "DWORD", 1 ))
                     ,(@("NoRemoteClearScroll","DWORD", 1 ))
                     )
  foreach ($RegistryValue in $RegistryValues) {
    New-ItemProperty -Path $RegistryPath -Name $RegistryValue[0] -Value $RegistryValue[2] -PropertyType $RegistryValue[1] -Force | Out-Null
  }

### Read file in folder for ips and session names to launch
  # skip empty or adresses starting with ;
  $Devices = Import-Csv -Delimiter "`t" $DeviceFile | % { if ( $_.Address.Length -gt 1 ) { if ($_.Address.Substring(0,1) -ne ";" ) { $_ }  } }

# Prompt for sessions to launch and loop till closed/canceled
$LaunchDevices = $Devices | Out-GridView -OutputMode Multiple
While ($LaunchDevices) {
  foreach ($Device in $LaunchDevices) {
     $LogFile = $PSScriptRoot+"\"+$Device.Name+$FileNameAppend
     if ($Device.UserName.Length -gt 1) {
       $Address = $Device.UserName+"@"+$Device.Address
     } Elseif ($Device.UserName -eq 'none' ) {
       $Address = $Device.Address
     } Else {
       $Address = "$env:UserName@"+$Device.Address
     }
     $RegistryValues = @(@()
                       ,(@("HostName",   "String",$Address  ))
                       ,(@("LogFileName","String",$LogFile         ))
                       ,(@("WinTitle",   "String",$Device.Name     ))
                       ,(@("PortNumber",  "DWORD",$Device.Port     ))
                       ,(@("Protocol",   "String",$Device.Protocol ))
                       )
     foreach ($RegistryValue in $RegistryValues) {
        New-ItemProperty -Path $RegistryPath -Name $RegistryValue[0] -Value $RegistryValue[2] -PropertyType $RegistryValue[1] -Force | Out-Null
     }
     Start-Process -FilePath "putty.exe" -ArgumentList '-load "LabLaunch"'
     start-sleep -m 200
  }
  $LaunchDevices = $Devices | Out-GridView -OutputMode Multiple
}
