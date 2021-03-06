#############################################################################
######  This script will search windows online updates and download/install
######  all available updates and email results to specified address
#############################################################################
$UserNameStr = $env:username
$ComputerNameStr = $env:computername
$TempDir = $env:temp
if ( $TempDir -notmatch "c:" ) {
  $TempDir = "c:\temp"
  if (-not (Test-Path $TempDir)) {
    New-Item $TempDir
  }
}
filter Logging { ("$(Get-Date -Format u): $_") | Tee-Object -Append -FilePath ("$TempDir\Updates.log") }

Write-Output "Starting Script on $ComputerNameStr by $UserNameStr" | Logging

  ### Figure out if WSUS is used and if so, temporarily disable, and store to turn back on later
  $UseWUServer = (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU UseWUServer).UseWUServer
  If ( $UseWUServer -eq 1 ) {
    Set-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU UseWUServer 0
    Restart-Service wuauserv
  }
  
  #Setup Com Object
  $Session = New-Object -ComObject "Microsoft.Update.Session"
  $UpdatesToDownload = New-Object -ComObject "Microsoft.Update.UpdateColl"
  
  #Create sub-Objects
  $Searcher = $Session.CreateUpdateSearcher()
  $Searcher.Online = 'TRUE'
  $Downloader = $Session.CreateUpdateDownloader()
  $Installer = $Session.CreateUpdateInstaller()
  
  ### Check for updates
  Write-Output "Searching for updates..." | Logging
  $NeedUpdates = $Searcher.Search("IsInstalled=0")
  
  ### Continue only if updates were found
  if (($NeedUpdates.Updates.Count -gt 0 ) -and -not ($NeedUpdates.Updates.Count -eq 1 -and $NeedUpdates.Updates.Item(0).Title.Substring(0,39) -eq 'Windows Malicious Software Removal Tool')) {
  
    ### Create download list
    Write-Output "Found updates:" | Logging
    for ( $i=0; $i -le ($NeedUpdates.Updates.Count - 1); $i++ ) {
      $Update = $NeedUpdates.Updates.Item($i)
      $rc = $UpdatesToDownload.Add($Update)
      Write-Output $Update.Title | Logging
    }
	
	### Download updates
    Write-Output "Downloading Updates..." | Logging
    $Downloader.Updates = $UpdatesToDownload
    $rc = $Downloader.Download()
    
    ### Install Updates
    Write-Output "Installing Updates..." | Logging
    $Installer.Updates = $UpdatesToDownload
    $rc = $Installer.Install()
    Write-Output "Install Complete" | Logging
    Write-Output $rc | Logging
	
	### Turn WSUS back on
    If ( $UseWUServer -eq 1 ) {
      Set-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU UseWUServer 1
    }
	
	### Reboot if required
	if ($rc.RebootRequired -eq $true) {
      Restart-Computer -Force
	} else {
	  Restart-Service wuauserv
	}
	
  } else {
    ### No updates, turn WSUS back on and exit
    Write-Output "No updates found" | Logging
    If ( $UseWUServer -eq 1 ) {
      Set-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU UseWUServer 1
	  Restart-Service wuauserv
    }
  }
