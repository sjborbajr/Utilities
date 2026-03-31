$MonitorsOff = $false
while(-not $MonitorsOff) {
    if ($MonitorsOff) {
        # Force sleep command (0 = sleep, 1 = force, 0 = disable wake)
        & rundll32.exe powrprof.dll,SetSuspendState 0,1,0
    }

    Start-Sleep -Seconds 10
    $MonitorsOff = (-not (Get-WmiObject -Namespace root\wmi -Class WmiMonitorID).Active -contains $true)
}
