@echo off
ping -n 1 %1 > nul || goto newdown
:newup
echo %date:~4% %time% up
:up
timeout /t 1 > nul
ping -n 1 %1 > nul && goto up
:newdown
echo %date:~4% %time% down
:down
ping -n 1 %1 > nul && goto newup
goto down
