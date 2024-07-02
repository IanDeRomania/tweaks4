# Optimize Memory Management
Fsutil behavior set memoryusage 2 > $null 2>&1
Reg.exe Add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "SystemPages" /t REG_DWORD /d "4294967295" /f > $null 2>&1
Reg.exe Add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d "1" /f > $null 2>&1
Reg.exe Add "HKLM\System\CurrentControlSet\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "4294967295" /f > $null 2>&1
Try { Disable-MMAgent -MemoryCompression  > $null 2>&1 } Catch {}
Try { Disable-MMAgent -PageCombining  > $null 2>&1 } Catch {}
Reg.exe Add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePageCombining" /t REG_DWORD /d "1" /f > $null 2>&1
Reg.exe Add "HKLM\System\CurrentControlSet\Control\Session Manager" /v "HeapDeCommitFreeBlockThreshold" /t REG_DWORD /d "262144" /f > $null 2>&1
& "$PWD\PowerRun.exe" /SW:0 powershell.exe -Command "Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' | Where-Object { `$_.Name -notmatch 'Xbl|Xbox|BITS' } | ForEach-Object { `$path = 'SYSTEM\CurrentControlSet\Services\' + `$_.PSChildName; `$found = Get-ItemProperty -Path "REGISTRY::`$_"; if (`$null -ne `$found.Start) { Reg.exe Add "`$_" /v "SvcHostSplitDisable" /t REG_DWORD /d "1" /f > `$Null 2>&1 } }; exit"
