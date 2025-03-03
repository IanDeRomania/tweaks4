Enable-NetAdapterQos -Name "*" -ErrorAction SilentlyContinue
Disable-NetAdapterIPsecOffload -Name "*" -ErrorAction SilentlyContinue
Reg Add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxConnectRetransmissions" /t REG_DWORD /d "1" /f > $null 2>&1
Reg Add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "1" /f > $null 2>&1
Reg Add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "32" /f > $null 2>&1
Reg Add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DelayedAckFrequency" /t REG_DWORD /d "1" /f > $null 2>&1
Reg Add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DelayedAckTicks" /t REG_DWORD /d "1" /f > $null 2>&1
Reg Add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "CongestionAlgorithm" /t REG_DWORD /d "1" /f > $null 2>&1
Reg Add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MultihopSets" /t REG_DWORD /d "15" /f > $null 2>&1
Reg Add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SackOpts" /t REG_DWORD /d "0" /f > $null 2>&1
Reg Add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d "30" /f > $null 2>&1
Reg Add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "SizReqBuf" /t REG_DWORD /d "17424" /f > $null 2>&1
Reg Add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "Size" /t REG_DWORD /d "3" /f > $null 2>&1
Reg Add "HKLM\Software\Policies\Microsoft\Windows\Psched" /v "TimerResolution" /t REG_DWORD /d "1" /f > $null 2>&1
Reg Add "HKLM\System\CurrentControlSet\Services\Tcpip\QoS" /v "Do not use NLA" /t REG_DWORD /d "1" /f > $null 2>&1
Reg Add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NegativeCacheTime" /t REG_DWORD /d "0" /f > $null 2>&1
Reg Add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NegativeSOACacheTime" /t REG_DWORD /d "0" /f > $null 2>&1
Reg Add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NetFailureCacheTime" /t REG_DWORD /d "0" /f > $null 2>&1
Reg Add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "EnableAutoDoh" /t REG_DWORD /d "2" /f > $null 2>&1
Reg Add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "FastSendDatagramThreshold" /t REG_DWORD /d "64000" /f > $null 2>&1
Reg Add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "DoNotHoldNicBuffers" /t REG_DWORD /d "1" /f > $null 2>&1
Reg Add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "DisableRawSecurity" /t REG_DWORD /d "1" /f > $null 2>&1
Reg Add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "NonBlockingSendSpecialBuffering" /t REG_DWORD /d "1" /f > $null 2>&1
Reg Add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "IgnorePushBitOnReceives" /t REG_DWORD /d "1" /f > $null 2>&1
Reg Add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "DynamicSendBufferDisable" /t REG_DWORD /d "1" /f > $null 2>&1
Reg Add "HKLM\Software\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f > $null 2>&1
Reg Add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v "DisabledComponents" /t REG_DWORD /d "1" /f > $null 2>&1
& "$PWD\PowerRun.exe" /SW:0 cmd.exe /k 'Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Services\BITS" /v "SvcHostSplitDisable" /t REG_DWORD /d "0" /f & exit'
$networkCardLines = reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards" /f "ServiceName" /s | Select-String -Pattern "ServiceName"
foreach ($line in $networkCardLines) {
    $serviceName = $line -split '\s+' | Select-Object -Last 1
    Reg Add `"HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$serviceName`" /v `"TCPNoDelay`" /t Reg_DWORD /d "1" /f > $null 2>&1
    Reg Add `"HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$serviceName`" /v `"TcpAckFrequency`" /t Reg_DWORD /d "1" /f > $null 2>&1
    Reg Add `"HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$serviceName`" /v `"TcpDelAckTicks`" /t Reg_DWORD /d "0" /f > $null 2>&1
    Reg Add `"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$serviceName`" /v `"TcpInitialRTT`" /d "300" /t REG_DWORD /f > $null 2>&1
    Reg Add `"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$serviceName`" /v `"UseZeroBroadcast`" /d "0" /t REG_DWORD /f > $null 2>&1
    Reg Add `"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$serviceName`" /v `"DeadGWDetectDefault`" /d "1" /t REG_DWORD /f > $null 2>&1
}
