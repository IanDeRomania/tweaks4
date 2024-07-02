Powercfg /setacvalueindex scheme_current 2a737441-1930-4402-8d77-b2bebba308a3 d4e98f31-5ffe-4ce1-be31-1b38b384c009 1 > $null 2>&1
Powercfg /setacvalueindex scheme_current 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 1 > $null 2>&1
Powercfg /setdcvalueindex scheme_current 2a737441-1930-4402-8d77-b2bebba308a3 d4e98f31-5ffe-4ce1-be31-1b38b384c009 1 > $null 2>&1
Powercfg /setdcvalueindex scheme_current 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 1 > $null 2>&1
$settings = @(
    "AllowIdleIrpInD3",
    "D3ColdSupported",
    "DeviceSelectiveSuspended",
    "EnableIdlePowerManagement",
    "EnableSelectiveSuspend",
    "EnhancedPowerManagementEnabled",
    "IdleInWorkingState",
    "SelectiveSuspendOn",
    "WaitWakeEnabled",
    "WakeEnabled",
    "WdfDirectedPowerTransitionEnable"
)

foreach ($setting in $settings) {
    $registryPaths = reg query "HKLM\SYSTEM\CurrentControlSet\Enum" /s /f $setting | Where-Object { $_ -match "HKEY" }
    foreach ($path in $registryPaths) {
        Reg.exe Add "$path" /v "$setting" /t REG_DWORD /d "1" /f > $null 2>&1
    }
}

Reg.exe Delete "HKLM\SYSTEM\CurrentControlSet\Control\Storage" /v "StorageD3InModernStandby" /f > $null 2>&1

Reg.exe Delete "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device" /v "IdlePowerMode" /f > $null 2>&1

Get-WmiObject MSPower_DeviceEnable -Namespace root\wmi | ForEach-Object { $_.enable = $true; $_.psbase.put(); } > $null 2>&1
Unregister-ScheduledTask -TaskName "DisablePowerSaving" -Confirm:$false -ErrorAction SilentlyContinue
powercfg /setactive scheme_current

wevtutil.exe set-log "Microsoft-Windows-SleepStudy/Diagnostic" /e:true /q:true > $null 2>&1
wevtutil.exe set-log "Microsoft-Windows-Kernel-Processor-Power/Diagnostic" /e:true /q:true > $null 2>&1
wevtutil.exe set-log "Microsoft-Windows-UserModePowerService/Diagnostic" /e:true /q:true > $null 2>&1

