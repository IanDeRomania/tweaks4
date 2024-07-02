Powercfg /setacvalueindex scheme_current 2a737441-1930-4402-8d77-b2bebba308a3 d4e98f31-5ffe-4ce1-be31-1b38b384c009 0 > $null 2>&1
Powercfg /setacvalueindex scheme_current 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0 > $null 2>&1
Powercfg /setdcvalueindex scheme_current 2a737441-1930-4402-8d77-b2bebba308a3 d4e98f31-5ffe-4ce1-be31-1b38b384c009 0 > $null 2>&1
Powercfg /setdcvalueindex scheme_current 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0 > $null 2>&1

$settings = @(
	"AllowIdleIrpInD3",
	"D3ColdSupported",
	"DeviceSelectiveSuspended",
	"EnableIdlePowerManagement",
	"EnableSelectiveSuspend",
	"EnhancedPowerManagementEnabled",
	"IdleInWorkingState",
  	"SelectiveSuspendEnabled",
	"SelectiveSuspendOn",
	"WaitWakeEnabled",
	"WakeEnabled",
	"WdfDirectedPowerTransitionEnable"
)

foreach ($setting in $settings) {
	$registryPaths = reg query "HKLM\SYSTEM\CurrentControlSet\Enum" /s /f $setting | Where-Object { $_ -match "HKEY" }
	foreach ($path in $registryPaths) {
		Reg.exe Add "$path" /v "$setting" /t REG_DWORD /d "0" /f > $null 2>&1
	}
}

Get-WmiObject MSPower_DeviceEnable -Namespace root\wmi | ForEach-Object { $_.enable = $false; $_.psbase.put(); } > $null 2>&1

Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Control\Storage" /v "StorageD3InModernStandby" /t REG_DWORD /d "0" /f > $null 2>&1

Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device" /v "IdlePowerMode" /t REG_DWORD /d "0" /f > $null 2>&1

Unregister-ScheduledTask -TaskName "DisablePowerSaving" -Confirm:$false -ErrorAction SilentlyContinue
$action = New-ScheduledTaskAction -Execute "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument '-WindowStyle hidden Get-WmiObject MSPower_DeviceEnable -Namespace root\wmi | ForEach-Object { $_.enable = $false; $_.psbase.put(); }'
$stateChangeTrigger = Get-CimClass `
    -Namespace ROOT\Microsoft\Windows\TaskScheduler `
    -ClassName MSFT_TaskSessionStateChangeTrigger
$onUnlockTrigger = New-CimInstance `
    -CimClass $stateChangeTrigger `
    -Property @{
        StateChange = 8  # TASK_SESSION_STATE_CHANGE_TYPE.TASK_SESSION_UNLOCK (taskschd.h)
    } `
    -ClientOnly
$triggerLogon = New-ScheduledTaskTrigger -AtLogon
$triggerLogon.Delay = 'PT10S'
$onUnlockTrigger.Delay = 'PT10S'
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries 
$task = New-ScheduledTask -Action $action -Trigger $triggerLogon, $onUnlockTrigger -Settings $settings
Register-ScheduledTask -TaskName "DisablePowerSaving" -InputObject $task -User "NT AUTHORITY\SYSTEM" | Out-Null 
powercfg /setactive scheme_current

wevtutil.exe set-log "Microsoft-Windows-SleepStudy/Diagnostic" /e:false > $null 2>&1
wevtutil.exe set-log "Microsoft-Windows-Kernel-Processor-Power/Diagnostic" /e:false > $null 2>&1
wevtutil.exe set-log "Microsoft-Windows-UserModePowerService/Diagnostic" /e:false > $null 2>&1

