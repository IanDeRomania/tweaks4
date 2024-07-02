& "$env:temp\PowerRun.exe" /SW:0 cmd.exe /k 'Reg.exe Add "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter" /v "ActivationType" /t REG_DWORD /d "0" /f & exit'
taskkill /f /im GameBarPresenceWriter.exe > $null 2>&1
& "$env:temp\PowerRun.exe" /SW:0 cmd.exe /k 'ren "%WinDir%\System32\GameBarPresenceWriter.exe" "GameBarPresenceWriter.exe.old" & exit'
taskkill /f /im gamebar.exe > $null 2>&1
taskkill /f /im GameBarFTServer.exe > $null 2>&1
taskkill /f /im XboxGameBarWidgets.exe > $null 2>&1
taskkill /f /im XboxPcAppFT.exe > $null 2>&1
taskkill /f /im backgroundtaskhost.exe > $null 2>&1
# Get-AppxPackage -allusers Microsoft.XboxGameOverlay | Remove-AppxPackage -ErrorAction SilentlyContinue
# Get-AppxPackage -allusers Microsoft.XboxGamingOverlay | Remove-AppxPackage -ErrorAction SilentlyContinue
Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f > $null 2>&1
Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AudioCaptureEnabled" /t REG_DWORD /d "0" /f > $null 2>&1
Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "CursorCaptureEnabled" /t REG_DWORD /d "0" /f > $null 2>&1
Reg.exe Add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f > $null 2>&1
Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d "0" /f > $null 2>&1
Reg.exe Add "HKCU\Software\Microsoft\GameBar" /v "ShowStartupPanel" /t REG_DWORD /d "0" /f > $null 2>&1
Reg.exe Add "HKCU\Software\Microsoft\GameBar" /v "UseNexusForGameBarEnabled" /t REG_DWORD /d "0" /f > $null 2>&1
Reg.exe Add "HKCU\Software\Microsoft\GameBar" /v "GamePanelStartupTipIndex" /t REG_DWORD /d "3" /f > $null 2>&1
Reg.exe Add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /v "value" /t REG_DWORD /d "0" /f > $null 2>&1
