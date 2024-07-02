& "$env:temp\PowerRun.exe" /SW:0 cmd.exe /k 'Reg.exe Add "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter" /v "ActivationType" /t REG_DWORD /d "1" /f & exit'
taskkill /f /im GameBarPresenceWriter.exe > $null 2>&1
& "$env:temp\PowerRun.exe" /SW:0 cmd.exe /k 'ren "%WinDir%\System32\GameBarPresenceWriter.exe.old" "GameBarPresenceWriter.exe" & exit'
<#
$ProgramFilesPath = [System.Environment]::GetFolderPath('ProgramFiles')
$BarFolders = Get-ChildItem -Path "$ProgramFilesPath\WindowsApps" -Directory -ErrorAction SilentlyContinue | Where-Object {
    $_.Name -match 'Microsoft.XboxGam*'
}

if ($BarFolders) {
    foreach ($BarFolder in $BarFolders) {
        $BarFolderPath = $BarFolder.FullName
        try {
            taskkill /f /im gamebar.exe > $null 2>&1
            taskkill /f /im GameBarFTServer.exe > $null 2>&1
            taskkill /f /im XboxGameBarWidgets.exe > $null 2>&1
            taskkill /f /im XboxPcAppFT.exe > $null 2>&1
            taskkill /f /im backgroundtaskhost.exe > $null 2>&1
            Add-AppxPackage -Register "$BarFolderPath\AppxManifest.xml" -DisableDevelopmentMode > $null 2>&1
        } catch {}
    }
}
#>
Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "1" /f > $null 2>&1
Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AudioCaptureEnabled" /t REG_DWORD /d "1" /f > $null 2>&1
Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "CursorCaptureEnabled" /t REG_DWORD /d "1" /f > $null 2>&1
Reg.exe Add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "1" /f > $null 2>&1
Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d "1" /f > $null 2>&1
Reg.exe Add "HKCU\Software\Microsoft\GameBar" /v "ShowStartupPanel" /t REG_DWORD /d "1" /f > $null 2>&1
Reg.exe Add "HKCU\Software\Microsoft\GameBar" /v "UseNexusForGameBarEnabled" /t REG_DWORD /d "1" /f > $null 2>&1
Reg.exe Delete "HKCU\Software\Microsoft\GameBar" /v "GamePanelStartupTipIndex" /f > $null 2>&1
Reg.exe Add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /v "value" /t REG_DWORD /d "1" /f > $null 2>&1
