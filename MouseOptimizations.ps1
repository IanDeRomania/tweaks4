# Mouse Optimizations
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class DPI {
    [DllImport("User32.dll")]
    public static extern int GetDpiForWindow(IntPtr hwnd);
    
    public static int GetDPI() {
        var hwnd = GetForegroundWindow();
        return GetDpiForWindow(hwnd);
    }

    [DllImport("user32.dll")]
    public static extern IntPtr GetForegroundWindow();
}
"@

$DPI = [DPI]::GetDPI()

$ScalePercentage = switch ($DPI)
{
    96 {"100%"}
    120 {"125%"}
    144 {"150%"}
    192 {"200%"}
    default {"Unknown"}
}

Reg.exe Add "HKCU\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f > $null 2>&1
Reg.exe Add "HKCU\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f > $null 2>&1
Reg.exe Add "HKCU\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f > $null 2>&1
Reg.exe Add "HKCU\Control Panel\Mouse" /v "MouseSensitivity" /t REG_SZ /d "10" /f > $null 2>&1
Reg.exe Add "HKCU\Control Panel\Mouse" /v "SmoothMouseYCurve" /t REG_BINARY /d "0000000000000000000038000000000000007000000000000000A800000000000000E00000000000" /f > $null 2>&1

if ($ScalePercentage -eq "100%") {
    reg add "HKCU\Control Panel\Mouse" /v "SmoothMouseXCurve" /t REG_BINARY /d "0000000000000000C0CC0C0000000000809919000000000040662600000000000033330000000000" /f > $null 2>&1
}

if ($ScalePercentage -eq "125%") {
    reg add "HKCU\Control Panel\Mouse" /v "SmoothMouseXCurve" /t REG_BINARY /d "00000000000000000000100000000000000020000000000000003000000000000000400000000000" /f > $null 2>&1
}

if ($ScalePercentage -eq "150%") {
    reg add "HKCU\Control Panel\Mouse" /v "SmoothMouseXCurve" /t REG_BINARY /d "0000000000000000303313000000000060662600000000009099390000000000C0CC4C0000000000" /f > $null 2>&1
}

if ($ScalePercentage -eq "175%") {
    reg add "HKCU\Control Panel\Mouse" /v "SmoothMouseXCurve" /t REG_BINARY /d "00000000000000006066160000000000C0CC2C000000000020334300000000008099590000000000" /f > $null 2>&1
}

if ($ScalePercentage -eq "200%") {
    reg add "HKCU\Control Panel\Mouse" /v "SmoothMouseXCurve" /t REG_BINARY /d "000000000000000090991900000000002033330000000000B0CC4C00000000004066660000000000" /f > $null 2>&1
}

Reg.exe Add "HKCU\Control Panel\Desktop" /v "LogPixels" /t REG_DWORD /d 96 /f > $null 2>&1
Reg.exe Add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "UseDpiScaling" /t REG_DWORD /d 0 /f > $null 2>&1
Reg.exe Add "HKCU\Control Panel\Desktop" /v "EnablePerProcessSystemDPI" /t REG_DWORD /d 0 /f > $null 2>&1
