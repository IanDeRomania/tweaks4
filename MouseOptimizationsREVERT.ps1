
Reg.exe Add "HKCU\Control Panel\Mouse" /v "SmoothMouseXCurve" /t REG_BINARY /d "0000000000000000156e000000000000004001000000000029dc0300000000000000280000000000" /f > $null 2>&1
Reg.exe Add "HKCU\Control Panel\Mouse" /v "SmoothMouseYCurve" /t REG_BINARY /d "0000000000000000fd11010000000000002404000000000000fc12000000000000c0bb0100000000" /f > $null 2>&1
Reg.exe Add "HKCU\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "1" /f > $null 2>&1
Reg.exe Add "HKCU\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "6" /f > $null 2>&1
Reg.exe Add "HKCU\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "10" /f > $null 2>&1
Reg.exe Delete "HKCU\Control Panel\Desktop" /v "LogPixels" /f > $null 2>&1
Reg.exe Delete "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "UseDpiScaling" /f > $null 2>&1
Reg.exe Delete "HKCU\Control Panel\Desktop" /v "EnablePerProcessSystemDPI" /f > $null 2>&1
