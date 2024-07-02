# Optimize Windows Scheduled tasks
Reg.exe Add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t REG_DWORD /d "1" /f 
Reg.exe Add "HKLM\SOFTWARE\Microsoft\Windows\ScheduledDiagnostics" /v "EnabledExecution" /t REG_DWORD /d "0" /f 
Schtasks /Change /TN "\Microsoft\Windows\Application Experience\StartupAppTask" /Disable 
Schtasks /Change /TN "\Microsoft\Windows\Application Experience\AitAgent" /Disable 
Schtasks /Change /TN "\Microsoft\Windows\Application Experience\MareBackup" /Disable 
Schtasks /Change /TN "\Microsoft\Windows\Application Experience\PcaPatchDbTask" /Disable 
Schtasks /Change /TN "\Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable 
Schtasks /Change /TN "\Microsoft\Windows\ApplicationData\CleanupTemporaryState" /Disable 
Schtasks /Change /TN "\Microsoft\Windows\ApplicationData\DsSvcCleanup" /Disable 
Schtasks /Change /TN "\Microsoft\Windows\AppID\SmartScreenSpecific" /Disable 
Schtasks /Change /TN "\Microsoft\Windows\Autochk\Proxy" /Disable 
Schtasks /Change /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable 
Schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyUpload" /Disable 
Schtasks /Change /TN "\Microsoft\Windows\Location\Notifications" /Disable 
Schtasks /Change /TN "\Microsoft\Windows\Location\WindowsActionDialog" /Disable 
Schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitorToastTask" /Disable 
Schtasks /Change /TN "\Microsoft\Windows\SettingSync\BackgroundUploadTask" /Disable 
Schtasks /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Uploader" /Disable 
Schtasks /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable 
Schtasks /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable 
Schtasks /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable 
Schtasks /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\BthSQM" /Disable 
Schtasks /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\HypervisorFlightingTask" /Disable 
Schtasks /Change /TN "\Microsoft\Windows\DiskFootprint\Diagnostics" /Disable 
Schtasks /Change /TN "\Microsoft\Windows\Feedback\Siuf\DmClient" /Disable 
Schtasks /Change /TN "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" /Disable 
Schtasks /Change /TN "\Microsoft\Windows\Maintenance\WinSAT" /Disable 
Schtasks /Change /TN "\Microsoft\Windows\Maps\MapsToastTask" /Disable 
Schtasks /Change /TN "\Microsoft\Windows\Maps\MapsUpdateTask" /Disable 
Schtasks /Change /TN "\Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser" /Disable 
Schtasks /Change /TN "\Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable 
Schtasks /Change /TN "\Microsoft\Windows\Offline Files\Background Synchronization" /Disable 
Schtasks /Change /TN "\Microsoft\Windows\Offline Files\Logon Synchronization" /Disable 
Schtasks /Change /TN "\Driver Easy Scheduled Scan" /Disable 
Schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitor" /Disable 
Schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyRefresh" /Disable 
Schtasks /Change /TN "\Microsoft\Windows\SpacePort\SpaceAgentTask" /Disable 
Schtasks /Change /TN "\Microsoft\Windows\SpacePort\SpaceManagerTask" /Disable 
Schtasks /Change /TN "\Microsoft\Windows\Speech\SpeechModelDownloadTask" /Disable 
Schtasks /Change /TN "\Microsoft\Windows\User Profile Service\HiveUploadTask" /Disable 
Schtasks /Change /TN "\Microsoft\Windows\Wininet\CacheTask" /Disable 
Schtasks /Change /TN "\Microsoft\Windows\Work Folders\Work Folders Logon Synchronization" /Disable 
Schtasks /Change /TN "\Microsoft\Windows\Work Folders\Work Folders Maintenance Work" /Disable 
Schtasks /Change /TN "\Microsoft\Windows\Workplace Join\Automatic-Device-Join" /Disable 
Schtasks /Change /TN "\Microsoft\Windows\Windows Media Sharing\UpdateLibrary" /Disable 
Schtasks /Change /TN "\Microsoft\Windows\SettingSync\BackupTask" /Disable 
Schtasks /Change /TN "\Microsoft\Windows\SettingSync\NetworkStateChangeTask" /Disable 
Schtasks /Change /TN "\Microsoft\Windows\Windows Filtering Platform\BfeOnServiceStartTypeChange" /Disable 
Schtasks /Change /TN "\Microsoft\Windows\File Classification Infrastructure\Property Definition Sync" /Disable 
Schtasks /Change /TN "\Microsoft\Windows\Management\Provisioning\Logon" /Disable 
Schtasks /Change /TN "\Microsoft\Windows\NlaSvc\WiFiTask" /Disable 
Schtasks /Change /TN "\Microsoft\Windows\WCM\WiFiTask" /Disable 
Schtasks /Change /TN "\Microsoft\Windows\Ras\MobilityManager" /Disable 
