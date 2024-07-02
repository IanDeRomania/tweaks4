# Optimize Windows Scheduled tasks
Reg.exe Add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t REG_DWORD /d "0" /f 
Reg.exe Add "HKLM\SOFTWARE\Microsoft\Windows\ScheduledDiagnostics" /v "EnabledExecution" /t REG_DWORD /d "1" /f 
Schtasks /Change /TN "\Microsoft\Windows\Application Experience\StartupAppTask" /Enable 
Schtasks /Change /TN "\Microsoft\Windows\Application Experience\AitAgent" /Enable 
Schtasks /Change /TN "\Microsoft\Windows\Application Experience\MareBackup" /Enable 
Schtasks /Change /TN "\Microsoft\Windows\Application Experience\PcaPatchDbTask" /Enable 
Schtasks /Change /TN "\Microsoft\Windows\Application Experience\ProgramDataUpdater" /Enable 
Schtasks /Change /TN "\Microsoft\Windows\ApplicationData\CleanupTemporaryState" /Enable 
Schtasks /Change /TN "\Microsoft\Windows\ApplicationData\DsSvcCleanup" /Enable 
Schtasks /Change /TN "\Microsoft\Windows\AppID\SmartScreenSpecific" /Enable 
Schtasks /Change /TN "\Microsoft\Windows\Autochk\Proxy" /Enable 
Schtasks /Change /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Enable 
Schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyUpload" /Enable 
Schtasks /Change /TN "\Microsoft\Windows\Location\Notifications" /Enable 
Schtasks /Change /TN "\Microsoft\Windows\Location\WindowsActionDialog" /Enable 
Schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitorToastTask" /Enable 
Schtasks /Change /TN "\Microsoft\Windows\SettingSync\BackgroundUploadTask" /Enable 
Schtasks /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Uploader" /Enable 
Schtasks /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Enable 
Schtasks /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Enable 
Schtasks /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Enable 
Schtasks /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\BthSQM" /Enable 
Schtasks /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\HypervisorFlightingTask" /Enable 
Schtasks /Change /TN "\Microsoft\Windows\DiskFootprint\Diagnostics" /Enable 
Schtasks /Change /TN "\Microsoft\Windows\Feedback\Siuf\DmClient" /Enable 
Schtasks /Change /TN "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" /Enable 
Schtasks /Change /TN "\Microsoft\Windows\Maintenance\WinSAT" /Enable 
Schtasks /Change /TN "\Microsoft\Windows\Maps\MapsToastTask" /Enable 
Schtasks /Change /TN "\Microsoft\Windows\Maps\MapsUpdateTask" /Enable 
Schtasks /Change /TN "\Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser" /Enable 
Schtasks /Change /TN "\Microsoft\Windows\NetTrace\GatherNetworkInfo" /Enable 
Schtasks /Change /TN "\Microsoft\Windows\Offline Files\Background Synchronization" /Enable 
Schtasks /Change /TN "\Microsoft\Windows\Offline Files\Logon Synchronization" /Enable 
Schtasks /Change /TN "\Driver Easy Scheduled Scan" /Enable 
Schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitor" /Enable 
Schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyRefresh" /Enable 
Schtasks /Change /TN "\Microsoft\Windows\SpacePort\SpaceAgentTask" /Enable 
Schtasks /Change /TN "\Microsoft\Windows\SpacePort\SpaceManagerTask" /Enable 
Schtasks /Change /TN "\Microsoft\Windows\Speech\SpeechModelDownloadTask" /Enable 
Schtasks /Change /TN "\Microsoft\Windows\User Profile Service\HiveUploadTask" /Enable 
Schtasks /Change /TN "\Microsoft\Windows\Wininet\CacheTask" /Enable 
Schtasks /Change /TN "\Microsoft\Windows\Work Folders\Work Folders Logon Synchronization" /Enable 
Schtasks /Change /TN "\Microsoft\Windows\Work Folders\Work Folders Maintenance Work" /Enable 
Schtasks /Change /TN "\Microsoft\Windows\Workplace Join\Automatic-Device-Join" /Enable 
Schtasks /Change /TN "\Microsoft\Windows\Windows Media Sharing\UpdateLibrary" /Enable 
Schtasks /Change /TN "\Microsoft\Windows\SettingSync\BackupTask" /Enable 
Schtasks /Change /TN "\Microsoft\Windows\SettingSync\NetworkStateChangeTask" /Enable 
Schtasks /Change /TN "\Microsoft\Windows\Windows Filtering Platform\BfeOnServiceStartTypeChange" /Enable 
Schtasks /Change /TN "\Microsoft\Windows\File Classification Infrastructure\Property Definition Sync" /Enable 
Schtasks /Change /TN "\Microsoft\Windows\Management\Provisioning\Logon" /Enable 
Schtasks /Change /TN "\Microsoft\Windows\NlaSvc\WiFiTask" /Enable 
Schtasks /Change /TN "\Microsoft\Windows\WCM\WiFiTask" /Enable 
Schtasks /Change /TN "\Microsoft\Windows\Ras\MobilityManager" /Enable 
