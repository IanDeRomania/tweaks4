# General Windows Privacy Optimizations
Reg.exe Delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenOverlayEnabled" /f > $null 2>&1
Reg.exe Delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenEnabled" /f > $null 2>&1
Reg.exe Delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "DisableWindowsSpotlightFeatures" /f > $null 2>&1
Reg.exe Delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "DisableTailoredExperiencesWithDiagnosticData" /f > $null 2>&1
Reg.exe Delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableCloudOptimizedContent" /f > $null 2>&1
Reg.exe Delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" /v "EnableFeeds" /f > $null 2>&1
Reg.exe Delete "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /f > $null 2>&1
Reg.exe Delete "HKLM\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /f > $null 2>&1
Reg.exe Delete "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth" /v "AllowAdvertising" /f > $null 2>&1
Reg.exe Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableAutomaticRestartSignOn" /f > $null 2>&1
Reg.exe Delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /f > $null 2>&1
Reg.exe Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" /v "AllowLinguisticDataCollection" /f > $null 2>&1
Reg.exe Delete "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "AllowInputPersonalization" /f > $null 2>&1
Reg.exe Delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /f > $null 2>&1
Reg.exe Delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /f > $null 2>&1
Reg.exe Delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableCdp" /f > $null 2>&1
Reg.exe Delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableMmx" /f > $null 2>&1
Reg.exe Delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "RSoPLogging" /f > $null 2>&1
Reg.exe Delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\Messaging" /v "AllowMessageSync" /f > $null 2>&1
Reg.exe Delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableCredentialsSettingSync" /f > $null 2>&1
Reg.exe Delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableCredentialsSettingSyncUserOverride" /f > $null 2>&1
Reg.exe Delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableApplicationSettingSync" /f > $null 2>&1
Reg.exe Delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableApplicationSettingSyncUserOverride" /f > $null 2>&1
Reg.exe Delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsActivateWithVoice" /f > $null 2>&1
Reg.exe Delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsSyncWithDevices" /f > $null 2>&1
Reg.exe Delete "HKLM\SOFTWARE\Policies\Microsoft\FindMyDevice" /v "AllowFindMyDevice" /f > $null 2>&1
Reg.exe Delete "HKLM\SOFTWARE\Microsoft\Settings\FindMyDevice" /v "LocationSyncEnabled" /f > $null 2>&1
Reg.exe Delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /f > $null 2>&1
Reg.exe Delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /f > $null 2>&1
Reg.exe Delete "HKCU\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /f > $null 2>&1
Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v "Value" /d "Allow" /f > $null 2>&1
Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /d "Allow" /f > $null 2>&1
Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity" /v "Value" /d "Allow" /f > $null 2>&1
Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\downloadsFolder" /v "Value" /d "Allow" /f > $null 2>&1
Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureProgrammatic\NonPackaged" /v "Value" /d "Allow" /f > $null 2>&1
Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureWithoutBorder\NonPackaged" /v "Value" /d "Allow" /f > $null 2>&1
Reg.exe Add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity" /v "Value" /d "Allow" /f > $null 2>&1
Reg.exe Add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\cellularData" /v "Value" /d "Allow" /f > $null 2>&1
Reg.exe Add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\downloadsFolder" /v "Value" /d "Allow" /f > $null 2>&1
Reg.exe Add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\gazeInput" /v "Value" /d "Allow" /f > $null 2>&1
Reg.exe Add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureProgrammatic" /v "Value" /d "Allow" /f > $null 2>&1
Reg.exe Add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureWithoutBorder" /v "Value" /d "Allow" /f > $null 2>&1
Reg.exe Add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\musicLibrary" /v "Value" /d "Allow" /f > $null 2>&1
Reg.exe Add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v "Value" /d "Allow" /f > $null 2>&1
Reg.exe Add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" /v "Value" /d "Allow" /f > $null 2>&1
Reg.exe Add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" /v "Value" /d "Allow" /f > $null 2>&1
Reg.exe Add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" /v "Value" /d "Allow" /f > $null 2>&1
Reg.exe Add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\calendar" /v "Value" /d "Allow" /f > $null 2>&1
Reg.exe Add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" /v "Value" /d "Allow" /f > $null 2>&1
Reg.exe Add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /v "Value" /d "Allow" /f > $null 2>&1
Reg.exe Add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" /v "Value" /d "Allow" /f > $null 2>&1
Reg.exe Add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" /v "Value" /d "Allow" /f > $null 2>&1
Reg.exe Add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /d "Allow" /f > $null 2>&1
Reg.exe Add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall" /v "Value" /d "Allow" /f > $null 2>&1
Reg.exe Add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" /v "Value" /d "Allow" /f > $null 2>&1
Reg.exe Add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" /v "Value" /d "Allow" /f > $null 2>&1
Reg.exe Add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" /v "Value" /d "Allow" /f > $null 2>&1
Reg.exe Add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /d "Allow" /f > $null 2>&1
Reg.exe Add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" /v "Value" /d "Allow" /f > $null 2>&11
Reg.exe Add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" /v "Value" /d "Allow" /f > $null 2>&1
Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "fAllowToGetHelp" /t REG_DWORD /d "1" /f > $null 2>&1
Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "fAllowFullControl" /t REG_DWORD /d "1" /f > $null 2>&1
Reg.exe Delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /f > $null 2>&1
Reg.exe Delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /f > $null 2>&1
Schtasks /Change /TN "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Enable > $null 2>&1
Reg.exe Delete "HKCU\Software\Microsoft\Windows\Shell\Associations\AppUrlAssociations\share.microsoft.com\AppX6bvervyj4dbgfhwjaqdvcttzfgz9rvpv\UserChoice" /v "Hash" /f > $null 2>&1
Reg.exe Delete "HKCU\Software\Microsoft\Windows\Shell\Associations\AppUrlAssociations\share.microsoft.com\AppX6bvervyj4dbgfhwjaqdvcttzfgz9rvpv\UserChoice" /v "Enabled" /f > $null 2>&1
Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "restrictanonymous" /t REG_DWORD /d "0" /f > $null 2>&1
Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "RestrictAnonymousSAM" /t REG_DWORD /d "1" /f > $null 2>&1
Reg.exe Delete "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /f > $null 2>&1
Reg.exe Delete "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportinfectioninformation" /f > $null 2>&1
Reg.exe Delete "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Experience" /v "AllowTailoredExperiencesWithDiagnosticData" /f > $null 2>&1
Reg.exe Delete "HKCU\Software\Microsoft\Windows\CurrentVersion\PenWorkspace" /v "PenWorkspaceAppSuggestionsEnabled" /f > $null 2>&1
Reg.exe Delete "HKLM\SOFTWARE\Microsoft\DusmSvc\Settings" /v "DisableSystemBucket" /f > $null 2>&1
Reg.exe Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInstrumentation" /f > $null 2>&1
Reg.exe Delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /f > $null 2>&1
Reg.exe Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "MaxTelemetryAllowed" /t REG_DWORD /d "3" /f > $null 2>&1
Reg.exe Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "1" /f > $null 2>&1
Reg.exe Add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "1" /f > $null 2>&1
Reg.exe Delete "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" /v "DiagnosticErrorText" /f > $null 2>&1
Reg.exe Delete "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings" /v "DiagnosticErrorText" /f > $null 2>&1
Reg.exe Delete "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings" /v "DiagnosticLinkText" /f > $null 2>&1
Reg.exe Add "HKLM\Software\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d "1" /f > $null 2>&1
Reg.exe Delete "HKLM\SOFTWARE\Policies\Microsoft\AppV\CEIP" /v "CEIPEnable" /f > $null 2>&1
Reg.exe Delete "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /f > $null 2>&1
Reg.exe Add "HKLM\SOFTWARE\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f > $null 2>&1
Reg.exe Delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /f > $null 2>&1
Reg.exe Delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /f > $null 2>&1
Reg.exe Delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /f > $null 2>&1
Reg.exe Delete "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /f > $null 2>&1
Reg.exe Delete "HKCU\SOFTWARE\Policies\Microsoft\WMDRM" /v "DisableOnline" /f > $null 2>&1
Reg.exe Delete "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Browser" /v "AllowAddressBarDropdown" /f > $null 2>&1
Reg.exe Delete "HKLM\SOFTWARE\Microsoft\Speech_OneCore\Preferences" /v "ModelDownloadAllowed" /f > $null 2>&1
Reg.exe Add "HKCU\Software\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "1" /f > $null 2>&1
Reg.exe Add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "0" /f > $null 2>&1
Reg.exe Add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "0" /f > $null 2>&1
Reg.exe Delete "HKLM\SOFTWARE\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /f > $null 2>&1
Reg.exe Delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /f > $null 2>&1
Reg.exe Delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /f > $null 2>&1
Reg.exe Add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /t REG_DWORD /d "1" /f > $null 2>&1
Reg.exe Delete "HKLM\SOFTWARE\Microsoft\OneDrive" /v "PreventNetworkTrafficPreUserSignIn" /f > $null 2>&1
Reg.exe Delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SpyNetReporting" /f > $null 2>&1
Reg.exe Delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /f > $null 2>&1
Reg.exe Delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "DisableBlockAtFirstSeen" /f > $null 2>&1
Reg.exe Delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "LocalSettingOverrideSpynetReporting" /f > $null 2>&1
Reg.exe Delete "HKLM\SOFTWARE\Policies\Microsoft\Microsoft Antimalware\SpyNet" /v "SpyNetReporting" /f > $null 2>&1
Reg.exe Delete "HKLM\SOFTWARE\Policies\Microsoft\Microsoft Antimalware\SpyNet" /v "LocalSettingOverrideSpyNetReporting" /f > $null 2>&1
Reg.exe Delete "HKLM\Software\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /f > $null 2>&1
Reg.exe Delete "HKLM\Software\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /f > $null 2>&1
Reg.exe Delete "HKCU\Software\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /f > $null 2>&1
Reg.exe Delete "HKCU\Software\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /f > $null 2>&1
Reg.exe Delete "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /f > $null 2>&1
Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2297E4E2-5DBE-466D-A12B-0F8286F0D9CA}" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E5323777-F976-4f5b-9B55-B94699C46E44}" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2EEF81BE-33FA-4800-9670-1CD474972C3F}" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{52079E78-A92B-413F-B213-E8FE35712E72}" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{7D7E8402-7C54-4821-A34E-AEEFD62DED93}" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{9231CB4C-BF57-4AF3-8C55-FDA7BFCC04C5}" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E390DF20-07DF-446D-B962-F5C953062741}" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
try { Remove-MpPreference -SubmitSamplesConsent > $null 2>&1 } Catch {}
Reg.exe Delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /f > $null 2>&1
Reg.exe Delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\OOBE" /v "DisablePrivacyExperience" /f > $null 2>&1
Reg.exe Delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}" /v "ScenarioExecutionEnabled" /f > $null 2>&1
Reg.exe Add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation" /v "Value" /t REG_DWORD /d "1" /f > $null 2>&1
Reg.exe Add "HKLM\Software\Microsoft\PolicyManager\current\device\System" /v "AllowExperimentation" /t REG_DWORD /d "1" /f > $null 2>&1
Reg.exe Delete "HKLM\SOFTWARE\Policies\Microsoft\DeviceHealthAttestationService" /v "EnableDeviceHealthAttestationService" /f > $null 2>&1
Reg.exe Delete "HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" /v "AcceptedPrivacyStatement" /f > $null 2>&1
Reg.exe Delete "HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" /v "UsageTracking" /f > $null 2>&1
Reg.exe Add "HKCU\Software\Microsoft\input\Settings" /v "InsightsEnabled" /t REG_DWORD /d "1" /f > $null 2>&1
netsh advfirewall firewall set rule group="Remote Assistance" new enable=yes > $null 2>&1
Reg.exe Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v "ScoobeSystemSettingEnabled" /t REG_DWORD /d "1" /f > $null 2>&1
Reg.exe Delete "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v "NoGenTicket" /f > $null 2>&1
Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Control\Diagnostics\Performance" /v "DisableDiagnosticTracing" /t REG_DWORD /d "0" /f > $null 2>&1
Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d "0" /f > $null 2>&1
setx DOTNET_CLI_TELEMETRY_OPTOUT 0 > $null 2>&1
setx POWERSHELL_TELEMETRY_OPTOUT 0 > $null 2>&1
Reg.exe Add "HKLM\Software\Microsoft\WcmSvc\wifinetworkmanager\config" /v "AutoConnectAllowedOEM" /t REG_DWORD /d "1" /f > $null 2>&1
Reg.exe Add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsNetHood" /t REG_DWORD /d "0" /f > $null 2>&1
Reg.exe Add "HKLM\System\CurrentControlSet\Control\Lsa" /v "LmCompatibilityLevel" /t REG_DWORD /d "1" /f > $null 2>&1

# Enable Lock Screen Notifications
Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK" /t REG_DWORD /d "1" /f > $null 2>&1

# Enable offline map network data traffic
Reg.exe Add "HKLM\Software\Policies\Microsoft\Windows\Maps" /v "AllowUntriggeredNetworkTrafficOnSettingsPage" /t REG_DWORD /d "1" /f > $null 2>&1

# Enable Maps auto-download and update
Reg.exe Add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v "AutoDownloadAndUpdateMapData" /t REG_DWORD /d "1" /f > $null 2>&1

# Enable Setting Synchronisation
Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /t REG_DWORD /d "5" /f > $null 2>&1
Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d "1" /f > $null 2>&1
Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d "1" /f > $null 2>&1
Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d "1" /f > $null 2>&1
Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /t REG_DWORD /d "1" /f > $null 2>&1
Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d "1" /f > $null 2>&1
Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d "1" /f > $null 2>&1

# Enable telemetry
Reg.exe Add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v "LimitDiagnosticLogCollection" /t REG_DWORD /d "0" /f > $null 2>&1
Reg.exe Add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v "EnableOneSettingsDownloads" /t REG_DWORD /d "0" /f > $null 2>&1

# Enable Location and Sensors
Reg.exe Add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v "EnableLocation" /t REG_DWORD /d "0" /f > $null 2>&1
Reg.exe Add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v "EnableSensors" /t REG_DWORD /d "0" /f > $null 2>&1

# Enable Headset and App Voice Activation Access
Reg.exe Add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v "AgentActivationOnLockScreenEnabled" /t REG_DWORD /d "1" /f > $null 2>&1
Reg.exe Add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v "AgentActivationLastUsed" /t REG_DWORD /d "1" /f > $null 2>&1
Reg.exe Add "HKCU\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps" /v "AgentActivationEnabled" /t REG_DWORD /d "1" /f > $null 2>&1
Reg.exe Add "HKCU\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps" /v "AgentActivationLastUsed" /t REG_DWORD /d "1" /f > $null 2>&1

# Enable improve start and search results by tracking app launches 
Reg.exe Delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\EdgeUI" /v "DisableMFUTracking" /f > $null 2>&1
Reg.exe Delete "HKCU\Software\Policies\Microsoft\Windows\EdgeUI" /v "DisableMFUTracking" /f > $null 2>&1

# Auto map updates and clipboard suggestions
Reg.exe Add "HKLM\SYSTEM\Maps" /v "AutoUpdateEnabled" /t REG_DWORD /d 1 /f > $null 2>&1
Reg.exe Delete "HKCU\Software\Microsoft\Windows\CurrentVersion\SmartActionPlatform\SmartClipboard" /v "Disabled" /f > $null 2>&1
