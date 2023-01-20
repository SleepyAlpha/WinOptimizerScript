# WinOptimizer 23.1.3 Gaming
# Big shoutout to Chris Titus for providing much of the code used in this project.
# https://christitus.com/ | https://github.com/ChrisTitusTech | https://www.youtube.com/c/ChrisTitusTech

Read-Host -Prompt "WARNING: The Computer Will Reboot When Execution Concludes, Press Enter to Continue"

$Deps = @(
            "9P7KNL5RWT25"  # Sysinternals Suite
        )

Write-Host "Installing Dependencies"
        foreach ($Dep in $Deps){
            Write-Host "Installing $Dep."
		    winget install --silent --accept-package-agreements --accept-source-agreements $Dep
        }

Write-Host "Disabling GameDVR"
            If (!(Test-Path "HKCU:\System\GameConfigStore")) {
                 New-Item -Path "HKCU:\System\GameConfigStore" -Force
            }
            Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_DXGIHonorFSEWindowsCompatible" -Type DWord -Value 1
            Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_HonorUserFSEBehaviorMode" -Type DWord -Value 1
            Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_EFSEFeatureFlags" -Type DWord -Value 0
            Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 0
            Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehavior" -Type DWord -Value 2
            If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR")) {
                New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Force
            }
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0

Write-Host "Disabling Activity History."
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0

Write-Host "Disabling Hibernation."
            Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernateEnabled" -Type Dword -Value 0
            If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
                New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
            }
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type Dword -Value 0

Write-Host "Setting Classic Right-Click Menu..."
            New-Item -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}" -Name "InprocServer32" -force -value ""

Write-Host "Setting DNS to Cloud Flare for all connections."
            Get-NetAdapter | set-DnsClientServerAddress -ServerAddresses ("1.1.1.1","1.0.0.1")


Write-Host "Disabling automatic Maps updates."
            Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0
	    
$Services = @(
                "ALG"                                          # Application Layer Gateway Service(Provides support for 3rd party protocol plug-ins for Internet Connection Sharing)
                "AJRouter"                                     # Needed for AllJoyn Router Service
                "BcastDVRUserService_48486de"                  # GameDVR and Broadcast is used for Game Recordings and Live Broadcasts
                "Browser"                                      # Let users browse and locate shared resources in neighboring computers
                "BthAvctpSvc"                                  # AVCTP service (needed for Bluetooth Audio Devices or Wireless Headphones)
                "CaptureService_48486de"                       # Optional screen capture functionality for applications that call the Windows.Graphics.Capture API.
                "cbdhsvc_48486de"                              # Clipboard Service
                "diagnosticshub.standardcollector.service"     # Microsoft (R) Diagnostics Hub Standard Collector Service
                "DiagTrack"                                    # Diagnostics Tracking Service
                "dmwappushservice"                             # WAP Push Message Routing Service
                "DPS"                                          # Diagnostic Policy Service (Detects and Troubleshoots Potential Problems)
                "edgeupdate"                                   # Edge Update Service
                "edgeupdatem"                                  # Another Update Service
                "Fax"                                          # Fax Service
                "fhsvc"                                        # Fax History
                "FontCache"                                    # Windows font cache
                "gupdate"                                      # Google Update
                "gupdatem"                                     # Another Google Update Service
                "lfsvc"                                        # Geolocation Service
                "lmhosts"                                      # TCP/IP NetBIOS Helper
                "MapsBroker"                                   # Downloaded Maps Manager
                "MicrosoftEdgeElevationService"                # Another Edge Update Service
                "MSDTC"                                        # Distributed Transaction Coordinator
                "NahimicService"                               # Nahimic Service
                "NetTcpPortSharing"                            # Net.Tcp Port Sharing Service
                "PcaSvc"                                       # Program Compatibility Assistant Service
                "PerfHost"                                     # Remote users and 64-bit processes to query performance.
                "PhoneSvc"                                     # Phone Service(Manages the telephony state on the device)
                "PrintNotify"                                  # Windows printer notifications and extentions
                "QWAVE"                                        # Quality Windows Audio Video Experience (audio and video might sound worse)
                "RemoteAccess"                                 # Routing and Remote Access
                "RemoteRegistry"                               # Remote Registry
                "RetailDemo"                                   # Demo Mode for Store Display
                "RtkBtManServ"                                 # Realtek Bluetooth Device Manager Service
                "SCardSvr"                                     # Windows Smart Card Service
                "seclogon"                                     # Secondary Logon (Disables other credentials only password will work)
                "SEMgrSvc"                                     # Payments and NFC/SE Manager (Manages payments and Near Field Communication (NFC) based secure elements)
                "SharedAccess"                                 # Internet Connection Sharing (ICS)
                "stisvc"                                       # Windows Image Acquisition (WIA)
                "SysMain"                                      # Analyses System Usage and Improves Performance
                "TrkWks"                                       # Distributed Link Tracking Client
                "WerSvc"                                       # Windows error reporting
                "wisvc"                                        # Windows Insider program(Windows Insider will not work if Disabled)
                "WMPNetworkSvc"                                # Windows Media Player Network Sharing Service
                "WpcMonSvc"                                    # Parental Controls
                "WPDBusEnum"                                   # Portable Device Enumerator Service
                "WpnService"                                   # WpnService (Push Notifications may not work)               
                "WSearch"                                      # Windows Search
                "XblAuthManager"                               # Xbox Live Auth Manager (Disabling Breaks Xbox Live Games)
                "XblGameSave"                                  # Xbox Live Game Save Service (Disabling Breaks Xbox Live Games)
                "XboxNetApiSvc"                                # Xbox Live Networking Service (Disabling Breaks Xbox Live Games)
                "XboxGipSvc"                                   # Xbox Accessory Management Service
                
                # Hp services
                "HPAppHelperCap"
                "HPDiagsCap"
                "HPNetworkCap"
                "HPSysInfoCap"
                "HpTouchpointAnalyticsService"
                
                # Hyper-V services
                "HvHost"
                "vmicguestinterface"
                "vmicheartbeat"
                "vmickvpexchange"
                "vmicrdv"
                "vmicshutdown"
                "vmictimesync"
                "vmicvmsession"
            )
        
            foreach ($Service in $Services) {
                # -ErrorAction SilentlyContinue is so it doesn't write an error to stdout if a service doesn't exist
                Write-Host "Setting $Service StartupType to Manual"
                Get-Service -Name $Service -ErrorAction SilentlyContinue | Set-Service -StartupType Manual
            }

Write-Host "Disabling Telemetry."
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
            Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
            Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\PcaPatchDbTask" | Out-Null
            
            # Forced to use psexec to start powershell as SYSTEM, otherwise the following line fails with permission denied error.
            psexec.exe -i -s powershell.exe -Command "Disable-ScheduledTask -TaskName Microsoft\Windows\'Application Experience'\SdbinstMergeDbTask"
            
            Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\StartupAppTask" | Out-Null
            Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
            Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
            Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
            Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null

Write-Host "Disabling Application suggestions."
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0
            
            If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
                New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
            }
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 0

Write-Host "Disabling Feedback."
            If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules")) {
                New-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Force | Out-Null
            }
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1
            Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
            Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null

Write-Host "Disabling Tailored Experiences."
            If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
                New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
            }
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1

Write-Host "Disabling Advertising ID."
            If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
                New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" | Out-Null
            }
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1

Write-Host "Disabling Error reporting."
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1
            Disable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null

Write-Host "Stopping and disabling Diagnostics Tracking Service."
            Stop-Service "DiagTrack" -WarningAction SilentlyContinue
            Set-Service "DiagTrack" -StartupType Disabled

Write-Host "Stopping and disabling WAP Push Service."
            Stop-Service "dmwappushservice" -WarningAction SilentlyContinue
            Set-Service "dmwappushservice" -StartupType Disabled

Write-Host "Disabling Remote Assistance."
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0

Write-Host "Stopping and disabling Superfetch service."
            Stop-Service "SysMain" -WarningAction SilentlyContinue
            Set-Service "SysMain" -StartupType Disabled

Write-Host "Hiding Task View button."
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0

Write-Host "Hiding People icon."
            If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {
                New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" | Out-Null
            }
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0

Write-Host "Changing default Explorer view to This PC."
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1
        
               ## Performance Tweaks and More Telemetry
               Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "SearchOrderConfig" -Type DWord -Value 0
               Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -Type DWord -Value 0
               Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Type DWord -Value 1
               Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "AutoEndTasks" -Type DWord -Value 1
               Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseHoverTime" -Type DWord -Value 400
               
               ## Timeout Tweaks cause flickering on Windows now
               Remove-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "WaitToKillServiceTimeout" -ErrorAction SilentlyContinue

Write-Host "Disabling HPET."
            bcdedit /set useplatformclock false
            bcdedit /set disabledynamictick yes

            # Network Tweaks
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "IRPStackSize" -Type DWord -Value 20
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Type DWord -Value 4294967295

            # Gaming Tweaks
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Priority" -Type DWord -Value 6
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Scheduling Category" -Type String -Value "High"

Write-Host "Disable News and Interests."
            If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds")) {
                New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" | Out-Null
            }
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Type DWord -Value 0
            
            # Remove "News and Interest" from taskbar
            Set-ItemProperty -Path  "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds" -Name "ShellFeedsTaskbarViewMode" -Type DWord -Value 2

            # remove "Meet Now" button from taskbar
            If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
                New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force | Out-Null
            }

            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Type DWord -Value 1

Write-Host "Removing AutoLogger file and restricting directory."
            $autoLoggerDir = "$env:PROGRAMDATA\Microsoft\Diagnosis\ETLLogs\AutoLogger"
            If (Test-Path "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl") {
                Remove-Item "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl"
            }
            icacls $autoLoggerDir /deny SYSTEM:`(OI`)`(CI`)F | Out-Null

Write-Host "Stopping and disabling Diagnostics Tracking Service."
            Stop-Service "DiagTrack"
            Set-Service "DiagTrack" -StartupType Disabled

Write-Host "Disabling Wi-Fi Sense."
            If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
                 New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
            }
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0
            If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots")) {
            New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Force | Out-Null
            }
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0

$Bloatware = @(
                "Microsoft.WindowsCamera"
		"Microsoft.549981C3F5F10"
                "Microsoft.3DBuilder"
                "Microsoft.Microsoft3DViewer"
                "Microsoft.AppConnector"
                "Microsoft.BingFinance"
                "Microsoft.BingNews"
                "Microsoft.BingSports"
                "Microsoft.BingTranslator"
                "Microsoft.BingWeather"
                "Microsoft.BingFoodAndDrink"
                "Microsoft.BingHealthAndFitness"
                "Microsoft.BingTravel"
                "Microsoft.MinecraftUWP"
                "Microsoft.WindowsReadingList"
                "Microsoft.GetHelp"
                "Microsoft.Getstarted"
                "Microsoft.Messaging"
                "Microsoft.Microsoft3DViewer"
                "Microsoft.MicrosoftSolitaireCollection"
                "Microsoft.NetworkSpeedTest"
                "Microsoft.News"
                "Microsoft.Office.Lens"
                "Microsoft.Office.Sway"
                "Microsoft.Office.OneNote"
                "Microsoft.OneConnect"
                "Microsoft.People"
                "Microsoft.Print3D"
                "Microsoft.SkypeApp"
                "Microsoft.Wallet"
                "Microsoft.Whiteboard"
                "Microsoft.WindowsAlarms"
                "microsoft.windowscommunicationsapps"
                "Microsoft.WindowsFeedbackHub"
                "Microsoft.WindowsMaps"
                "Microsoft.WindowsPhone"
                "Microsoft.WindowsSoundRecorder"
                "Microsoft.ConnectivityStore"
                "Microsoft.CommsPhone"
                "Microsoft.ScreenSketch"
                "Microsoft.MixedReality.Portal"
                "Microsoft.ZuneMusic"
                "Microsoft.ZuneVideo"
                "Microsoft.YourPhone"
                "Microsoft.Getstarted"
                "Microsoft.MicrosoftOfficeHub"
                "*EclipseManager*"
                "*ActiproSoftwareLLC*"
                "*AdobeSystemsIncorporated.AdobePhotoshopExpress*"
                "*Duolingo-LearnLanguagesforFree*"
                "*PandoraMediaInc*"
                "*CandyCrush*"
                "*BubbleWitch3Saga*"
                "*Wunderlist*"
                "*Flipboard*"
                "*Twitter*"
                "*Facebook*"
                "*Royal Revolt*"
                "*Sway*"
                "*Speed Test*"
                "*Viber*"
                "*ACGMediaPlayer*"
                "*Netflix*"
                "*OneCalendar*"
                "*LinkedInforWindows*"
                "*HiddenCityMysteryofShadows*"
                "*Hulu*"
                "*HiddenCity*"
                "*AdobePhotoshopExpress*"
                "*HotspotShieldFreeVPN*"
                "*Adobe*"
                "*Instagram*"
                "*TikTok*"
                "*Spotify*"
                "*Disney*"
                "*Prime*"
                "*Clipchamp*"
                "*Teams*"
                "*Paint*"
                "*Messenger*"
                "*Todos*"
                "*Microsoft.Advertising.Xaml*"
                "*Microsoft.MSPaint*"
                "*Microsoft.MicrosoftStickyNotes*"
		"*MicrosoftCorporationII.QuickAssist*"
		"*Microsoft.PowerAutomateDesktop*"
            )

Write-Host "Removing Bloatware."
            foreach ($Bloat in $Bloatware) {
                Get-AppxPackage -Name $Bloat | Remove-AppxPackage
                Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat | Remove-AppxProvisionedPackage -Online
                Write-Host "Trying to remove $Bloat."
            }

Write-Host "Removing Widgets."
		    winget uninstall "Windows web experience Pack"


Write-Host "Disabling mouse acceleration."
            Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSpeed" -Type String -Value 0
            Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold1" -Type String -Value 0
            Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold2" -Type String -Value 0

# Shoutout to CrazyMax for providing the ip's needed to create the firewall rules.
# https://crazymax.dev/ | https://github.com/crazy-max | https://twitter.com/crazyws

# NOTE: The latest version of the following list is commit:2c945aef4dd59573d3401cca21a3a8610bc0f632 from May 16th 2022.
Write-Host "Disabling Extra Telemetry With Firewall."
$IpList = @(
                "207.68.166.254"
                "13.64.90.137"
                "13.69.131.175"
                "13.66.56.243"
                "13.68.82.8"
                "13.68.92.143"
                "13.68.233.9"
                "13.69.109.130"
                "13.69.109.131"
                "13.73.26.107"
                "13.74.169.109"
                "13.78.130.220"
                "13.78.232.226"
                "13.78.233.133"
                "13.88.21.125"
                "13.92.194.212"
                "13.104.215.69"
                "13.105.28.32"
                "13.105.28.48"
                "20.44.86.43"
                "20.49.150.241"
                "20.54.232.160"
                "20.60.20.4"
                "20.69.137.228"
                "20.190.169.24"
                "20.190.169.25"
                "23.99.49.121"
                "23.102.4.253"
                "23.102.5.5"
                "23.102.21.4"
                "23.103.182.126"
                "40.68.222.212"
                "40.69.153.67"
                "40.70.184.83"
                "40.70.220.248"
                "40.77.228.47"
                "40.77.228.87"
                "40.77.228.92"
                "40.77.232.101"
                "40.78.128.150"
                "40.79.85.125"
                "40.88.32.150"
                "40.112.209.200"
                "40.115.3.210"
                "40.115.119.185"
                "40.119.211.203"
                "40.124.34.70"
                "40.126.41.96"
                "40.126.41.160"
                "51.104.136.2"
                "51.140.40.236"
                "51.140.157.153"
                "51.143.53.152"
                "51.143.111.7"
                "51.143.111.81"
                "51.144.227.73"
                "52.147.198.201"
                "52.138.204.217"
                "52.155.94.78"
                "52.157.234.37"
                "52.158.208.111"
                "52.164.241.205"
                "52.169.189.83"
                "52.170.83.19"
                "52.174.22.246"
                "52.178.147.240"
                "52.178.151.212"
                "52.178.223.23"
                "52.182.141.63"
                "52.183.114.173"
                "52.184.221.185"
                "52.229.39.152"
                "52.230.85.180"
                "52.230.222.68"
                "52.236.42.239"
                "52.236.43.202"
                "52.255.188.83"
                "65.52.100.7"
                "65.52.100.9"
                "65.52.100.11"
                "65.52.100.91"
                "65.52.100.92"
                "65.52.100.93"
                "65.52.100.94"
                "65.52.161.64"
                "65.55.29.238"
                "65.55.83.120"
                "65.55.113.11"
                "65.55.113.12"
                "65.55.113.13"
                "65.55.176.90"
                "65.55.252.43"
                "65.55.252.63"
                "65.55.252.70"
                "65.55.252.71"
                "65.55.252.72"
                "65.55.252.93"
                "65.55.252.190"
                "65.55.252.202"
                "66.119.147.131"
                "104.41.207.73"
                "104.42.151.234"
                "104.43.137.66"
                "104.43.139.21"
                "104.43.139.144"
                "104.43.140.223"
                "104.43.193.48"
                "104.43.228.53"
                "104.43.228.202"
                "104.43.237.169"
                "104.45.11.195"
                "104.45.214.112"
                "104.46.1.211"
                "104.46.38.64"
                "104.46.162.224"
                "104.46.162.226"
                "104.210.4.77"
                "104.210.40.87"
                "104.210.212.243"
                "104.214.35.244"
                "104.214.78.152"
                "131.253.6.87"
                "131.253.6.103"
                "131.253.34.230"
                "131.253.34.234"
                "131.253.34.237"
                "131.253.34.243"
                "131.253.34.246"
                "131.253.34.247"
                "131.253.34.249"
                "131.253.34.252"
                "131.253.34.255"
                "131.253.40.37"
                "134.170.30.202"
                "134.170.30.203"
                "134.170.30.204"
                "134.170.30.221"
                "134.170.52.151"
                "134.170.235.16"
                "157.56.74.250"
                "157.56.91.77"
                "157.56.106.184"
                "157.56.106.185"
                "157.56.106.189"
                "157.56.113.217"
                "157.56.121.89"
                "157.56.124.87"
                "157.56.149.250"
                "157.56.194.72"
                "157.56.194.73"
                "157.56.194.74"
                "168.61.24.141"
                "168.61.146.25"
                "168.61.149.17"
                "168.61.161.212"
                "168.61.172.71"
                "168.62.187.13"
                "168.63.100.61"
                "168.63.108.233"
                "191.236.155.80"
                "191.237.218.239"
                "191.239.50.18"
                "191.239.50.77"
                "191.239.52.100"
                "191.239.54.52"
            )

            foreach ($Ip in $IpList) {
                New-NetFirewallRule -DisplayName "TelDisable_$Ip" -Direction Outbound -LocalPort Any -Protocol TCP -Action Block -RemoteAddress $Ip | Out-Null
                Write-Host "Blocking $Ip."
            }

Write-Host "Removing Dependencies."
            foreach ($Dep in $Deps){
                Write-Host "Removing $Dep."
                winget uninstall $Dep
            }

$AppList = @(
                "Discord.Discord"                   # Discord
                "Valve.Steam"                       # Steam Client
                "ElectronicArts.EADesktop"          # EA Play
                "Ubisoft.Connect"                   # Ubisoft
                "EpicGames.EpicGamesLauncher"       # Epic Games Client
                "GOG.Galaxy"                        # Gog Galaxy
            )

	    foreach ($App in $AppList) {
	    	Write-Host "Installing $App."
		    winget install --force --silent --accept-package-agreements --accept-source-agreements $App
        }

Write-Host "Disabling Multi-Plane Overlay."
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Dwm" -Name "OverlayTestMode" -Type Dword -Value 5

Write-Host "Cleaning Windows."
                Get-ChildItem -Path "C:\Windows\Temp" *.* -Recurse | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
                Get-ChildItem -Path $env:TEMP *.* -Recurse | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
                cmd /c cleanmgr.exe /d C: /VERYLOWDISK

Restart-Computer -Force
