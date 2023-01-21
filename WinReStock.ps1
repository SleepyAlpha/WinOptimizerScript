# WinOptimizer 23.1.3 Revert Tool
# Big shoutout to Chris Titus for providing much of the code used in this project.
# https://christitus.com/ | https://github.com/ChrisTitusTech | https://www.youtube.com/c/ChrisTitusTech

Read-Host -Prompt "WARNING: The Computer Will Reboot When Execution Concludes, Press Enter to Continue"

Write-Host "Disabling Windows 11 Education Themes"
            Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Education" -Force -ErrorAction SilentlyContinue

Write-Host  "Enabling Bing Search"
            Remove-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Force -ErrorAction SilentlyContinue

Write-Host "Enabling GameDVR"
            If (!(Test-Path "HKCU:\System\GameConfigStore")) {
                 New-Item -Path "HKCU:\System\GameConfigStore" -Force
            }
            Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_DXGIHonorFSEWindowsCompatible" -Type DWord -Value 0
            Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_HonorUserFSEBehaviorMode" -Type DWord -Value 0
            Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_EFSEFeatureFlags" -Type DWord -Value 0
            Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 1
            Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehaviorMode" -Type DWord -Value 2
            Remove-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Force -ErrorAction SilentlyContinue


Write-Host "Enabling Activity History."
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 1
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 1
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 1


Write-Host "Enabling Hibernation."
            Remove-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernateEnabled"
            Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Force -ErrorAction SilentlyContinue


Write-Host "Setting Context Menu to Stock..."
            Remove-Item -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}" -force -Recurse -ErrorAction SilentlyContinue


Write-Host "Setting DNS to Auto for all connections."
            Get-NetAdapter | set-DnsClientServerAddress -ResetServerAddresses


Write-Host "Enabling automatic Maps updates."
            Remove-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -ErrorAction SilentlyContinue


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
                Write-Host "Setting $Service StartupType to Stock"
                Get-Service -Name $Service -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic
            }


Write-Host "Enabling Telemetry."
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 1
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" 
            Enable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"  -ErrorAction SilentlyContinue
            Enable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\PcaPatchDbTask" -ErrorAction SilentlyContinue
            Enable-ScheduledTask -TaskName "Microsoft\Windows\'Application Experience'\SdbinstMergeDbTask" -ErrorAction SilentlyContinue
            Enable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\StartupAppTask" -ErrorAction SilentlyContinue
            Enable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" -ErrorAction SilentlyContinue
            Enable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" -ErrorAction SilentlyContinue
            Enable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" -ErrorAction SilentlyContinue
            Enable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" -ErrorAction SilentlyContinue


Write-Host "Enabling Application suggestions."
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 1
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 1
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 1
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 1
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 1
            Remove-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force -ErrorAction SilentlyContinue


Write-Host "Enabling Feedback."
            Remove-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf" -Force -Recurse -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -ErrorAction SilentlyContinue
            Enable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue
            Enable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue


Write-Host "Enabling Tailored Experiences."
            Remove-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -ErrorAction SilentlyContinue


Write-Host "Enabling Advertising ID."
            Remove-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Force -ErrorAction SilentlyContinue


Write-Host "Enabling Error reporting."
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -ErrorAction SilentlyContinue
            Enable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null


Write-Host "Starting and Enabling Diagnostics Tracking Service."
            Start-Service "DiagTrack" -WarningAction SilentlyContinue
            Set-Service "DiagTrack" -StartupType Automatic


Write-Host "Starting and Enabling WAP Push Service."
            Start-Service "dmwappushservice" -WarningAction SilentlyContinue
            Set-Service "dmwappushservice" -StartupType Automatic


Write-Host "Enabling Remote Assistance."
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 1


Write-Host "Starting and Enabling Superfetch service."
            Start-Service "SysMain" -WarningAction SilentlyContinue
            Set-Service "SysMain" -StartupType Automatic


Write-Host "Showing Task View button."
            Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -ErrorAction SilentlyContinue


Write-Host "Showing People icon."
            Remove-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Force -ErrorAction SilentlyContinue


Write-Host "Changing default Explorer view to stock."
            Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -ErrorAction SilentlyContinue
    
               ## Revert Extra Tweaks
               Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "SearchOrderConfig" -Type DWord -Value 1
               Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -Type DWord -Value 14
               Remove-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "AutoEndTasks" -ErrorAction SilentlyContinue
               Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "WaitToKillServiceTimeout" -ErrorAction SilentlyContinue


Write-Host "Enabling HPET."
            bcdedit /set useplatformclock true
            bcdedit /set disabledynamictick no

            # Revert Network Tweaks
            Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "IRPStackSize" -ErrorAction SilentlyContinue
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Type DWord -Value 10

            # Rever Gaming Tweaks
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Priority" -Type DWord -Value 2
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Scheduling Category" -Type String -Value "Medium"
        
            # Revert svchost.exe processes managment
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -Type DWord -Value 3670016 -Force


Write-Host "Enabling News and Interests."
            Remove-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Force -ErrorAction SilentlyContinue
            
            # Add "News and Interest" to taskbar
            Remove-ItemProperty  "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds" -Name "ShellFeedsTaskbarViewMode" -ErrorAction SilentlyContinue

            # Add "Meet Now" button to taskbar
            Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\" -Force -ErrorAction SilentlyContinue


Write-Host "Reset Autologger."
            $autoLoggerDir = "$env:PROGRAMDATA\Microsoft\Diagnosis\ETLLogs\AutoLogger"
            icacls $autoLoggerDir /allow SYSTEM:`(OI`)`(CI`)F | Out-Null


Write-Host "Starting and Enabling Diagnostics Tracking Service."
            Start-Service "DiagTrack"
            Set-Service "DiagTrack" -StartupType Automatic


Write-Host "Enabling Wi-Fi Sense."
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -ErrorAction SilentlyContinue
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 1


Write-Host "Installing Stock Software."
            Get-AppXPackage -allusers | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"} -ErrorAction SilentlyContinue
            


Write-Host "Installing Widgets."
		    winget install "Windows web experience Pack"



Write-Host "Enabling mouse acceleration."
            Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSpeed" -Type String -Value 1
            Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold1" -Type String -Value 6
            Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold2" -Type String -Value 10


Write-Host "Removing WinOptimizer Firewall Rules."

           Remove-NetFirewallRule -DisplayName "TelDisable*" 



Write-Host "Reset Multi-Plane Overlay."
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Dwm" -Name "OverlayTestMode" -ErrorAction SilentlyContinue


Write-Host "Cleaning Windows."
                Get-ChildItem -Path "C:\Windows\Temp" *.* -Recurse | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
                Get-ChildItem -Path $env:TEMP *.* -Recurse | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
                cmd /c cleanmgr.exe /d C: /VERYLOWDISK

Restart-Computer -Force
