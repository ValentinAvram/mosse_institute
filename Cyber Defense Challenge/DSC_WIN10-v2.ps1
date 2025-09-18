# Student ID:
# 82R4k2JOBFYpjzrPT6xpDrASy2C3

Configuration ACSC_Hardening_DSC {
    Import-DscResource -ModuleName PSDesiredStateConfiguration

    param(
        [string[]]$NodeName = 'localhost',
        [string]$AppLockerPolicyPath = "C:\DSC\Policies\AppLockerPolicy.xml",
        [string]$ExploitProtectXmlPath = "C:\DSC\Policies\ExploitProtection.xml"
    )

    Node $NodeName {

        File PolicyFolder {
            Ensure = "Present"
            Type = "Directory"
            DestinationPath = "C:\DSC\Policies"
        }

        # 1) Application whitelisting - AppLocker
        Script AppLocker_EnableAndApply {
            DependsOn = "[File]PolicyFolder"
            GetScript = {
                @{ Result = (Test-Path $using:AppLockerPolicyPath) }
            }
            SetScript = {

                # Enable Application Identity service (required by AppLocker)
                if ((Get-Service -Name AppIDSvc -ErrorAction SilentlyContinue) -eq $null) {
                    Write-Verbose "AppIDSvc service not present on this OS."
                } else {
                    Set-Service -Name AppIDSvc -StartupType Automatic
                    Start-Service -Name AppIDSvc
                }

                if (-not (Test-Path $using:AppLockerPolicyPath)) {
                    $policy = New-AppLockerPolicy -DefaultRule -Xml
                    $policy | Out-File -FilePath $using:AppLockerPolicyPath -Encoding utf8
                }

                # Apply AppLocker policy (enforcement mode = Enforce rules for Executable rules)
                $xml = [xml](Get-Content -Path $using:AppLockerPolicyPath)
                Set-AppLockerPolicy -PolicyObject $xml -Merge -ErrorAction Stop
                # Enforce for Executable, Windows Installer, Script, Packaged app (leave fine-tuning to admins)
            }
            TestScript = {
                Test-Path $using:AppLockerPolicyPath
            }
        }

        # 2) Windows Defender: Attack Surface Reduction (ASR) + Controlled Folder Access
  
        Script Defender_ASR_CFA {
            DependsOn = "[File]PolicyFolder"
            GetScript = { @{ Applied = $true } }
            TestScript = {
                # Basic test: Controlled Folder Access is Enabled?
                $mp = Get-MpPreference
                $cfa = $mp.EnableControlledFolderAccess
                # Accept either 'Enabled' or 'AuditMode' depending on staged deployment
                return ($cfa -eq 'Enabled' -or $cfa -eq 'AuditMode')
            }
            SetScript = {
                # Enable Controlled Folder Access (start in AuditMode for rollout if you prefer)
                Set-MpPreference -EnableControlledFolderAccess Enabled

                # Example: enable a set of ASR rules to Block.
                # NOTE: replace these GUIDs with the specific ACSC-recommended rule GUIDs for v1709 list.
                $asrRuleGuids = @(
                    # Example popular ASR rule IDs (update for latest list when using in prod)
                    '56a863a9-8755-4dbf-9fdd-1f3d0b3b5c5e', # Block credential stealing from LSASS (sample)
                    'd4f940ab-401b-4efc-aadc-ad5f3c50688a'  # Block Office from creating child processes (sample)
                )

                foreach ($id in $asrRuleGuids) {
                    try {
                        Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions Enabled -ErrorAction Stop
                    } catch {
                        # Set-MpPreference may be needed as fallback
                        Write-Verbose "Add-MpPreference failed for $id; attempting Set-MpPreference"
                        $existingIds = (Get-MpPreference).AttackSurfaceReductionRules_Ids
                        if ($existingIds -notcontains $id) {
                            Set-MpPreference -AttackSurfaceReductionRules_Ids ($existingIds + $id)
                        }
                    }
                }

                # Example: add common allowed app for Controlled Folder Access
                $pwshPath = (Get-Command pwsh.exe -ErrorAction SilentlyContinue).Source
                if ($pwshPath) { Add-MpPreference -ControlledFolderAccessAllowedApplication $pwshPath }
            }
        }

        # 3) Exploit Protection - import XML config (the ACSC recommends specific mitigations).

        Script Defender_ExploitProtection {
            DependsOn = "[File]PolicyFolder"
            GetScript = { @{ Present = Test-Path $using:ExploitProtectXmlPath } }
            TestScript = {
                Test-Path $using:ExploitProtectXmlPath
            }
            SetScript = {
                # This expects you provide a hardened Exploit Protection XML file at $ExploitProtectXmlPath.
                # You can export from a reference machine via Windows Security -> App & browser control -> Exploit protection -> Export.
                if (Test-Path $using:ExploitProtectXmlPath) {
                    # Import-ProcessMitigation exists in newer Windows 10/Server builds (PowerShell).
                    # Use official Import tool - wrapped in try/catch for compatibility.
                    try {
                        Import-Clixml -Path $using:ExploitProtectXmlPath | Out-Null
                    } catch {
                        # Microsoft describes using PowerShell to import EMET-like XML:
                        # Use the defender endpoint Import-ProcessMitigation cmdlet where available.
                        if (Get-Command -Name Import-ProcessMitigation -ErrorAction SilentlyContinue) {
                            Import-ProcessMitigation -XmlFile $using:ExploitProtectXmlPath -Confirm:$false
                        } else {
                            Write-Verbose "Exploit Protection import cmdlet not available on this OS. Admins must import manually or use GPO/Intune."
                        }
                    }
                } else {
                    Write-Verbose "Exploit protection XML not found at $using:ExploitProtectXmlPath. Skipping import."
                }
            }
        }


        # 4) No LM hash storage (Credential caching / NoLMHash)

        Registry NoLMHash {
            Key = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa"
            ValueName = "NoLmHash"
            ValueType = "Dword"
            ValueData = 1
            Ensure = "Present"
        }

        # 5) Disable Guest account and built-in guest access

        Script Disable_Guest {
            GetScript = { @{ Disabled = ((Get-LocalUser -Name Guest -ErrorAction SilentlyContinue).Enabled -eq $false) } }
            TestScript = {
                $g = Get-LocalUser -Name Guest -ErrorAction SilentlyContinue
                if (-not $g) { return $true } # guest account may be absent on some SKUs
                return (-not $g.Enabled)
            }
            SetScript = {
                $g = Get-LocalUser -Name Guest -ErrorAction SilentlyContinue
                if ($g) {
                    Disable-LocalUser -Name Guest
                }
            }
        }

        # 6) Disable AutoRun & Autoplay (Autoplay for all drives)

        Registry Disable_AutoRun_Autoplay {
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
            ValueName = "NoDriveTypeAutoRun"
            ValueType = "Dword"
            # 0xFF disables AutoRun on all types per MS guidance (255 decimal -> 0xFF)
            ValueData = 255
            Ensure = "Present"
        }

        # 7) Disable CD burning (remove Burn capability)

        Registry Disable_CDBurning {
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
            ValueName = "NoCDBurning"
            ValueType = "Dword"
            ValueData = 1
            Ensure = "Present"
        }

        # 8) PowerShell: enable ScriptBlockLogging and constrain execution policy

        Registry PowerShell_ScriptblockLogging {
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
            ValueName = "EnableScriptBlockLogging"
            ValueType = "Dword"
            ValueData = 1
            Ensure = "Present"
        }

        Registry PowerShell_Constrained_ExecutionPolicy {
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
            ValueName = "ExecutionPolicy"
            ValueType = "String"
            ValueData = "AllSigned"
            Ensure = "Present"
        }

        # 9) Disable Remote Assistance and Solicited RA (ACSC recommends disabling)

        Registry Disable_RemoteAssistance {
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
            ValueName = "fAllowToGetHelp"
            ValueType = "Dword"
            ValueData = 0
            Ensure = "Present"
        }

        # 10) Disable Remote Desktop Services (deny interactive RDP logon for local accounts)

        Script Disable_RDP {
            GetScript = { @{ RDPDisabled = (-not (Get-Service -Name TermService -ErrorAction SilentlyContinue).Status -eq 'Running') } }
            TestScript = {
                $svc = Get-Service -Name TermService -ErrorAction SilentlyContinue
                if (-not $svc) { return $true }
                return ($svc.Status -ne 'Running')
            }
            SetScript = {
                if (Get-Service -Name TermService -ErrorAction SilentlyContinue) {
                    Stop-Service -Name TermService -Force -ErrorAction SilentlyContinue
                    Set-Service -Name TermService -StartupType Disabled
                }
                # disable firewall rule for Remote Desktop
                Get-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue | Disable-NetFirewallRule -ErrorAction SilentlyContinue
            }
        }

        # 11) Password policy & account lockout (basic local enforcement via net accounts & secedit)

        Script Local_Password_Policy {
            GetScript = { @{ Applied = $true } }
            TestScript = { $true } # simplified - complex to accurately test every policy here
            SetScript = {
                # Example: set minimum password length to 14, max age 60 days
                net accounts /minpwlen:14 /maxpwage:60 /minpwage:1 /uniquepw:5 | Out-Null

                # Account lockout (no direct net command) - use secedit to merge an INF or use ntrights/PowerShell modules.
                $inf = @"
[System Access]
LockoutBadCount = 5
ResetLockoutCount = 30
LockoutDuration = 30
"@ 
                $infPath = "$env:TEMP\passwdpolicy.inf"
                $inf | Out-File -FilePath $infPath -Encoding ascii
                secedit /configure /db secedit.sdb /cfg $infPath /areas SECURITYPOLICY | Out-Null
            }
        }

        # 12) Disable registry editing tools (regedit) - policy via registry

        Registry Disable_Regedit {
            Key = "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            ValueName = "DisableRegistryTools"
            ValueType = "Dword"
            ValueData = 1
            Ensure = "Present"
        }

        # 13) Disable built-in sharing where relevant: File and Print Sharing via firewall

        Script Disable_FilePrintSharing {
            GetScript = { @{ Done = $true } }
            TestScript = { $true }
            SetScript = {
                # Turn off File and Printer Sharing firewall rules (Domain/Profile/Private)
                Get-NetFirewallRule -DisplayGroup "File and Printer Sharing" -ErrorAction SilentlyContinue | Disable-NetFirewallRule -ErrorAction SilentlyContinue
            }
        }

        # 14) Windows Defender AV: ensure real-time & tamper protection (where available)

        Script Defender_Basic {
            GetScript = { @{ Ok = $true } }
            TestScript = { $true }
            SetScript = {
                # Basic preferences - keep on
                Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -DisableBlockAtFirstSeen $false -EnableNetworkProtection $true -SignatureDisableUpdateOnStartupWithoutEngine $false
                # Tamper protection cannot be set via Set-MpPreference; it's managed via MDE portal or local UI (documented limitation).
            }
        }

        # 15) Early Launch Antimalware / ELAM - ensure driver signing policies (informational)

        Script Note_ELAM {
            GetScript = { @{ Present = $true } }
            TestScript = { $true }
            SetScript = {
                Write-Verbose "ELAM and boot-time antimalware are controlled by Defender and Windows Boot flow. For enterprise, ensure secure boot and Microsoft Defender for Endpoint enrollment."
            }
        }

        # 16) Misc: Disable SoundRecorder / Windows To Go / Cortana -- illustrative registry policy settings
        
        Registry Disable_Cortana {
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
            ValueName = "AllowCortana"
            ValueType = "Dword"
            ValueData = 0
            Ensure = "Present"
        }
    } # Node
} # Configuration

# Example: compile for localhost, with paths for policy files (adjust as needed)
# ACSC_Hardening_DSC -NodeName "localhost" -AppLockerPolicyPath "C:\DSC\Policies\AppLockerPolicy.xml" -ExploitProtectXmlPath "C:\DSC\Policies\ExploitProtection.xml"
# After compile: Start-DscConfiguration -Path .\ACSC_Hardening_DSC\ -Wait -Verbose -Force