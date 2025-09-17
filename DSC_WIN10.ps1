# Student ID:
# 82R4k2JOBFYpjzrPT6xpDrASy2C3

# Helper functions

function Ensure-Module {
    param($Name)
    if (-not (Get-Module -ListAvailable -Name $Name)) {
        Write-Verbose "Installing module $Name from PSGallery"
        Install-Module -Name $Name -Force -Scope AllUsers
    }
}

# Ensure common DSC modules are available
Ensure-Module -Name SecurityPolicyDsc
Ensure-Module -Name AuditPolicyDsc
Ensure-Module -Name ComputerManagementDsc

Import-Module SecurityPolicyDsc -ErrorAction Stop
Import-Module AuditPolicyDsc -ErrorAction Stop
Import-Module ComputerManagementDsc -ErrorAction Stop

# Configuration: Base Hardening

Configuration ACSC_Hardening_Base {
    param(
        [string[]]$NodeName = 'localhost'
    )

    Import-DscResource -ModuleName SecurityPolicyDsc
    Import-DscResource -ModuleName AuditPolicyDsc
    Import-DscResource -ModuleName ComputerManagementDsc

    Node $NodeName {

        # Security options: password & lockout 
        # Use SecurityPolicyDsc (MSFT_SecurityPolicy/ MSFT_SecurityOption) to set password/lockout
        # Example: set maximum password age, minimum length, history, lockout thresholds

        SecurityPolicyTemplate PasswordAndLockout
        {
            Ensure = 'Present'
            TemplateFile = "$env:ProgramData\\ACSC_Policies\\PasswordLockout.inf"
            # The above INF can be created or exported from a working machine using secedit
        }

        # No LM Hash (credential caching) 
        # Do not store LM hashes in the SAM (registry policy)

        Registry NoLmHashPolicy {
            Ensure = 'Present'
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
            ValueName = 'NoLMHash'
            ValueType = 'Dword'
            ValueData = 1
        }

        # Network authentication & LM/NTLM settings
        # Configure LAN Manager authentication level via registry

        Registry LmCompatibilityLevel {
            Ensure = 'Present'
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
            ValueName = 'LmCompatibilityLevel'
            ValueType = 'Dword'
            # Send NTLMv2 response only. Refuse LM & NTLM
            ValueData = 5
        }

        # Disable Remote Assistance

        Registry DisableRemoteAssistance {
            Ensure = 'Present'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsNT\TerminalServices'
            ValueName = 'fAllowToGetHelp'
            ValueType = 'DWord'
            ValueData = 0
        }

        # Disable Remote Desktop 
        Service DisableRDPListener {
            Name = 'TermService'
            State = 'Stopped'
            StartupType = 'Disabled'
            DependsOn = '[Registry]DisableRemoteAssistance'
        }

        # Disable Registry Editing Tools 
        # Prevent regedit.exe from running
        Registry DisableRegedit {
            Ensure = 'Present'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueName = 'DisableRegistryTools'
            ValueType = 'DWord'
            ValueData = 1
        }

        # PowerShell hardening 
        # Enable Script Block Logging and restrict execution policy to AllSigned
        Registry PS_ScriptBlockLogging {
            Ensure = 'Present'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
            ValueName = 'EnableScriptBlockLogging'
            ValueType = 'DWord'
            ValueData = 1
        }
        Registry PS_ExecutionPolicy {
            Ensure = 'Present'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ExecutionPolicy'
            ValueName = 'ExecutionPolicy'
            ValueType = 'String'
            ValueData = 'AllSigned'
        }

        # Power management (example) 
        # Set high performance (example of power scheme change)
        Script PowerPlanHighPerformance {
            GetScript = { @{ Result = 'Get' } }
            SetScript = { powercfg -S SCHEME_MIN } # Administrator required
            TestScript = { $true }
        }

        # Audit event management (example) 
        # Use AuditPolicyDsc to enforce auditing categories (example shown)
        AuditPolicy "Audit_Account_Logon" {
            Subcategory = 'Account Logon'
            Success = 'Enable'
            Failure = 'Enable'
        }
        AuditPolicy "Audit_Account_Management" {
            Subcategory = 'Account Management'
            Success = 'Enable'
            Failure = 'Enable'
        }

        # AppLocker (application whitelisting) 
        # AppLocker is best managed via a prepared XML policy. Import via script if present.
        Script Import-AppLockerPolicy {
            GetScript = { @{ Result = 'Get' } }
            TestScript = {
                # rudimentary: check if AppLocker policy exists
                try { (Get-AppLockerPolicy -Effective -ErrorAction Stop) -ne $null } catch { $false }
            }
            SetScript = {
                $xml = 'C:\ACSC\Policies\AppLockerPolicy.xml'
                if (Test-Path $xml) {
                    $policy = [xml](Get-Content $xml -Raw)
                    Set-AppLockerPolicy -XmlPolicy $policy -ErrorAction Stop
                } else {
                    Write-Verbose "AppLocker XML not found at $xml - skipping"
                }
            }
            DependsOn = '[Service]DisableRDPListener'
        }

        # Microsoft Defender: ASR rules & Controlled Folder Access 
        Script Configure_Defender_ASR_CFA {
            GetScript = { @{ Result = 'Get' } }
            TestScript = {
                # Always return false so SetScript will run (idempotence is not perfect here)
                $false
            }
            SetScript = {
                # Example: put ASR rules into Audit mode first. Replace GUIDs with real rule IDs.
                # ASR rule IDs are documented by Microsoft. Use Audit (0) or Block (1) values.
                $asrRules = @{
                    # sample GUIDs - administrator should replace with rules from MS docs
                    'D4F940AB-401B-4EFC-AADC-AD5F3C50688A' = 1 # Block executable content from email client
                    '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84' = 1 # Block credential stealing from LSASS
                }
                $ids = $asrRules.Keys -join ','
                $values = ($asrRules.Values -join ',')
                # Build the hashtable form acceptable to Set-MpPreference
                $mpRules = @{ }
                foreach ($k in $asrRules.Keys) { $mpRules[$k] = $asrRules[$k] }
                Try {
                    # set rules (requires Defender presence)
                    Set-MpPreference -AttackSurfaceReductionRules_Ids $mpRules.Keys -AttackSurfaceReductionRules_Actions $mpRules.Values
                } catch {
                    Write-Warning "Set-MpPreference failed: $_"
                }

                # Enable Controlled Folder Access (Audit first: 2, Enabled:1)
                Try {
                    # AuditMode = 2, Enabled = 1
                    Set-MpPreference -EnableControlledFolderAccess 2
                    # Add some protected folders as example
                    Add-MpPreference -ControlledFolderAccessProtectedFolders 'C:\Users\Public\Documents'
                } catch {
                    Write-Warning "Controlled Folder Access configuration failed: $_"
                }
            }
            DependsOn = '[Registry]DisableRegedit'
        }

        # Exploit Protection / Early Launch Antimalware 
        # Exploit protection settings are manageable via Export/Import from 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' or via Set-ProcessMitigation.
        Script ExploitProtection {
            GetScript = { @{ Result = 'Get' } }
            TestScript = { $false }
            SetScript = {
                # Example: turn on DEP for all processes (as an example of exploit mitigations)
                Try { Set-ProcessMitigation -System -Enable DEP } catch { Write-Verbose "Set-ProcessMitigation not available on this platform: $_" }
            }
        }

        # Disable the built-in Guest account 
        Script DisableGuestAccount {
            GetScript = { @{ Result = 'Get' } }
            TestScript = { (Get-LocalUser -Name Guest -ErrorAction SilentlyContinue).Enabled -eq $false }
            SetScript = { 
                $g = Get-LocalUser -Name Guest -ErrorAction SilentlyContinue
                if ($g) { Disable-LocalUser -Name Guest }
            }
            DependsOn = '[Registry]NoLmHashPolicy'
        }

        # Microsoft Edge: example policy - block saving passwords 
        Registry EdgeDisableSavePassword {
            Ensure = 'Present'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            ValueName = 'PasswordManagerEnabled'
            ValueType = 'DWord'
            ValueData = 0
        }

        # SafeMode: block non-admins from entering Safe Mode (example) 
        Registry SafeModeBlockNonAdmins {
            Ensure = 'Present'
            Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName = 'SafeModeBlockNonAdmins'
            ValueType = 'DWord'
            ValueData = 1
        }

        # Windows Update: basic config (enable automatic updates) 
        Script EnableWindowsUpdateAuto {
            GetScript = { @{ Result = 'Get' } }
            TestScript = { $false }
            SetScript = {
                # configure AU to auto download & schedule install
                $auKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
                if (-not (Test-Path $auKey)) { New-Item -Path $auKey -Force | Out-Null }
                New-ItemProperty -Path $auKey -Name 'NoAutoUpdate' -Value 0 -PropertyType DWord -Force | Out-Null
                New-ItemProperty -Path $auKey -Name 'AUOptions' -Value 4 -PropertyType DWord -Force | Out-Null
            }
        }

        # Attachment Manager (block zone information preservation) 
        Registry AttachmentManager_ZoneInfo {
            Ensure = 'Present'
            Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments'
            ValueName = 'SaveZoneInformation'
            ValueType = 'DWord'
            ValueData = 2 # 2 = Do not preserve zone information in file attachments
        }

        # Disable AutoPlay/AutoRun 
        Registry TurnOffAutoPlay {
            Ensure = 'Present'
            Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueName = 'NoDriveTypeAutoRun'
            ValueType = 'DWord'
            ValueData = 255
        }

        # Additional: disable CD burning 
        Registry RemoveCDBurning {
            Ensure = 'Present'
            Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueName = 'NoCDBurning'
            ValueType = 'DWord'
            ValueData = 1
        }

        # End of Node 
    }
}

# -- Helper: create a sample INF for SecurityPolicyDsc  --
function New-SamplePasswordLockoutInf {
    param(
        [string]$Path = "$env:ProgramData\ACSC_Policies\PasswordLockout.inf"
    )
    if (-not (Test-Path (Split-Path $Path))) { New-Item -Path (Split-Path $Path) -ItemType Directory -Force | Out-Null }
    @"
[Unicode]
Unicode=yes
[System Access]
MinimumPasswordLength = 14
MaximumPasswordAge = 60
MinimumPasswordAge = 1
PasswordComplexity = 1
PasswordHistorySize = 24
LockoutBadCount = 5
ResetLockoutCount = 15
LockoutDuration = 30
"@ | Out-File -FilePath $Path -Encoding ascii -Force
    return $Path
}

# create a sample INF (if not present)
$samp = New-SamplePasswordLockoutInf

# -- Expose the configurations for easy MOF generation --
Export-ModuleMember -Function ACSC_Hardening_Base, New-SamplePasswordLockoutInf

