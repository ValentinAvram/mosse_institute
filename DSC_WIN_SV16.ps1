# Student ID:
# 82R4k2JOBFYpjzrPT6xpDrASy2C3


Configuration DSCConfig_Windows2016_v1 {
    param (
    [string[]]$NodeName = 'localhost'
    )

    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'AuditPolicyDsc'
    Import-DscResource -ModuleName 'SecurityPolicyDsc'

    
    # Implement Node Name Account Policies
    
    Node $NodeName {
    
    # Set StoragePool
      
     Script Pool
     {
     SetScript = {
         New-StoragePool -FriendlyName StoragePool1 -StorageSubSystemFriendlyName '*storage*' -PhysicalDisks (Get-PhysicalDisk –CanPool $True)
     }
     TestScript = {
        (Get-StoragePool -ErrorAction SilentlyContinue -FriendlyName StoragePool1).OperationalStatus -eq 'OK'
     }
     GetScript = {
        @{Ensure = if ((Get-StoragePool -FriendlyName StoragePool1).OperationalStatus -eq 'OK') {'Present'} Else {'Absent'}}
     }
    }

    AccountPolicy AccountPolicies  {
            Name                                        = 'PasswordPolicies'

            # CceId: CCE-37166-6
            # DataSource: BaselineSecurityPolicyRule
            # Ensure 'Enforce password history' is set to '24 or more password'
            Enforce_password_history                    = 24

            # CceId: CCE-37167-4
            # DataSource: BaselineSecurityPolicyRule
            # Ensure 'Maximum password age' is set to '70 or fewer days, but not 0'
            Maximum_Password_Age                        = 70

            # CceId: CCE-37073-4
            # DataSource: BaselineSecurityPolicyRule
            # Ensure 'Minimum password age' is set to '1 or more day'
            Minimum_Password_Age                        = 1

            # CceId: CCE-36534-6
            # DataSource: BaselineSecurityPolicyRule
            # Ensure 'Minimum password length' is set to '14 or more character'
            Minimum_Password_Length                     = 14

            # CceId: CCE-37063-5
            # DataSource: BaselineSecurityPolicyRule
            # Ensure 'Password must meet complexity requirements' is set to 'Enabled'
            Password_must_meet_complexity_requirements  = 'Enabled'

            # CceId: CCE-36286-3
            # DataSource: BaselineSecurityPolicyRule
            # Ensure 'Store passwords using reversible encryption' is set to 'Disabled'
            Store_passwords_using_reversible_encryption = 'Disabled'
        }

        # CceId: CCE-35818-4
        # DataSource: BaselineSecurityPolicyRule
        # Configure 'Access this computer from the network'
        UserRightsAssignment Accessthiscomputerfromthenetwork {
            Policy       = 'Access_this_computer_from_the_network'
            Identity     = 'Administrators, Authenticated Users'
        }

        # CceId: CCE-37072-6
        # DataSource: BaselineSecurityPolicyRule
        # Configure 'Allow log on through Remote Desktop Services'
       UserRightsAssignment AllowlogonthroughRemoteDesktopServices {
        Policy       = 'Allow_log_on_through_Remote_Desktop_Services'
        Identity     = 'Administrators, Remote Desktop Users' 
        }

        # CceId: CCE-35823-4
        # DataSource: BaselineSecurityPolicyRule
        # Configure 'Create symbolic links'
       UserRightsAssignment Createsymboliclinks {
        Policy       = 'Create_symbolic_links'
        Identity     = 'Administrators'
        }
        
        # CceId: CCE-37954-5
        # DataSource: BaselineSecurityPolicyRule
        # Configure 'Deny access to this computer from the network'
        UserRightsAssignment Denyaccesstothiscomputerfromthenetwork {
            Policy       = 'Deny_access_to_this_computer_from_the_network'
            Identity     = 'Guests, Local Account'
         }

        # CceId: CCE-36860-5
        # DataSource: BaselineSecurityPolicyRule
        # Configure 'Enable computer and user accounts to be trusted for delegation'
        UserRightsAssignment Enablecomputeranduseraccountstobetrustedfordelegation {
            Policy       = 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
            Identity     = ''
         }

        # CceId: CCE-35906-7
        # DataSource: BaselineSecurityPolicyRule
        # Configure 'Manage auditing and security log'
        UserRightsAssignment Manageauditingandsecuritylog {
            Policy       = 'Manage_auditing_and_security_log'
            Identity     = 'Administrators'
         }

        # CceId: CCE-37056-9
        # DataSource: BaselineSecurityPolicyRule
        # Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'
        UserRightsAssignment AccessCredentialManagerasatrustedcaller {
            Policy       = 'Access_Credential_Manager_as_a_trusted_caller'
            Identity     = ''
         }

        # CceId: CCE-36876-1
        # DataSource: BaselineSecurityPolicyRule
        # Ensure 'Act as part of the operating system' is set to 'No One'
        UserRightsAssignment Actaspartoftheoperatingsystem {
            Policy       = 'Act_as_part_of_the_operating_system'
            Identity     = ''
         }

        # CceId: CCE-35912-5
        # DataSource: BaselineSecurityPolicyRule
        # Ensure 'Back up files and directories' is set to 'Administrators'
        UserRightsAssignment Backupfilesanddirectories {
            Policy       = 'Back_up_files_and_directories'
            Identity     = 'Administrators,Backup Operators'
         }

        # CceId: CCE-37452-0
        # DataSource: BaselineSecurityPolicyRule
        # Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'
        UserRightsAssignment Changethesystemtime {
            Policy       = 'Change_the_system_time'
            Identity     = 'Administrators, LOCAL SERVICE'
         }

        # CceId: CCE-37700-2
        # DataSource: BaselineSecurityPolicyRule       
        # Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE'
        UserRightsAssignment Changethetimezone {
            Policy       = 'Change_the_time_zone'
            Identity     = 'Administrators, LOCAL SERVICE'
         }

        # CceId: CCE-35821-8
        # DataSource: BaselineSecurityPolicyRule
        # Ensure 'Create a pagefile' is set to 'Administrators'
        UserRightsAssignment Createapagefile {
            Policy       = 'Create_a_pagefile'
            Identity     = 'Administrators'
         }

        # CceId: CCE-36861-3
        # DataSource: BaselineSecurityPolicyRule
        # Ensure 'Create a token object' is set to 'No One'
        UserRightsAssignment Createatokenobject {
            Policy       = 'Create_a_token_object'
            Identity     = ''
         }

        # CceId: CCE-37453-8
        # DataSource: BaselineSecurityPolicyRule
        # Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
        UserRightsAssignment Createglobalobjects {
            Policy       = 'Create_global_objects'
            Identity     = 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
         }

        # CceId: CCE-36532-0
        # DataSource: BaselineSecurityPolicyRule
        # Ensure 'Create permanent shared objects' is set to 'No One'
        UserRightsAssignment Createpermanentsharedobjects {
            Policy       = 'Create_permanent_shared_objects'
            Identity     = ''
         }

        # CceId: CCE-36923-1
        # DataSource: BaselineSecurityPolicyRule
        # Ensure 'Deny log on as a batch job' to include 'Guests'
        UserRightsAssignment Denylogonasabatchjob {
            Policy       = 'Deny_log_on_as_a_batch_job'
            Identity     = 'Guests'
         }

        # CceId: CCE-36877-9
        # DataSource: BaselineSecurityPolicyRule
        # Ensure 'Deny log on as a service' to include 'Guests'
        UserRightsAssignment Denylogonasaservice {
            Policy       = 'Deny_log_on_as_a_service'
            Identity     = 'Guests'
         }

        # CceId: CCE-37146-8
        # DataSource: BaselineSecurityPolicyRule
        # Ensure 'Deny log on locally' to include 'Guests'
        UserRightsAssignment Denylogonlocally {
            Policy       = 'Deny_log_on_locally'
            Identity     = 'Guests'
         }

        # CceId: CCE-36867-0
        # DataSource: BaselineSecurityPolicyRule
        # Ensure 'Deny log on through Remote Desktop Services' to include 'Guests'
        UserRightsAssignment DenylogonthroughRemoteDesktopServices {
            Policy       = 'Deny_log_on_through_Remote_Desktop_Services'
            Identity     = 'Guests'
         }

        # CceId: CCE-37877-8
        # DataSource: BaselineSecurityPolicyRule
        # Ensure 'Force shutdown from a remote system' is set to 'Administrators'
        UserRightsAssignment Forceshutdownfromaremotesystem {
            Policy       = 'Force_shutdown_from_a_remote_system'
            Identity     = 'Administrators'
         }

        # CceId: CCE-37639-2
        # DataSource: BaselineSecurityPolicyRule
        # Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'
        UserRightsAssignment Generatesecurityaudits {
            Policy       = 'Generate_security_audits'
            Identity     = 'LOCAL SERVICE, NETWORK SERVICE'
         }

        # CceId: CCE-38326-5
        # DataSource: BaselineSecurityPolicyRule
        # Ensure 'Increase scheduling priority' is set to 'Administrators'
        UserRightsAssignment Increaseschedulingpriority {
            Policy       = 'Increase_scheduling_priority'
            Identity     = 'Administrators'
         }

        # CceId: CCE-36318-4
        # DataSource: BaselineSecurityPolicyRule
        # Ensure 'Load and unload device drivers' is set to 'Administrators'
        UserRightsAssignment Loadandunloaddevicedrivers {
            Policy       = 'Load_and_unload_device_drivers'
            Identity     = 'Administrators'
         }

        # CceId: CCE-36495-0
        # DataSource: BaselineSecurityPolicyRule
        # Ensure 'Lock pages in memory' is set to 'No One'
        UserRightsAssignment Lockpagesinmemory {
            Policy       = 'Lock_pages_in_memory'
            Identity     = ''
         }

        # CceId: CCE-36054-5
        # DataSource: BaselineSecurityPolicyRule
        # Ensure 'Modify an object label' is set to 'No One'
        UserRightsAssignment Modifyanobjectlabel {
            Policy       = 'Modify_an_object_label'
            Identity     = ''
         }

        # CceId: CCE-38113-7
        # DataSource: BaselineSecurityPolicyRule
        # Ensure 'Modify firmware environment values' is set to 'Administrators'
        UserRightsAssignment Modifyfirmwareenvironmentvalues {
            Policy       = 'Modify_firmware_environment_values'
            Identity     = 'Administrators'
         }

        # CceId: CCE-36143-6
        # DataSource: BaselineSecurityPolicyRule
        # Ensure 'Perform volume maintenance tasks' is set to 'Administrators'
        UserRightsAssignment Performvolumemaintenancetasks {
            Policy       = 'Perform_volume_maintenance_tasks'
            Identity     = 'Administrators'
         }

        # CceId: CCE-37131-0
        # DataSource: BaselineSecurityPolicyRule
        # Ensure 'Profile single process' is set to 'Administrators'
        UserRightsAssignment Profilesingleprocess {
            Policy       = 'Profile_single_process'
            Identity     = 'Administrators'
         }

        # CceId: CCE-36052-9
        # DataSource: BaselineSecurityPolicyRule
        # Ensure 'Profile system performance' is set to 'Administrators, NT SERVICE\WdiServiceHost'
        UserRightsAssignment Profilesystemperformance {
            Policy       = 'Profile_system_performance'
            Identity     = 'Administrators,WdiServiceHost'
         }

        # CceId: CCE-37430-6
        # DataSource: BaselineSecurityPolicyRule
        # Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'
        UserRightsAssignment Replaceaprocessleveltoken {
            Policy       = 'Replace_a_process_level_token'
            Identity     = 'LOCAL SERVICE, NETWORK SERVICE'
         }

        # CceId: CCE-37613-7
        # DataSource: BaselineSecurityPolicyRule
        # Ensure 'Restore files and directories' is set to 'Administrators, Backup Operators'
        UserRightsAssignment Restorefilesanddirectories {
            Policy       = 'Restore_files_and_directories'
            Identity     = 'Administrators, Backup Operators'
         }

        # CceId: CCE-38328-1
        # DataSource: BaselineSecurityPolicyRule
        # Ensure 'Shut down the system' is set to 'Administrators'
        UserRightsAssignment Shutdownthesystem {
            Policy       = 'Shut_down_the_system'
            Identity     = 'Administrators'
         }

        # CceId: CCE-38325-7
        # DataSource: BaselineSecurityPolicyRule
        # Ensure 'Take ownership of files or other objects' is set to 'Administrators'
        UserRightsAssignment Takeownershipoffilesorotherobjects {
            Policy       = 'Take_ownership_of_files_or_other_objects'
            Identity     = 'Administrators'
         }

        # CceId: NOT_ASSIGNED
        # DataSource: BaselineSecurityPolicyRule
        # Bypass traverse checking
        UserRightsAssignment Bypasstraversechecking {
            Policy       = 'Bypass_traverse_checking'
            Identity     = 'Administrators, Authenticated Users, Backup Operators, Local Service, Network Service'
         }

        # CceId: NOT_ASSIGNED
        # DataSource: BaselineSecurityPolicyRule
        # Increase a process working set
        UserRightsAssignment Increaseaprocessworkingset {
            Policy       = 'Increase_a_process_working_set'
            Identity     = 'Administrators, Local Service'
         }

        # CceId: NOT_ASSIGNED
        # DataSource: BaselineSecurityPolicyRule
        # Remove computer from docking station
        UserRightsAssignment Removecomputerfromdockingstation {
            Policy       = 'Remove_computer_from_docking_station'
            Identity     = 'Administrators'
         }

       SecurityOption AccountSecurityOptions {
          Name                                   = 'AccountSecurityOptions'

          # CceId: CCE-37615-2
          # DataSource: BaselineRegistryRule
          # Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'
          Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only = 'Enabled'

          # CceId: CCE-35907-5
          # DataSource: BaselineRegistryRule
          # Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'
          Audit_Shut_down_system_immediately_if_unable_to_log_security_audits = 'Disabled'

          # CceId: CCE-37942-0
          # DataSource: BaselineRegistryRule
          # Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'
          Devices_Prevent_users_from_installing_printer_drivers = 'Enabled'

          # CceId: CCE-36142-8
          # DataSource: BaselineRegistryRule
          # Ensure 'Domain member: Digitally encrypt or sign secure channel data ' is set to 'Enabled'
          Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always = 'Enabled'          

          # CceId: CCE-37130-2
          # DataSource: BaselineRegistryRule
          # Ensure 'Domain member: Digitally encrypt secure channel data ' is set to 'Enabled'
          Domain_member_Digitally_encrypt_secure_channel_data_when_possible = 'Enabled'

          # CceId: CCE-37222-7
          # DataSource: BaselineRegistryRule
          # Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'
          Domain_member_Digitally_sign_secure_channel_data_when_possible = 'Enabled'

          # CceId: CCE-37508-9
          # DataSource: BaselineRegistryRule
          # Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled'
          Domain_member_Disable_machine_account_password_changes = 'Disabled'

          # CceId: CCE-37431-4
          # DataSource: BaselineRegistryRule
          # Ensure 'Domain member: Maximum machine account password age' is set to '30 or fewer days, but not 0'
          Domain_member_Maximum_machine_account_password_age = '30'

          # CceId: CCE-37614-5
          # DataSource: BaselineRegistryRule
          # Ensure 'Domain member: Require strong session key' is set to 'Enabled'
          Domain_member_Require_strong_Windows_2000_or_later_session_key = 'Enabled'

          # CceId: CCE-36056-0
          # DataSource: BaselineRegistryRule
          # Ensure 'Interactive logon: Do not display last user name' is set to 'Enabled'
          Interactive_logon_Do_not_display_last_user_name = 'Enabled'

          # CceId: CCE-37637-6
          # DataSource: BaselineRegistryRule
          # Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'
          Interactive_logon_Do_not_require_CTRL_ALT_DEL = 'Disabled' 

          # CceId: CCE-36325-9
          # DataSource: BaselineRegistryRule
          # Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'
          Microsoft_network_client_Digitally_sign_communications_always = 'Enabled'

          # CceId: CCE-36269-9
          # DataSource: BaselineRegistryRule
          # Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled'
          Microsoft_network_client_Digitally_sign_communications_if_server_agrees = 'Enabled'

          # CceId: CCE-37863-8
          # DataSource: BaselineRegistryRule
          # Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled' 
          Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers = 'Disabled'

          # CceId: CCE-38046-9
          # DataSource: BaselineRegistryRule
          # Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute, but not 0'
          Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session = '15' 

          # CceId: CCE-37864-6
          # DataSource: BaselineRegistryRule
          # Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'
          Microsoft_network_server_Digitally_sign_communications_always = 'Enabled'

          # CceId: CCE-35988-5
          # DataSource: BaselineRegistryRule
          # Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'
          Microsoft_network_server_Digitally_sign_communications_if_client_agrees = 'Enabled'

          # CceId: CCE-37972-7
          # DataSource: BaselineRegistryRule
          # Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'
          Microsoft_network_server_Disconnect_clients_when_logon_hours_expire = 'Enabled' 

          # CceId: CCE-36077-6
          # DataSource: BaselineRegistryRule
          # Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled'
          Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares = 'Enabled'

          # CceId: CCE-36316-8
          # DataSource: BaselineRegistryRule
          # Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled'
          Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts = 'Enabled'

          # CceId: CCE-36148-5
          # DataSource: BaselineRegistryRule
          # Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'
          Network_access_Let_Everyone_permissions_apply_to_anonymous_users = 'Disabled' 

          # CceId: CCE-36021-4
          # DataSource: BaselineRegistryRule
          # Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled'
          Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares = 'Enabled' 

          # CceId: CCE-37623-6
          # DataSource: BaselineRegistryRule
          # Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves' 
          Network_access_Sharing_and_security_model_for_local_accounts = 'Classic - Local users authenticate as themselves'

          # CceId: CCE-37035-3
          # DataSource: BaselineRegistryRule
          # Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled'
          Network_security_Allow_LocalSystem_NULL_session_fallback = 'Disabled'

          # CceId: CCE-38047-7
          # DataSource: BaselineRegistryRule
          # Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled'
          Network_security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities = 'Disabled'

          # CceId: CCE-36326-7
          # DataSource: BaselineRegistryRule
          # Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'
          Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change = 'Enabled'

          # CceId: CCE-36858-9
          # DataSource: BaselineRegistryRule
          # Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher
          Network_security_LDAP_client_signing_requirements = 'Negotiate Signing' 

          # CceId: CCE-37553-5
          # DataSource: BaselineRegistryRule
          # Ensure 'Network security: Minimum session security for NTLM SSP based clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'
          Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients = 'Both options checked' 

          # CceId: CCE-37835-6
          # DataSource: BaselineRegistryRule
          # Ensure 'Network security: Minimum session security for NTLM SSP based servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'
          Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers = 'Both options checked' 

          # CceId: CCE-36788-8
          # DataSource: BaselineRegistryRule
          # Ensure 'Shutdown: Allow system to be shut down without having to log on' is set to 'Disabled'
          Shutdown_Allow_system_to_be_shut_down_without_having_to_log_on = 'Disabled'

          # CceId: CCE-37885-1
          # DataSource: BaselineRegistryRule
          # Ensure 'System objects: Require case insensitivity for non-Windows subsystems' is set to 'Enabled'
          System_objects_Require_case_insensitivity_for_non_Windows_subsystems = 'Enabled' 

          # CceId: CCE-37644-2
          # DataSource: BaselineRegistryRule
          # Ensure 'System objects: Strengthen default permissions of internal system objects ' is set to 'Enabled'
          System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links = 'Enabled'

          # CceId: CCE-36494-3
          # DataSource: BaselineRegistryRule
          # Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled'
          User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account = 'Enabled'

          # CceId: CCE-36863-9
          # DataSource: BaselineRegistryRule
          # Ensure 'User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop' is set to 'Disabled'
          User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop = 'Disabled'

          # CceId: CCE-37029-6
          # DataSource: BaselineRegistryRule
          # Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop'
          User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode = 'Prompt for consent on the secure desktop'

          # CceId: CCE-36864-7
          # DataSource: BaselineRegistryRule
          # Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'
          User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users = 'Automatically deny elevation request'

          # CceId: CCE-36533-8
          # DataSource: BaselineRegistryRule
          # Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled'
          User_Account_Control_Detect_application_installations_and_prompt_for_elevation = 'Enabled'

          # CceId: CCE-37057-7
          # DataSource: BaselineRegistryRule
          # Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled'
          User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations = 'Enabled'

          # CceId: CCE-36869-6
          # DataSource: BaselineRegistryRule
          # Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled'
          User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode = 'Enabled'

          # CceId: CCE-36866-2
          # DataSource: BaselineRegistryRule
          # Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled'
          User_Account_Control_Switch_to_the_secure_desktop_when_prompting_for_elevation = 'Enabled'

          # CceId: CCE-37064-3
          # DataSource: BaselineRegistryRule
          # Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'
          User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations = 'Enabled'

          # CceId: NOT_ASSIGNED
          # DataSource: BaselineRegistryRule
          # Recovery console: Allow floppy copy and access to all drives and all folders
          Recovery_console_Allow_floppy_copy_and_access_to_all_drives_and_folders = 'Disabled'

          # CceId: CCE-37432-2
          # DataSource: BaselineSecurityPolicyRule
          # Ensure 'Accounts: Guest account status' is set to 'Disabled'
          Accounts_Guest_account_status = 'Disabled'
       }

        # CceId: CCE-38329-9
        # DataSource: BaselineAuditPolicyRule
        # Ensure 'Audit Application Group Management' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Application Group Management (Success)'  {
            Name      = 'Application Group Management'
            AuditFlag = 'Success'
            Ensure    = 'Absent'
        }

        AuditPolicySubcategory 'Audit Application Group Management (Failure)'  {
            Name      = 'Application Group Management'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }

        # CceId: CCE-38004-8
        # DataSource: BaselineAuditPolicyRule
        # Ensure 'Audit Computer Account Management' is set to 'Success'    
        AuditPolicySubcategory 'Audit Computer Account Management (Success)'  {
            Name      = 'Computer Account Management'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Computer Account Management (Failure)'  {
            Name      = 'Computer Account Management'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }

        # CceId: CCE-37741-6
        # DataSource: BaselineAuditPolicyRule
        # Ensure 'Audit Credential Validation' is set to 'Success and Failure'
        AuditPolicySubcategory "Audit Credential Validation (Success)"  {
            Name      = 'Credential Validation'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Credential Validation (Failure)'
        {
            Name      = 'Credential Validation'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        # CceId: CCE-36265-7
        # DataSource: BaselineAuditPolicyRule
        # Ensure 'Audit Distribution Group Management' is set to 'No Auditing'
        AuditPolicySubcategory 'Audit Distribution Group Management (Success)'  {
            Name      = 'Distribution Group Management'
            AuditFlag = 'Success'
            Ensure    = 'Absent'
        }

        AuditPolicySubcategory 'Audit Distribution Group Management (Failure)'  {
            Name      = 'Distribution Group Management'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }

        # CceId: CCE-38237-4
        # DataSource: BaselineAuditPolicyRule
        # Ensure 'Audit Logoff' is set to 'Success'
        AuditPolicySubcategory 'Audit Logoff (Success)'  {
            Name      = 'Logoff'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Logoff (Failure)' {
            Name      = 'Logoff'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }

        # CceId: CCE-38036-0
        # DataSource: BaselineAuditPolicyRule
        # Ensure 'Audit Logon' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Logon (Success)'  {
            Name      = 'Logon'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Logon (Failure)'  {
            Name      = 'Logon'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        # CceId: CCE-37855-4
        # DataSource: BaselineAuditPolicyRule
        # Ensure 'Audit Other Account Management Events' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Other Account Management Events (Success)'  {
            Name      = 'Other Account Management Events'
            AuditFlag = 'Success'
            Ensure    = 'Absent'
        }

        AuditPolicySubcategory 'Audit Other Account Management Events (Failure)' {
            Name      = 'Other Account Management Events'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }

        # CceId: NOT_ASSIGNED
        # DataSource: BaselineAuditPolicyRule
        # Ensure 'Audit PNP Activity' is set to 'Success'
        AuditPolicySubcategory 'Audit PNP Activity (Success)' {
            Name      = 'Plug and Play Events'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit PNP Activity (Failure)' {
            Name      = 'Plug and Play Events'
            Ensure    = 'Absent'
            AuditFlag = 'Failure'
        }

        # CceId: CCE-36059-4
        # DataSource: BaselineAuditPolicyRule
        # Ensure 'Audit Process Creation' is set to 'Success'
        AuditPolicySubcategory 'Audit Process Creation (Success)'  {
            Name      = 'Process Creation'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Process Creation (Failure)'  {
            Name      = 'Process Creation'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }

        # CceId: CCE-37617-8
        # DataSource: BaselineAuditPolicyRule
        # Ensure 'Audit Removable Storage' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Removable Storage (Success)' {
            Name      = 'Removable Storage'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Removable Storage (Failure)' {
            Name      = 'Removable Storage'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        # CceId: CCE-38034-5
        # DataSource: BaselineAuditPolicyRule
        # Ensure 'Audit Security Group Management' is set to 'Success'
        AuditPolicySubcategory 'Audit Security Group Management (Success)' {
            Name      = 'Security Group Management'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Security Group Management (Failure)' {
            Name      = 'Security Group Management'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }

        # CceId: CCE-36266-5
        # DataSource: BaselineAuditPolicyRule
        # Ensure 'Audit Special Logon' is set to 'Success'
        AuditPolicySubcategory 'Audit Special Logon (Success)' 
        {
            Name      = 'Special Logon'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Special Logon (Failure)' 
        {
            Name      = 'Special Logon'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }

        # CceId: CCE-37856-2
        # DataSource: BaselineAuditPolicyRule
        # Ensure 'Audit User Account Management' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit User Account Management (Success)' {
            Name      = 'User Account Management'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit User Account Management (Failure)' {
            Name      = 'User Account Management'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        # CceId: NOT_ASSIGNED
        # DataSource: BaselineAuditPolicyRule
        # Audit Non Sensitive Privilege Use
        AuditPolicySubcategory 'Audit Non Sensitive Privilege Use (Success)'  {
            Name      = 'Non Sensitive Privilege Use'
            AuditFlag = 'Success'
            Ensure    = 'Absent'
        }

        AuditPolicySubcategory 'Audit Non Sensitive Privilege Use (Failure)' {
            Name      = 'Non Sensitive Privilege Use'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }


    # Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'
    Registry LimitBlankPasswordUse
    {
        Ensure = "Present"
        Key = "HKLM:System\CurrentControlSet\Control\Lsa"
        ValueName = "LimitBlankPasswordUse"
        ValueData = "1"
        ValueType = "Dword"
    }

    # Ensure 'Allow Basic authentication' is set to 'Disabled'
    Registry AllowBasic
    {
        Ensure = "Present"
        Key = "HKLM:Software\Policies\Microsoft\Windows\WinRM\Client"
        ValueName = "AllowBasic"
        ValueData = "0"
        ValueType = "Dword"
    }

    # Ensure 'Allow indexing of encrypted files' is set to 'Disabled'
    Registry AllowIndexingEncryptedStoresOrItems
    {
        Ensure = "Present"
        Key = "HKLM:Software\Policies\Microsoft\Windows\Windows Search"
        ValueName = "AllowIndexingEncryptedStoresOrItems"
        ValueData = "0"
        ValueType = "Dword"
    }

    # Ensure 'Allow Input Personalization' is set to 'Disabled'
    Registry AllowingInputPersonalization
    {
       Ensure = "Present"
       Key = "HKLM:Software\Policies\Microsoft\InputPersonalization"
       ValueName = "AllowInputPersonalization"
       ValueData = "0"
       ValueType = "Dword"
    }

    # Ensure 'Allow Telemetry' is set to 'Enabled: 0 - Security [Enterprise Only]'
    Registry AllowingTelemetry
    {
       Ensure = "Present"
       Key = "HKLM:Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
       ValueName = "AllowTelemetry"
       ValueData = "0"
       ValueType = "Dword"
    }

    # Ensure 'Allow unencrypted traffic from Windows Remote Management (WinRM)' is set to 'Disabled'
    Registry AllowUnencryptedTraffic
    {
       Ensure = "Present"
       Key = "HKLM:Software\Policies\Microsoft\Windows\WinRM\Client"
       ValueName = "AllowUnencryptedTraffic"
       ValueData = "0"
       ValueType = "Dword"
    }

    # Ensure 'Allow user control over installs' is set to 'Disabled'
    Registry EnableUserControl
    {
      Ensure = "Present"
      Key = "HKLM:Software\Policies\Microsoft\Windows\Installer"
      ValueName = "EnableUserControl"
      ValueData = "0"
      ValueType = "Dword"
    }

    # Ensure 'Always install with elevated privileges' is set to 'Disabled'
    Registry AlwaysInstallElevated
    {
     Ensure = "Present"
     Key = "HKLM:Software\Policies\Microsoft\Windows\Installer"
     ValueName = "AlwaysInstallElevated"
     ValueData = "0"
     ValueType = "Dword"
    }  

    # Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'
    Registry CrashOnAuditFail
    {
    Ensure = "Present"
    Key = "HKLM:System\CurrentControlSet\Control\Lsa"
    ValueName = "CrashOnAuditFail"
    ValueData = "0"
    ValueType = "Dword"
    } 

    # Ensure 'Configure Offer Remote Assistance' is set to 'Disabled'
    Registry AllowUnsolicited
    {
    Ensure = "Present"
    Key = "HKLM:Software\Policies\Microsoft\Windows NT\Terminal Services"
    ValueName = "AllowUnsolicited"
    ValueData = "0"
    ValueType = "Dword"
    }

    # Ensure 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'
    Registry NoBackgroundPolicy
    {
    Ensure = "Present"
    Key = "HKLM:Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"
    ValueName = "NoBackgroundPolicy"
    ValueData = "0"
    ValueType = "Dword"
    }

    # Ensure 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE'
    Registry NoGPOListChanges
    {
    Ensure = "Present"
    Key = "HKLM:Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"
    ValueName = "NoGPOListChanges"
    ValueData = "0"
    ValueType = "Dword"
    }

    # Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'
    Registry ConfigureSolicitedRemoteAssist
    {
    Ensure = "Present"
    ValueName = "AllowToGetHelp"
    Key = "HKLM:Software\Policies\Microsoft\Windows NT\Terminal Services"
    ValueData = "0"
    ValueType = "Dword"
    }

    # Ensure 'Continue experiences on this device' is set to 'Disabled'
    Registry EnableCdp
    {
    Ensure = "Present"
    ValueName = "EnableCdp"
    Key = "HKLM:Software\Policies\Microsoft\Windows\System"
    ValueData = "0"
    ValueType = "Dword"
    } 

    # Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'
    Registry AddPrinterDrivers
    {
    Ensure = "Present"
    ValueName = "AddPrinterDrivers"
    Key = "HKLM:System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers"
    ValueData = "1"
    ValueType = "Dword"
    }

    # Ensure 'Disallow Digest authentication' is set to 'Enabled'
    Registry AllowDigest
    {
    Ensure = "Present"
    ValueName = "AllowDigest"
    Key = "HKLM:Software\Policies\Microsoft\Windows\WinRM\Client"
    ValueData = "0"
    ValueType = "Dword"
    }

    # Ensure 'Do not enumerate connected users on domain-joined computers' is set to 'Enabled'
    Registry DontEnumerateConnectedUsers
    {
    Ensure = "Present"
    ValueName = "DontEnumerateConnectedUsers"
    Key = "HKLM:Software\Policies\Microsoft\Windows\System"
    ValueData = "1"
    ValueType = "Dword"
    }

    # Ensure 'Domain member: Digitally encrypt or sign secure channel data ' is set to 'Enabled'     
    Registry RequireSignOrSeal
    {
    Ensure = "Present"
    ValueName = "RequireSignOrSeal"
    Key = "HKLM:System\CurrentControlSet\Services\Netlogon\Parameters"
    ValueData = "1"
    ValueType = "Dword"
    }

    # Ensure 'Domain member: Digitally encrypt secure channel data ' is set to 'Enabled'
    Registry SealSecureChannel
    {
    Ensure = "Present"
    ValueName = "SealSecureChannel"
    Key = "HKLM:System\CurrentControlSet\Services\Netlogon\Parameters"
    ValueData = "1"
    ValueType = "Dword"
    }

    # Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'

    Registry SignSecureChannel
    {
    Ensure = "Present"
    ValueName = "SignSecureChannel"
    Key = "HKLM:System\CurrentControlSet\Services\Netlogon\Parameters"
    ValueData = "1"
    ValueType = "Dword"
    }

    # Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled'
    
    Registry DisablePasswordC
    {
    Ensure = "Present"
    ValueNAme = "DisablePasswordC"
    Key = "HKLM:System\CurrentControlSet\Services\Netlogon\Parameters"
    ValueData = "0"
    ValueType = "Dword"
    }

    # Ensure 'Domain member: Maximum machine account password age' is set to '30 or fewer days, but not 0'
    
    Registry MaximumPasswordAge
    {
    Ensure = "Present"
    ValueName = "MaximumPasswordAge"
    Key = "HKLM:System\CurrentControlSet\Services\Netlogon\Parameters"
    ValueData = "30"
    ValueType = "Dword"
    }

    # Ensure 'Domain member: Require strong session key' is set to 'Enabled'
    
    Registry RequireStrongKey 
    {
    Ensure = "Present"
    ValueName = "RequireStrongKey"
    Key = "HKLM:System\CurrentControlSet\Services\Netlogon\Parameters"
    ValueData = "1"
    ValueType = "Dword"
    }

    # Ensure 'Enable insecure guest logons' is set to 'Disabled'
    Registry AllowInsecureGuestAuth
    {
    Ensure = "Present"
    ValueName = "AllowInsecureGuestAuth"
    Key = "HKLM:Software\Policies\Microsoft\Windows\LanmanWorkstation"
    ValueData = "0"
    ValueType = "Dword"
    }

    # Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled'
    Registry EnumerateAdministrators
    {
    Ensure = "Present"
    ValueName = "EnumerateAdministrators"
    Key = "HKLM:Software\Microsoft\Windows\CurrentVersion\Policies\CredUI"
    ValueData = "0"
    ValueType = "Dword"
    }

    # Ensure 'Enumerate local users on domain-joined computers' is set to 'Disabled'
    Registry EnumerateLocalUsers
    {
    Ensure = "Present"
    ValueName = "EnumerateLocalUsers"
    Key = "HKLM:Software\Policies\Microsoft\Windows\System"
    ValueData = "0"
    ValueType = "Dword"
    }

    # Ensure 'Interactive logon: Do not display last user name' is set to 'Enabled'
    Registry DontDisplayLastUserName
    {
    Ensure = "Present"
    ValueName = "DontDisplayLastUserName"
    Key = "HKLM:Software\Microsoft\Windows\CurrentVersion\Policies\System"
    ValueData = "1"
    ValueType = "Dword"
    }

    # Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'
    Registry DisableCAD
    {
    Ensure = "Present"
    ValueName = "DisableCAD"
    Key = "HKLM:Software\Microsoft\Windows\CurrentVersion\Policies\System"
    ValueData = "0"
    ValueType = "Dword" 
    }

    # Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'
    Registry RequireSecuritySignature
    {
    Ensure = "Present"
    ValueName = "RequireSecuritySignature"
    Key = "HKLM:System\CurrentControlSet\Services\LanmanWorkstation\Parameters"
    ValueData = "1"
    ValueType = "Dword"
    }

    # Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled'
    Registry EnableSecuritySignature
    {
    Ensure = "Present"
    ValueName = "EnableSecuritySignature"
    Key = "HKLM:System\CurrentControlSet\Services\LanmanWorkstation\Parameters"
    ValueData = "1"
    ValueType = "Dword"
    }

    # Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled'
    Registry EnablePlainTextPassword
    {
    Ensure = "Present"
    ValueName = "EnablePlainTextPassword"
    Key = "HKLM:System\CurrentControlSet\Services\LanmanWorkstation\Parameters"
    ValueData = "0"
    ValueType = "Dword"
    }

    # Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute, but not 0'
    Registry AutoDisconnect
    {
    Ensure = "Present"
    ValueName = "AutoDisconnect"
    Key = "HKLM:System\CurrentControlSet\Services\LanManServer\Parameters"
    ValueData = "15"
    ValueType = "Dword"
    }

    # Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'
    Registry EnableForcedLogoff
    {
    Ensure = "Present"
    ValueName = "EnableForcedLogoff"
    Key = "HKLM:System\CurrentControlSet\Services\LanManServer\Parameters"
    ValueData = "1"
    ValueType = "Dword"
    }

    # Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled'
    Registry RestrictAnonymous
    {
    Ensure = "Present"
    ValueName = "RestrictAnonymous"
    Key = "HKLM:System\CurrentControlSet\Control\Lsa"
    ValueData = "1"
    ValueType = "Dword"
    }

    # Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled'
    Registry RestrictAnonymousSAM
    {
    Ensure = "Present"
    ValueName = "RestrictAnonymousSAM"
    Key = "HKLM:System\CurrentControlSet\Control\Lsa"
    ValueData = "1"
    ValueType = "Dword"
    }

    # Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'
    Registry EveryoneIncludesAnonymous
    {
    Ensure = "Present"
    ValueName = "EveryoneIncludesAnonymous"
    Key = "HKLM:System\CurrentControlSet\Control\Lsa"
    ValueData = "0"
    ValueType = "Dword"
    }

    # Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled'
    Registry RestrictNullSessAccess
    {
    Ensure = "Present"
    ValueName = "RestrictNullSessAccess"
    Key = "HKLM:System\CurrentControlSet\Services\LanManServer\Parameters"
    ValueData = "1"
    ValueType = "Dword"
    } 

    # Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves'
    Registry ForceGuest
    {
    Ensure = "Present"
    ValueName = "ForceGuest"
    Key = "HKLM:System\CurrentControlSet\Control\Lsa"
    ValueData = "0"
    ValueType = "Dword"
    }

    # Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled'
    Registry AllowNullSessionFallback
    {
    Ensure = "Present"
    ValueName = "AllowNullSessionFallback"
    Key = "HKLM:System\CurrentControlSet\Control\Lsa\MSV1_0"
    ValueData = "0"
    ValueType = "Dword"
    }

    # Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled'
    Registry AllowOnlineID
    {
    Ensure = "Present"
    ValueName = "AllowOnlineID"
    Key = "HKLM:System\CurrentControlSet\Control\Lsa\pku2u"
    ValueData = "0"
    ValueType = "Dword"
    }

    # Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'
    Registry NoLMHash
    {
    Ensure = "Present"
    ValueName = "NoLMHash"
    Key = "HKLM:System\CurrentControlSet\Control\Lsa"
    ValueData = "1"
    ValueType = "Dword"
    }

    # Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher
    Registry LDAPClientIntegrity    
    {
    Ensure = "Present"
    ValueName = "LDAPClientIntegrity"
    Key = "HKLM:System\CurrentControlSet\Services\LDAP"
    ValueData = "1"
    ValueType = "Dword" 
    }

    # Ensure 'Network security: Minimum session security for NTLM SSP based  clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'
    Registry NTLMMinClientSec
    {
    Ensure = "Present"
    ValueName = "NTLMMinClientSec"
    Key = "HKLM:System\CurrentControlSet\Control\Lsa\MSV1_0"
    ValueData = "537395200"
    ValueType = "Dword"
    }

    # Ensure 'Network security: Minimum session security for NTLM SSP based  servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'
    Registry NTLMMinServerSec
    {
    Ensure = "Present"
    ValueName = "NTLMMinServerSec"
    Key = "HKLM:System\CurrentControlSet\Control\Lsa\MSV1_0"
    ValueData = "537395200"
    ValueType = "Dword"
    } 

    # Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'
    Registry NC_AllowNetBridge_NLA
    {
    Ensure = "Present"
    ValueName = "NC_AllowNetBridge_NLA"
    Key = "HKLM:Software\Policies\Microsoft\Windows\Network Connections"
    ValueData = "0"
    ValueType = "Dword"
    }

    # Ensure 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled'
    Registry NC_PersonalFirewallConfig
    {
    Ensure = "Present"
    ValueName = "NC_PersonalFirewallConfig"
    Key = "HKLM:Software\Policies\Microsoft\Windows\Network Connections"
    ValueData = "0"
    ValueType = "Dword"
    }

    # Ensure 'Shutdown: Allow system to be shut down without having to log on' is set to 'Disabled'
    Registry ShutdownWithoutLogon
    {
    Ensure = "Present"
    ValueName = "ShutdownWithoutLogon"
    Key = "HKLM:Software\Microsoft\Windows\CurrentVersion\Policies\System"
    ValueData = "0"
    ValueType = "Dword"
    }

    # Ensure 'Sign-in last interactive user automatically after a system-initiated restart' is set to 'Disabled'
    Registry DisableAutomaticRestartSignOn
    {
    Ensure = "Present"
    ValueName = "DisableAutomaticRestartSignOn"
    Key = "HKLM:Software\Microsoft\Windows\CurrentVersion\Policies\System"
    ValueData = "1"
    ValueType = "Dword"
    }

    # Ensure 'System objects: Require case insensitivity for non-Windows subsystems' is set to 'Enabled'
    Registry ObCaseInsensitive
    {
    Ensure = "Present"
    ValueName = "ObCaseInsensitive"
    Key = "HKLM:System\CurrentControlSet\Control\Session Manager\Kernel"
    ValueData = "1"
    ValueType = "Dword"
    } 

    # Ensure 'System objects: Strengthen default permissions of internal system objects ' is set to 'Enabled'
    Registry ProtectionMode
    {
    Ensure = "Present"
    ValueName = "ProtectionMode"
    Key = "HKLM:System\CurrentControlSet\Control\Session Manager"
    ValueData = "1"
    ValueType = "Dword"
    }

    # Ensure 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled'
    Registry NoDataExecutionPrevention
    {
    Ensure = "Present"
    ValueName = "NoDataExecutionPrevention"
    Key = "HKLM:Software\Policies\Microsoft\Windows\Explorer"
    ValueData = "0"
    ValueType = "Dword"  
    }

    # Ensure 'Turn off heap termination on corruption' is set to 'Disabled'
    Registry NoHeapTermiantionOnCorruption
    {
    Ensure = "Present"
    ValueName = "NoHeapTerminationOnCorruption"
    Key = "HKLM:Software\Policies\Microsoft\Windows\Explorer"
    ValueData = "0"
    ValueType = "Dword"
    }

    # Ensure 'Turn off shell protocol protected mode' is set to 'Disabled'
    Registry PreXPSP2ShellProtocolBehavior
    {
    Ensure = "Present"
    ValueName = "PreXPSP2ShellProtocolBehavior"
    Key = "HKLM:Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    ValueData = "0"
    ValueType = "Dword"
    }

    # Ensure 'Turn on convenience PIN sign-in' is set to 'Disabled'
    Registry AllowDomainPINLogon
    {
    Ensure = "Present"
    ValueName = "AllowDomainPINLogon"
    Key = "HKLM:Software\Policies\Microsoft\Windows\System"
    ValueData = "0"
    ValueType = "Dword"
    }

    # Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled'
    Registry FilterAdministratorToken
    {
    Ensure = "Present"
    ValueName = "FilterAdministratorToken"
    Key = "HKLM:Software\Microsoft\Windows\CurrentVersion\Policies\System"
    ValueData = "1"
    ValueType = "Dword"
    }
    
    # Ensure 'User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop' is set to 'Disabled'
    Registry EnableUIADesktopToggle
    {
    Ensure = "Present"
    ValueName = "EnableUIADesktopToggle"
    Key = "HKLM:Software\Microsoft\Windows\CurrentVersion\Policies\System"
    ValueData = "1"
    ValueType = "Dword"
    }

    # Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop'
    Registry ConsentPromptBehaviorAdmin
    {
    Ensure = "Present"
    ValueName = "ConsentPromptBehaviorAdmin"
    Key = "HKLM:Software\Microsoft\Windows\CurrentVersion\Policies\System"
    ValueData = "2"
    ValueType = "Dword"
    }
     
    # Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'
    Registry ConsentPromptBehaviorUser
    {
    Ensure = "Present"
    ValueName = "ConsentPromptBehaviorUser"
    Key = "HKLM:Software\Microsoft\Windows\CurrentVersion\Policies\System"
    ValueData = "0"
    ValueType = "Dword"
    } 

    # Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled'
    Registry EnableInstallerDetection
    {
    Ensure = "Present"
    ValueName = "EnableInstallerDetection"
    Key = "HKLM:Software\Microsoft\Windows\CurrentVersion\Policies\System"
    ValueData = "1"
    ValueType = "Dword"
    }

    # Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled'
    Registry EnableSecureUIAPaths
    {
    Ensure = "Present"
    ValueName = "EnableSecureUIAPaths"
    Key = "HKLM:Software\Microsoft\Windows\CurrentVersion\Policies\System"
    ValueData = "1"
    ValueType = "Dword"
    } 

    # Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled'
    Registry EnableLUA    
    {
    Ensure = "Present"
    ValueName = "EnableLUA"
    Key = "HKLM:Software\Microsoft\Windows\CurrentVersion\Policies\System"
    ValueData = "1"
    ValueType = "Dword" 
    }

    # Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled'
    Registry PromptOnSecureDesktop
    {
    Ensure = "Present"
    ValueName = "PromptOnSecureDesktop"
    Key = "HKLM:Software\Microsoft\Windows\CurrentVersion\Policies\System"
    ValueData = "1"
    ValueType = "Dword"
    }

    # Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'
    Registry EnableVirtualization
    {
    Ensure = "Present"
    ValueName = "EnableVirtualization"
    Key = "HKLM:Software\Microsoft\Windows\CurrentVersion\Policies\System"
    ValueData = "1"
    ValueType = "Dword"
    }

    # Disable 'Configure local setting override for reporting to Microsoft MAPS'
    Registry LocalSettingOverrideSpynetReporting
    {
    Ensure = "Present"
    ValueName = "LocalSettingOverrideSpynetReporting"
    Key = "HKLM:Software\Policies\Microsoft\Windows Defender\SpyNet"
    ValueData = "0"
    ValueType = "Dword"
    }

    # Disable SMB v1 client
    Registry DependOnService
    {
    Ensure = "Present"
    ValueName = "DependOnService"
    Key = "HKLM:System\CurrentControlSet\Services\LanmanWorkstation"
    ValueData = "0"
    ValueType = "Dword"
    } 

    # Disable SMB v1 server
    Registry SMB1
    {
    Ensure = "Present"
    ValueName = "SMB1"
    Key = "HKLM:System\CurrentControlSet\Services\LanmanServer\Parameters"
    ValueData = "0"
    ValueType = "Dword"
    }

    # Disable Windows Search Service
    Registry Start
    {
    Ensure = "Present"
    ValueName = "Start"
    Key = "HKLM:System\CurrentControlSet\Services\Wsearch"
    ValueData = "4"
    ValueType = "Dword"
    }

    # Enable 'Scan removable drives' by setting DisableRemovableDriveScanning  to 0
    Registry EnableScanRemovableDrives
    {
    Ensure = "Present"
    ValueName = "EnableScanREmovableDrives"
    Key = "HKLM:Software\Policies\Microsoft\Windows Defender\Scan"
    ValueData = "0"
    ValueType = "Dword"
    }

    # Enable 'Turn on behavior monitoring'
    Registry DisableBehaviorMonitoring
    {
    Ensure = "Present"
    ValueName = "DisableBehaviorMonitoring"
    Key = "HKLM:Software\Policies\Microsoft\Windows Defender\Real-Time Protection"
    ValueData = "0"
    ValueType = "Dword"
    }  

    # Enable Windows Error Reporting
    Registry Disabled
    {
    Ensure = "Present"
    ValueName = "Disabled"
    Key = "HKLM:Software\Microsoft\Windows\Windows Error Reporting"
    ValueData = "0"
    ValueType = "Dword"
    }

    # Recovery console: Allow floppy copy and access to all drives and all folders
    Registry setcommand
    {
    Ensure = "Present"
    ValueName = "setcommand"
    Key = "HKLM:Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole"
    ValueData = "0"
    ValueType = "Dword"
    }

    # Shutdown: Clear virtual memory pagefile
    Registry ClearPageFileAtShutdown
    {
    Ensure = "Present"
    ValueName = "ClearPageFileAtShutdown"
    Key = "HKLM:System\CurrentControlSet\Control\Session Manager\Memory Management"
    ValueData = "0"
    ValueType = "Dword"
    }
  }
}    

DSCConfig_Windows2016_v1 localhost

cd $PSScriptRoot

Start-DscConfiguration -Path "$PSScriptRoot/DSCConfig_Windows2016_v1" -ComputerName localhost -Force -Verbose -Wait

Write-Output "Your DSC file has been successfully configured via Windows Server 2016"
Write-Output "If you get the error Invoke-CimMethod : The SendConfigurationApply function did not succeed when attempting to run a very short-lived process (e.g. a console app that requires arguments that have been omitted, thereby terminating immediately), it may be due to the OS mis-interpreting that the configuration failed. The process still executed."