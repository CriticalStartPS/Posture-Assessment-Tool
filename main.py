from GraphAuthenticator import GraphAuthenticator
from TenantInfoHandler import TenantInfoHandler
from EntraID.ConditionalAccess.ConditionalAccessPolicyHandler import ConditionalAccessPolicyHandler
from EntraID.AuthorizationPolicy.AuthorizationPolicyHandler import AuthorizationPolicyHandler
from DefenderForOffice365.AntiSpamPolicyHandler import AntiSpamPolicyHandler
from DefenderForOffice365.AntiPhishingPolicyHandler import AntiPhishingPolicyHandler
from DefenderForOffice365.AntiMalwarePolicyHandler import AntiMalwarePolicyHandler
from DefenderForOffice365.SafeAttachmentsPolicyHandler import SafeAttachmentsPolicyHandler
from DefenderForOffice365.SafeLinksPolicyHandler import SafeLinksPolicyHandler
from DefenderForOffice365.ExchangeOnlineConfigHandler import ExchangeOnlineConfigHandler
from DefenderForOffice365.ExchangeOnlineSessionManager import ExchangeOnlineSessionManager
from DefenderForOffice365.MultiDomainDNSConfigHandler import MultiDomainDNSConfigHandler
from DefenderForEndpoint.AntivirusConfigHandler import AntivirusConfigHandler
from DefenderForEndpoint.AttackSurfaceReductionConfigHandler import AttackSurfaceReductionConfigHandler
from ReportGenerator import ReportGenerator
import os

def main():
    auth = GraphAuthenticator()
    token = auth.authenticate()
    if token:
        # Get Conditional Access results
        ca_handler = ConditionalAccessPolicyHandler(token, 'config/ConditionalAccess/policy_requirements.yaml')
        policies = ca_handler.fetch_policies()
        ca_results = ca_handler.check_policies(policies)
        
        print("\nDebug - Conditional Access Results:")
        print(f"Number of results: {len(ca_results)}")
        for result in ca_results:
            print(f"Policy: {result['requirement_name']}")
            print(f"Found: {result['found']}")
            print(f"Status: {result.get('status', 'N/A')}")
            print("-" * 40)

        # Get Authorization Policy results
        auth_handler = AuthorizationPolicyHandler(token, 'config/AuthorizationPolicy/policy_requirements.yaml')
        auth_results = auth_handler.check_policies()
        
        print("\nDebug - Authorization Policy Results:")
        print(f"Number of results: {len(auth_results)}")
        for result in auth_results:
            print(f"Policy: {result['requirement_name']}")
            print(f"Found: {result['found']}")
            print(f"Status: {result.get('status', 'N/A')}")
            print("-" * 40)

        # Get Defender for Endpoint Antivirus Configuration results
        print("\n=== Checking Defender for Endpoint Antivirus Configurations ===")
        try:
            antivirus_handler = AntivirusConfigHandler(token, 'config/DefenderForEndpoint/antivirus_requirements.yaml')
            antivirus_results = antivirus_handler.check_policies()
            
            print("\nDebug - Defender for Endpoint Antivirus Results:")
            print(f"Number of results: {len(antivirus_results)}")
            for result in antivirus_results:
                print(f"Policy: {result['requirement_name']}")
                print(f"Found: {result['found']}")
                print(f"Status: {result.get('status', 'N/A')}")
                print("-" * 40)
        except Exception as e:
            print(f"Error checking Defender for Endpoint antivirus configurations: {e}")
            antivirus_results = [{
                'requirement_name': 'Antivirus Configuration Error',
                'check_id': 'ANTIVIRUS_ERROR',
                'found': False,
                'status': f'ERROR - {str(e)}',
                'policy_type': 'antivirus'
            }]

        # Get Defender for Endpoint Attack Surface Reduction Configuration results
        print("\n=== Checking Defender for Endpoint Attack Surface Reduction Configurations ===")
        try:
            asr_handler = AttackSurfaceReductionConfigHandler(token, 'config/DefenderForEndpoint/asr_requirements.yaml')
            asr_results = asr_handler.check_policies()
            
            print("\nDebug - Defender for Endpoint ASR Results:")
            print(f"Number of results: {len(asr_results)}")
            for result in asr_results:
                print(f"Policy: {result['requirement_name']}")
                print(f"Found: {result['found']}")
                print(f"Status: {result.get('status', 'N/A')}")
                print("-" * 40)
        except Exception as e:
            print(f"Error checking Defender for Endpoint ASR configurations: {e}")
            asr_results = [{
                'requirement_name': 'ASR Configuration Error',
                'check_id': 'ASR_ERROR',
                'found': False,
                'status': f'ERROR - {str(e)}',
                'policy_type': 'asr'
            }]

        # Create shared Exchange Online session manager for all Defender for Office 365 policies
        exchange_session_manager = ExchangeOnlineSessionManager()

        # Check what Defender policies we need and retrieve them all at once
        defender_policy_types = []
        antispam_results = []
        antiphishing_results = []
        antimalware_results = []
        safeattachments_results = []
        safelinks_results = []
        exchangeonline_results = []
        dns_results = []
        
        try:
            print("\n=== Checking Defender for Office 365 Anti-Spam Policies ===")
            
            # Check if Exchange Online module is available
            check_module_script = """
$module = Get-Module -ListAvailable -Name ExchangeOnlineManagement | Sort-Object Version -Descending | Select-Object -First 1
if ($module) {
    Write-Output "Module available: $($module.Version)"
    exit 0
} else {
    Write-Output "Module not available"
    exit 1
}
"""
        
            import subprocess
            
            # Try PowerShell 7 first
            powershell_exe = "pwsh"
            try:
                subprocess.run([powershell_exe, "-Version"], 
                             capture_output=True, timeout=5, check=True)
                print("Using PowerShell 7 (pwsh)")
            except (subprocess.CalledProcessError, FileNotFoundError):
                print("PowerShell 7 not found, using Windows PowerShell")
                powershell_exe = "powershell.exe"
            
            module_check = subprocess.run([
                powershell_exe,
                "-ExecutionPolicy", "Bypass",
                "-Command", check_module_script
            ], capture_output=True, text=True, timeout=30)
            
            if module_check.returncode != 0:
                print("Exchange Online PowerShell module not found. Please install it:")
                print("Install-Module -Name ExchangeOnlineManagement -Force")
                antispam_results = [{
                    'requirement_name': 'Module Missing',
                    'found': False,
                    'status': 'MISSING - Exchange Online PowerShell module not installed',
                    'policy_type': 'antispam'
                }]
                antiphishing_results = [{
                    'requirement_name': 'Module Missing',
                    'found': False,
                    'status': 'MISSING - Exchange Online PowerShell module not installed',
                    'policy_type': 'antiphishing'
                }]
                antimalware_results = [{
                    'requirement_name': 'Module Missing',
                    'found': False,
                    'status': 'MISSING - Exchange Online PowerShell module not installed',
                    'policy_type': 'antimalware'
                }]
                safeattachments_results = [{
                    'requirement_name': 'Module Missing',
                    'found': False,
                    'status': 'MISSING - Exchange Online PowerShell module not installed',
                    'policy_type': 'safeattachments'
                }]
                safelinks_results = [{
                    'requirement_name': 'Module Missing',
                    'found': False,
                    'status': 'MISSING - Exchange Online PowerShell module not installed',
                    'policy_type': 'safelinks'
                }]
                exchangeonline_results = [{
                    'requirement_name': 'Module Missing',
                    'found': False,
                    'status': 'MISSING - Exchange Online PowerShell module not installed',
                    'policy_type': 'exchangeonline'
                }]
            else:
                print(f"Exchange Online module found: {module_check.stdout.strip()}")
                
                # Check which anti-spam files exist
                inbound_standard_file = 'config/DefenderForOffice365/antispam_inbound_standard_requirements.yaml'
                inbound_strict_file = 'config/DefenderForOffice365/antispam_inbound_strict_requirements.yaml'
                outbound_file = 'config/DefenderForOffice365/antispam_outbound_requirements.yaml'
                
                standard_exists = os.path.exists(inbound_standard_file)
                strict_exists = os.path.exists(inbound_strict_file)
                outbound_exists = os.path.exists(outbound_file)
                
                print(f"Standard inbound requirements file exists: {standard_exists}")
                print(f"Strict inbound requirements file exists: {strict_exists}")
                print(f"Outbound requirements file exists: {outbound_exists}")
                
                # Check for legacy anti-spam files if none found
                legacy_inbound_file = None
                if not standard_exists and not strict_exists and not outbound_exists:
                    print("No anti-spam requirements files found. Checking for legacy files...")
                    
                    legacy_inbound_candidate = 'config/DefenderForOffice365/antispam_inbound_requirements.yaml'
                    legacy_general_candidate = 'config/DefenderForOffice365/antispam_requirements.yaml'
                    
                    if os.path.exists(legacy_inbound_candidate):
                        print("Found legacy antispam_inbound_requirements.yaml file")
                        legacy_inbound_file = legacy_inbound_candidate
                    elif os.path.exists(legacy_general_candidate):
                        print("Found legacy antispam_requirements.yaml file")
                        legacy_inbound_file = legacy_general_candidate
                
                # Check which anti-phishing files exist
                antiphishing_standard_file = 'config/DefenderForOffice365/antiphishing_standard_requirements.yaml'
                antiphishing_strict_file = 'config/DefenderForOffice365/antiphishing_strict_requirements.yaml'
                
                antiphishing_standard_exists = os.path.exists(antiphishing_standard_file)
                antiphishing_strict_exists = os.path.exists(antiphishing_strict_file)
                
                print(f"Standard antiphishing requirements file exists: {antiphishing_standard_exists}")
                print(f"Strict antiphishing requirements file exists: {antiphishing_strict_exists}")
                
                # Check which anti-malware files exist
                antimalware_file = 'config/DefenderForOffice365/antimalware_requirements.yaml'
                antimalware_exists = os.path.exists(antimalware_file)
                
                print(f"Anti-malware requirements file exists: {antimalware_exists}")
                
                # Check which Safe Attachments files exist
                safeattachments_file = 'config/DefenderForOffice365/safeattachments_requirements.yaml'
                safeattachments_exists = os.path.exists(safeattachments_file)
                
                print(f"Safe Attachments requirements file exists: {safeattachments_exists}")
                
                # Check which Safe Links files exist
                safelinks_file = 'config/DefenderForOffice365/safelinks_requirements.yaml'
                safelinks_exists = os.path.exists(safelinks_file)
                
                print(f"Safe Links requirements file exists: {safelinks_exists}")
                
                # Check which ATP Policy files exist
                exchangeonline_file = 'config/DefenderForOffice365/exchangeonline_requirements.yaml'
                exchangeonline_exists = os.path.exists(exchangeonline_file)
                
                print(f"Exchange Online requirements file exists: {exchangeonline_exists}")
                
                # Check which DNS files exist
                dns_file = 'config/DefenderForOffice365/dns_requirements.yaml'
                dns_exists = os.path.exists(dns_file)
                
                print(f"DNS requirements file exists: {dns_exists}")
                
                # Check which DNS files exist
                dns_file = 'config/DefenderForOffice365/dns_requirements.yaml'
                dns_exists = os.path.exists(dns_file)
                
                print(f"DNS requirements file exists: {dns_exists}")
                
                # Determine which policy types we need
                need_antispam = (standard_exists or strict_exists or outbound_exists or legacy_inbound_file)
                need_antiphishing = (antiphishing_standard_exists or antiphishing_strict_exists)
                need_antimalware = antimalware_exists
                need_safeattachments = safeattachments_exists
                need_safelinks = safelinks_exists
                need_exchangeonline = exchangeonline_exists
                need_dns = dns_exists
                
                if need_antispam:
                    defender_policy_types.extend(['antispam_inbound', 'antispam_outbound'])
                
                if need_antiphishing:
                    defender_policy_types.append('antiphishing')
                
                if need_antimalware:
                    defender_policy_types.append('antimalware')
                
                if need_safeattachments:
                    defender_policy_types.append('safeattachments')
                
                if need_safelinks:
                    defender_policy_types.append('safelinks')
                
                if need_exchangeonline:
                    defender_policy_types.append('atppolicy')
                    defender_policy_types.append('externalinoutlook')
                    defender_policy_types.append('organizationconfig')
                    defender_policy_types.append('reportsubmissionpolicy')
                    defender_policy_types.append('dkim')
                
                if need_dns:
                    # Add DKIM and authoritative domains for multi-domain DNS checks
                    if 'dkim' not in defender_policy_types:
                        defender_policy_types.append('dkim')
                    if 'authoritativedomains' not in defender_policy_types:
                        defender_policy_types.append('authoritativedomains')
                
                # Retrieve all needed Defender policies in a single authentication session
                if defender_policy_types:
                    print(f"\n=== Retrieving all Defender policies in single session: {defender_policy_types} ===")
                    all_defender_policies = exchange_session_manager.get_all_defender_policies(defender_policy_types)
                    print(f"Retrieved policies: {list(all_defender_policies.keys())}")
                
                # Process anti-spam policies if needed
                if need_antispam:
                    try:
                        if legacy_inbound_file:
                            print("Using legacy anti-spam requirements file")
                            antispam_handler = AntiSpamPolicyHandler(legacy_inbound_file=legacy_inbound_file, session_manager=exchange_session_manager)
                        else:
                            antispam_handler = AntiSpamPolicyHandler(
                                inbound_standard_file=inbound_standard_file if standard_exists else None,
                                inbound_strict_file=inbound_strict_file if strict_exists else None,
                                outbound_requirements_file=outbound_file if outbound_exists else None,
                                session_manager=exchange_session_manager
                            )
                        
                        antispam_results = antispam_handler.check_policies()
                    except Exception as e:
                        print(f"Error processing anti-spam policies: {str(e)}")
                        antispam_results = [{
                            'requirement_name': 'Error',
                            'found': False,
                            'status': f'ERROR - {str(e)}',
                            'policy_type': 'antispam'
                        }]
                else:
                    print("No anti-spam requirements files found. Skipping anti-spam checks.")
                
                # Process anti-phishing policies if needed
                if need_antiphishing:
                    try:
                        print("\n=== Checking Defender for Office 365 Anti-Phishing Policies ===")
                        
                        antiphishing_handler = AntiPhishingPolicyHandler(
                            standard_file=antiphishing_standard_file if antiphishing_standard_exists else None,
                            strict_file=antiphishing_strict_file if antiphishing_strict_exists else None,
                            session_manager=exchange_session_manager  # Use the same shared session manager
                        )
                        
                        antiphishing_results = antiphishing_handler.check_policies()
                    except Exception as e:
                        print(f"Error processing anti-phishing policies: {str(e)}")
                        antiphishing_results = [{
                            'requirement_name': 'Error',
                            'found': False,
                            'status': f'ERROR - {str(e)}',
                            'policy_type': 'antiphishing'
                        }]
                else:
                    print("No anti-phishing requirements files found. Skipping anti-phishing checks.")

                # Process anti-malware policies if needed
                if need_antimalware:
                    try:
                        print("\n=== Checking Defender for Office 365 Anti-Malware Policies ===")
                        
                        antimalware_handler = AntiMalwarePolicyHandler(
                            requirements_file=antimalware_file,
                            session_manager=exchange_session_manager  # Use the same shared session manager
                        )
                        
                        antimalware_results = antimalware_handler.check_policies()
                    except Exception as e:
                        print(f"Error processing anti-malware policies: {str(e)}")
                        antimalware_results = [{
                            'requirement_name': 'Error',
                            'found': False,
                            'status': f'ERROR - {str(e)}',
                            'policy_type': 'antimalware'
                        }]
                else:
                    antimalware_results = []
                    print("No anti-malware requirements file found. Skipping anti-malware checks.")

                # Process Safe Attachments policies if needed
                if need_safeattachments:
                    try:
                        print("\n=== Checking Defender for Office 365 Safe Attachments Policies ===")
                        
                        safeattachments_handler = SafeAttachmentsPolicyHandler(
                            requirements_file=safeattachments_file,
                            session_manager=exchange_session_manager  # Use the same shared session manager
                        )
                        
                        safeattachments_results = safeattachments_handler.check_policies()
                    except Exception as e:
                        print(f"Error processing Safe Attachments policies: {str(e)}")
                        safeattachments_results = [{
                            'requirement_name': 'Error',
                            'found': False,
                            'status': f'ERROR - {str(e)}',
                            'policy_type': 'safeattachments'
                        }]
                else:
                    safeattachments_results = []
                    print("No Safe Attachments requirements file found. Skipping Safe Attachments checks.")

                # Process Safe Links policies if needed
                if need_safelinks:
                    try:
                        print("\n=== Checking Defender for Office 365 Safe Links Policies ===")
                        
                        safelinks_handler = SafeLinksPolicyHandler(
                            requirements_file=safelinks_file,
                            session_manager=exchange_session_manager  # Use the same shared session manager
                        )
                        
                        safelinks_results = safelinks_handler.check_policies()
                    except Exception as e:
                        print(f"Error processing Safe Links policies: {str(e)}")
                        safelinks_results = [{
                            'requirement_name': 'Error',
                            'found': False,
                            'status': f'ERROR - {str(e)}',
                            'policy_type': 'safelinks'
                        }]
                else:
                    safelinks_results = []
                    print("No Safe Links requirements file found. Skipping Safe Links checks.")

                # Process Exchange Online configs if needed
                if need_exchangeonline:
                    try:
                        print("\n=== Checking Exchange Online Configurations ===")
                        
                        exchangeonline_handler = ExchangeOnlineConfigHandler(
                            requirements_file=exchangeonline_file,
                            session_manager=exchange_session_manager  # Use the same shared session manager
                        )
                        
                        exchangeonline_results = exchangeonline_handler.check_policies()
                    except Exception as e:
                        print(f"Error processing Exchange Online configurations: {str(e)}")
                        exchangeonline_results = [{
                            'requirement_name': 'Error',
                            'found': False,
                            'status': f'ERROR - {str(e)}',
                            'policy_type': 'exchangeonline'
                        }]
                else:
                    exchangeonline_results = []
                    print("No Exchange Online requirements file found. Skipping Exchange Online checks.")

                # Process DNS configurations if needed
                if need_dns:
                    try:
                        print("\n=== Checking DNS Configurations for All Authoritative Domains ===")
                        
                        # Use multi-domain DNS handler for comprehensive checking
                        dns_handler = MultiDomainDNSConfigHandler(
                            exchange_session_manager=exchange_session_manager,
                            requirements_file_path=dns_file
                        )
                        
                        dns_results = dns_handler.check_policies()
                    except Exception as e:
                        print(f"Error processing multi-domain DNS configurations: {str(e)}")
                        dns_results = [{
                            'requirement_name': 'Multi-Domain DNS Check Error',
                            'found': False,
                            'status': f'ERROR - {str(e)}',
                            'policy_type': 'dns',
                            'domain': 'N/A'
                        }]
                else:
                    dns_results = []
                    print("No DNS requirements file found. Skipping DNS checks.")

        except Exception as e:
            print(f"Error in Defender for Office 365 policy checks: {str(e)}")
            if not antispam_results:
                antispam_results = [{
                    'requirement_name': 'Error',
                    'found': False,
                    'status': f'ERROR - {str(e)}',
                    'policy_type': 'antispam'
                }]
            if not antiphishing_results:
                antiphishing_results = [{
                    'requirement_name': 'Error',
                    'found': False,
                    'status': f'ERROR - {str(e)}',
                    'policy_type': 'antiphishing'
                }]
            if not antimalware_results:
                antimalware_results = [{
                    'requirement_name': 'Error',
                    'found': False,
                    'status': f'ERROR - {str(e)}',
                    'policy_type': 'antimalware'
                }]
            if not safeattachments_results:
                safeattachments_results = [{
                    'requirement_name': 'Error',
                    'found': False,
                    'status': f'ERROR - {str(e)}',
                    'policy_type': 'safeattachments'
                }]
            if not safelinks_results:
                safelinks_results = [{
                    'requirement_name': 'Error',
                    'found': False,
                    'status': f'ERROR - {str(e)}',
                    'policy_type': 'safelinks'
                }]
            if not exchangeonline_results:
                exchangeonline_results = [{
                    'requirement_name': 'Error',
                    'found': False,
                    'status': f'ERROR - {str(e)}',
                    'policy_type': 'exchangeonline'
                }]
            if not dns_results:
                dns_results = [{
                    'requirement_name': 'Error',
                    'found': False,
                    'status': f'ERROR - {str(e)}',
                    'policy_type': 'dns'
                }]

        # Clear the session cache after all Defender policies are retrieved
        print(f"\nSession manager cached policies: {list(exchange_session_manager.get_cached_policies().keys())}")
        
        # Get tenant information
        print("\n=== Retrieving Tenant Information ===")
        tenant_handler = TenantInfoHandler(token)
        tenant_info = tenant_handler.get_tenant_information()
        
        # Update report generation to include all Defender for Office 365 policy results
        report = ReportGenerator()
        report.generate_report(ca_results, auth_results, antispam_results, antiphishing_results, antimalware_results, safeattachments_results, safelinks_results, exchangeonline_results, dns_results, antivirus_results, asr_results, tenant_info)

if __name__ == '__main__':
    main()