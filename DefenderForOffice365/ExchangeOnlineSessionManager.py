import subprocess
import json
import os
import tempfile
from typing import Dict, List, Any, Optional

class ExchangeOnlineSessionManager:
    """
    Shared session manager for Exchange Online connections across all Defender for Office 365 policy handlers.
    This class manages a single authentication session that can be used to retrieve multiple policy types.
    """
    
    def __init__(self):
        self._session_active = False
        self._cached_policies = {}
        self._powershell_exe = None
        
    def _determine_powershell_executable(self) -> str:
        """Determine which PowerShell executable to use"""
        if self._powershell_exe:
            return self._powershell_exe
            
        try:
            subprocess.run(["pwsh", "-Version"], 
                         capture_output=True, timeout=5, check=True)
            self._powershell_exe = "pwsh"
            print("Using PowerShell 7 (pwsh)")
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("PowerShell 7 not found, using Windows PowerShell")
            self._powershell_exe = "powershell.exe"
            
        return self._powershell_exe
    
    def get_all_defender_policies(self, policy_types: List[str] = None) -> Dict[str, List[Dict]]:
        """
        Retrieve all requested Defender for Office 365 policies in a single session.
        
        Args:
            policy_types: List of policy types to retrieve. Options:
                         ['antispam_inbound', 'antispam_outbound', 'antiphishing', 'antimalware', 'safeattachments', 'safelinks', 'atppolicy', 'externalinoutlook', 'organizationconfig', 'reportsubmissionpolicy']
                         If None, retrieves all available policy types.
        
        Returns:
            Dictionary with policy type as key and list of policies as value
        """
        if policy_types is None:
            policy_types = ['antispam_inbound', 'antispam_outbound', 'antiphishing', 'antimalware']
        
        # Check if we already have cached results for these policy types
        cached_results = {}
        missing_types = []
        
        for policy_type in policy_types:
            if policy_type in self._cached_policies:
                cached_results[policy_type] = self._cached_policies[policy_type]
            else:
                missing_types.append(policy_type)
        
        # If we have all requested policies cached, return them
        if not missing_types:
            print("All requested policies found in cache")
            return cached_results
        
        # Retrieve missing policy types
        print(f"Retrieving policies for: {missing_types}")
        new_policies = self._retrieve_policies_from_exchange(missing_types)
        
        # Update cache and merge results
        self._cached_policies.update(new_policies)
        result = {**cached_results, **new_policies}
        
        return result
    
    def _retrieve_policies_from_exchange(self, policy_types: List[str]) -> Dict[str, List[Dict]]:
        """Retrieve specified policy types from Exchange Online in a single session"""
        try:
            print("Connecting to Exchange Online and retrieving Defender policies...")
            
            # Build PowerShell script based on requested policy types
            ps_script_content = self._build_powershell_script(policy_types)
            
            return self._execute_powershell_script(ps_script_content, policy_types)
                    
        except subprocess.TimeoutExpired:
            print("✗ PowerShell connection timed out after 600 seconds")
            return {policy_type: [] for policy_type in policy_types}
        except Exception as e:
            print(f"✗ Error in Exchange Online connection process: {str(e)}")
            return {policy_type: [] for policy_type in policy_types}
    
    def _build_powershell_script(self, policy_types: List[str]) -> str:
        """Build PowerShell script to retrieve specified policy types"""
        
        # Script header and connection logic
        script_header = '''
# PowerShell script for Exchange Online connection and Defender policy retrieval
$PSVersionTable | Format-Table

Write-Output "Starting Exchange Online connection and Defender policy retrieval process..."

# Clean environment
Write-Output "Preparing PowerShell environment..."
try {
    Get-PSSession | Remove-PSSession -ErrorAction SilentlyContinue
    Remove-Module ExchangeOnlineManagement -Force -ErrorAction SilentlyContinue
    Write-Output "Environment cleaned"
} catch {
    Write-Output "Environment cleanup completed"
}

# Import Exchange Online module
Write-Output "Importing ExchangeOnlineManagement module..."
try {
    Import-Module ExchangeOnlineManagement -Force -DisableNameChecking
    Write-Output "Module imported successfully"
    
    # Verify module is loaded
    $module = Get-Module ExchangeOnlineManagement
    if ($module) {
        Write-Output "Module verified: $($module.Version)"
    } else {
        throw "Module not loaded after import"
    }
} catch {
    Write-Error "Failed to import module: $($_.Exception.Message)"
    exit 1
}

# Connect to Exchange Online with interactive authentication
Write-Output "Connecting to Exchange Online..."
Write-Output "Please sign in when prompted..."
try {
    Connect-ExchangeOnline -ShowBanner:$false -ShowProgress:$false
    Write-Output "Connection command executed successfully"
    
    # Test connection
    Write-Output "Testing connection..."
    $orgConfig = Get-OrganizationConfig -ErrorAction Stop | Select-Object Name, Identity -First 1
    if ($orgConfig) {
        Write-Output "Connection test successful - Organization: $($orgConfig.Name)"
    } else {
        Write-Error "Connection test failed - no organization config returned"
        exit 1
    }
} catch {
    Write-Error "Connection failed with error: $($_.Exception.Message)"
    exit 1
}

Write-Output "Retrieving all Defender policies in single session..."
'''
        
        # Policy retrieval sections
        policy_sections = []
        
        if 'antispam_inbound' in policy_types:
            policy_sections.append('''
# Get inbound anti-spam policies (HostedContentFilterPolicy)
Write-Output "Retrieving inbound anti-spam policies..."
try {
    $inboundPolicies = Get-HostedContentFilterPolicy -ErrorAction Stop | Select-Object *
    
    if ($inboundPolicies) {
        Write-Output "Found $($inboundPolicies.Count) inbound anti-spam policies"
        
        # Convert to JSON with proper depth
        $inboundJsonOutput = $inboundPolicies | ConvertTo-Json -Depth 10 -Compress
        Write-Output "ANTISPAM_INBOUND_DATA_START"
        Write-Output $inboundJsonOutput
        Write-Output "ANTISPAM_INBOUND_DATA_END"
        
        Write-Output "Inbound anti-spam policy retrieval completed successfully"
    } else {
        Write-Warning "No inbound anti-spam policies found"
        Write-Output "ANTISPAM_INBOUND_DATA_START"
        Write-Output "[]"
        Write-Output "ANTISPAM_INBOUND_DATA_END"
    }
} catch {
    Write-Error "Error retrieving inbound anti-spam policies: $($_.Exception.Message)"
    Write-Output "ANTISPAM_INBOUND_DATA_START"
    Write-Output "[]"
    Write-Output "ANTISPAM_INBOUND_DATA_END"
}
''')
        
        if 'antispam_outbound' in policy_types:
            policy_sections.append('''
# Get outbound anti-spam policies (HostedOutboundSpamFilterPolicy)
Write-Output "Retrieving outbound anti-spam policies..."
try {
    $outboundPolicies = Get-HostedOutboundSpamFilterPolicy -ErrorAction Stop | Select-Object *
    
    if ($outboundPolicies) {
        Write-Output "Found $($outboundPolicies.Count) outbound anti-spam policies"
        
        # Convert to JSON with proper depth
        $outboundJsonOutput = $outboundPolicies | ConvertTo-Json -Depth 10 -Compress
        Write-Output "ANTISPAM_OUTBOUND_DATA_START"
        Write-Output $outboundJsonOutput
        Write-Output "ANTISPAM_OUTBOUND_DATA_END"
        
        Write-Output "Outbound anti-spam policy retrieval completed successfully"
    } else {
        Write-Warning "No outbound anti-spam policies found"
        Write-Output "ANTISPAM_OUTBOUND_DATA_START"
        Write-Output "[]"
        Write-Output "ANTISPAM_OUTBOUND_DATA_END"
    }
} catch {
    Write-Error "Error retrieving outbound anti-spam policies: $($_.Exception.Message)"
    Write-Output "ANTISPAM_OUTBOUND_DATA_START"
    Write-Output "[]"
    Write-Output "ANTISPAM_OUTBOUND_DATA_END"
}
''')
        
        if 'antiphishing' in policy_types:
            policy_sections.append('''
# Get anti-phishing policies (AntiPhishPolicy)
Write-Output "Retrieving anti-phishing policies..."
try {
    $antiphishPolicies = Get-AntiPhishPolicy -ErrorAction Stop | Select-Object *
    
    if ($antiphishPolicies) {
        Write-Output "Found $($antiphishPolicies.Count) anti-phishing policies"
        
        # Convert to JSON with proper depth
        $antiphishJsonOutput = $antiphishPolicies | ConvertTo-Json -Depth 10 -Compress
        Write-Output "ANTIPHISHING_DATA_START"
        Write-Output $antiphishJsonOutput
        Write-Output "ANTIPHISHING_DATA_END"
        
        Write-Output "Anti-phishing policy retrieval completed successfully"
    } else {
        Write-Warning "No anti-phishing policies found"
        Write-Output "ANTIPHISHING_DATA_START"
        Write-Output "[]"
        Write-Output "ANTIPHISHING_DATA_END"
    }
} catch {
    Write-Error "Error retrieving anti-phishing policies: $($_.Exception.Message)"
    Write-Output "ANTIPHISHING_DATA_START"
    Write-Output "[]"
    Write-Output "ANTIPHISHING_DATA_END"
}
''')
        
        if 'antimalware' in policy_types:
            policy_sections.append('''
# Get anti-malware policies (MalwareFilterPolicy)
Write-Output "Retrieving anti-malware policies..."
try {
    $antimalwarePolicies = Get-MalwareFilterPolicy -ErrorAction Stop | Select-Object *
    
    if ($antimalwarePolicies) {
        Write-Output "Found $($antimalwarePolicies.Count) anti-malware policies"
        
        # Convert to JSON with proper depth
        $antimalwareJsonOutput = $antimalwarePolicies | ConvertTo-Json -Depth 10 -Compress
        Write-Output "ANTIMALWARE_DATA_START"
        Write-Output $antimalwareJsonOutput
        Write-Output "ANTIMALWARE_DATA_END"
        
        Write-Output "Anti-malware policy retrieval completed successfully"
    } else {
        Write-Warning "No anti-malware policies found"
        Write-Output "ANTIMALWARE_DATA_START"
        Write-Output "[]"
        Write-Output "ANTIMALWARE_DATA_END"
    }
} catch {
    Write-Error "Error retrieving anti-malware policies: $($_.Exception.Message)"
    Write-Output "ANTIMALWARE_DATA_START"
    Write-Output "[]"
    Write-Output "ANTIMALWARE_DATA_END"
}
''')
        
        if 'safeattachments' in policy_types:
            policy_sections.append('''
# Get Safe Attachments policies
Write-Output "Retrieving Safe Attachments policies..."
try {
    $safeAttachmentsPolicies = Get-SafeAttachmentPolicy -ErrorAction Stop | Select-Object *
    
    if ($safeAttachmentsPolicies) {
        Write-Output "Found $($safeAttachmentsPolicies.Count) Safe Attachments policies"
        
        # Convert to JSON with proper depth
        $safeAttachmentsJsonOutput = $safeAttachmentsPolicies | ConvertTo-Json -Depth 10 -Compress
        Write-Output "SAFEATTACHMENTS_DATA_START"
        Write-Output $safeAttachmentsJsonOutput
        Write-Output "SAFEATTACHMENTS_DATA_END"
        
        Write-Output "Safe Attachments policy retrieval completed successfully"
    } else {
        Write-Warning "No Safe Attachments policies found"
        Write-Output "SAFEATTACHMENTS_DATA_START"
        Write-Output "[]"
        Write-Output "SAFEATTACHMENTS_DATA_END"
    }
} catch {
    Write-Error "Error retrieving Safe Attachments policies: $($_.Exception.Message)"
    Write-Output "SAFEATTACHMENTS_DATA_START"
    Write-Output "[]"
    Write-Output "SAFEATTACHMENTS_DATA_END"
}
''')
        
        if 'safelinks' in policy_types:
            policy_sections.append('''
# Get Safe Links policies
Write-Output "Retrieving Safe Links policies..."
try {
    $safeLinksPolicies = Get-SafeLinksPolicy -ErrorAction Stop | Select-Object *
    
    if ($safeLinksPolicies) {
        Write-Output "Found $($safeLinksPolicies.Count) Safe Links policies"
        
        # Convert to JSON with proper depth
        $safeLinksJsonOutput = $safeLinksPolicies | ConvertTo-Json -Depth 10 -Compress
        Write-Output "SAFELINKS_DATA_START"
        Write-Output $safeLinksJsonOutput
        Write-Output "SAFELINKS_DATA_END"
        
        Write-Output "Safe Links policy retrieval completed successfully"
    } else {
        Write-Warning "No Safe Links policies found"
        Write-Output "SAFELINKS_DATA_START"
        Write-Output "[]"
        Write-Output "SAFELINKS_DATA_END"
    }
} catch {
    Write-Error "Error retrieving Safe Links policies: $($_.Exception.Message)"
    Write-Output "SAFELINKS_DATA_START"
    Write-Output "[]"
    Write-Output "SAFELINKS_DATA_END"
}
''')
        
        # Add ATP Policy for O365 retrieval if requested
        if 'atppolicy' in policy_types:
            policy_sections.append('''
# Retrieve ATP Policy for O365
Write-Output "Retrieving ATP Policy for O365..."
try {
    $atpPolicies = Get-AtpPolicyForO365 -ErrorAction Stop | Select-Object *
    
    if ($atpPolicies) {
        Write-Output "Found $($atpPolicies.Count) ATP Policy configurations"
        
        # Convert to JSON and output with markers
        $atpPolicyJsonOutput = $atpPolicies | ConvertTo-Json -Depth 10 -Compress
        Write-Output "ATPPOLICY_DATA_START"
        Write-Output $atpPolicyJsonOutput
        Write-Output "ATPPOLICY_DATA_END"
    } else {
        Write-Output "No ATP Policy configurations found"
        Write-Output "ATPPOLICY_DATA_START"
        Write-Output "[]"
        Write-Output "ATPPOLICY_DATA_END"
    }
} catch {
    Write-Error "Error retrieving ATP Policy for O365: $($_.Exception.Message)"
    Write-Output "ATPPOLICY_DATA_START"
    Write-Output "[]"
    Write-Output "ATPPOLICY_DATA_END"
}
''')
        
        # Add External In Outlook configuration retrieval if requested
        if 'externalinoutlook' in policy_types:
            policy_sections.append('''
# Retrieve External Sender Notification In Outlook configuration
Write-Output "Retrieving External Sender Notification In Outlook configuration..."
try {
    $externalInOutlookConfig = Get-ExternalInOutlook | ConvertTo-Json -Depth 10 -Compress
    
    if ($externalInOutlookConfig) {
        Write-Output "Found External Sender Notification In Outlook configuration"
        
        # Output with markers
        Write-Output "EXTERNALINOUTLOOK_DATA_START"
        Write-Output $externalInOutlookConfig
        Write-Output "EXTERNALINOUTLOOK_DATA_END"
    } else {
        Write-Output "No External In Outlook configuration found"
        Write-Output "EXTERNALINOUTLOOK_DATA_START"
        Write-Output "[]"
        Write-Output "EXTERNALINOUTLOOK_DATA_END"
    }
} catch {
    Write-Error "Error retrieving External In Outlook configuration: $($_.Exception.Message)"
    Write-Output "EXTERNALINOUTLOOK_DATA_START"
    Write-Output "[]"
    Write-Output "EXTERNALINOUTLOOK_DATA_END"
}
''')
        
        # Add Organization Configuration retrieval if requested
        if 'organizationconfig' in policy_types:
            policy_sections.append('''
# Retrieve Organization Configuration (Mail Auditing)
Write-Output "Retrieving Organization Configuration..."
try {
    $orgConfig = Get-OrganizationConfig -ErrorAction Stop | Select-Object AuditDisabled, RejectDirectSend
    
    if ($orgConfig) {
        Write-Output "Found Organization Configuration"
        
        # Convert to JSON and output with markers
        $orgConfigJsonOutput = $orgConfig | ConvertTo-Json -Depth 10 -Compress
        Write-Output "ORGANIZATIONCONFIG_DATA_START"
        Write-Output $orgConfigJsonOutput
        Write-Output "ORGANIZATIONCONFIG_DATA_END"
    } else {
        Write-Output "No Organization Configuration found"
        Write-Output "ORGANIZATIONCONFIG_DATA_START"
        Write-Output "[]"
        Write-Output "ORGANIZATIONCONFIG_DATA_END"
    }
} catch {
    Write-Error "Error retrieving Organization Configuration: $($_.Exception.Message)"
    Write-Output "ORGANIZATIONCONFIG_DATA_START"
    Write-Output "[]"
    Write-Output "ORGANIZATIONCONFIG_DATA_END"
}
''')
        
        # Add Report Submission Policy retrieval if requested
        if 'reportsubmissionpolicy' in policy_types:
            policy_sections.append('''
# Retrieve Report Submission Policy
Write-Output "Retrieving Report Submission Policy..."
try {
    $reportSubmissionPolicy = Get-ReportSubmissionPolicy | ConvertTo-Json -Depth 10 -Compress
    
    if ($reportSubmissionPolicy) {
        Write-Output "Found Report Submission Policy"
        
        # Output with markers
        Write-Output "REPORTSUBMISSIONPOLICY_DATA_START"
        Write-Output $reportSubmissionPolicy
        Write-Output "REPORTSUBMISSIONPOLICY_DATA_END"
    } else {
        Write-Output "No Report Submission Policy found"
        Write-Output "REPORTSUBMISSIONPOLICY_DATA_START"
        Write-Output "[]"
        Write-Output "REPORTSUBMISSIONPOLICY_DATA_END"
    }
} catch {
    Write-Error "Error retrieving Report Submission Policy: $($_.Exception.Message)"
    Write-Output "REPORTSUBMISSIONPOLICY_DATA_START"
    Write-Output "[]"
    Write-Output "REPORTSUBMISSIONPOLICY_DATA_END"
}
''')
        
        # Add DKIM configuration retrieval if requested
        if 'dkim' in policy_types:
            policy_sections.append('''
# Retrieve DKIM Signing Configuration
Write-Output "Retrieving DKIM Signing Configuration..."
try {
    $dkimConfig = Get-DkimSigningConfig | Select-Object Domain,Selector1KeySize,Selector2KeySize,Enabled,Status | ConvertTo-Json -Depth 10 -Compress
    
    if ($dkimConfig) {
        Write-Output "Found DKIM Signing Configuration"
        
        # Output with markers
        Write-Output "DKIM_DATA_START"
        Write-Output $dkimConfig
        Write-Output "DKIM_DATA_END"
    } else {
        Write-Output "No DKIM Signing Configuration found"
        Write-Output "DKIM_DATA_START"
        Write-Output "[]"
        Write-Output "DKIM_DATA_END"
    }
} catch {
    Write-Error "Error retrieving DKIM Signing Configuration: $($_.Exception.Message)"
    Write-Output "DKIM_DATA_START"
    Write-Output "[]"
    Write-Output "DKIM_DATA_END"
}
''')

        # Add Authoritative Domains retrieval if requested (for multi-domain DNS checks)
        if 'authoritativedomains' in policy_types:
            policy_sections.append('''
# Retrieve All Authoritative Domains for DNS checks (excluding .onmicrosoft.com)
Write-Output "Retrieving All Authoritative Domains for DNS checks..."
try {
    $authoritativeDomains = Get-AcceptedDomain | Where-Object {
        $_.DomainType -eq "Authoritative" -and 
        -not $_.DomainName.EndsWith(".onmicrosoft.com")
    } | Select-Object DomainName | ConvertTo-Json -Depth 10 -Compress
    
    if ($authoritativeDomains) {
        Write-Output "Found Authoritative Domains for DNS checking"
        Write-Output "AUTHORITATIVE_DOMAINS_START"
        Write-Output $authoritativeDomains
        Write-Output "AUTHORITATIVE_DOMAINS_END"
    } else {
        Write-Output "No Authoritative Domains found (excluding .onmicrosoft.com)"
        Write-Output "AUTHORITATIVE_DOMAINS_START"
        Write-Output "[]"
        Write-Output "AUTHORITATIVE_DOMAINS_END"
    }
} catch {
    Write-Error "Error retrieving Authoritative Domains: $($_.Exception.Message)"
    Write-Output "AUTHORITATIVE_DOMAINS_START"
    Write-Output "[]"
    Write-Output "AUTHORITATIVE_DOMAINS_END"
}
''')

        # Always retrieve Default Accepted Domain for backward compatibility
        policy_sections.append('''
# Keep Default Accepted Domain for backward compatibility
Write-Output "Retrieving Default Accepted Domain..."
try {
    $defaultDomain = Get-AcceptedDomain | Where-Object {$_.Default -eq $true} | Select-Object DomainName | ConvertTo-Json -Depth 10 -Compress
    
    if ($defaultDomain) {
        Write-Output "Found Default Accepted Domain"
        Write-Output "ACCEPTED_DOMAIN_START"
        Write-Output $defaultDomain
        Write-Output "ACCEPTED_DOMAIN_END"
    } else {
        Write-Output "No Default Accepted Domain found"
        Write-Output "ACCEPTED_DOMAIN_START"
        Write-Output "{}"
        Write-Output "ACCEPTED_DOMAIN_END"
    }
} catch {
    Write-Error "Error retrieving Default Accepted Domain: $($_.Exception.Message)"
    Write-Output "ACCEPTED_DOMAIN_START"
    Write-Output "{}"
    Write-Output "ACCEPTED_DOMAIN_END"
}
''')
        
        # Script footer
        script_footer = '''
# Disconnect from Exchange Online
Write-Output "Disconnecting from Exchange Online..."
try {
    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
    Write-Output "Disconnected successfully"
} catch {
    Write-Output "Disconnect completed with warnings"
}

Write-Output "All Defender policy retrieval completed successfully"
exit 0
'''
        
        return script_header + '\n'.join(policy_sections) + script_footer
    
    def _execute_powershell_script(self, ps_script_content: str, policy_types: List[str]) -> Dict[str, List[Dict]]:
        """Execute PowerShell script and extract all policy data"""
        # Write script to temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.ps1', delete=False) as temp_file:
            temp_file.write(ps_script_content)
            script_path = temp_file.name
        
        print(f"PowerShell script written to: {script_path}")
        
        try:
            # Execute using PowerShell
            print("Executing combined Defender policy retrieval script...")
            
            powershell_exe = self._determine_powershell_executable()
            
            result = subprocess.run([
                powershell_exe,
                "-ExecutionPolicy", "Bypass",
                "-NoProfile",
                "-File", script_path
            ], capture_output=True, text=True, timeout=600)  # Increased timeout for interactive auth
            
            print(f"\n=== PowerShell Execution Results (Combined Defender Policies) ===")
            print(f"PowerShell executable used: {powershell_exe}")
            print(f"Return code: {result.returncode}")
            print(f"=== STDOUT ===")
            print(result.stdout)
            if result.stderr:
                print(f"=== STDERR ===")
                print(result.stderr)
            print(f"=== END RESULTS ===\n")
            
            policies = {}
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                
                # Parse each policy type's data
                policies.update(self._extract_policy_data(lines, 'antispam_inbound', 'ANTISPAM_INBOUND_DATA_START', 'ANTISPAM_INBOUND_DATA_END'))
                policies.update(self._extract_policy_data(lines, 'antispam_outbound', 'ANTISPAM_OUTBOUND_DATA_START', 'ANTISPAM_OUTBOUND_DATA_END'))
                policies.update(self._extract_policy_data(lines, 'antiphishing', 'ANTIPHISHING_DATA_START', 'ANTIPHISHING_DATA_END'))
                policies.update(self._extract_policy_data(lines, 'antimalware', 'ANTIMALWARE_DATA_START', 'ANTIMALWARE_DATA_END'))
                policies.update(self._extract_policy_data(lines, 'safeattachments', 'SAFEATTACHMENTS_DATA_START', 'SAFEATTACHMENTS_DATA_END'))
                policies.update(self._extract_policy_data(lines, 'safelinks', 'SAFELINKS_DATA_START', 'SAFELINKS_DATA_END'))
                policies.update(self._extract_policy_data(lines, 'atppolicy', 'ATPPOLICY_DATA_START', 'ATPPOLICY_DATA_END'))
                policies.update(self._extract_policy_data(lines, 'externalinoutlook', 'EXTERNALINOUTLOOK_DATA_START', 'EXTERNALINOUTLOOK_DATA_END'))
                policies.update(self._extract_policy_data(lines, 'organizationconfig', 'ORGANIZATIONCONFIG_DATA_START', 'ORGANIZATIONCONFIG_DATA_END'))
                policies.update(self._extract_policy_data(lines, 'reportsubmissionpolicy', 'REPORTSUBMISSIONPOLICY_DATA_START', 'REPORTSUBMISSIONPOLICY_DATA_END'))
                policies.update(self._extract_policy_data(lines, 'dkim', 'DKIM_DATA_START', 'DKIM_DATA_END'))
                policies.update(self._extract_policy_data(lines, 'accepteddomain', 'ACCEPTED_DOMAIN_START', 'ACCEPTED_DOMAIN_END'))
                policies.update(self._extract_policy_data(lines, 'authoritativedomains', 'AUTHORITATIVE_DOMAINS_START', 'AUTHORITATIVE_DOMAINS_END'))
                
            else:
                print("✗ Failed to connect to Exchange Online or retrieve policies")
                
                if "CMDLET_NOT_FOUND" in result.stderr:
                    print("ERROR ANALYSIS: Exchange Online cmdlets not available")
                    print("SOLUTIONS:")
                    print("1. Ensure you have Exchange Administrator or Global Administrator role")
                    print("2. Try running as Administrator")
                    print("3. Reinstall Exchange Online Management module:")
                    print("   Uninstall-Module ExchangeOnlineManagement -Force")
                    print("   Install-Module ExchangeOnlineManagement -Force")
                
                # Return empty results for requested policy types
                policies = {policy_type: [] for policy_type in policy_types}
            
            return policies
                
        finally:
            # Clean up temporary file
            try:
                os.unlink(script_path)
                print(f"Cleaned up temp file: {script_path}")
            except Exception as cleanup_error:
                print(f"Warning: Could not clean up temp file: {cleanup_error}")
    
    def _extract_policy_data(self, lines: List[str], policy_type: str, start_marker: str, end_marker: str) -> Dict[str, List[Dict]]:
        """Extract policy data for a specific policy type from PowerShell output"""
        result = {}
        
        # Find start and end markers
        start_idx = -1
        end_idx = -1
        
        for i, line in enumerate(lines):
            if start_marker in line:
                start_idx = i + 1
            elif end_marker in line and start_idx != -1:
                end_idx = i
                break
        
        if start_idx != -1 and end_idx != -1:
            json_data = '\n'.join(lines[start_idx:end_idx])
            try:
                if json_data.strip() and json_data.strip() != "[]":
                    policies_json = json.loads(json_data)
                    if isinstance(policies_json, dict):
                        result[policy_type] = [policies_json]
                    elif isinstance(policies_json, list):
                        result[policy_type] = policies_json
                    else:
                        result[policy_type] = []
                else:
                    result[policy_type] = []
                print(f"Successfully parsed {len(result.get(policy_type, []))} {policy_type} policies")
            except json.JSONDecodeError as e:
                print(f"JSON decode error for {policy_type} policies: {e}")
                print(f"Raw {policy_type} JSON data: {json_data[:500]}...")
                result[policy_type] = []
        else:
            # Policy type was not requested or not found
            pass
        
        return result
    
    def clear_cache(self):
        """Clear the cached policies to force fresh retrieval"""
        self._cached_policies = {}
        self._session_active = False
        print("Policy cache cleared")
    
    def get_cached_policies(self) -> Dict[str, List[Dict]]:
        """Return all cached policies"""
        return self._cached_policies.copy()
    
    def execute_exchange_command(self, command: str, timeout: int = 60) -> Optional[str]:
        """
        Execute a custom PowerShell command within an Exchange Online session
        
        Args:
            command: PowerShell command to execute
            timeout: Command timeout in seconds
            
        Returns:
            Command output as string, or None if failed
        """
        try:
            print(f"Executing Exchange Online command: {command}")
            
            # Build PowerShell script with connection and custom command
            powershell_script = f"""
# PowerShell script for Exchange Online connection and custom command execution
Write-Output "Starting Exchange Online connection for custom command..."

try {{
    # Try to connect using various methods
    try {{
        Connect-ExchangeOnline -ErrorAction Stop
        Write-Output "Successfully connected to Exchange Online"
    }} catch {{
        try {{
            Connect-ExchangeOnline -ShowProgress:$false -ErrorAction Stop
            Write-Output "Successfully connected to Exchange Online (no progress)"
        }} catch {{
            throw "All connection methods failed: $($_.Exception.Message)"
        }}
    }}
}} catch {{
    Write-Error "Failed to connect to Exchange Online: $_"
    exit 1
}}

try {{
    Write-Output "Executing custom command..."
    $result = {command}
    
    Write-Output "=== COMMAND_RESULT_START ==="
    Write-Output ($result | ConvertTo-Json -Depth 10 -Compress)
    Write-Output "=== COMMAND_RESULT_END ==="
    
}} catch {{
    Write-Output "=== COMMAND_ERROR_START ==="
    Write-Output "Error: $($_.Exception.Message)"
    Write-Output "=== COMMAND_ERROR_END ==="
}} finally {{
    try {{
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
        Write-Output "Disconnected from Exchange Online"
    }} catch {{
        Write-Output "Disconnect warning: $($_.Exception.Message)"
    }}
}}
"""
            
            # Execute the PowerShell script
            powershell_exe = self._determine_powershell_executable()
            
            result = subprocess.run([
                powershell_exe,
                "-ExecutionPolicy", "Bypass",
                "-Command", powershell_script
            ], capture_output=True, text=True, timeout=timeout)
            
            print(f"PowerShell exit code: {result.returncode}")
            if result.stderr:
                print(f"PowerShell stderr: {result.stderr}")
            
            if result.returncode == 0 and result.stdout:
                # Extract the command result
                stdout = result.stdout
                start_marker = "=== COMMAND_RESULT_START ==="
                end_marker = "=== COMMAND_RESULT_END ==="
                
                start_idx = stdout.find(start_marker)
                end_idx = stdout.find(end_marker)
                
                if start_idx != -1 and end_idx != -1:
                    command_output = stdout[start_idx + len(start_marker):end_idx].strip()
                    print(f"Command executed successfully")
                    return command_output
                else:
                    # Check for error
                    error_start = "=== COMMAND_ERROR_START ==="
                    error_end = "=== COMMAND_ERROR_END ==="
                    error_start_idx = stdout.find(error_start)
                    error_end_idx = stdout.find(error_end)
                    
                    if error_start_idx != -1 and error_end_idx != -1:
                        error_text = stdout[error_start_idx + len(error_start):error_end_idx].strip()
                        print(f"Command failed: {error_text}")
                        return None
                    else:
                        print("Could not parse command output")
                        print(f"Raw stdout: {stdout}")
                        return None
            else:
                print(f"PowerShell command failed with return code {result.returncode}")
                return None
                
        except subprocess.TimeoutExpired:
            print(f"Command timed out after {timeout} seconds")
            return None
        except Exception as e:
            print(f"Error executing Exchange command: {str(e)}")
            return None