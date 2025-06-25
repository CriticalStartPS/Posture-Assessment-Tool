import subprocess
import json
import yaml
import os
import tempfile
from typing import Dict, List, Any

class AntiSpamPolicyHandler:
    def __init__(self, requirements_file: str):
        self.requirements_file = requirements_file
        with open(requirements_file, 'r') as file:
            self.requirements = yaml.safe_load(file)

    def _connect_and_get_policies(self) -> List[Dict]:
        """Connect to Exchange Online and retrieve anti-spam policies in a single session"""
        try:
            print("Connecting to Exchange Online and retrieving anti-spam policies...")
            
            # Create comprehensive PowerShell script that does everything in one session
            ps_script_content = """
# PowerShell script for Exchange Online connection and policy retrieval
$PSVersionTable | Format-Table

Write-Output "Starting Exchange Online connection and policy retrieval process..."

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

# Now retrieve anti-spam policies in the same session
Write-Output "Retrieving anti-spam policies..."
try {
    # Get all hosted content filter policies (anti-spam policies)
    $policies = Get-HostedContentFilterPolicy -ErrorAction Stop | Select-Object *
    
    if ($policies) {
        Write-Output "Found $($policies.Count) anti-spam policies"
        
        # Convert to JSON with proper depth
        $jsonOutput = $policies | ConvertTo-Json -Depth 10 -Compress
        Write-Output "POLICY_DATA_START"
        Write-Output $jsonOutput
        Write-Output "POLICY_DATA_END"
        
        Write-Output "Policy retrieval completed successfully"
    } else {
        Write-Error "No anti-spam policies found"
        exit 1
    }
} catch {
    Write-Error "Error retrieving anti-spam policies: $($_.Exception.Message)"
    Write-Error "Full error details: $($_.Exception)"
    
    # Check if it's a cmdlet recognition issue
    if ($_.Exception.Message -like "*not recognized*") {
        Write-Error "CMDLET_NOT_FOUND: Get-HostedContentFilterPolicy cmdlet not available"
        Write-Error "This usually means:"
        Write-Error "1. Exchange Online session is not properly established"
        Write-Error "2. User doesn't have sufficient permissions"
        Write-Error "3. Exchange Online PowerShell module is not properly loaded"
        
        # Try to check what Exchange cmdlets are available
        $exchangeCmdlets = Get-Command -Module ExchangeOnlineManagement -ErrorAction SilentlyContinue
        if ($exchangeCmdlets) {
            Write-Output "Available Exchange cmdlets: $($exchangeCmdlets.Count)"
        } else {
            Write-Error "No Exchange cmdlets found - module not properly loaded"
        }
    }
    
    exit 1
} finally {
    # Disconnect from Exchange Online
    Write-Output "Disconnecting from Exchange Online..."
    try {
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
        Write-Output "Disconnected successfully"
    } catch {
        Write-Output "Disconnect completed with warnings"
    }
}

Write-Output "Script completed successfully"
exit 0
"""
            
            # Write script to temporary file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.ps1', delete=False) as temp_file:
                temp_file.write(ps_script_content)
                script_path = temp_file.name
            
            print(f"PowerShell script written to: {script_path}")
            
            try:
                # Execute using PowerShell (try pwsh first, fallback to powershell.exe)
                print("Executing PowerShell script...")
                
                powershell_exe = "pwsh"
                try:
                    subprocess.run([powershell_exe, "-Version"], 
                                 capture_output=True, timeout=5, check=True)
                    print("Using PowerShell 7 (pwsh)")
                except (subprocess.CalledProcessError, FileNotFoundError):
                    print("PowerShell 7 not found, using Windows PowerShell")
                    powershell_exe = "powershell.exe"
                
                result = subprocess.run([
                    powershell_exe,
                    "-ExecutionPolicy", "Bypass",
                    "-NoProfile",
                    "-File", script_path
                ], capture_output=True, text=True, timeout=600)  # Increased timeout for interactive auth
                
                print(f"\n=== PowerShell Execution Results ===")
                print(f"PowerShell executable used: {powershell_exe}")
                print(f"Return code: {result.returncode}")
                print(f"=== STDOUT ===")
                print(result.stdout)
                if result.stderr:
                    print(f"=== STDERR ===")
                    print(result.stderr)
                print(f"=== END RESULTS ===\n")
                
                if result.returncode == 0 and "POLICY_DATA_START" in result.stdout:
                    # Extract JSON data between markers
                    lines = result.stdout.split('\n')
                    json_start = -1
                    json_end = -1
                    
                    for i, line in enumerate(lines):
                        if "POLICY_DATA_START" in line:
                            json_start = i + 1
                        elif "POLICY_DATA_END" in line:
                            json_end = i
                            break
                    
                    if json_start != -1 and json_end != -1:
                        json_data = '\n'.join(lines[json_start:json_end])
                        try:
                            policies_json = json.loads(json_data)
                            if isinstance(policies_json, dict):
                                return [policies_json]
                            return policies_json if isinstance(policies_json, list) else []
                        except json.JSONDecodeError as e:
                            print(f"JSON decode error: {e}")
                            print(f"Raw JSON data: {json_data[:500]}...")
                            return []
                    else:
                        print("Could not find policy data markers in output")
                        return []
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
                    
                    return []
                    
            finally:
                # Clean up temporary file
                try:
                    os.unlink(script_path)
                    print(f"Cleaned up temp file: {script_path}")
                except Exception as cleanup_error:
                    print(f"Warning: Could not clean up temp file: {cleanup_error}")
                    
        except subprocess.TimeoutExpired:
            print("✗ PowerShell connection timed out after 600 seconds")
            return []
        except Exception as e:
            print(f"✗ Error in connection process: {str(e)}")
            return []

    def check_policies(self) -> List[Dict[str, Any]]:
        """Check anti-spam policies against requirements"""
        results = []
        
        print("\n=== Starting Defender for Office 365 Anti-Spam Policy Check ===")
        
        # Get policies using the combined connection and retrieval method
        policies = self._connect_and_get_policies()
        
        if not policies:
            return [{
                'requirement_name': 'Connection Error',
                'found': False,
                'status': 'MISSING - Could not connect to Exchange Online or retrieve policies',
                'policy_type': 'antispam'
            }]
        
        print(f"Successfully retrieved {len(policies)} anti-spam policies")
        
        for requirement in self.requirements.get('antispam_policies', []):
            policy_name = requirement.get('policy_name', 'Default')
            setting = requirement['setting']
            expected_value = requirement['expected_value']
            
            # Find the matching policy
            matching_policy = None
            for policy in policies:
                if policy.get('Name', '').lower() == policy_name.lower():
                    matching_policy = policy
                    break
            
            if not matching_policy and policy_name.lower() == 'default':
                # For default policy, take the first one or look for IsDefault=True
                for policy in policies:
                    if policy.get('IsDefault', False) or len(policies) == 1:
                        matching_policy = policy
                        break
            
            if matching_policy:
                current_value = matching_policy.get(setting)
                
                # Compare values
                if isinstance(expected_value, bool):
                    current_bool = bool(current_value) if current_value is not None else False
                    is_compliant = current_bool == expected_value
                    status = f"PRESENT - Current: {current_bool}"
                    if not is_compliant:
                        status = f"MISSING - Current: {current_bool}, Expected: {expected_value}"
                elif isinstance(expected_value, (int, float)):
                    is_compliant = current_value == expected_value
                    status = f"PRESENT - Current: {current_value}"
                    if not is_compliant:
                        status = f"MISSING - Current: {current_value}, Expected: {expected_value}"
                else:
                    is_compliant = str(current_value).lower() == str(expected_value).lower()
                    status = f"PRESENT - Current: {current_value}"
                    if not is_compliant:
                        status = f"MISSING - Current: {current_value}, Expected: {expected_value}"
                
                results.append({
                    'requirement_name': requirement['name'],
                    'found': True,
                    'current_value': current_value,
                    'expected_value': expected_value,
                    'policy_type': 'antispam',
                    'status': status,
                    'policy_name': matching_policy.get('Name', 'Unknown')
                })
            else:
                results.append({
                    'requirement_name': requirement['name'],
                    'found': False,
                    'status': f'MISSING - Policy "{policy_name}" not found',
                    'policy_type': 'antispam'
                })
        
        return results
