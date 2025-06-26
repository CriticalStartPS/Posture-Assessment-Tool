import subprocess
import json
import yaml
import os
import tempfile
from typing import Dict, List, Any

class AntiSpamPolicyHandler:
    def __init__(self, inbound_standard_file: str = None, inbound_strict_file: str = None, outbound_requirements_file: str = None, legacy_inbound_file: str = None):
        self.inbound_standard_requirements = None
        self.inbound_strict_requirements = None
        self.outbound_requirements = None
        
        if inbound_standard_file and os.path.exists(inbound_standard_file):
            with open(inbound_standard_file, 'r') as file:
                self.inbound_standard_requirements = yaml.safe_load(file)
                
        if inbound_strict_file and os.path.exists(inbound_strict_file):
            with open(inbound_strict_file, 'r') as file:
                self.inbound_strict_requirements = yaml.safe_load(file)
                
        if outbound_requirements_file and os.path.exists(outbound_requirements_file):
            with open(outbound_requirements_file, 'r') as file:
                self.outbound_requirements = yaml.safe_load(file)
                
        # Backward compatibility with legacy single inbound file
        if legacy_inbound_file and os.path.exists(legacy_inbound_file):
            with open(legacy_inbound_file, 'r') as file:
                legacy_requirements = yaml.safe_load(file)
                # Convert legacy format to standard format if no standard file is provided
                if not self.inbound_standard_requirements:
                    self.inbound_standard_requirements = legacy_requirements

    def _connect_and_get_inbound_policies(self) -> List[Dict]:
        """Connect to Exchange Online and retrieve inbound anti-spam policies (HostedContentFilterPolicy)"""
        try:
            print("Connecting to Exchange Online and retrieving inbound anti-spam policies...")
            
            # Create comprehensive PowerShell script that does everything in one session
            ps_script_content = """
# PowerShell script for Exchange Online connection and inbound policy retrieval
$PSVersionTable | Format-Table

Write-Output "Starting Exchange Online connection and inbound policy retrieval process..."

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

# Now retrieve inbound anti-spam policies in the same session
Write-Output "Retrieving inbound anti-spam policies..."
try {
    # Get all hosted content filter policies (inbound anti-spam policies)
    $policies = Get-HostedContentFilterPolicy -ErrorAction Stop | Select-Object *
    
    if ($policies) {
        Write-Output "Found $($policies.Count) inbound anti-spam policies"
        
        # Convert to JSON with proper depth
        $jsonOutput = $policies | ConvertTo-Json -Depth 10 -Compress
        Write-Output "POLICY_DATA_START"
        Write-Output $jsonOutput
        Write-Output "POLICY_DATA_END"
        
        Write-Output "Inbound policy retrieval completed successfully"
    } else {
        Write-Error "No inbound anti-spam policies found"
        exit 1
    }
} catch {
    Write-Error "Error retrieving inbound anti-spam policies: $($_.Exception.Message)"
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
            
            return self._execute_powershell_script(ps_script_content, "inbound")
                    
        except subprocess.TimeoutExpired:
            print("✗ PowerShell connection timed out after 600 seconds")
            return []
        except Exception as e:
            print(f"✗ Error in inbound connection process: {str(e)}")
            return []

    def _connect_and_get_outbound_policies(self) -> List[Dict]:
        """Connect to Exchange Online and retrieve outbound anti-spam policies (HostedOutboundSpamFilterPolicy)"""
        try:
            print("Connecting to Exchange Online and retrieving outbound anti-spam policies...")
            
            # Create comprehensive PowerShell script that does everything in one session
            ps_script_content = """
# PowerShell script for Exchange Online connection and outbound policy retrieval
$PSVersionTable | Format-Table

Write-Output "Starting Exchange Online connection and outbound policy retrieval process..."

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

# Now retrieve outbound anti-spam policies in the same session
Write-Output "Retrieving outbound anti-spam policies..."
try {
    # Get all hosted outbound spam filter policies (outbound anti-spam policies)
    $policies = Get-HostedOutboundSpamFilterPolicy -ErrorAction Stop | Select-Object *
    
    if ($policies) {
        Write-Output "Found $($policies.Count) outbound anti-spam policies"
        
        # Convert to JSON with proper depth
        $jsonOutput = $policies | ConvertTo-Json -Depth 10 -Compress
        Write-Output "POLICY_DATA_START"
        Write-Output $jsonOutput
        Write-Output "POLICY_DATA_END"
        
        Write-Output "Outbound policy retrieval completed successfully"
    } else {
        Write-Error "No outbound anti-spam policies found"
        exit 1
    }
} catch {
    Write-Error "Error retrieving outbound anti-spam policies: $($_.Exception.Message)"
    Write-Error "Full error details: $($_.Exception)"
    
    # Check if it's a cmdlet recognition issue
    if ($_.Exception.Message -like "*not recognized*") {
        Write-Error "CMDLET_NOT_FOUND: Get-HostedOutboundSpamFilterPolicy cmdlet not available"
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
            
            return self._execute_powershell_script(ps_script_content, "outbound")
                    
        except subprocess.TimeoutExpired:
            print("✗ PowerShell connection timed out after 600 seconds")
            return []
        except Exception as e:
            print(f"✗ Error in outbound connection process: {str(e)}")
            return []

    def _execute_powershell_script(self, ps_script_content: str, policy_type: str) -> List[Dict]:
        """Execute PowerShell script and extract policy data"""
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
            
            print(f"\n=== PowerShell Execution Results ({policy_type}) ===")
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
                print(f"✗ Failed to connect to Exchange Online or retrieve {policy_type} policies")
                
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

    def _check_policy_requirements(self, policies: List[Dict], requirements: Dict, policy_type: str) -> List[Dict[str, Any]]:
        """Check policies against requirements for a specific policy type"""
        results = []
        
        if not policies:
            return [{
                'requirement_name': f'{policy_type.title()} Connection Error',
                'found': False,
                'status': f'MISSING - Could not connect to Exchange Online or retrieve {policy_type} policies',
                'policy_type': f'antispam_{policy_type}'
            }]
        
        print(f"Successfully retrieved {len(policies)} {policy_type} anti-spam policies")
        
        # Filter to only enabled policies (policies that are actually in use)
        enabled_policies = []
        for policy in policies:
            # Include default policies and enabled custom policies
            if (policy.get('IsDefault', False) or 
                policy.get('IsValid', True)):  # IsValid typically indicates the policy is enabled
                enabled_policies.append(policy)
                print(f"  - {policy_type.title()} Policy: {policy.get('Name', 'Unknown')} (Default: {policy.get('IsDefault', False)})")
        
        if not enabled_policies:
            enabled_policies = policies  # Fallback to all policies if none marked as enabled
            print(f"No enabled {policy_type} policies found via IsDefault/IsValid, evaluating all policies")
        
        print(f"Evaluating {len(enabled_policies)} enabled {policy_type} anti-spam policies")
        
        # Get the appropriate requirements key
        requirements_key = f'antispam_{policy_type}_policies'
        policy_requirements = requirements.get(requirements_key, [])
        
        # Evaluate each requirement against ALL enabled policies
        for requirement in policy_requirements:
            setting = requirement['setting']
            expected_value = requirement['expected_value']
            requirement_name = requirement['name']
            
            # Track results for this requirement across all policies
            policy_results = []
            compliant_policies = []
            non_compliant_policies = []
            
            for policy in enabled_policies:
                policy_name = policy.get('Name', 'Unknown')
                current_value = policy.get(setting)
                
                # Determine compliance for this policy
                is_compliant = False
                if isinstance(expected_value, bool):
                    current_bool = bool(current_value) if current_value is not None else False
                    is_compliant = current_bool == expected_value
                elif isinstance(expected_value, (int, float)):
                    if setting == "BulkThreshold":
                        # For bulk threshold, compliant if current value is <= expected
                        is_compliant = (current_value is not None and 
                                      isinstance(current_value, (int, float)) and 
                                      current_value <= expected_value)
                    else:
                        # For other numeric values, check if they meet or exceed expected
                        is_compliant = (current_value is not None and 
                                      isinstance(current_value, (int, float)) and 
                                      current_value >= expected_value)
                else:
                    is_compliant = str(current_value).lower() == str(expected_value).lower()
                
                policy_result = {
                    'policy_name': policy_name,
                    'current_value': current_value,
                    'is_compliant': is_compliant,
                    'is_default': policy.get('IsDefault', False)
                }
                
                policy_results.append(policy_result)
                
                if is_compliant:
                    compliant_policies.append(policy_result)
                else:
                    non_compliant_policies.append(policy_result)
            
            # Determine overall compliance for this requirement
            # Requirement is met if ALL enabled policies are compliant
            overall_compliant = len(non_compliant_policies) == 0 and len(compliant_policies) > 0
            
            # Create summary status
            if overall_compliant:
                status = f"PRESENT - All {len(compliant_policies)} policies compliant"
                status_detail = f"✓ All policies meet requirement"
            else:
                status = f"MISSING - {len(non_compliant_policies)}/{len(policy_results)} policies non-compliant"
                status_detail = f"✗ {len(non_compliant_policies)} policies need configuration"
            
            # Create detailed breakdown for the report
            policy_breakdown = []
            for result in policy_results:
                policy_status = "COMPLIANT" if result['is_compliant'] else "NON-COMPLIANT"
                default_indicator = " (Default)" if result['is_default'] else ""
                policy_breakdown.append(
                    f"{result['policy_name']}{default_indicator}: {policy_status} "
                    f"(Current: {result['current_value']}, Expected: {expected_value})"
                )
            
            # Add result for this requirement
            result_entry = {
                'requirement_name': f"{requirement_name} ({policy_type.title()})",
                'found': len(policy_results) > 0,
                'current_value': f"{len(compliant_policies)}/{len(policy_results)} policies compliant",
                'expected_value': expected_value,
                'policy_type': f'antispam_{policy_type}',
                'status': status,
                'policy_breakdown': policy_breakdown,
                'total_policies': len(policy_results),
                'compliant_policies': len(compliant_policies),
                'non_compliant_policies': len(non_compliant_policies)
            }
            
            results.append(result_entry)
            
            # Print detailed breakdown to console
            print(f"\n{policy_type.title()} Requirement: {requirement_name}")
            print(f"  Status: {status}")
            for breakdown in policy_breakdown:
                print(f"    {breakdown}")
        
        return results

    def _connect_and_get_all_policies(self) -> Dict[str, List[Dict]]:
        """Connect to Exchange Online once and retrieve both inbound and outbound anti-spam policies in a single session"""
        try:
            print("Connecting to Exchange Online and retrieving all anti-spam policies...")
            
            # Create comprehensive PowerShell script that does everything in one session
            ps_script_content = """
# PowerShell script for Exchange Online connection and all policy retrieval
$PSVersionTable | Format-Table

Write-Output "Starting Exchange Online connection and all policy retrieval process..."

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

# Now retrieve all anti-spam policies in the same session
Write-Output "Retrieving all anti-spam policies in single session..."

# Get inbound policies (HostedContentFilterPolicy)
Write-Output "Retrieving inbound anti-spam policies..."
try {
    $inboundPolicies = Get-HostedContentFilterPolicy -ErrorAction Stop | Select-Object *
    
    if ($inboundPolicies) {
        Write-Output "Found $($inboundPolicies.Count) inbound anti-spam policies"
        
        # Convert to JSON with proper depth
        $inboundJsonOutput = $inboundPolicies | ConvertTo-Json -Depth 10 -Compress
        Write-Output "INBOUND_POLICY_DATA_START"
        Write-Output $inboundJsonOutput
        Write-Output "INBOUND_POLICY_DATA_END"
        
        Write-Output "Inbound policy retrieval completed successfully"
    } else {
        Write-Warning "No inbound anti-spam policies found"
        Write-Output "INBOUND_POLICY_DATA_START"
        Write-Output "[]"
        Write-Output "INBOUND_POLICY_DATA_END"
    }
} catch {
    Write-Error "Error retrieving inbound anti-spam policies: $($_.Exception.Message)"
    Write-Output "INBOUND_POLICY_DATA_START"
    Write-Output "[]"
    Write-Output "INBOUND_POLICY_DATA_END"
}

# Get outbound policies (HostedOutboundSpamFilterPolicy)
Write-Output "Retrieving outbound anti-spam policies..."
try {
    $outboundPolicies = Get-HostedOutboundSpamFilterPolicy -ErrorAction Stop | Select-Object *
    
    if ($outboundPolicies) {
        Write-Output "Found $($outboundPolicies.Count) outbound anti-spam policies"
        
        # Convert to JSON with proper depth
        $outboundJsonOutput = $outboundPolicies | ConvertTo-Json -Depth 10 -Compress
        Write-Output "OUTBOUND_POLICY_DATA_START"
        Write-Output $outboundJsonOutput
        Write-Output "OUTBOUND_POLICY_DATA_END"
        
        Write-Output "Outbound policy retrieval completed successfully"
    } else {
        Write-Warning "No outbound anti-spam policies found"
        Write-Output "OUTBOUND_POLICY_DATA_START"
        Write-Output "[]"
        Write-Output "OUTBOUND_POLICY_DATA_END"
    }
} catch {
    Write-Error "Error retrieving outbound anti-spam policies: $($_.Exception.Message)"
    Write-Output "OUTBOUND_POLICY_DATA_START"
    Write-Output "[]"
    Write-Output "OUTBOUND_POLICY_DATA_END"
}

# Disconnect from Exchange Online
Write-Output "Disconnecting from Exchange Online..."
try {
    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
    Write-Output "Disconnected successfully"
} catch {
    Write-Output "Disconnect completed with warnings"
}

Write-Output "All policy retrieval completed successfully"
exit 0
"""
            
            return self._execute_combined_powershell_script(ps_script_content)
                    
        except subprocess.TimeoutExpired:
            print("✗ PowerShell connection timed out after 600 seconds")
            return {"inbound": [], "outbound": []}
        except Exception as e:
            print(f"✗ Error in combined connection process: {str(e)}")
            return {"inbound": [], "outbound": []}

    def _execute_combined_powershell_script(self, ps_script_content: str) -> Dict[str, List[Dict]]:
        """Execute PowerShell script and extract both inbound and outbound policy data"""
        # Write script to temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.ps1', delete=False) as temp_file:
            temp_file.write(ps_script_content)
            script_path = temp_file.name
        
        print(f"PowerShell script written to: {script_path}")
        
        try:
            # Execute using PowerShell (try pwsh first, fallback to powershell.exe)
            print("Executing combined PowerShell script...")
            
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
            
            print(f"\n=== PowerShell Execution Results (Combined) ===")
            print(f"PowerShell executable used: {powershell_exe}")
            print(f"Return code: {result.returncode}")
            print(f"=== STDOUT ===")
            print(result.stdout)
            if result.stderr:
                print(f"=== STDERR ===")
                print(result.stderr)
            print(f"=== END RESULTS ===\n")
            
            policies = {"inbound": [], "outbound": []}
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                
                # Extract inbound policies
                inbound_start = -1
                inbound_end = -1
                for i, line in enumerate(lines):
                    if "INBOUND_POLICY_DATA_START" in line:
                        inbound_start = i + 1
                    elif "INBOUND_POLICY_DATA_END" in line:
                        inbound_end = i
                        break
                
                if inbound_start != -1 and inbound_end != -1:
                    inbound_json_data = '\n'.join(lines[inbound_start:inbound_end])
                    try:
                        if inbound_json_data.strip() and inbound_json_data.strip() != "[]":
                            inbound_policies_json = json.loads(inbound_json_data)
                            if isinstance(inbound_policies_json, dict):
                                policies["inbound"] = [inbound_policies_json]
                            elif isinstance(inbound_policies_json, list):
                                policies["inbound"] = inbound_policies_json
                        print(f"Successfully parsed {len(policies['inbound'])} inbound policies")
                    except json.JSONDecodeError as e:
                        print(f"JSON decode error for inbound policies: {e}")
                        print(f"Raw inbound JSON data: {inbound_json_data[:500]}...")
                
                # Extract outbound policies
                outbound_start = -1
                outbound_end = -1
                for i, line in enumerate(lines):
                    if "OUTBOUND_POLICY_DATA_START" in line:
                        outbound_start = i + 1
                    elif "OUTBOUND_POLICY_DATA_END" in line:
                        outbound_end = i
                        break
                
                if outbound_start != -1 and outbound_end != -1:
                    outbound_json_data = '\n'.join(lines[outbound_start:outbound_end])
                    try:
                        if outbound_json_data.strip() and outbound_json_data.strip() != "[]":
                            outbound_policies_json = json.loads(outbound_json_data)
                            if isinstance(outbound_policies_json, dict):
                                policies["outbound"] = [outbound_policies_json]
                            elif isinstance(outbound_policies_json, list):
                                policies["outbound"] = outbound_policies_json
                        print(f"Successfully parsed {len(policies['outbound'])} outbound policies")
                    except json.JSONDecodeError as e:
                        print(f"JSON decode error for outbound policies: {e}")
                        print(f"Raw outbound JSON data: {outbound_json_data[:500]}...")
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
            
            return policies
                
        finally:
            # Clean up temporary file
            try:
                os.unlink(script_path)
                print(f"Cleaned up temp file: {script_path}")
            except Exception as cleanup_error:
                print(f"Warning: Could not clean up temp file: {cleanup_error}")

    def check_policies(self) -> List[Dict[str, Any]]:
        """Check both inbound and outbound anti-spam policies against requirements using single authentication session"""
        all_results = []
        
        print("\n=== Starting Defender for Office 365 Anti-Spam Policy Check ===")
        
        # Use single session to get all policies if any requirements are provided
        if (self.inbound_standard_requirements or self.inbound_strict_requirements or self.outbound_requirements):
            print("Retrieving all anti-spam policies in single authentication session...")
            all_policies = self._connect_and_get_all_policies()
            
            inbound_policies = all_policies.get("inbound", [])
            outbound_policies = all_policies.get("outbound", [])
            
            print(f"Retrieved {len(inbound_policies)} inbound policies and {len(outbound_policies)} outbound policies")
            
            # Check inbound standard policies if requirements are provided
            if self.inbound_standard_requirements:
                print("\n--- Checking Inbound Anti-Spam Policies (Standard) ---")
                inbound_standard_results = self._check_policy_requirements(inbound_policies, self.inbound_standard_requirements, "inbound_standard")
                all_results.extend(inbound_standard_results)
            
            # Check inbound strict policies if requirements are provided
            if self.inbound_strict_requirements:
                print("\n--- Checking Inbound Anti-Spam Policies (Strict) ---")
                inbound_strict_results = self._check_policy_requirements(inbound_policies, self.inbound_strict_requirements, "inbound_strict")
                all_results.extend(inbound_strict_results)
            
            # Check outbound policies if requirements are provided  
            if self.outbound_requirements:
                print("\n--- Checking Outbound Anti-Spam Policies ---")
                outbound_results = self._check_policy_requirements(outbound_policies, self.outbound_requirements, "outbound")
                all_results.extend(outbound_results)
        else:
            print("No anti-spam requirements files provided")
            return [{
                'requirement_name': 'No Requirements',
                'found': False,
                'status': 'MISSING - No anti-spam requirements files provided',
                'policy_type': 'antispam'
            }]
        
        return all_results
