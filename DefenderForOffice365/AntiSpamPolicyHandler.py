import subprocess
import json
import yaml
import os
import tempfile
from typing import Dict, List, Any
from .ExchangeOnlineSessionManager import ExchangeOnlineSessionManager

class AntiSpamPolicyHandler:
    def __init__(self, inbound_standard_file: str = None, inbound_strict_file: str = None, outbound_requirements_file: str = None, legacy_inbound_file: str = None, session_manager: ExchangeOnlineSessionManager = None):
        self.inbound_standard_requirements = None
        self.inbound_strict_requirements = None
        self.outbound_requirements = None
        
        # Use provided session manager or create a new one
        self.session_manager = session_manager if session_manager else ExchangeOnlineSessionManager()
        
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

    def check_policies(self) -> List[Dict[str, Any]]:
        """Check both inbound and outbound anti-spam policies against requirements using shared session manager"""
        all_results = []
        
        print("\n=== Starting Defender for Office 365 Anti-Spam Policy Check ===")
        
        # Determine which policy types we need based on loaded requirements
        required_policy_types = []
        if self.inbound_standard_requirements or self.inbound_strict_requirements:
            required_policy_types.append('antispam_inbound')
        if self.outbound_requirements:
            required_policy_types.append('antispam_outbound')
        
        if not required_policy_types:
            print("No anti-spam requirements files provided")
            return [{
                'requirement_name': 'No Requirements',
                'found': False,
                'status': 'MISSING - No anti-spam requirements files provided',
                'policy_type': 'antispam'
            }]
        
        print(f"Retrieving anti-spam policies using shared session manager: {required_policy_types}")
        
        # Use shared session manager to get all required policies
        all_policies = self.session_manager.get_all_defender_policies(required_policy_types)
        
        inbound_policies = all_policies.get("antispam_inbound", [])
        outbound_policies = all_policies.get("antispam_outbound", [])
        
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
        
        return all_results

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
                policy.get('IsValid', True) ):  # IsValid typically indicates the policy is enabled
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
                if expected_value == "not_null":
                    # Special case: check if value is not null/None/empty
                    is_compliant = current_value is not None and current_value != "" and current_value != []
                elif isinstance(expected_value, bool):
                    current_bool = bool(current_value) if current_value is not None else False
                    is_compliant = current_bool == expected_value
                elif isinstance(expected_value, (int, float)):
                    if setting == "BulkThreshold":
                        # For bulk threshold, compliant if current value exactly matches expected (direct match required - 7 for standard, 5 for strict)
                        is_compliant = (current_value is not None and 
                                      isinstance(current_value, (int, float)) and 
                                      current_value == expected_value)
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
                'current_value': self._format_current_value_display(policy_results, expected_value, setting),
                'expected_value': expected_value,
                'policy_type': f'antispam_{policy_type}',
                'status': status,
                'policy_breakdown': policy_breakdown,
                'total_policies': len(policy_results),
                'compliant_policies': len(compliant_policies),
                'non_compliant_policies': len(non_compliant_policies),
                'policy_results': policy_results
            }
            
            results.append(result_entry)
            
            # Print detailed breakdown to console
            print(f"\n{policy_type.title()} Requirement: {requirement_name}")
            print(f"  Status: {status}")
            for breakdown in policy_breakdown:
                print(f"    {breakdown}")
        
        return results

    def _format_current_value_display(self, policy_results: List[Dict], expected_value: Any, setting: str) -> str:
        """Format the current value display for the report, showing actual policy values instead of policy counts"""
        try:
            if not policy_results or len(policy_results) == 0:
                return "No policies found"
            
            # Get actual current values from policies, not policy_results which are the result objects
            current_values = []
            compliant_count = 0
            
            for result in policy_results:
                if result.get('current_value') is not None:
                    current_values.append(result['current_value'])
                    if result.get('is_compliant', False):
                        compliant_count += 1
            
            if not current_values:
                return "No values configured"
            
            # For BulkThreshold and other numeric settings, show the range or specific values
            if setting == "BulkThreshold" and all(isinstance(v, (int, float)) for v in current_values):
                unique_values = list(set(current_values))
                if len(unique_values) == 1:
                    return f"{unique_values[0]} (all policies)"
                else:
                    min_val = min(current_values)
                    max_val = max(current_values)
                    return f"Range: {min_val}-{max_val} (across {len(policy_results)} policies)"
            
            # For boolean settings
            elif isinstance(expected_value, bool):
                true_count = sum(1 for v in current_values if v)
                false_count = len(current_values) - true_count
                if true_count == len(current_values):
                    return "True (all policies)"
                elif false_count == len(current_values):
                    return "False (all policies)"
                else:
                    return f"Mixed: {true_count} True, {false_count} False"
            
            # For string/other settings
            else:
                unique_values = list(set(str(v) for v in current_values))
                if len(unique_values) == 1:
                    return f"{unique_values[0]} (all policies)"
                else:
                    return f"Mixed values: {', '.join(unique_values[:3])}{'...' if len(unique_values) > 3 else ''}"
                    
        except Exception as e:
            print(f"Error formatting current value display: {e}")
            return f"{compliant_count}/{len(policy_results)} policies compliant"
