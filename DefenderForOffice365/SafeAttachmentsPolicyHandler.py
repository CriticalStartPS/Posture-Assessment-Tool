import subprocess
import json
import yaml
import os
import tempfile
import re
from typing import Dict, List, Any
from .ExchangeOnlineSessionManager import ExchangeOnlineSessionManager

class SafeAttachmentsPolicyHandler:
    def __init__(self, requirements_file: str = None, session_manager: ExchangeOnlineSessionManager = None):
        self.requirements = None
        
        # Use provided session manager or create a new one
        self.session_manager = session_manager if session_manager else ExchangeOnlineSessionManager()
        
        if requirements_file and os.path.exists(requirements_file):
            with open(requirements_file, 'r') as file:
                self.requirements = yaml.safe_load(file)

    def check_policies(self) -> List[Dict[str, Any]]:
        """Check Safe Attachments policies against requirements using shared session manager"""
        all_results = []
        
        print("\n=== Starting Defender for Office 365 Safe Attachments Policy Check ===")
        
        if not self.requirements:
            print("No Safe Attachments requirements file provided")
            return [{
                'requirement_name': 'No Requirements',
                'found': False,
                'status': 'MISSING - No Safe Attachments requirements file provided',
                'policy_type': 'safeattachments'
            }]
        
        print("Retrieving Safe Attachments policies using shared session manager")
        
        # Use shared session manager to get Safe Attachments policies
        all_policies = self.session_manager.get_all_defender_policies(['safeattachments'])
        
        safeattachments_policies = all_policies.get("safeattachments", [])
        
        print(f"Retrieved {len(safeattachments_policies)} Safe Attachments policies")
        
        # Check Safe Attachments policies against requirements
        print("\n--- Checking Safe Attachments Policies ---")
        safeattachments_results = self._check_policy_requirements(safeattachments_policies, self.requirements, "safeattachments")
        all_results.extend(safeattachments_results)
        
        return all_results

    def _check_policy_requirements(self, policies: List[Dict], requirements: Dict, policy_type: str) -> List[Dict[str, Any]]:
        """Check policies against requirements for Safe Attachments policies"""
        results = []
        
        if not policies:
            return [{
                'requirement_name': f'{policy_type.title()} Connection Error',
                'found': False,
                'status': f'MISSING - Could not connect to Exchange Online or retrieve {policy_type} policies',
                'policy_type': policy_type
            }]
        
        print(f"Successfully retrieved {len(policies)} {policy_type} policies")
        
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
        
        print(f"Evaluating {len(enabled_policies)} enabled {policy_type} policies")
        
        # Get the appropriate requirements key
        requirements_key = f'{policy_type}_policies'
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
                elif isinstance(expected_value, str):
                    if expected_value == "email_present":
                        # Special case for RedirectAddress - check if it's a valid email
                        if current_value and isinstance(current_value, str):
                            # Simple email validation - contains @ and has some content before and after
                            email_pattern = r'^[^@\s]+@[^@\s]+\.[^@\s]+$'
                            is_compliant = bool(re.match(email_pattern, current_value.strip()))
                        else:
                            is_compliant = False
                    else:
                        is_compliant = current_value == expected_value
                else:
                    is_compliant = current_value == expected_value
                
                # Store result for this policy
                policy_result = {
                    'policy_name': policy_name,
                    'current_value': current_value,
                    'is_compliant': is_compliant
                }
                policy_results.append(policy_result)
                
                if is_compliant:
                    compliant_policies.append(policy_name)
                else:
                    non_compliant_policies.append(f"{policy_name} (Current: {current_value})")
            
            # Determine overall compliance for this requirement
            # At least one policy must be compliant for the requirement to pass
            overall_compliant = len(compliant_policies) > 0
            
            # Create result entry
            if overall_compliant:
                status = f"COMPLIANT - Found in policies: {', '.join(compliant_policies)}"
            else:
                status = f"NON-COMPLIANT - All policies failed: {', '.join(non_compliant_policies)}"
            
            result = {
                'requirement_name': requirement_name,
                'setting': setting,
                'expected_value': expected_value,
                'found': overall_compliant,
                'status': status,
                'policy_type': policy_type,
                'policy_results': policy_results
            }
            
            results.append(result)
            
            # Print detailed results
            if overall_compliant:
                print(f"  ✓ {requirement_name}: COMPLIANT")
                print(f"    Compliant policies: {', '.join(compliant_policies)}")
            else:
                print(f"  ✗ {requirement_name}: NON-COMPLIANT")
                print(f"    Expected: {expected_value}")
                for policy_result in policy_results:
                    print(f"    {policy_result['policy_name']}: {policy_result['current_value']} ({'✓' if policy_result['is_compliant'] else '✗'})")
        
        return results

    def get_requirements_summary(self) -> Dict[str, Any]:
        """Get a summary of loaded requirements"""
        if not self.requirements:
            return {'loaded': False, 'requirements_count': 0}
        
        safeattachments_count = len(self.requirements.get('safeattachments_policies', []))
        
        return {
            'loaded': True,
            'requirements_count': safeattachments_count,
            'safeattachments_policies': safeattachments_count
        }
