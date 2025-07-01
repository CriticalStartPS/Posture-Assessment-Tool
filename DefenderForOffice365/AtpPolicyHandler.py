import subprocess
import json
import yaml
import os
import tempfile
from typing import Dict, List, Any
from .ExchangeOnlineSessionManager import ExchangeOnlineSessionManager

class AtpPolicyHandler:
    def __init__(self, requirements_file: str = None, session_manager: ExchangeOnlineSessionManager = None):
        self.requirements = None
        
        # Use provided session manager or create a new one
        self.session_manager = session_manager if session_manager else ExchangeOnlineSessionManager()
        
        if requirements_file and os.path.exists(requirements_file):
            with open(requirements_file, 'r') as file:
                self.requirements = yaml.safe_load(file)

    def check_policies(self) -> List[Dict[str, Any]]:
        """Check ATP Policy for O365 against requirements using shared session manager"""
        all_results = []
        
        print("\n=== Starting Defender for Office 365 ATP Policy Check ===")
        
        if not self.requirements:
            print("No ATP Policy requirements file provided")
            return [{
                'requirement_name': 'No Requirements',
                'found': False,
                'status': 'MISSING - No ATP Policy requirements file provided',
                'policy_type': 'atppolicy'
            }]
        
        print("Retrieving ATP Policy for O365 using shared session manager")
        
        # Use shared session manager to get ATP policies
        all_policies = self.session_manager.get_all_defender_policies(['atppolicy'])
        
        atppolicy_policies = all_policies.get("atppolicy", [])
        
        print(f"Retrieved {len(atppolicy_policies)} ATP Policy configurations")
        
        # Check ATP policies against requirements
        print("\n--- Checking ATP Policy for O365 ---")
        atppolicy_results = self._check_policy_requirements(atppolicy_policies, self.requirements, "atppolicy")
        all_results.extend(atppolicy_results)
        
        return all_results

    def _check_policy_requirements(self, policies: List[Dict], requirements: Dict, policy_type: str) -> List[Dict[str, Any]]:
        """Check policies against requirements for ATP Policy for O365"""
        results = []
        
        if not policies:
            return [{
                'requirement_name': f'{policy_type.title()} Connection Error',
                'found': False,
                'status': f'MISSING - Could not connect to Exchange Online or retrieve {policy_type} policies',
                'policy_type': policy_type
            }]
        
        print(f"Successfully retrieved {len(policies)} {policy_type} policies")
        
        # For ATP Policy, we typically have one default policy or custom policies
        enabled_policies = []
        for policy in policies:
            # Include all valid policies - ATP Policy is usually one default policy
            if policy.get('IsValid', True):
                enabled_policies.append(policy)
                print(f"  - {policy_type.title()} Policy: {policy.get('Name', 'Unknown')} (Valid: {policy.get('IsValid', True)})")
        
        if not enabled_policies:
            enabled_policies = policies  # Fallback to all policies if none marked as valid
            print(f"No valid {policy_type} policies found via IsValid, evaluating all policies")
        
        print(f"Evaluating {len(enabled_policies)} valid {policy_type} policies")
        
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
        
        atppolicy_count = len(self.requirements.get('atppolicy_policies', []))
        
        return {
            'loaded': True,
            'requirements_count': atppolicy_count,
            'atppolicy_policies': atppolicy_count
        }
