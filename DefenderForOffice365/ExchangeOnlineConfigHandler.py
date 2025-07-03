import subprocess
import json
import yaml
import os
import tempfile
from typing import Dict, List, Any
from .ExchangeOnlineSessionManager import ExchangeOnlineSessionManager

class ExchangeOnlineConfigHandler:
    def __init__(self, requirements_file: str = None, session_manager: ExchangeOnlineSessionManager = None):
        self.requirements = None
        
        # Use provided session manager or create a new one
        self.session_manager = session_manager if session_manager else ExchangeOnlineSessionManager()
        
        if requirements_file and os.path.exists(requirements_file):
            with open(requirements_file, 'r') as file:
                self.requirements = yaml.safe_load(file)

    def check_policies(self) -> List[Dict[str, Any]]:
        """Check Exchange Online configurations against requirements using shared session manager"""
        all_results = []
        
        print("\n=== Starting Exchange Online Configuration Checks ===")
        
        if not self.requirements:
            print("No Exchange Online configuration requirements file provided")
            return [{
                'requirement_name': 'No Requirements',
                'found': False,
                'status': 'MISSING - No Exchange Online configuration requirements file provided',
                'policy_type': 'exchangeonline'
            }]

        # Determine which configuration types we need to check
        config_types = []
        if 'atppolicy_policies' in self.requirements:
            config_types.append('atppolicy')
        if 'externalinoutlook_policies' in self.requirements:
            config_types.append('externalinoutlook')
        if 'organizationconfig_policies' in self.requirements:
            config_types.append('organizationconfig')
        if 'reportsubmissionpolicy_policies' in self.requirements:
            config_types.append('reportsubmissionpolicy')
        
        print(f"Configuration types to check: {config_types}")
        
        # Use shared session manager to get Exchange Online configurations
        all_configs = self.session_manager.get_all_defender_policies(config_types)
        
        # Check ATP Policy configurations
        if 'atppolicy' in config_types:
            print("\n--- Checking ATP Policy for O365 ---")
            atppolicy_configs = all_configs.get("atppolicy", [])
            print(f"Retrieved {len(atppolicy_configs)} ATP Policy configurations")
            atppolicy_results = self._check_policy_requirements(atppolicy_configs, self.requirements, "atppolicy")
            all_results.extend(atppolicy_results)
        
        # Check External In Outlook configurations
        if 'externalinoutlook' in config_types:
            print("\n--- Checking External Sender Notification In Outlook Configuration ---")
            externalinoutlook_configs = all_configs.get("externalinoutlook", [])
            print(f"Retrieved {len(externalinoutlook_configs)} External Sender Notification In Outlook configurations")
            externalinoutlook_results = self._check_policy_requirements(externalinoutlook_configs, self.requirements, "externalinoutlook")
            all_results.extend(externalinoutlook_results)
        
        # Check Organization configurations 
        if 'organizationconfig' in config_types:
            print("\n--- Checking Organization Configuration ---")
            organizationconfig_configs = all_configs.get("organizationconfig", [])
            print(f"Retrieved {len(organizationconfig_configs)} Organization configurations")
            organizationconfig_results = self._check_policy_requirements(organizationconfig_configs, self.requirements, "organizationconfig")
            all_results.extend(organizationconfig_results)
        
        # Check Report Submission Policy configurations
        if 'reportsubmissionpolicy' in config_types:
            print("\n--- Checking Report Submission Policy Configuration ---")
            reportsubmissionpolicy_configs = all_configs.get("reportsubmissionpolicy", [])
            print(f"Retrieved {len(reportsubmissionpolicy_configs)} Report Submission Policy configurations")
            reportsubmissionpolicy_results = self._check_policy_requirements(reportsubmissionpolicy_configs, self.requirements, "reportsubmissionpolicy")
            all_results.extend(reportsubmissionpolicy_results)
        
        return all_results

    def _check_policy_requirements(self, policies: List[Dict], requirements: Dict, policy_type: str) -> List[Dict[str, Any]]:
        """Check policies against requirements for Exchange Online configurations"""
        results = []
        
        if not policies:
            return [{
                'requirement_name': f'{policy_type.title()} Connection Error',
                'found': False,
                'status': f'MISSING - Could not connect to Exchange Online or retrieve {policy_type} configurations',
                'policy_type': policy_type
            }]
        
        print(f"Successfully retrieved {len(policies)} {policy_type} configurations")
        
        # For most Exchange Online configs, we typically have one default configuration or custom ones
        enabled_policies = []
        for policy in policies:
            # Include all valid configurations
            if policy.get('IsValid', True):
                enabled_policies.append(policy)
                policy_name = policy.get('Name', policy.get('Identity', 'Unknown'))
                print(f"  - {policy_type.title()} Configuration: {policy_name} (Valid: {policy.get('IsValid', True)})")
        
        if not enabled_policies:
            enabled_policies = policies  # Fallback to all configurations if none marked as valid
            print(f"No valid {policy_type} configurations found via IsValid, evaluating all configurations")
        
        print(f"Evaluating {len(enabled_policies)} valid {policy_type} configurations")
        
        # Get the appropriate requirements key
        requirements_key = f'{policy_type}_policies'
        policy_requirements = requirements.get(requirements_key, [])
        
        # Evaluate each requirement against ALL enabled configurations
        for requirement in policy_requirements:
            setting = requirement['setting']
            expected_value = requirement['expected_value']
            requirement_name = requirement['name']
            
            # Track results for this requirement across all configurations
            policy_results = []
            compliant_policies = []
            non_compliant_policies = []
            
            for policy in enabled_policies:
                policy_name = policy.get('Name', policy.get('Identity', 'Unknown'))
                current_value = policy.get(setting)
                
                # Determine compliance for this configuration
                is_compliant = False
                if expected_value == "not_null":
                    # Special case: check if value is not null/None/empty
                    is_compliant = current_value is not None and current_value != "" and current_value != []
                elif isinstance(expected_value, bool):
                    current_bool = bool(current_value) if current_value is not None else False
                    is_compliant = current_bool == expected_value
                elif isinstance(expected_value, str):
                    is_compliant = current_value == expected_value
                else:
                    is_compliant = current_value == expected_value
                
                # Store result for this configuration
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
            # At least one configuration must be compliant for the requirement to pass
            overall_compliant = len(compliant_policies) > 0
            
            # Create result entry
            if overall_compliant:
                status = f"COMPLIANT - Found in configurations: {', '.join(compliant_policies)}"
            else:
                status = f"NON-COMPLIANT - All configurations failed: {', '.join(non_compliant_policies)}"
            
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
                print(f"    Compliant configurations: {', '.join(compliant_policies)}")
            else:
                print(f"  ✗ {requirement_name}: NON-COMPLIANT")
                print(f"    Expected: {expected_value}")
                for policy_result in policy_results:
                    print(f"    {policy_result['policy_name']}: {policy_result['current_value']} ({'✓' if policy_result['is_compliant'] else '✗'})")
        
        return results

    def get_requirements_summary(self) -> Dict[str, Any]:
        """Get a summary of loaded requirements for all Exchange Online config types"""
        if not self.requirements:
            return {'loaded': False, 'requirements_count': 0}
        
        summary = {'loaded': True, 'requirements_count': 0}
        
        # Count requirements for each config type
        for key in self.requirements.keys():
            if key.endswith('_policies'):
                config_type = key.replace('_policies', '')
                count = len(self.requirements.get(key, []))
                summary[config_type] = count
                summary['requirements_count'] += count
        
        return summary
