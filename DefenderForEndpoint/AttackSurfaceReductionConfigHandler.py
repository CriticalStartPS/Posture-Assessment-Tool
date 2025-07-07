import requests
import json
import yaml
from typing import Dict, List, Any, Optional

class AttackSurfaceReductionConfigHandler:
    def __init__(self, access_token: str, config_path: str):
        """
        Initialize the Attack Surface Reduction Configuration Handler
        
        Args:
            access_token: The access token for Microsoft Graph API
            config_path: Path to the YAML configuration file
        """
        self.access_token = access_token
        self.config_path = config_path
        self.base_url = "https://graph.microsoft.com/beta"
        self.headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }
        
        # Load configuration requirements
        self.requirements = self._load_requirements()
    
    def _load_requirements(self) -> Dict[str, Any]:
        """Load requirements from YAML configuration file"""
        try:
            with open(self.config_path, 'r') as file:
                return yaml.safe_load(file)
        except FileNotFoundError:
            print(f"Configuration file not found: {self.config_path}")
            return {}
        except yaml.YAMLError as e:
            print(f"Error parsing YAML file: {e}")
            return {}
    
    def fetch_configuration_policies(self) -> List[Dict[str, Any]]:
        """
        Fetch Attack Surface Reduction configuration policies from Intune
        
        Returns:
            List of configuration policies from the endpointSecurityAttackSurfaceReduction template family
        """
        try:
            # Get configuration policies filtered by template family for efficiency
            url = f"{self.base_url}/deviceManagement/configurationPolicies"
            params = {
                "$filter": "templateReference/templateFamily eq 'endpointSecurityAttackSurfaceReduction'"
            }
            
            response = requests.get(url, headers=self.headers, params=params)
            response.raise_for_status()
            
            data = response.json()
            policies = data.get('value', [])
            
            print(f"Found {len(policies)} policies in endpointSecurityAttackSurfaceReduction template family")
            return policies
            
        except requests.exceptions.RequestException as e:
            print(f"Error fetching configuration policies: {e}")
            return []
    
    def find_asr_policies(self, policies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Find Attack Surface Reduction Rules policies by template display name, filtering for Windows platforms only
        
        Args:
            policies: List of all configuration policies
            
        Returns:
            List of Attack Surface Reduction Rules policies for Windows platforms
        """
        asr_policies = []
        
        print(f"Searching through {len(policies)} policies for ASR rules...")
        
        for policy in policies:
            template_ref = policy.get('templateReference', {})
            template_display_name = template_ref.get('templateDisplayName', '')
            template_family = template_ref.get('templateFamily', '')
            platforms = policy.get('platforms', '')
            technologies = policy.get('technologies', '')
            
            # Debug: Print policy details for troubleshooting
            print(f"Policy: {policy.get('name', 'Unknown')}")
            print(f"  Template Display Name: '{template_display_name}'")
            print(f"  Template Family: '{template_family}'")
            print(f"  Platforms: '{platforms}'")
            print(f"  Technologies: '{technologies}'")
            
            # Check if this is specifically an Attack Surface Reduction Rules policy for Windows
            # Must match EXACTLY on template display name (not just template family)
            if (template_display_name == 'Attack Surface Reduction Rules' and 
                platforms == 'windows10'):
                asr_policies.append(policy)
                print(f"✓ Found matching ASR policy: {policy.get('name', 'Unknown')}")
            else:
                print(f"✗ Policy does not match ASR criteria")
                if template_family == 'endpointSecurityAttackSurfaceReduction':
                    print(f"  (This is a {template_display_name} policy, not Attack Surface Reduction Rules)")
            
            print()  # Empty line for readability
        
        print(f"Total Attack Surface Reduction Rules policies found for Windows: {len(asr_policies)}")
        return asr_policies
    
    def fetch_policy_settings(self, policy_id: str) -> Dict[str, Any]:
        """
        Fetch detailed settings for a specific policy
        
        Args:
            policy_id: The ID of the policy to fetch settings for
            
        Returns:
            Policy details with settings
        """
        try:
            url = f"{self.base_url}/deviceManagement/configurationPolicies/{policy_id}?$expand=settings"
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            
            return response.json()
            
        except requests.exceptions.RequestException as e:
            print(f"Error fetching policy settings for {policy_id}: {e}")
            return {}
    
    def extract_setting_value(self, settings: List[Dict[str, Any]], setting_definition_id: str) -> Any:
        """
        Extract a specific setting value from policy settings
        
        Args:
            settings: List of policy settings
            setting_definition_id: The ID of the setting to extract
            
        Returns:
            The setting value or None if not found
        """
        for setting in settings:
            if setting.get('settingInstance', {}).get('settingDefinitionId') == setting_definition_id:
                setting_instance = setting.get('settingInstance', {})
                
                # Handle different setting types
                if 'simpleSettingValue' in setting_instance:
                    return setting_instance['simpleSettingValue'].get('value')
                elif 'choiceSettingValue' in setting_instance:
                    return setting_instance['choiceSettingValue'].get('value')
                elif 'groupSettingCollectionValue' in setting_instance:
                    # Special handling for ASR rules collection
                    if setting_definition_id == 'device_vendor_msft_policy_config_defender_attacksurfacereductionrules':
                        return self._extract_asr_rules(setting_instance['groupSettingCollectionValue'])
                    return setting_instance['groupSettingCollectionValue']
                elif 'groupSettingValue' in setting_instance:
                    return setting_instance['groupSettingValue']
        
        return None
    
    def _extract_asr_rules(self, group_collection: List[Dict[str, Any]]) -> Dict[str, str]:
        """
        Extract ASR rules from the group collection and return a mapping of rule IDs to their values
        
        Args:
            group_collection: The groupSettingCollectionValue for ASR rules
            
        Returns:
            Dictionary mapping setting definition IDs to their values
        """
        asr_rules = {}
        
        if not group_collection:
            return asr_rules
        
        # Look through the collection for ASR rules
        for group in group_collection:
            children = group.get('children', [])
            for child in children:
                if child.get('@odata.type') == '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance':
                    setting_def_id = child.get('settingDefinitionId', '')
                    choice_value = child.get('choiceSettingValue', {}).get('value', '')
                    
                    if setting_def_id and choice_value:
                        asr_rules[setting_def_id] = choice_value
        
        return asr_rules
    
    def check_policy_compliance(self, policy_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Check if a policy meets the compliance requirements
        
        Args:
            policy_data: The policy data with settings
            
        Returns:
            List of compliance check results for this specific policy
        """
        results = []
        policy_name = policy_data.get('name', 'Unknown Policy')
        policy_id = policy_data.get('id', '')
        settings = policy_data.get('settings', [])
        
        print(f"\n--- Checking ASR compliance for policy: {policy_name} ---")
        
        # Check each requirement against this specific policy
        for requirement in self.requirements.get('requirements', []):
            requirement_name = requirement.get('name', 'Unknown Requirement')
            setting_definition_id = requirement.get('setting_definition_id', '')
            expected_value = requirement.get('expected_value')
            check_id = requirement.get('check_id', '')
            
            # Extract the current setting value from this policy
            current_value = self.extract_setting_value(settings, setting_definition_id)
            
            # Determine compliance
            is_compliant = False
            status = "NON-COMPLIANT"
            found = current_value is not None
            
            # Special handling for ASR rules collection
            if setting_definition_id == 'device_vendor_msft_policy_config_defender_attacksurfacereductionrules':
                # For ASR rules, we need to check if the specific rule is configured
                asr_rule_id = requirement.get('asr_rule_id', '')
                if isinstance(current_value, dict) and asr_rule_id in current_value:
                    rule_value = current_value[asr_rule_id]
                    current_value = rule_value
                    found = True
                    
                    if expected_value is not None:
                        is_compliant = rule_value == expected_value
                        status = "COMPLIANT" if is_compliant else "NON-COMPLIANT"
                    else:
                        # If expected_value is null, we just check that the rule exists
                        is_compliant = True
                        status = "COMPLIANT"
                else:
                    found = False
                    status = "NOT CONFIGURED"
            else:
                # Handle other setting types
                if current_value is not None:
                    if expected_value is not None:
                        is_compliant = current_value == expected_value
                        status = "COMPLIANT" if is_compliant else "NON-COMPLIANT"
                    else:
                        # If expected_value is null, we just check that the setting exists
                        is_compliant = True
                        status = "COMPLIANT"
                else:
                    status = "NOT CONFIGURED"
            
            result = {
                'requirement_name': requirement_name,
                'check_id': check_id,
                'policy_name': policy_name,
                'policy_id': policy_id,
                'setting_definition_id': setting_definition_id,
                'asr_rule_id': requirement.get('asr_rule_id', ''),
                'current_value': current_value,
                'expected_value': expected_value,
                'is_compliant': is_compliant,
                'status': status,
                'found': found,
                'policy_type': 'asr'
            }
            
            print(f"  {requirement_name}: {'✓' if is_compliant else '✗'} {status}")
            results.append(result)
        
        compliant_count = sum(1 for r in results if r['is_compliant'])
        total_count = len(results)
        print(f"Policy {policy_name}: {compliant_count}/{total_count} ASR requirements met")
        
        return results
    
    def check_policies(self) -> List[Dict[str, Any]]:
        """
        Main method to check all Attack Surface Reduction Rules policies for compliance
        
        Returns:
            List of all compliance check results from all policies
        """
        all_results = []
        
        # Fetch ASR-related configuration policies
        policies = self.fetch_configuration_policies()
        
        if not policies:
            # Return error result if no policies found
            return [{
                'requirement_name': 'No ASR Policies Found',
                'check_id': 'ASR_001',
                'policy_name': 'N/A',
                'policy_id': 'N/A',
                'current_value': None,
                'expected_value': None,
                'is_compliant': False,
                'status': 'ERROR - No ASR-related configuration policies found',
                'found': False,
                'policy_type': 'asr'
            }]
        
        # Find Attack Surface Reduction Rules policies for Windows
        asr_policies = self.find_asr_policies(policies)
        
        if not asr_policies:
            # Return result indicating no ASR policies found
            return [{
                'requirement_name': 'No ASR Policies Found',
                'check_id': 'ASR_001',
                'policy_name': 'N/A',
                'policy_id': 'N/A',
                'current_value': None,
                'expected_value': None,
                'is_compliant': False,
                'status': 'NOT CONFIGURED - No Attack Surface Reduction Rules policies found for Windows',
                'found': False,
                'policy_type': 'asr'
            }]
        
        print(f"\n=== Processing {len(asr_policies)} Attack Surface Reduction Rules policies ===")
        
        # Process each ASR policy
        for i, policy in enumerate(asr_policies, 1):
            policy_id = policy.get('id', '')
            policy_name = policy.get('name', 'Unknown')
            
            print(f"\n[{i}/{len(asr_policies)}] Processing policy: {policy_name}")
            
            # Fetch detailed settings for this policy
            policy_data = self.fetch_policy_settings(policy_id)
            
            if policy_data:
                # Check compliance for this policy
                policy_results = self.check_policy_compliance(policy_data)
                all_results.extend(policy_results)
            else:
                # Add error result for this policy
                print(f"❌ Error: Could not fetch settings for policy {policy_name}")
                for requirement in self.requirements.get('requirements', []):
                    all_results.append({
                        'requirement_name': requirement.get('name', 'Unknown Requirement'),
                        'check_id': requirement.get('check_id', 'ASR_ERROR'),
                        'policy_name': policy_name,
                        'policy_id': policy_id,
                        'setting_definition_id': requirement.get('setting_definition_id', ''),
                        'asr_rule_id': requirement.get('asr_rule_id', ''),
                        'current_value': None,
                        'expected_value': requirement.get('expected_value'),
                        'is_compliant': False,
                        'status': 'ERROR - Could not fetch policy settings',
                        'found': False,
                        'policy_type': 'asr'
                    })
        
        # Summary of results
        total_policies = len(asr_policies)
        total_results = len(all_results)
        
        # Count fully compliant policies
        compliant_policies = []
        for policy in asr_policies:
            policy_name = policy.get('name', 'Unknown')
            policy_results = [r for r in all_results if r.get('policy_name') == policy_name]
            if policy_results and all(r.get('is_compliant', False) for r in policy_results):
                compliant_policies.append(policy_name)
        
        print(f"\n=== ASR Summary ===")
        print(f"Total ASR policies processed: {total_policies}")
        print(f"Total ASR compliance checks: {total_results}")
        print(f"Fully compliant ASR policies: {len(compliant_policies)}")
        if compliant_policies:
            print(f"Compliant ASR policy names: {', '.join(compliant_policies)}")
        
        print(f"Completed ASR policy compliance check. Found {len(all_results)} results across {total_policies} policies.")
        return all_results
