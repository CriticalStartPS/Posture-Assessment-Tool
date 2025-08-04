import requests
import json
import yaml
from typing import Dict, List, Any, Optional

class AntivirusConfigHandler:
    def __init__(self, access_token: str, config_path: str):
        """
        Initialize the Antivirus Configuration Handler
        
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
        Fetch all configuration policies from Intune
        
        Returns:
            List of configuration policies
        """
        try:
            # Get all configuration policies
            url = f"{self.base_url}/deviceManagement/configurationPolicies"
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            
            data = response.json()
            policies = data.get('value', [])
            
            print(f"Found {len(policies)} configuration policies")
            return policies
            
        except requests.exceptions.RequestException as e:
            print(f"Error fetching configuration policies: {e}")
            return []
    
    def find_antivirus_policies(self, policies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Find Microsoft Defender Antivirus policies by template display name, filtering for Windows platforms only
        
        Args:
            policies: List of all configuration policies
            
        Returns:
            List of Microsoft Defender Antivirus policies for Windows platforms
        """
        antivirus_policies = []
        
        for policy in policies:
            template_ref = policy.get('templateReference', {})
            template_display_name = template_ref.get('templateDisplayName', '')
            platforms = policy.get('platforms', '')
            
            # Check if this is a Microsoft Defender Antivirus policy for Windows
            if (template_display_name == 'Microsoft Defender Antivirus' and 
                platforms == 'windows10'):
                antivirus_policies.append(policy)
                print(f"Found Microsoft Defender Antivirus policy for Windows: {policy.get('name', 'Unknown')}")
        
        print(f"Total Microsoft Defender Antivirus policies found for Windows: {len(antivirus_policies)}")
        return antivirus_policies
    
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
                    # Special handling for threat severity default action
                    if setting_definition_id == 'device_vendor_msft_policy_config_defender_threatseveritydefaultaction':
                        return self._extract_threat_severity_actions(setting_instance['groupSettingCollectionValue'])
                    return setting_instance['groupSettingCollectionValue']
                elif 'groupSettingValue' in setting_instance:
                    return setting_instance['groupSettingValue']
        
        return None
    
    def _extract_threat_severity_actions(self, group_collection: List[Dict[str, Any]]) -> str:
        """
        Extract threat severity default actions and check if any are set to quarantine
        
        Args:
            group_collection: The groupSettingCollectionValue for threat severity actions
            
        Returns:
            'quarantine' if any severity level is set to quarantine, 'other' otherwise
        """
        if not group_collection:
            return None
        
        # Look through the collection for quarantine actions
        for group in group_collection:
            children = group.get('children', [])
            for child in children:
                if child.get('@odata.type') == '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance':
                    choice_value = child.get('choiceSettingValue', {}).get('value', '')
                    # Check if any severity level is set to quarantine
                    if 'quarantine' in choice_value.lower():
                        return 'quarantine'
        
        return 'other'
    
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
        
        print(f"\n--- Checking compliance for policy: {policy_name} ---")
        
        # Check each requirement against this specific policy
        for requirement in self.requirements.get('requirements', []):
            requirement_name = requirement.get('name', 'Unknown Requirement')
            setting_definition_id = requirement.get('setting_definition_id', '')
            expected_value = requirement.get('expected_value')
            check_id = requirement.get('check_id', '')
            description = requirement.get('description', '')
            
            # Extract the current setting value from this policy
            current_value = self.extract_setting_value(settings, setting_definition_id)
            
            # Determine compliance
            is_compliant = False
            status = "NON-COMPLIANT"
            found = current_value is not None
            
            if current_value is not None:
                if expected_value is not None:
                    # Handle list-based expected values (multiple acceptable values)
                    if isinstance(expected_value, list):
                        is_compliant = current_value in expected_value
                    # Special handling for threat severity actions
                    elif setting_definition_id == 'device_vendor_msft_policy_config_defender_threatseveritydefaultaction':
                        is_compliant = current_value == expected_value
                    else:
                        is_compliant = current_value == expected_value
                    status = "COMPLIANT" if is_compliant else "NON-COMPLIANT"
                else:
                    # If expected_value is null, we just check that the setting exists
                    is_compliant = True
                    status = "COMPLIANT"
            else:
                status = "NOT CONFIGURED"
            
            # Create human-readable expected value for display
            display_expected_value = self._create_display_expected_value(expected_value, description, setting_definition_id)
            
            result = {
                'requirement_name': requirement_name,
                'check_id': check_id,
                'policy_name': policy_name,
                'policy_id': policy_id,
                'setting_definition_id': setting_definition_id,
                'current_value': current_value,
                'expected_value': display_expected_value,
                'raw_expected_value': expected_value,  # Keep original for logic
                'description': description,
                'is_compliant': is_compliant,
                'status': status,
                'found': found,
                'policy_type': 'antivirus'
            }
            
            print(f"  {requirement_name}: {'✓' if is_compliant else '✗'} {status}")
            results.append(result)
        
        compliant_count = sum(1 for r in results if r['is_compliant'])
        total_count = len(results)
        print(f"Policy {policy_name}: {compliant_count}/{total_count} requirements met")
        
        return results
    
    def check_policies(self) -> List[Dict[str, Any]]:
        """
        Main method to check all Microsoft Defender Antivirus policies for compliance
        
        Returns:
            List of all compliance check results from all policies
        """
        all_results = []
        
        # Fetch all configuration policies
        policies = self.fetch_configuration_policies()
        
        if not policies:
            # Return error result if no policies found
            return [{
                'requirement_name': 'No Policies Found',
                'check_id': 'ANTIVIRUS_001',
                'policy_name': 'N/A',
                'policy_id': 'N/A',
                'current_value': None,
                'expected_value': None,
                'is_compliant': False,
                'status': 'ERROR - No configuration policies found',
                'found': False,
                'policy_type': 'antivirus'
            }]
        
        # Find Microsoft Defender Antivirus policies for Windows
        antivirus_policies = self.find_antivirus_policies(policies)
        
        if not antivirus_policies:
            # Return result indicating no antivirus policies found
            return [{
                'requirement_name': 'No Antivirus Policies Found',
                'check_id': 'ANTIVIRUS_001',
                'policy_name': 'N/A',
                'policy_id': 'N/A',
                'current_value': None,
                'expected_value': None,
                'is_compliant': False,
                'status': 'NOT CONFIGURED - No Microsoft Defender Antivirus policies found for Windows',
                'found': False,
                'policy_type': 'antivirus'
            }]
        
        print(f"\n=== Processing {len(antivirus_policies)} Microsoft Defender Antivirus policies ===")
        
        # Process each antivirus policy
        for i, policy in enumerate(antivirus_policies, 1):
            policy_id = policy.get('id', '')
            policy_name = policy.get('name', 'Unknown')
            
            print(f"\n[{i}/{len(antivirus_policies)}] Processing policy: {policy_name}")
            
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
                        'check_id': requirement.get('check_id', 'ANTIVIRUS_ERROR'),
                        'policy_name': policy_name,
                        'policy_id': policy_id,
                        'setting_definition_id': requirement.get('setting_definition_id', ''),
                        'current_value': None,
                        'expected_value': requirement.get('expected_value'),
                        'is_compliant': False,
                        'status': 'ERROR - Could not fetch policy settings',
                        'found': False,
                        'policy_type': 'antivirus'
                    })
        
        # Summary of results
        total_policies = len(antivirus_policies)
        total_results = len(all_results)
        
        # Count fully compliant policies
        compliant_policies = []
        for policy in antivirus_policies:
            policy_name = policy.get('name', 'Unknown')
            policy_results = [r for r in all_results if r.get('policy_name') == policy_name]
            if policy_results and all(r.get('is_compliant', False) for r in policy_results):
                compliant_policies.append(policy_name)
        
        print(f"\n=== Summary ===")
        print(f"Total policies processed: {total_policies}")
        print(f"Total compliance checks: {total_results}")
        print(f"Fully compliant policies: {len(compliant_policies)}")
        if compliant_policies:
            print(f"Compliant policy names: {', '.join(compliant_policies)}")
        
        print(f"Completed antivirus policy compliance check. Found {len(all_results)} results across {total_policies} policies.")
        return all_results
    
    def _create_display_expected_value(self, expected_value: Any, description: str, setting_definition_id: str) -> str:
        """Create human-readable expected value for display in reports"""
        if expected_value is None:
            return "Any configured value"
        
        # Handle list-based expected values
        if isinstance(expected_value, list):
            if setting_definition_id == 'device_vendor_msft_policy_config_defender_scanparameter':
                readable_values = []
                for value in expected_value:
                    if value == 'device_vendor_msft_policy_config_defender_scanparameter_1':
                        readable_values.append('Quick Scan (1)')
                    elif value == 'device_vendor_msft_policy_config_defender_scanparameter_2':
                        readable_values.append('Full Scan (2)')
                    else:
                        readable_values.append(value)
                return f"One of: {' or '.join(readable_values)}"
            elif setting_definition_id == 'device_vendor_msft_policy_config_defender_cloudblocklevel':
                readable_values = []
                for value in expected_value:
                    if value == 'device_vendor_msft_policy_config_defender_cloudblocklevel_2':
                        readable_values.append('High (2)')
                    elif value == 'device_vendor_msft_policy_config_defender_cloudblocklevel_4':
                        readable_values.append('High Plus (4)')
                    elif value == 'device_vendor_msft_policy_config_defender_cloudblocklevel_6':
                        readable_values.append('Zero Tolerance (6)')
                    else:
                        readable_values.append(value)
                return f"One of: {', '.join(readable_values)}"
            else:
                return f"One of: {', '.join(map(str, expected_value))}"
        
        # Handle specific setting mappings for better readability
        if setting_definition_id == 'device_vendor_msft_policy_config_defender_scanparameter':
            if expected_value == 'device_vendor_msft_policy_config_defender_scanparameter_1':
                return 'Quick Scan (1)'
            elif expected_value == 'device_vendor_msft_policy_config_defender_scanparameter_2':
                return 'Full Scan (2)'
        
        # Handle enable/disable settings
        if setting_definition_id.endswith('_1'):
            return 'Enabled'
        elif setting_definition_id.endswith('_0'):
            return 'Disabled'
        
        # Handle cloud block level (single values)
        if setting_definition_id == 'device_vendor_msft_policy_config_defender_cloudblocklevel':
            if expected_value == 'device_vendor_msft_policy_config_defender_cloudblocklevel_6':
                return 'Zero Tolerance (6)'
            elif expected_value == 'device_vendor_msft_policy_config_defender_cloudblocklevel_4':
                return 'High Plus (4)'
            elif expected_value == 'device_vendor_msft_policy_config_defender_cloudblocklevel_2':
                return 'High (2)'
            elif expected_value == 'device_vendor_msft_policy_config_defender_cloudblocklevel_1':
                return 'Medium (1)'
            elif expected_value == 'device_vendor_msft_policy_config_defender_cloudblocklevel_0':
                return 'Low (0)'
        
        # Handle real-time scan direction
        if setting_definition_id == 'device_vendor_msft_policy_config_defender_realtimescandirection':
            if expected_value == 'device_vendor_msft_policy_config_defender_realtimescandirection_0':
                return 'Monitor incoming and outgoing files (both directions)'
            elif expected_value == 'device_vendor_msft_policy_config_defender_realtimescandirection_1':
                return 'Monitor incoming files only'
            elif expected_value == 'device_vendor_msft_policy_config_defender_realtimescandirection_2':
                return 'Monitor outgoing files only'
        
        # Handle submission consent
        if setting_definition_id == 'device_vendor_msft_policy_config_defender_submitsamplesconsent':
            if expected_value == 'device_vendor_msft_policy_config_defender_submitsamplesconsent_1':
                return 'Send safe samples automatically'
            elif expected_value == 'device_vendor_msft_policy_config_defender_submitsamplesconsent_2':
                return 'Prompt before sending samples'
            elif expected_value == 'device_vendor_msft_policy_config_defender_submitsamplesconsent_3':
                return 'Never send samples'
        
        # For threat severity default action
        if setting_definition_id == 'device_vendor_msft_policy_config_defender_threatseveritydefaultaction':
            if expected_value == 'quarantine':
                return 'Quarantine threats'
            elif expected_value == 'remove':
                return 'Remove threats'
            elif expected_value == 'allow':
                return 'Allow threats'
        
        # Fallback to description if available, otherwise show the raw value
        if description:
            return f"{description} ({expected_value})"
        
        return str(expected_value)
