import yaml
import requests
from typing import Dict, List, Any, Union

class ConditionalAccessPolicyHandler:
    def __init__(self, token: str, requirements_file: str):
        self.base_url = "https://graph.microsoft.com/v1.0"
        self.headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        self.requirements = self._load_requirements(requirements_file)

    def _load_requirements(self, file_path: str) -> List[Dict]:
        """Load and parse requirements from YAML file"""
        with open(file_path, 'r') as file:
            data = yaml.safe_load(file)
            # Extract the list of policies from the YAML structure
            return data.get('conditional_access_policies', [])

    def fetch_policies(self) -> List[Dict[str, Any]]:
        """Fetch all conditional access policies"""
        try:
            response = requests.get(
                f"{self.base_url}/identity/conditionalAccess/policies",
                headers=self.headers
            )
            response.raise_for_status()
            return response.json().get('value', [])
        except Exception as e:
            print(f"Error fetching policies: {str(e)}")
            return []

    def _compare_lists(self, policy_list: Union[List, None], required_list: Union[List, None]) -> bool:
        """Helper method to compare lists of values"""
        if policy_list is None:
            policy_list = []
        if required_list is None:
            required_list = []
        
        # Convert to lists if not already
        if not isinstance(policy_list, list):
            policy_list = [policy_list]
        if not isinstance(required_list, list):
            required_list = [required_list]

        # Case insensitive comparison for strings
        policy_list = [str(x).lower() if isinstance(x, str) else x for x in policy_list]
        required_list = [str(x).lower() if isinstance(x, str) else x for x in required_list]

        return all(req in policy_list for req in required_list)

    def _compare_platform_lists(self, policy_platforms: list, required_platforms: list) -> bool:
        """Special comparison for platform lists that ignores order and is case-insensitive"""
        if policy_platforms is None:
            policy_platforms = []
        if required_platforms is None:
            required_platforms = []

        policy_set = {str(p).lower() for p in policy_platforms}
        required_set = {str(r).lower() for r in required_platforms}
        
        print(f"Platform comparison:")
        print(f"Policy platforms: {policy_set}")
        print(f"Required platforms: {required_set}")
        
        # For excludePlatforms, we want to ensure all required exclusions are present
        # but allow additional exclusions
        return required_set.issubset(policy_set)

    def _get_nested_value(self, obj: Dict, key: str, default: Any = None) -> Any:
        """Helper method to safely get nested dictionary values"""
        try:
            return obj.get(key, default)
        except (AttributeError, TypeError):
            return default

    def _check_session_controls(self, policy_session_controls: Dict, required_session_controls: Dict) -> bool:
        """Check if session controls match requirements"""
        if not required_session_controls:
            return True
            
        if not policy_session_controls:
            print("✗ Failed: No session controls found in policy")
            return False

        print("\nChecking session controls:")
        print(f"Required: {required_session_controls}")
        print(f"Found: {policy_session_controls}")

        # Check sign in frequency
        if 'signInFrequency' in required_session_controls:
            required_freq = required_session_controls['signInFrequency']
            policy_freq = policy_session_controls.get('signInFrequency', {})
            
            print("\nChecking sign in frequency:")
            print(f"Required: {required_freq}")
            print(f"Found: {policy_freq}")

            # Only check the fields we care about
            if required_freq.get('isEnabled'):
                if not policy_freq.get('isEnabled'):
                    print("✗ Failed: Sign in frequency not enabled")
                    return False
                
                if required_freq.get('authenticationType') and \
                   required_freq['authenticationType'] != policy_freq.get('authenticationType'):
                    print("✗ Failed: Authentication type mismatch")
                    return False
                
                if required_freq.get('frequencyInterval') and \
                   required_freq['frequencyInterval'] != policy_freq.get('frequencyInterval'):
                    print("✗ Failed: Frequency interval mismatch")
                    return False
                
            print("✓ Passed sign in frequency checks")

        # Check persistent browser settings
        if 'persistentBrowser' in required_session_controls:
            required_browser = required_session_controls['persistentBrowser']
            policy_browser = policy_session_controls.get('persistentBrowser', {})
            
            print("\nChecking persistent browser settings:")
            print(f"Required: {required_browser}")
            print(f"Found: {policy_browser}")

            if required_browser.get('isEnabled'):
                if not policy_browser.get('isEnabled'):
                    print("✗ Failed: Persistent browser settings not enabled")
                    return False
                
                if required_browser.get('mode') and \
                   required_browser['mode'] != policy_browser.get('mode'):
                    print("✗ Failed: Persistent browser mode mismatch")
                    return False
                
            print("✓ Passed persistent browser checks")

        return True

    def _normalize_rule(self, rule: str) -> str:
        """Normalize rule string by standardizing quotes and whitespace"""
        if not rule:
            return ""
        # Replace all quote types with standard double quotes
        normalized = rule.replace("'", '"').replace(""", '"').replace(""", '"')
        # Remove extra whitespace
        normalized = " ".join(normalized.split())
        return normalized.lower()

    def _compare_device_filter(self, policy_filter: dict, required_filter: dict) -> bool:
        """Compare device filter conditions"""
        if not policy_filter or not required_filter:
            print("✗ Failed: Missing device filter")
            return False

        print("\nChecking device filter:")
        print(f"Required filter: {required_filter}")
        print(f"Policy filter: {policy_filter}")

        # Check mode matches (case-insensitive)
        policy_mode = str(policy_filter.get('mode', '')).lower()
        required_mode = str(required_filter.get('mode', '')).lower()
        if policy_mode != required_mode:
            print("✗ Failed: Device filter mode mismatch")
            return False

        # Normalize and compare rules
        policy_rule = self._normalize_rule(policy_filter.get('rule', ''))
        required_rule = self._normalize_rule(required_filter.get('rule', ''))

        print(f"Comparing normalized rules:")
        print(f"Policy rule: {policy_rule}")
        print(f"Required rule: {required_rule}")

        if policy_rule != required_rule:
            print("✗ Failed: Device filter rule mismatch")
            return False

        print("✓ Passed device filter check")
        return True

    def _policy_matches_requirements(self, policy: Dict, required: Dict) -> bool:
        """Check if a policy matches the required conditions"""
        try:
            print(f"\nDebug - Checking policy conditions...")
            print(f"Policy State: {policy.get('state', 'unknown')}")
            print(f"Policy Name: {policy.get('displayName', 'unknown')}")

            # Check if policy is enabled or in report mode
            policy_state = policy.get('state', '').lower()
            if policy_state not in ['enabled', 'enabledforreportingbutnotenforced']:
                print("✗ Failed: Policy not enabled or in report mode")
                return False

            required_conditions = required.get('required_conditions', {})
            policy_conditions = policy.get('conditions', {})

            # Check each required condition
            for key, value in required_conditions.items():
                policy_value = self._get_nested_value(policy_conditions, key)
                print(f"\nChecking condition: {key}")
                print(f"Required: {value}")
                print(f"Found: {policy_value}")

                if key == 'platforms':
                    # Special handling for platforms
                    if not policy_value:
                        print("✗ Failed: No platform conditions found")
                        return False
                    
                    # Check includePlatforms
                    include_match = self._compare_lists(
                        policy_value.get('includePlatforms'), 
                        value.get('includePlatforms')
                    )
                    
                    # Use new platform comparison for excludePlatforms
                    exclude_match = self._compare_platform_lists(
                        policy_value.get('excludePlatforms'), 
                        value.get('excludePlatforms')
                    )
                    
                    print(f"Platform include match: {include_match}")
                    print(f"Platform exclude match: {exclude_match}")
                    
                    if not (include_match and exclude_match):
                        print("✗ Failed platform condition check")
                        return False
                    print("✓ Passed platform condition check")
                    continue

                # Add device filter check
                if key == 'devices':
                    if not policy_value:
                        print("✗ Failed: No device conditions found")
                        return False
                    
                    device_filter_match = self._compare_device_filter(
                        policy_value.get('deviceFilter'),
                        value.get('deviceFilter')
                    )
                    if not device_filter_match:
                        return False
                    continue

                # Rest of the condition checks
                if isinstance(value, dict):
                    # Special handling for nested conditions
                    for sub_key, sub_value in value.items():
                        policy_sub_value = self._get_nested_value(policy_value, sub_key)
                        print(f"  Checking sub-condition: {sub_key}")
                        print(f"  Required: {sub_value}")
                        print(f"  Found: {policy_sub_value}")

                        # Special handling for applications.includeUserActions
                        if key == 'applications' and sub_key == 'includeUserActions':
                            if not self._compare_lists(policy_sub_value, sub_value):
                                print("✗ Failed includeUserActions check")
                                return False
                            print("✓ Passed includeUserActions check")
                            continue

                        # Handle users section specially
                        if key == 'users':
                            if sub_key == 'excludeUsers' and 'GuestsOrExternalUsers' in sub_value:
                                # Check if guests are excluded via excludeGuestsOrExternalUsers
                                guests_excluded = policy_value.get('excludeGuestsOrExternalUsers') is not None
                                if not guests_excluded:
                                    print("✗ Failed guest exclusion check")
                                    return False
                                print("✓ Passed guest exclusion check")
                                continue

                        if not self._compare_lists(policy_sub_value, sub_value):
                            print(f"✗ Failed {sub_key} check")
                            return False
                        print(f"✓ Passed {sub_key} check")

                elif isinstance(value, list):
                    if not self._compare_lists(policy_value, value):
                        print(f"✗ Failed {key} list check")
                        return False
                    print(f"✓ Passed {key} list check")
                else:
                    if policy_value != value:
                        print(f"✗ Failed {key} value check")
                        return False
                    print(f"✓ Passed {key} value check")

            # Check session controls if required
            if 'required_session_controls' in required:
                if not self._check_session_controls(
                    policy.get('sessionControls', {}),
                    required['required_session_controls']
                ):
                    return False

            # Check grant controls and authentication strength
            if 'required_controls' in required:
                required_controls = required.get('required_controls', {})
                policy_controls = policy.get('grantControls', {})
                
                print("\nChecking grant controls:")
                print(f"Required controls: {required_controls}")
                print(f"Policy controls: {policy_controls}")

                # Handle nested grantControls structure
                if 'grantControls' in required_controls:
                    required_controls = required_controls['grantControls']

                # Handle both direct builtInControls and nested structures
                if 'builtInControls' in required_controls:
                    required_built_in = required_controls['builtInControls']
                    policy_built_in = policy_controls.get('builtInControls', [])
                    
                    print(f"Required built-in controls: {required_built_in}")
                    print(f"Policy built-in controls: {policy_built_in}")
                    
                    if not self._compare_lists(policy_built_in, required_built_in):
                        print("✗ Failed built-in controls check")
                        return False
                    print("✓ Passed built-in controls check")

                # Handle operator if specified
                if 'operator' in required_controls:
                    if required_controls['operator'] != policy_controls.get('operator'):
                        print("✗ Failed operator check")
                        return False
                    print("✓ Passed operator check")

                print("✓ Passed all grant control checks")

            print("✓ All conditions and controls passed")
            return True

        except Exception as e:
            print(f"Error checking policy: {str(e)}")
            print(f"Policy details: {policy}")
            return False

    def check_policies(self, policies: List[Dict]) -> List[Dict]:
        """Check policies against requirements"""
        results = []
        for requirement in self.requirements:
            found = False
            status = "MISSING"
            current_value = "false"  # Default to false
            matching_policies = []
            
            print(f"\nDebug - Checking requirement: {requirement.get('name')}")
            
            for policy in policies:
                # Check if policy matches requirements
                if self._policy_matches_requirements(policy, requirement):
                    found = True
                    # If ANY policy matches all requirements, the requirement is met
                    current_value = "true"  # Set to true when requirements are met
                    matching_policies.append(policy.get('displayName', 'Unnamed Policy'))
                    
                    print(f"Policy Match Details:")
                    print(f"- Required Policy Type: {requirement.get('name')}")
                    print(f"- Matched Policy Name: {policy.get('displayName', 'Unnamed Policy')}")
                    print(f"- All Requirements Met: True")
                    # Continue checking other policies instead of breaking
            
            if found:
                if len(matching_policies) == 1:
                    status = f"PRESENT - Current: {current_value} (Matched Policy: {matching_policies[0]})"
                else:
                    status = f"PRESENT - Current: {current_value} (Matched Policies: {', '.join(matching_policies)})"
            else:
                print(f"No matching policy found for requirement: {requirement.get('name')}")
                status = "MISSING - Current: false, Expected: true (No matching policy found)"
            
            results.append({
                'requirement_name': requirement.get('name', 'Unknown Policy'),
                'found': found,
                'status': status,
                'current_value': current_value,
                'expected_value': 'true',
                'policy_type': 'conditional_access',
                'matched_policies': matching_policies
            })
            
        return results
