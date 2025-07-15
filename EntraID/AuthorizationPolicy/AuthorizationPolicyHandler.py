import requests
import yaml
from typing import Dict, List, Any

class AuthorizationPolicyHandler:
    def __init__(self, token: str, requirements_file: str):
        self.base_url = "https://graph.microsoft.com/v1.0"
        self.headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        self.requirements_file = requirements_file
        with open(requirements_file, 'r') as file:
            self.requirements = yaml.safe_load(file)
        self.guest_role_mapping = {
            "a0b1b346-4d3e-4e8b-98f8-753987be4970": "Same as member users",
            "10dae51f-b6af-4016-8d66-8c2a99b929b3": "Limited access (default)",
            "2af84b1e-32c8-42b7-82bc-daa82404023b": "Restricted access"
        }

    def _fetch_policy(self) -> Dict[str, Any]:
        response = requests.get(
            f"{self.base_url}/policies/authorizationPolicy",
            headers=self.headers
        )
        response.raise_for_status()
        return response.json()

    def _get_role_name(self, role_id: str) -> str:
        return self.guest_role_mapping.get(role_id, role_id)

    def check_policies(self) -> List[Dict[str, Any]]:
        policy = self._fetch_policy()
        results = []
        
        for requirement in self.requirements['authorization_policies']:
            setting = requirement['setting']
            expected_value = requirement['expected_value']
            
            # Handle nested settings
            if '.' in setting:
                parent, child = setting.split('.')
                current_value = policy.get(parent, {}).get(child)
            else:
                current_value = policy.get(setting)

            # Special handling for guestUserRoleId
            if setting == 'guestUserRoleId':
                current_name = self._get_role_name(current_value)
                expected_name = self._get_role_name(expected_value)
                is_compliant = current_value == expected_value
                status = f"PRESENT - Current: {current_name}"
                if current_value != expected_value:
                    status = f"MISSING - Current: {current_name}, Expected: {expected_name}"
            else:
                # Normalize current value
                current_str = str(current_value).lower() if current_value is not None else 'false'
                
                # For boolean settings, ensure true/false string
                if isinstance(expected_value, bool):
                    current_str = str(current_str == 'true').lower()

                # Create result dict with normalized values
                status = f"PRESENT - Current: {current_str}"
                if isinstance(expected_value, list):
                    is_compliant = current_str in [str(v).lower() for v in expected_value]
                    if not is_compliant:
                        status = f"MISSING - Current: {current_str}, Expected one of: {', '.join(map(str, expected_value))}"
                else:
                    expected_str = str(expected_value).lower()
                    is_compliant = current_str == expected_str
                    if not is_compliant:
                        status = f"MISSING - Current: {current_str}, Expected: {expected_str}"

            result = {
                'requirement_name': requirement['name'],
                'description': requirement.get('description', ''),
                'found': True,
                'current_value': current_value,
                'expected_value': expected_value,
                'policy_type': 'authorization',
                'status': status,
                'is_compliant': is_compliant
            }

            results.append(result)

        return results
