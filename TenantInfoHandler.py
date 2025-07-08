import requests
import json
from datetime import datetime

class TenantInfoHandler:
    def __init__(self, access_token=None):
        """
        Initialize the tenant info handler with an access token
        
        Args:
            access_token: The access token for Microsoft Graph API calls
        """
        self.access_token = access_token
        
    def get_tenant_information(self):
        """
        Retrieve tenant information including display name and tenant ID
        
        Returns:
            dict: Tenant information containing displayName, id, and other details
        """
        try:
            print("Retrieving tenant information...")
            
            # Check if we have an access token
            if not self.access_token:
                print("❌ No access token provided for tenant information")
                return self._get_default_tenant_info()
            
            print(f"✅ Using provided access token (length: {len(self.access_token)})")
            
            # Make API call to get organization information
            headers = {
                'Authorization': f'Bearer {self.access_token}',
                'Content-Type': 'application/json'
            }
            
            url = 'https://graph.microsoft.com/v1.0/organization'
            print(f"Making API call to: {url}")
            
            response = requests.get(url, headers=headers)
            
            print(f"Response status: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                print(f"Response data keys: {list(data.keys())}")
                
                if 'value' in data and len(data['value']) > 0:
                    org_info = data['value'][0]  # Get the first (and typically only) organization
                    print(f"Organization info keys: {list(org_info.keys())}")
                    print(f"Display Name: {org_info.get('displayName')}")
                    print(f"Tenant ID: {org_info.get('id')}")
                    
                    tenant_info = {
                        'displayName': org_info.get('displayName', 'Unknown Organization'),
                        'tenantId': org_info.get('id', 'Unknown'),
                        'id': org_info.get('id', 'Unknown'),  # Also include as 'id' for consistency
                        'country': org_info.get('country'),
                        'countryLetterCode': org_info.get('countryLetterCode'),
                        'city': org_info.get('city'),
                        'state': org_info.get('state'),
                        'postalCode': org_info.get('postalCode'),
                        'createdDateTime': org_info.get('createdDateTime'),
                        'tenantType': org_info.get('tenantType'),
                        'defaultDomain': self._get_default_domain(org_info.get('verifiedDomains', [])),
                        'retrievedAt': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
                    
                    print(f"✅ Retrieved tenant information for: {tenant_info['displayName']} (ID: {tenant_info['tenantId']})")
                    return tenant_info
                else:
                    print("⚠️ No organization data found in response")
                    print(f"Full response: {data}")
                    return self._get_default_tenant_info()
                    
            else:
                print(f"❌ Failed to retrieve tenant information. Status: {response.status_code}")
                print(f"Response: {response.text}")
                return self._get_default_tenant_info()
                
        except Exception as e:
            print(f"❌ Error retrieving tenant information: {str(e)}")
            import traceback
            traceback.print_exc()
            return self._get_default_tenant_info()
    
    def _get_default_domain(self, verified_domains):
        """
        Extract the default domain from verified domains list
        
        Args:
            verified_domains (list): List of verified domain objects
            
        Returns:
            str: Default domain name or None
        """
        try:
            for domain in verified_domains:
                if domain.get('isDefault', False):
                    return domain.get('name')
            # If no default found, return the first non-onmicrosoft domain
            for domain in verified_domains:
                domain_name = domain.get('name', '')
                if not domain_name.endswith('.onmicrosoft.com'):
                    return domain_name
            # Fallback to first domain
            if verified_domains:
                return verified_domains[0].get('name')
        except Exception as e:
            print(f"⚠️ Error extracting default domain: {str(e)}")
        
        return None
    
    def _get_default_tenant_info(self):
        """
        Return default tenant information when API call fails
        
        Returns:
            dict: Default tenant information
        """
        return {
            'displayName': 'Unknown Organization',
            'tenantId': 'Unknown',
            'country': None,
            'countryLetterCode': None,
            'city': None,
            'state': None,
            'postalCode': None,
            'createdDateTime': None,
            'tenantType': None,
            'defaultDomain': None,
            'retrievedAt': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'error': 'Failed to retrieve tenant information'
        }
    
    def format_tenant_summary(self, tenant_info):
        """
        Format tenant information for display in reports
        
        Args:
            tenant_info (dict): Tenant information from get_tenant_information()
            
        Returns:
            str: Formatted tenant summary string
        """
        try:
            summary_parts = []
            
            # Organization name and ID
            summary_parts.append(f"Organization: {tenant_info.get('displayName', 'Unknown')}")
            summary_parts.append(f"Tenant ID: {tenant_info.get('tenantId', 'Unknown')}")
            
            # Location if available
            location_parts = []
            if tenant_info.get('city'):
                location_parts.append(tenant_info['city'])
            if tenant_info.get('state'):
                location_parts.append(tenant_info['state'])
            if tenant_info.get('countryLetterCode'):
                location_parts.append(tenant_info['countryLetterCode'])
            
            if location_parts:
                summary_parts.append(f"Location: {', '.join(location_parts)}")
            
            # Default domain if available
            if tenant_info.get('defaultDomain'):
                summary_parts.append(f"Primary Domain: {tenant_info['defaultDomain']}")
            
            # Tenant type if available
            if tenant_info.get('tenantType'):
                summary_parts.append(f"Tenant Type: {tenant_info['tenantType']}")
            
            return " | ".join(summary_parts)
            
        except Exception as e:
            print(f"⚠️ Error formatting tenant summary: {str(e)}")
            return f"Organization: {tenant_info.get('displayName', 'Unknown')} | Tenant ID: {tenant_info.get('tenantId', 'Unknown')}"
