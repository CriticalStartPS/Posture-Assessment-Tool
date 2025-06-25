from GraphAuthenticator import GraphAuthenticator
from EntraID.ConditionalAccess.ConditionalAccessPolicyHandler import ConditionalAccessPolicyHandler
from EntraID.AuthorizationPolicy.AuthorizationPolicyHandler import AuthorizationPolicyHandler
from DefenderForOffice365.AntiSpamPolicyHandler import AntiSpamPolicyHandler
from ReportGenerator import ReportGenerator

def main():
    auth = GraphAuthenticator()
    token = auth.authenticate()
    if token:
        # Get Conditional Access results
        ca_handler = ConditionalAccessPolicyHandler(token, 'config/ConditionalAccess/policy_requirements.yaml')
        policies = ca_handler.fetch_policies()
        ca_results = ca_handler.check_policies(policies)
        
        print("\nDebug - Conditional Access Results:")
        print(f"Number of results: {len(ca_results)}")
        for result in ca_results:
            print(f"Policy: {result['requirement_name']}")
            print(f"Found: {result['found']}")
            print(f"Status: {result.get('status', 'N/A')}")
            print("-" * 40)

        # Get Authorization Policy results
        auth_handler = AuthorizationPolicyHandler(token, 'config/AuthorizationPolicy/policy_requirements.yaml')
        auth_results = auth_handler.check_policies()
        
        print("\nDebug - Authorization Policy Results:")
        print(f"Number of results: {len(auth_results)}")
        for result in auth_results:
            print(f"Policy: {result['requirement_name']}")
            print(f"Found: {result['found']}")
            print(f"Status: {result.get('status', 'N/A')}")
            print("-" * 40)

        # Get Defender for Office 365 Anti-Spam results
        antispam_results = []
        try:
            print("\n=== Checking Defender for Office 365 Anti-Spam Policies ===")
            
            # Check if Exchange Online module is available
            check_module_script = """
$module = Get-Module -ListAvailable -Name ExchangeOnlineManagement | Sort-Object Version -Descending | Select-Object -First 1
if ($module) {
    Write-Output "Module available: $($module.Version)"
    exit 0
} else {
    Write-Output "Module not available"
    exit 1
}
"""
        
            import subprocess
            
            # Try PowerShell 7 first
            powershell_exe = "pwsh"
            try:
                subprocess.run([powershell_exe, "-Version"], 
                             capture_output=True, timeout=5, check=True)
                print("Using PowerShell 7 (pwsh)")
            except (subprocess.CalledProcessError, FileNotFoundError):
                print("PowerShell 7 not found, using Windows PowerShell")
                powershell_exe = "powershell.exe"
            
            module_check = subprocess.run([
                powershell_exe,
                "-ExecutionPolicy", "Bypass",
                "-Command", check_module_script
            ], capture_output=True, text=True, timeout=30)
            
            if module_check.returncode != 0:
                print("Exchange Online PowerShell module not found. Please install it:")
                print("Install-Module -Name ExchangeOnlineManagement -Force")
                antispam_results = [{
                    'requirement_name': 'Module Missing',
                    'found': False,
                    'status': 'MISSING - Exchange Online PowerShell module not installed',
                    'policy_type': 'antispam'
                }]
            else:
                print(f"Exchange Online module found: {module_check.stdout.strip()}")
                # Remove token parameter - now uses interactive auth
                antispam_handler = AntiSpamPolicyHandler('config/DefenderForOffice365/antispam_requirements.yaml')
                antispam_results = antispam_handler.check_policies()
        
        except FileNotFoundError:
            print("Anti-spam requirements file not found. Skipping Defender checks.")
            antispam_results = []
        except Exception as e:
            print(f"Error checking anti-spam policies: {str(e)}")
            antispam_results = [{
                'requirement_name': 'Error',
                'found': False,
                'status': f'ERROR - {str(e)}',
                'policy_type': 'antispam'
            }]

        # Update report generation to include anti-spam results
        report = ReportGenerator()
        report.generate_report(ca_results, auth_results, antispam_results)

if __name__ == '__main__':
    main()