import os
from datetime import datetime
from jinja2 import Environment, FileSystemLoader

class ReportGenerator:
    def __init__(self):
        self.template_dir = os.path.join(os.path.dirname(__file__), 'templates')
        if not os.path.exists(self.template_dir):
            os.makedirs(self.template_dir)
        self.env = Environment(loader=FileSystemLoader(self.template_dir))
        
    def parse_policy_status(self, result):
        """Parse policy status and determine if it passes requirements"""
        status = str(result.get('status', '')).lower()
        current_value = result.get('current_value')
        expected_value = result.get('expected_value')
        found = result.get('found', False)
        policy_type = result.get('policy_type', '')

        print(f"\nDebug - Policy Status Check:")
        print(f"Policy: {result.get('requirement_name')}")
        print(f"Current Value: {current_value}")
        print(f"Expected Value: {expected_value}")
        print(f"Status: {status}")
        print(f"Found: {found}")
        print(f"Policy Type: {policy_type}")

        # For conditional access policies, consider found policies as passed
        # since the matching logic already verified conditions and controls
        if policy_type == 'conditional_access' and found:
            print("Policy found and conditions/controls matched -> PASS")
            return True

        # For policies that aren't found
        if not found:
            print("Failed: Policy not found")
            return False

        # For anti-spam and authorization policies, check if status indicates compliance
        if policy_type in ['antispam', 'authorization']:
            # Check if status starts with "PRESENT" (meaning current matches expected)
            is_compliant = status.startswith('present')
            print(f"Policy type {policy_type} - Status compliance check: {is_compliant}")
            return is_compliant

        # Fallback to value comparison for other policy types
        current_value_str = str(current_value).lower() if current_value is not None else ''
        
        # Handle different expected value types
        if isinstance(expected_value, list):
            is_passed = current_value_str in [str(v).lower() for v in expected_value]
            print(f"List comparison: {current_value_str} in {expected_value} -> {is_passed}")
            return is_passed
        elif isinstance(expected_value, bool):
            is_passed = current_value_str == str(expected_value).lower()
            print(f"Boolean comparison: {current_value_str} == {expected_value} -> {is_passed}")
            return is_passed
        else:
            # String comparison
            expected_value_str = str(expected_value).lower() if expected_value is not None else ''
            is_passed = current_value_str == expected_value_str
            print(f"String comparison: {current_value_str} == {expected_value_str} -> {is_passed}")
            return is_passed

    def is_policy_passed(self, result, is_conditional_access=True):
        """Unified policy checking for both types"""
        try:
            passed = self.parse_policy_status(result)
            print(f"Final result for {result.get('requirement_name')}: {passed}")
            return passed
        except Exception as e:
            print(f"Error checking policy {result.get('requirement_name')}: {str(e)}")
            return False

    def calculate_compliance_details(self, results, is_conditional_access=True):
        if not results:
            return {
                'percentage': 0,
                'passed': 0,
                'total': 0,
                'is_compliant': False
            }
        
        total = len(results)
        passed = 0
        
        policy_type_name = 'Conditional Access' if is_conditional_access else results[0].get('policy_type', 'Unknown').title()
        print(f"\nCalculating compliance for {policy_type_name} policies:")
        
        for result in results:
            is_passed = self.is_policy_passed(result, is_conditional_access)
            if is_passed:
                passed += 1
                
            print(f"Policy: {result.get('requirement_name')}")
            print(f"Status: {result.get('status')}")
            print(f"Found: {result.get('found')}")
            print(f"Passed: {is_passed}")
            print("-" * 30)

        percentage = round((passed / total) * 100) if total > 0 else 0
        
        result_dict = {
            'percentage': percentage,
            'passed': passed,
            'total': total,
            'is_compliant': percentage == 100
        }
        
        print(f"Final {policy_type_name} calculation: {result_dict}")
        return result_dict

    def generate_report(self, ca_results, auth_results, antispam_results=None):
        # Calculate detailed compliance metrics
        ca_compliance = self.calculate_compliance_details(ca_results, is_conditional_access=True)
        auth_compliance = self.calculate_compliance_details(auth_results, is_conditional_access=False)
        
        # Calculate anti-spam compliance if provided
        antispam_compliance = None
        if antispam_results:
            antispam_compliance = self.calculate_compliance_details(antispam_results, is_conditional_access=False)
        
        # Calculate overall compliance
        total_passed = ca_compliance['passed'] + auth_compliance['passed']
        total_policies = ca_compliance['total'] + auth_compliance['total']
        
        if antispam_compliance:
            total_passed += antispam_compliance['passed']
            total_policies += antispam_compliance['total']
        
        overall_compliance = round((total_passed / total_policies) * 100) if total_policies > 0 else 0

        template = self.env.get_template('report_template.html')
        output = template.render(
            ca_results=ca_results,
            auth_results=auth_results,
            antispam_results=antispam_results or [],
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            compliance_percentage=overall_compliance,
            ca_compliance=ca_compliance,
            auth_compliance=auth_compliance,
            antispam_compliance=antispam_compliance
        )
        
        # Create reports directory if it doesn't exist
        reports_dir = os.path.join(os.path.dirname(__file__), 'reports')
        if not os.path.exists(reports_dir):
            os.makedirs(reports_dir)
            
        # Write the report with UTF-8 encoding to support Unicode characters (emojis)
        report_path = os.path.join(reports_dir, f'report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.html')
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(output)
        print(f"Report generated: {report_path}")