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
        """Parse policy status and determine if it passes requirements - FIXED VERSION"""
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

        # If policy is not found, it's automatically non-compliant
        if not found:
            print("Failed: Policy not found")
            return False

        # For all policy types, check if status indicates compliance
        # Status format: "PRESENT - Current: X (matched policies...)" or "MISSING - ..."
        if status.startswith('present'):
            print("Status indicates PRESENT -> PASS")
            return True
        elif status.startswith('missing'):
            print("Status indicates MISSING -> FAIL")
            return False
        
        # For policies where status doesn't start with PRESENT/MISSING, 
        # check if current value matches expected value
        if current_value is not None and expected_value is not None:
            # Handle boolean comparison
            if isinstance(expected_value, bool):
                if isinstance(current_value, bool):
                    is_passed = current_value == expected_value
                else:
                    # Convert string to boolean for comparison
                    current_bool = str(current_value).lower() in ['true', '1', 'yes', 'on']
                    is_passed = current_bool == expected_value
                print(f"Boolean comparison: {current_value} == {expected_value} -> {is_passed}")
                return is_passed
            
            # Handle list comparison (expected value is one of multiple options)
            elif isinstance(expected_value, list):
                current_str = str(current_value).lower()
                expected_strs = [str(v).lower() for v in expected_value]
                is_passed = current_str in expected_strs
                print(f"List comparison: {current_str} in {expected_strs} -> {is_passed}")
                return is_passed
            
            # Handle string/numeric comparison
            else:
                current_str = str(current_value).lower()
                expected_str = str(expected_value).lower()
                is_passed = current_str == expected_str
                print(f"String comparison: {current_str} == {expected_str} -> {is_passed}")
                return is_passed
        
        # If we can't determine compliance from status or values, 
        # assume non-compliant for safety
        print("Unable to determine compliance -> FAIL (safety default)")
        return False

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
        
        # Calculate separate anti-spam compliance metrics by category
        antispam_compliance = None
        antispam_inbound_standard_compliance = {'percentage': 0, 'passed': 0, 'total': 0, 'is_compliant': False}
        antispam_inbound_strict_compliance = {'percentage': 0, 'passed': 0, 'total': 0, 'is_compliant': False}
        antispam_outbound_compliance = {'percentage': 0, 'passed': 0, 'total': 0, 'is_compliant': False}
        
        if antispam_results:
            # Filter results by policy type
            inbound_standard_results = [r for r in antispam_results if r.get('policy_type') == 'antispam_inbound_standard']
            inbound_strict_results = [r for r in antispam_results if r.get('policy_type') == 'antispam_inbound_strict']
            outbound_results = [r for r in antispam_results if r.get('policy_type') == 'antispam_outbound']
            
            # Calculate compliance for each category
            if inbound_standard_results:
                antispam_inbound_standard_compliance = self.calculate_compliance_details(inbound_standard_results, is_conditional_access=False)
            if inbound_strict_results:
                antispam_inbound_strict_compliance = self.calculate_compliance_details(inbound_strict_results, is_conditional_access=False)
            if outbound_results:
                antispam_outbound_compliance = self.calculate_compliance_details(outbound_results, is_conditional_access=False)
            
            # Calculate overall anti-spam compliance for backward compatibility
            antispam_compliance = self.calculate_compliance_details(antispam_results, is_conditional_access=False)
        
        # Calculate overall compliance using the separate anti-spam categories
        total_passed = (ca_compliance['passed'] + auth_compliance['passed'] + 
                       antispam_inbound_standard_compliance['passed'] + 
                       antispam_inbound_strict_compliance['passed'] + 
                       antispam_outbound_compliance['passed'])
        total_policies = (ca_compliance['total'] + auth_compliance['total'] + 
                         antispam_inbound_standard_compliance['total'] + 
                         antispam_inbound_strict_compliance['total'] + 
                         antispam_outbound_compliance['total'])
        
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
            antispam_compliance=antispam_compliance,
            antispam_inbound_standard_compliance=antispam_inbound_standard_compliance,
            antispam_inbound_strict_compliance=antispam_inbound_strict_compliance,
            antispam_outbound_compliance=antispam_outbound_compliance
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