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

    def calculate_antispam_compliance_by_policy(self, results, policy_type):
        """Calculate compliance for anti-spam policies where one complete policy meeting all requirements = compliant"""
        if not results:
            return {
                'percentage': 0,
                'passed': 0,
                'total': 0,
                'is_compliant': False,
                'compliant_policy': None
            }
        
        # Group results by policy type to get all requirements for this category
        category_results = [r for r in results if r.get('policy_type') == f'antispam_{policy_type}']
        
        if not category_results:
            return {
                'percentage': 0,
                'passed': 0,
                'total': 0,
                'is_compliant': False,
                'compliant_policy': None
            }
        
        print(f"\nCalculating policy-level compliance for {policy_type} anti-spam:")
        
        # Extract all unique policy names from the results
        all_policy_names = set()
        for result in category_results:
            if 'policy_breakdown' in result:
                for breakdown in result['policy_breakdown']:
                    # Extract policy name from breakdown string (format: "PolicyName: STATUS")
                    if ':' in breakdown:
                        policy_name = breakdown.split(':')[0].strip()
                        # Remove "(Default)" suffix if present
                        if ' (Default)' in policy_name:
                            policy_name = policy_name.replace(' (Default)', '')
                        all_policy_names.add(policy_name)
        
        print(f"Found policies: {list(all_policy_names)}")
        
        # Check each policy to see if it meets ALL requirements
        compliant_policies = []
        total_requirements = len(category_results)
        
        for policy_name in all_policy_names:
            policy_compliant_count = 0
            policy_requirements_checked = 0
            
            print(f"\nChecking policy: {policy_name}")
            
            for result in category_results:
                if 'policy_breakdown' in result:
                    # Look for this policy in the breakdown
                    policy_found_in_requirement = False
                    policy_compliant_in_requirement = False
                    
                    for breakdown in result['policy_breakdown']:
                        if policy_name in breakdown or f"{policy_name} (Default)" in breakdown:
                            policy_found_in_requirement = True
                            # FIXED: Check for exact "COMPLIANT" match, not just substring
                            # This ensures we don't match "NON-COMPLIANT" as compliant
                            if ": COMPLIANT" in breakdown and "NON-COMPLIANT" not in breakdown:
                                policy_compliant_in_requirement = True
                            break
                    
                    if policy_found_in_requirement:
                        policy_requirements_checked += 1
                        if policy_compliant_in_requirement:
                            policy_compliant_count += 1
                            print(f"  ✓ {result['requirement_name']}: COMPLIANT")
                        else:
                            print(f"  ✗ {result['requirement_name']}: NON-COMPLIANT")
            
            # A policy is fully compliant if it meets ALL requirements
            if policy_requirements_checked == total_requirements and policy_compliant_count == total_requirements:
                compliant_policies.append(policy_name)
                print(f"  ✅ Policy '{policy_name}' meets ALL {total_requirements} requirements")
            else:
                print(f"  ❌ Policy '{policy_name}' meets {policy_compliant_count}/{total_requirements} requirements")
        
        # Category is compliant if ANY policy meets ALL requirements
        is_compliant = len(compliant_policies) > 0
        compliant_policy = compliant_policies[0] if compliant_policies else None
        
        # For display purposes, show how many requirements would be "passed" 
        # If compliant: all requirements pass, if not: show actual pass count
        passed_count = total_requirements if is_compliant else sum(1 for r in category_results if self.parse_policy_status(r))
        percentage = 100 if is_compliant else round((passed_count / total_requirements) * 100)
        
        result_dict = {
            'percentage': percentage,
            'passed': passed_count,
            'total': total_requirements,
            'is_compliant': is_compliant,
            'compliant_policy': compliant_policy,
            'compliant_policies': compliant_policies
        }
        
        print(f"Final {policy_type} anti-spam compliance: {result_dict}")
        return result_dict

    def calculate_antispam_compliance_by_requirement(self, results, policy_type):
        """Calculate compliance for anti-spam policies based on requirement-level compliance (simpler approach)"""
        if not results:
            return {
                'percentage': 0,
                'passed': 0,
                'total': 0,
                'is_compliant': False,
                'compliant_policy': None
            }
        
        # Group results by policy type to get all requirements for this category
        category_results = [r for r in results if r.get('policy_type') == f'antispam_{policy_type}']
        
        if not category_results:
            return {
                'percentage': 0,
                'passed': 0,
                'total': 0,
                'is_compliant': False,
                'compliant_policy': None
            }
        
        print(f"\nCalculating requirement-level compliance for {policy_type} anti-spam:")
        
        total_requirements = len(category_results)
        passed_requirements = 0
        
        # Check each requirement's status
        for result in category_results:
            status = result.get('status', '').lower()
            requirement_name = result.get('requirement_name', 'Unknown')
            
            # A requirement passes if status starts with "PRESENT" (meaning all policies comply)
            if status.startswith('present'):
                passed_requirements += 1
                print(f"  ✓ {requirement_name}: PASSED ({status})")
            else:
                print(f"  ✗ {requirement_name}: FAILED ({status})")
        
        # Category is compliant if ALL requirements pass
        is_compliant = passed_requirements == total_requirements
        percentage = round((passed_requirements / total_requirements) * 100) if total_requirements > 0 else 0
        
        # For anti-spam, we don't have a specific "compliant policy" since it's requirement-based
        # But we can indicate the compliance approach
        compliant_policy = "All policies meet requirements" if is_compliant else None
        
        result_dict = {
            'percentage': percentage,
            'passed': passed_requirements,
            'total': total_requirements,
            'is_compliant': is_compliant,
            'compliant_policy': compliant_policy,
            'compliant_policies': [compliant_policy] if compliant_policy else []
        }
        
        print(f"Final {policy_type} anti-spam compliance: {result_dict}")
        return result_dict

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

    def calculate_antiphishing_compliance_by_policy(self, results, policy_type):
        """Calculate compliance for anti-phishing policies where one complete policy meeting all requirements = compliant"""
        if not results:
            return {
                'percentage': 0,
                'passed': 0,
                'total': 0,
                'is_compliant': False,
                'compliant_policy': None,
                'compliant_policies': []
            }
        
        # Group results by policy type to get all requirements for this category
        category_results = [r for r in results if r.get('policy_type') == f'antiphishing_{policy_type}']
        
        if not category_results:
            return {
                'percentage': 0,
                'passed': 0,
                'total': 0,
                'is_compliant': False,
                'compliant_policy': None,
                'compliant_policies': []
            }
        
        print(f"\nCalculating policy-level compliance for {policy_type} anti-phishing:")
        
        # Extract all unique policy names from the results
        all_policy_names = set()
        for result in category_results:
            if 'policy_breakdown' in result:
                for breakdown in result['policy_breakdown']:
                    # Extract policy name from breakdown string (format: "PolicyName: STATUS")
                    if ':' in breakdown:
                        policy_name = breakdown.split(':')[0].strip()
                        # Remove "(Default)" suffix if present
                        if ' (Default)' in policy_name:
                            policy_name = policy_name.replace(' (Default)', '')
                        all_policy_names.add(policy_name)
        
        print(f"Found policies: {list(all_policy_names)}")
        
        # Check each policy to see if it meets ALL requirements
        compliant_policies = []
        total_requirements = len(category_results)
        
        for policy_name in all_policy_names:
            policy_compliant_count = 0
            policy_requirements_checked = 0
            
            print(f"\nChecking policy: {policy_name}")
            
            for result in category_results:
                if 'policy_breakdown' in result:
                    # Look for this policy in the breakdown
                    policy_found_in_requirement = False
                    policy_compliant_in_requirement = False
                    
                    for breakdown in result['policy_breakdown']:
                        if policy_name in breakdown or f"{policy_name} (Default)" in breakdown:
                            policy_found_in_requirement = True
                            # Check for exact "COMPLIANT" match, not just substring
                            # This ensures we don't match "NON-COMPLIANT" as compliant
                            if ": COMPLIANT" in breakdown and "NON-COMPLIANT" not in breakdown:
                                policy_compliant_in_requirement = True
                            break
                    
                    if policy_found_in_requirement:
                        policy_requirements_checked += 1
                        if policy_compliant_in_requirement:
                            policy_compliant_count += 1
                            print(f"  ✓ {result['requirement_name']}: COMPLIANT")
                        else:
                            print(f"  ✗ {result['requirement_name']}: NON-COMPLIANT")
            
            # A policy is fully compliant if it meets ALL requirements
            if policy_requirements_checked == total_requirements and policy_compliant_count == total_requirements:
                compliant_policies.append(policy_name)
                print(f"  ✅ Policy '{policy_name}' meets ALL {total_requirements} requirements")
            else:
                print(f"  ❌ Policy '{policy_name}' meets {policy_compliant_count}/{total_requirements} requirements")
        
        # Category is compliant if ANY policy meets ALL requirements
        is_compliant = len(compliant_policies) > 0
        compliant_policy = compliant_policies[0] if compliant_policies else None
        
        # For display purposes, show how many requirements would be "passed" 
        # If compliant: all requirements pass, if not: show actual pass count
        passed_count = total_requirements if is_compliant else sum(1 for r in category_results if self.parse_policy_status(r))
        percentage = 100 if is_compliant else round((passed_count / total_requirements) * 100)
        
        result_dict = {
            'percentage': percentage,
            'passed': passed_count,
            'total': total_requirements,
            'is_compliant': is_compliant,
            'compliant_policy': compliant_policy,
            'compliant_policies': compliant_policies
        }
        
        print(f"Final {policy_type} anti-phishing compliance: {result_dict}")
        return result_dict

    def generate_report(self, ca_results, auth_results, antispam_results=None, antiphishing_results=None, antimalware_results=None):
        # Calculate detailed compliance metrics
        ca_compliance = self.calculate_compliance_details(ca_results, is_conditional_access=True)
        auth_compliance = self.calculate_compliance_details(auth_results, is_conditional_access=False)
        
        # Calculate separate anti-spam compliance metrics by category using policy-level compliance
        antispam_compliance = None
        antispam_inbound_standard_compliance = {'percentage': 0, 'passed': 0, 'total': 0, 'is_compliant': False}
        antispam_inbound_strict_compliance = {'percentage': 0, 'passed': 0, 'total': 0, 'is_compliant': False}
        antispam_outbound_compliance = {'percentage': 0, 'passed': 0, 'total': 0, 'is_compliant': False}
        
        if antispam_results:            
            # Calculate policy-level compliance for each category (where one policy meeting all requirements = compliant)
            if any(r.get('policy_type') == 'antispam_inbound_standard' for r in antispam_results):
                antispam_inbound_standard_compliance = self.calculate_antispam_compliance_by_policy(antispam_results, 'inbound_standard')
            if any(r.get('policy_type') == 'antispam_inbound_strict' for r in antispam_results):
                antispam_inbound_strict_compliance = self.calculate_antispam_compliance_by_policy(antispam_results, 'inbound_strict')
            if any(r.get('policy_type') == 'antispam_outbound' for r in antispam_results):
                antispam_outbound_compliance = self.calculate_antispam_compliance_by_policy(antispam_results, 'outbound')
            
            # Calculate overall anti-spam compliance for backward compatibility
            antispam_compliance = self.calculate_compliance_details(antispam_results, is_conditional_access=False)
        
        # Calculate separate anti-phishing compliance metrics by category using policy-level compliance
        antiphishing_compliance = None
        antiphishing_standard_compliance = {'percentage': 0, 'passed': 0, 'total': 0, 'is_compliant': False}
        antiphishing_strict_compliance = {'percentage': 0, 'passed': 0, 'total': 0, 'is_compliant': False}
        
        if antiphishing_results:
            # Calculate policy-level compliance for each category (where one policy meeting all requirements = compliant)
            if any(r.get('policy_type') == 'antiphishing_standard' for r in antiphishing_results):
                antiphishing_standard_compliance = self.calculate_antiphishing_compliance_by_policy(antiphishing_results, 'standard')
            if any(r.get('policy_type') == 'antiphishing_strict' for r in antiphishing_results):
                antiphishing_strict_compliance = self.calculate_antiphishing_compliance_by_policy(antiphishing_results, 'strict')
            
            # Calculate overall anti-phishing compliance for backward compatibility
            antiphishing_compliance = self.calculate_compliance_details(antiphishing_results, is_conditional_access=False)
        
        # Calculate anti-malware compliance
        antimalware_compliance = None
        if antimalware_results:
            antimalware_compliance = self.calculate_compliance_details(antimalware_results, is_conditional_access=False)
        
        # Calculate overall compliance using the separate categories
        total_passed = (ca_compliance['passed'] + auth_compliance['passed'] + 
                       antispam_inbound_standard_compliance['passed'] + 
                       antispam_inbound_strict_compliance['passed'] + 
                       antispam_outbound_compliance['passed'] +
                       antiphishing_standard_compliance['passed'] +
                       antiphishing_strict_compliance['passed'])
        total_policies = (ca_compliance['total'] + auth_compliance['total'] + 
                         antispam_inbound_standard_compliance['total'] + 
                         antispam_inbound_strict_compliance['total'] + 
                         antispam_outbound_compliance['total'] +
                         antiphishing_standard_compliance['total'] +
                         antiphishing_strict_compliance['total'])
        
        # Add anti-malware compliance to totals if present
        if antimalware_compliance:
            total_passed += antimalware_compliance['passed']
            total_policies += antimalware_compliance['total']
        
        overall_compliance = round((total_passed / total_policies) * 100) if total_policies > 0 else 0

        template = self.env.get_template('report_template.html')
        output = template.render(
            ca_results=ca_results,
            auth_results=auth_results,
            antispam_results=antispam_results or [],
            antiphishing_results=antiphishing_results or [],
            antimalware_results=antimalware_results or [],
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            compliance_percentage=overall_compliance,
            ca_compliance=ca_compliance,
            auth_compliance=auth_compliance,
            antispam_compliance=antispam_compliance,
            antispam_inbound_standard_compliance=antispam_inbound_standard_compliance,
            antispam_inbound_strict_compliance=antispam_inbound_strict_compliance,
            antispam_outbound_compliance=antispam_outbound_compliance,
            antiphishing_compliance=antiphishing_compliance,
            antiphishing_standard_compliance=antiphishing_standard_compliance,
            antiphishing_strict_compliance=antiphishing_strict_compliance,
            antimalware_compliance=antimalware_compliance
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