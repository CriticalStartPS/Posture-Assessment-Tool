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

    def calculate_antimalware_compliance_by_policy(self, results):
        """Calculate compliance for anti-malware policies where one complete policy meeting all requirements = compliant"""
        if not results:
            return {
                'percentage': 0,
                'passed': 0,
                'total': 0,
                'is_compliant': False,
                'compliant_policy': None
            }
        
        # Filter anti-malware results
        category_results = [r for r in results if r.get('policy_type') == 'antimalware']
        
        if not category_results:
            return {
                'percentage': 0,
                'passed': 0,
                'total': 0,
                'is_compliant': False,
                'compliant_policy': None
            }
        
        print(f"\nCalculating policy-level compliance for anti-malware:")
        
        # Extract all unique policy names from the results
        all_policy_names = set()
        for result in category_results:
            if 'policy_results' in result and result['policy_results']:
                for policy_result in result['policy_results']:
                    policy_name = policy_result.get('policy_name', 'Unknown')
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
                if 'policy_results' in result and result['policy_results']:
                    # Look for this policy in the policy_results
                    policy_found_in_requirement = False
                    policy_compliant_in_requirement = False
                    
                    for policy_result in result['policy_results']:
                        if policy_result.get('policy_name') == policy_name:
                            policy_found_in_requirement = True
                            policy_compliant_in_requirement = policy_result.get('is_compliant', False)
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
        passed_count = total_requirements if is_compliant else sum(1 for r in category_results if r.get('found', False))
        percentage = 100 if is_compliant else round((passed_count / total_requirements) * 100)
        
        result_dict = {
            'percentage': percentage,
            'passed': passed_count,
            'total': total_requirements,
            'is_compliant': is_compliant,
            'compliant_policy': compliant_policy,
            'compliant_policies': compliant_policies
        }
        
        print(f"Final anti-malware compliance: {result_dict}")
        return result_dict

    def calculate_safeattachments_compliance_by_policy(self, results):
        """Calculate compliance for Safe Attachments policies where one complete policy meeting all requirements = compliant"""
        if not results:
            return {
                'percentage': 0,
                'passed': 0,
                'total': 0,
                'is_compliant': False,
                'compliant_policy': None
            }
        
        # Filter Safe Attachments results
        category_results = [r for r in results if r.get('policy_type') == 'safeattachments']
        
        if not category_results:
            return {
                'percentage': 0,
                'passed': 0,
                'total': 0,
                'is_compliant': False,
                'compliant_policy': None
            }
        
        print(f"\nCalculating policy-level compliance for Safe Attachments:")
        
        # Extract all unique policy names from the results
        all_policy_names = set()
        for result in category_results:
            if 'policy_results' in result and result['policy_results']:
                for policy_result in result['policy_results']:
                    policy_name = policy_result.get('policy_name', 'Unknown')
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
                if 'policy_results' in result and result['policy_results']:
                    # Look for this policy in the policy_results
                    policy_found_in_requirement = False
                    policy_compliant_in_requirement = False
                    
                    for policy_result in result['policy_results']:
                        if policy_result.get('policy_name') == policy_name:
                            policy_found_in_requirement = True
                            policy_compliant_in_requirement = policy_result.get('is_compliant', False)
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
        passed_count = total_requirements if is_compliant else sum(1 for r in category_results if r.get('found', False))
        percentage = 100 if is_compliant else round((passed_count / total_requirements) * 100)
        
        result_dict = {
            'percentage': percentage,
            'passed': passed_count,
            'total': total_requirements,
            'is_compliant': is_compliant,
            'compliant_policy': compliant_policy,
            'compliant_policies': compliant_policies
        }
        
        print(f"Final Safe Attachments compliance: {result_dict}")
        return result_dict

    def calculate_safelinks_compliance_by_policy(self, results):
        """Calculate compliance for Safe Links policies where one complete policy meeting all requirements = compliant"""
        if not results:
            return {
                'percentage': 0,
                'passed': 0,
                'total': 0,
                'is_compliant': False,
                'compliant_policy': None
            }
        
        # Filter Safe Links results
        category_results = [r for r in results if r.get('policy_type') == 'safelinks']
        
        if not category_results:
            return {
                'percentage': 0,
                'passed': 0,
                'total': 0,
                'is_compliant': False,
                'compliant_policy': None
            }
        
        print(f"\nCalculating policy-level compliance for Safe Links:")
        
        # Extract all unique policy names from the results
        all_policy_names = set()
        for result in category_results:
            if 'policy_results' in result and result['policy_results']:
                for policy_result in result['policy_results']:
                    policy_name = policy_result.get('policy_name', 'Unknown')
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
                if 'policy_results' in result and result['policy_results']:
                    # Look for this policy in the policy_results
                    policy_found_in_requirement = False
                    policy_compliant_in_requirement = False
                    
                    for policy_result in result['policy_results']:
                        if policy_result.get('policy_name') == policy_name:
                            policy_found_in_requirement = True
                            policy_compliant_in_requirement = policy_result.get('is_compliant', False)
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
        passed_count = total_requirements if is_compliant else sum(1 for r in category_results if r.get('found', False))
        percentage = 100 if is_compliant else round((passed_count / total_requirements) * 100)
        
        result_dict = {
            'percentage': percentage,
            'passed': passed_count,
            'total': total_requirements,
            'is_compliant': is_compliant,
            'compliant_policy': compliant_policy,
            'compliant_policies': compliant_policies
        }
        
        print(f"Final Safe Links compliance: {result_dict}")
        return result_dict

    def calculate_exchangeonline_compliance_by_policy(self, results):
        """Calculate compliance for Exchange Online configurations where one complete policy meeting all requirements = compliant"""
        if not results:
            return {
                'percentage': 0,
                'passed': 0,
                'total': 0,
                'is_compliant': False,
                'compliant_policy': None
            }
        
        # Group results by policy type (atppolicy, externalinoutlook, organizationconfig)
        compliance_by_type = {}
        
        # Get all unique policy types
        policy_types = list(set(r.get('policy_type', 'unknown') for r in results))
        
        for policy_type in policy_types:
            category_results = [r for r in results if r.get('policy_type') == policy_type]
            
            if not category_results:
                compliance_by_type[policy_type] = {
                    'percentage': 0,
                    'passed': 0,
                    'total': 0,
                    'is_compliant': False,
                    'compliant_policy': None
                }
            
            print(f"\nCalculating policy-level compliance for {policy_type}:")
            
            # Extract all unique policy names from the results
            all_policy_names = set()
            for result in category_results:
                if 'policy_results' in result and result['policy_results']:
                    for policy_result in result['policy_results']:
                        policy_name = policy_result.get('policy_name', 'Unknown')
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
                    if 'policy_results' in result and result['policy_results']:
                        # Look for this policy in the policy_results
                        policy_found_in_requirement = False
                        policy_compliant_in_requirement = False
                        
                        for policy_result in result['policy_results']:
                            if policy_result.get('policy_name') == policy_name:
                                policy_found_in_requirement = True
                                policy_compliant_in_requirement = policy_result.get('is_compliant', False)
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
            passed_count = total_requirements if is_compliant else sum(1 for r in category_results if r.get('found', False))
            percentage = 100 if is_compliant else round((passed_count / total_requirements) * 100)
            
            compliance_by_type[policy_type] = {
                'percentage': percentage,
                'passed': passed_count,
                'total': total_requirements,
                'is_compliant': is_compliant,
                'compliant_policy': compliant_policy,
                'compliant_policies': compliant_policies
            }
            
            print(f"Final {policy_type} compliance: {compliance_by_type[policy_type]}")
        
        # Calculate overall Exchange Online compliance
        total_passed = sum(comp['passed'] for comp in compliance_by_type.values())
        total_requirements = sum(comp['total'] for comp in compliance_by_type.values())
        overall_percentage = round((total_passed / total_requirements) * 100) if total_requirements > 0 else 0
        overall_compliant = all(comp['is_compliant'] for comp in compliance_by_type.values())
        
        return {
            'percentage': overall_percentage,
            'passed': total_passed,
            'total': total_requirements,
            'is_compliant': overall_compliant,
            'by_type': compliance_by_type
        }

    def add_hierarchical_numbering(self, ca_results, auth_results, antispam_results, antiphishing_results, 
                                   antimalware_results, safeattachments_results, safelinks_results, exchangeonline_results, antivirus_results):
        """Add hierarchical numbering to all policy results for easy referencing"""
        
        # Define the policy sections and their numbers
        section_counter = 1
        
        # 1. Conditional Access Policies
        if ca_results:
            for i, result in enumerate(ca_results, 1):
                result['check_id'] = f"{section_counter}.{i}"
                result['section_name'] = "Conditional Access Policies"
                result['section_number'] = section_counter
        section_counter += 1
        
        # 2. Authorization Policies
        if auth_results:
            for i, result in enumerate(auth_results, 1):
                result['check_id'] = f"{section_counter}.{i}"
                result['section_name'] = "Authorization Policies"
                result['section_number'] = section_counter
        section_counter += 1
        
        # 3. Defender for Office 365 - Anti-Spam Policies
        if antispam_results:
            subsection_counter = 1
            
            # Group anti-spam results by policy type
            inbound_standard = [r for r in antispam_results if r.get('policy_type') == 'antispam_inbound_standard']
            inbound_strict = [r for r in antispam_results if r.get('policy_type') == 'antispam_inbound_strict']
            outbound = [r for r in antispam_results if r.get('policy_type') == 'antispam_outbound']
            general = [r for r in antispam_results if r.get('policy_type') == 'antispam']
            
            # 3.1 Inbound Standard
            if inbound_standard:
                for i, result in enumerate(inbound_standard, 1):
                    result['check_id'] = f"{section_counter}.{subsection_counter}.{i}"
                    result['section_name'] = "Anti-Spam Policies (Inbound Standard)"
                    result['section_number'] = section_counter
                    result['subsection_number'] = subsection_counter
                subsection_counter += 1
            
            # 3.2 Inbound Strict
            if inbound_strict:
                for i, result in enumerate(inbound_strict, 1):
                    result['check_id'] = f"{section_counter}.{subsection_counter}.{i}"
                    result['section_name'] = "Anti-Spam Policies (Inbound Strict)"
                    result['section_number'] = section_counter
                    result['subsection_number'] = subsection_counter
                subsection_counter += 1
            
            # 3.3 Outbound
            if outbound:
                for i, result in enumerate(outbound, 1):
                    result['check_id'] = f"{section_counter}.{subsection_counter}.{i}"
                    result['section_name'] = "Anti-Spam Policies (Outbound)"
                    result['section_number'] = section_counter
                    result['subsection_number'] = subsection_counter
                subsection_counter += 1
            
            # 3.4 General (legacy)
            if general:
                for i, result in enumerate(general, 1):
                    result['check_id'] = f"{section_counter}.{subsection_counter}.{i}"
                    result['section_name'] = "Anti-Spam Policies"
                    result['section_number'] = section_counter
                    result['subsection_number'] = subsection_counter
        section_counter += 1
        
        # 4. Defender for Office 365 - Anti-Phishing Policies
        if antiphishing_results:
            subsection_counter = 1
            
            # Group anti-phishing results by policy type
            standard = [r for r in antiphishing_results if r.get('policy_type') == 'antiphishing_standard']
            strict = [r for r in antiphishing_results if r.get('policy_type') == 'antiphishing_strict']
            general = [r for r in antiphishing_results if r.get('policy_type') == 'antiphishing']
            
            # 4.1 Standard
            if standard:
                for i, result in enumerate(standard, 1):
                    result['check_id'] = f"{section_counter}.{subsection_counter}.{i}"
                    result['section_name'] = "Anti-Phishing Policies (Standard)"
                    result['section_number'] = section_counter
                    result['subsection_number'] = subsection_counter
                subsection_counter += 1
            
            # 4.2 Strict
            if strict:
                for i, result in enumerate(strict, 1):
                    result['check_id'] = f"{section_counter}.{subsection_counter}.{i}"
                    result['section_name'] = "Anti-Phishing Policies (Strict)"
                    result['section_number'] = section_counter
                    result['subsection_number'] = subsection_counter
                subsection_counter += 1
            
            # 4.3 General
            if general:
                for i, result in enumerate(general, 1):
                    result['check_id'] = f"{section_counter}.{subsection_counter}.{i}"
                    result['section_name'] = "Anti-Phishing Policies"
                    result['section_number'] = section_counter
                    result['subsection_number'] = subsection_counter
        section_counter += 1
        
        # 5. Defender for Office 365 - Anti-Malware Policies
        if antimalware_results:
            for i, result in enumerate(antimalware_results, 1):
                result['check_id'] = f"{section_counter}.{i}"
                result['section_name'] = "Anti-Malware Policies"
                result['section_number'] = section_counter
        section_counter += 1
        
        # 6. Defender for Office 365 - Safe Attachments Policies
        if safeattachments_results:
            for i, result in enumerate(safeattachments_results, 1):
                result['check_id'] = f"{section_counter}.{i}"
                result['section_name'] = "Safe Attachments Policies"
                result['section_number'] = section_counter
        section_counter += 1
        
        # 7. Defender for Office 365 - Safe Links Policies
        if safelinks_results:
            for i, result in enumerate(safelinks_results, 1):
                result['check_id'] = f"{section_counter}.{i}"
                result['section_name'] = "Safe Links Policies"
                result['section_number'] = section_counter
        section_counter += 1
        
        # 8. Exchange Online Configurations
        if exchangeonline_results:
            subsection_counter = 1
            
            # Group Exchange Online results by policy type
            atppolicy = [r for r in exchangeonline_results if r.get('policy_type') == 'atppolicy']
            externalinoutlook = [r for r in exchangeonline_results if r.get('policy_type') == 'externalinoutlook']
            organizationconfig = [r for r in exchangeonline_results if r.get('policy_type') == 'organizationconfig']
            reportsubmissionpolicy = [r for r in exchangeonline_results if r.get('policy_type') == 'reportsubmissionpolicy']
            
            # 8.1 ATP Policy for O365
            if atppolicy:
                for i, result in enumerate(atppolicy, 1):
                    result['check_id'] = f"{section_counter}.{subsection_counter}.{i}"
                    result['section_name'] = "Exchange Online - ATP Policy for O365"
                    result['section_number'] = section_counter
                    result['subsection_number'] = subsection_counter
                subsection_counter += 1
            
            # 8.2 External Sender Notification In Outlook
            if externalinoutlook:
                for i, result in enumerate(externalinoutlook, 1):
                    result['check_id'] = f"{section_counter}.{subsection_counter}.{i}"
                    result['section_name'] = "Exchange Online - External Sender Notification In Outlook"
                    result['section_number'] = section_counter
                    result['subsection_number'] = subsection_counter
                subsection_counter += 1
            
            # 8.3 Organization Configuration
            if organizationconfig:
                for i, result in enumerate(organizationconfig, 1):
                    result['check_id'] = f"{section_counter}.{subsection_counter}.{i}"
                    result['section_name'] = "Exchange Online - Organization Configuration"
                    result['section_number'] = section_counter
                    result['subsection_number'] = subsection_counter
                subsection_counter += 1
            
            # 8.4 Report Submission Policy
            if reportsubmissionpolicy:
                for i, result in enumerate(reportsubmissionpolicy, 1):
                    result['check_id'] = f"{section_counter}.{subsection_counter}.{i}"
                    result['section_name'] = "Exchange Online - Report Submission Policy"
                    result['section_number'] = section_counter
                    result['subsection_number'] = subsection_counter
        section_counter += 1
        
        # 9. Defender for Endpoint - Antivirus Configurations
        if antivirus_results:
            for i, result in enumerate(antivirus_results, 1):
                result['check_id'] = f"{section_counter}.{i}"
                result['section_name'] = "Defender for Endpoint - Antivirus Configurations"
                result['section_number'] = section_counter
        
        return {
            'ca_results': ca_results,
            'auth_results': auth_results,
            'antispam_results': antispam_results,
            'antiphishing_results': antiphishing_results,
            'antimalware_results': antimalware_results,
            'safeattachments_results': safeattachments_results,
            'safelinks_results': safelinks_results,
            'exchangeonline_results': exchangeonline_results,
            'antivirus_results': antivirus_results
        }

    def generate_report(self, ca_results, auth_results, antispam_results=None, antiphishing_results=None, antimalware_results=None, safeattachments_results=None, safelinks_results=None, exchangeonline_results=None, antivirus_results=None):
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
        antimalware_compliance = {'percentage': 0, 'passed': 0, 'total': 0, 'is_compliant': False}
        if antimalware_results:
            antimalware_compliance = self.calculate_antimalware_compliance_by_policy(antimalware_results)
        
        # Calculate Safe Attachments compliance
        safeattachments_compliance = {'percentage': 0, 'passed': 0, 'total': 0, 'is_compliant': False}
        if safeattachments_results:
            safeattachments_compliance = self.calculate_safeattachments_compliance_by_policy(safeattachments_results)
        
        # Calculate Safe Links compliance
        safelinks_compliance = {'percentage': 0, 'passed': 0, 'total': 0, 'is_compliant': False}
        if safelinks_results:
            safelinks_compliance = self.calculate_safelinks_compliance_by_policy(safelinks_results)
        
        # Calculate ATP Policy compliance
        atppolicy_compliance = {'percentage': 0, 'passed': 0, 'total': 0, 'is_compliant': False}
        # Calculate Exchange Online compliance
        exchangeonline_compliance = None
        if exchangeonline_results:
            exchangeonline_compliance = self.calculate_exchangeonline_compliance_by_policy(exchangeonline_results)
        
        # Calculate Defender for Endpoint antivirus compliance
        antivirus_compliance = None
        if antivirus_results:
            antivirus_compliance = self.calculate_antivirus_compliance_by_policy(antivirus_results)
        
        # Calculate overall compliance using the separate categories
        total_passed = (ca_compliance['passed'] + auth_compliance['passed'] + 
                       antispam_inbound_standard_compliance['passed'] + 
                       antispam_inbound_strict_compliance['passed'] + 
                       antispam_outbound_compliance['passed'] +
                       antiphishing_standard_compliance['passed'] +
                       antiphishing_strict_compliance['passed'] +
                       antimalware_compliance['passed'] +
                       safeattachments_compliance['passed'] +
                       safelinks_compliance['passed'] +
                       (exchangeonline_compliance['passed'] if exchangeonline_compliance else 0) +
                       (antivirus_compliance['passed'] if antivirus_compliance else 0))
        total_policies = (ca_compliance['total'] + auth_compliance['total'] + 
                         antispam_inbound_standard_compliance['total'] + 
                         antispam_inbound_strict_compliance['total'] + 
                         antispam_outbound_compliance['total'] +
                         antiphishing_standard_compliance['total'] +
                         antiphishing_strict_compliance['total'] +
                         antimalware_compliance['total'] +
                         safeattachments_compliance['total'] +
                         safelinks_compliance['total'] +
                         (exchangeonline_compliance['total'] if exchangeonline_compliance else 0) +
                         (antivirus_compliance['total'] if antivirus_compliance else 0))
        
        overall_compliance = round((total_passed / total_policies) * 100) if total_policies > 0 else 0

        # Restructure antivirus results to group by requirement with policy breakdowns
        restructured_antivirus_results = self.restructure_antivirus_results(antivirus_results) if antivirus_results else []

        # Add hierarchical numbering to all results for easy referencing
        numbered_results = self.add_hierarchical_numbering(
            ca_results, auth_results, antispam_results, antiphishing_results, 
            antimalware_results, safeattachments_results, safelinks_results, exchangeonline_results, restructured_antivirus_results
        )

        template = self.env.get_template('report_template.html')
        output = template.render(
            ca_results=numbered_results['ca_results'],
            auth_results=numbered_results['auth_results'],
            antispam_results=numbered_results['antispam_results'] or [],
            antiphishing_results=numbered_results['antiphishing_results'] or [],
            antimalware_results=numbered_results['antimalware_results'] or [],
            safeattachments_results=numbered_results['safeattachments_results'] or [],
            safelinks_results=numbered_results['safelinks_results'] or [],
            exchangeonline_results=numbered_results['exchangeonline_results'] or [],
            antivirus_results=numbered_results['antivirus_results'] or [],
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
            antimalware_compliance=antimalware_compliance,
            safeattachments_compliance=safeattachments_compliance,
            safelinks_compliance=safelinks_compliance,
            exchangeonline_compliance=exchangeonline_compliance,
            antivirus_compliance=antivirus_compliance
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

    def restructure_antivirus_results(self, results):
        """Restructure antivirus results to group by requirement with policy breakdowns"""
        if not results:
            return []
        
        # Group results by requirement (check_id)
        requirement_groups = {}
        
        for result in results:
            check_id = result.get('check_id', 'Unknown')
            requirement_name = result.get('requirement_name', 'Unknown')
            
            if check_id not in requirement_groups:
                requirement_groups[check_id] = {
                    'check_id': check_id,
                    'requirement_name': requirement_name,
                    'setting_definition_id': result.get('setting_definition_id', ''),
                    'expected_value': result.get('expected_value'),
                    'policy_results': [],
                    'found': False,
                    'status': 'NOT CONFIGURED',
                    'policy_type': 'antivirus'
                }
            
            # Add this policy's result to the requirement
            policy_result = {
                'policy_name': result.get('policy_name', 'Unknown'),
                'policy_id': result.get('policy_id', ''),
                'current_value': result.get('current_value'),
                'is_compliant': result.get('is_compliant', False),
                'status': result.get('status', 'NOT CONFIGURED'),
                'found': result.get('found', False)
            }
            
            requirement_groups[check_id]['policy_results'].append(policy_result)
            
            # Update overall status for this requirement
            if result.get('found', False):
                requirement_groups[check_id]['found'] = True
                
                # Check if any policy is compliant for this requirement
                if result.get('is_compliant', False):
                    requirement_groups[check_id]['status'] = 'COMPLIANT'
                elif requirement_groups[check_id]['status'] not in ['COMPLIANT']:
                    requirement_groups[check_id]['status'] = 'NON-COMPLIANT'
        
        # Find compliant policies for each requirement to update status message
        for group in requirement_groups.values():
            compliant_policies = [p['policy_name'] for p in group['policy_results'] if p['is_compliant']]
            if compliant_policies:
                group['status'] = f"COMPLIANT - Found in policies: {', '.join(compliant_policies)}"
            elif group['found']:
                group['status'] = "NON-COMPLIANT - Policy configured but not meeting requirements"
            else:
                group['status'] = "NOT CONFIGURED - No policies found for this requirement"
        
        # Convert to list and sort by check_id
        restructured_results = list(requirement_groups.values())
        restructured_results.sort(key=lambda x: x.get('check_id', ''))
        
        return restructured_results

    def calculate_antivirus_compliance_by_policy(self, results):
        """Calculate compliance for Defender for Endpoint Antivirus configurations where one complete policy meeting all requirements = compliant"""
        if not results:
            return {
                'percentage': 0,
                'passed': 0,
                'total': 0,
                'is_compliant': False,
                'compliant_policy': None
            }
        
        print(f"\nCalculating policy-level compliance for Defender for Endpoint Antivirus:")
        
        # Extract all unique policy names from the results
        all_policy_names = set()
        for result in results:
            policy_name = result.get('policy_name', 'Unknown')
            if policy_name != 'N/A' and policy_name != 'Unknown':
                all_policy_names.add(policy_name)
        
        print(f"Found {len(all_policy_names)} unique antivirus policies: {list(all_policy_names)}")
        
        # If no valid policies found, return error state
        if not all_policy_names:
            print("No valid antivirus policies found")
            return {
                'percentage': 0,
                'passed': 0,
                'total': len(results),
                'is_compliant': False,
                'compliant_policy': None
            }
        
        # Check each policy for compliance
        compliant_policies = []
        
        for policy_name in all_policy_names:
            # Get all requirements for this policy
            policy_results = [r for r in results if r.get('policy_name') == policy_name]
            
            print(f"\nChecking policy: {policy_name}")
            print(f"Requirements for this policy: {len(policy_results)}")
            
            # Check if all requirements for this policy are met
            policy_compliant = True
            compliant_count = 0
            
            for result in policy_results:
                is_requirement_met = self.parse_policy_status(result)
                if is_requirement_met:
                    compliant_count += 1
                else:
                    policy_compliant = False
                
                print(f"  - {result.get('requirement_name', 'Unknown')}: {'PASS' if is_requirement_met else 'FAIL'}")
            
            if policy_compliant:
                compliant_policies.append(policy_name)
                print(f"Policy '{policy_name}' is COMPLIANT (all {len(policy_results)} requirements met)")
            else:
                print(f"Policy '{policy_name}' is NON-COMPLIANT ({compliant_count}/{len(policy_results)} requirements met)")
        
        # Determine overall compliance
        is_compliant = len(compliant_policies) > 0
        compliant_policy = compliant_policies[0] if compliant_policies else None
        
        # Calculate totals
        total_requirements = len(results)
        
        # For display purposes, show how many requirements would be "passed" 
        # If compliant: all requirements pass, if not: show actual pass count
        passed_count = total_requirements if is_compliant else sum(1 for r in results if r.get('found', False))
        percentage = 100 if is_compliant else round((passed_count / total_requirements) * 100)
        
        final_result = {
            'percentage': percentage,
            'passed': passed_count,
            'total': total_requirements,
            'is_compliant': is_compliant,
            'compliant_policy': compliant_policy,
            'compliant_policies': compliant_policies
        }
        
        print(f"Final antivirus compliance: {final_result}")
        return final_result