#!/usr/bin/env python3

from ReportGenerator import ReportGenerator

def test_compliance_calculations():
    """Test compliance calculations for anti-malware and outbound anti-spam"""
    
    report_gen = ReportGenerator()
    
    # Mock anti-malware results
    antimalware_results = [
        {
            'policy_type': 'antimalware',
            'requirement_name': 'File Filter Enabled',
            'found': True,
            'policy_results': [
                {'policy_name': 'Anti-malware Default Policy', 'is_compliant': True, 'current_value': True}
            ]
        },
        {
            'policy_type': 'antimalware',
            'requirement_name': 'ZAP Enabled',
            'found': True,
            'policy_results': [
                {'policy_name': 'Anti-malware Default Policy', 'is_compliant': True, 'current_value': True}
            ]
        }
    ]
    
    # Mock outbound anti-spam results
    antispam_results = [
        {
            'policy_type': 'antispam_outbound',
            'requirement_name': 'Test Outbound Requirement',
            'found': True,
            'policy_breakdown': ['Test Outbound Policy: COMPLIANT (Current: test, Expected: test)']
        }
    ]
    
    # Test anti-malware compliance
    antimalware_compliance = report_gen.calculate_antimalware_compliance_by_policy(antimalware_results)
    print("Anti-malware compliance:", antimalware_compliance)
    
    # Test outbound anti-spam compliance
    outbound_compliance = report_gen.calculate_antispam_compliance_by_policy(antispam_results, 'outbound')
    print("Outbound anti-spam compliance:", outbound_compliance)
    
    # Test if policy type detection works
    has_outbound = any(r.get('policy_type') == 'antispam_outbound' for r in antispam_results)
    has_antimalware = any(r.get('policy_type') == 'antimalware' for r in antimalware_results)
    
    print(f"Has outbound anti-spam: {has_outbound}")
    print(f"Has anti-malware: {has_antimalware}")

if __name__ == "__main__":
    test_compliance_calculations()
