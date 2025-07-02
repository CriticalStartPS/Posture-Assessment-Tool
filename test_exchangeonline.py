#!/usr/bin/env python3

import sys
import os
sys.path.append(os.path.dirname(__file__))

from DefenderForOffice365.ExchangeOnlineConfigHandler import ExchangeOnlineConfigHandler

def test_exchangeonline():
    print("Testing Exchange Online Configuration Handler...")
    
    # Initialize handler
    exchangeonline_file = 'config/DefenderForOffice365/exchangeonline_requirements.yaml'
    handler = ExchangeOnlineConfigHandler(requirements_file=exchangeonline_file)
    
    # Test loading requirements
    print("\n1. Loading Exchange Online requirements...")
    requirements_path = os.path.join(os.path.dirname(__file__), 'config', 'DefenderForOffice365', 'exchangeonline_requirements.yaml')
    
    if os.path.exists(requirements_path):
        print(f"✓ Requirements file found: {requirements_path}")
        
        # Run assessment
        print("\n2. Running Exchange Online assessment...")
        results = handler.check_policies()
        
        print(f"\n3. Assessment Results:")
        print(f"Total results: {len(results) if results else 0}")
        
        if results:
            for i, result in enumerate(results, 1):
                print(f"\nResult {i}:")
                print(f"  Policy Type: {result.get('policy_type', 'Unknown')}")
                print(f"  Requirement: {result.get('requirement_name', 'Unknown')}")
                print(f"  Status: {result.get('status', 'Unknown')}")
                print(f"  Found: {result.get('found', False)}")
                
                if 'policy_results' in result and result['policy_results']:
                    print(f"  Policy Details:")
                    for policy_result in result['policy_results']:
                        print(f"    - Policy: {policy_result.get('policy_name', 'Unknown')}")
                        print(f"      Current Value: {policy_result.get('current_value', 'N/A')}")
                        print(f"      Compliant: {policy_result.get('is_compliant', False)}")
        else:
            print("  No results returned")
    else:
        print(f"✗ Requirements file not found: {requirements_path}")

if __name__ == "__main__":
    test_exchangeonline()
