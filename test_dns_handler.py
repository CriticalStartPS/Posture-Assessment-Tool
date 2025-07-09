#!/usr/bin/env python3

# Test script for DNS handler domain retrieval
import sys
import os

# Add the current directory to Python path so we can import our modules
sys.path.append(os.getcwd())

from DefenderForOffice365.ExchangeOnlineDNSConfigHandler import ExchangeOnlineDNSConfigHandler
from DefenderForOffice365.ExchangeOnlineSessionManager import ExchangeOnlineSessionManager

def test_dns_domain_retrieval():
    print("=== Testing DNS Domain Retrieval ===")
    
    # Create session manager and DNS handler
    session_manager = ExchangeOnlineSessionManager()
    dns_handler = ExchangeOnlineDNSConfigHandler(
        exchange_session_manager=session_manager,
        requirements_file_path='config/DefenderForOffice365/dns_requirements.yaml'
    )
    
    # Test domain retrieval
    print("\n1. Testing get_default_domain()...")
    domain = dns_handler.get_default_domain()
    print(f"Result: {domain}")
    
    if domain:
        print(f"\n2. Testing DNS checks for domain: {domain}")
        
        # Test SPF check
        print("\n2a. Testing SPF check...")
        spf_result = dns_handler.check_spf_record(domain)
        print(f"SPF Result: {spf_result}")
        
        # Test DKIM check
        print("\n2b. Testing DKIM check...")
        dkim_result = dns_handler.check_dkim_records(domain)
        print(f"DKIM Result: {dkim_result}")
        
        # Test DMARC check
        print("\n2c. Testing DMARC check...")
        dmarc_result = dns_handler.check_dmarc_record(domain)
        print(f"DMARC Result: {dmarc_result}")
        
        print("\n3. Testing full check_policies()...")
        all_results = dns_handler.check_policies()
        print(f"Full Results: {all_results}")
    else:
        print("❌ Could not retrieve domain - skipping DNS checks")

if __name__ == "__main__":
    test_dns_domain_retrieval()
