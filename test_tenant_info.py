#!/usr/bin/env python3

"""
Test script to verify tenant information retrieval
"""

from GraphAuthenticator import GraphAuthenticator
from TenantInfoHandler import TenantInfoHandler

def test_tenant_info():
    print("=== Testing Tenant Information Retrieval ===")
    
    # Initialize authenticator
    auth = GraphAuthenticator()
    token = auth.authenticate()
    
    if not token:
        print("❌ Authentication failed")
        return
        
    print("✅ Authentication successful")
    
    # Test tenant info retrieval
    tenant_handler = TenantInfoHandler(token)
    tenant_info = tenant_handler.get_tenant_information()
    
    print("\n=== Tenant Information ===")
    for key, value in tenant_info.items():
        print(f"{key}: {value}")
    
    print("\n=== Formatted Summary ===")
    summary = tenant_handler.format_tenant_summary(tenant_info)
    print(summary)

if __name__ == '__main__':
    test_tenant_info()
