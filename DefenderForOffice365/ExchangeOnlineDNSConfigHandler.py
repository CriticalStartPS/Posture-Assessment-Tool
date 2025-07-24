import dns.resolver
import json
import re
import subprocess
from datetime import datetime

class ExchangeOnlineDNSConfigHandler:
    def __init__(self, exchange_session_manager, requirements_file_path):
        """
        Initialize the DNS configuration handler for Exchange Online
        
        Args:
            exchange_session_manager: An instance of ExchangeOnlineSessionManager
            requirements_file_path: Path to the DNS requirements YAML file
        """
        self.exchange_session_manager = exchange_session_manager
        self.requirements_file_path = requirements_file_path
        self.default_domain = None
        
    def get_default_domain(self):
        """
        Get the default accepted domain from Exchange Online using existing session data.
        
        This method first attempts to retrieve the true default accepted domain from 
        Exchange Online's accepted domains configuration. If that fails, it falls back
        to inferring the domain from DKIM configuration data.
        
        Returns:
            str: The default domain name or None if not found
        """
        try:
            print("Retrieving default accepted domain from cached Exchange Online data...")
            
            # First, try to get the true default accepted domain from cache
            cached_policies = self.exchange_session_manager.get_cached_policies()
            
            if 'accepteddomain' in cached_policies and cached_policies['accepteddomain']:
                print("Found default accepted domain in cache...")
                domain_data = cached_policies['accepteddomain']
                
                # Handle both single object and array responses
                if isinstance(domain_data, list) and len(domain_data) > 0:
                    domain_data = domain_data[0]
                
                if isinstance(domain_data, dict) and 'DomainName' in domain_data:
                    domain = domain_data['DomainName']
                    print(f"✅ Found authoritative domain from Exchange Online: {domain}")
                    self.default_domain = domain
                    return domain
                    
            print("⚠️ No default accepted domain found in cache, falling back to DKIM data...")
            
            # Fallback: try to get domain from cached DKIM data if available
            if 'dkim' in cached_policies and cached_policies['dkim']:
                print("Found DKIM data in cache, extracting domain...")
                dkim_data = cached_policies['dkim']
                
                for dkim_entry in dkim_data:
                    domain = dkim_entry.get('Domain', '')
                    # Look for the primary domain (not the .onmicrosoft.com domain)
                    if domain and not domain.endswith('.onmicrosoft.com'):
                        print(f"✅ Found domain from DKIM data (fallback): {domain}")
                        self.default_domain = domain
                        return domain
                
                # If no primary domain found, use the first domain available
                if dkim_data and 'Domain' in dkim_data[0]:
                    domain = dkim_data[0]['Domain']
                    print(f"✅ Using first available domain from DKIM data (fallback): {domain}")
                    self.default_domain = domain
                    return domain
            
            print("⚠️ No domain found in cached data and avoiding additional Exchange Online connection")
            print("⚠️ To avoid multiple login prompts, DNS checks will be skipped")
            return None
                
        except Exception as e:
            print(f"❌ Error retrieving default domain: {str(e)}")
            return None
    
    def check_spf_record(self, domain):
        """
        Check SPF record for the domain
        
        Args:
            domain: Domain name to check
            
        Returns:
            dict: SPF check results
        """
        try:
            print(f"Checking SPF record for {domain}...")
            
            answers = dns.resolver.resolve(domain, 'TXT')
            spf_records = []
            spf_status = "No SPF Record Found"
            has_hard_fail = False
            has_soft_fail = False
            
            for rdata in answers:
                record_text = str(rdata).strip('"')
                if record_text.startswith('v=spf1'):
                    spf_records.append(record_text)
                    
                    # Check for hard fail (-all)
                    if '-all' in record_text:
                        has_hard_fail = True
                        spf_status = "Hard SPF Fail Found (-all)"
                    # Check for soft fail (~all)
                    elif '~all' in record_text:
                        has_soft_fail = True
                        spf_status = "Soft SPF Fail Found (~all)"
                    # Check for redirect
                    elif 'redirect=' in record_text:
                        spf_status = "SPF Redirect Found"
                    else:
                        spf_status = "SPF Record Found (no explicit policy)"
            
            if not spf_records:
                spf_status = "No SPF Record Found"
            
            return {
                'domain': domain,
                'status': spf_status,
                'records': spf_records,
                'record_count': len(spf_records),
                'has_hard_fail': has_hard_fail,
                'has_soft_fail': has_soft_fail,
                'is_compliant': len(spf_records) > 0 and (has_hard_fail or has_soft_fail)
            }
            
        except dns.resolver.NXDOMAIN:
            return {
                'domain': domain,
                'status': 'Domain not found',
                'records': [],
                'record_count': 0,
                'has_hard_fail': False,
                'has_soft_fail': False,
                'is_compliant': False
            }
        except Exception as e:
            return {
                'domain': domain,
                'status': f'Error checking SPF: {str(e)}',
                'records': [],
                'record_count': 0,
                'has_hard_fail': False,
                'has_soft_fail': False,
                'is_compliant': False
            }
    
    def check_dkim_records(self, domain):
        """
        Check DKIM records for the domain (Google and Office 365 selectors)
        
        Args:
            domain: Domain name to check
            
        Returns:
            dict: DKIM check results
        """
        try:
            print(f"Checking DKIM records for {domain}...")
            
            dkim_results = {
                'domain': domain,
                'google_dkim': None,
                'o365_selector1': None,
                'o365_selector2': None,
                'status': 'No DKIM Found',
                'is_compliant': False
            }
            
            # Check Google DKIM selector
            try:
                google_selector = dns.resolver.resolve(f'google._domainkey.{domain}', 'TXT')
                google_records = []
                for rdata in google_selector:
                    google_records.append(str(rdata).strip('"'))
                dkim_results['google_dkim'] = google_records
                dkim_results['status'] = 'Google DKIM Found'
                dkim_results['is_compliant'] = True
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
            
            # Check Office 365 DKIM selectors
            try:
                selector1 = dns.resolver.resolve(f'selector1._domainkey.{domain}', 'CNAME')
                selector1_records = []
                for rdata in selector1:
                    selector1_records.append(str(rdata))
                dkim_results['o365_selector1'] = selector1_records
                
                try:
                    selector2 = dns.resolver.resolve(f'selector2._domainkey.{domain}', 'CNAME')
                    selector2_records = []
                    for rdata in selector2:
                        selector2_records.append(str(rdata))
                    dkim_results['o365_selector2'] = selector2_records
                    dkim_results['status'] = 'Office 365 DKIM Found'
                    dkim_results['is_compliant'] = True
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    dkim_results['status'] = 'Office 365 DKIM Partial (Selector1 only)'
                    dkim_results['is_compliant'] = True
                    
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
            
            return dkim_results
            
        except Exception as e:
            return {
                'domain': domain,
                'google_dkim': None,
                'o365_selector1': None,
                'o365_selector2': None,
                'status': f'Error checking DKIM: {str(e)}',
                'is_compliant': False
            }
    
    def check_dmarc_record(self, domain):
        """
        Check DMARC record for the domain
        
        Args:
            domain: Domain name to check
            
        Returns:
            dict: DMARC check results
        """
        try:
            print(f"Checking DMARC record for {domain}...")
            
            answers = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
            dmarc_records = []
            dmarc_status = "DMARC Record Found"
            policy = "none"
            
            for rdata in answers:
                record_text = str(rdata).strip('"')
                if record_text.startswith('v=DMARC1'):
                    dmarc_records.append(record_text)
                    
                    # Extract policy
                    if 'p=reject' in record_text:
                        policy = "reject"
                        dmarc_status = "DMARC in Reject Mode"
                    elif 'p=quarantine' in record_text:
                        policy = "quarantine"
                        dmarc_status = "DMARC in Quarantine Mode"
                    elif 'p=none' in record_text:
                        policy = "none"
                        dmarc_status = "DMARC in None Mode"
            
            return {
                'domain': domain,
                'status': dmarc_status,
                'records': dmarc_records,
                'policy': policy,
                'record_count': len(dmarc_records),
                'is_compliant': len(dmarc_records) > 0 and policy in ['quarantine', 'reject']
            }
            
        except dns.resolver.NXDOMAIN:
            return {
                'domain': domain,
                'status': 'No DMARC Record Found',
                'records': [],
                'policy': 'none',
                'record_count': 0,
                'is_compliant': False
            }
        except Exception as e:
            return {
                'domain': domain,
                'status': f'Error checking DMARC: {str(e)}',
                'records': [],
                'policy': 'none',
                'record_count': 0,
                'is_compliant': False
            }
    
    def check_policies(self):
        """
        Check DNS policies for the default domain
        
        Returns:
            list: List of DNS check results
        """
        try:
            print("=== Checking Exchange Online DNS Configurations ===")
            
            # Get the default domain
            default_domain = self.get_default_domain()
            if not default_domain:
                return [{
                    'requirement_name': 'Default Domain Retrieval',
                    'found': False,
                    'status': 'ERROR - Could not retrieve default domain from Exchange Online',
                    'policy_type': 'dns',
                    'current_value': None,
                    'expected_value': 'Default domain should be retrievable'
                }]
            
            results = []
            
            # Check SPF
            spf_result = self.check_spf_record(default_domain)
            results.append({
                'requirement_name': 'SPF Record Configuration',
                'found': spf_result['record_count'] > 0,
                'status': f"PRESENT - {spf_result['status']}" if spf_result['record_count'] > 0 else f"MISSING - {spf_result['status']}",
                'policy_type': 'dns',
                'current_value': spf_result['records'],
                'expected_value': 'SPF record with hard fail (-all) or soft fail (~all)',
                'is_compliant': spf_result['is_compliant'],
                'details': spf_result
            })
            
            # Check DKIM
            dkim_result = self.check_dkim_records(default_domain)
            results.append({
                'requirement_name': 'DKIM Record Configuration',
                'found': dkim_result['is_compliant'],
                'status': f"PRESENT - {dkim_result['status']}" if dkim_result['is_compliant'] else f"MISSING - {dkim_result['status']}",
                'policy_type': 'dns',
                'current_value': {
                    'google_dkim': dkim_result['google_dkim'],
                    'o365_selector1': dkim_result['o365_selector1'],
                    'o365_selector2': dkim_result['o365_selector2']
                },
                'expected_value': 'DKIM selectors configured (Google or Office 365)',
                'is_compliant': dkim_result['is_compliant'],
                'details': dkim_result
            })
            
            # Check DMARC
            dmarc_result = self.check_dmarc_record(default_domain)
            results.append({
                'requirement_name': 'DMARC Record Configuration',
                'found': dmarc_result['record_count'] > 0,
                'status': f"PRESENT - {dmarc_result['status']}" if dmarc_result['is_compliant'] else f"MISSING - {dmarc_result['status']}",
                'policy_type': 'dns',
                'current_value': {
                    'records': dmarc_result['records'],
                    'policy': dmarc_result['policy']
                },
                'expected_value': 'DMARC record with quarantine or reject policy',
                'is_compliant': dmarc_result['is_compliant'],
                'details': dmarc_result
            })
            
            # Add MX Provider Detection
            print("\n--- Detecting MX Provider for Domain ---")
            mx_detection = self.detect_mx_provider(default_domain)
            
            results.append({
                'check_id': '9.4',
                'requirement_name': f'MX Provider Detection - {default_domain}',
                'found': mx_detection['status'] == 'SUCCESS',
                'status': f"DETECTED - {mx_detection['provider_details']}" if mx_detection['status'] == 'SUCCESS' else f"ERROR - {mx_detection['provider_details']}",
                'policy_type': 'dns',
                'current_value': {
                    'domain': mx_detection['domain'],
                    'provider': mx_detection['provider'],
                    'mx_records': mx_detection['mx_records']
                },
                'expected_value': 'Automated detection of email security provider',
                'is_compliant': mx_detection['status'] == 'SUCCESS',
                'details': mx_detection
            })
            
            print(f"  Domain: {default_domain} - Provider: {mx_detection['provider']}")
            print(f"✅ Completed DNS checks for domain: {default_domain}")
            return results
            
        except Exception as e:
            print(f"❌ Error during DNS policy checks: {str(e)}")
            return [{
                'requirement_name': 'DNS Configuration Check',
                'found': False,
                'status': f'ERROR - {str(e)}',
                'policy_type': 'dns',
                'current_value': None,
                'expected_value': 'DNS records should be checkable'
            }]

    def detect_mx_provider(self, domain: str) -> dict:
        """Detect the MX record provider for a given domain"""
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            mx_records = []
            provider = "Unknown"
            provider_details = ""
            
            for rdata in answers:
                mx_record = {
                    'host': str(rdata.exchange),
                    'preference': rdata.preference
                }
                mx_records.append(mx_record)
                mx_string = f"Host: {rdata.exchange}, Preference: {rdata.preference}"
                
                # Check for known providers
                if "eo.outlook.com" in str(rdata.exchange).lower():
                    provider = "Microsoft Forefront (Legacy)"
                    provider_details = f"Old Microsoft Forefront MX Record Detected - {mx_string}"
                elif "mail.protection.outlook.com" in str(rdata.exchange).lower():
                    provider = "Microsoft Exchange Online Protection"
                    provider_details = f"New EOP MX Record Detected - {mx_string}"
                elif "barracudanetworks.com" in str(rdata.exchange).lower():
                    provider = "Barracuda Networks"
                    provider_details = f"Barracuda Spam Filter Detected - {mx_string}"
                elif "aspmx.l.google.com" in str(rdata.exchange).lower():
                    provider = "Google Gmail"
                    provider_details = f"Gmail Detected - {mx_string}"
                elif "mimecast.com" in str(rdata.exchange).lower():
                    provider = "Mimecast"
                    provider_details = f"Mimecast Detected - {mx_string}"
                elif "pphosted.com" in str(rdata.exchange).lower():
                    provider = "Proofpoint"
                    provider_details = f"Proofpoint Detected - {mx_string}"
                else:
                    provider = "Other/Custom"
                    provider_details = f"Other Mail Provider Detected - {mx_string}"
            
            return {
                'domain': domain,
                'provider': provider,
                'provider_details': provider_details,
                'mx_records': mx_records,
                'status': 'SUCCESS'
            }
            
        except Exception as e:
            return {
                'domain': domain,
                'provider': "Error",
                'provider_details': f"Failed to resolve MX records: {str(e)}",
                'mx_records': [],
                'status': 'ERROR'
            }
