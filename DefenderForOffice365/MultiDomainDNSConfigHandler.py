import dns.resolver
import yaml
from typing import Dict, List, Any

class MultiDomainDNSConfigHandler:
    """
    Enhanced DNS configuration handler that checks SPF, DKIM, and DMARC records
    across all authoritative domains (excluding .onmicrosoft.com domains).
    
    This handler provides comprehensive DNS security posture assessment for
    organizations with multiple mail-enabled domains.
    """
    
    def __init__(self, exchange_session_manager, requirements_file_path):
        self.exchange_session_manager = exchange_session_manager
        self.requirements_file_path = requirements_file_path
        self.requirements = self._load_requirements()
    
    def _load_requirements(self) -> Dict:
        """Load DNS requirements from YAML file"""
        try:
            with open(self.requirements_file_path, 'r') as file:
                return yaml.safe_load(file)
        except Exception as e:
            print(f"Warning: Could not load DNS requirements: {e}")
            return {}
    
    def get_authoritative_domains(self) -> List[str]:
        """
        Get all authoritative domains excluding .onmicrosoft.com domains.
        
        Returns:
            List of domain names that should be checked for DNS configuration
        """
        try:
            cached_policies = self.exchange_session_manager.get_cached_policies()
            
            if 'authoritativedomains' in cached_policies and cached_policies['authoritativedomains']:
                domains = []
                domain_data = cached_policies['authoritativedomains']
                
                # Handle both single domain and list of domains
                if isinstance(domain_data, dict):
                    domain_data = [domain_data]
                
                for domain_entry in domain_data:
                    domain_name = domain_entry.get('DomainName', '')
                    if domain_name and not domain_name.endswith('.onmicrosoft.com'):
                        domains.append(domain_name)
                
                print(f"Found {len(domains)} authoritative domains for DNS checking: {domains}")
                return domains
            
            print("No authoritative domains found in cache, checking for fallback options...")
            
            # Fallback to default domain if available
            if 'accepteddomain' in cached_policies and cached_policies['accepteddomain']:
                fallback_domain = cached_policies['accepteddomain'][0].get('DomainName', '')
                if fallback_domain and not fallback_domain.endswith('.onmicrosoft.com'):
                    print(f"Using fallback default domain: {fallback_domain}")
                    return [fallback_domain]
            
            print("No suitable domains found for DNS checking")
            return []
            
        except Exception as e:
            print(f"Error retrieving authoritative domains: {str(e)}")
            return []
    
    def check_spf_record(self, domain: str) -> Dict[str, Any]:
        """
        Check SPF record for a specific domain.
        
        Args:
            domain: Domain name to check
            
        Returns:
            Dictionary with SPF check results
        """
        try:
            print(f"Checking SPF record for {domain}...")
            
            # Query TXT records for the domain
            txt_records = dns.resolver.resolve(domain, 'TXT')
            spf_records = []
            has_hard_fail = False
            has_soft_fail = False
            spf_status = "No SPF Record Found"
            
            for record in txt_records:
                record_text = str(record).strip('"')
                if record_text.startswith('v=spf1'):
                    spf_records.append(record_text)
                    
                    # Check for policy mechanisms
                    if record_text.endswith(' -all'):
                        has_hard_fail = True
                        spf_status = "SPF Hard Fail Found (-all)"
                    elif record_text.endswith(' ~all'):
                        has_soft_fail = True
                        spf_status = "SPF Soft Fail Found (~all)"
                    elif 'redirect=' in record_text:
                        spf_status = "SPF Redirect Found"
                    else:
                        spf_status = "SPF Record Found (no explicit policy)"
            
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
    
    def check_dkim_records(self, domain: str) -> Dict[str, Any]:
        """
        Check DKIM records for a specific domain.
        
        Args:
            domain: Domain name to check
            
        Returns:
            Dictionary with DKIM check results
        """
        try:
            print(f"Checking DKIM records for {domain}...")
            
            # Check common DKIM selectors
            selectors_to_check = [
                'selector1',  # Office 365 default
                'selector2',  # Office 365 default
                'google',     # Google Workspace
                'default',    # Generic
                'mail',       # Generic
                'dkim'        # Generic
            ]
            
            dkim_records = []
            found_selectors = []
            
            for selector in selectors_to_check:
                try:
                    dkim_domain = f"{selector}._domainkey.{domain}"
                    
                    # First try TXT records (for Google Workspace and direct DKIM)
                    try:
                        txt_records = dns.resolver.resolve(dkim_domain, 'TXT')
                        for record in txt_records:
                            record_text = str(record).strip('"')
                            if 'v=DKIM1' in record_text or 'k=' in record_text:
                                dkim_records.append({
                                    'selector': selector,
                                    'record': record_text,
                                    'type': 'TXT'
                                })
                                found_selectors.append(selector)
                                break
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                        pass
                    
                    # If no TXT record found, try CNAME (for Office 365)
                    if selector not in found_selectors:
                        try:
                            cname_records = dns.resolver.resolve(dkim_domain, 'CNAME')
                            for record in cname_records:
                                cname_target = str(record).rstrip('.')
                                # Office 365 DKIM CNAME found
                                dkim_records.append({
                                    'selector': selector,
                                    'record': f'CNAME -> {cname_target}',
                                    'type': 'CNAME'
                                })
                                found_selectors.append(selector)
                                break
                        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                            pass
                            
                except Exception as e:
                    print(f"Error checking DKIM selector {selector} for {domain}: {e}")
                    continue
            
            # Determine compliance and status
            is_compliant = len(found_selectors) > 0
            
            if len(found_selectors) >= 2:
                status = f"Multiple DKIM selectors configured ({', '.join(found_selectors)})"
            elif len(found_selectors) == 1:
                status = f"DKIM configured with selector: {found_selectors[0]}"
            else:
                status = "No DKIM records found"
            
            return {
                'domain': domain,
                'status': status,
                'records': dkim_records,
                'selectors': found_selectors,
                'record_count': len(dkim_records),
                'is_compliant': is_compliant,
                'google_dkim': 'google' in found_selectors,
                'o365_selector1': 'selector1' in found_selectors,
                'o365_selector2': 'selector2' in found_selectors
            }
            
        except Exception as e:
            return {
                'domain': domain,
                'status': f'Error checking DKIM: {str(e)}',
                'records': [],
                'selectors': [],
                'record_count': 0,
                'is_compliant': False,
                'google_dkim': False,
                'o365_selector1': False,
                'o365_selector2': False
            }
    
    def check_dmarc_record(self, domain: str) -> Dict[str, Any]:
        """
        Check DMARC record for a specific domain.
        
        Args:
            domain: Domain name to check
            
        Returns:
            Dictionary with DMARC check results
        """
        try:
            print(f"Checking DMARC record for {domain}...")
            
            # Query DMARC record
            dmarc_domain = f"_dmarc.{domain}"
            txt_records = dns.resolver.resolve(dmarc_domain, 'TXT')
            dmarc_records = []
            policy = "none"
            dmarc_status = "No DMARC Record Found"
            
            for record in txt_records:
                record_text = str(record).strip('"')
                if record_text.startswith('v=DMARC1'):
                    dmarc_records.append(record_text)
                    
                    # Extract policy
                    if 'p=reject' in record_text:
                        policy = "reject"
                        dmarc_status = "DMARC Reject Policy"
                    elif 'p=quarantine' in record_text:
                        policy = "quarantine"
                        dmarc_status = "DMARC Quarantine Policy"
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
    
    def detect_mx_provider(self, domain: str) -> Dict[str, Any]:
        """
        Detect the MX record provider for a domain.
        
        Args:
            domain: Domain name to check
            
        Returns:
            Dictionary with MX provider detection results
        """
        try:
            print(f"Detecting MX provider for {domain}...")
            
            mx_records = dns.resolver.resolve(domain, 'MX')
            mx_hosts = [str(mx.exchange).lower().rstrip('.') for mx in mx_records]
            
            # Provider detection logic
            if any('outlook.com' in mx or 'protection.outlook.com' in mx for mx in mx_hosts):
                provider = "Microsoft 365"
                provider_details = "Microsoft 365 / Exchange Online"
            elif any('google.com' in mx or 'googlemail.com' in mx for mx in mx_hosts):
                provider = "Google Workspace"
                provider_details = "Google Workspace"
            elif any('proofpoint.com' in mx for mx in mx_hosts):
                provider = "Proofpoint"
                provider_details = "Proofpoint Email Security"
            elif any('mimecast.com' in mx for mx in mx_hosts):
                provider = "Mimecast"
                provider_details = "Mimecast Email Security"
            else:
                provider = "Other/Custom"
                provider_details = f"Custom MX records: {', '.join(mx_hosts[:3])}"
            
            return {
                'domain': domain,
                'status': 'SUCCESS',
                'provider': provider,
                'provider_details': provider_details,
                'mx_records': mx_hosts
            }
            
        except Exception as e:
            return {
                'domain': domain,
                'status': 'ERROR',
                'provider': 'Unknown',
                'provider_details': f'Error detecting MX provider: {str(e)}',
                'mx_records': []
            }
    
    def check_policies(self) -> List[Dict[str, Any]]:
        """
        Check DNS policies for all authoritative domains.
        
        Returns:
            List of DNS check results for all domains
        """
        try:
            print("=== Checking DNS Configurations for All Authoritative Domains ===")
            
            # Get all authoritative domains
            domains = self.get_authoritative_domains()
            
            if not domains:
                return [{
                    'requirement_name': 'Domain Retrieval',
                    'found': False,
                    'status': 'ERROR - Could not retrieve authoritative domains from Exchange Online',
                    'policy_type': 'dns',
                    'domain': 'N/A',
                    'current_value': None,
                    'expected_value': 'Authoritative domains should be retrievable',
                    'is_compliant': False
                }]
            
            all_results = []
            
            # Check each domain
            for domain in domains:
                print(f"\n--- Checking DNS for domain: {domain} ---")
                
                # SPF Check
                spf_result = self.check_spf_record(domain)
                all_results.append({
                    'requirement_name': f'SPF Record - {domain}',
                    'found': spf_result['record_count'] > 0,
                    'status': f"{domain} - {spf_result['status']}",
                    'policy_type': 'dns',
                    'domain': domain,
                    'current_value': spf_result['records'],
                    'expected_value': 'SPF record with hard fail (-all) or soft fail (~all)',
                    'is_compliant': spf_result['is_compliant'],
                    'details': spf_result
                })
                
                # DKIM Check
                dkim_result = self.check_dkim_records(domain)
                all_results.append({
                    'requirement_name': f'DKIM Record - {domain}',
                    'found': dkim_result['is_compliant'],
                    'status': f"{domain} - {dkim_result['status']}",
                    'policy_type': 'dns',
                    'domain': domain,
                    'current_value': {
                        'selectors': dkim_result['selectors'],
                        'google_dkim': dkim_result['google_dkim'],
                        'o365_selector1': dkim_result['o365_selector1'],
                        'o365_selector2': dkim_result['o365_selector2']
                    },
                    'expected_value': 'DKIM selectors configured (Google or Office 365)',
                    'is_compliant': dkim_result['is_compliant'],
                    'details': dkim_result
                })
                
                # DMARC Check
                dmarc_result = self.check_dmarc_record(domain)
                all_results.append({
                    'requirement_name': f'DMARC Record - {domain}',
                    'found': dmarc_result['record_count'] > 0,
                    'status': f"{domain} - {dmarc_result['status']}",
                    'policy_type': 'dns',
                    'domain': domain,
                    'current_value': {
                        'records': dmarc_result['records'],
                        'policy': dmarc_result['policy']
                    },
                    'expected_value': 'DMARC record with quarantine or reject policy',
                    'is_compliant': dmarc_result['is_compliant'],
                    'details': dmarc_result
                })
                
                # MX Provider Detection
                mx_detection = self.detect_mx_provider(domain)
                all_results.append({
                    'requirement_name': f'MX Provider Detection - {domain}',
                    'found': mx_detection['status'] == 'SUCCESS',
                    'status': f"{domain} - {mx_detection['provider_details']}",
                    'policy_type': 'dns',
                    'domain': domain,
                    'current_value': {
                        'provider': mx_detection['provider'],
                        'mx_records': mx_detection['mx_records']
                    },
                    'expected_value': 'Automated detection of email security provider',
                    'is_compliant': mx_detection['status'] == 'SUCCESS',
                    'details': mx_detection
                })
                
                print(f"✅ Completed DNS checks for domain: {domain}")
            
            # Summary
            total_domains = len(domains)
            total_checks = len(all_results)
            compliant_checks = sum(1 for result in all_results if result.get('is_compliant', False))
            
            print(f"\n=== DNS Check Summary ===")
            print(f"Domains checked: {total_domains}")
            print(f"Total DNS checks: {total_checks}")
            print(f"Compliant checks: {compliant_checks}/{total_checks}")
            print(f"Overall compliance rate: {(compliant_checks/total_checks)*100:.1f}%")
            
            return all_results
            
        except Exception as e:
            print(f"❌ Error during multi-domain DNS policy checks: {str(e)}")
            return [{
                'requirement_name': 'Multi-Domain DNS Configuration Check',
                'found': False,
                'status': f'ERROR - {str(e)}',
                'policy_type': 'dns',
                'domain': 'N/A',
                'current_value': None,
                'expected_value': 'DNS records should be checkable across all domains',
                'is_compliant': False
            }]
