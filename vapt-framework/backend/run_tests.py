"""
Simple test runner - Run this from the backend folder.
"""

from modules.recon import ReconOrchestrator
from modules.recon.data_normalizer import ReconResult, DNSRecord, WhoisInfo, SubdomainInfo

def test_imports():
    """Test that all imports work."""
    print("SUCCESS: Imports successful")
    print("  - ReconOrchestrator: " + str(ReconOrchestrator))
    print("  - ReconResult: " + str(ReconResult))
    print("  - DNSRecord: " + str(DNSRecord))
    print("  - WhoisInfo: " + str(WhoisInfo))
    print("  - SubdomainInfo: " + str(SubdomainInfo))
    return True

def test_basic():
    """Test basic data structures."""
    print("")
    print("--- Testing Data Structures ---")
    
    # Test DNSRecord
    record = DNSRecord(record_type="A", value="192.168.1.1", ttl=300)
    print("DNSRecord created: " + str(record.to_dict()))
    
    # Test WhoisInfo
    whois = WhoisInfo(registrar="Test Registrar", name_servers=["ns1.test.com"])
    print("WhoisInfo created: " + str(whois.to_dict()))
    
    # Test ReconResult
    result = ReconResult(target="test.com", target_type="domain")
    result.dns_records = {"A": ["192.168.1.1"]}
    result.resolved_ips = ["192.168.1.1"]
    result.modules_executed = ["dns", "whois"]
    
    print("ReconResult target: " + result.target)
    print("ReconResult valid: " + str(result.validate()))
    
    return True

def test_recon():
    """Test basic reconnaissance on example.com."""
    print("")
    print("--- Testing Reconnaissance on example.com ---")
    
    try:
        orchestrator = ReconOrchestrator()
        result = orchestrator.run_sync("example.com")
        
        print("Target: " + str(result['target']))
        print("Type: " + str(result['target_type']))
        print("Modules: " + str(result['modules_executed']))
        print("Errors: " + str(len(result['errors'])))
        
        if result['recon_data']['resolved_ips']:
            print("Resolved IPs: " + str(result['recon_data']['resolved_ips']))
        
        if result['recon_data']['subdomains']:
            subdomains = result['recon_data']['subdomains']
            print("Subdomains found: " + str(len(subdomains)))
            for sub in subdomains[:5]:
                print("  - " + sub)
        
        if result['recon_data']['whois']:
            whois_data = result['recon_data']['whois']
            print("WHOIS registrar: " + str(whois_data.get('registrar', 'N/A')))
        
        return True
        
    except Exception as e:
        print("ERROR: " + str(e))
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("=" * 60)
    print("VAPT Framework - Reconnaissance Module Test")
    print("=" * 60)
    
    test_imports()
    test_basic()
    test_recon()
    
    print("")
    print("=" * 60)
    print("Testing Complete")
    print("=" * 60)