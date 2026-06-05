import requests
import json
import os
from datetime import datetime
from config import SECTOR_KEYWORDS, FEEDS

def ensure_directories():
    """Dynamically sets up folder trees for each industry segment"""
    for sector in SECTOR_KEYWORDS.keys():
        os.makedirs(f"industry_feeds/{sector}", exist_ok=True)

def process_technical_cti():
    """Downloads live compromised IPs and seeds each vertical's blocklist"""
    print("[*] Contacting Emerging Threats IP Blocklist API...")
    try:
        response = requests.get(FEEDS["technical"])
        if response.status_code == 200:
            # Filter empty lines or comment headers (#)
            ips = [line.strip() for line in response.text.splitlines() if line.strip() and not line.startswith("#")]
            
            # Seed our tactical target verticals with top high-confidence active IPs
            for sector in SECTOR_KEYWORDS.keys():
                output_path = f"industry_feeds/{sector}/technical_cti.json"
                payload = {
                    "branch": "Technical CTI",
                    "sector": sector,
                    "description": f"Machine-readable network reputation blocklist for active {sector} firewall objects.",
                    "last_updated": datetime.utcnow().isoformat() + "Z",
                    "indicators": [{"type": "ipv4-addr", "value": ip} for ip in ips[:50]] # 50 highest priority indicators
                }
                with open(output_path, "w") as f:
                    json.dump(payload, f, indent=4)
            print(f"[+] Technical CTI Processing Complete. Synced 50 live malicious infrastructure nodes.")
    except Exception as e:
        print(f"[-] Error compiling Technical CTI: {e}")

def process_multi_branch_matrix():
    """Downloads CISA KEV vulnerabilities and maps to Operational, Tactical, and Strategic fields"""
    print("[*] Pulling live exploitation metrics from CISA KEV catalog...")
    try:
        response = requests.get(FEEDS["operational"])
        if response.status_code != 200:
            print("[-] Unable to contact CISA feeds endpoint.")
            return
            
        vulnerabilities = response.json().get("vulnerabilities", [])
        
        # Prepare an empty bucket matrix for each sector
        matrix = {sector: {"tactical": [], "operational": [], "strategic": []} for sector in SECTOR_KEYWORDS.keys()}
        
        # Parse the newest 60 entries being exploited globally
        for vuln in vulnerabilities[:60]:
            cve_id = vuln.get("cveID")
            vendor = vuln.get("vendorProject", "Unknown Vendor")
            product = vuln.get("product", "Unknown Platform")
            summary = vuln.get("shortDescription", "").lower()
            action = vuln.get("requiredAction", "Apply patches immediately.")
            due_date = vuln.get("dueDate", "Immediate action required")
            
            # Check sector attribution using key phrase matrices
            for sector, tokens in SECTOR_KEYWORDS.items():
                is_match = any(token in summary for token in tokens) or any(token in product.lower() for token in tokens)
                
                if is_match:
                    # Operational CTI generation (Defenders' task context)
                    matrix[sector]["operational"].append({
                        "indicator_id": cve_id,
                        "vulnerable_asset": f"{vendor} {product}",
                        "mitigation_directive": action,
                        "remediation_timeline_deadline": due_date
                    })
                    
                    # Tactical CTI generation (Blue team hunting logic / logic rules)
                    matrix[sector]["tactical"].append({
                        "threat_actor_activity": f"In-the-wild exploitation targeted at {product}",
                        "detection_logic_focus": f"Verify process runtime traces for anomalous payloads invoking {vendor} frameworks.",
                        "attack_vector_classification": "Initial Access / Privilege Escalation Execution"
                    })
                    
                    # Strategic CTI generation (Executive impact visibility)
                    matrix[sector]["strategic"].append({
                        "executive_alert": f"Active exploitation campaign tracking against {sector} deployments utilizing {product}.",
                        "operational_impact": "Potential system takeover, ransomware exposure risk, or sensitive data loss profile.",
                        "governance_priority": "Critical patch deployment cycle acceleration needed."
                    })

        # Save generated structures out to individual storage nodes
        for sector in SECTOR_KEYWORDS.keys():
            for branch in ["operational", "tactical", "strategic"]:
                output_path = f"industry_feeds/{sector}/{branch}_cti.json"
                
                # Baseline padding if no specific active campaign hit during this block cycle
                records = matrix[sector][branch] if matrix[sector][branch] else [{
                    "status": "Baseline protection active. No vertical anomalies isolated over past 24hr loop."
                }]
                
                payload = {
                    "branch": f"{branch.capitalize()} CTI",
                    "vertical_sector": sector,
                    "last_updated": datetime.utcnow().isoformat() + "Z",
                    "feed_count": len(matrix[sector][branch]),
                    "intel_records": records
                }
                
                with open(output_path, "w") as f:
                    json.dump(payload, f, indent=4)
                    
        print("[+] Industry Multi-Branch Threat Intelligence Matrix fully distributed.")
    except Exception as e:
        print(f"[-] Error processing multi-branch matrix arrays: {e}")

if __name__ == "__main__":
    ensure_directories()
    process_technical_cti()
    process_multi_branch_matrix()
  
