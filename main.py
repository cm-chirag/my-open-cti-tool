import requests
import json
from datetime import datetime

# A highly reliable, open-source feed of known malicious IP addresses
FEED_URL = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
DATA_FILE = "data/indicators.json"

def fetch_and_process_intel():
    print("Fetching latest threat intelligence from Emerging Threats...")
    
    # 1. Grab the plain text IP list
    response = requests.get(FEED_URL)
    if response.status_code != 200:
        print(f"Failed to fetch data. Status code: {response.status_code}")
        return
        
    # 2. Clean up the text data (split by lines)
    raw_lines = response.text.splitlines()
    
    cleaned_intel = {
        "last_updated": datetime.utcnow().isoformat() + "Z",
        "malicious_ips": []
    }
    
    # 3. Filter out comments and blank lines, then grab the top 50 malicious IPs
    for line in raw_lines:
        line = line.strip()
        # Skip empty lines or lines starting with '#' (comments)
        if not line or line.startswith('#'):
            continue
            
        # If it looks like a valid IP entry, add it to our list
        ip_data = {
            "ip_address": line,
            "threat_type": "Compromised Host / Botnet",
            "confidence": "High"
        }
        cleaned_intel["malicious_ips"].append(ip_data)
        
        # Stop once we have 50 items so our file stays lightweight
        if len(cleaned_intel["malicious_ips"]) >= 50:
            break
        
    # 4. Save the populated list to our filing cabinet
    with open(DATA_FILE, "w") as f:
        json.dump(cleaned_intel, f, indent=4)
        
    print(f"Successfully saved {len(cleaned_intel['malicious_ips'])} active threat IPs to {DATA_FILE}!")

if __name__ == "__main__":
    fetch_and_process_intel()
