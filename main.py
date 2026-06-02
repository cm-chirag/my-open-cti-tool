import requests
import json
import os
from datetime import datetime

# 1. The URL of the free threat intelligence feed (Top 300 recent malicious links)
FEED_URL = "https://urlhaus.abuse.ch/downloads/json/recent/"
DATA_FILE = "data/indicators.json"

def fetch_and_process_intel():
    print("Fetching latest threat intelligence...")
    
    # 2. Go to the internet and grab the data
    response = requests.get(FEED_URL)
    if response.status_code != 200:
        print("Failed to fetch data from the open-source feed.")
        return
        
    raw_data = response.json()
    
    # 3. Create a clean structure for our storage
    cleaned_intel = {
        "last_updated": datetime.utcnow().isoformat() + "Z",
        "malicious_urls": []
    }
    
    # 4. Loop through the raw data and pull out only what we care about
    # URLhaus structures their JSON with an "urls" key containing a list
    for entry in raw_data.get("urls", [])[:50]: # Let's just grab the top 50 newest threats
        url_data = {
            "id": entry.get("id"),
            "url": entry.get("url"),
            "status": entry.get("url_status"),
            "threat_type": entry.get("threat"),
            "reported_at": entry.get("date_added")
        }
        cleaned_intel["malicious_urls"].append(url_data)
        
    # 5. Save the clean data back into our filing cabinet folder
    with open(DATA_FILE, "w") as f:
        json.dump(cleaned_intel, f, indent=4)
        
    print(f"Successfully saved {len(cleaned_intel['malicious_urls'])} active threats to {DATA_FILE}!")

if __name__ == "__main__":
    fetch_and_process_intel()
  
