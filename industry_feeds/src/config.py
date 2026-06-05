# Master configuration mapping threat keywords to target industries
SECTOR_KEYWORDS = {
    "finance": [
        "bank", "swift", "atm", "crypto", "payment", "fintech", "ransomware", 
        "lazarus", "carbanak", "revil", "pos-malware", "credit-card"
    ],
    "healthcare": [
        "hospital", "medical", "health", "pharma", "patient", "clinic", 
        "epic", "cerner", "emr", "clop", "biomedical", "telehealth"
    ],
    "manufacturing": [
        "ics", "scada", "ot", "factory", "supply-chain", "plc", "firmware", 
        "modbus", "siemens", "lockbit", "industrial", "cnc-machine"
    ]
}

# Free Public Real-Time Threat Feeds 
FEEDS = {
    # Technical CTI: Live Compromised IP reputation database from Proofpoint Emerging Threats
    "technical": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    
    # Operational CTI: Live actively exploited security vulnerabilities cataloged by US CISA
    "operational": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
}
