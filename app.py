import streamlit as st
import json
import os
import requests
from datetime import datetime

# Configure clean, wide portal workspace layout
st.set_page_config(page_title="Unified CTI & Risk Management Platform", layout="wide", page_icon="🛡️")

# Top Header Branding Panel
st.title("🛡️ Enterprise Threat Intelligence & Risk Matrix Platform")
st.markdown("---")

# Helper function to load JSON threat feeds safely from our background scraper
def load_sector_feed(sector, branch):
    file_path = f"industry_feeds/{sector}/{branch}_cti.json"
    if os.path.exists(file_path):
        try:
            with open(file_path, "r") as f:
                return json.load(f)
        except Exception:
            return None
    return None

# ==========================================
# SIDEBAR CONTROL WORKSPACE
# ==========================================
st.sidebar.header("🕹️ Platform Controls")
app_mode = st.sidebar.radio("Navigate Application Modules:", ["Verticalized Threat Dashboard", "Tech Stack Risk Portal"])

# Static Master Vulnerability Library mapped to software types for the Risk Calculator
VULN_LIBRARY = {
    "Linux Ubuntu 22.04 LTS": {"cve": "CVE-2024-1086", "base_score": 7.8, "epss_prob": 0.64, "vector": "Local Privilege Escalation"},
    "Apache HTTP Server": {"cve": "CVE-2023-25690", "base_score": 9.8, "epss_prob": 0.82, "vector": "Remote Code Execution"},
    "Windows Server 2022": {"cve": "CVE-2024-21408", "base_score": 8.1, "epss_prob": 0.45, "vector": "Denial of Service Execution"},
    "WordPress CMS 6.5": {"cve": "CVE-2024-25600", "base_score": 8.8, "epss_prob": 0.73, "vector": "Bypass/Authentication Bypass"},
    "Log4j Core Java Module": {"cve": "CVE-2021-44228", "base_score": 10.0, "epss_prob": 0.97, "vector": "Full Infrastructure Compromise"}
}

# ==========================================
# MODULE 1: VERTICALIZED THREAT DASHBOARD
# ==========================================
if app_mode == "Verticalized Threat Dashboard":
    st.subheader("📊 Sector-Specific Real-Time Cyber Intelligence")
    st.write("Review active technical indicators and strategic vectors targeting specific business models.")
    
    # User selects target industry vertical
    selected_sector = st.selectbox("Select Target Industry Vertical:", ["healthcare", "finance", "manufacturing"])
    
    # Render layout columns
    col1, col2 = st.columns([1, 2])
    
    with col1:
        st.info(f"### Current Focus: {selected_sector.upper()} Sector")
        st.write("This intelligence dashboard filters live open-source parameters against industry infrastructure tracking keywords.")
        
        # Load Technical indicators (IP blocklists)
        tech_data = load_sector_feed(selected_sector, "technical")
        if tech_data and "indicators" in tech_data:
            st.error(f"🔴 Firewall Blocklist Nodes ({len(tech_data['indicators'])} Active)")
            # Display raw blocklist inside a scannable box
            ip_list = [item['value'] for item in tech_data['indicators']]
            st.code("\n".join(ip_list[:15]), language="text")
            st.caption("Subscribe your perimeter firewalls directly to this raw JSON layout path.")
        else:
            st.success("✅ No industry-specific perimeter blocklist nodes flagged.")

    with col2:
        # Load other operational/strategic files
        op_data = load_sector_feed(selected_sector, "operational")
        tac_data = load_sector_feed(selected_sector, "tactical")
        strat_data = load_sector_feed(selected_sector, "strategic")
        
        tab1, tab2, tab3 = st.tabs(["🔧 Operational CTI (Patches)", "🎯 Tactical CTI (TTPs)", "📈 Strategic CTI (Trends)"])
        
        with tab1:
            st.write("#### Urgent Remediation Directives")
            if op_data and "intel_records" in op_data:
                for record in op_data["intel_records"]:
                    if "vulnerable_asset" in record:
                        st.markdown(f"🔹 **Asset Exposed:** `{record['vulnerable_asset']}` ({record['indicator_id']})")
                        st.markdown(f"⚠️ **Action Required:** {record['mitigation_directive']}")
                        st.caption(f"Target Patch Deadline: {record['remediation_timeline_deadline']}")
                        st.markdown("---")
                    else:
                        st.write(record.get("status", "No entry metrics loaded."))
            else:
                st.write("No operational profiles compiled for this sector over the past execution sequence.")

        with tab2:
            st.write("#### Adversary Hunting & Behavioral Tracking")
            if tac_data and "intel_records" in tac_data:
                for record in tac_data["intel_records"]:
                    if "threat_actor_activity" in record:
                        st.warning(f"🎭 **Observed Activity:** {record['threat_actor_activity']}")
                        st.write(f"🔍 **Detection Hunting Metric:** {record['detection_logic_focus']}")
                        st.markdown("---")
                    else:
                        st.write(record.get("status", "No hunting logic compiled."))
            else:
                st.write("No tactical tracking metrics found.")

        with tab3:
            st.write("#### Strategic Threat Assessment for Decisions")
            if strat_data and "intel_records" in strat_data:
                for record in strat_data["intel_records"]:
                    if "executive_alert" in record:
                        st.markdown(f"💼 **Executive Brief:** {record['executive_alert']}")
                        st.markdown(f"💥 **Business Impact Assessment:** {record['operational_impact']}")
                        st.markdown(f"📌 **Governance Recommendation:** {record['governance_priority']}")
                        st.markdown("---")
                    else:
                        st.write(record.get("status", "No executive trends logged."))
            else:
                st.write("No strategic metrics mapped.")

# ==========================================
# MODULE 2: TECH STACK RISK PORTAL
# ==========================================
elif app_mode == "Tech Stack Risk Portal":
    st.subheader("🎛️ Organizational Tech Profile & Threat Clock Calculator")
    st.write("Populate your network infrastructure profile below to evaluate your compromise probability window.")
    
    # Dropdown interactive stack selector
    user_stack = st.multiselect(
        "Select the infrastructure components running inside your operational environment:",
        options=list(VULN_LIBRARY.keys())
    )
    
    if user_stack:
        st.markdown("---")
        st.write("### 🧮 Compounding Threat Risk Metrics")
        
        highest_severity = 0.0
        compounding_exploit_prob = 1.0 # Mathematical calculation base
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("#### Exposed Vulnerability Vector Matrix")
            for tech in user_stack:
                meta = VULN_LIBRARY[tech]
                st.error(f"⚠️ **{tech}** $\rightarrow$ Tracking Component Flaw: **{meta['cve']}**")
                st.write(f"• Attack Result Profile: `{meta['vector']}`")
                st.write(f"• Severity Base Score: `{meta['base_score']}/10` | Active Exploitation Likelihood: `{meta['epss_prob']*100:.1f}%`")
                st.markdown("---")
                
                # Math calculation models
                if meta['base_score'] > highest_severity:
                    highest_severity = meta['base_score']
                # Calculate compounding probability that at least one vulnerability gets exploited
                compounding_exploit_prob *= (1.0 - meta['epss_prob'])
                
            final_compromise_probability = (1.0 - compounding_exploit_prob) * 100
            
        with col2:
            st.write("#### System Compromise Timeline Projections")
            
            # Metric gauges
            st.metric(label="Peak Exposure Severity Index", value=f"{highest_severity} / 10")
            st.metric(label="Compounding 30-Day Exploitation Likelihood", value=f"{final_compromise_probability:.2f}%")
            
            # Risk Tier Analysis and Action Windows
            if final_compromise_probability >= 75.0:
                st.markdown("🚨 **COMPROMISE TIMELINE PROJECTION: EXTREMELY URGENT**")
                st.error("Your environment houses compounding, high-probability exploitative entry targets. Expect malicious automated scanning probing to locate these points within **24 to 72 hours**.")
            elif final_compromise_probability >= 40.0:
                st.markdown("⚠️ **COMPROMISE TIMELINE PROJECTION: HIGH PROBABILITY**")
                st.warning("Threat actors are actively leveraging vectors matching your selections. Breach window vulnerability targets exploitation likely within **1 to 3 weeks** if unpatched.")
            else:
                st.markdown("🟢 **COMPROMISE TIMELINE PROJECTION: MANAGEABLE RISK**")
                st.success("Exposure paths remain inside manageable standard tracking thresholds. Execute normal patch verification inside regular monthly maintenance cycles.")
                
    else:
        st.info("Select items from the multi-select box above to spin up the threat risk modeling matrix.")

  
