
import json
import time
import os
import shutil
import streamlit as st
from pathlib import Path
from datetime import datetime
import pandas as pd

# Title and Config
st.set_page_config(page_title="🛡️ SecureAgent Live Dashboard", layout="wide", initial_sidebar_state="expanded")

# Paths
BASE_DIR = Path(__file__).parent.resolve()
DASHBOARD_DIR = BASE_DIR / "dashboard"
LOG_FILE = DASHBOARD_DIR / "security_events.jsonl"
SCREENSHOTS_DIR = DASHBOARD_DIR / "screenshots"

# Initialize Session State
if "confirm_delete" not in st.session_state:
    st.session_state.confirm_delete = False

# Sidebar
st.sidebar.title("🛡️ Zero-Trust Security")
page = st.sidebar.radio("Navigation", ["🔴 Live Feed", "📊 Profile & Reports"])

st.sidebar.markdown("---")
st.sidebar.header("Monitor Controls")

# Debugging (Temporary)
if LOG_FILE.exists():
    st.sidebar.caption(f"✅ Log file active")
else:
    st.sidebar.caption(f"❌ Log file missing")

auto_refresh = st.sidebar.checkbox("Auto-Refresh (2s)", value=True)

st.sidebar.markdown("---")
st.sidebar.subheader("🚫 Danger Zone")

if st.sidebar.button("⚠️ Clear Logs & Evidence"):
    st.session_state.confirm_delete = True

if st.session_state.confirm_delete:
    st.sidebar.warning("Do you really wanna clear logs and delete screenshots?")
    col_confirm1, col_confirm2 = st.sidebar.columns(2)
    if col_confirm1.button("Yes, Delete"):
        # Delete Logs
        if LOG_FILE.exists():
            os.remove(LOG_FILE)
        # Delete Screenshots
        if SCREENSHOTS_DIR.exists():
            try:
                shutil.rmtree(SCREENSHOTS_DIR)
                os.makedirs(SCREENSHOTS_DIR)
            except Exception as e:
                st.sidebar.error(f"Error deleting screenshots: {e}")
        
        st.session_state.confirm_delete = False
        st.sidebar.success("All data wiped.")
        time.sleep(1)
        st.rerun()
    
    if col_confirm2.button("Cancel"):
        st.session_state.confirm_delete = False
        st.rerun()

# Load Data
events = []
if LOG_FILE.exists():
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    events.append(json.loads(line))
    except Exception as e:
        st.error(f"Error reading logs: {e}")

# Helper to format timestamp
def get_formatted_time(timestamp):
    try:
        return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
    except:
        return ""

# Common Metrics Calculation
total_events = len(events)
injections_blocked = sum(1 for e in events if e.get('event_type') == 'INJECTION_ATTEMPT')
critical_threats = sum(1 for e in events if e.get('risk_level') == 'CRITICAL')
hostile_domains = len(set(e.get('url') for e in events if e.get('risk_level') in ['HIGH', 'CRITICAL']))

# --- PAGE: LIVE FEED ---
if page == "🔴 Live Feed":
    st.title("🛡️ Real-time Security Feed")
    
    # Metrics Row
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Events", total_events)
    col2.metric("Injections Blocked", injections_blocked, delta_color="normal")
    col3.metric("Critical Threats", critical_threats, delta_color="inverse")
    col4.metric("Hostile Domains", hostile_domains)

    st.divider()

    # Display Events (Latest First)
    for event in reversed(events):
        color = "gray"
        lvl = event.get('risk_level', 'SAFE')
        if lvl == 'CRITICAL': color = "red"
        elif lvl == 'HIGH': color = "orange"
        elif lvl == 'MEDIUM': color = "yellow"
        elif lvl == 'SAFE': color = "green"

        with st.container(border=True):
            cols = st.columns([2, 2, 5, 2])
            
            # Correct Date/Time
            timestamp_val = event.get('timestamp')
            display_time = get_formatted_time(timestamp_val) if timestamp_val else event.get('time_str', 'N/A')
            
            cols[0].caption(f"📅 {display_time}")
            cols[1].markdown(f"**:{color}[{event.get('event_type')}]**")
            cols[2].write(f"{event.get('details')} \n\n 🔗 `{event.get('url', 'N/A')}`")
            cols[3].caption(f"Action: **{event.get('action')}**")
            
            if event.get('screenshot'):
                try:
                    raw_path = event['screenshot']
                    filename = raw_path.replace('\\', '/').split('/')[-1]
                    local_path = SCREENSHOTS_DIR / filename
                    
                    if local_path.exists():
                        st.image(str(local_path), caption="Evidence Snapshot", width=400)
                except Exception:
                    pass

# --- PAGE: PROFILE & REPORTS ---
elif page == "📊 Profile & Reports":
    st.title("📊 Security Profile Analysis")
    
    if total_events == 0:
        st.info("No data available yet. Run the agent to generate traffic.")
    else:
        # Create DataFrame for easier analysis
        df = pd.DataFrame(events)
        if 'timestamp' in df.columns:
            df['datetime'] = pd.to_datetime(df['timestamp'], unit='s')
        
        # 1. Stats Overview
        st.header("📈 Activity Overview")
        
        # Stats Logic
        unique_sites = df['url'].nunique() if 'url' in df.columns else 0
        malicious_sites_count = df[df['risk_level'].isin(['HIGH', 'CRITICAL'])]['url'].nunique() if 'risk_level' in df.columns else 0
        blocked_actions_count = df[df['action'].isin(['BLOCKED', 'SANITIZED', 'WARNED'])]['url'].count() if 'action' in df.columns else 0
        
        m1, m2, m3 = st.columns(3)
        m1.metric("🌍 Unique Sites Visited", unique_sites)
        m2.metric("💀 Malicious Domains Identified", malicious_sites_count, delta_color="inverse")
        m3.metric("🛡️ Interventions (Blocks/Warnings)", blocked_actions_count)
        
        st.divider()

        # 2. Graphic Visualization
        g1, g2 = st.columns(2)
        
        with g1:
            st.subheader("Threat Severity Distribution")
            if 'risk_level' in df.columns:
                risk_counts = df['risk_level'].value_counts()
                st.bar_chart(risk_counts, color="#ff4b4b")
        
        with g2:
            st.subheader("Event Types")
            if 'event_type' in df.columns:
                type_counts = df['event_type'].value_counts()
                st.bar_chart(type_counts, horizontal=True)

        st.divider()

        # 3. Detailed Lists
        st.subheader("📝 Sites Identified as Malicious")
        if 'risk_level' in df.columns and 'url' in df.columns:
            malicious_df = df[df['risk_level'].isin(['HIGH', 'CRITICAL'])][['datetime', 'url', 'risk_level', 'details']].drop_duplicates(subset=['url'])
            if not malicious_df.empty:
                st.dataframe(malicious_df, use_container_width=True)
            else:
                st.success("No malicious sites detected so far security is clean.")

        st.subheader("🛡️ Blocked / Sanitized Actions")
        if 'action' in df.columns:
            blocked_df = df[df['action'].isin(['BLOCKED', 'SANITIZED'])][['datetime', 'event_type', 'url', 'details']]
            if not blocked_df.empty:
                st.dataframe(blocked_df, use_container_width=True)
            else:
                st.info("No active blocking actions recorded yet.")


if auto_refresh:
    time.sleep(2)
    st.rerun()
