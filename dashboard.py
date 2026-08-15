import streamlit as st
import plotly.express as px
import pandas as pd

from src.parser import parse_logs
from src.detector import detect_attacks
from src.threat_score import calculate_threat_score

# Page Configuration
st.set_page_config(
    page_title="AI Linux Log Analyzer",
    page_icon="🛡️",
    layout="wide"
)

# Title
st.title("🛡️ AI Linux Log Analyzer Dashboard")
st.markdown("---")

# Load Data
logs = parse_logs("data/auth.log")
results = detect_attacks(logs)
threat_score = calculate_threat_score(results)

# Metrics
total_logs = len(logs)

high_threats = (
    len(results["brute_force"]) +
    len(results["root_attempts"]) +
    len(results["sudo_abuse"]) +
    len(results["privilege_escalation"])
)

medium_threats = len(results["invalid_users"])

# Dashboard Cards
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("📄 Total Logs", total_logs)

with col2:
    st.metric("⚠️ Threat Score", f"{threat_score}/100")

with col3:
    st.metric("🔴 High Threats", high_threats)

with col4:
    st.metric("🟡 Medium Threats", medium_threats)

st.markdown("---")

# Attack Distribution Chart
st.subheader("📊 Attack Distribution")

attack_data = pd.DataFrame({
    "Attack Type": [
        "Brute Force",
        "Invalid Users",
        "Root Login",
        "Sudo Abuse",
        "Privilege Escalation"
    ],
    "Count": [
        len(results["brute_force"]),
        len(results["invalid_users"]),
        len(results["root_attempts"]),
        len(results["sudo_abuse"]),
        len(results["privilege_escalation"])
    ]
})

fig = px.pie(
    attack_data,
    names="Attack Type",
    values="Count",
    title="Attack Distribution"
)

st.plotly_chart(fig, use_container_width=True)

st.markdown("---")

# Threat Summary
st.subheader("🚨 Threat Summary")

st.write(f"Total Logs Parsed: {total_logs}")
st.write(f"Threat Score: {threat_score}/100")
st.write(f"High Severity Threats: {high_threats}")
st.write(f"Medium Severity Threats: {medium_threats}")

st.markdown("---")

# Recent Log Entries
st.subheader("📜 Recent Log Entries")

if logs:
    log_df = pd.DataFrame(logs)
    st.dataframe(log_df, use_container_width=True)
else:
    st.warning("No logs found.")