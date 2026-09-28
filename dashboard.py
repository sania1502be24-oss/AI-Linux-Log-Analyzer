import streamlit as st
import plotly.express as px
import pandas as pd

from src.parser import parse_logs
from src.detector import detect_attacks
from src.threat_score import calculate_threat_score
from src.pdf_report import generate_pdf_report
from src.incident_investigator import build_incidents


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="AI Linux Log Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# STYLING AND HEADER
# ============================================================

st.markdown(
    """
    <style>
        .main-title {
            font-size: 2.4rem;
            font-weight: 700;
            margin-bottom: 0.2rem;
        }
        .subtitle {
            color: #777;
            font-size: 1rem;
            margin-bottom: 1.5rem;
        }
        div[data-testid="stMetric"] {
            border: 1px solid rgba(128, 128, 128, 0.25);
            padding: 12px;
            border-radius: 10px;
        }
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    '<div class="main-title">🛡️ AI Linux Log Analyzer</div>',
    unsafe_allow_html=True,
)
st.markdown(
    '<div class="subtitle">Security monitoring and threat detection dashboard</div>',
    unsafe_allow_html=True,
)


# ============================================================
# SIDEBAR
# ============================================================

st.sidebar.title("⚙️ Dashboard Controls")
severity_filter = st.sidebar.selectbox(
    "Alert Severity Filter",
    ["All", "CRITICAL", "HIGH", "MEDIUM"],
)
search_query = st.sidebar.text_input("🔎 Search Alerts", "")

st.sidebar.markdown("---")
st.sidebar.markdown(
    """
    ### 📊 Data Source
    **Log file:** `data/auth.log`

    This dashboard analyzes Linux authentication logs for suspicious
    activity. Findings are indicators for investigation, not proof of compromise.
    """
)


# ============================================================
# LOAD LOG DATA
# ============================================================

try:
    logs = parse_logs("data/auth.log")
except Exception as error:
    st.error(f"Unable to parse log file: {error}")
    logs = []


# ============================================================
# DETECT SECURITY EVENTS
# ============================================================

try:
    results = detect_attacks(logs)
except Exception as error:
    st.error(f"Unable to detect security events: {error}")
    results = {
        "brute_force": {},
        "invalid_users": [],
        "root_attempts": [],
        "sudo_abuse": [],
        "privilege_escalation": [],
    }

brute_force = results.get("brute_force", {})
invalid_users = results.get("invalid_users", [])
root_attempts = results.get("root_attempts", [])
sudo_abuse = results.get("sudo_abuse", [])
privilege_escalation = results.get("privilege_escalation", [])


# ============================================================
# DAY 20 - INCIDENT INVESTIGATION
# ============================================================

try:
    incidents = build_incidents(logs, results)
except Exception as error:
    st.error(f"Incident investigation could not be completed: {error}")
    incidents = []


# ============================================================
# THREAT SCORE AND RISK LEVEL
# ============================================================

try:
    threat_score = calculate_threat_score(results)
except Exception:
    threat_score = 0

if threat_score >= 80:
    risk_level = "CRITICAL"
elif threat_score >= 60:
    risk_level = "HIGH"
elif threat_score >= 30:
    risk_level = "MEDIUM"
else:
    risk_level = "LOW"

brute_force_count = len(brute_force)
invalid_user_count = len(invalid_users)
root_count = len(root_attempts)
sudo_count = len(sudo_abuse)
privilege_count = len(privilege_escalation)

total_attacks = (
    brute_force_count
    + invalid_user_count
    + root_count
    + sudo_count
    + privilege_count
)

attacker_ips = [
    {
        "IP Address": ip,
        "Failed Attempts": count,
        "Risk Level": "HIGH" if count >= 5 else "MEDIUM",
    }
    for ip, count in brute_force.items()
]

if risk_level == "CRITICAL":
    security_status = "🚨 CRITICAL THREATS DETECTED"
elif risk_level == "HIGH":
    security_status = "🔴 HIGH RISK ACTIVITY"
elif risk_level == "MEDIUM":
    security_status = "🟠 SUSPICIOUS ACTIVITY"
else:
    security_status = "🟢 SYSTEM MONITORING"


# ============================================================
# SECURITY OVERVIEW
# ============================================================

st.markdown("---")
st.markdown("### 🛡️ Security Overview")

metric1, metric2, metric3, metric4, metric5 = st.columns(5)
metric1.metric("Total Logs", len(logs))
metric2.metric("Total Attacks", total_attacks)
metric3.metric("Threat Score", f"{threat_score}/100")
metric4.metric("Attacker IPs", len(attacker_ips))
metric5.metric("Risk Level", risk_level)

st.info(f"Security Status: {security_status}")


# ============================================================
# ATTACK STATISTICS
# ============================================================

st.markdown("---")
st.markdown("### 📊 Attack Statistics")

attack_stats = pd.DataFrame(
    {
        "Attack Type": [
            "Brute Force",
            "Invalid User",
            "Root Login",
            "Sudo Abuse",
            "Privilege Escalation",
        ],
        "Count": [
            brute_force_count,
            invalid_user_count,
            root_count,
            sudo_count,
            privilege_count,
        ],
    }
)

chart_col1, chart_col2 = st.columns(2)
with chart_col1:
    fig_pie = px.pie(
        attack_stats,
        names="Attack Type",
        values="Count",
        title="Attack Distribution",
    )
    st.plotly_chart(fig_pie, width="stretch")

with chart_col2:
    fig_bar = px.bar(
        attack_stats,
        x="Count",
        y="Attack Type",
        orientation="h",
        title="Attack Frequency",
    )
    st.plotly_chart(fig_bar, width="stretch")


# ============================================================
# ATTACK INTELLIGENCE AND RISK ASSESSMENT
# ============================================================

st.markdown("---")
st.markdown("### 🎯 Attack Intelligence")

intel_col1, intel_col2, intel_col3 = st.columns(3)
intel_col1.metric("Brute Force Sources", brute_force_count)
intel_col2.metric("Privilege Escalation Events", privilege_count)
intel_col3.metric("Sudo Abuse Events", sudo_count)

st.markdown("---")
st.markdown("### ⚠️ Risk Assessment")

if threat_score >= 80:
    st.error(
        "Critical risk score. Investigate authentication and privilege-related "
        "activity promptly."
    )
elif threat_score >= 60:
    st.warning(
        "High risk score. Review suspicious authentication and privilege events."
    )
elif threat_score >= 30:
    st.warning(
        "Medium risk score. Continue monitoring and investigate suspicious events."
    )
else:
    st.success("No significant high-risk activity was detected by the current rules.")


# ============================================================
# SOC ANALYST FOCUS
# ============================================================

st.markdown("---")
st.markdown("### 🧑‍💻 SOC Analyst Focus")

focus_items = []
if brute_force:
    focus_items.append("Investigate repeated failed login attempts.")
if invalid_users:
    focus_items.append("Review invalid username authentication attempts.")
if root_attempts:
    focus_items.append("Verify whether root account login activity was authorized.")
if sudo_abuse:
    focus_items.append("Audit privileged command execution.")
if privilege_escalation:
    focus_items.append("Investigate privilege escalation indicators.")
if not focus_items:
    focus_items.append("Continue routine security monitoring.")

for item in focus_items:
    st.write(f"• {item}")


# ============================================================
# SECURITY ALERTS
# ============================================================

st.markdown("---")
st.markdown("### 🚨 Security Alerts")

alerts = []

for ip, count in brute_force.items():
    alerts.append(
        {
            "Severity": "HIGH",
            "Type": "Brute Force",
            "Source": ip,
            "Message": f"{count} failed login attempts detected",
        }
    )

for attack in invalid_users:
    alerts.append(
        {
            "Severity": "MEDIUM",
            "Type": "Invalid User",
            "Source": "",
            "Message": str(attack),
        }
    )

for attack in root_attempts:
    alerts.append(
        {
            "Severity": "HIGH",
            "Type": "Root Login",
            "Source": "",
            "Message": str(attack),
        }
    )

for attack in sudo_abuse:
    alerts.append(
        {
            "Severity": "HIGH",
            "Type": "Sudo Abuse",
            "Source": "",
            "Message": str(attack),
        }
    )

for attack in privilege_escalation:
    alerts.append(
        {
            "Severity": "CRITICAL",
            "Type": "Privilege Escalation",
            "Source": "",
            "Message": str(attack),
        }
    )

alerts_df = pd.DataFrame(
    alerts,
    columns=["Severity", "Type", "Source", "Message"],
)

filtered_alerts = alerts_df.copy()
if not filtered_alerts.empty:
    if severity_filter != "All":
        filtered_alerts = filtered_alerts[
            filtered_alerts["Severity"] == severity_filter
        ]

    if search_query.strip():
        search_text = search_query.strip().lower()
        searchable = filtered_alerts[["Message", "Source", "Type"]].astype(str)
        matches = searchable.apply(
            lambda column: column.str.lower().str.contains(
                search_text, regex=False
            )
        ).any(axis=1)
        filtered_alerts = filtered_alerts[matches]

st.metric("Displayed Alerts", len(filtered_alerts))

if not filtered_alerts.empty:
    st.dataframe(filtered_alerts, width="stretch", hide_index=True)
    st.download_button(
        label="📥 Download Filtered Alerts as CSV",
        data=filtered_alerts.to_csv(index=False).encode("utf-8"),
        file_name="security_alerts.csv",
        mime="text/csv",
    )

    severity_counts = (
        filtered_alerts["Severity"].value_counts().rename_axis("Severity")
        .reset_index(name="Count")
    )
    fig_severity = px.bar(
        severity_counts,
        x="Severity",
        y="Count",
        title="Security Alerts by Severity",
    )
    st.plotly_chart(fig_severity, width="stretch")
else:
    st.success("🟢 No security alerts match the selected filters.")


# ============================================================
# DAY 20 - SECURITY INCIDENT INVESTIGATION PANEL
# ============================================================

st.markdown("---")
st.markdown("## 🕵️ Security Incident Investigation")
st.caption(
    "Incidents are grouped from matching log indicators. Severity is rule-based "
    "and should be validated by an analyst."
)

if incidents:
    incident_rows = []
    for incident in incidents:
        incident_rows.append(
            {
                "Incident ID": incident.get("Incident ID", "N/A"),
                "Severity": incident.get("Severity", "UNKNOWN"),
                "Source": incident.get("Source", "Unknown"),
                "Event Types": incident.get("Event Types", ""),
                "Event Count": incident.get("Event Count", 0),
                "First Seen": incident.get("First Seen", "Unknown"),
                "Last Seen": incident.get("Last Seen", "Unknown"),
            }
        )

    incidents_df = pd.DataFrame(incident_rows)

    critical_count = sum(
        incident.get("Severity") == "CRITICAL" for incident in incidents
    )
    high_count = sum(
        incident.get("Severity") == "HIGH" for incident in incidents
    )
    medium_count = sum(
        incident.get("Severity") == "MEDIUM" for incident in incidents
    )
    low_count = sum(
        incident.get("Severity") == "LOW" for incident in incidents
    )

    inc1, inc2, inc3, inc4, inc5 = st.columns(5)
    inc1.metric("Total Incidents", len(incidents))
    inc2.metric("Critical", critical_count)
    inc3.metric("High", high_count)
    inc4.metric("Medium", medium_count)
    inc5.metric("Low", low_count)

    incident_filter = st.selectbox(
        "Filter incidents by severity",
        ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
        key="incident_severity_filter",
    )

    visible_incidents_df = incidents_df.copy()
    if incident_filter != "All":
        visible_incidents_df = visible_incidents_df[
            visible_incidents_df["Severity"] == incident_filter
        ]

    st.dataframe(
        visible_incidents_df,
        width="stretch",
        hide_index=True,
    )

    st.download_button(
        label="📥 Export Incident Summaries as CSV",
        data=incidents_df.to_csv(index=False).encode("utf-8"),
        file_name="security_incidents.csv",
        mime="text/csv",
        key="incident_csv_download",
    )

    incident_options = {
        f'{item.get("Incident ID", "N/A")} | '
        f'{item.get("Severity", "UNKNOWN")} | '
        f'{item.get("Source", "Unknown")} | '
        f'{item.get("Event Count", 0)} events': index
        for index, item in enumerate(incidents)
    }

    selected_incident_label = st.selectbox(
        "Select an incident to investigate",
        list(incident_options.keys()),
        key="selected_incident",
    )
    selected_incident = incidents[incident_options[selected_incident_label]]

    st.markdown("### 🔎 Incident Details")
    detail1, detail2, detail3 = st.columns(3)
    detail1.metric("Incident ID", selected_incident.get("Incident ID", "N/A"))
    detail2.metric("Severity", selected_incident.get("Severity", "UNKNOWN"))
    detail3.metric("Source", selected_incident.get("Source", "Unknown"))

    st.write("**Event types:**", selected_incident.get("Event Types", "N/A"))
    st.write("**First seen:**", selected_incident.get("First Seen", "Unknown"))
    st.write("**Last seen:**", selected_incident.get("Last Seen", "Unknown"))
    st.write("**Related events:**", selected_incident.get("Event Count", 0))

    st.markdown("### 🧾 Evidence Timeline")
    evidence = selected_incident.get("Evidence", [])
    if evidence:
        evidence_df = pd.DataFrame(evidence)
        st.dataframe(evidence_df, width="stretch", hide_index=True)
        st.download_button(
            label="Download Selected Incident Evidence as CSV",
            data=evidence_df.to_csv(index=False).encode("utf-8"),
            file_name=f'{selected_incident.get("Incident ID", "incident")}_evidence.csv',
            mime="text/csv",
            key="incident_evidence_download",
        )
    else:
        st.info("No log evidence was attached to this incident.")

    st.markdown("### ✅ Suggested Investigation Steps")
    recommendations = selected_incident.get("Recommendations", [])
    if recommendations:
        for recommendation in recommendations:
            st.write(f"• {recommendation}")
    else:
        st.info("No recommendations are available for this incident.")
else:
    st.info(
        "No investigation incidents were generated from the current log entries. "
        "Check that data/auth.log contains supported authentication events."
    )


# ============================================================
# THREAT INTELLIGENCE
# ============================================================

st.markdown("---")
st.markdown("### 🌐 Threat Intelligence")

if attacker_ips:
    intelligence_df = pd.DataFrame(attacker_ips)
    st.dataframe(intelligence_df, width="stretch", hide_index=True)

    fig_attackers = px.bar(
        intelligence_df,
        x="IP Address",
        y="Failed Attempts",
        title="Brute-Force Sources by Failed Attempts",
    )
    st.plotly_chart(fig_attackers, width="stretch")
else:
    st.info("No brute-force source IPs identified by the current detection rules.")


# ============================================================
# THREAT ACTIVITY TIMELINE
# ============================================================

st.markdown("---")
st.markdown("### 🕒 Threat Activity Timeline")

timeline_data = []
for log in logs:
    if isinstance(log, dict):
        timestamp = log.get("timestamp") or log.get("time") or log.get("date")
        message = log.get("message") or log.get("raw") or str(log)
        if timestamp:
            timeline_data.append({"timestamp": timestamp, "message": message})

if timeline_data:
    timeline_df = pd.DataFrame(timeline_data)
    timeline_df["timestamp"] = pd.to_datetime(
        timeline_df["timestamp"], format="mixed", errors="coerce"
    )
    timeline_df = timeline_df.dropna(subset=["timestamp"])

    if not timeline_df.empty:
        timeline_counts = (
            timeline_df.set_index("timestamp")
            .resample("h")
            .size()
            .reset_index(name="Events")
        )
        fig_timeline = px.line(
            timeline_counts,
            x="timestamp",
            y="Events",
            markers=True,
            title="Log Events Over Time",
        )
        st.plotly_chart(fig_timeline, width="stretch")
    else:
        st.info("No valid timestamps were available for the timeline.")
else:
    st.info("Timestamp field not available in the parsed logs.")


# ============================================================
# IP INVESTIGATION
# ============================================================

st.markdown("---")
st.markdown("### 🔎 IP Investigation")

if attacker_ips:
    investigation_df = pd.DataFrame(attacker_ips)
    selected_ip = st.selectbox(
        "Select an IP address to investigate",
        investigation_df["IP Address"].tolist(),
        key="selected_attacker_ip",
    )
    selected_data = investigation_df[
        investigation_df["IP Address"] == selected_ip
    ].iloc[0]

    ip_col1, ip_col2, ip_col3 = st.columns(3)
    ip_col1.metric("IP Address", selected_ip)
    ip_col2.metric("Failed Attempts", int(selected_data["Failed Attempts"]))
    ip_col3.metric("Risk Level", selected_data["Risk Level"])

    st.markdown("#### Related Alerts")
    ip_alerts = alerts_df[alerts_df["Source"] == selected_ip]
    if not ip_alerts.empty:
        st.dataframe(ip_alerts, width="stretch", hide_index=True)
    else:
        st.info("No additional alerts were associated with this IP.")
else:
    st.info("No brute-force attacker IPs are available for investigation.")


# ============================================================
# RECENT LOG ENTRIES
# ============================================================

st.markdown("---")
st.markdown("### 📜 Recent Log Entries")

if logs:
    log_df = pd.DataFrame(logs)
    st.dataframe(log_df.tail(100), width="stretch", hide_index=True)
    st.caption("Showing up to the latest 100 parsed log entries.")
else:
    st.warning("No logs found.")


# ============================================================
# SECURITY REPORT CENTER
# ============================================================

st.markdown("---")
st.markdown("### 📄 Security Report Center")
st.write(
    "Generate a PDF report based on the current log analysis and detection results."
)

if st.button("📄 Generate Security Report", width="stretch"):
    try:
        report_path = generate_pdf_report(
            total_logs=len(logs),
            threat_score=threat_score,
            high_threats=len(brute_force) + len(root_attempts) + len(sudo_abuse),
            medium_threats=len(invalid_users),
            total_attacks=total_attacks,
            risk_level=risk_level,
            brute_force=brute_force,
            invalid_users=invalid_users,
            root_attempts=root_attempts,
            sudo_abuse=sudo_abuse,
            privilege_escalation=privilege_escalation,
        )

        with open(report_path, "rb") as pdf_file:
            pdf_data = pdf_file.read()

        st.success("Security report generated successfully.")
        st.download_button(
            label="⬇️ Download Security Report PDF",
            data=pdf_data,
            file_name="security_report.pdf",
            mime="application/pdf",
            width="stretch",
        )
    except Exception as error:
        st.error(f"Unable to generate security report: {error}")


# ============================================================
# FOOTER
# ============================================================

st.markdown("---")
st.caption(
    "AI Linux Log Analyzer | SOC Dashboard | "
    "Cybersecurity Monitoring Platform | Day 20"
)
