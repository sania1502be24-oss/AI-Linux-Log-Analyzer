import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd

from src.parser import parse_logs
from src.detector import detect_attacks
from src.threat_score import calculate_threat_score


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="AI Linux Log Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# ============================================================
# CUSTOM STYLING
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

        .section-title {
            font-size: 1.5rem;
            font-weight: 650;
            margin-top: 1rem;
        }

        div[data-testid="stMetric"] {
            border: 1px solid rgba(128, 128, 128, 0.25);
            padding: 12px;
            border-radius: 10px;
        }
    </style>
    """,
    unsafe_allow_html=True
)


# ============================================================
# HEADER
# ============================================================

st.markdown(
    '<div class="main-title">🛡️ AI Linux Log Analyzer</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="subtitle">'
    'Security monitoring and threat detection dashboard'
    '</div>',
    unsafe_allow_html=True
)


# ============================================================
# SIDEBAR
# ============================================================

st.sidebar.title("⚙️ Dashboard Controls")

st.sidebar.markdown(
    "Use the controls below to investigate detected security events."
)

severity_filter = st.sidebar.selectbox(
    "Alert Severity",
    ["All", "HIGH", "MEDIUM", "CRITICAL"]
)

search_term = st.sidebar.text_input(
    "Search Alerts",
    placeholder="Search IP, attack type, message..."
)

st.sidebar.markdown("---")

st.sidebar.info(
    "📌 Data Source\n\n"
    "Linux authentication log\n\n"
    "`data/auth.log`"
)


# ============================================================
# LOAD LOG DATA
# ============================================================

try:
    logs = parse_logs("data/auth.log")
except Exception as error:
    st.error(f"Unable to parse authentication logs: {error}")
    st.stop()


# ============================================================
# DETECT ATTACKS
# ============================================================

try:
    results = detect_attacks(logs)
except Exception as error:
    st.error(f"Attack detection failed: {error}")
    st.stop()


# ============================================================
# CALCULATE THREAT SCORE
# ============================================================

try:
    threat_score = calculate_threat_score(results)
except Exception as error:
    st.error(f"Threat score calculation failed: {error}")
    st.stop()


# ============================================================
# BASIC METRICS
# ============================================================

total_logs = len(logs)

brute_force_count = len(
    results.get("brute_force", {})
)

invalid_user_count = len(
    results.get("invalid_users", [])
)

root_attempt_count = len(
    results.get("root_attempts", [])
)

sudo_abuse_count = len(
    results.get("sudo_abuse", [])
)

privilege_escalation_count = len(
    results.get("privilege_escalation", [])
)


high_threats = (
    brute_force_count
    + root_attempt_count
    + sudo_abuse_count
)

medium_threats = invalid_user_count

critical_threats = privilege_escalation_count


total_attacks = (
    brute_force_count
    + invalid_user_count
    + root_attempt_count
    + sudo_abuse_count
    + privilege_escalation_count
)


unique_attacker_ips = len(
    results.get("brute_force", {})
)


# ============================================================
# RISK CLASSIFICATION
# ============================================================

if threat_score >= 70:
    risk_level = "CRITICAL"
    risk_message = (
        "Immediate investigation recommended."
    )

elif threat_score >= 40:
    risk_level = "HIGH"
    risk_message = (
        "Suspicious activity requires investigation."
    )

elif total_attacks > 0:
    risk_level = "MEDIUM"
    risk_message = (
        "Suspicious activity was detected."
    )

else:
    risk_level = "LOW"
    risk_message = (
        "No significant suspicious activity detected."
    )


# ============================================================
# TOP METRICS
# ============================================================

st.markdown("### 📊 Security Overview")

metric1, metric2, metric3, metric4, metric5 = st.columns(5)

with metric1:
    st.metric(
        "📄 Logs Parsed",
        total_logs
    )

with metric2:
    st.metric(
        "🎯 Threat Score",
        f"{threat_score}/100"
    )

with metric3:
    st.metric(
        "🚨 Total Attacks",
        total_attacks
    )

with metric4:
    st.metric(
        "🌐 Attacker IPs",
        unique_attacker_ips
    )

with metric5:
    st.metric(
        "⚠️ Risk Level",
        risk_level
    )


# ============================================================
# SECURITY STATUS
# ============================================================

st.markdown("---")

if risk_level == "CRITICAL":

    st.error(
        "🔴 CRITICAL SECURITY RISK — "
        "Immediate investigation recommended."
    )

elif risk_level == "HIGH":

    st.warning(
        "🟠 HIGH SECURITY RISK — "
        "Suspicious activity requires investigation."
    )

elif risk_level == "MEDIUM":

    st.warning(
        "🟡 MEDIUM SECURITY RISK — "
        "Monitor detected suspicious activity."
    )

else:

    st.success(
        "🟢 SYSTEM STATUS — "
        "No significant suspicious activity detected."
    )


# ============================================================
# THREAT SCORE SECTION
# ============================================================

st.markdown("### 🎯 Threat Score")

score_col1, score_col2 = st.columns([2, 1])

with score_col1:

    st.progress(
        min(max(threat_score / 100, 0.0), 1.0)
    )

    st.write(
        f"Current threat score: **{threat_score}/100**"
    )

    st.caption(
        "Higher scores indicate greater detected security risk."
    )


with score_col2:

    st.metric(
        "Current Risk",
        risk_level
    )


# ============================================================
# ATTACK COUNTS
# ============================================================

attack_counts = {
    "Brute Force": brute_force_count,
    "Invalid Users": invalid_user_count,
    "Root Login": root_attempt_count,
    "Sudo Abuse": sudo_abuse_count,
    "Privilege Escalation": privilege_escalation_count
}


# ============================================================
# MOST COMMON ATTACK
# ============================================================

if any(attack_counts.values()):

    most_common_attack = max(
        attack_counts,
        key=attack_counts.get
    )

    most_common_count = attack_counts[
        most_common_attack
    ]

else:

    most_common_attack = "None"
    most_common_count = 0


# ============================================================
# ATTACK DISTRIBUTION
# ============================================================

st.markdown("---")
st.markdown("### 📊 Attack Distribution")

attack_data = pd.DataFrame({
    "Attack Type": list(attack_counts.keys()),
    "Events": list(attack_counts.values())
})

attack_data_nonzero = attack_data[
    attack_data["Events"] > 0
]


if not attack_data_nonzero.empty:

    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:

        pie_fig = px.pie(
            attack_data_nonzero,
            names="Attack Type",
            values="Events",
            hole=0.45,
            title="Attack Type Distribution"
        )

        pie_fig.update_layout(
            margin=dict(t=60, b=20, l=20, r=20)
        )

        st.plotly_chart(
            pie_fig,
            width="stretch"
        )

    with chart_col2:

        bar_fig = px.bar(
            attack_data_nonzero.sort_values(
                "Events",
                ascending=True
            ),
            x="Events",
            y="Attack Type",
            orientation="h",
            text="Events",
            title="Detected Attack Events"
        )

        st.plotly_chart(
            bar_fig,
            width="stretch"
        )

else:

    st.success(
        "🟢 No attack events detected."
    )


# ============================================================
# ATTACK INTELLIGENCE
# ============================================================

st.markdown("---")
st.markdown("### 🧠 Attack Intelligence")

intel1, intel2, intel3, intel4 = st.columns(4)

with intel1:

    st.metric(
        "💥 Total Attacks",
        total_attacks
    )

with intel2:

    st.metric(
        "🔥 Dominant Attack",
        most_common_attack
    )

with intel3:

    st.metric(
        "📈 Occurrences",
        most_common_count
    )

with intel4:

    st.metric(
        "🌐 Unique IPs",
        unique_attacker_ips
    )


# ============================================================
# RISK ASSESSMENT
# ============================================================

st.markdown("---")
st.markdown("### 🚨 Risk Assessment")

risk_factors = []


if threat_score >= 70:

    risk_factors.append(
        "Very high overall threat score."
    )


if top_attacker_attempts := (
    max(results.get("brute_force", {}).values())
    if results.get("brute_force", {})
    else 0
):

    if top_attacker_attempts >= 10:

        risk_factors.append(
            "Repeated failed login attempts detected from a single IP."
        )


if unique_attacker_ips >= 3:

    risk_factors.append(
        "Multiple attacker IP addresses detected."
    )


if privilege_escalation_count > 0:

    risk_factors.append(
        "Privilege escalation activity detected."
    )


if root_attempt_count > 0:

    risk_factors.append(
        "Root login activity detected."
    )


if sudo_abuse_count > 0:

    risk_factors.append(
        "Suspicious sudo activity detected."
    )


if risk_factors:

    for factor in risk_factors:

        st.warning(
            f"⚠️ {factor}"
        )

else:

    st.success(
        "🟢 No significant risk factors detected."
    )


# ============================================================
# SOC ANALYST FOCUS
# ============================================================

st.markdown("### 🛡️ SOC Analyst Focus")

if risk_level == "CRITICAL":

    st.error(
        "🔴 Investigate the highest-risk attacker IP, "
        "review authentication logs, and verify "
        "whether unauthorized access or privilege "
        "escalation occurred."
    )

elif risk_level == "HIGH":

    st.warning(
        "🟠 Review repeated authentication failures, "
        "investigate suspicious source IPs, and check "
        "for unusual privileged activity."
    )

elif risk_level == "MEDIUM":

    st.info(
        "🟡 Monitor authentication activity and "
        "investigate recurring suspicious events."
    )

else:

    st.success(
        "🟢 Continue monitoring system activity."
    )


# ============================================================
# ALERT DATASET
# ============================================================

alerts = []


# Brute force
for ip, count in results.get(
    "brute_force",
    {}
).items():

    alerts.append({
        "Severity": "HIGH",
        "Type": "Brute Force",
        "Source": ip,
        "Message": (
            f"{ip} -> {count} failed login attempts"
        )
    })


# Invalid users
for attack in results.get(
    "invalid_users",
    []
):

    alerts.append({
        "Severity": "MEDIUM",
        "Type": "Invalid User",
        "Source": "Unknown",
        "Message": str(attack)
    })


# Root login
for attack in results.get(
    "root_attempts",
    []
):

    alerts.append({
        "Severity": "HIGH",
        "Type": "Root Login",
        "Source": "Unknown",
        "Message": str(attack)
    })


# Sudo abuse
for attack in results.get(
    "sudo_abuse",
    []
):

    alerts.append({
        "Severity": "HIGH",
        "Type": "Sudo Abuse",
        "Source": "Local User",
        "Message": str(attack)
    })


# Privilege escalation
for attack in results.get(
    "privilege_escalation",
    []
):

    alerts.append({
        "Severity": "CRITICAL",
        "Type": "Privilege Escalation",
        "Source": "Local User",
        "Message": str(attack)
    })


alerts_df = pd.DataFrame(
    alerts,
    columns=[
        "Severity",
        "Type",
        "Source",
        "Message"
    ]
)


# ============================================================
# APPLY ALERT FILTERS
# ============================================================

filtered_alerts = alerts_df.copy()


if not filtered_alerts.empty:

    if severity_filter != "All":

        filtered_alerts = filtered_alerts[
            filtered_alerts["Severity"] == severity_filter
        ]


    if search_term:

        search_mask = (
            filtered_alerts["Message"]
            .str.contains(
                search_term,
                case=False,
                na=False
            )
            |
            filtered_alerts["Source"]
            .str.contains(
                search_term,
                case=False,
                na=False
            )
            |
            filtered_alerts["Type"]
            .str.contains(
                search_term,
                case=False,
                na=False
            )
        )

        filtered_alerts = filtered_alerts[
            search_mask
        ]


# ============================================================
# SECURITY ALERTS
# ============================================================

st.markdown("---")
st.markdown("### 🚨 Security Alerts")

st.metric(
    "Displayed Alerts",
    len(filtered_alerts)
)


if not filtered_alerts.empty:

    st.dataframe(
        filtered_alerts,
        width="stretch",
        hide_index=True
    )

else:

    st.success(
        "🟢 No security alerts match the selected filters."
    )


# ============================================================
# EXPORT ALERTS
# ============================================================

st.markdown("### 📥 Export Alerts")

if not filtered_alerts.empty:

    csv_data = filtered_alerts.to_csv(
        index=False
    ).encode("utf-8")

    st.download_button(
        label="📥 Download Alerts as CSV",
        data=csv_data,
        file_name="security_alerts.csv",
        mime="text/csv"
    )

else:

    st.info(
        "No alerts available for export."
    )


# ============================================================
# SEVERITY DISTRIBUTION
# ============================================================

st.markdown("---")
st.markdown("### 🚦 Alert Severity Distribution")

if not filtered_alerts.empty:

    severity_data = (
        filtered_alerts["Severity"]
        .value_counts()
        .reset_index()
    )

    severity_data.columns = [
        "Severity",
        "Count"
    ]

    severity_fig = px.bar(
        severity_data,
        x="Severity",
        y="Count",
        text="Count",
        title="Security Alerts by Severity"
    )

    st.plotly_chart(
        severity_fig,
        width="stretch"
    )

else:

    st.info(
        "No alert data available for severity analysis."
    )


# ============================================================
# THREAT INTELLIGENCE
# ============================================================

st.markdown("---")
st.markdown("### 🕵️ Threat Intelligence")

attacker_ips = []


for ip, count in results.get(
    "brute_force",
    {}
).items():

    if count >= 10:

        risk = "CRITICAL"

    elif count >= 5:

        risk = "HIGH"

    elif count >= 3:

        risk = "MEDIUM"

    else:

        risk = "LOW"


    attacker_ips.append({
        "IP Address": ip,
        "Failed Attempts": count,
        "Risk Level": risk
    })


if attacker_ips:

    threat_df = pd.DataFrame(
        attacker_ips
    )

    threat_df = threat_df.sort_values(
        by="Failed Attempts",
        ascending=False
    )

    st.dataframe(
        threat_df,
        width="stretch",
        hide_index=True
    )

else:

    st.success(
        "🟢 No attacker IPs detected."
    )


# ============================================================
# TOP ATTACKER IPS
# ============================================================

st.markdown("---")
st.markdown("### 🌐 Top Attacker IPs")

if attacker_ips:

    top_ips_df = pd.DataFrame(
        attacker_ips
    ).sort_values(
        by="Failed Attempts",
        ascending=False
    ).head(10)

    attacker_fig = px.bar(
        top_ips_df,
        x="IP Address",
        y="Failed Attempts",
        text="Failed Attempts",
        title="Top 10 Attacker IPs"
    )

    st.plotly_chart(
        attacker_fig,
        width="stretch"
    )

else:

    st.info(
        "No attacker IPs available."
    )


# ============================================================
# THREAT ACTIVITY TIMELINE
# ============================================================

st.markdown("---")
st.markdown("### 📈 Threat Activity Timeline")

if logs:

    timeline_df = pd.DataFrame(logs)

    if "timestamp" in timeline_df.columns:

        timeline_df["timestamp"] = pd.to_datetime(
            timeline_df["timestamp"],
            errors="coerce"
        )

        timeline_df = timeline_df.dropna(
            subset=["timestamp"]
        )

        if not timeline_df.empty:

            activity = (
                timeline_df
                .set_index("timestamp")
                .resample("h")
                .size()
                .reset_index(name="Events")
            )

            timeline_fig = px.line(
                activity,
                x="timestamp",
                y="Events",
                markers=True,
                title="Log Activity Over Time"
            )

            timeline_fig.update_layout(
                xaxis_title="Time",
                yaxis_title="Events"
            )

            st.plotly_chart(
                timeline_fig,
                width="stretch"
            )

        else:

            st.info(
                "No valid timestamps available."
            )

    else:

        st.info(
            "Timestamp field not available."
        )

else:

    st.info(
        "No logs available."
    )


# ============================================================
# IP INVESTIGATION
# ============================================================

st.markdown("---")
st.markdown("### 🔎 IP Investigation")

if attacker_ips:

    investigation_df = pd.DataFrame(
        attacker_ips
    )

    selected_ip = st.selectbox(
        "Select an IP address to investigate",
        investigation_df["IP Address"].tolist()
    )

    selected_data = investigation_df[
        investigation_df["IP Address"] == selected_ip
    ].iloc[0]

    ip_col1, ip_col2, ip_col3 = st.columns(3)

    with ip_col1:

        st.metric(
            "🌐 IP Address",
            selected_ip
        )

    with ip_col2:

        st.metric(
            "🔐 Failed Attempts",
            int(selected_data["Failed Attempts"])
        )

    with ip_col3:

        st.metric(
            "⚠️ Risk Level",
            selected_data["Risk Level"]
        )

    st.markdown("#### 📋 Related Alerts")

    ip_alerts = alerts_df[
        alerts_df["Source"] == selected_ip
    ]

    if not ip_alerts.empty:

        st.dataframe(
            ip_alerts,
            width="stretch",
            hide_index=True
        )

    else:

        st.info(
            "No additional alerts found for this IP."
        )

else:

    st.info(
        "No attacker IPs available for investigation."
    )


# ============================================================
# RECENT LOG ENTRIES
# ============================================================

st.markdown("---")
st.markdown("### 📜 Recent Log Entries")

if logs:

    log_df = pd.DataFrame(logs)

    st.dataframe(
        log_df,
        width="stretch",
        hide_index=True
    )

else:

    st.warning(
        "No logs found."
    )


# ============================================================
# FOOTER
# ============================================================

st.markdown("---")

st.caption(
    "AI Linux Log Analyzer | "
    "SOC Dashboard | "
    "Cybersecurity Monitoring Platform | "
    "Day 18"
)