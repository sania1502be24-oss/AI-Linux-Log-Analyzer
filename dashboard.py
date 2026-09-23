import streamlit as st
import plotly.express as px
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
    layout="wide"
)


# ============================================================
# TITLE
# ============================================================

st.title("🛡️ AI Linux Log Analyzer Dashboard")
st.markdown("---")


# ============================================================
# SIDEBAR FILTERS
# ============================================================

st.sidebar.title("⚙️ Filters")

severity_filter = st.sidebar.selectbox(
    "Select Severity",
    ["All", "HIGH", "MEDIUM", "CRITICAL"]
)

search_term = st.sidebar.text_input(
    "Search Alerts"
)


# ============================================================
# LOAD DATA
# ============================================================

logs = parse_logs("data/auth.log")

results = detect_attacks(logs)

threat_score = calculate_threat_score(results)


# ============================================================
# METRICS
# ============================================================

total_logs = len(logs)

high_threats = (
    len(results.get("brute_force", {}))
    + len(results.get("root_attempts", []))
    + len(results.get("sudo_abuse", []))
)

medium_threats = len(
    results.get("invalid_users", [])
)

critical_threats = len(
    results.get("privilege_escalation", [])
)


# ============================================================
# DASHBOARD CARDS
# ============================================================

col1, col2, col3, col4, col5 = st.columns(5)

with col1:
    st.metric(
        "📄 Total Logs",
        total_logs
    )

with col2:
    st.metric(
        "⚠️ Threat Score",
        f"{threat_score}/100"
    )

with col3:
    st.metric(
        "🔴 High Threats",
        high_threats
    )

with col4:
    st.metric(
        "🟡 Medium Threats",
        medium_threats
    )

with col5:
    st.metric(
        "🚨 Critical Threats",
        critical_threats
    )


# ============================================================
# SECURITY STATUS
# ============================================================

st.markdown("---")

if threat_score >= 70:

    st.error(
        "🔴 CRITICAL SECURITY RISK DETECTED"
    )

elif threat_score >= 40:

    st.warning(
        "🟠 MEDIUM SECURITY RISK DETECTED"
    )

else:

    st.success(
        "🟢 SYSTEM APPEARS SECURE"
    )


# ============================================================
# THREAT SCORE
# ============================================================

st.subheader("🎯 Threat Score")

if threat_score >= 70:
    risk_label = "🔴 CRITICAL"

elif threat_score >= 40:
    risk_label = "🟠 MEDIUM"

else:
    risk_label = "🟢 LOW"

st.markdown(
    f"### Current Risk Level: {risk_label}"
)

st.progress(
    min(max(threat_score / 100, 0.0), 1.0)
)

st.write(
    f"Current Threat Score: {threat_score}/100"
)

st.markdown("---")


# ============================================================
# ATTACK DISTRIBUTION
# ============================================================

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
        len(results.get("brute_force", {})),
        len(results.get("invalid_users", [])),
        len(results.get("root_attempts", [])),
        len(results.get("sudo_abuse", [])),
        len(results.get("privilege_escalation", []))
    ]
})

if attack_data["Count"].sum() > 0:

    fig = px.pie(
        attack_data,
        names="Attack Type",
        values="Count",
        title="Attack Distribution"
    )

    st.plotly_chart(
        fig,
        width="stretch"
    )

else:

    st.info(
        "No attacks detected."
    )


# ============================================================
# DAY 17 - ATTACK SUMMARY
# ============================================================

st.markdown("---")

st.subheader("🧠 Attack Summary")


# Total detected attacks
total_attacks = sum([
    len(results.get("brute_force", {})),
    len(results.get("invalid_users", [])),
    len(results.get("root_attempts", [])),
    len(results.get("sudo_abuse", [])),
    len(results.get("privilege_escalation", []))
])


# Unique attacker IPs
unique_attacker_ips = len(
    results.get("brute_force", {})
)


# ============================================================
# ATTACK COUNTS
# ============================================================

attack_counts = {
    "Brute Force": len(
        results.get("brute_force", {})
    ),

    "Invalid Users": len(
        results.get("invalid_users", [])
    ),

    "Root Login": len(
        results.get("root_attempts", [])
    ),

    "Sudo Abuse": len(
        results.get("sudo_abuse", [])
    ),

    "Privilege Escalation": len(
        results.get("privilege_escalation", [])
    )
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
# TOP ATTACKER
# ============================================================

top_attacker_ip = "N/A"

top_attacker_attempts = 0

if results.get("brute_force", {}):

    top_attacker_ip = max(
        results["brute_force"],
        key=results["brute_force"].get
    )

    top_attacker_attempts = results[
        "brute_force"
    ][top_attacker_ip]


# ============================================================
# ATTACK SUMMARY CARDS
# ============================================================

summary1, summary2, summary3, summary4 = st.columns(4)

with summary1:

    st.metric(
        "💥 Total Attacks",
        total_attacks
    )

with summary2:

    st.metric(
        "🌐 Attacker IPs",
        unique_attacker_ips
    )

with summary3:

    st.metric(
        "🔥 Most Common Attack",
        most_common_attack
    )

with summary4:

    st.metric(
        "🎯 Top Attacker",
        top_attacker_ip
    )


# ============================================================
# ATTACK INTELLIGENCE
# ============================================================

st.markdown("### 🔍 Attack Intelligence")

intel_col1, intel_col2 = st.columns(2)

with intel_col1:

    st.write(
        f"**Most Common Attack:** "
        f"{most_common_attack}"
    )

    st.write(
        f"**Occurrences:** "
        f"{most_common_count}"
    )

    st.write(
        f"**Unique Attacker IPs:** "
        f"{unique_attacker_ips}"
    )


with intel_col2:

    st.write(
        f"**Top Attacker IP:** "
        f"{top_attacker_ip}"
    )

    st.write(
        f"**Failed Attempts:** "
        f"{top_attacker_attempts}"
    )

    st.write(
        f"**Overall Threat Score:** "
        f"{threat_score}/100"
    )


# ============================================================
# DAY 17 - ATTACK RISK ASSESSMENT
# ============================================================

st.markdown("---")

st.subheader("🧠 Attack Risk Assessment")


# ============================================================
# RISK FACTORS
# ============================================================

risk_factors = []


if threat_score >= 70:

    risk_factors.append(
        "Very high overall threat score"
    )


if top_attacker_attempts >= 10:

    risk_factors.append(
        "Repeated failed login attempts from a single IP"
    )


if unique_attacker_ips >= 3:

    risk_factors.append(
        "Multiple attacker IP addresses detected"
    )


if len(
    results.get("privilege_escalation", [])
) > 0:

    risk_factors.append(
        "Privilege escalation activity detected"
    )


if len(
    results.get("root_attempts", [])
) > 0:

    risk_factors.append(
        "Root login activity detected"
    )


if len(
    results.get("sudo_abuse", [])
) > 0:

    risk_factors.append(
        "Suspicious sudo activity detected"
    )


# ============================================================
# RISK LEVEL
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
        "Some suspicious activity was detected."
    )

else:

    risk_level = "LOW"

    risk_message = (
        "No significant suspicious activity detected."
    )


# ============================================================
# RISK DISPLAY
# ============================================================

risk_col1, risk_col2 = st.columns(2)

with risk_col1:

    st.metric(
        "⚠️ Overall Risk Level",
        risk_level
    )


with risk_col2:

    st.metric(
        "🎯 Threat Score",
        f"{threat_score}/100"
    )


st.write(
    f"**Assessment:** {risk_message}"
)


# ============================================================
# DETECTED RISK FACTORS
# ============================================================

if risk_factors:

    st.markdown("### 🚨 Detected Risk Factors")

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
        "review authentication logs, and verify whether "
        "privilege escalation or unauthorized access occurred."
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
# DAY 17 - ATTACK PATTERN ANALYSIS
# ============================================================

st.markdown("---")

st.subheader("📊 Attack Pattern Analysis")


pattern_data = pd.DataFrame({
    "Attack Type": [
        "Brute Force",
        "Invalid Users",
        "Root Login",
        "Sudo Abuse",
        "Privilege Escalation"
    ],

    "Events": [
        len(results.get("brute_force", {})),
        len(results.get("invalid_users", [])),
        len(results.get("root_attempts", [])),
        len(results.get("sudo_abuse", [])),
        len(results.get("privilege_escalation", []))
    ]
})


# Remove zero-event attack types
pattern_data = pattern_data[
    pattern_data["Events"] > 0
]


if not pattern_data.empty:

    pattern_data = pattern_data.sort_values(
        by="Events",
        ascending=False
    )


    pattern_fig = px.bar(
        pattern_data,
        x="Attack Type",
        y="Events",
        text="Events",
        title="Detected Attack Patterns"
    )


    pattern_fig.update_layout(
        xaxis_title="Attack Type",
        yaxis_title="Number of Events"
    )


    st.plotly_chart(
        pattern_fig,
        width="stretch"
    )


    dominant_attack = pattern_data.iloc[0][
        "Attack Type"
    ]

    dominant_count = pattern_data.iloc[0][
        "Events"
    ]


    st.info(
        f"🧠 **Dominant Attack Pattern:** "
        f"{dominant_attack} "
        f"({dominant_count} detected events)"
    )


else:

    st.success(
        "🟢 No attack patterns detected."
    )


# ============================================================
# THREAT SUMMARY
# ============================================================

st.markdown("---")

st.subheader("🚨 Threat Summary")


summary_col1, summary_col2 = st.columns(2)


with summary_col1:

    st.write(
        f"📄 **Total Logs Parsed:** {total_logs}"
    )

    st.write(
        f"🎯 **Threat Score:** {threat_score}/100"
    )

    st.write(
        f"🔴 **High Severity Threats:** {high_threats}"
    )


with summary_col2:

    st.write(
        f"🟡 **Medium Severity Threats:** {medium_threats}"
    )

    st.write(
        f"🚨 **Critical Threats:** {critical_threats}"
    )


# ============================================================
# SECURITY OVERVIEW
# ============================================================

st.markdown("---")

st.subheader("📋 Security Overview")


overview = pd.DataFrame({
    "Metric": [
        "Total Logs",
        "Threat Score",
        "High Threats",
        "Medium Threats",
        "Critical Threats"
    ],

    "Value": [
        total_logs,
        threat_score,
        high_threats,
        medium_threats,
        critical_threats
    ]
})


st.dataframe(
    overview,
    width="stretch",
    hide_index=True
)


# ============================================================
# ALERTS DATASET
# ============================================================

alerts = []


# ============================================================
# BRUTE FORCE ALERTS
# ============================================================

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


# ============================================================
# INVALID USER ALERTS
# ============================================================

for attack in results.get(
    "invalid_users",
    []
):

    alerts.append({
        "Severity": "MEDIUM",
        "Type": "Invalid User",
        "Source": "Unknown",
        "Message": attack
    })


# ============================================================
# ROOT LOGIN ALERTS
# ============================================================

for attack in results.get(
    "root_attempts",
    []
):

    alerts.append({
        "Severity": "HIGH",
        "Type": "Root Login",
        "Source": "Unknown",
        "Message": attack
    })


# ============================================================
# SUDO ABUSE ALERTS
# ============================================================

for attack in results.get(
    "sudo_abuse",
    []
):

    alerts.append({
        "Severity": "HIGH",
        "Type": "Sudo Abuse",
        "Source": "Local User",
        "Message": attack
    })


# ============================================================
# PRIVILEGE ESCALATION
# ============================================================

for attack in results.get(
    "privilege_escalation",
    []
):

    alerts.append({
        "Severity": "CRITICAL",
        "Type": "Privilege Escalation",
        "Source": "Local User",
        "Message": attack
    })


# ============================================================
# CREATE ALERT DATAFRAME
# ============================================================

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
# APPLY FILTERS
# ============================================================

if not alerts_df.empty:

    if severity_filter != "All":

        alerts_df = alerts_df[
            alerts_df["Severity"] == severity_filter
        ]


    if search_term:

        alerts_df = alerts_df[
            alerts_df["Message"].str.contains(
                search_term,
                case=False,
                na=False
            )
        ]


# ============================================================
# SECURITY ALERTS
# ============================================================

st.markdown("---")

st.subheader(
    "🚨 Recent Security Alerts"
)


st.metric(
    "Displayed Alerts",
    len(alerts_df)
)


if not alerts_df.empty:

    st.dataframe(
        alerts_df,
        width="stretch",
        hide_index=True
    )

else:

    st.success(
        "No security alerts match the selected filters."
    )


# ============================================================
# EXPORT SECURITY ALERTS
# ============================================================

st.markdown("---")

st.subheader(
    "📥 Export Security Alerts"
)


if not alerts_df.empty:

    csv_data = alerts_df.to_csv(
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
# ALERT SEVERITY DISTRIBUTION
# ============================================================

st.markdown("---")

st.subheader(
    "🚦 Alert Severity Distribution"
)


if not alerts_df.empty:

    severity_data = (
        alerts_df["Severity"]
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
        title="Security Alerts by Severity",
        text="Count"
    )


    severity_fig.update_layout(
        xaxis_title="Severity",
        yaxis_title="Number of Alerts"
    )


    st.plotly_chart(
        severity_fig,
        width="stretch"
    )

else:

    st.info(
        "No alerts available for severity analysis."
    )


# ============================================================
# THREAT INTELLIGENCE
# ============================================================

st.markdown("---")

st.subheader(
    "🕵️ Threat Intelligence - Attacker Risk"
)


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

st.subheader(
    "🌐 Top Attacker IPs"
)


if attacker_ips:

    top_ips_df = pd.DataFrame(
        attacker_ips
    )


    top_ips_df = top_ips_df.sort_values(
        by="Failed Attempts",
        ascending=False
    ).head(10)


    attacker_fig = px.bar(
        top_ips_df,
        x="IP Address",
        y="Failed Attempts",
        title="Top 10 Attacker IPs",
        text="Failed Attempts"
    )


    attacker_fig.update_layout(
        xaxis_title="Attacker IP",
        yaxis_title="Failed Login Attempts"
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

st.subheader(
    "📈 Threat Activity Timeline"
)


if logs:

    timeline_df = pd.DataFrame(
        logs
    )


    if "timestamp" in timeline_df.columns:

        timeline_df["timestamp"] = pd.to_datetime(
            timeline_df["timestamp"],
            errors="coerce"
        )


        timeline_df = timeline_df.dropna(
            subset=["timestamp"]
        )


        if not timeline_df.empty:

            timeline_df["Time"] = (
                timeline_df[
                    "timestamp"
                ].dt.strftime("%H:%M")
            )


            activity = (
                timeline_df
                .groupby("Time")
                .size()
                .reset_index(
                    name="Events"
                )
            )


            timeline_fig = px.line(
                activity,
                x="Time",
                y="Events",
                markers=True,
                title="Log Activity Over Time"
            )


            timeline_fig.update_layout(
                xaxis_title="Time",
                yaxis_title="Number of Events"
            )


            st.plotly_chart(
                timeline_fig,
                width="stretch"
            )


        else:

            st.info(
                "No valid timestamps available "
                "for timeline analysis."
            )


    else:

        st.info(
            "Timestamp field not available "
            "in log data."
        )


else:

    st.info(
        "No logs available for timeline analysis."
    )


# ============================================================
# IP INVESTIGATION
# ============================================================

st.markdown("---")

st.subheader(
    "🔎 IP Investigation"
)


if attacker_ips:

    investigation_df = pd.DataFrame(
        attacker_ips
    )


    selected_ip = st.selectbox(
        "Select an IP Address to investigate",
        investigation_df[
            "IP Address"
        ].tolist()
    )


    selected_data = investigation_df[
        investigation_df[
            "IP Address"
        ] == selected_ip
    ].iloc[0]


    col1, col2, col3 = st.columns(3)


    with col1:

        st.metric(
            "🌐 IP Address",
            selected_ip
        )


    with col2:

        st.metric(
            "🔐 Failed Attempts",
            selected_data[
                "Failed Attempts"
            ]
        )


    with col3:

        st.metric(
            "⚠️ Risk Level",
            selected_data[
                "Risk Level"
            ]
        )


    st.markdown(
        "### 📋 Investigation Details"
    )


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

st.subheader(
    "📜 Recent Log Entries"
)


if logs:

    log_df = pd.DataFrame(
        logs
    )


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
    "Cybersecurity Monitoring Platform"
)