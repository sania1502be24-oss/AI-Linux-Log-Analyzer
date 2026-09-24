import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd

from src.parser import parse_logs
from src.detector import detect_attacks
from src.threat_score import calculate_threat_score
from src.pdf_report import generate_pdf_report


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


severity_filter = st.sidebar.selectbox(
    "Severity Filter",
    [
        "All",
        "HIGH",
        "MEDIUM",
        "CRITICAL"
    ]
)


search_query = st.sidebar.text_input(
    "🔎 Search Alerts",
    ""
)


st.sidebar.markdown("---")

st.sidebar.markdown(
    """
    ### 📊 Data Source

    **Log File**

    `data/auth.log`

    The dashboard analyzes Linux authentication
    logs for suspicious activity.
    """
)


# ============================================================
# LOAD LOG DATA
# ============================================================

try:

    logs = parse_logs(
        "data/auth.log"
    )

except Exception as error:

    st.error(
        f"Unable to parse log file: {error}"
    )

    logs = []


# ============================================================
# DETECT SECURITY EVENTS
# ============================================================

try:

    results = detect_attacks(
        logs
    )

except Exception as error:

    st.error(
        f"Unable to detect security events: {error}"
    )

    results = {
        "brute_force": {},
        "invalid_users": [],
        "root_attempts": [],
        "sudo_abuse": [],
        "privilege_escalation": []
    }


# ============================================================
# EXTRACT ATTACK RESULTS
# ============================================================

brute_force = results.get(
    "brute_force",
    {}
)

invalid_users = results.get(
    "invalid_users",
    []
)

root_attempts = results.get(
    "root_attempts",
    []
)

sudo_abuse = results.get(
    "sudo_abuse",
    []
)

privilege_escalation = results.get(
    "privilege_escalation",
    []
)


# ============================================================
# THREAT SCORE
# ============================================================

try:

    threat_score = calculate_threat_score(
        results
    )

except Exception:

    threat_score = 0


# ============================================================
# RISK LEVEL
# ============================================================

if threat_score >= 80:

    risk_level = "CRITICAL"

elif threat_score >= 60:

    risk_level = "HIGH"

elif threat_score >= 30:

    risk_level = "MEDIUM"

else:

    risk_level = "LOW"


# ============================================================
# ATTACK COUNTS
# ============================================================

brute_force_count = len(
    brute_force
)

invalid_user_count = len(
    invalid_users
)

root_count = len(
    root_attempts
)

sudo_count = len(
    sudo_abuse
)

privilege_count = len(
    privilege_escalation
)


total_attacks = (
    brute_force_count
    + invalid_user_count
    + root_count
    + sudo_count
    + privilege_count
)


# ============================================================
# ATTACKER IP INFORMATION
# ============================================================

attacker_ips = []

for ip, count in brute_force.items():

    attacker_ips.append(
        {
            "IP Address": ip,
            "Failed Attempts": count,
            "Risk Level": (
                "HIGH"
                if count >= 5
                else "MEDIUM"
            )
        }
    )


# ============================================================
# SECURITY STATUS
# ============================================================

if risk_level == "CRITICAL":

    security_status = "🚨 CRITICAL THREATS DETECTED"

elif risk_level == "HIGH":

    security_status = "🔴 HIGH RISK ACTIVITY"

elif risk_level == "MEDIUM":

    security_status = "🟠 SUSPICIOUS ACTIVITY"

else:

    security_status = "🟢 SYSTEM MONITORING"


# ============================================================
# EXECUTIVE SECURITY OVERVIEW
# ============================================================

st.markdown("---")

st.markdown(
    "### 🛡️ Security Overview"
)


metric1, metric2, metric3, metric4, metric5 = st.columns(5)


with metric1:

    st.metric(
        "Total Logs",
        len(logs)
    )


with metric2:

    st.metric(
        "Total Attacks",
        total_attacks
    )


with metric3:

    st.metric(
        "Threat Score",
        f"{threat_score}/100"
    )


with metric4:

    st.metric(
        "Attacker IPs",
        len(attacker_ips)
    )


with metric5:

    st.metric(
        "Risk Level",
        risk_level
    )


st.info(
    f"Security Status: {security_status}"
)


# ============================================================
# ATTACK STATISTICS
# ============================================================

st.markdown("---")

st.markdown(
    "### 📊 Attack Statistics"
)


attack_stats = pd.DataFrame(
    {
        "Attack Type": [
            "Brute Force",
            "Invalid User",
            "Root Login",
            "Sudo Abuse",
            "Privilege Escalation"
        ],
        "Count": [
            brute_force_count,
            invalid_user_count,
            root_count,
            sudo_count,
            privilege_count
        ]
    }
)


chart_col1, chart_col2 = st.columns(2)


with chart_col1:

    fig_pie = px.pie(
        attack_stats,
        names="Attack Type",
        values="Count",
        title="Attack Distribution"
    )

    st.plotly_chart(
        fig_pie,
        width="content"
    )


with chart_col2:

    fig_bar = px.bar(
        attack_stats,
        x="Count",
        y="Attack Type",
        orientation="h",
        title="Attack Frequency"
    )

    st.plotly_chart(
        fig_bar,
        width="stretch"
    )


# ============================================================
# ATTACK INTELLIGENCE
# ============================================================

st.markdown("---")

st.markdown(
    "### 🎯 Attack Intelligence"
)


intel_col1, intel_col2, intel_col3 = st.columns(3)


with intel_col1:

    st.metric(
        "Brute Force Sources",
        brute_force_count
    )


with intel_col2:

    st.metric(
        "Privilege Escalations",
        privilege_count
    )


with intel_col3:

    st.metric(
        "Sudo Abuse Events",
        sudo_count
    )


# ============================================================
# RISK ASSESSMENT
# ============================================================

st.markdown("---")

st.markdown(
    "### ⚠️ Risk Assessment"
)


if threat_score >= 80:

    st.error(
        "Critical risk detected. Immediate investigation "
        "of authentication and privilege-related activity "
        "is recommended."
    )

elif threat_score >= 60:

    st.warning(
        "High-risk activity detected. Review suspicious "
        "authentication and privilege events."
    )

elif threat_score >= 30:

    st.warning(
        "Medium-risk activity detected. Continue monitoring "
        "and investigate suspicious events."
    )

else:

    st.success(
        "No significant high-risk activity detected."
    )


# ============================================================
# SOC ANALYST FOCUS
# ============================================================

st.markdown("---")

st.markdown(
    "### 🧑‍💻 SOC Analyst Focus"
)


focus_items = []


if brute_force:

    focus_items.append(
        "Investigate repeated failed login attempts."
    )


if invalid_users:

    focus_items.append(
        "Review invalid username authentication attempts."
    )


if root_attempts:

    focus_items.append(
        "Review root account login activity."
    )


if sudo_abuse:

    focus_items.append(
        "Audit privileged command execution."
    )


if privilege_escalation:

    focus_items.append(
        "Investigate privilege escalation indicators."
    )


if not focus_items:

    focus_items.append(
        "Continue routine security monitoring."
    )


for item in focus_items:

    st.write(
        f"• {item}"
    )


# ============================================================
# SECURITY ALERTS
# ============================================================

st.markdown("---")

st.markdown(
    "### 🚨 Security Alerts"
)


alerts = []


# ------------------------------------------------------------
# BRUTE FORCE ALERTS
# ------------------------------------------------------------

for ip, count in brute_force.items():

    alerts.append(
        {
            "Severity": "HIGH",
            "Type": "Brute Force",
            "Source": ip,
            "Message": (
                f"{count} failed login attempts detected"
            )
        }
    )


# ------------------------------------------------------------
# INVALID USER ALERTS
# ------------------------------------------------------------

for attack in invalid_users:

    alerts.append(
        {
            "Severity": "MEDIUM",
            "Type": "Invalid User",
            "Source": "",
            "Message": str(attack)
        }
    )


# ------------------------------------------------------------
# ROOT LOGIN ALERTS
# ------------------------------------------------------------

for attack in root_attempts:

    alerts.append(
        {
            "Severity": "HIGH",
            "Type": "Root Login",
            "Source": "",
            "Message": str(attack)
        }
    )


# ------------------------------------------------------------
# SUDO ALERTS
# ------------------------------------------------------------

for attack in sudo_abuse:

    alerts.append(
        {
            "Severity": "HIGH",
            "Type": "Sudo Abuse",
            "Source": "",
            "Message": str(attack)
        }
    )


# ------------------------------------------------------------
# PRIVILEGE ESCALATION ALERTS
# ------------------------------------------------------------

for attack in privilege_escalation:

    alerts.append(
        {
            "Severity": "CRITICAL",
            "Type": "Privilege Escalation",
            "Source": "",
            "Message": str(attack)
        }
    )


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
# ALERT FILTERING
# ============================================================

filtered_alerts = alerts_df.copy()


if not filtered_alerts.empty:

    if severity_filter != "All":

        filtered_alerts = filtered_alerts[
            filtered_alerts["Severity"]
            == severity_filter
        ]


    if search_query:

        search_text = search_query.lower()

        filtered_alerts = filtered_alerts[
            filtered_alerts[
                [
                    "Message",
                    "Source",
                    "Type"
                ]
            ]
            .astype(str)
            .apply(
                lambda row:
                row.str.lower()
                .str.contains(
                    search_text
                ).any(),
                axis=1
            )
        ]


# ============================================================
# DISPLAY ALERTS
# ============================================================

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

st.markdown("---")

st.markdown(
    "### 📥 Export Alerts"
)


if not filtered_alerts.empty:

    csv_data = filtered_alerts.to_csv(
        index=False
    )

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

if not filtered_alerts.empty:

    severity_counts = (
        filtered_alerts["Severity"]
        .value_counts()
        .reset_index()
    )

    severity_counts.columns = [
        "Severity",
        "Count"
    ]


    fig_severity = px.bar(
        severity_counts,
        x="Severity",
        y="Count",
        title="Security Alerts by Severity"
    )

    st.plotly_chart(
        fig_severity,
        width="stretch"
    )


# ============================================================
# THREAT INTELLIGENCE
# ============================================================

st.markdown("---")

st.markdown(
    "### 🌐 Threat Intelligence"
)


if attacker_ips:

    intelligence_df = pd.DataFrame(
        attacker_ips
    )

    st.dataframe(
        intelligence_df,
        width="stretch",
        hide_index=True
    )


    fig_attackers = px.bar(
        intelligence_df,
        x="IP Address",
        y="Failed Attempts",
        title="Top Attacker IPs"
    )

    st.plotly_chart(
        fig_attackers,
        width="stretch"
    )

else:

    st.info(
        "No attacker IPs identified."
    )


# ============================================================
# THREAT ACTIVITY TIMELINE
# ============================================================

st.markdown("---")

st.markdown(
    "### 🕒 Threat Activity Timeline"
)


timeline_data = []


for log in logs:

    if isinstance(log, dict):

        timestamp = (
            log.get("timestamp")
            or log.get("time")
            or log.get("date")
        )

        message = (
            log.get("message")
            or log.get("raw")
            or str(log)
        )

        if timestamp:

            timeline_data.append(
                {
                    "timestamp": timestamp,
                    "message": message
                }
            )


if timeline_data:

    timeline_df = pd.DataFrame(
        timeline_data
    )

    timeline_df["timestamp"] = pd.to_datetime(
    timeline_df["timestamp"],
    format="mixed",
    errors="coerce"
)

    timeline_df = timeline_df.dropna(
        subset=["timestamp"]
    )


    if not timeline_df.empty:

        timeline_counts = (
            timeline_df
            .set_index("timestamp")
            .resample("h")
            .size()
            .reset_index(
                name="Events"
            )
        )


        fig_timeline = px.line(
            timeline_counts,
            x="timestamp",
            y="Events",
            markers=True,
            title="Threat Activity Over Time"
        )

        st.plotly_chart(
            fig_timeline,
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


# ============================================================
# IP INVESTIGATION
# ============================================================

st.markdown("---")

st.markdown(
    "### 🔎 IP Investigation"
)


if attacker_ips:

    investigation_df = pd.DataFrame(
        attacker_ips
    )


    selected_ip = st.selectbox(
        "Select an IP address to investigate",
        investigation_df[
            "IP Address"
        ].tolist()
    )


    selected_data = investigation_df[
        investigation_df["IP Address"]
        == selected_ip
    ].iloc[0]


    ip_col1, ip_col2, ip_col3 = st.columns(3)


    with ip_col1:

        st.metric(
            "🌐 IP Address",
            selected_ip
        )


    with ip_col2:

        st.metric(
            "Failed Attempts",
            selected_data[
                "Failed Attempts"
            ]
        )


    with ip_col3:

        st.metric(
            "Risk Level",
            selected_data[
                "Risk Level"
            ]
        )


    st.markdown(
        "#### 📋 Related Alerts"
    )


    ip_alerts = alerts_df[
        alerts_df["Source"]
        == selected_ip
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

st.markdown(
    "### 📜 Recent Log Entries"
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
# SECURITY REPORT CENTER
# ============================================================

st.markdown("---")

st.markdown(
    "### 📄 Security Report Center"
)

st.write(
    "Generate and download a professional security incident "
    "report based on the current log analysis."
)


if st.button(
    "📄 Generate Security Report",
    width="stretch"
):

    try:

        # ----------------------------------------------------
        # GENERATE REPORT
        # ----------------------------------------------------

        report_path = generate_pdf_report(

            total_logs=len(logs),

            threat_score=threat_score,

            high_threats=(
                len(brute_force)
                + len(root_attempts)
                + len(sudo_abuse)
            ),

            medium_threats=len(
                invalid_users
            ),

            total_attacks=total_attacks,

            risk_level=risk_level,

            brute_force=brute_force,

            invalid_users=invalid_users,

            root_attempts=root_attempts,

            sudo_abuse=sudo_abuse,

            privilege_escalation=(
                privilege_escalation
            )
        )


        st.success(
            "✅ Security report generated successfully."
        )


        # ----------------------------------------------------
        # PDF DOWNLOAD
        # ----------------------------------------------------

        with open(
            report_path,
            "rb"
        ) as pdf_file:

            pdf_data = pdf_file.read()


        st.download_button(

            label="⬇️ Download Security Report PDF",

            data=pdf_data,

            file_name="security_report.pdf",

            mime="application/pdf",

            width="stretch"
        )


    except Exception as error:

        st.error(
            f"Unable to generate security report: {error}"
        )


# ============================================================
# FOOTER
# ============================================================

st.markdown("---")

st.caption(
    "AI Linux Log Analyzer | "
    "SOC Dashboard | "
    "Cybersecurity Monitoring Platform | "
    "Day 19"
)
