from datetime import datetime

from src.threat_score import calculate_threat_score


def generate_report(results, total_logs):
    """
    Generate a professional security incident report.

    Parameters:
        results (dict): Detected security events.
        total_logs (int): Total number of logs analyzed.

    Returns:
        str: Formatted security report.
    """

    brute_force = results.get("brute_force", {})
    invalid_users = results.get("invalid_users", [])
    root_attempts = results.get("root_attempts", [])
    sudo_abuse = results.get("sudo_abuse", [])
    privilege_escalation = results.get("privilege_escalation", [])

    # ---------------------------------------------------------
    # THREAT SCORE
    # ---------------------------------------------------------

    threat_score = calculate_threat_score(results)

    # ---------------------------------------------------------
    # RISK LEVEL
    # ---------------------------------------------------------

    if threat_score >= 80:
        risk_level = "CRITICAL"
    elif threat_score >= 60:
        risk_level = "HIGH"
    elif threat_score >= 30:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    # ---------------------------------------------------------
    # ATTACK COUNTS
    # ---------------------------------------------------------

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

    # ---------------------------------------------------------
    # ATTACKER IPs
    # ---------------------------------------------------------

    attacker_ips = list(brute_force.keys())

    # ---------------------------------------------------------
    # REPORT
    # ---------------------------------------------------------

    report = []

    report.append("=" * 70)
    report.append("              AI LINUX LOG ANALYZER")
    report.append("              SECURITY INCIDENT REPORT")
    report.append("=" * 70)

    report.append("")
    report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append(f"Total Logs Analyzed: {total_logs}")
    report.append(f"Total Detected Attacks: {total_attacks}")

    # ---------------------------------------------------------
    # EXECUTIVE SUMMARY
    # ---------------------------------------------------------

    report.append("")
    report.append("-" * 70)
    report.append("EXECUTIVE SUMMARY")
    report.append("-" * 70)

    report.append(
        f"Overall Risk Level: {risk_level}"
    )

    report.append(
        f"Threat Score: {threat_score}/100"
    )

    report.append(
        "The log analysis identified "
        f"{total_attacks} security-related events."
    )

    if attacker_ips:
        report.append(
            f"Unique Attacker IPs Identified: {len(attacker_ips)}"
        )
    else:
        report.append("Unique Attacker IPs Identified: 0")

    # ---------------------------------------------------------
    # ATTACK STATISTICS
    # ---------------------------------------------------------

    report.append("")
    report.append("-" * 70)
    report.append("ATTACK STATISTICS")
    report.append("-" * 70)

    report.append(
        f"Brute Force Sources: {brute_force_count}"
    )

    report.append(
        f"Invalid User Attempts: {invalid_user_count}"
    )

    report.append(
        f"Root Login Attempts: {root_count}"
    )

    report.append(
        f"Sudo Abuse Attempts: {sudo_count}"
    )

    report.append(
        f"Privilege Escalation Attempts: {privilege_count}"
    )

    # ---------------------------------------------------------
    # ATTACKER IP INTELLIGENCE
    # ---------------------------------------------------------

    report.append("")
    report.append("-" * 70)
    report.append("ATTACKER IP INTELLIGENCE")
    report.append("-" * 70)

    if brute_force:
        for ip, count in brute_force.items():
            report.append(
                f"{ip} -> {count} failed login attempts"
            )
    else:
        report.append("No attacker IPs identified.")

    # ---------------------------------------------------------
    # BRUTE FORCE
    # ---------------------------------------------------------

    report.append("")
    report.append("-" * 70)
    report.append("BRUTE FORCE ATTACKS")
    report.append("-" * 70)

    if brute_force:
        for ip, count in brute_force.items():
            report.append(
                f"[HIGH] {ip} -> {count} failed login attempts"
            )
    else:
        report.append("No brute force attacks detected.")

    # ---------------------------------------------------------
    # INVALID USERS
    # ---------------------------------------------------------

    report.append("")
    report.append("-" * 70)
    report.append("INVALID USER ATTACKS")
    report.append("-" * 70)

    if invalid_users:
        for attack in invalid_users:
            report.append(f"[MEDIUM] {attack}")
    else:
        report.append("No invalid user attacks detected.")

    # ---------------------------------------------------------
    # ROOT LOGIN
    # ---------------------------------------------------------

    report.append("")
    report.append("-" * 70)
    report.append("ROOT LOGIN ATTEMPTS")
    report.append("-" * 70)

    if root_attempts:
        for attack in root_attempts:
            report.append(f"[HIGH] {attack}")
    else:
        report.append("No root login attempts detected.")

    # ---------------------------------------------------------
    # SUDO ABUSE
    # ---------------------------------------------------------

    report.append("")
    report.append("-" * 70)
    report.append("SUDO ABUSE ATTEMPTS")
    report.append("-" * 70)

    if sudo_abuse:
        for attack in sudo_abuse:
            report.append(f"[HIGH] {attack}")
    else:
        report.append("No sudo abuse detected.")

    # ---------------------------------------------------------
    # PRIVILEGE ESCALATION
    # ---------------------------------------------------------

    report.append("")
    report.append("-" * 70)
    report.append("PRIVILEGE ESCALATION ATTEMPTS")
    report.append("-" * 70)

    if privilege_escalation:
        for attack in privilege_escalation:
            report.append(f"[CRITICAL] {attack}")
    else:
        report.append("No privilege escalation detected.")

    # ---------------------------------------------------------
    # RECOMMENDED ACTIONS
    # ---------------------------------------------------------

    report.append("")
    report.append("-" * 70)
    report.append("RECOMMENDED SECURITY ACTIONS")
    report.append("-" * 70)

    if brute_force:
        report.append(
            "1. Investigate repeated authentication failures."
        )
        report.append(
            "2. Review and consider restricting suspicious source IPs."
        )
    else:
        report.append(
            "1. Continue monitoring authentication activity."
        )

    if root_attempts:
        report.append(
            "3. Review root account access and authentication logs."
        )

    if sudo_abuse:
        report.append(
            "4. Audit privileged command execution."
        )

    if privilege_escalation:
        report.append(
            "5. Investigate privilege escalation indicators immediately."
        )

    report.append(
        "6. Continue monitoring Linux authentication logs."
    )

    # ---------------------------------------------------------
    # END OF REPORT
    # ---------------------------------------------------------

    report.append("")
    report.append("=" * 70)
    report.append("End of Security Incident Report")
    report.append("Generated by AI Linux Log Analyzer")
    report.append("=" * 70)

    return "\n".join(report)