from datetime import datetime


def generate_report(results, total_logs):
    brute_force = results["brute_force"]
    invalid_users = results["invalid_users"]
    root_attempts = results["root_attempts"]

    high_count = len(brute_force) + len(root_attempts)
    medium_count = len(invalid_users)

    report = []

    report.append("=" * 60)
    report.append("       AI LINUX LOG ANALYZER - SECURITY REPORT")
    report.append("=" * 60)

    report.append(f"Generated: {datetime.now()}")
    report.append(f"Total Logs Analyzed: {total_logs}")

    report.append("\n--- THREAT SUMMARY ---")
    report.append(f"High Severity Threats: {high_count}")
    report.append(f"Medium Severity Threats: {medium_count}")

    report.append("\n--- BRUTE FORCE ATTACKS ---")

    if brute_force:
        for ip, count in brute_force.items():
            report.append(
                f"[HIGH] {ip} -> {count} failed login attempts"
            )
    else:
        report.append("No brute force attacks detected.")

    report.append("\n--- INVALID USER ATTACKS ---")

    if invalid_users:
        for attack in invalid_users:
            report.append(f"[MEDIUM] {attack}")
    else:
        report.append("No invalid user attacks detected.")

    report.append("\n--- ROOT LOGIN ATTEMPTS ---")

    if root_attempts:
        for attack in root_attempts:
            report.append(f"[HIGH] {attack}")
    else:
        report.append("No root login attempts detected.")

    report.append("\n" + "=" * 60)

    return "\n".join(report)