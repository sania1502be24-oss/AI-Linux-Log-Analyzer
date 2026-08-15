from parser import parse_logs
from detector import detect_attacks
from reporter import generate_report
from threat_score import calculate_threat_score
from email_alert import send_alert
from bruteforce_detector import detect_bruteforce
from threat_intelligence import detect_malicious_ips
from pdf_report import generate_pdf_report

# Parse logs
logs = parse_logs("data/auth.log")

print(f"Total Logs Parsed: {len(logs)}")

# Detect attacks
results = detect_attacks(logs)

# Day 10 - Advanced Brute Force Detection
bruteforce_alerts = detect_bruteforce(logs)

# Day 11 - Threat Intelligence Detection
malicious_ip_alerts = detect_malicious_ips(logs)

# Calculate threat score
threat_score = calculate_threat_score(results)

print(f"\nOverall Threat Score: {threat_score}/100")

# Existing Brute Force Detection
print("\n=== BRUTE FORCE ATTEMPTS ===")

if results["brute_force"]:
    for ip, count in results["brute_force"].items():
        print(f"[HIGH] {ip} -> {count} failed attempts")
else:
    print("No brute force attacks detected.")

# Day 10 - Advanced Brute Force Detection
print("\n=== ADVANCED BRUTE FORCE DETECTION ===")

if bruteforce_alerts:
    for attack in bruteforce_alerts:
        print(
            f"[{attack['severity']}] "
            f"{attack['ip']} "
            f"({attack['attempts']} attempts)"
        )
else:
    print("No advanced brute force attacks detected.")

# Invalid User Attacks
print("\n=== INVALID USER ATTACKS ===")

if results["invalid_users"]:
    for attack in results["invalid_users"]:
        print(f"[MEDIUM] {attack}")
else:
    print("No invalid user attacks detected.")

# Root Login Attempts
print("\n=== ROOT LOGIN ATTEMPTS ===")

if results["root_attempts"]:
    for attack in results["root_attempts"]:
        print(f"[HIGH] {attack}")
else:
    print("No root login attempts detected.")

# Sudo Abuse Attempts
print("\n=== SUDO ABUSE ATTEMPTS ===")

if results["sudo_abuse"]:
    for attack in results["sudo_abuse"]:
        print(f"[HIGH] {attack}")
else:
    print("No sudo abuse detected.")

# Privilege Escalation Attempts
print("\n=== PRIVILEGE ESCALATION ATTEMPTS ===")

if results["privilege_escalation"]:
    for attack in results["privilege_escalation"]:
        print(f"[CRITICAL] {attack}")
else:
    print("No privilege escalation detected.")

# Day 11 - Threat Intelligence Alerts
print("\n=== THREAT INTELLIGENCE ALERTS ===")

if malicious_ip_alerts:
    for alert in malicious_ip_alerts:
        print(
            f"[{alert['severity']}] "
            f"{alert['ip']} -> "
            f"{alert['reason']}"
        )
else:
    print("No malicious IPs detected.")

# Generate Report
report = generate_report(results, len(logs))

with open("reports/security_report.txt", "w") as file:
    file.write(report)

print("\nReport generated successfully!")
print("Location: reports/security_report.txt")

# Calculate threat counts
high_count = (
    len(results["brute_force"]) +
    len(results["root_attempts"]) +
    len(results["sudo_abuse"]) +
    len(results["privilege_escalation"]) +
    len(bruteforce_alerts) +
    len(malicious_ip_alerts)
)

medium_count = len(results["invalid_users"])

# Send email alert for high threat score
if threat_score >= 70:
    send_alert(
        "HIGH RISK SECURITY ALERT",
        f"""
Threat Score: {threat_score}/100

High Severity Threats: {high_count}
Medium Severity Threats: {medium_count}

Advanced Brute Force Attacks: {len(bruteforce_alerts)}
Threat Intelligence Alerts: {len(malicious_ip_alerts)}

Please review the security report immediately.
"""
    )
generate_pdf_report(
    total_logs=len(logs),
    threat_score=threat_score,
    high_threats=high_count,
    medium_threats=medium_count
)

print("PDF report generated successfully!")
print("Location: reports/security_report.pdf")