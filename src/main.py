from parser import parse_logs
from detector import detect_attacks
from reporter import generate_report
from threat_score import calculate_threat_score
from email_alert import send_alert

# Parse logs
logs = parse_logs("data/auth.log")

print(f"Total Logs Parsed: {len(logs)}")

# Detect attacks
results = detect_attacks(logs)

# Calculate threat score
threat_score = calculate_threat_score(results)

print(f"\nOverall Threat Score: {threat_score}/100")

# Brute Force Attacks
print("\n=== BRUTE FORCE ATTEMPTS ===")

if results["brute_force"]:
    for ip, count in results["brute_force"].items():
        print(f"[HIGH] {ip} -> {count} failed attempts")
else:
    print("No brute force attacks detected.")

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
    len(results["privilege_escalation"])
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

Please review the security report immediately.
"""
    )