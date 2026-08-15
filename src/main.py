from parser import parse_logs
from detector import detect_attacks
from reporter import generate_report
from threat_score import calculate_threat_score

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

# Generate Report
report = generate_report(results, len(logs))

with open("reports/security_report.txt", "w") as file:
    file.write(report)

print("\nReport generated successfully!")
print("Location: reports/security_report.txt")