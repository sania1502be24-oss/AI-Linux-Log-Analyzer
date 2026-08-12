from parser import parse_logs
from detector import detect_failed_logins

logs = parse_logs("data/auth.log")

print(f"Total Logs Parsed: {len(logs)}")

suspicious_ips = detect_failed_logins(logs)

print("\n=== Suspicious Failed Login Attempts ===")

if suspicious_ips:
    for ip, count in suspicious_ips.items():
        print(f"{ip} -> {count} failed attempts")
else:
    print("No suspicious activity detected.")