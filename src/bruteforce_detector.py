import re
from collections import defaultdict


def detect_bruteforce(logs):
    ip_attempts = defaultdict(int)

    for log in logs:
        message = log["message"]

        if "Failed password" in message:
            match = re.search(
                r'from (\d+\.\d+\.\d+\.\d+)',
                message
            )

            if match:
                ip = match.group(1)
                ip_attempts[ip] += 1

    brute_force_alerts = []

    for ip, count in ip_attempts.items():
        if count >= 5:
            brute_force_alerts.append({
                "ip": ip,
                "attempts": count,
                "severity": "CRITICAL"
            })

    return brute_force_alerts