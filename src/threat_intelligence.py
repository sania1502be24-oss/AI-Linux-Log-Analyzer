KNOWN_MALICIOUS_IPS = {
    "192.168.1.250": "Root Attack Source",
    "192.168.1.200": "Brute Force Source",
    "10.0.0.50": "Blacklisted Host"
}


def detect_malicious_ips(logs):
    alerts = []

    for log in logs:
        message = log["message"]

        for ip, reason in KNOWN_MALICIOUS_IPS.items():
            if ip in message:
                alerts.append({
                    "ip": ip,
                    "reason": reason,
                    "severity": "CRITICAL"
                })

    return alerts