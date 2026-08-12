from collections import Counter

def detect_failed_logins(logs):
    failed_ips = []

    for log in logs:
        message = log["message"]

        if "Failed password" in message:
            parts = message.split()

            if "from" in parts:
                ip = parts[parts.index("from") + 1]
                failed_ips.append(ip)

    ip_counts = Counter(failed_ips)

    suspicious = {
        ip: count
        for ip, count in ip_counts.items()
        if count >= 3
    }

    return suspicious