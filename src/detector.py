from collections import Counter

def detect_attacks(logs):
    failed_ips = []
    invalid_users = []
    root_attempts = []

    for log in logs:
        message = log["message"]

        # Failed password attempts
        if "Failed password" in message:
            parts = message.split()

            if "from" in parts:
                ip = parts[parts.index("from") + 1]
                failed_ips.append(ip)

        # Invalid user attacks
        if "Invalid user" in message:
            invalid_users.append(message)

        # Root login attempts
        if "for root" in message:
            root_attempts.append(message)

    brute_force = {
        ip: count
        for ip, count in Counter(failed_ips).items()
        if count >= 3
    }

    return {
        "brute_force": brute_force,
        "invalid_users": invalid_users,
        "root_attempts": root_attempts
    }