from collections import Counter

def detect_attacks(logs):
    failed_ips = []
    invalid_users = []
    root_attempts = []
    sudo_abuse = []
    privilege_escalation = []

    for log in logs:
        message = log["message"]
        lower_message = message.lower()

        # Failed password attempts
        if "Failed password" in message:
            parts = message.split()

            if "from" in parts:
                ip = parts[parts.index("from") + 1]
                failed_ips.append(ip)

        # Invalid user attacks
        if "Invalid user" in message:
            invalid_users.append(message)

        # Successful root logins
        if "Accepted password for root" in message:
            root_attempts.append(message)

        # Sudo abuse detection
        sudo_patterns = [
            "sudo su",
            "sudo -i",
            "sudo bash",
            "sudo sh"
        ]

        for pattern in sudo_patterns:
            if pattern in lower_message:
                sudo_abuse.append(message)
                break

        # Privilege escalation detection
        privilege_patterns = [
            "su root",
            "usermod -ag sudo",
            "chmod 777"
        ]

        for pattern in privilege_patterns:
            if pattern in lower_message:
                privilege_escalation.append(message)
                break

    brute_force = {
        ip: count
        for ip, count in Counter(failed_ips).items()
        if count >= 3
    }

    return {
        "brute_force": brute_force,
        "invalid_users": invalid_users,
        "root_attempts": root_attempts,
        "sudo_abuse": sudo_abuse,
        "privilege_escalation": privilege_escalation
    }