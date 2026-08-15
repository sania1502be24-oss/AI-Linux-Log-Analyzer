def calculate_threat_score(results):
    score = 0

    # Brute force attacks
    for _, count in results["brute_force"].items():
        score += count * 10

    # Invalid users
    score += len(results["invalid_users"]) * 5

    # Root logins
    score += len(results["root_attempts"]) * 25

    # Sudo abuse
    score += len(results["sudo_abuse"]) * 15

    if score > 100:
        score = 100

    return score