
from collections import defaultdict
from hashlib import sha256


SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
}


RECOMMENDATIONS = {
    "Brute Force": [
        "Review failed login attempts and authentication logs.",
        "Check whether any login succeeded after repeated failures.",
        "Consider rate limiting and appropriate account protection.",
    ],
    "Invalid User": [
        "Verify whether the attempted username is expected.",
        "Review nearby authentication events for the same source.",
    ],
    "Root Login": [
        "Verify whether direct root access is authorized.",
        "Review the login source and surrounding authentication events.",
    ],
    "Sudo Abuse": [
        "Review sudo commands and authorization records.",
        "Verify the activity against approved administrative tasks.",
    ],
    "Privilege Escalation": [
        "Inspect the command and related authentication events.",
        "Verify the account's permissions and recent system changes.",
    ],
}


def build_incidents(logs, detection_results):
    """
    Build investigation incidents from parsed logs and detector output.

    Expected log fields:
        timestamp, hostname, service, message

    Expected detection_results:
        Dictionary returned by src.detector.detect_attacks().
    """
    grouped = defaultdict(list)

    # Group related events by source IP when available.
    for log in logs:
        message = str(log.get("message", ""))
        source_ip = _extract_source_ip(message)
        lower = message.lower()

        if "failed password" in lower:
            event_type = "Authentication Failure"
        elif "invalid user" in lower:
            event_type = "Invalid User"
        elif "accepted password for root" in lower:
            event_type = "Root Login"
        elif any(
            pattern in lower
            for pattern in ("sudo su", "sudo -i", "sudo bash", "sudo sh")
        ):
            event_type = "Sudo Abuse"
        elif any(
            pattern in lower
            for pattern in ("su root", "usermod -ag sudo", "chmod 777")
        ):
            event_type = "Privilege Escalation"
        else:
            continue

        # Avoid combining unrelated unknown-source events.
        key = source_ip or f"unknown:{event_type}"
        grouped[key].append({
            "Timestamp": log.get("timestamp", "Unknown"),
            "Hostname": log.get("hostname", "Unknown"),
            "Service": log.get("service", "Unknown"),
            "Event": event_type,
            "Evidence": message,
        })

    incidents = []

    for source, evidence in grouped.items():
        event_types = {item["Event"] for item in evidence}

        if "Privilege Escalation" in event_types:
            severity = "CRITICAL"
        elif "Root Login" in event_types or "Sudo Abuse" in event_types:
            severity = "HIGH"
        elif "Invalid User" in event_types:
            severity = "MEDIUM"
        else:
            # Three or more failed attempts are the existing detector's
            # brute-force threshold.
            failures = sum(
                item["Event"] == "Authentication Failure"
                for item in evidence
            )
            severity = "HIGH" if failures >= 3 else "LOW"

        fingerprint = sha256(
            f"{source}|{'|'.join(sorted(event_types))}".encode("utf-8")
        ).hexdigest()[:10].upper()

        recommendations = []
        for event_type in sorted(event_types):
            if event_type == "Authentication Failure":
                recommendations.extend(RECOMMENDATIONS["Brute Force"])
            else:
                recommendations.extend(
                    RECOMMENDATIONS.get(event_type, [])
                )

        # Preserve recommendation order while removing duplicates.
        recommendations = list(dict.fromkeys(recommendations))

        incidents.append({
            "Incident ID": f"INC-{fingerprint}",
            "Severity": severity,
            "Source": source if not source.startswith("unknown:") else "Unknown",
            "Event Types": ", ".join(sorted(event_types)),
            "Event Count": len(evidence),
            "First Seen": min(
                item["Timestamp"] for item in evidence
            ),
            "Last Seen": max(
                item["Timestamp"] for item in evidence
            ),
            "Evidence": evidence,
            "Recommendations": recommendations,
        })

    incidents.sort(
        key=lambda item: (
            SEVERITY_ORDER[item["Severity"]],
            item["Event Count"],
        ),
        reverse=True,
    )

    return incidents


def _extract_source_ip(message):
    """Extract an IPv4 address from common SSH authentication messages."""
    import re

    match = re.search(
        r"\b(?:from|rhost=)\s*(\d{1,3}(?:\.\d{1,3}){3})",
        message,
        flags=re.IGNORECASE,
    )

    if not match:
        return None

    candidate = match.group(1)
    octets = candidate.split(".")

    if all(0 <= int(part) <= 255 for part in octets):
        return candidate

    return None