import re

LOG_PATTERN = re.compile(
    r"^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+([\w/-]+)(?:\[\d+\])?:\s+(.*)$"
)

def parse_log_line(line):
    match = LOG_PATTERN.match(line)

    if not match:
        return None

    return {
        "timestamp": match.group(1),
        "hostname": match.group(2),
        "service": match.group(3),
        "message": match.group(4)
    }

def parse_logs(file_path):
    logs = []

    with open(file_path, "r") as file:
        for line in file:
            parsed = parse_log_line(line.strip())

            if parsed:
                logs.append(parsed)

    return logs