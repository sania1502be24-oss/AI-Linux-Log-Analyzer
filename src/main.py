from parser import parse_log_line

LOG_FILE = "../data/auth.log"

with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as file:
    for line in file:
        result = parse_log_line(line.strip())

        if result:
            print(result)