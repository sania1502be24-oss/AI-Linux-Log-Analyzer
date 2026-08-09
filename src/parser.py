import os

log_path = os.path.join("data", "auth.log")

with open(log_path, "r") as file:
    logs = file.readlines()

print("=== Linux Logs ===\n")

for log in logs:
    print(log.strip())