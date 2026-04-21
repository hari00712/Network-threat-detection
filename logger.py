import time
import os

LOG_FILE = "logs.txt"


def write_log(message):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {message}"

    print(log_entry)

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(log_entry + "\n")