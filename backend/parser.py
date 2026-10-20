# SentinelX - Log Parser

def parse_log(log_line):
    parts = log_line.strip().split()

    timestamp = parts[0] + " " + parts[1]
    event_type = parts[2]

    username = parts[3].split("=")[1]
    source_ip = parts[4].split("=")[1]

    event = {
        "timestamp": timestamp,
        "event_type": event_type,
        "username": username,
        "source_ip": source_ip
    }

    return event