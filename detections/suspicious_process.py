# SentinelX - Suspicious Process Detection


def detect_suspicious_process(log_file):

    alerts = []

    suspicious_processes = [
        "powershell.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe"
    ]

    with open(log_file, "r") as file:

        for line in file:

            line = line.strip()

            if not line:
                continue

            # Example:
            # 2026-10-20 12:00:10 process
            # source_ip=192.168.1.20
            # username=user1
            # process=powershell.exe
            # pid=2300

            parts = line.split()

            if len(parts) < 6:
                continue

            # Timestamp
            timestamp = parts[0] + " " + parts[1]

            # Event type
            event_type = parts[2]

            if event_type.lower() != "process":
                continue

            # Default values
            source_ip = None
            username = None
            process = None
            pid = None

            # Extract key=value fields
            for part in parts[3:]:

                if part.startswith("source_ip="):

                    source_ip = part.split("=", 1)[1]

                elif part.startswith("username="):

                    username = part.split("=", 1)[1]

                elif part.startswith("process="):

                    process = part.split("=", 1)[1]

                elif part.startswith("pid="):

                    pid = part.split("=", 1)[1]

            # Ignore incomplete records
            if process is None:
                continue

            # Detect suspicious process
            if process.lower() in suspicious_processes:

                alert = {

                    "alert_type":
                        "Suspicious Process",

                    "severity":
                        "MEDIUM",

                    "timestamp":
                        timestamp,

                    "source_ip":
                        source_ip,

                    "username":
                        username,

                    "process":
                        process,

                    "pid":
                        pid,

                    "status":
                        "NEW",

                    "mitre_attack": {

                        "technique_id":
                            "T1059",

                        "technique_name":
                            "Command and Scripting Interpreter"

                    },

                    "description":
                        (
                            f"Suspicious process "
                            f"{process} detected for "
                            f"user {username} "
                            f"from {source_ip}."
                        )
                }

                alerts.append(alert)

    return alerts