# SentinelX - Suspicious Process Detection

from datetime import datetime


SUSPICIOUS_PROCESSES = [
    "powershell.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe"
]


def detect_suspicious_processes(log_file):

    alerts = []


    with open(log_file, "r") as file:

        for line in file:

            line = line.strip()


            if not line:

                continue


            parts = line.split()


            timestamp_text = (
                parts[0] + " " + parts[1]
            )


            timestamp = datetime.strptime(
                timestamp_text,
                "%Y-%m-%d %H:%M:%S"
            )


            source_ip = None

            username = None

            process = None

            pid = None


            for part in parts:

                if part.startswith(
                    "source_ip="
                ):

                    source_ip = part.split("=")[1]


                elif part.startswith(
                    "username="
                ):

                    username = part.split("=")[1]


                elif part.startswith(
                    "process="
                ):

                    process = part.split("=")[1]


                elif part.startswith(
                    "pid="
                ):

                    pid = part.split("=")[1]


            if (
                process
                and process.lower()
                in SUSPICIOUS_PROCESSES
            ):

                alert = {

                    "timestamp":
                        timestamp.strftime(
                            "%Y-%m-%d %H:%M:%S"
                        ),

                    "alert_type":
                        "Suspicious Process",

                    "severity":
                        "MEDIUM",

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
                        f"Suspicious process "
                        f"{process} detected "
                        f"on host "
                        f"{source_ip} "
                        f"for user "
                        f"{username}"

                }


                alerts.append(alert)


    return alerts