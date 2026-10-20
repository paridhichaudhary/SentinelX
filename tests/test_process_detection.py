# Test SentinelX Suspicious Process Detection

from detections.process_detection import (
    detect_suspicious_processes
)


log_file = "logs/process.log"


alerts = detect_suspicious_processes(
    log_file
)


print("Suspicious Process Detection Test")
print("----------------------------------")


if len(alerts) > 0:

    print("SUSPICIOUS PROCESS DETECTED")

    print()


    for alert in alerts:

        print(
            "Source IP:",
            alert["source_ip"]
        )

        print(
            "Username:",
            alert["username"]
        )

        print(
            "Process:",
            alert["process"]
        )

        print(
            "PID:",
            alert["pid"]
        )

        print(
            "Severity:",
            alert["severity"]
        )

        print(
            "MITRE:",
            alert["mitre_attack"]["technique_id"],
            "-",
            alert["mitre_attack"]["technique_name"]
        )

        print()

else:

    print(
        "NO SUSPICIOUS PROCESS DETECTED"
    )