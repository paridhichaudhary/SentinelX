# SentinelX - Incident Report Generator

import json
from datetime import datetime


ALERT_FILE = "logs/alerts.json"


def load_alerts():

    with open(ALERT_FILE, "r") as file:

        return json.load(file)


def find_alert(alert_id):

    alerts = load_alerts()

    for alert in alerts:

        if alert["alert_id"] == alert_id:

            return alert

    return None


def generate_report(alert_id):

    alert = find_alert(alert_id)


    if alert is None:

        print("Alert not found.")

        return


    print()
    print("=" * 60)
    print("             SENTINELX INCIDENT REPORT")
    print("=" * 60)
    print()


    print("Alert ID:", alert["alert_id"])

    print(
        "Incident Type:",
        alert["alert_type"]
    )

    print(
        "Severity:",
        alert["severity"]
    )

    print(
        "Timestamp:",
        alert["timestamp"]
    )

    print()


    print("SOURCE INFORMATION")
    print("-" * 60)

    print(
        "Source IP:",
        alert["source_ip"]
    )


    if alert["alert_type"] == "Brute Force":

        print(
            "Target Username:",
            alert["username"]
        )

        print(
            "Failed Attempts:",
            alert["failed_attempts"]
        )

        print(
            "Time Window:",
            alert["time_window_seconds"],
            "seconds"
        )


    elif alert["alert_type"] == "Port Scan":

        print(
            "Destination IP:",
            alert["destination_ip"]
        )

        print(
            "Unique Ports:",
            alert["unique_ports"]
        )

        print(
            "Ports Scanned:",
            alert["ports"]
        )


    print()


    print("DETECTION")
    print("-" * 60)

    print(
        alert["description"]
    )

    print()


    print("MITRE ATT&CK")
    print("-" * 60)

    print(
        "Technique ID:",
        alert["mitre_attack"]["technique_id"]
    )

    print(
        "Technique:",
        alert["mitre_attack"]["technique_name"]
    )

    print()


    print("ALERT STATUS")
    print("-" * 60)

    print(
        "Current Status:",
        alert["status"]
    )

    print()


    print("RECOMMENDED ACTIONS")
    print("-" * 60)


    if alert["alert_type"] == "Brute Force":

        print(
            "1. Investigate the source IP."
        )

        print(
            "2. Check whether the account was compromised."
        )

        print(
            "3. Review successful logins after the failures."
        )

        print(
            "4. Consider blocking the source IP."
        )

        print(
            "5. Recommend stronger authentication."
        )


    elif alert["alert_type"] == "Port Scan":

        print(
            "1. Investigate the source IP."
        )

        print(
            "2. Identify the host generating the scan."
        )

        print(
            "3. Review additional network activity."
        )

        print(
            "4. Determine whether the scan was authorized."
        )

        print(
            "5. Monitor the source for further activity."
        )


    print()

    print("=" * 60)

    print(
        "Report generated:",
        datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    )

    print("=" * 60)


if __name__ == "__main__":

    print("Available SentinelX Alerts")
    print("---------------------------")


    alerts = load_alerts()


    for alert in alerts:

        print(
            alert["alert_id"],
            "-",
            alert["alert_type"],
            "-",
            alert["severity"]
        )


    print()


    alert_id = input(
        "Enter Alert ID to investigate: "
    )


    generate_report(alert_id)