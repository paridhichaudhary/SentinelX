# SentinelX - Alert Investigation

import json


def load_alerts():

    with open("logs/alerts.json", "r") as file:
        alerts = json.load(file)

    return alerts


def load_logs():

    with open("logs/sample_auth.log", "r") as file:
        logs = file.readlines()

    return logs


def investigate_alert(alert_id):

    alerts = load_alerts()
    logs = load_logs()

    selected_alert = None

    # Find the requested alert
    for alert in alerts:

        if alert["alert_id"] == alert_id:
            selected_alert = alert
            break

    if selected_alert is None:

        print("Alert not found.")
        return


    source_ip = selected_alert["source_ip"]

    print("===================================")
    print("      SENTINELX INVESTIGATION      ")
    print("===================================")

    print("Alert ID       :", selected_alert["alert_id"])
    print("Alert Type     :", selected_alert["alert_type"])
    print("Severity       :", selected_alert["severity"])
    print("Source IP      :", selected_alert["source_ip"])
    print("Username       :", selected_alert["username"])
    print("Failed Attempts:", selected_alert["failed_attempts"])
    print("Status         :", selected_alert["status"])

    print(
        "MITRE ATT&CK   :",
        selected_alert["mitre_attack"]["technique_id"],
        "-",
        selected_alert["mitre_attack"]["technique_name"]
    )

    print()
    print("========== RELATED EVENTS ==========")


    related_events = 0

    for log in logs:

        if f"source_ip={source_ip}" in log:

            print(log.strip())

            related_events += 1


    print("-----------------------------------")
    print("Related events:", related_events)


if __name__ == "__main__":

    investigate_alert("SX-0001")