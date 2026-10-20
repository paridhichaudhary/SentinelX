# SentinelX - Alert Manager

import json
import os


ALERT_FILE = "logs/alerts.json"


def load_alerts():

    if not os.path.exists(ALERT_FILE):

        return []

    with open(
        ALERT_FILE,
        "r"
    ) as file:

        try:

            return json.load(file)

        except json.JSONDecodeError:

            return []


def save_alerts(new_alerts):

    existing_alerts = load_alerts()


    # ===================================
    # REMOVE TEMPORARY IDs
    # ===================================

    for alert in new_alerts:

        if alert.get("alert_id") == "TEMP":

            alert.pop(
                "alert_id",
                None
            )


    # ===================================
    # DEDUPLICATION
    # ===================================

    for new_alert in new_alerts:

        duplicate = False


        for old_alert in existing_alerts:

            same_type = (
                old_alert.get("alert_type")
                ==
                new_alert.get("alert_type")
            )


            same_ip = (
                old_alert.get("source_ip")
                ==
                new_alert.get("source_ip")
            )


            same_timestamp = (
                old_alert.get("timestamp")
                ==
                new_alert.get("timestamp")
            )


            same_process = (
                old_alert.get("process")
                ==
                new_alert.get("process")
            )


            if (
                same_type
                and same_ip
                and same_timestamp
                and same_process
            ):

                duplicate = True

                break


        if not duplicate:

            existing_alerts.append(
                new_alert
            )


    # ===================================
    # GENERATE STABLE ALERT IDs
    # ===================================

    for index, alert in enumerate(
        existing_alerts,
        start=1
    ):

        alert["alert_id"] = (
            f"SX-{index:04d}"
        )


    # ===================================
    # SAVE
    # ===================================

    with open(
        ALERT_FILE,
        "w"
    ) as file:

        json.dump(
            existing_alerts,
            file,
            indent=4
        )


    print(
        "Alerts saved successfully to "
        "logs/alerts.json"
    )