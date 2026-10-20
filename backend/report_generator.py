# SentinelX - Incident Report Generator

import json
import os
from datetime import datetime


ALERT_FILE = "logs/alerts.json"
CASE_FILE = "cases/cases.json"
REPORT_FOLDER = "reports"


def load_json(file_path):

    if not os.path.exists(file_path):

        return []

    with open(
        file_path,
        "r"
    ) as file:

        try:

            return json.load(file)

        except json.JSONDecodeError:

            return []


def generate_report(alert_id):

    alerts = load_json(ALERT_FILE)

    cases = load_json(CASE_FILE)


    # Find alert

    alert = None

    for item in alerts:

        if item["alert_id"] == alert_id:

            alert = item

            break


    if alert is None:

        return None


    # Find investigation case

    case = None

    for item in cases:

        if item["alert_id"] == alert_id:

            case = item

            break


    # Create report

    report = {

        "report_id":
            "IR-" + alert_id,

        "generated_at":
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),

        "alert":

            {

                "alert_id":
                    alert["alert_id"],

                "timestamp":
                    alert["timestamp"],

                "alert_type":
                    alert["alert_type"],

                "severity":
                    alert["severity"],

                "source_ip":
                    alert.get(
                        "source_ip",
                        "N/A"
                    ),

                "username":
                    alert.get(
                        "username",
                        "N/A"
                    ),

                "description":
                    alert["description"]

            },

        "mitre_attack":
            alert.get(
                "mitre_attack",
                {}
            ),

        "investigation":
            case if case else {

                "status":
                    "No investigation recorded"

            }

    }


    # Create reports folder

    os.makedirs(
        REPORT_FOLDER,
        exist_ok=True
    )


    report_file = os.path.join(

        REPORT_FOLDER,

        alert_id + "_incident_report.json"

    )


    with open(
        report_file,
        "w"
    ) as file:

        json.dump(
            report,
            file,
            indent=4
        )


    return report_file