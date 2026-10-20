# SentinelX - Brute Force Detection

from datetime import datetime


def detect_brute_force(log_file):

    failed_logins = []

    alerts = []


    # Read the authentication log

    with open(log_file, "r") as file:

        for line in file:

            line = line.strip()


            if not line:

                continue


            parts = line.split()


            # First two values are date and time

            timestamp = (
                parts[0] + " " + parts[1]
            )


            source_ip = None

            username = None

            event_type = None


            # Read key=value information

            for part in parts[2:]:

                if part.startswith(
                    "source_ip="
                ):

                    source_ip = part.split(
                        "=",
                        1
                    )[1]


                elif part.startswith(
                    "username="
                ):

                    username = part.split(
                        "=",
                        1
                    )[1]


                elif part.startswith(
                    "event_type="
                ):

                    event_type = part.split(
                        "=",
                        1
                    )[1]


            # Support our current sample log format

            if "login_failed" in line.lower():

                event_type = "LOGIN_FAILED"


            # Store failed login

            if event_type == "LOGIN_FAILED":

                failed_logins.append({

                    "timestamp": timestamp,

                    "source_ip": source_ip,

                    "username": username

                })


    # ===================================
    # Detect 5 failed attempts
    # ===================================

    if len(failed_logins) >= 5:

        first_event = failed_logins[0]

        last_event = failed_logins[4]


        first_time = datetime.strptime(
            first_event["timestamp"],
            "%Y-%m-%d %H:%M:%S"
        )


        last_time = datetime.strptime(
            last_event["timestamp"],
            "%Y-%m-%d %H:%M:%S"
        )


        time_difference = (
            last_time - first_time
        ).total_seconds()


        # Only alert if attempts happened
        # within 120 seconds

        if time_difference <= 120:

            alert = {

                "alert_id":
                    "TEMP",

                "timestamp":
                    last_event["timestamp"],

                "alert_type":
                    "Brute Force",

                "severity":
                    "HIGH",

                "source_ip":
                    first_event["source_ip"],

                "username":
                    first_event["username"],

                "failed_attempts":
                    len(failed_logins),

                "time_window_seconds":
                    int(time_difference),

                "status":
                    "NEW",

                "mitre_attack": {

                    "technique_id":
                        "T1110",

                    "technique_name":
                        "Brute Force"

                },

                "description":
                    f"{len(failed_logins)} failed "
                    f"login attempts detected from "
                    f"{first_event['source_ip']} "
                    f"within "
                    f"{int(time_difference)} seconds"

            }


            alerts.append(alert)


    return alerts