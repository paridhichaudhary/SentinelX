# SentinelX - Case Manager

import json
import os
from datetime import datetime


CASE_FILE = "cases/cases.json"


# ==========================================
# LOAD CASES
# ==========================================

def load_cases():

    if not os.path.exists(CASE_FILE):

        return []

    with open(
        CASE_FILE,
        "r"
    ) as file:

        try:

            return json.load(file)

        except json.JSONDecodeError:

            return []


# ==========================================
# SAVE CASE
# ==========================================

def save_case(
    alert_id,
    analyst,
    notes,
    action
):

    cases = load_cases()


    # Check whether a case
    # already exists for alert

    for case in cases:

        if case["alert_id"] == alert_id:

            case["analyst"] = analyst

            case["notes"] = notes

            case["action"] = action

            case["updated_at"] = (
                datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            )

            with open(
                CASE_FILE,
                "w"
            ) as file:

                json.dump(
                    cases,
                    file,
                    indent=4
                )

            return case


    # Create new case

    case = {

        "alert_id":
            alert_id,

        "analyst":
            analyst,

        "notes":
            notes,

        "action":
            action,

        "created_at":
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),

        "updated_at":
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )

    }


    cases.append(case)


    with open(
        CASE_FILE,
        "w"
    ) as file:

        json.dump(
            cases,
            file,
            indent=4
        )


    return case