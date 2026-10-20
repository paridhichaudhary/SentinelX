# SentinelX - FastAPI Backend

import json

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from backend.alert_manager import load_alerts
from backend.case_manager import load_cases, save_case
from backend.report_generator import generate_report


app = FastAPI(
    title="SentinelX Mini-SIEM",
    description="Beginner-level Security Operations Center API",
    version="1.0.0"
)


# ==========================================
# CORS CONFIGURATION
# ==========================================

app.add_middleware(
    CORSMiddleware,

    allow_origins=[
        "http://localhost:5500",
        "http://127.0.0.1:5500"
    ],

    allow_credentials=True,

    allow_methods=["*"],

    allow_headers=["*"]
)


# ==========================================
# STATUS MODEL
# ==========================================

class StatusUpdate(BaseModel):

    status: str


# ==========================================
# CASE MODEL
# ==========================================

class CaseCreate(BaseModel):

    analyst: str

    notes: str

    action: str


# ==========================================
# HOME
# ==========================================

@app.get("/")
def home():

    return {
        "message": "SentinelX Mini-SIEM API is running"
    }


# ==========================================
# GET ALL ALERTS
# ==========================================

@app.get("/alerts")
def get_alerts():

    alerts = load_alerts()

    return {
        "total": len(alerts),
        "alerts": alerts
    }


# ==========================================
# GET ONE ALERT
# ==========================================

@app.get("/alerts/{alert_id}")
def get_alert(alert_id: str):

    alerts = load_alerts()

    for alert in alerts:

        if alert["alert_id"] == alert_id:

            return alert

    raise HTTPException(
        status_code=404,
        detail="Alert not found"
    )


# ==========================================
# SOC STATISTICS
# ==========================================

@app.get("/stats")
def get_stats():

    alerts = load_alerts()

    high = 0
    medium = 0
    low = 0

    new = 0
    investigating = 0
    resolved = 0

    by_type = {}

    for alert in alerts:

        severity = alert.get(
            "severity",
            "LOW"
        )

        status = alert.get(
            "status",
            "NEW"
        )

        alert_type = alert.get(
            "alert_type",
            "Unknown"
        )

        # Severity

        if severity == "HIGH":

            high += 1

        elif severity == "MEDIUM":

            medium += 1

        elif severity == "LOW":

            low += 1

        # Status

        if status == "NEW":

            new += 1

        elif status == "INVESTIGATING":

            investigating += 1

        elif status == "RESOLVED":

            resolved += 1

        # Alert type

        if alert_type not in by_type:

            by_type[alert_type] = 0

        by_type[alert_type] += 1

    return {

        "total_alerts":
            len(alerts),

        "high":
            high,

        "medium":
            medium,

        "low":
            low,

        "new":
            new,

        "investigating":
            investigating,

        "resolved":
            resolved,

        "by_type":
            by_type

    }


# ==========================================
# GET ALL CASES
# ==========================================

@app.get("/cases")
def get_cases():

    cases = load_cases()

    return {

        "total":
            len(cases),

        "cases":
            cases

    }


# ==========================================
# GET CASE FOR ALERT
# ==========================================

@app.get("/alerts/{alert_id}/case")
def get_alert_case(
    alert_id: str
):

    cases = load_cases()

    for case in cases:

        if case["alert_id"] == alert_id:

            return case

    raise HTTPException(
        status_code=404,
        detail="No investigation case found"
    )


# ==========================================
# CREATE / UPDATE CASE
# ==========================================

@app.post("/alerts/{alert_id}/case")
def create_case(
    alert_id: str,
    case_data: CaseCreate
):

    alerts = load_alerts()

    # Check alert exists

    alert_exists = False

    for alert in alerts:

        if alert["alert_id"] == alert_id:

            alert_exists = True

            break

    if not alert_exists:

        raise HTTPException(
            status_code=404,
            detail="Alert not found"
        )

    # Save investigation

    case = save_case(

        alert_id,

        case_data.analyst,

        case_data.notes,

        case_data.action

    )

    return {

        "message":
            "Investigation case saved",

        "case":
            case

    }


# ==========================================
# UPDATE ALERT STATUS
# ==========================================

@app.put("/alerts/{alert_id}/status")
def update_alert_status(
    alert_id: str,
    status_update: StatusUpdate
):

    allowed_statuses = [
        "NEW",
        "INVESTIGATING",
        "RESOLVED"
    ]

    if status_update.status not in allowed_statuses:

        raise HTTPException(
            status_code=400,
            detail="Invalid alert status"
        )

    alerts = load_alerts()

    for alert in alerts:

        if alert["alert_id"] == alert_id:

            alert["status"] = (
                status_update.status
            )

            with open(
                "logs/alerts.json",
                "w"
            ) as file:

                json.dump(
                    alerts,
                    file,
                    indent=4
                )

            return {

                "message":
                    "Alert status updated",

                "alert_id":
                    alert_id,

                "status":
                    alert["status"]

            }

    raise HTTPException(
        status_code=404,
        detail="Alert not found"
    )


# ==========================================
# GENERATE INCIDENT REPORT
# ==========================================

@app.post("/alerts/{alert_id}/report")
def create_incident_report(
    alert_id: str
):

    report_file = generate_report(
        alert_id
    )

    if report_file is None:

        raise HTTPException(
            status_code=404,
            detail="Alert not found"
        )

    return {

        "message":
            "Incident report generated",

        "alert_id":
            alert_id,

        "report_file":
            report_file

    }