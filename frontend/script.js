// ==========================================
// SentinelX SOC Dashboard
// ==========================================

const API_URL = "http://127.0.0.1:8000";

let alerts = [];
let selectedAlert = null;


// ==========================================
// LOAD DASHBOARD
// ==========================================

async function loadDashboard() {

    try {

        await loadStats();

        await loadAlerts();

    } catch (error) {

        console.error(
            "Dashboard error:",
            error
        );

    }

}


// ==========================================
// LOAD STATISTICS
// ==========================================

async function loadStats() {

    const response = await fetch(
        `${API_URL}/stats`
    );

    const data = await response.json();


    document.getElementById(
        "totalAlerts"
    ).textContent = data.total_alerts;


    document.getElementById(
        "highAlerts"
    ).textContent = data.high;


    document.getElementById(
        "newAlerts"
    ).textContent = data.new;

}


// ==========================================
// LOAD ALERTS
// ==========================================

async function loadAlerts() {

    const response = await fetch(
        `${API_URL}/alerts`
    );

    const data = await response.json();

    alerts = data.alerts;

    displayAlerts(alerts);

}


// ==========================================
// DISPLAY ALERTS
// ==========================================

function displayAlerts(alertList) {

    const tableBody =
        document.getElementById(
            "alertTableBody"
        );


    tableBody.innerHTML = "";


    alertList.forEach(
        (alert) => {

            const row =
                document.createElement(
                    "tr"
                );


            row.innerHTML = `

                <td>
                    ${alert.alert_id}
                </td>

                <td>
                    ${alert.alert_type}
                </td>

                <td>
                    ${alert.severity}
                </td>

                <td>
                    ${alert.source_ip}
                </td>

                <td>
                    ${alert.status}
                </td>

                <td>

                    <button
                        class="alert-button"
                        onclick="selectAlert('${alert.alert_id}')"
                    >
                        Investigate
                    </button>

                </td>

            `;


            tableBody.appendChild(row);

        }
    );

}


// ==========================================
// SELECT ALERT
// ==========================================

async function selectAlert(alertId) {

    try {

        const response =
            await fetch(
                `${API_URL}/alerts/${alertId}`
            );


        if (!response.ok) {

            throw new Error(
                "Alert not found"
            );

        }


        selectedAlert =
            await response.json();


        displayInvestigation(
            selectedAlert
        );


        await loadCase(
            alertId
        );

    } catch (error) {

        console.error(
            "Alert error:",
            error
        );

    }

}


// ==========================================
// DISPLAY INVESTIGATION
// ==========================================

function displayInvestigation(alert) {

    document.getElementById(
        "investigationPanel"
    ).style.display = "block";


    document.getElementById(
        "investigationAlertId"
    ).textContent =
        alert.alert_id;


    document.getElementById(
        "investigationType"
    ).textContent =
        alert.alert_type;


    document.getElementById(
        "investigationSeverity"
    ).textContent =
        alert.severity;


    document.getElementById(
        "investigationIP"
    ).textContent =
        alert.source_ip;


    document.getElementById(
        "investigationUser"
    ).textContent =
        alert.username || "N/A";


    document.getElementById(
        "investigationAttempts"
    ).textContent =
        alert.failed_attempts || "N/A";


    document.getElementById(
        "investigationMITRE"
    ).textContent =

        alert.mitre_attack
        ? `${alert.mitre_attack.technique_id} - ${alert.mitre_attack.technique_name}`
        : "N/A";


    document.getElementById(
        "investigationDescription"
    ).textContent =
        alert.description;


    document.getElementById(
        "alertStatus"
    ).value =
        alert.status;

}


// ==========================================
// LOAD CASE
// ==========================================

async function loadCase(alertId) {

    try {

        const response =
            await fetch(
                `${API_URL}/alerts/${alertId}/case`
            );


        if (!response.ok) {

            clearCaseFields();

            return;

        }


        const caseData =
            await response.json();


        document.getElementById(
            "analystName"
        ).value =
            caseData.analyst || "";


        document.getElementById(
            "investigationNotes"
        ).value =
            caseData.notes || "";


        document.getElementById(
            "investigationAction"
        ).value =
            caseData.action || "";


    } catch (error) {

        clearCaseFields();

    }

}


// ==========================================
// CLEAR CASE FIELDS
// ==========================================

function clearCaseFields() {

    document.getElementById(
        "analystName"
    ).value = "";


    document.getElementById(
        "investigationNotes"
    ).value = "";


    document.getElementById(
        "investigationAction"
    ).value = "";

}


// ==========================================
// UPDATE STATUS
// ==========================================

async function updateStatus() {

    if (!selectedAlert) {

        return;

    }


    const status =
        document.getElementById(
            "alertStatus"
        ).value;


    try {

        const response =
            await fetch(
                `${API_URL}/alerts/${selectedAlert.alert_id}/status`,
                {

                    method: "PUT",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({
                        status: status
                    })

                }
            );


        const data =
            await response.json();


        if (!response.ok) {

            throw new Error(
                data.detail ||
                "Status update failed"
            );

        }


        document.getElementById(
            "statusMessage"
        ).textContent =
            "Status updated successfully.";


        await loadDashboard();


        selectedAlert.status =
            status;


    } catch (error) {

        document.getElementById(
            "statusMessage"
        ).textContent =
            error.message;

    }

}


// ==========================================
// SAVE INVESTIGATION CASE
// ==========================================

async function saveInvestigation() {

    if (!selectedAlert) {

        return;

    }


    const analyst =
        document.getElementById(
            "analystName"
        ).value;


    const notes =
        document.getElementById(
            "investigationNotes"
        ).value;


    const action =
        document.getElementById(
            "investigationAction"
        ).value;


    if (
        analyst.trim() === "" ||
        notes.trim() === "" ||
        action.trim() === ""
    ) {

        document.getElementById(
            "caseMessage"
        ).textContent =
            "Please complete all investigation fields.";

        return;

    }


    try {

        const response =
            await fetch(
                `${API_URL}/alerts/${selectedAlert.alert_id}/case`,
                {

                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({

                        analyst: analyst,

                        notes: notes,

                        action: action

                    })

                }
            );


        const data =
            await response.json();


        if (!response.ok) {

            throw new Error(
                data.detail ||
                "Case save failed"
            );

        }


        document.getElementById(
            "caseMessage"
        ).textContent =
            "Investigation case saved successfully.";

    } catch (error) {

        document.getElementById(
            "caseMessage"
        ).textContent =
            error.message;

    }

}


// ==========================================
// GENERATE INCIDENT REPORT
// ==========================================

async function generateIncidentReport() {

    if (!selectedAlert) {

        return;

    }


    try {

        const response =
            await fetch(
                `${API_URL}/alerts/${selectedAlert.alert_id}/report`,
                {

                    method: "POST"

                }
            );


        const data =
            await response.json();


        if (!response.ok) {

            throw new Error(
                data.detail ||
                "Report generation failed"
            );

        }


        document.getElementById(
            "reportMessage"
        ).textContent =
            "Incident report generated successfully.";


        console.log(
            "Report:",
            data.report_file
        );


    } catch (error) {

        document.getElementById(
            "reportMessage"
        ).textContent =
            error.message;

    }

}


// ==========================================
// REFRESH BUTTON
// ==========================================

async function refreshDashboard() {

    await loadDashboard();

}


// ==========================================
// START DASHBOARD
// ==========================================

document.addEventListener(
    "DOMContentLoaded",
    function () {

        loadDashboard();

    }
);