# SentinelX - Log Processing Pipeline

from backend.alert_manager import save_alerts

from detections.brute_force import detect_brute_force
from detections.port_scan import detect_port_scan
from detections.suspicious_process import detect_suspicious_process


# ==========================================
# LOG FILES
# ==========================================

AUTH_LOG = "logs/sample_auth.log"

NETWORK_LOG = "logs/network.log"

PROCESS_LOG = "logs/process.log"


# ==========================================
# PROCESS LOGS
# ==========================================

def process_logs():

    print("==========================================")
    print("SentinelX Log Processing Started")
    print("==========================================")


    # ======================================
    # BRUTE FORCE
    # ======================================

    print("\n[1] Checking authentication logs...")

    brute_force_alerts = detect_brute_force(
        AUTH_LOG
    )

    print(
        "Brute-force alerts:",
        len(brute_force_alerts)
    )


    # ======================================
    # PORT SCAN
    # ======================================

    print("\n[2] Checking network logs...")

    port_scan_alerts = detect_port_scan(
        NETWORK_LOG
    )

    print(
        "Port-scan alerts:",
        len(port_scan_alerts)
    )


    # ======================================
    # SUSPICIOUS PROCESS
    # ======================================

    print("\n[3] Checking process logs...")

    suspicious_process_alerts = (
        detect_suspicious_process(
            PROCESS_LOG
        )
    )

    print(
        "Suspicious-process alerts:",
        len(suspicious_process_alerts)
    )


    # ======================================
    # COMBINE ALL ALERTS
    # ======================================

    all_alerts = (
        brute_force_alerts
        + port_scan_alerts
        + suspicious_process_alerts
    )


    print(
        "\nTotal detected alerts:",
        len(all_alerts)
    )


    # ======================================
    # SAVE ALERTS
    # ======================================

    save_alerts(
        all_alerts
    )


    print(
        "\nAlerts saved successfully."
    )

    print("==========================================")


# ==========================================
# RUN
# ==========================================

if __name__ == "__main__":

    process_logs()