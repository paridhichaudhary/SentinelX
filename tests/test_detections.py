# SentinelX - Detection Tests

from pathlib import Path

from detections.brute_force import detect_brute_force
from detections.port_scan import detect_port_scan
from detections.suspicious_process import detect_suspicious_process


# ==========================================
# PROJECT ROOT
# ==========================================

BASE_DIR = Path(__file__).resolve().parent.parent

AUTH_LOG = BASE_DIR / "logs" / "sample_auth.log"

NETWORK_LOG = BASE_DIR / "logs" / "network.log"

PROCESS_LOG = BASE_DIR / "logs" / "process.log"


# ==========================================
# TEST BRUTE FORCE
# ==========================================

def test_brute_force():

    alerts = detect_brute_force(
        str(AUTH_LOG)
    )

    assert len(alerts) > 0

    assert alerts[0]["alert_type"] == "Brute Force"

    assert (
        alerts[0]["mitre_attack"]["technique_id"]
        == "T1110"
    )


# ==========================================
# TEST PORT SCAN
# ==========================================

def test_port_scan():

    alerts = detect_port_scan(
        str(NETWORK_LOG)
    )

    assert len(alerts) > 0

    assert alerts[0]["alert_type"] == "Port Scan"

    assert (
        alerts[0]["mitre_attack"]["technique_id"]
        == "T1046"
    )


# ==========================================
# TEST SUSPICIOUS PROCESS
# ==========================================

def test_suspicious_process():

    alerts = detect_suspicious_process(
        str(PROCESS_LOG)
    )

    assert len(alerts) > 0

    assert (
        alerts[0]["alert_type"]
        == "Suspicious Process"
    )

    assert (
        alerts[0]["mitre_attack"]["technique_id"]
        == "T1059"
    )