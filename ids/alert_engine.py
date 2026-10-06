"""
Alert Engine for the Network IDS Simulation.

Creates and manages IDS security alerts.
"""

from datetime import datetime, timezone
import uuid


ALERT_STATUSES = {
    "NEW",
    "INVESTIGATING",
    "RESOLVED",
    "FALSE_POSITIVE",
}


def generate_alert_id():
    """Generate a unique alert ID."""
    return f"ALERT-{uuid.uuid4().hex[:8].upper()}"


def generate_timestamp():
    """Generate a UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


def build_alert_description(
    classification,
    matched_rules,
    anomaly_score,
    risk_score,
):
    """Build a human-readable alert description."""

    if matched_rules:
        rule_names = []

        for rule in matched_rules:
            if isinstance(rule, dict):
                rule_id = rule.get("rule_id", "UNKNOWN_RULE")
                rule_names.append(rule_id)
            else:
                rule_names.append(str(rule))

        rules_text = ", ".join(rule_names)

        return (
            f"Potential suspicious network activity detected. "
            f"Matched rules: {rules_text}. "
            f"Anomaly score: {anomaly_score:.2f}. "
            f"Risk score: {risk_score:.2f}. "
            f"Classification: {classification}."
        )

    return (
        f"Network flow analyzed with classification "
        f"{classification}. "
        f"Anomaly score: {anomaly_score:.2f}. "
        f"Risk score: {risk_score:.2f}."
    )


def generate_alert(
    flow,
    rule_results,
    anomaly_results,
    risk_results,
):
    """
    Generate an alert from IDS detection results.

    Parameters:
        flow: Network flow dictionary.
        rule_results: Results from the rule engine.
        anomaly_results: Results from the anomaly detector.
        risk_results: Results from the risk engine.
    """

    # --------------------------------------------------
    # Safely read rule results
    # --------------------------------------------------

    if not isinstance(rule_results, dict):
        rule_results = {}

    matched_rules = rule_results.get("matched_rules", [])

    if not isinstance(matched_rules, list):
        matched_rules = []

    # --------------------------------------------------
    # Safely read anomaly results
    # --------------------------------------------------

    if isinstance(anomaly_results, dict):
        anomaly_score = anomaly_results.get(
            "anomaly_score",
            0.0
        )

    else:
        # Supports a plain numerical anomaly score too.
        anomaly_score = anomaly_results

    try:
        anomaly_score = float(anomaly_score)
    except (TypeError, ValueError):
        anomaly_score = 0.0

    anomaly_score = max(
        0.0,
        min(100.0, anomaly_score)
    )

    # --------------------------------------------------
    # Safely read risk results
    # --------------------------------------------------

    if not isinstance(risk_results, dict):
        risk_results = {}

    risk_score = risk_results.get(
        "risk_score",
        0.0
    )

    try:
        risk_score = float(risk_score)
    except (TypeError, ValueError):
        risk_score = 0.0

    risk_score = max(
        0.0,
        min(100.0, risk_score)
    )

    classification = risk_results.get(
        "classification",
        "NORMAL"
    )

    severity = risk_results.get(
        "severity",
        "INFO"
    )

    # --------------------------------------------------
    # Only create an alert for suspicious activity
    # --------------------------------------------------

    suspicious = (
        bool(rule_results.get("suspicious", False))
        or anomaly_score > 40
        or risk_score > 40
    )

    if not suspicious:
        return None

    # --------------------------------------------------
    # Build alert
    # --------------------------------------------------

    alert = {
        "alert_id": generate_alert_id(),
        "timestamp": generate_timestamp(),

        "flow_id": flow.get(
            "flow_id",
            "UNKNOWN_FLOW"
        ),

        "source_ip": flow.get(
            "source_ip",
            "UNKNOWN"
        ),

        "destination_ip": flow.get(
            "destination_ip",
            "UNKNOWN"
        ),

        "protocol": flow.get(
            "protocol",
            "UNKNOWN"
        ),

        "source_port": flow.get(
            "source_port",
            0
        ),

        "destination_port": flow.get(
            "destination_port",
            0
        ),

        "rule_id": (
            matched_rules[0].get("rule_id", "NONE")
            if matched_rules
            and isinstance(matched_rules[0], dict)
            else "NONE"
        ),

        "alert_type": (
            "RULE_MATCH"
            if matched_rules
            else "ANOMALY_DETECTED"
        ),

        "severity": severity,

        "risk_score": round(
            risk_score,
            2
        ),

        "anomaly_score": round(
            anomaly_score,
            2
        ),

        "classification": classification,

        "matched_rules": matched_rules,

        "description": build_alert_description(
            classification,
            matched_rules,
            anomaly_score,
            risk_score,
        ),

        "status": "NEW",

        "analyst_notes": "",

        "resolution_notes": "",
    }

    return alert


def validate_alert(alert):
    """Validate an alert dictionary."""

    if not isinstance(alert, dict):
        return False

    required_fields = [
        "alert_id",
        "timestamp",
        "source_ip",
        "destination_ip",
        "protocol",
        "severity",
        "risk_score",
        "status",
        "description",
    ]

    for field in required_fields:
        if field not in alert:
            return False

    if alert["status"] not in ALERT_STATUSES:
        return False

    try:
        risk_score = float(alert["risk_score"])
    except (TypeError, ValueError):
        return False

    if not 0 <= risk_score <= 100:
        return False

    return True


def update_alert_status(
    alert,
    new_status,
    notes=None,
):
    """
    Update the status of an alert.

    Valid statuses:
        NEW
        INVESTIGATING
        RESOLVED
        FALSE_POSITIVE
    """

    if not isinstance(alert, dict):
        return False

    if new_status not in ALERT_STATUSES:
        return False

    alert["status"] = new_status

    if notes is not None:
        if new_status in {
            "RESOLVED",
            "FALSE_POSITIVE",
        }:
            alert["resolution_notes"] = str(notes)
        else:
            alert["analyst_notes"] = str(notes)

    return True


def demo():
    """Demonstrate the alert engine."""

    flow = {
        "flow_id": "FLOW-DEMO-001",
        "timestamp": generate_timestamp(),
        "source_ip": "192.0.2.10",
        "destination_ip": "198.51.100.20",
        "source_port": 45000,
        "destination_port": 22,
        "protocol": "TCP",
    }

    rule_results = {
        "suspicious": True,
        "matched_rules": [
            {
                "rule_id": "HIGH_CONNECTION_RATE",
                "description": "Connection rate is unusually high.",
            }
        ],
        "rule_count": 1,
    }

    anomaly_results = {
        "anomaly_score": 72.5,
        "classification": "SUSPICIOUS",
    }

    risk_results = {
        "risk_score": 68.0,
        "classification": "HIGH RISK",
        "severity": "HIGH",
    }

    alert = generate_alert(
        flow,
        rule_results,
        anomaly_results,
        risk_results,
    )

    print("\n=== Alert Engine Demo ===")

    if alert is None:
        print("No alert generated.")

    else:
        print("Alert ID:", alert["alert_id"])
        print("Severity:", alert["severity"])
        print("Risk Score:", alert["risk_score"])
        print("Anomaly Score:", alert["anomaly_score"])
        print("Classification:", alert["classification"])
        print("Status:", alert["status"])
        print("Description:", alert["description"])

        print("\nValidation:")
        print(validate_alert(alert))

        print("\nUpdating status...")

        update_alert_status(
            alert,
            "INVESTIGATING",
            "Analyst is reviewing the suspicious activity."
        )

        print("Status:", alert["status"])
        print("Notes:", alert["analyst_notes"])

        update_alert_status(
            alert,
            "RESOLVED",
            "Activity reviewed and investigation completed."
        )

        print("Final Status:", alert["status"])
        print("Resolution:", alert["resolution_notes"])


if __name__ == "__main__":
    demo()