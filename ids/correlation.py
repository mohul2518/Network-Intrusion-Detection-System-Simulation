from datetime import datetime


# ============================================================
# TIME PARSER
# ============================================================

def parse_timestamp(timestamp):
    """
    Convert an ISO timestamp into a datetime object.
    """

    if isinstance(timestamp, datetime):
        return timestamp

    if not timestamp:
        return None

    try:
        return datetime.fromisoformat(
            str(timestamp).replace("Z", "+00:00")
        )

    except ValueError:
        return None


# ============================================================
# CORRELATE ALERTS
# ============================================================

def correlate_alerts(alerts, time_window_seconds=300):
    """
    Group related alerts.

    Alerts are correlated using:
    - source IP
    - alert type
    - time window

    time_window_seconds defaults to 5 minutes.
    """

    if not alerts:
        return []

    groups = []

    for alert in alerts:

        source_ip = alert.get("source_ip", "UNKNOWN")
        alert_type = alert.get("alert_type", "UNKNOWN")

        current_time = parse_timestamp(
            alert.get("timestamp")
        )

        if current_time is None:
            continue

        matched_group = None

        # ----------------------------------------------------
        # Look for an existing related group
        # ----------------------------------------------------

        for group in groups:

            if group["source_ip"] != source_ip:
                continue

            if group["alert_type"] != alert_type:
                continue

            first_time = group["first_timestamp"]

            time_difference = abs(
                (current_time - first_time).total_seconds()
            )

            if time_difference <= time_window_seconds:

                matched_group = group
                break

        # ----------------------------------------------------
        # Add alert to existing group
        # ----------------------------------------------------

        if matched_group:

            matched_group["alerts"].append(alert)

            # Update maximum risk score
            risk_score = alert.get("risk_score")

            if risk_score is not None:

                matched_group["max_risk_score"] = max(
                    matched_group["max_risk_score"],
                    float(risk_score)
                )

            # Update highest severity
            severity_order = {
                "INFO": 1,
                "LOW": 2,
                "MEDIUM": 3,
                "HIGH": 4,
                "CRITICAL": 5
            }

            current_severity = alert.get(
                "severity",
                "INFO"
            )

            existing_severity = matched_group[
                "severity"
            ]

            if severity_order.get(
                current_severity,
                0
            ) > severity_order.get(
                existing_severity,
                0
            ):

                matched_group["severity"] = current_severity

        # ----------------------------------------------------
        # Create a new group
        # ----------------------------------------------------

        else:

            groups.append(
                {
                    "correlation_id":
                        f"CORR-{len(groups) + 1:04d}",

                    "source_ip":
                        source_ip,

                    "alert_type":
                        alert_type,

                    "first_timestamp":
                        current_time,

                    "last_timestamp":
                        current_time,

                    "severity":
                        alert.get(
                            "severity",
                            "INFO"
                        ),

                    "max_risk_score":
                        float(
                            alert.get(
                                "risk_score",
                                0
                            ) or 0
                        ),

                    "alerts": [alert]
                }
            )

    # --------------------------------------------------------
    # Add summary information
    # --------------------------------------------------------

    results = []

    for group in groups:

        group["last_timestamp"] = max(
            parse_timestamp(
                alert.get("timestamp")
            )
            for alert in group["alerts"]
            if parse_timestamp(
                alert.get("timestamp")
            ) is not None
        )

        group["alert_count"] = len(
            group["alerts"]
        )

        results.append(group)

    return results


# ============================================================
# VALIDATE CORRELATION
# ============================================================

def validate_correlation(correlations):

    if not isinstance(correlations, list):
        return False

    for group in correlations:

        required_fields = [
            "correlation_id",
            "source_ip",
            "alert_type",
            "severity",
            "max_risk_score",
            "alerts",
            "alert_count"
        ]

        for field in required_fields:

            if field not in group:
                return False

    return True


# ============================================================
# DEMO
# ============================================================

if __name__ == "__main__":

    print("=" * 60)
    print("ALERT CORRELATION TEST")
    print("=" * 60)

    sample_alerts = [

        {
            "alert_id": "ALERT-001",
            "timestamp":
                "2026-10-06T10:00:00",
            "source_ip":
                "192.0.2.10",
            "alert_type":
                "RULE_MATCH",
            "severity":
                "HIGH",
            "risk_score":
                75
        },

        {
            "alert_id": "ALERT-002",
            "timestamp":
                "2026-10-06T10:02:00",
            "source_ip":
                "192.0.2.10",
            "alert_type":
                "RULE_MATCH",
            "severity":
                "CRITICAL",
            "risk_score":
                90
        },

        {
            "alert_id": "ALERT-003",
            "timestamp":
                "2026-10-06T10:03:00",
            "source_ip":
                "198.51.100.20",
            "alert_type":
                "ANOMALY",
            "severity":
                "MEDIUM",
            "risk_score":
                55
        }
    ]

    correlations = correlate_alerts(
        sample_alerts
    )

    print("\nCorrelated groups:")

    for group in correlations:

        print(
            f"\nCorrelation ID: "
            f"{group['correlation_id']}"
        )

        print(
            f"Source IP: "
            f"{group['source_ip']}"
        )

        print(
            f"Alert Type: "
            f"{group['alert_type']}"
        )

        print(
            f"Alert Count: "
            f"{group['alert_count']}"
        )

        print(
            f"Severity: "
            f"{group['severity']}"
        )

        print(
            f"Maximum Risk: "
            f"{group['max_risk_score']}"
        )

    print("\nValidation:")

    print(
        validate_correlation(
            correlations
        )
    )

    print("\nCorrelation engine is working.")