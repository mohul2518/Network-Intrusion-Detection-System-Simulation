"""
Risk Engine for the Network IDS Simulation.

Combines rule-based and anomaly-based detection scores
into a final risk score from 0 to 100.

Risk classification:
0-20   -> NORMAL
21-40  -> LOW RISK
41-60  -> SUSPICIOUS
61-80  -> HIGH RISK
81-100 -> CRITICAL INVESTIGATION
"""


def calculate_rule_score(rule_results):
    """
    Convert rule-engine results into a score from 0 to 100.

    Each matched rule contributes to the score.
    More matched rules = higher rule score.
    """

    if not isinstance(rule_results, dict):
        return 0.0

    matched_rules = rule_results.get("matched_rules", [])

    if not isinstance(matched_rules, list):
        return 0.0

    rule_count = len(matched_rules)

    # Give increasing weight to multiple matched rules.
    if rule_count == 0:
        return 0.0
    elif rule_count == 1:
        return 40.0
    elif rule_count == 2:
        return 60.0
    elif rule_count == 3:
        return 75.0
    elif rule_count == 4:
        return 90.0
    else:
        return 100.0


def calculate_anomaly_component(anomaly_results):
    """
    Extract the anomaly score safely.
    """

    if not isinstance(anomaly_results, dict):
        return 0.0

    anomaly_score = anomaly_results.get("anomaly_score", 0.0)

    try:
        anomaly_score = float(anomaly_score)
    except (TypeError, ValueError):
        anomaly_score = 0.0

    return max(0.0, min(100.0, anomaly_score))


def classify_risk(risk_score):
    """
    Convert a numerical risk score into a risk classification.
    """

    if risk_score <= 20:
        return "NORMAL"

    if risk_score <= 40:
        return "LOW RISK"

    if risk_score <= 60:
        return "SUSPICIOUS"

    if risk_score <= 80:
        return "HIGH RISK"

    return "CRITICAL INVESTIGATION"


def determine_severity(risk_score):
    """
    Convert the risk score into an alert severity.
    """

    if risk_score <= 20:
        return "INFO"

    if risk_score <= 40:
        return "LOW"

    if risk_score <= 60:
        return "MEDIUM"

    if risk_score <= 80:
        return "HIGH"

    return "CRITICAL"


def calculate_risk_score(rule_results, anomaly_results, ml_score=None):
    """
    Calculate the final IDS risk score.

    Without ML:
        Rule score    = 60%
        Anomaly score = 40%

    With ML:
        Rule score    = 40%
        Anomaly score = 30%
        ML score      = 30%

    Returns a dictionary containing:
        risk_score
        classification
        severity
        rule_score
        anomaly_score
        ml_score
    """

    # -----------------------------------------
    # 1. Calculate rule score
    # -----------------------------------------

    rule_score = calculate_rule_score(rule_results)

    # -----------------------------------------
    # 2. Calculate anomaly score
    # -----------------------------------------

    anomaly_score = calculate_anomaly_component(anomaly_results)

    # -----------------------------------------
    # 3. Calculate final score
    # -----------------------------------------

    if ml_score is not None:

        try:
            ml_score = float(ml_score)
        except (TypeError, ValueError):
            ml_score = 0.0

        ml_score = max(0.0, min(100.0, ml_score))

        risk_score = (
            rule_score * 0.40
            + anomaly_score * 0.30
            + ml_score * 0.30
        )

    else:

        ml_score = None

        risk_score = (
            rule_score * 0.60
            + anomaly_score * 0.40
        )

    # -----------------------------------------
    # 4. Keep score between 0 and 100
    # -----------------------------------------

    risk_score = max(0.0, min(100.0, float(risk_score)))

    # Round for cleaner output
    risk_score = round(risk_score, 2)

    # -----------------------------------------
    # 5. Classification and severity
    # -----------------------------------------

    classification = classify_risk(risk_score)
    severity = determine_severity(risk_score)

    return {
        "risk_score": risk_score,
        "classification": classification,
        "severity": severity,
        "rule_score": round(rule_score, 2),
        "anomaly_score": round(anomaly_score, 2),
        "ml_score": ml_score,
    }


def demo():
    """
    Demonstration of the risk engine.
    """

    rule_results = {
        "suspicious": True,
        "matched_rules": [
            {
                "rule_id": "HIGH_CONNECTION_RATE",
                "description": "Connection rate is unusually high."
            },
            {
                "rule_id": "SYN_HEAVY",
                "description": "SYN traffic ratio is unusually high."
            }
        ],
        "rule_count": 2,
    }

    anomaly_results = {
        "anomaly_score": 70.0,
        "classification": "SUSPICIOUS",
    }

    result = calculate_risk_score(
        rule_results,
        anomaly_results
    )

    print("\n=== Risk Engine Demo ===")
    print("Rule Score:", result["rule_score"])
    print("Anomaly Score:", result["anomaly_score"])
    print("Risk Score:", result["risk_score"])
    print("Classification:", result["classification"])
    print("Severity:", result["severity"])


if __name__ == "__main__":
    demo()