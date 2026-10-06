import json
from pathlib import Path

from feature_extractor import (
    extract_network_features,
    validate_flow
)

from rule_engine import analyze_flow

from anomaly_detector import calculate_anomaly_score

from risk_engine import calculate_risk_score

from alert_engine import generate_alert


# ---------------------------------------------------------
# PROJECT PATH
# ---------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parents[1]

BASELINE_FILE = BASE_DIR / "models" / "baseline.json"


# ---------------------------------------------------------
# LOAD SAVED BASELINE
# ---------------------------------------------------------

def create_baseline():

    if not BASELINE_FILE.exists():
        raise FileNotFoundError(
            f"Baseline file not found: {BASELINE_FILE}"
        )

    with open(
        BASELINE_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        baseline = json.load(file)

    return baseline


# ---------------------------------------------------------
# CLASSIFY ANOMALY SCORE
# ---------------------------------------------------------

def classify_anomaly_score(score):

    try:
        score = float(score)
    except (TypeError, ValueError):
        score = 0.0

    if score >= 70:
        classification = "POTENTIAL INTRUSION"

    elif score >= 40:
        classification = "SUSPICIOUS"

    else:
        classification = "NORMAL"

    return classification


# ---------------------------------------------------------
# NORMALIZE ANOMALY RESULT
# ---------------------------------------------------------

def normalize_anomaly_result(anomaly_result):

    # If a dictionary was returned
    if isinstance(anomaly_result, dict):

        score = anomaly_result.get(
            "anomaly_score",
            anomaly_result.get("score", 0)
        )

        classification = anomaly_result.get(
            "classification"
        )

        if classification is None:
            classification = classify_anomaly_score(score)

        return {
            "anomaly_score": float(score),
            "classification": classification
        }

    # If a number was returned
    try:
        score = float(anomaly_result)

    except (TypeError, ValueError):
        score = 0.0

    return {
        "anomaly_score": score,
        "classification": classify_anomaly_score(score)
    }


# ---------------------------------------------------------
# ANALYZE NETWORK FLOW
# ---------------------------------------------------------

def analyze_network_flow(flow):

    print("\n================================")
    print("ANALYZING NETWORK FLOW")
    print("================================")

    # -----------------------------------------------------
    # 1. VALIDATE FLOW
    # -----------------------------------------------------

    validation = validate_flow(flow)

    if validation is not True:

        raise ValueError(
            "Invalid network flow."
        )

    # -----------------------------------------------------
    # 2. FEATURE EXTRACTION
    # -----------------------------------------------------

    features = extract_network_features(flow)

    print("\nFeature extraction completed.")

    # -----------------------------------------------------
    # 3. SIGNATURE / RULE ANALYSIS
    # -----------------------------------------------------

    rule_results = analyze_flow(flow)

    print("\nRule analysis completed.")

    # -----------------------------------------------------
    # 4. LOAD BASELINE
    # -----------------------------------------------------

    baseline = create_baseline()

    # -----------------------------------------------------
    # 5. ANOMALY ANALYSIS
    # -----------------------------------------------------

    anomaly_score = calculate_anomaly_score(
        flow,
        baseline
    )

    anomaly_results = normalize_anomaly_result(
        anomaly_score
    )

    print(
        f"\nAnomaly score: "
        f"{anomaly_results['anomaly_score']:.2f}"
    )

    print(
        f"Anomaly classification: "
        f"{anomaly_results['classification']}"
    )

    # -----------------------------------------------------
    # 6. MACHINE LEARNING ANALYSIS
    # -----------------------------------------------------

    try:

        from ml.predict import predict_flow

        ml_results = predict_flow(flow)

        ml_score = ml_results.get(
            "ml_score",
            0
        )

        print(
            f"\nML classification: "
            f"{ml_results.get('classification')}"
        )

        print(
            f"ML score: "
            f"{ml_score:.2f}"
        )

    except Exception as error:

        print(
            f"\nML prediction skipped: {error}"
        )

        ml_results = {
            "classification": "UNAVAILABLE",
            "normal_probability": 0,
            "suspicious_probability": 0,
            "ml_score": 0
        }

        ml_score = 0

    # -----------------------------------------------------
    # 7. RISK CALCULATION
    # -----------------------------------------------------

    risk_results = calculate_risk_score(
        rule_results,
        anomaly_results,
        ml_score=ml_score
    )

    print(
        f"\nRisk score: "
        f"{risk_results.get('risk_score', 0):.2f}"
    )

    print(
        f"Risk classification: "
        f"{risk_results.get('classification')}"
    )

    print(
        f"Severity: "
        f"{risk_results.get('severity')}"
    )

    # -----------------------------------------------------
    # 8. ALERT GENERATION
    # -----------------------------------------------------

    alert = generate_alert(
        flow,
        rule_results,
        anomaly_results,
        risk_results
    )

    # -----------------------------------------------------
    # 9. ADD ML INFORMATION TO ALERT
    # -----------------------------------------------------

    alert["ml_score"] = ml_score

    alert["ml_classification"] = (
        ml_results.get(
            "classification",
            "UNAVAILABLE"
        )
    )

    alert["normal_probability"] = (
        ml_results.get(
            "normal_probability",
            0
        )
    )

    alert["suspicious_probability"] = (
        ml_results.get(
            "suspicious_probability",
            0
        )
    )

    # -----------------------------------------------------
    # 10. ADD FEATURES
    # -----------------------------------------------------

    alert["features"] = features

    # -----------------------------------------------------
    # 11. FINAL RESULT
    # -----------------------------------------------------

    print("\n================================")
    print("FINAL IDS RESULT")
    print("================================")

    print(
        f"Alert ID: "
        f"{alert.get('alert_id')}"
    )

    print(
        f"Classification: "
        f"{risk_results.get('classification')}"
    )

    print(
        f"Risk Score: "
        f"{risk_results.get('risk_score')}"
    )

    print(
        f"Severity: "
        f"{risk_results.get('severity')}"
    )

    print(
        f"ML Score: "
        f"{ml_score}"
    )

    print(
        f"Alert Status: "
        f"{alert.get('status')}"
    )

    print("================================")

    return {
        "flow": flow,
        "features": features,
        "rules": rule_results,
        "anomaly": anomaly_results,
        "ml": ml_results,
        "risk": risk_results,
        "alert": alert
    }


# ---------------------------------------------------------
# DEMO
# ---------------------------------------------------------

def demo():

    sample_flow = {
        "flow_id": "DEMO-FLOW-001",
        "timestamp": "2026-10-06T15:30:00",
        "source_ip": "192.0.2.10",
        "destination_ip": "198.51.100.20",
        "source_port": 45000,
        "destination_port": 22,
        "protocol": "TCP",
        "packet_count": 150,
        "byte_count": 120000,
        "duration_seconds": 5,
        "connection_count": 30,
        "failed_connection_count": 15,
        "syn_count": 20,
        "rst_count": 5,
        "average_packet_size": 800,
        "label": "SUSPICIOUS",
        "scenario_type": "REPEATED_FAILED_CONNECTIONS"
    }

    result = analyze_network_flow(
        sample_flow
    )

    return result


# ---------------------------------------------------------
# MAIN
# ---------------------------------------------------------

if __name__ == "__main__":

    demo()