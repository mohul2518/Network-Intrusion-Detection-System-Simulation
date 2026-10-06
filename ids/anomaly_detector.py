"""
Anomaly-Based IDS Detector

This module detects unusual network behavior by comparing
flow features against a baseline.

The anomaly score ranges from 0 to 100.

Higher score = more unusual behavior.
"""

from typing import Dict, List, Any
import math
import statistics

try:
    from .feature_extractor import extract_network_features
except ImportError:
    from feature_extractor import extract_network_features

# ---------------------------------------------------------
# Features used for anomaly detection
# ---------------------------------------------------------

ANALYSIS_FEATURES = [
    "packets_per_second",
    "bytes_per_second",
    "connections_per_second",
    "failed_connection_ratio",
    "syn_ratio",
]


# ---------------------------------------------------------
# Basic statistical functions
# ---------------------------------------------------------

def calculate_mean(values: List[float]) -> float:
    """Calculate the mean of a list of values."""

    if not values:
        return 0.0

    return statistics.mean(values)


def calculate_standard_deviation(
    values: List[float],
) -> float:
    """Calculate standard deviation safely."""

    if len(values) < 2:
        return 0.0

    return statistics.pstdev(values)


def calculate_z_score(
    value: float,
    mean: float,
    standard_deviation: float,
) -> float:
    """
    Calculate a Z-score.

    If standard deviation is zero, return 0.
    """

    if standard_deviation == 0:
        return 0.0

    return abs(
        (value - mean) / standard_deviation
    )


# ---------------------------------------------------------
# Baseline creation
# ---------------------------------------------------------

def build_baseline(
    flows: List[Dict[str, Any]],
) -> Dict[str, Dict[str, float]]:
    """
    Build a statistical baseline from network flows.

    Returns mean and standard deviation for each
    analysis feature.
    """

    if not flows:
        return {}

    feature_values = {
        feature: []
        for feature in ANALYSIS_FEATURES
    }

    for flow in flows:

        features = extract_network_features(flow)

        for feature in ANALYSIS_FEATURES:
            feature_values[feature].append(
                features[feature]
            )

    baseline = {}

    for feature in ANALYSIS_FEATURES:

        values = feature_values[feature]

        baseline[feature] = {
            "mean": calculate_mean(values),
            "std": calculate_standard_deviation(
                values
            ),
        }

    return baseline


# ---------------------------------------------------------
# Individual anomaly score
# ---------------------------------------------------------

def calculate_feature_anomaly_score(
    value: float,
    mean: float,
    standard_deviation: float,
) -> float:
    """
    Convert a Z-score into a 0-100 anomaly contribution.

    Z-score < 1      → low anomaly
    Z-score 1-2      → moderate
    Z-score 2-3      → high
    Z-score >= 3     → very high
    """

    z_score = calculate_z_score(
        value,
        mean,
        standard_deviation,
    )

    if z_score < 1:
        score = 10

    elif z_score < 2:
        score = 35

    elif z_score < 3:
        score = 65

    else:
        score = 100

    return float(score)


# ---------------------------------------------------------
# Complete anomaly calculation
# ---------------------------------------------------------

def calculate_anomaly_score(
    flow: Dict[str, Any],
    baseline: Dict[str, Dict[str, float]],
) -> float:
    """
    Calculate an overall anomaly score from 0 to 100.
    """

    if not baseline:
        return 0.0

    features = extract_network_features(flow)

    feature_scores = []

    for feature in ANALYSIS_FEATURES:

        if feature not in baseline:
            continue

        mean = baseline[feature]["mean"]
        std = baseline[feature]["std"]

        value = features[feature]

        score = calculate_feature_anomaly_score(
            value,
            mean,
            std,
        )

        feature_scores.append(score)

    if not feature_scores:
        return 0.0

    average_score = statistics.mean(
        feature_scores
    )

    return round(
        min(100.0, max(0.0, average_score)),
        2,
    )


# ---------------------------------------------------------
# Detailed anomaly analysis
# ---------------------------------------------------------

def analyze_anomaly(
    flow: Dict[str, Any],
    baseline: Dict[str, Dict[str, float]],
) -> Dict[str, Any]:
    """
    Analyze a flow and return detailed anomaly information.
    """

    if not baseline:
        return {
            "anomaly_score": 0.0,
            "classification": "NORMAL",
            "anomalous_features": [],
        }

    features = extract_network_features(flow)

    anomalous_features = []

    for feature in ANALYSIS_FEATURES:

        if feature not in baseline:
            continue

        mean = baseline[feature]["mean"]
        std = baseline[feature]["std"]
        value = features[feature]

        z_score = calculate_z_score(
            value,
            mean,
            std,
        )

        if z_score >= 2:
            anomalous_features.append({
                "feature": feature,
                "value": round(value, 4),
                "baseline_mean": round(
                    mean,
                    4,
                ),
                "z_score": round(
                    z_score,
                    4,
                ),
            })

    anomaly_score = calculate_anomaly_score(
        flow,
        baseline,
    )

    if anomaly_score >= 70:
        classification = "POTENTIAL INTRUSION"

    elif anomaly_score >= 40:
        classification = "SUSPICIOUS"

    else:
        classification = "NORMAL"

    return {
        "anomaly_score": anomaly_score,
        "classification": classification,
        "anomalous_features": anomalous_features,
    }


# ---------------------------------------------------------
# Demonstration
# ---------------------------------------------------------

if __name__ == "__main__":

    normal_flows = [
        {
            "flow_id": "BASE-1",
            "source_ip": "192.0.2.10",
            "destination_ip": "198.51.100.10",
            "source_port": 50001,
            "destination_port": 443,
            "protocol": "TCP",
            "packet_count": 100,
            "byte_count": 75000,
            "duration_seconds": 10,
            "connection_count": 5,
            "failed_connection_count": 0,
            "syn_count": 5,
            "rst_count": 0,
            "average_packet_size": 750,
        },
        {
            "flow_id": "BASE-2",
            "source_ip": "192.0.2.11",
            "destination_ip": "198.51.100.11",
            "source_port": 50002,
            "destination_port": 443,
            "protocol": "TCP",
            "packet_count": 120,
            "byte_count": 90000,
            "duration_seconds": 12,
            "connection_count": 6,
            "failed_connection_count": 0,
            "syn_count": 6,
            "rst_count": 0,
            "average_packet_size": 750,
        },
        {
            "flow_id": "BASE-3",
            "source_ip": "192.0.2.12",
            "destination_ip": "198.51.100.12",
            "source_port": 50003,
            "destination_port": 443,
            "protocol": "TCP",
            "packet_count": 90,
            "byte_count": 67500,
            "duration_seconds": 9,
            "connection_count": 4,
            "failed_connection_count": 0,
            "syn_count": 4,
            "rst_count": 0,
            "average_packet_size": 750,
        },
        {
            "flow_id": "BASE-4",
            "source_ip": "192.0.2.13",
            "destination_ip": "203.0.113.10",
            "source_port": 50004,
            "destination_port": 80,
            "protocol": "TCP",
            "packet_count": 110,
            "byte_count": 82500,
            "duration_seconds": 11,
            "connection_count": 5,
            "failed_connection_count": 0,
            "syn_count": 5,
            "rst_count": 0,
            "average_packet_size": 750,
        },
    ]

    suspicious_flow = {
        "flow_id": "ANOMALOUS-1",
        "source_ip": "192.0.2.14",
        "destination_ip": "198.51.100.10",
        "source_port": 60000,
        "destination_port": 443,
        "protocol": "TCP",
        "packet_count": 5000,
        "byte_count": 7500000,
        "duration_seconds": 2,
        "connection_count": 500,
        "failed_connection_count": 200,
        "syn_count": 3000,
        "rst_count": 100,
        "average_packet_size": 1500,
    }

    print("=" * 60)
    print("BUILDING BASELINE")
    print("=" * 60)

    baseline = build_baseline(
        normal_flows
    )

    for feature, values in baseline.items():
        print(
            f"{feature}: "
            f"mean={values['mean']:.4f}, "
            f"std={values['std']:.4f}"
        )

    print()
    print("=" * 60)
    print("ANOMALY ANALYSIS")
    print("=" * 60)

    result = analyze_anomaly(
        suspicious_flow,
        baseline,
    )

    print(
        f"Anomaly score: "
        f"{result['anomaly_score']}"
    )

    print(
        f"Classification: "
        f"{result['classification']}"
    )

    print("\nAnomalous features:")

    for item in result["anomalous_features"]:
        print(
            f"- {item['feature']}: "
            f"value={item['value']}, "
            f"z-score={item['z_score']}"
        )