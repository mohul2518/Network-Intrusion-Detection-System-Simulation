"""
Signature-Based IDS Rule Engine

This module checks synthetic network-flow features against
configurable detection rules.

A rule match indicates suspicious activity that requires
investigation. It does not prove malicious activity.
"""

from typing import Any, Dict, List

try:
    from .feature_extractor import extract_network_features
except ImportError:
    from feature_extractor import extract_network_features

# ---------------------------------------------------------
# Rule configuration
# ---------------------------------------------------------

RULES = {
    "HIGH_CONNECTION_RATE": {
        "description": "Unusually high number of connections per second.",
        "threshold": 20.0,
    },

    "REPEATED_FAILED_CONNECTIONS": {
        "description": "High ratio of failed connections.",
        "threshold": 0.50,
    },

    "MULTI_PORT_PROBING": {
        "description": "Large number of connections indicating possible multi-port probing.",
        "threshold": 50,
    },

    "SYN_HEAVY": {
        "description": "Unusually high SYN packet ratio.",
        "threshold": 0.40,
    },

    "UNUSUAL_PORT_ACTIVITY": {
        "description": "Traffic directed toward an unusual service port.",
        "ports": {
            4444,
            5555,
            8081,
            9001,
            31337,
        },
    },

    "HIGH_TRAFFIC_VOLUME": {
        "description": "Unusually high network traffic volume.",
        "threshold": 5_000_000,
    },
}


# ---------------------------------------------------------
# Individual rule checks
# ---------------------------------------------------------

def check_high_connection_rate(
    features: Dict[str, float],
) -> bool:
    """Check for unusually high connection rate."""

    return (
        features["connections_per_second"]
        > RULES["HIGH_CONNECTION_RATE"]["threshold"]
    )


def check_repeated_failed_connections(
    features: Dict[str, float],
) -> bool:
    """Check for a high failed-connection ratio."""

    return (
        features["failed_connection_ratio"]
        >= RULES["REPEATED_FAILED_CONNECTIONS"]["threshold"]
    )


def check_multi_port_probing(
    features: Dict[str, float],
) -> bool:
    """
    Check for a high number of connections.

    In the single-flow representation, this acts as a
    proxy for probing-like behavior. Broader port diversity
    will be handled by aggregated traffic analysis later.
    """

    return (
        features["connection_count"]
        >= RULES["MULTI_PORT_PROBING"]["threshold"]
    )


def check_syn_heavy(
    features: Dict[str, float],
) -> bool:
    """Check for unusually high SYN ratio."""

    return (
        features["syn_ratio"]
        >= RULES["SYN_HEAVY"]["threshold"]
    )


def check_unusual_port_activity(
    flow: Dict[str, Any],
) -> bool:
    """Check whether destination port is unusual."""

    try:
        destination_port = int(
            flow.get("destination_port", 0)
        )
    except (TypeError, ValueError):
        return False

    unusual_ports = RULES[
        "UNUSUAL_PORT_ACTIVITY"
    ]["ports"]

    return destination_port in unusual_ports


def check_high_traffic_volume(
    features: Dict[str, float],
) -> bool:
    """Check for unusually high byte volume."""

    return (
        features["byte_count"]
        >= RULES["HIGH_TRAFFIC_VOLUME"]["threshold"]
    )


# ---------------------------------------------------------
# Main rule analyzer
# ---------------------------------------------------------

def analyze_flow(
    flow: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Analyze a network flow using all configured rules.

    Returns a structured detection result.
    """

    features = extract_network_features(flow)

    matched_rules: List[Dict[str, Any]] = []

    # High connection rate
    if check_high_connection_rate(features):
        matched_rules.append({
            "rule_id": "HIGH_CONNECTION_RATE",
            "description": RULES[
                "HIGH_CONNECTION_RATE"
            ]["description"],
        })

    # Repeated failed connections
    if check_repeated_failed_connections(features):
        matched_rules.append({
            "rule_id": "REPEATED_FAILED_CONNECTIONS",
            "description": RULES[
                "REPEATED_FAILED_CONNECTIONS"
            ]["description"],
        })

    # Multi-port probing
    if check_multi_port_probing(features):
        matched_rules.append({
            "rule_id": "MULTI_PORT_PROBING",
            "description": RULES[
                "MULTI_PORT_PROBING"
            ]["description"],
        })

    # SYN-heavy
    if check_syn_heavy(features):
        matched_rules.append({
            "rule_id": "SYN_HEAVY",
            "description": RULES[
                "SYN_HEAVY"
            ]["description"],
        })

    # Unusual destination port
    if check_unusual_port_activity(flow):
        matched_rules.append({
            "rule_id": "UNUSUAL_PORT_ACTIVITY",
            "description": RULES[
                "UNUSUAL_PORT_ACTIVITY"
            ]["description"],
        })

    # High traffic volume
    if check_high_traffic_volume(features):
        matched_rules.append({
            "rule_id": "HIGH_TRAFFIC_VOLUME",
            "description": RULES[
                "HIGH_TRAFFIC_VOLUME"
            ]["description"],
        })

    suspicious = len(matched_rules) > 0

    if suspicious:
        classification = "SUSPICIOUS"
    else:
        classification = "NORMAL"

    return {
        "flow_id": flow.get("flow_id"),
        "classification": classification,
        "suspicious": suspicious,
        "matched_rules": matched_rules,
        "rule_count": len(matched_rules),
        "features": features,
    }


# ---------------------------------------------------------
# Demo
# ---------------------------------------------------------

if __name__ == "__main__":

    normal_flow = {
        "flow_id": "FLOW-NORMAL",
        "source_ip": "192.0.2.10",
        "destination_ip": "198.51.100.10",
        "source_port": 54321,
        "destination_port": 443,
        "protocol": "TCP",
        "packet_count": 100,
        "byte_count": 75000,
        "duration_seconds": 10,
        "connection_count": 5,
        "failed_connection_count": 1,
        "syn_count": 5,
        "rst_count": 1,
        "average_packet_size": 750,
    }

    suspicious_flow = {
        "flow_id": "FLOW-SUSPICIOUS",
        "source_ip": "192.0.2.11",
        "destination_ip": "198.51.100.11",
        "source_port": 54322,
        "destination_port": 4444,
        "protocol": "TCP",
        "packet_count": 1000,
        "byte_count": 7500000,
        "duration_seconds": 2,
        "connection_count": 100,
        "failed_connection_count": 70,
        "syn_count": 600,
        "rst_count": 30,
        "average_packet_size": 750,
    }

    print("=" * 60)
    print("NORMAL FLOW ANALYSIS")
    print("=" * 60)

    normal_result = analyze_flow(normal_flow)

    print(
        f"Classification: "
        f"{normal_result['classification']}"
    )

    print(
        f"Matched rules: "
        f"{normal_result['rule_count']}"
    )

    for rule in normal_result["matched_rules"]:
        print(f"- {rule['rule_id']}")

    print()

    print("=" * 60)
    print("SUSPICIOUS FLOW ANALYSIS")
    print("=" * 60)

    suspicious_result = analyze_flow(
        suspicious_flow
    )

    print(
        f"Classification: "
        f"{suspicious_result['classification']}"
    )

    print(
        f"Matched rules: "
        f"{suspicious_result['rule_count']}"
    )

    for rule in suspicious_result["matched_rules"]:
        print(
            f"- {rule['rule_id']}: "
            f"{rule['description']}"
        )