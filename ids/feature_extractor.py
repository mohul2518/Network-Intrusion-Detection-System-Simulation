"""
Network Feature Extractor

Converts a network-flow record into numerical features
that can be used by the IDS detection engines.
"""

from typing import Any, Dict


def safe_divide(numerator: float, denominator: float) -> float:
    """
    Safely divide two numbers.

    Returns 0.0 when the denominator is zero.
    """

    if denominator == 0:
        return 0.0

    return numerator / denominator


def get_numeric(flow: Dict[str, Any], field: str) -> float:
    """
    Safely retrieve a numeric value from a flow.

    Invalid or missing values become 0.0.
    """

    try:
        value = flow.get(field, 0)

        if value is None or value == "":
            return 0.0

        return float(value)

    except (TypeError, ValueError):
        return 0.0


def extract_network_features(
    flow: Dict[str, Any],
) -> Dict[str, float]:
    """
    Extract IDS features from a single network-flow record.

    Parameters
    ----------
    flow:
        Dictionary containing network-flow information.

    Returns
    -------
    dict
        Numerical features used by the IDS.
    """

    packet_count = get_numeric(flow, "packet_count")
    byte_count = get_numeric(flow, "byte_count")
    duration = get_numeric(flow, "duration_seconds")
    connection_count = get_numeric(flow, "connection_count")
    failed_connections = get_numeric(
        flow,
        "failed_connection_count",
    )
    syn_count = get_numeric(flow, "syn_count")
    rst_count = get_numeric(flow, "rst_count")
    average_packet_size = get_numeric(
        flow,
        "average_packet_size",
    )

    # -----------------------------------------------------
    # Traffic rates
    # -----------------------------------------------------

    packets_per_second = safe_divide(
        packet_count,
        duration,
    )

    bytes_per_second = safe_divide(
        byte_count,
        duration,
    )

    connections_per_second = safe_divide(
        connection_count,
        duration,
    )

    # -----------------------------------------------------
    # Connection ratios
    # -----------------------------------------------------

    failed_connection_ratio = safe_divide(
        failed_connections,
        connection_count,
    )

    syn_ratio = safe_divide(
        syn_count,
        packet_count,
    )

    rst_ratio = safe_divide(
        rst_count,
        packet_count,
    )

    # -----------------------------------------------------
    # Basic diversity features
    #
    # A single flow normally contains one destination IP
    # and one destination port. The simulator will later
    # aggregate these values for broader behavioral analysis.
    # -----------------------------------------------------

    destination_ip = flow.get(
        "destination_ip",
        "",
    )

    destination_port = flow.get(
        "destination_port",
        0,
    )

    unique_destination_ips = (
        1 if destination_ip else 0
    )

    try:
        destination_port = int(destination_port)

        unique_destination_ports = (
            1
            if 1 <= destination_port <= 65535
            else 0
        )

    except (TypeError, ValueError):
        unique_destination_ports = 0

    # -----------------------------------------------------
    # Return extracted features
    # -----------------------------------------------------

    return {
        "packet_count": packet_count,
        "byte_count": byte_count,
        "duration_seconds": duration,
        "connection_count": connection_count,
        "failed_connection_count": failed_connections,
        "syn_count": syn_count,
        "rst_count": rst_count,
        "average_packet_size": average_packet_size,
        "packets_per_second": round(
            packets_per_second,
            4,
        ),
        "bytes_per_second": round(
            bytes_per_second,
            4,
        ),
        "connections_per_second": round(
            connections_per_second,
            4,
        ),
        "failed_connection_ratio": round(
            failed_connection_ratio,
            4,
        ),
        "syn_ratio": round(
            syn_ratio,
            4,
        ),
        "rst_ratio": round(
            rst_ratio,
            4,
        ),
        "unique_destination_ips": unique_destination_ips,
        "unique_destination_ports": unique_destination_ports,
    }


def validate_flow(flow: Dict[str, Any]) -> bool:
    """
    Perform basic validation of a network-flow record.

    Returns True when the flow contains reasonable values.
    """

    required_fields = [
        "source_ip",
        "destination_ip",
        "source_port",
        "destination_port",
        "protocol",
    ]

    for field in required_fields:
        if field not in flow:
            return False

    protocol = str(flow.get("protocol", "")).upper()

    if protocol not in {"TCP", "UDP"}:
        return False

    try:
        source_port = int(flow["source_port"])
        destination_port = int(flow["destination_port"])

        if not 1 <= source_port <= 65535:
            return False

        if not 1 <= destination_port <= 65535:
            return False

    except (TypeError, ValueError):
        return False

    return True


if __name__ == "__main__":
    # Simple demonstration using one synthetic flow.

    example_flow = {
        "flow_id": "FLOW-DEMO",
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

    print("Flow valid:", validate_flow(example_flow))

    features = extract_network_features(example_flow)

    print("\nExtracted features:")

    for name, value in features.items():
        print(f"{name}: {value}")