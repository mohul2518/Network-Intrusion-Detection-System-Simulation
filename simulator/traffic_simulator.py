
"""
Synthetic Network Traffic Simulator
------------------------------------

This simulator generates FAKE network flow records.

IMPORTANT:
- No real network packets are sent.
- No external systems are contacted.
- All IP addresses come from documentation-only ranges.
- This is intended for defensive IDS simulation and testing.
"""

import argparse
import json
import random
import time
from datetime import datetime, timezone
from pathlib import Path


# Documentation-only IP ranges
SOURCE_IPS = [
    "192.0.2.10",
    "192.0.2.11",
    "192.0.2.12",
    "192.0.2.13",
    "192.0.2.14",
]

DESTINATION_IPS = [
    "198.51.100.10",
    "198.51.100.11",
    "198.51.100.12",
    "203.0.113.10",
    "203.0.113.11",
]


# Common service ports used in the synthetic simulation
NORMAL_PORTS = {
    "HTTP": 80,
    "HTTPS": 443,
    "DNS": 53,
    "SSH": 22,
    "SMTP": 25,
    "DATABASE": 3306,
}


# Synthetic suspicious ports
UNUSUAL_PORTS = [
    4444,
    5555,
    8081,
    9001,
    31337,
]


def generate_timestamp() -> str:
    """Return the current UTC timestamp."""

    return datetime.now(timezone.utc).isoformat()


def generate_flow_id(counter: int) -> str:
    """Generate a unique flow ID."""

    return f"FLOW-{counter:06d}"


def generate_normal_flow(flow_id: str) -> dict:
    """
    Generate a normal synthetic network flow.
    """

    scenario = random.choice(
        [
            "NORMAL_WEB",
            "NORMAL_DNS",
            "NORMAL_SSH",
            "NORMAL_EMAIL",
            "NORMAL_DATABASE",
        ]
    )

    source_ip = random.choice(SOURCE_IPS)
    destination_ip = random.choice(DESTINATION_IPS)

    if scenario == "NORMAL_WEB":
        protocol = "TCP"
        destination_port = random.choice([80, 443])
        packet_count = random.randint(20, 120)
        byte_count = random.randint(5_000, 150_000)
        duration = round(random.uniform(1, 30), 2)
        connection_count = random.randint(1, 5)
        failed_connections = 0
        syn_count = random.randint(1, 3)
        rst_count = random.randint(0, 1)

    elif scenario == "NORMAL_DNS":
        protocol = "UDP"
        destination_port = 53
        packet_count = random.randint(2, 20)
        byte_count = random.randint(200, 5_000)
        duration = round(random.uniform(0.01, 2), 2)
        connection_count = random.randint(1, 3)
        failed_connections = 0
        syn_count = 0
        rst_count = 0

    elif scenario == "NORMAL_SSH":
        protocol = "TCP"
        destination_port = 22
        packet_count = random.randint(30, 150)
        byte_count = random.randint(3_000, 100_000)
        duration = round(random.uniform(5, 120), 2)
        connection_count = random.randint(1, 3)
        failed_connections = 0
        syn_count = random.randint(1, 3)
        rst_count = random.randint(0, 1)

    elif scenario == "NORMAL_EMAIL":
        protocol = "TCP"
        destination_port = 25
        packet_count = random.randint(20, 100)
        byte_count = random.randint(5_000, 80_000)
        duration = round(random.uniform(2, 60), 2)
        connection_count = random.randint(1, 4)
        failed_connections = 0
        syn_count = random.randint(1, 3)
        rst_count = random.randint(0, 1)

    else:
        protocol = "TCP"
        destination_port = 3306
        packet_count = random.randint(30, 150)
        byte_count = random.randint(10_000, 200_000)
        duration = round(random.uniform(2, 60), 2)
        connection_count = random.randint(1, 4)
        failed_connections = 0
        syn_count = random.randint(1, 3)
        rst_count = random.randint(0, 1)

    average_packet_size = round(
        byte_count / max(packet_count, 1),
        2,
    )

    return {
        "flow_id": flow_id,
        "timestamp": generate_timestamp(),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": random.randint(1024, 65535),
        "destination_port": destination_port,
        "protocol": protocol,
        "packet_count": packet_count,
        "byte_count": byte_count,
        "duration_seconds": duration,
        "connection_count": connection_count,
        "failed_connection_count": failed_connections,
        "syn_count": syn_count,
        "rst_count": rst_count,
        "average_packet_size": average_packet_size,
        "label": "NORMAL",
        "scenario_type": scenario,
    }


def generate_suspicious_flow(flow_id: str) -> dict:
    """
    Generate a suspicious synthetic network flow.

    The suspicious scenarios correspond to the IDS
    scenarios described in the project specification.
    """

    scenario = random.choice(
        [
            "HIGH_CONNECTION_RATE",
            "REPEATED_FAILED_CONNECTIONS",
            "MULTI_PORT_PROBING_PATTERN",
            "SYN_HEAVY_PATTERN",
            "UNUSUAL_PORT_ACTIVITY",
            "HIGH_TRAFFIC_VOLUME",
        ]
    )

    source_ip = random.choice(SOURCE_IPS)
    destination_ip = random.choice(DESTINATION_IPS)

    protocol = "TCP"

    # Default values
    destination_port = random.choice(
        list(NORMAL_PORTS.values())
    )

    packet_count = random.randint(50, 200)
    byte_count = random.randint(20_000, 300_000)
    duration = round(random.uniform(0.5, 10), 2)
    connection_count = random.randint(5, 15)
    failed_connections = random.randint(0, 3)
    syn_count = random.randint(1, 10)
    rst_count = random.randint(0, 3)

    if scenario == "HIGH_CONNECTION_RATE":

        connection_count = random.randint(30, 80)
        duration = round(
            random.uniform(0.5, 2),
            2,
        )

    elif scenario == "REPEATED_FAILED_CONNECTIONS":

        connection_count = random.randint(10, 30)
        failed_connections = random.randint(
            6,
            connection_count,
        )
        duration = round(
            random.uniform(1, 10),
            2,
        )

    elif scenario == "MULTI_PORT_PROBING_PATTERN":

        connection_count = random.randint(50, 100)
        failed_connections = random.randint(10, 40)
        duration = round(
            random.uniform(1, 5),
            2,
        )

    elif scenario == "SYN_HEAVY_PATTERN":

        connection_count = random.randint(20, 60)
        syn_count = random.randint(
            max(10, connection_count // 2),
            connection_count,
        )
        failed_connections = random.randint(5, 20)

    elif scenario == "UNUSUAL_PORT_ACTIVITY":

        destination_port = random.choice(
            UNUSUAL_PORTS
        )
        connection_count = random.randint(10, 40)
        failed_connections = random.randint(2, 15)

    elif scenario == "HIGH_TRAFFIC_VOLUME":

        packet_count = random.randint(
            50_000,
            150_000,
        )

        byte_count = random.randint(
            5_000_000,
            20_000_000,
        )

        duration = round(
            random.uniform(5, 60),
            2,
        )

        connection_count = random.randint(
            10,
            30,
        )

    average_packet_size = round(
        byte_count / max(packet_count, 1),
        2,
    )

    return {
        "flow_id": flow_id,
        "timestamp": generate_timestamp(),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": random.randint(1024, 65535),
        "destination_port": destination_port,
        "protocol": protocol,
        "packet_count": packet_count,
        "byte_count": byte_count,
        "duration_seconds": duration,
        "connection_count": connection_count,
        "failed_connection_count": failed_connections,
        "syn_count": syn_count,
        "rst_count": rst_count,
        "average_packet_size": average_packet_size,
        "label": "SUSPICIOUS",
        "scenario_type": scenario,
    }


def generate_flow(
    flow_id: str,
    mode: str = "mixed",
) -> dict:
    """
    Generate one synthetic network flow.

    mode:
        normal -> only normal flows
        mixed  -> normal and suspicious flows
    """

    if mode == "normal":
        return generate_normal_flow(flow_id)

    # Mixed mode
    if random.random() < 0.70:
        return generate_normal_flow(flow_id)

    return generate_suspicious_flow(flow_id)


def save_flow(flow: dict, output_file: Path) -> None:
    """
    Append a generated flow to a JSON Lines file.

    Each line contains one JSON object.
    """

    output_file.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with output_file.open(
        "a",
        encoding="utf-8",
    ) as file:

        file.write(
            json.dumps(flow)
            + "\n"
        )


def run_simulator(
    mode: str,
    speed: str,
    limit: int | None = None,
) -> None:
    """
    Run the synthetic traffic simulator.
    """

    output_file = Path(
        "data/live_flows.jsonl"
    )

    # Speed controls the delay between flows
    if speed == "slow":
        delay = 2.0
    else:
        delay = 0.5

    print("=" * 60)
    print("SYNTHETIC NETWORK TRAFFIC SIMULATOR")
    print("=" * 60)

    print(f"Mode: {mode}")
    print(f"Speed: {speed}")
    print(f"Output: {output_file}")
    print()
    print("No real network packets are being sent.")
    print("Press Ctrl+C to stop the simulator.")
    print()

    counter = 1

    try:

        while True:

            flow_id = generate_flow_id(counter)

            flow = generate_flow(
                flow_id,
                mode,
            )

            save_flow(
                flow,
                output_file,
            )

            print(
                f"{flow['flow_id']} | "
                f"{flow['label']} | "
                f"{flow['scenario_type']} | "
                f"{flow['source_ip']} -> "
                f"{flow['destination_ip']}:{flow['destination_port']}"
            )

            counter += 1

            if limit is not None and counter > limit:
                break

            time.sleep(delay)

    except KeyboardInterrupt:

        print()
        print("Simulator stopped safely.")


def parse_arguments():
    """
    Parse command-line arguments.
    """

    parser = argparse.ArgumentParser(
        description=(
            "Synthetic Network Traffic Simulator "
            "for the defensive IDS project."
        )
    )

    parser.add_argument(
        "--mode",
        choices=["normal", "mixed"],
        default="mixed",
        help=(
            "Traffic mode: "
            "normal or mixed. "
            "Default: mixed."
        ),
    )

    parser.add_argument(
        "--speed",
        choices=["slow", "fast"],
        default="slow",
        help=(
            "Simulation speed: "
            "slow or fast. "
            "Default: slow."
        ),
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help=(
            "Optional number of flows to generate. "
            "Useful for testing."
        ),
    )

    return parser.parse_args()


def main():
    """Program entry point."""

    args = parse_arguments()

    run_simulator(
        mode=args.mode,
        speed=args.speed,
        limit=args.limit,
    )


if __name__ == "__main__":
    main()

