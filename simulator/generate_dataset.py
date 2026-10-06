"""
Synthetic Network Traffic Dataset Generator

This module generates safe, synthetic network-flow records for the
Network Intrusion Detection System (IDS) Simulation project.

No real network packets are sent.
No real systems are contacted.
"""

import csv
import random
from datetime import datetime, timedelta
from pathlib import Path


# ---------------------------------------------------------
# Configuration
# ---------------------------------------------------------

NUM_RECORDS = 5000

OUTPUT_FILE = (
    Path(__file__).resolve().parent.parent / "data" / "network_traffic.csv"
)

PROTOCOLS = ["TCP", "UDP"]

# Reserved documentation IP ranges.
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
    "203.0.113.12",
]

START_TIME = datetime(2026, 10, 1, 9, 0, 0)


# ---------------------------------------------------------
# Utility functions
# ---------------------------------------------------------

def random_timestamp(index):
    """Generate a timestamp that increases throughout the dataset."""
    return START_TIME + timedelta(seconds=index * random.randint(1, 5))


def random_flow_id(index):
    """Generate a unique flow identifier."""
    return f"FLOW-{index + 1:06d}"


def random_normal_port():
    """Return a common service port."""
    return random.choice([
        53,     # DNS
        80,     # HTTP
        443,    # HTTPS
        22,     # SSH
        25,     # SMTP
        110,    # POP3
        143,    # IMAP
        3306,   # MySQL
        5432,   # PostgreSQL
    ])


def calculate_average_packet_size(packet_count, byte_count):
    """Calculate average packet size safely."""
    if packet_count <= 0:
        return 0.0

    return round(byte_count / packet_count, 2)


# ---------------------------------------------------------
# Normal traffic scenarios
# ---------------------------------------------------------

def generate_normal_web():
    """Generate normal HTTPS/HTTP traffic."""
    protocol = "TCP"
    packet_count = random.randint(20, 200)
    average_size = random.randint(400, 1200)
    byte_count = packet_count * average_size

    return {
        "protocol": protocol,
        "source_port": random.randint(1024, 65535),
        "destination_port": random.choice([80, 443]),
        "packet_count": packet_count,
        "byte_count": byte_count,
        "duration_seconds": round(random.uniform(1, 30), 2),
        "connection_count": random.randint(1, 5),
        "failed_connection_count": random.randint(0, 1),
        "syn_count": random.randint(1, 5),
        "rst_count": random.randint(0, 1),
        "label": "NORMAL",
        "scenario_type": "NORMAL_WEB",
    }


def generate_normal_dns():
    """Generate normal DNS traffic."""
    protocol = "UDP"
    packet_count = random.randint(2, 30)
    average_size = random.randint(50, 300)
    byte_count = packet_count * average_size

    return {
        "protocol": protocol,
        "source_port": random.randint(1024, 65535),
        "destination_port": 53,
        "packet_count": packet_count,
        "byte_count": byte_count,
        "duration_seconds": round(random.uniform(0.1, 5), 2),
        "connection_count": random.randint(1, 3),
        "failed_connection_count": 0,
        "syn_count": 0,
        "rst_count": 0,
        "label": "NORMAL",
        "scenario_type": "NORMAL_DNS",
    }


def generate_normal_ssh():
    """Generate normal SSH traffic."""
    protocol = "TCP"
    packet_count = random.randint(30, 250)
    average_size = random.randint(300, 900)
    byte_count = packet_count * average_size

    return {
        "protocol": protocol,
        "source_port": random.randint(1024, 65535),
        "destination_port": 22,
        "packet_count": packet_count,
        "byte_count": byte_count,
        "duration_seconds": round(random.uniform(5, 120), 2),
        "connection_count": random.randint(1, 3),
        "failed_connection_count": random.randint(0, 1),
        "syn_count": random.randint(1, 4),
        "rst_count": random.randint(0, 1),
        "label": "NORMAL",
        "scenario_type": "NORMAL_SSH",
    }


def generate_normal_email():
    """Generate normal email traffic."""
    protocol = "TCP"
    packet_count = random.randint(20, 150)
    average_size = random.randint(300, 1000)
    byte_count = packet_count * average_size

    return {
        "protocol": protocol,
        "source_port": random.randint(1024, 65535),
        "destination_port": random.choice([25, 110, 143]),
        "packet_count": packet_count,
        "byte_count": byte_count,
        "duration_seconds": round(random.uniform(2, 60), 2),
        "connection_count": random.randint(1, 4),
        "failed_connection_count": random.randint(0, 1),
        "syn_count": random.randint(1, 4),
        "rst_count": random.randint(0, 1),
        "label": "NORMAL",
        "scenario_type": "NORMAL_EMAIL",
    }


def generate_normal_database():
    """Generate normal database traffic."""
    protocol = "TCP"
    packet_count = random.randint(50, 300)
    average_size = random.randint(400, 1400)
    byte_count = packet_count * average_size

    return {
        "protocol": protocol,
        "source_port": random.randint(1024, 65535),
        "destination_port": random.choice([3306, 5432]),
        "packet_count": packet_count,
        "byte_count": byte_count,
        "duration_seconds": round(random.uniform(1, 60), 2),
        "connection_count": random.randint(1, 5),
        "failed_connection_count": random.randint(0, 1),
        "syn_count": random.randint(1, 5),
        "rst_count": random.randint(0, 1),
        "label": "NORMAL",
        "scenario_type": "NORMAL_DATABASE",
    }


# ---------------------------------------------------------
# Suspicious traffic scenarios
# ---------------------------------------------------------

def generate_high_connection_rate():
    """Generate unusually high connection-rate traffic."""
    protocol = "TCP"
    packet_count = random.randint(500, 1500)
    average_size = random.randint(300, 800)
    byte_count = packet_count * average_size

    return {
        "protocol": protocol,
        "source_port": random.randint(1024, 65535),
        "destination_port": random.choice([80, 443, 22]),
        "packet_count": packet_count,
        "byte_count": byte_count,
        "duration_seconds": round(random.uniform(1, 5), 2),
        "connection_count": random.randint(100, 300),
        "failed_connection_count": random.randint(5, 40),
        "syn_count": random.randint(50, 150),
        "rst_count": random.randint(5, 30),
        "label": "SUSPICIOUS",
        "scenario_type": "HIGH_CONNECTION_RATE",
    }


def generate_repeated_failed_connections():
    """Generate repeated failed connection activity."""
    protocol = "TCP"
    packet_count = random.randint(50, 300)
    average_size = random.randint(200, 700)
    byte_count = packet_count * average_size

    failed_connections = random.randint(20, 80)

    return {
        "protocol": protocol,
        "source_port": random.randint(1024, 65535),
        "destination_port": random.choice([22, 80, 443]),
        "packet_count": packet_count,
        "byte_count": byte_count,
        "duration_seconds": round(random.uniform(5, 60), 2),
        "connection_count": random.randint(30, 100),
        "failed_connection_count": failed_connections,
        "syn_count": random.randint(10, 50),
        "rst_count": random.randint(5, 30),
        "label": "SUSPICIOUS",
        "scenario_type": "REPEATED_FAILED_CONNECTIONS",
    }


def generate_multi_port_probing():
    """Generate traffic associated with many destination ports."""
    protocol = "TCP"
    packet_count = random.randint(100, 500)
    average_size = random.randint(100, 500)
    byte_count = packet_count * average_size

    return {
        "protocol": protocol,
        "source_port": random.randint(1024, 65535),
        "destination_port": random.randint(1, 1023),
        "packet_count": packet_count,
        "byte_count": byte_count,
        "duration_seconds": round(random.uniform(1, 20), 2),
        "connection_count": random.randint(50, 150),
        "failed_connection_count": random.randint(20, 100),
        "syn_count": random.randint(30, 100),
        "rst_count": random.randint(10, 60),
        "label": "SUSPICIOUS",
        "scenario_type": "MULTI_PORT_PROBING_PATTERN",
    }


def generate_syn_heavy():
    """Generate SYN-heavy synthetic traffic."""
    protocol = "TCP"
    packet_count = random.randint(300, 1000)
    average_size = random.randint(100, 500)
    byte_count = packet_count * average_size

    return {
        "protocol": protocol,
        "source_port": random.randint(1024, 65535),
        "destination_port": random.choice([80, 443, 22]),
        "packet_count": packet_count,
        "byte_count": byte_count,
        "duration_seconds": round(random.uniform(1, 10), 2),
        "connection_count": random.randint(50, 200),
        "failed_connection_count": random.randint(10, 100),
        "syn_count": random.randint(150, 600),
        "rst_count": random.randint(20, 100),
        "label": "SUSPICIOUS",
        "scenario_type": "SYN_HEAVY_PATTERN",
    }


def generate_unusual_port_activity():
    """Generate activity involving an unusual service port."""
    protocol = "TCP"
    packet_count = random.randint(100, 400)
    average_size = random.randint(200, 900)
    byte_count = packet_count * average_size

    unusual_port = random.choice([
        4444,
        5555,
        8081,
        9001,
        31337,
    ])

    return {
        "protocol": protocol,
        "source_port": random.randint(1024, 65535),
        "destination_port": unusual_port,
        "packet_count": packet_count,
        "byte_count": byte_count,
        "duration_seconds": round(random.uniform(1, 30), 2),
        "connection_count": random.randint(10, 80),
        "failed_connection_count": random.randint(5, 30),
        "syn_count": random.randint(5, 50),
        "rst_count": random.randint(2, 20),
        "label": "SUSPICIOUS",
        "scenario_type": "UNUSUAL_PORT_ACTIVITY",
    }


def generate_high_traffic_volume():
    """Generate unusually high byte/packet volume."""
    protocol = random.choice(["TCP", "UDP"])
    packet_count = random.randint(5000, 15000)
    average_size = random.randint(1000, 1500)
    byte_count = packet_count * average_size

    return {
        "protocol": protocol,
        "source_port": random.randint(1024, 65535),
        "destination_port": random.choice([80, 443]),
        "packet_count": packet_count,
        "byte_count": byte_count,
        "duration_seconds": round(random.uniform(5, 30), 2),
        "connection_count": random.randint(50, 300),
        "failed_connection_count": random.randint(0, 20),
        "syn_count": random.randint(10, 100),
        "rst_count": random.randint(0, 20),
        "label": "SUSPICIOUS",
        "scenario_type": "HIGH_TRAFFIC_VOLUME",
    }


# ---------------------------------------------------------
# Scenario selection
# ---------------------------------------------------------

SCENARIO_GENERATORS = [
    generate_normal_web,
    generate_normal_dns,
    generate_normal_ssh,
    generate_normal_email,
    generate_normal_database,
    generate_high_connection_rate,
    generate_repeated_failed_connections,
    generate_multi_port_probing,
    generate_syn_heavy,
    generate_unusual_port_activity,
    generate_high_traffic_volume,
]


# ---------------------------------------------------------
# Complete record generation
# ---------------------------------------------------------

def generate_record(index):
    """Generate one complete network-flow record."""

    generator = random.choice(SCENARIO_GENERATORS)
    traffic = generator()

    source_ip = random.choice(SOURCE_IPS)
    destination_ip = random.choice(DESTINATION_IPS)

    duration = traffic["duration_seconds"]
    packet_count = traffic["packet_count"]
    byte_count = traffic["byte_count"]

    average_packet_size = calculate_average_packet_size(
        packet_count,
        byte_count,
    )

    record = {
        "flow_id": random_flow_id(index),
        "timestamp": random_timestamp(index).isoformat(),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": traffic["source_port"],
        "destination_port": traffic["destination_port"],
        "protocol": traffic["protocol"],
        "packet_count": packet_count,
        "byte_count": byte_count,
        "duration_seconds": duration,
        "connection_count": traffic["connection_count"],
        "failed_connection_count": traffic["failed_connection_count"],
        "syn_count": traffic["syn_count"],
        "rst_count": traffic["rst_count"],
        "average_packet_size": average_packet_size,
        "label": traffic["label"],
        "scenario_type": traffic["scenario_type"],
    }

    return record


# ---------------------------------------------------------
# Dataset generation
# ---------------------------------------------------------

def generate_dataset(num_records=NUM_RECORDS):
    """Generate and save the complete synthetic dataset."""

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "flow_id",
        "timestamp",
        "source_ip",
        "destination_ip",
        "source_port",
        "destination_port",
        "protocol",
        "packet_count",
        "byte_count",
        "duration_seconds",
        "connection_count",
        "failed_connection_count",
        "syn_count",
        "rst_count",
        "average_packet_size",
        "label",
        "scenario_type",
    ]

    records = []

    print("Generating synthetic network traffic...")
    print(f"Number of records: {num_records}")
    print()

    for index in range(num_records):
        records.append(generate_record(index))

    with open(
        OUTPUT_FILE,
        "w",
        newline="",
        encoding="utf-8",
    ) as csv_file:

        writer = csv.DictWriter(
            csv_file,
            fieldnames=fieldnames,
        )

        writer.writeheader()
        writer.writerows(records)

    print("Dataset generation completed successfully!")
    print(f"Saved to: {OUTPUT_FILE}")
    print(f"Total records: {len(records)}")

    normal_count = sum(
        1 for record in records if record["label"] == "NORMAL"
    )

    suspicious_count = sum(
        1 for record in records if record["label"] == "SUSPICIOUS"
    )

    print()
    print("Dataset summary:")
    print(f"NORMAL records: {normal_count}")
    print(f"SUSPICIOUS records: {suspicious_count}")


# ---------------------------------------------------------
# Program entry point
# ---------------------------------------------------------

if __name__ == "__main__":
    generate_dataset()
    