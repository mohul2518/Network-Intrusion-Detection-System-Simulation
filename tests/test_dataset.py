"""
Tests for the synthetic network traffic dataset.
"""

import csv
from pathlib import Path


DATASET_PATH = (
    Path(__file__).resolve().parent.parent
    / "data"
    / "network_traffic.csv"
)


REQUIRED_COLUMNS = [
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


def load_dataset():
    """Load the generated CSV dataset."""

    with open(
        DATASET_PATH,
        "r",
        encoding="utf-8",
        newline="",
    ) as file:
        return list(csv.DictReader(file))


def test_dataset_exists():
    """Check that the dataset file exists."""

    assert DATASET_PATH.exists()


def test_dataset_has_5000_records():
    """Check that the dataset contains at least 5000 records."""

    records = load_dataset()

    assert len(records) >= 5000


def test_required_columns_exist():
    """Check that all required columns are present."""

    records = load_dataset()

    assert len(records) > 0

    for column in REQUIRED_COLUMNS:
        assert column in records[0]


def test_normal_and_suspicious_labels_exist():
    """Check that both major labels exist."""

    records = load_dataset()

    labels = {record["label"] for record in records}

    assert "NORMAL" in labels
    assert "SUSPICIOUS" in labels


def test_flow_ids_are_unique():
    """Check that every flow has a unique ID."""

    records = load_dataset()

    flow_ids = [record["flow_id"] for record in records]

    assert len(flow_ids) == len(set(flow_ids))


def test_protocols_are_valid():
    """Check that generated protocols are TCP or UDP."""

    records = load_dataset()

    valid_protocols = {"TCP", "UDP"}

    for record in records:
        assert record["protocol"] in valid_protocols


def test_ports_are_valid():
    """Check that ports are within the valid range."""

    records = load_dataset()

    for record in records:
        source_port = int(record["source_port"])
        destination_port = int(record["destination_port"])

        assert 1 <= source_port <= 65535
        assert 1 <= destination_port <= 65535


def test_packet_and_byte_counts_are_positive():
    """Check that packet and byte counts are valid."""

    records = load_dataset()

    for record in records:
        packet_count = int(record["packet_count"])
        byte_count = int(record["byte_count"])

        assert packet_count > 0
        assert byte_count > 0


def test_scenario_types_exist():
    """Check that multiple traffic scenarios were generated."""

    records = load_dataset()

    scenarios = {
        record["scenario_type"]
        for record in records
    }

    assert len(scenarios) >= 5