"""
Baseline Builder for the Network IDS Simulation.

This module reads the synthetic network traffic dataset,
selects NORMAL traffic, calculates statistical baselines,
and saves the baseline to models/baseline.json.
"""

import json
from pathlib import Path

import pandas as pd


# --------------------------------------------------
# Project paths
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATASET_PATH = PROJECT_ROOT / "data" / "network_traffic.csv"

BASELINE_PATH = PROJECT_ROOT / "models" / "baseline.json"


# --------------------------------------------------
# Features used by the anomaly detector
# --------------------------------------------------

BASELINE_FEATURES = [
    "packets_per_second",
    "bytes_per_second",
    "connections_per_second",
    "failed_connection_ratio",
    "syn_ratio",
    "destination_port_diversity",
]


def safe_divide(numerator, denominator):
    """
    Safely divide two values.

    Returns 0 when the denominator is zero.
    """

    if denominator == 0:
        return 0.0

    return numerator / denominator


def calculate_features(df):
    """
    Calculate anomaly-detection features from network flows.
    """

    df = df.copy()

    # Make sure numeric columns contain valid numbers.
    numeric_columns = [
        "packet_count",
        "byte_count",
        "duration_seconds",
        "connection_count",
        "failed_connection_count",
        "syn_count",
        "destination_port",
    ]

    for column in numeric_columns:
        df[column] = pd.to_numeric(
            df[column],
            errors="coerce"
        ).fillna(0)

    # Prevent division by zero.
    duration = df["duration_seconds"].replace(
        0,
        0.001
    )

    # Packets per second
    df["packets_per_second"] = (
        df["packet_count"] / duration
    )

    # Bytes per second
    df["bytes_per_second"] = (
        df["byte_count"] / duration
    )

    # Connections per second
    df["connections_per_second"] = (
        df["connection_count"] / duration
    )

    # Failed connection ratio
    df["failed_connection_ratio"] = (
        df["failed_connection_count"]
        / df["connection_count"].replace(0, 1)
    )

    # SYN ratio
    df["syn_ratio"] = (
        df["syn_count"]
        / df["packet_count"].replace(0, 1)
    )

    # Each individual flow has one destination port.
    # The broader multi-port analysis will be handled later
    # by flow aggregation/correlation.
    df["destination_port_diversity"] = 1.0

    return df


def build_baseline():
    """
    Build a statistical baseline from NORMAL traffic.
    """

    print("\nLoading dataset...")

    if not DATASET_PATH.exists():
        raise FileNotFoundError(
            f"Dataset not found: {DATASET_PATH}"
        )

    df = pd.read_csv(DATASET_PATH)

    print(
        f"Total records loaded: {len(df)}"
    )

    # --------------------------------------------------
    # Select NORMAL traffic
    # --------------------------------------------------

    normal_df = df[
        df["label"].astype(str).str.upper() == "NORMAL"
    ].copy()

    if normal_df.empty:
        raise ValueError(
            "No NORMAL traffic records were found."
        )

    print(
        f"Normal records used for baseline: "
        f"{len(normal_df)}"
    )

    # --------------------------------------------------
    # Calculate features
    # --------------------------------------------------

    normal_df = calculate_features(normal_df)

    baseline = {}

    # --------------------------------------------------
    # Calculate mean and standard deviation
    # --------------------------------------------------

    for feature in BASELINE_FEATURES:

        mean_value = float(
            normal_df[feature].mean()
        )

        std_value = float(
            normal_df[feature].std()
        )

        # If the standard deviation is zero,
        # use a small value to prevent division issues.
        if std_value == 0:
            std_value = 0.0001

        baseline[feature] = {
            "mean": round(
                mean_value,
                6
            ),
            "std": round(
                std_value,
                6
            ),
        }

    return baseline


def save_baseline(baseline):
    """
    Save the baseline as JSON.
    """

    BASELINE_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(
        BASELINE_PATH,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            baseline,
            file,
            indent=4
        )

    print(
        f"\nBaseline saved to:\n{BASELINE_PATH}"
    )


def main():
    """
    Build and save the normal-traffic baseline.
    """

    print("=" * 60)
    print("NETWORK IDS - BASELINE BUILDER")
    print("=" * 60)

    baseline = build_baseline()

    save_baseline(baseline)

    print("\n=== Baseline Summary ===")

    for feature, values in baseline.items():

        print(
            f"{feature}: "
            f"mean={values['mean']}, "
            f"std={values['std']}"
        )

    print("\nBaseline creation completed successfully! ✅")


if __name__ == "__main__":
    main()