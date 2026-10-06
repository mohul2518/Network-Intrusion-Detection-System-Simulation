import json
from pathlib import Path

import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
)
from sklearn.model_selection import train_test_split


# ---------------------------------------------------------
# PATHS
# ---------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parents[1]

DATA_FILE = BASE_DIR / "data" / "network_traffic.csv"
MODEL_DIR = BASE_DIR / "models"

MODEL_FILE = MODEL_DIR / "random_forest_ids_model.joblib"
METRICS_FILE = MODEL_DIR / "ml_metrics.json"
CONFUSION_MATRIX_FILE = MODEL_DIR / "confusion_matrix.json"


# ---------------------------------------------------------
# FEATURES
# ---------------------------------------------------------

FEATURE_COLUMNS = [
    "packet_count",
    "byte_count",
    "duration_seconds",
    "connection_count",
    "failed_connection_count",
    "syn_count",
    "rst_count",
    "average_packet_size",
    "source_port",
    "destination_port",
]


# ---------------------------------------------------------
# LOAD DATASET
# ---------------------------------------------------------

def load_dataset():
    print("Loading dataset...")

    if not DATA_FILE.exists():
        raise FileNotFoundError(
            f"Dataset not found: {DATA_FILE}"
        )

    df = pd.read_csv(DATA_FILE)

    print(f"Dataset loaded: {len(df)} records")

    return df


# ---------------------------------------------------------
# PREPARE DATA
# ---------------------------------------------------------

def prepare_data(df):

    required_columns = FEATURE_COLUMNS + ["label"]

    missing_columns = [
        column
        for column in required_columns
        if column not in df.columns
    ]

    if missing_columns:
        raise ValueError(
            f"Missing columns: {missing_columns}"
        )

    X = df[FEATURE_COLUMNS].copy()

    y = df["label"].copy()

    # Convert labels into binary values
    # NORMAL = 0
    # SUSPICIOUS = 1

    y = y.map({
        "NORMAL": 0,
        "SUSPICIOUS": 1
    })

    if y.isna().any():
        raise ValueError(
            "Dataset contains labels other than NORMAL or SUSPICIOUS."
        )

    # Handle missing values
    X = X.fillna(0)

    return X, y


# ---------------------------------------------------------
# TRAIN MODEL
# ---------------------------------------------------------

def train_model(X_train, y_train):

    print("\nTraining Random Forest model...")

    model = RandomForestClassifier(
        n_estimators=150,
        random_state=42,
        max_depth=12,
        class_weight="balanced"
    )

    model.fit(X_train, y_train)

    print("Model training completed.")

    return model


# ---------------------------------------------------------
# EVALUATE MODEL
# ---------------------------------------------------------

def evaluate_model(model, X_test, y_test):

    predictions = model.predict(X_test)

    accuracy = accuracy_score(
        y_test,
        predictions
    )

    precision = precision_score(
        y_test,
        predictions,
        zero_division=0
    )

    recall = recall_score(
        y_test,
        predictions,
        zero_division=0
    )

    f1 = f1_score(
        y_test,
        predictions,
        zero_division=0
    )

    matrix = confusion_matrix(
        y_test,
        predictions
    )

    print("\n==============================")
    print("MODEL EVALUATION")
    print("==============================")

    print(f"Accuracy : {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall   : {recall:.4f}")
    print(f"F1 Score : {f1:.4f}")

    print("\nConfusion Matrix:")
    print(matrix)

    print("\nClassification Report:")
    print(
        classification_report(
            y_test,
            predictions,
            target_names=[
                "NORMAL",
                "SUSPICIOUS"
            ],
            zero_division=0
        )
    )

    return {
        "accuracy": round(float(accuracy), 4),
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1_score": round(float(f1), 4),
        "confusion_matrix": matrix.tolist()
    }


# ---------------------------------------------------------
# SAVE RESULTS
# ---------------------------------------------------------

def save_results(model, metrics):

    MODEL_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    joblib.dump(
        model,
        MODEL_FILE
    )

    with open(
        METRICS_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            metrics,
            file,
            indent=4
        )

    with open(
        CONFUSION_MATRIX_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            metrics["confusion_matrix"],
            file,
            indent=4
        )

    print("\nFiles saved successfully:")

    print(
        f"Model: {MODEL_FILE}"
    )

    print(
        f"Metrics: {METRICS_FILE}"
    )

    print(
        f"Confusion matrix: {CONFUSION_MATRIX_FILE}"
    )


# ---------------------------------------------------------
# MAIN
# ---------------------------------------------------------

def main():

    print("==============================")
    print("NETWORK IDS ML TRAINING")
    print("==============================")

    df = load_dataset()

    X, y = prepare_data(df)

    print(
        f"\nFeatures used: {len(FEATURE_COLUMNS)}"
    )

    print(
        f"Training samples available: {len(X)}"
    )

    print("\nClass distribution:")

    print(
        y.value_counts()
        .rename({
            0: "NORMAL",
            1: "SUSPICIOUS"
        })
    )

    # 80% training / 20% testing
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y
    )

    print(
        f"\nTraining set: {len(X_train)}"
    )

    print(
        f"Testing set: {len(X_test)}"
    )

    model = train_model(
        X_train,
        y_train
    )

    metrics = evaluate_model(
        model,
        X_test,
        y_test
    )

    save_results(
        model,
        metrics
    )

    print("\n==============================")
    print("ML TRAINING FINISHED")
    print("==============================")


if __name__ == "__main__":
    main()