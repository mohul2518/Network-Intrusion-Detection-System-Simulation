import sys
from pathlib import Path

import joblib
import pandas as pd


# ---------------------------------------------------------
# PROJECT PATH
# ---------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parents[1]

MODEL_FILE = BASE_DIR / "models" / "random_forest_ids_model.joblib"


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
# LOAD MODEL
# ---------------------------------------------------------

def load_model():

    if not MODEL_FILE.exists():

        raise FileNotFoundError(
            f"Trained model not found: {MODEL_FILE}"
        )

    return joblib.load(MODEL_FILE)


# ---------------------------------------------------------
# PREPARE FLOW
# ---------------------------------------------------------

def prepare_flow(flow):

    data = {}

    for feature in FEATURE_COLUMNS:

        value = flow.get(feature, 0)

        if value is None:
            value = 0

        data[feature] = value

    dataframe = pd.DataFrame(
        [data],
        columns=FEATURE_COLUMNS
    )

    return dataframe


# ---------------------------------------------------------
# PREDICT FLOW
# ---------------------------------------------------------

def predict_flow(flow):

    model = load_model()

    dataframe = prepare_flow(flow)

    prediction = model.predict(dataframe)[0]

    # Get probability if the model supports it
    probability = model.predict_proba(dataframe)[0]

    normal_probability = float(probability[0])
    suspicious_probability = float(probability[1])

    if prediction == 1:

        classification = "SUSPICIOUS"

    else:

        classification = "NORMAL"

    return {
        "prediction": int(prediction),
        "classification": classification,
        "normal_probability": round(
            normal_probability,
            4
        ),
        "suspicious_probability": round(
            suspicious_probability,
            4
        ),
        "ml_score": round(
            suspicious_probability * 100,
            2
        )
    }


# ---------------------------------------------------------
# DEMO
# ---------------------------------------------------------

def demo():

    print("==============================")
    print("IDS ML PREDICTION TEST")
    print("==============================")

    sample_flow = {
        "packet_count": 150,
        "byte_count": 120000,
        "duration_seconds": 5,
        "connection_count": 30,
        "failed_connection_count": 15,
        "syn_count": 20,
        "rst_count": 5,
        "average_packet_size": 800,
        "source_port": 45000,
        "destination_port": 22,
    }

    result = predict_flow(sample_flow)

    print("\nSample Flow:")
    print(sample_flow)

    print("\nML Prediction:")
    print(f"Classification: {result['classification']}")
    print(f"Normal probability: {result['normal_probability']}")
    print(
        f"Suspicious probability: "
        f"{result['suspicious_probability']}"
    )
    print(f"ML score: {result['ml_score']}")

    print("\nPrediction completed successfully.")


# ---------------------------------------------------------
# MAIN
# ---------------------------------------------------------

if __name__ == "__main__":

    demo()