import json
from pathlib import Path

import matplotlib.pyplot as plt


# ---------------------------------------------------------
# PROJECT PATHS
# ---------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parents[1]

METRICS_FILE = BASE_DIR / "models" / "ml_metrics.json"

CONFUSION_MATRIX_FILE = (
    BASE_DIR / "models" / "confusion_matrix.json"
)

REPORTS_DIR = BASE_DIR / "reports"

CONFUSION_MATRIX_IMAGE = (
    REPORTS_DIR / "ml_confusion_matrix.png"
)


# ---------------------------------------------------------
# LOAD METRICS
# ---------------------------------------------------------

def load_metrics():

    if not METRICS_FILE.exists():
        raise FileNotFoundError(
            f"Metrics file not found: {METRICS_FILE}"
        )

    with open(
        METRICS_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        return json.load(file)


# ---------------------------------------------------------
# LOAD CONFUSION MATRIX
# ---------------------------------------------------------

def load_confusion_matrix():

    if not CONFUSION_MATRIX_FILE.exists():
        raise FileNotFoundError(
            f"Confusion matrix not found: "
            f"{CONFUSION_MATRIX_FILE}"
        )

    with open(
        CONFUSION_MATRIX_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        return json.load(file)


# ---------------------------------------------------------
# DISPLAY METRICS
# ---------------------------------------------------------

def display_metrics(metrics):

    print("\n================================")
    print("ML MODEL EVALUATION")
    print("================================")

    print(
        f"Accuracy : "
        f"{metrics['accuracy']:.4f}"
    )

    print(
        f"Precision: "
        f"{metrics['precision']:.4f}"
    )

    print(
        f"Recall   : "
        f"{metrics['recall']:.4f}"
    )

    print(
        f"F1 Score : "
        f"{metrics['f1_score']:.4f}"
    )


# ---------------------------------------------------------
# CREATE CONFUSION MATRIX IMAGE
# ---------------------------------------------------------

def create_confusion_matrix_image(matrix):

    REPORTS_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    plt.figure(
        figsize=(6, 5)
    )

    plt.imshow(
        matrix,
        interpolation="nearest"
    )

    plt.title(
        "Network IDS - ML Confusion Matrix"
    )

    plt.colorbar()

    labels = [
        "NORMAL",
        "SUSPICIOUS"
    ]

    plt.xticks(
        [0, 1],
        labels
    )

    plt.yticks(
        [0, 1],
        labels
    )

    plt.xlabel(
        "Predicted Label"
    )

    plt.ylabel(
        "Actual Label"
    )

    # Write values inside the matrix
    for row in range(len(matrix)):

        for column in range(len(matrix[row])):

            plt.text(
                column,
                row,
                str(matrix[row][column]),
                ha="center",
                va="center"
            )

    plt.tight_layout()

    plt.savefig(
        CONFUSION_MATRIX_IMAGE,
        dpi=150
    )

    plt.close()

    print(
        f"\nConfusion matrix image saved to:"
    )

    print(
        CONFUSION_MATRIX_IMAGE
    )


# ---------------------------------------------------------
# MAIN
# ---------------------------------------------------------

def main():

    print("Loading ML evaluation results...")

    metrics = load_metrics()

    matrix = load_confusion_matrix()

    display_metrics(
        metrics
    )

    print("\nConfusion Matrix:")

    for row in matrix:
        print(row)

    create_confusion_matrix_image(
        matrix
    )

    print("\n================================")
    print("EVALUATION COMPLETE")
    print("================================")


if __name__ == "__main__":
    main()