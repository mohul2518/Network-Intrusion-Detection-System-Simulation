import json
import time
from pathlib import Path

from ids_engine import analyze_network_flow

import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.database.database_service import (
    insert_flow,
    insert_alert,
)


BASE_DIR = Path(__file__).resolve().parents[1]

LIVE_FLOW_FILE = BASE_DIR / "data" / "live_flows.jsonl"
ALERT_FILE = BASE_DIR / "data" / "alerts.jsonl"


def process_flow(flow: dict):
    """
    Process one synthetic network flow through the IDS engine.
    """

    print("\n" + "=" * 60)
    print("Processing flow:", flow.get("flow_id"))
    print("=" * 60)

    # ---------------------------------------------------------
    # 1. Store the network flow in SQLite
    # ---------------------------------------------------------

    try:
        flow_db_id = insert_flow(flow)

        print(f"Flow stored in database. DB ID: {flow_db_id}")

    except Exception as error:
        print(f"Database error while storing flow: {error}")

    # ---------------------------------------------------------
    # 2. Analyze the flow using the IDS engine
    # ---------------------------------------------------------

    try:
        result = analyze_network_flow(flow)

    except Exception as error:
        print(f"IDS analysis error: {error}")
        return None

    # ---------------------------------------------------------
    # 3. Display IDS result
    # ---------------------------------------------------------

    if not result:
        print("No analysis result.")
        return None

    print("\nIDS Classification:")
    print(result.get("classification"))

    print("Risk Score:")
    print(result.get("risk_score"))

    print("Severity:")
    print(result.get("severity"))

    # ---------------------------------------------------------
    # 4. Save alert if one was generated
    # ---------------------------------------------------------

    alert = result.get("alert")

    if alert:

        try:
            alert_db_id = insert_alert(alert)

            print(f"\nALERT STORED IN DATABASE")
            print(f"Alert DB ID: {alert_db_id}")
            print(f"Alert ID: {alert.get('alert_id')}")
            print(f"Severity: {alert.get('severity')}")
            print(f"Risk Score: {alert.get('risk_score')}")
            print(f"Type: {alert.get('alert_type')}")

        except Exception as error:
            print(f"Database error while storing alert: {error}")

        # Also keep JSONL output for debugging/history.
        try:
            save_alert(alert)
        except Exception as error:
            print(f"Could not save JSON alert: {error}")

    else:
        print("\nNo alert generated.")

    return result


def save_alert(alert: dict):
    """
    Save an alert to data/alerts.jsonl.
    """

    ALERT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with ALERT_FILE.open("a", encoding="utf-8") as file:

        file.write(
            json.dumps(alert, default=str) + "\n"
        )


def process_existing_flows():
    """
    Process all flows currently present in live_flows.jsonl.
    """

    if not LIVE_FLOW_FILE.exists():

        print("No live flow file found.")

        return

    with LIVE_FLOW_FILE.open(
        "r",
        encoding="utf-8"
    ) as file:

        for line in file:

            line = line.strip()

            if not line:
                continue

            try:

                flow = json.loads(line)

                process_flow(flow)

            except json.JSONDecodeError:

                print("Skipping invalid JSON line.")

            except Exception as error:

                print(f"Unexpected processing error: {error}")


def watch_live_flows():
    """
    Watch live_flows.jsonl and process new flows
    as they appear.
    """

    print("\nWatching for new synthetic network flows...")
    print("Press CTRL+C to stop.\n")

    if not LIVE_FLOW_FILE.exists():

        LIVE_FLOW_FILE.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        LIVE_FLOW_FILE.touch()

    with LIVE_FLOW_FILE.open(
        "r",
        encoding="utf-8"
    ) as file:

        # Start from the end of the existing file.
        file.seek(0, 2)

        while True:

            line = file.readline()

            if not line:

                time.sleep(0.5)

                continue

            line = line.strip()

            if not line:
                continue

            try:

                flow = json.loads(line)

                process_flow(flow)

            except json.JSONDecodeError:

                print("Skipping invalid JSON line.")

            except Exception as error:

                print(
                    f"Unexpected processing error: {error}"
                )


def main():

    print("=" * 60)
    print("NETWORK IDS FLOW PROCESSOR")
    print("=" * 60)

    print("\nProcessing existing flows...")

    process_existing_flows()

    print("\nFlow processing completed.")

    print("\nCurrent database statistics:")

    try:

        from backend.database.database_service import (
            get_database_counts
        )

        counts = get_database_counts()

        print(
            f"Total flows: "
            f"{counts['total_flows']}"
        )

        print(
            f"Total alerts: "
            f"{counts['total_alerts']}"
        )

        print(
            f"Open alerts: "
            f"{counts['open_alerts']}"
        )

    except Exception as error:

        print(
            f"Could not read database statistics: "
            f"{error}"
        )


if __name__ == "__main__":
    main()