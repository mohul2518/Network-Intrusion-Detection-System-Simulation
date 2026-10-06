import sqlite3
from pathlib import Path


# ==================================================
# DATABASE PATH
# ==================================================

BASE_DIR = Path(__file__).resolve().parents[2]

DATABASE_PATH = BASE_DIR / "data" / "ids_database.db"


# ==================================================
# DATABASE CONNECTION
# ==================================================

def get_connection():

    connection = sqlite3.connect(
        DATABASE_PATH,
        timeout=10
    )

    connection.row_factory = sqlite3.Row

    connection.execute(
        "PRAGMA busy_timeout = 10000"
    )

    return connection


# ==================================================
# INSERT FLOW
# ==================================================

def insert_flow(flow):

    connection = get_connection()

    try:

        cursor = connection.cursor()

        cursor.execute("""
            INSERT OR IGNORE INTO network_flows
            (
                flow_id,
                timestamp,
                source_ip,
                destination_ip,
                source_port,
                destination_port,
                protocol,
                packet_count,
                byte_count,
                duration_seconds,
                connection_count,
                failed_connection_count,
                syn_count,
                rst_count,
                average_packet_size,
                label,
                scenario_type
            )

            VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?
            )
        """, (

            flow.get("flow_id"),

            flow.get("timestamp"),

            flow.get("source_ip"),

            flow.get("destination_ip"),

            flow.get("source_port"),

            flow.get("destination_port"),

            flow.get("protocol"),

            flow.get("packet_count"),

            flow.get("byte_count"),

            flow.get("duration_seconds"),

            flow.get("connection_count"),

            flow.get("failed_connection_count"),

            flow.get("syn_count"),

            flow.get("rst_count"),

            flow.get("average_packet_size"),

            flow.get("label"),

            flow.get("scenario_type")
        ))

        connection.commit()

        return True

    except sqlite3.Error as error:

        print(
            f"Database error while storing flow: {error}"
        )

        return False

    finally:

        connection.close()


# ==================================================
# INSERT ALERT
# ==================================================

def insert_alert(alert):

    connection = get_connection()

    try:

        cursor = connection.cursor()


        # ------------------------------------------
        # MATCHED RULES
        # ------------------------------------------

        matched_rules = alert.get(
            "matched_rules",
            []
        )

        rule_ids = []

        if isinstance(matched_rules, list):

            for rule in matched_rules:

                if isinstance(rule, dict):

                    rule_id = (
                        rule.get("rule_id")
                        or rule.get("id")
                        or rule.get("rule")
                    )

                    if rule_id:

                        rule_ids.append(
                            str(rule_id)
                        )

                else:

                    rule_ids.append(
                        str(rule)
                    )


        rule_id = alert.get("rule_id")

        if not rule_id and rule_ids:

            rule_id = rule_ids[0]


        matched_rule_text = ",".join(
            rule_ids
        )


        cursor.execute("""
            INSERT OR REPLACE INTO alerts
            (
                alert_id,
                flow_id,
                timestamp,
                source_ip,
                destination_ip,
                protocol,
                source_port,
                destination_port,
                rule_id,
                alert_type,
                severity,
                risk_score,
                description,
                status
            )

            VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?
            )
        """, (

            alert.get("alert_id"),

            alert.get("flow_id"),

            alert.get("timestamp"),

            alert.get("source_ip"),

            alert.get("destination_ip"),

            alert.get("protocol"),

            alert.get("source_port"),

            alert.get("destination_port"),

            rule_id or matched_rule_text,

            alert.get("alert_type"),

            alert.get("severity"),

            alert.get("risk_score"),

            alert.get("description"),

            alert.get("status", "NEW")
        ))


        connection.commit()

        return True

    except sqlite3.Error as error:

        print(
            f"Database error while storing alert: {error}"
        )

        return False

    finally:

        connection.close()


# ==================================================
# GET ALL FLOWS
# ==================================================

def get_all_flows():

    connection = get_connection()

    try:

        cursor = connection.cursor()

        cursor.execute("""
            SELECT *
            FROM network_flows
            ORDER BY timestamp DESC
        """)

        rows = cursor.fetchall()

        return [
            dict(row)
            for row in rows
        ]

    finally:

        connection.close()


# ==================================================
# GET ALL ALERTS
# ==================================================

def get_all_alerts():

    connection = get_connection()

    try:

        cursor = connection.cursor()

        cursor.execute("""
            SELECT *
            FROM alerts
            ORDER BY timestamp DESC
        """)

        rows = cursor.fetchall()

        return [
            dict(row)
            for row in rows
        ]

    finally:

        connection.close()


# ==================================================
# GET ALERT BY ID
# ==================================================

def get_alert_by_id(alert_id: str):

    connection = get_connection()

    try:

        cursor = connection.cursor()

        cursor.execute("""
            SELECT *
            FROM alerts
            WHERE alert_id = ?
        """, (alert_id,))

        row = cursor.fetchone()

        if row:

            return dict(row)

        return None

    finally:

        connection.close()


# ==================================================
# UPDATE ALERT STATUS
# ==================================================

def update_alert_status(
    alert_id: str,
    status: str
):

    connection = get_connection()

    try:

        cursor = connection.cursor()

        cursor.execute("""
            UPDATE alerts

            SET status = ?

            WHERE alert_id = ?
        """, (
            status,
            alert_id
        ))

        connection.commit()

        return cursor.rowcount > 0

    finally:

        connection.close()


# ==================================================
# ADD INCIDENT NOTE
# ==================================================

def add_incident_note(
    alert_id: str,
    note: str
):

    connection = get_connection()

    try:

        cursor = connection.cursor()

        cursor.execute("""
            INSERT INTO incident_notes
            (
                alert_id,
                note
            )

            VALUES (?, ?)
        """, (
            alert_id,
            note
        ))

        connection.commit()

        return True

    except sqlite3.Error as error:

        print(
            f"Database error while saving note: {error}"
        )

        return False

    finally:

        connection.close()


# ==================================================
# GET INCIDENT NOTES
# ==================================================

def get_incident_notes(
    alert_id: str
):

    connection = get_connection()

    try:

        cursor = connection.cursor()

        cursor.execute("""
            SELECT
                id,
                alert_id,
                note,
                created_at

            FROM incident_notes

            WHERE alert_id = ?

            ORDER BY id ASC
        """, (
            alert_id,
        ))

        rows = cursor.fetchall()

        return [
            dict(row)
            for row in rows
        ]

    finally:

        connection.close()


# ==================================================
# ADD RESOLUTION NOTE
# ==================================================

def add_resolution_note(
    alert_id: str,
    resolution_note: str
):

    connection = get_connection()

    try:

        cursor = connection.cursor()

        cursor.execute("""
            UPDATE alerts

            SET resolution_notes = ?

            WHERE alert_id = ?
        """, (
            resolution_note,
            alert_id
        ))

        connection.commit()

        return cursor.rowcount > 0

    except sqlite3.Error as error:

        print(
            f"Database error while saving resolution: {error}"
        )

        return False

    finally:

        connection.close()


# ==================================================
# GET ALERTS FOR CORRELATION
# ==================================================

def get_alerts_for_correlation():

    connection = get_connection()

    try:

        cursor = connection.cursor()

        cursor.execute("""
            SELECT *
            FROM alerts
            ORDER BY timestamp ASC
        """)

        rows = cursor.fetchall()

        return [
            dict(row)
            for row in rows
        ]

    finally:

        connection.close()


# ==================================================
# GET ALL RULES
# ==================================================

def get_all_rules():

    connection = get_connection()

    try:

        cursor = connection.cursor()

        cursor.execute("""
            SELECT
                id,
                rule_id,
                rule_name,
                description,
                threshold,
                severity,
                enabled,
                created_at

            FROM rules

            ORDER BY id ASC
        """)

        rows = cursor.fetchall()

        return [
            dict(row)
            for row in rows
        ]

    finally:

        connection.close()


# ==================================================
# UPDATE RULE
# ==================================================

def update_rule(
    rule_id: str,
    threshold=None,
    severity=None,
    enabled=None
):

    connection = get_connection()

    try:

        cursor = connection.cursor()

        cursor.execute("""
            SELECT *
            FROM rules

            WHERE rule_id = ?
        """, (
            rule_id,
        ))

        existing = cursor.fetchone()

        if not existing:

            return False


        current_threshold = existing["threshold"]

        current_severity = existing["severity"]

        current_enabled = existing["enabled"]


        if threshold is None:

            threshold = current_threshold


        if severity is None:

            severity = current_severity


        if enabled is None:

            enabled = current_enabled


        cursor.execute("""
            UPDATE rules

            SET
                threshold = ?,
                severity = ?,
                enabled = ?

            WHERE rule_id = ?
        """, (
            threshold,
            severity,
            int(bool(enabled)),
            rule_id
        ))


        connection.commit()

        return cursor.rowcount > 0

    finally:

        connection.close()


# ==================================================
# DATABASE COUNTS
# ==================================================

def get_database_counts():

    connection = get_connection()

    try:

        cursor = connection.cursor()


        # ------------------------------------------
        # TOTAL FLOWS
        # ------------------------------------------

        cursor.execute("""
            SELECT COUNT(*)
            FROM network_flows
        """)

        total_flows = cursor.fetchone()[0]


        # ------------------------------------------
        # NORMAL FLOWS
        # ------------------------------------------

        cursor.execute("""
            SELECT COUNT(*)
            FROM network_flows
            WHERE label = 'NORMAL'
        """)

        normal_flows = cursor.fetchone()[0]


        # ------------------------------------------
        # SUSPICIOUS FLOWS
        # ------------------------------------------

        cursor.execute("""
            SELECT COUNT(*)
            FROM network_flows
            WHERE label = 'SUSPICIOUS'
        """)

        suspicious_flows = cursor.fetchone()[0]


        # ------------------------------------------
        # TOTAL ALERTS
        # ------------------------------------------

        cursor.execute("""
            SELECT COUNT(*)
            FROM alerts
        """)

        total_alerts = cursor.fetchone()[0]


        # ------------------------------------------
        # OPEN ALERTS
        # ------------------------------------------

        cursor.execute("""
            SELECT COUNT(*)
            FROM alerts

            WHERE status IN (
                'NEW',
                'INVESTIGATING'
            )
        """)

        open_alerts = cursor.fetchone()[0]


        # ------------------------------------------
        # AVERAGE RISK
        # ------------------------------------------

        cursor.execute("""
            SELECT AVG(risk_score)
            FROM alerts
        """)

        average_risk = cursor.fetchone()[0]


        if average_risk is None:

            average_risk = 0


        return {

            "total_flows":
                total_flows,

            "normal_flows":
                normal_flows,

            "suspicious_flows":
                suspicious_flows,

            "total_alerts":
                total_alerts,

            "open_alerts":
                open_alerts,

            "average_risk":
                round(
                    float(average_risk),
                    2
                )
        }

    finally:

        connection.close()


# ==================================================
# TEST
# ==================================================

if __name__ == "__main__":

    print(
        "Testing database service..."
    )

    print(
        f"Database: {DATABASE_PATH}"
    )


    print(
        "\nDatabase counts:"
    )

    print(
        get_database_counts()
    )


    print(
        "\nRules:"
    )

    print(
        get_all_rules()
    )


    print(
        "\nDatabase service test completed."
    )