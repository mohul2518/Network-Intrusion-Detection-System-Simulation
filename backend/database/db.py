import sqlite3
from pathlib import Path


# ==================================================
# DATABASE PATH
# ==================================================

BASE_DIR = Path(__file__).resolve().parents[2]

DATABASE_PATH = BASE_DIR / "data" / "ids_database.db"


# ==================================================
# UPGRADE EXISTING RULES TABLE
# ==================================================

def upgrade_rules_table():

    connection = sqlite3.connect(DATABASE_PATH)

    cursor = connection.cursor()

    cursor.execute("""
        PRAGMA table_info(rules)
    """)

    columns = [
        row[1]
        for row in cursor.fetchall()
    ]


    if "rule_name" not in columns:

        cursor.execute("""
            ALTER TABLE rules
            ADD COLUMN rule_name TEXT
        """)


    if "description" not in columns:

        cursor.execute("""
            ALTER TABLE rules
            ADD COLUMN description TEXT
        """)


    if "threshold" not in columns:

        cursor.execute("""
            ALTER TABLE rules
            ADD COLUMN threshold REAL DEFAULT 0
        """)


    if "severity" not in columns:

        cursor.execute("""
            ALTER TABLE rules
            ADD COLUMN severity TEXT DEFAULT 'MEDIUM'
        """)


    if "enabled" not in columns:

        cursor.execute("""
            ALTER TABLE rules
            ADD COLUMN enabled INTEGER DEFAULT 1
        """)


    if "created_at" not in columns:

        cursor.execute("""
            ALTER TABLE rules
            ADD COLUMN created_at TEXT
        """)


    connection.commit()

    connection.close()


# ==================================================
# CREATE DATABASE
# ==================================================

def create_database():

    DATABASE_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    cursor = connection.cursor()


    # ==================================================
    # NETWORK FLOWS
    # ==================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS network_flows (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            flow_id TEXT UNIQUE,

            timestamp TEXT,

            source_ip TEXT,

            destination_ip TEXT,

            source_port INTEGER,

            destination_port INTEGER,

            protocol TEXT,

            packet_count INTEGER,

            byte_count INTEGER,

            duration_seconds REAL,

            connection_count INTEGER,

            failed_connection_count INTEGER,

            syn_count INTEGER,

            rst_count INTEGER,

            average_packet_size REAL,

            label TEXT,

            scenario_type TEXT
        )
    """)


    # ==================================================
    # ALERTS
    # ==================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            alert_id TEXT UNIQUE,

            flow_id TEXT,

            timestamp TEXT,

            source_ip TEXT,

            destination_ip TEXT,

            protocol TEXT,

            source_port INTEGER,

            destination_port INTEGER,

            rule_id TEXT,

            alert_type TEXT,

            severity TEXT,

            risk_score REAL,

            description TEXT,

            status TEXT,

            anomaly_score REAL,

            classification TEXT,

            analyst_notes TEXT,

            resolution_notes TEXT
        )
    """)


    # ==================================================
    # RULES
    # ==================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS rules (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            rule_id TEXT UNIQUE,

            rule_name TEXT,

            description TEXT,

            threshold REAL,

            severity TEXT,

            enabled INTEGER DEFAULT 1,

            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)


    # ==================================================
    # INCIDENT NOTES
    # ==================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incident_notes (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            alert_id TEXT,

            note TEXT,

            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)


    connection.commit()

    connection.close()


# ==================================================
# INSERT DEFAULT RULES
# ==================================================

def insert_default_rules():

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    cursor = connection.cursor()


    rules = [

        (
            "HIGH_CONNECTION_RATE",
            "High Connection Rate",
            "Detects unusually high connection activity.",
            20,
            "HIGH"
        ),

        (
            "REPEATED_FAILED_CONNECTIONS",
            "Repeated Failed Connections",
            "Detects a high ratio of failed connections.",
            0.50,
            "HIGH"
        ),

        (
            "MULTI_PORT_PROBING",
            "Multi-Port Probing",
            "Detects unusually high connection activity associated with multiple destination ports.",
            50,
            "HIGH"
        ),

        (
            "SYN_HEAVY",
            "SYN Heavy Pattern",
            "Detects traffic with an unusually high SYN ratio.",
            0.40,
            "MEDIUM"
        ),

        (
            "UNUSUAL_PORT_ACTIVITY",
            "Unusual Port Activity",
            "Detects activity involving unusual service ports.",
            0,
            "HIGH"
        ),

        (
            "HIGH_TRAFFIC_VOLUME",
            "High Traffic Volume",
            "Detects unusually large traffic volumes.",
            5000000,
            "HIGH"
        )
    ]


    for rule in rules:

        cursor.execute("""
            INSERT OR IGNORE INTO rules
            (
                rule_id,
                rule_name,
                description,
                threshold,
                severity
            )

            VALUES (?, ?, ?, ?, ?)
        """, rule)


    connection.commit()

    connection.close()


# ==================================================
# INDEXES
# ==================================================

def create_indexes():

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    cursor = connection.cursor()


    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_flow_timestamp
        ON network_flows(timestamp)
    """)


    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_flow_source_ip
        ON network_flows(source_ip)
    """)


    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_alert_timestamp
        ON alerts(timestamp)
    """)


    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_alert_status
        ON alerts(status)
    """)


    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_alert_severity
        ON alerts(severity)
    """)


    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_rule_id
        ON rules(rule_id)
    """)


    connection.commit()

    connection.close()


# ==================================================
# MAIN
# ==================================================

if __name__ == "__main__":

    print("Initializing IDS database...")

    # 1. Create missing tables
    create_database()

    # 2. Upgrade old tables
    upgrade_rules_table()

    # 3. Insert default rules
    insert_default_rules()

    # 4. Create indexes
    create_indexes()

    print("IDS database initialized successfully.")

    print(
        f"Database location: {DATABASE_PATH}"
    )