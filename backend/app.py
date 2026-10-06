from pathlib import Path
import sys
from collections import Counter

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel


# --------------------------------------------------
# PROJECT ROOT
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parents[1]

if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))


# --------------------------------------------------
# DATABASE IMPORTS
# --------------------------------------------------

from backend.database.database_service import (
    get_connection,
    get_all_flows,
    get_all_alerts,
    get_alert_by_id,
    get_database_counts,
    update_alert_status,
    add_incident_note,
    get_incident_notes,
    add_resolution_note,
    get_alerts_for_correlation,
    get_all_rules,
    update_rule,
)


# --------------------------------------------------
# CORRELATION
# --------------------------------------------------

from ids.correlation import correlate_alerts


# --------------------------------------------------
# FASTAPI APP
# --------------------------------------------------

app = FastAPI(
    title="Network IDS Simulation",
    description="Defensive Network Intrusion Detection System Simulation",
    version="1.0.0"
)


# --------------------------------------------------
# CORS
# --------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --------------------------------------------------
# PYDANTIC MODELS
# --------------------------------------------------

class StatusRequest(BaseModel):

    status: str


class NoteRequest(BaseModel):

    note: str


class ResolutionNoteRequest(BaseModel):

    resolution_note: str


class RuleUpdateRequest(BaseModel):

    threshold: float | None = None

    severity: str | None = None

    enabled: bool | None = None


# --------------------------------------------------
# ROOT
# --------------------------------------------------

@app.get("/")
def root():

    return {
        "message": "Network IDS Simulation API is running",
        "version": "1.0.0"
    }


# --------------------------------------------------
# HEALTH
# --------------------------------------------------

@app.get("/api/health")
def health_check():

    return {
        "status": "healthy"
    }


# --------------------------------------------------
# API INFORMATION
# --------------------------------------------------

@app.get("/api")
def api_information():

    return {
        "project": "Network IDS Simulation",

        "endpoints": {

            "health": "/api/health",

            "flows": "/api/flows",

            "alerts": "/api/alerts",

            "dashboard_stats": "/api/dashboard/stats",

            "dashboard_traffic": "/api/dashboard/traffic",

            "dashboard_alerts": "/api/dashboard/alerts",

            "dashboard_top_sources": "/api/dashboard/top-sources",

            "dashboard_risk": "/api/dashboard/risk",

            "correlated_alerts": "/api/alerts/correlated",

            "rules": "/api/rules",

            "investigation_notes":
                "/api/alerts/{alert_id}/notes",

            "resolution":
                "/api/alerts/{alert_id}/resolution"
        }
    }


# ==================================================
# FLOWS
# ==================================================

@app.get("/api/flows")
def get_flows():

    flows = get_all_flows()

    return {
        "count": len(flows),
        "flows": flows
    }


# --------------------------------------------------
# GET FLOW BY ID
# --------------------------------------------------

@app.get("/api/flows/{flow_id}")
def get_flow(flow_id: str):

    connection = get_connection()

    try:

        cursor = connection.cursor()

        cursor.execute("""
            SELECT *
            FROM network_flows
            WHERE flow_id = ?
        """, (flow_id,))

        row = cursor.fetchone()

        if not row:

            raise HTTPException(
                status_code=404,
                detail="Flow not found"
            )

        return dict(row)

    finally:

        connection.close()


# ==================================================
# ALERTS
# ==================================================

@app.get("/api/alerts")
def get_alerts():

    alerts = get_all_alerts()

    return {
        "count": len(alerts),
        "alerts": alerts
    }


# --------------------------------------------------
# GET SINGLE ALERT
# --------------------------------------------------

@app.get("/api/alerts/{alert_id}")
def get_single_alert(alert_id: str):

    alert = get_alert_by_id(alert_id)

    if not alert:

        raise HTTPException(
            status_code=404,
            detail="Alert not found"
        )

    return alert


# --------------------------------------------------
# UPDATE ALERT STATUS
# --------------------------------------------------

@app.put("/api/alerts/{alert_id}/status")
def change_alert_status(
    alert_id: str,
    request: StatusRequest
):

    allowed_statuses = {
        "NEW",
        "INVESTIGATING",
        "RESOLVED",
        "FALSE_POSITIVE"
    }

    if request.status not in allowed_statuses:

        raise HTTPException(
            status_code=400,
            detail="Invalid alert status"
        )


    alert = get_alert_by_id(alert_id)

    if not alert:

        raise HTTPException(
            status_code=404,
            detail="Alert not found"
        )


    success = update_alert_status(
        alert_id,
        request.status
    )


    if not success:

        raise HTTPException(
            status_code=500,
            detail="Failed to update alert status"
        )


    return {
        "success": True,
        "alert_id": alert_id,
        "status": request.status,
        "message": "Alert status updated successfully"
    }


# ==================================================
# INCIDENT NOTES
# ==================================================

@app.post("/api/alerts/{alert_id}/notes")
def save_incident_note(
    alert_id: str,
    request: NoteRequest
):

    alert = get_alert_by_id(alert_id)

    if not alert:

        raise HTTPException(
            status_code=404,
            detail="Alert not found"
        )


    note = request.note.strip()

    if not note:

        raise HTTPException(
            status_code=400,
            detail="Note cannot be empty"
        )


    success = add_incident_note(
        alert_id,
        note
    )


    if not success:

        raise HTTPException(
            status_code=500,
            detail="Failed to save investigation note"
        )


    return {
        "success": True,
        "alert_id": alert_id,
        "message": "Investigation note saved successfully"
    }


# --------------------------------------------------
# GET INCIDENT NOTES
# --------------------------------------------------

@app.get("/api/alerts/{alert_id}/notes")
def get_notes(alert_id: str):

    alert = get_alert_by_id(alert_id)

    if not alert:

        raise HTTPException(
            status_code=404,
            detail="Alert not found"
        )


    notes = get_incident_notes(alert_id)


    return {
        "count": len(notes),
        "notes": notes
    }


# ==================================================
# RESOLUTION NOTES
# ==================================================

@app.post("/api/alerts/{alert_id}/resolution")
def save_resolution(
    alert_id: str,
    request: ResolutionNoteRequest
):

    alert = get_alert_by_id(alert_id)

    if not alert:

        raise HTTPException(
            status_code=404,
            detail="Alert not found"
        )


    resolution = request.resolution_note.strip()

    if not resolution:

        raise HTTPException(
            status_code=400,
            detail="Resolution note cannot be empty"
        )


    success = add_resolution_note(
        alert_id,
        resolution
    )


    if not success:

        raise HTTPException(
            status_code=500,
            detail="Failed to save resolution note"
        )


    return {
        "success": True,
        "alert_id": alert_id,
        "message": "Resolution note saved successfully"
    }


# ==================================================
# CORRELATED ALERTS
# IMPORTANT: KEEP THIS BEFORE /{alert_id}
# ==================================================

@app.get("/api/alerts/correlated")
def get_correlated_alerts():

    alerts = get_alerts_for_correlation()


    correlations = correlate_alerts(
        alerts,
        time_window_seconds=300
    )


    return {
        "count": len(correlations),
        "correlations": correlations
    }


# ==================================================
# DASHBOARD STATISTICS
# ==================================================

@app.get("/api/dashboard/stats")
def dashboard_stats():

    counts = get_database_counts()


    return {
        "total_flows":
            counts.get("total_flows", 0),

        "normal_flows":
            counts.get("normal_flows", 0),

        "suspicious_flows":
            counts.get("suspicious_flows", 0),

        "total_alerts":
            counts.get("total_alerts", 0),

        "open_alerts":
            counts.get("open_alerts", 0),

        "average_risk":
            counts.get("average_risk", 0)
    }


# ==================================================
# DASHBOARD TRAFFIC
# ==================================================

@app.get("/api/dashboard/traffic")
def dashboard_traffic():

    flows = get_all_flows()


    traffic = []


    for flow in flows:

        traffic.append({
            "timestamp":
                flow.get("timestamp"),

            "bytes":
                flow.get("byte_count", 0),

            "packets":
                flow.get("packet_count", 0),

            "label":
                flow.get("label", "NORMAL")
        })


    return {
        "count": len(traffic),
        "traffic": traffic
    }


# ==================================================
# DASHBOARD ALERT STATISTICS
# ==================================================

@app.get("/api/dashboard/alerts")
def dashboard_alerts():

    alerts = get_all_alerts()


    severity_counter = Counter()
    alert_type_counter = Counter()
    protocol_counter = Counter()


    for alert in alerts:

        severity_counter[
            alert.get("severity", "UNKNOWN")
        ] += 1


        alert_type_counter[
            alert.get("alert_type", "UNKNOWN")
        ] += 1


        protocol_counter[
            alert.get("protocol", "UNKNOWN")
        ] += 1


    return {

        "severity": dict(
            severity_counter
        ),

        "alert_types": dict(
            alert_type_counter
        ),

        "protocols": dict(
            protocol_counter
        )
    }


# ==================================================
# TOP SOURCE IPS
# ==================================================

@app.get("/api/dashboard/top-sources")
def dashboard_top_sources():

    alerts = get_all_alerts()


    source_counter = Counter()


    for alert in alerts:

        source_ip = alert.get(
            "source_ip",
            "UNKNOWN"
        )

        source_counter[source_ip] += 1


    top_sources = [

        {
            "source_ip": ip,
            "count": count
        }

        for ip, count
        in source_counter.most_common(10)

    ]


    return {
        "sources": top_sources
    }


# ==================================================
# RISK DISTRIBUTION
# ==================================================

@app.get("/api/dashboard/risk")
def dashboard_risk():

    alerts = get_all_alerts()


    distribution = {

        "NORMAL": 0,

        "LOW_RISK": 0,

        "SUSPICIOUS": 0,

        "HIGH_RISK": 0,

        "CRITICAL": 0
    }


    for alert in alerts:

        risk = alert.get(
            "risk_score",
            0
        )


        try:

            risk = float(risk)

        except:

            risk = 0


        if risk <= 20:

            distribution["NORMAL"] += 1

        elif risk <= 40:

            distribution["LOW_RISK"] += 1

        elif risk <= 60:

            distribution["SUSPICIOUS"] += 1

        elif risk <= 80:

            distribution["HIGH_RISK"] += 1

        else:

            distribution["CRITICAL"] += 1


    return distribution


# ==================================================
# RULE MANAGEMENT
# ==================================================

@app.get("/api/rules")
def get_rules():

    rules = get_all_rules()


    return {
        "count": len(rules),
        "rules": rules
    }


# --------------------------------------------------
# UPDATE RULE
# --------------------------------------------------

@app.put("/api/rules/{rule_id}")
def change_rule(
    rule_id: str,
    request: RuleUpdateRequest
):

    allowed_severities = {
        "INFO",
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL"
    }


    if (
        request.severity is not None
        and request.severity not in allowed_severities
    ):

        raise HTTPException(
            status_code=400,
            detail="Invalid severity"
        )


    if (
        request.threshold is not None
        and request.threshold < 0
    ):

        raise HTTPException(
            status_code=400,
            detail="Threshold cannot be negative"
        )


    success = update_rule(

        rule_id=rule_id,

        threshold=request.threshold,

        severity=request.severity,

        enabled=request.enabled
    )


    if not success:

        raise HTTPException(
            status_code=404,
            detail="Rule not found"
        )


    return {

        "success": True,

        "rule_id": rule_id,

        "message":
            "Rule updated successfully"
    }


# ==================================================
# STARTUP
# ==================================================

@app.on_event("startup")
def startup_event():

    print(
        "Network IDS Simulation API started successfully."
    )