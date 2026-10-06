const API_BASE = "http://127.0.0.1:8000";


async function fetchJSON(endpoint) {

    const response = await fetch(
        `${API_BASE}${endpoint}`
    );

    if (!response.ok) {
        throw new Error(
            `API error: ${response.status}`
        );
    }

    return await response.json();
}


/* --------------------------------------------------
   Dashboard statistics
-------------------------------------------------- */

async function loadStats() {

    const data = await fetchJSON(
        "/api/dashboard/stats"
    );

    document.getElementById(
        "totalFlows"
    ).textContent = data.total_flows;

    document.getElementById(
        "normalFlows"
    ).textContent = data.normal_flows;

    document.getElementById(
        "suspiciousFlows"
    ).textContent = data.suspicious_flows;

    document.getElementById(
        "totalAlerts"
    ).textContent = data.total_alerts;

    document.getElementById(
        "openAlerts"
    ).textContent = data.open_alerts;

    document.getElementById(
        "averageRisk"
    ).textContent = data.average_risk;
}


/* --------------------------------------------------
   Create simple chart/list
-------------------------------------------------- */

function renderList(
    containerId,
    items,
    labelKey,
    valueKey
) {

    const container =
        document.getElementById(containerId);

    container.innerHTML = "";

    if (!items || items.length === 0) {

        container.innerHTML =
            "<p>No data available.</p>";

        return;
    }

    items.forEach(item => {

        const row =
            document.createElement("div");

        row.className = "chart-item";

        const label =
            document.createElement("span");

        label.className = "chart-label";

        label.textContent =
            item[labelKey];

        const value =
            document.createElement("span");

        value.className = "chart-value";

        value.textContent =
            item[valueKey];

        row.appendChild(label);

        row.appendChild(value);

        container.appendChild(row);

    });
}


/* --------------------------------------------------
   Alert statistics
-------------------------------------------------- */

async function loadAlertStatistics() {

    const data = await fetchJSON(
        "/api/dashboard/alerts"
    );

    renderList(
        "severityChart",
        data.severity,
        "severity",
        "count"
    );

    renderList(
        "alertTypesChart",
        data.alert_types,
        "alert_type",
        "count"
    );

    renderList(
        "protocolChart",
        data.protocols,
        "protocol",
        "count"
    );
}


/* --------------------------------------------------
   Risk distribution
-------------------------------------------------- */

async function loadRiskDistribution() {

    const data = await fetchJSON(
        "/api/dashboard/risk"
    );

    const items = Object.entries(data)
        .map(([label, count]) => ({
            label,
            count
        }));

    renderList(
        "riskChart",
        items,
        "label",
        "count"
    );
}


/* --------------------------------------------------
   Top source IPs
-------------------------------------------------- */

async function loadTopSources() {

    const data = await fetchJSON(
        "/api/dashboard/top-sources"
    );

    const container =
        document.getElementById("topSources");

    container.innerHTML = "";

    if (
        !data.sources ||
        data.sources.length === 0
    ) {

        container.innerHTML =
            "<p>No alert sources available.</p>";

        return;
    }

    data.sources.forEach(source => {

        const row =
            document.createElement("div");

        row.className = "source-item";

        const ip =
            document.createElement("span");

        ip.className = "source-ip";

        ip.textContent =
            source.source_ip;

        const count =
            document.createElement("strong");

        count.textContent =
            `${source.alert_count} alerts`;

        row.appendChild(ip);

        row.appendChild(count);

        container.appendChild(row);

    });
}


/* --------------------------------------------------
   Recent alerts
-------------------------------------------------- */

async function loadAlerts() {

    const data = await fetchJSON(
        "/api/alerts?limit=20"
    );

    const table =
        document.getElementById("alertsTable");

    table.innerHTML = "";

    if (
        !data.alerts ||
        data.alerts.length === 0
    ) {

        table.innerHTML = `
            <tr>
                <td colspan="8">
                    No alerts available.
                </td>
            </tr>
        `;

        return;
    }

    data.alerts.forEach(alert => {

        const row =
            document.createElement("tr");

        const severity =
            String(
                alert.severity || "INFO"
            ).replaceAll(" ", "_");

        const status =
            String(
                alert.status || "NEW"
            ).replaceAll(" ", "_");

        row.innerHTML = `
            <td>${escapeHTML(
                alert.alert_id
            )}</td>

            <td>${escapeHTML(
                alert.timestamp
            )}</td>

            <td>${escapeHTML(
                alert.source_ip
            )}</td>

            <td>${escapeHTML(
                alert.destination_ip
            )}</td>

            <td>${escapeHTML(
                alert.alert_type
            )}</td>

            <td>
                <span class="badge severity-${severity}">
                    ${escapeHTML(
                        alert.severity
                    )}
                </span>
            </td>

            <td>${escapeHTML(
                alert.risk_score
            )}</td>

            <td>
                <span class="badge status-${status}">
                    ${escapeHTML(
                        alert.status
                    )}
                </span>
            </td>
        `;

        table.appendChild(row);

    });
}


/* --------------------------------------------------
   Basic HTML escaping
-------------------------------------------------- */

function escapeHTML(value) {

    if (value === null ||
        value === undefined) {

        return "";
    }

    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}


/* --------------------------------------------------
   Load complete dashboard
-------------------------------------------------- */

async function loadDashboard() {

    try {

        await loadStats();

        await loadAlertStatistics();

        await loadRiskDistribution();

        await loadTopSources();

        await loadAlerts();

        document.getElementById(
            "lastUpdated"
        ).textContent =
            `Last updated: ${
                new Date().toLocaleString()
            }`;

    } catch (error) {

        console.error(
            "Dashboard loading error:",
            error
        );

        document.getElementById(
            "lastUpdated"
        ).textContent =
            "Unable to connect to IDS backend.";

    }
}


/* --------------------------------------------------
   Initial load
-------------------------------------------------- */

loadDashboard();


/* --------------------------------------------------
   Auto refresh every 10 seconds
-------------------------------------------------- */

setInterval(
    loadDashboard,
    10000
);