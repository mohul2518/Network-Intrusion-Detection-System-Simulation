const API_BASE = "http://127.0.0.1:8000";


// Get alert ID from URL

const urlParams = new URLSearchParams(window.location.search);

const alertId = urlParams.get("id");


// --------------------------------------------------
// LOAD ALERT
// --------------------------------------------------

async function loadAlert() {

    if (!alertId) {

        document.getElementById("alertDetails").innerHTML =
            "<p>No alert ID was provided.</p>";

        return;
    }

    try {

        const response = await fetch(
            `${API_BASE}/api/alerts/${encodeURIComponent(alertId)}`
        );

        if (!response.ok) {

            throw new Error("Alert not found");
        }

        const alert = await response.json();

        displayAlert(alert);

        await loadNotes();

    } catch (error) {

        console.error(error);

        document.getElementById("alertDetails").innerHTML =
            `<p>Error loading alert: ${escapeHtml(error.message)}</p>`;
    }
}



// --------------------------------------------------
// DISPLAY ALERT
// --------------------------------------------------

function displayAlert(alert) {

    const container =
        document.getElementById("alertDetails");

    const matchedRules =
        formatRules(alert.matched_rules);

    container.innerHTML = `

        <div class="alert-details">

            <p>
                <strong>Alert ID:</strong>
                ${escapeHtml(alert.alert_id || "-")}
            </p>

            <p>
                <strong>Flow ID:</strong>
                ${escapeHtml(alert.flow_id || "-")}
            </p>

            <p>
                <strong>Timestamp:</strong>
                ${escapeHtml(alert.timestamp || "-")}
            </p>

            <p>
                <strong>Source IP:</strong>
                ${escapeHtml(alert.source_ip || "-")}
            </p>

            <p>
                <strong>Destination IP:</strong>
                ${escapeHtml(alert.destination_ip || "-")}
            </p>

            <p>
                <strong>Protocol:</strong>
                ${escapeHtml(alert.protocol || "-")}
            </p>

            <p>
                <strong>Source Port:</strong>
                ${escapeHtml(String(alert.source_port ?? "-"))}
            </p>

            <p>
                <strong>Destination Port:</strong>
                ${escapeHtml(String(alert.destination_port ?? "-"))}
            </p>

            <p>
                <strong>Alert Type:</strong>
                ${escapeHtml(alert.alert_type || "-")}
            </p>

            <p>
                <strong>Severity:</strong>
                ${escapeHtml(alert.severity || "-")}
            </p>

            <p>
                <strong>Risk Score:</strong>
                ${escapeHtml(String(alert.risk_score ?? "-"))}
            </p>

            <p>
                <strong>Anomaly Score:</strong>
                ${escapeHtml(String(alert.anomaly_score ?? "-"))}
            </p>

            <p>
                <strong>Classification:</strong>
                ${escapeHtml(alert.classification || "-")}
            </p>

            <p>
                <strong>Status:</strong>
                ${escapeHtml(alert.status || "-")}
            </p>

            <p>
                <strong>Description:</strong>
                ${escapeHtml(alert.description || "-")}
            </p>

            <p>
                <strong>Matched Rules:</strong>
            </p>

            <div>
                ${matchedRules}
            </div>

        </div>
    `;


    // Set current status in dropdown

    const statusSelect =
        document.getElementById("status");

    if (alert.status) {

        statusSelect.value = alert.status;
    }
}



// --------------------------------------------------
// FORMAT RULES
// --------------------------------------------------

function formatRules(rules) {

    if (!rules) {

        return "<p>No matched rules.</p>";
    }


    if (!Array.isArray(rules)) {

        return `<p>${escapeHtml(String(rules))}</p>`;
    }


    if (rules.length === 0) {

        return "<p>No matched rules.</p>";
    }


    return `
        <ul>
            ${rules.map(rule => {

                if (typeof rule === "object") {

                    return `
                        <li>
                            ${escapeHtml(
                                rule.rule_id ||
                                rule.id ||
                                JSON.stringify(rule)
                            )}
                        </li>
                    `;

                }

                return `
                    <li>
                        ${escapeHtml(String(rule))}
                    </li>
                `;

            }).join("")}
        </ul>
    `;
}



// --------------------------------------------------
// UPDATE STATUS
// --------------------------------------------------

async function updateStatus() {

    const status =
        document.getElementById("status").value;

    const message =
        document.getElementById("statusMessage");


    try {

        const response = await fetch(
            `${API_BASE}/api/alerts/${encodeURIComponent(alertId)}/status`,
            {
                method: "PUT",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({
                    status: status
                })
            }
        );


        const data = await response.json();


        if (!response.ok) {

            throw new Error(
                data.detail || "Failed to update status"
            );
        }


        message.textContent =
            "Status updated successfully.";

        message.style.color = "#22c55e";


        await loadAlert();


    } catch (error) {

        console.error(error);

        message.textContent =
            error.message;

        message.style.color = "#ef4444";
    }
}



// --------------------------------------------------
// SAVE ANALYST NOTES
// --------------------------------------------------

async function saveNotes() {

    const notes =
        document.getElementById("analystNotes").value.trim();

    const message =
        document.getElementById("notesMessage");


    if (!notes) {

        message.textContent =
            "Please enter a note first.";

        message.style.color = "#f59e0b";

        return;
    }


    try {

        const response = await fetch(
            `${API_BASE}/api/alerts/${encodeURIComponent(alertId)}/notes`,
            {
                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({
                    note: notes
                })
            }
        );


        const data = await response.json();


        if (!response.ok) {

            throw new Error(
                data.detail || "Failed to save note"
            );
        }


        message.textContent =
            "Investigation note saved successfully.";

        message.style.color = "#22c55e";


        document.getElementById("analystNotes").value = "";


        await loadNotes();


    } catch (error) {

        console.error(error);

        message.textContent =
            error.message;

        message.style.color = "#ef4444";
    }
}



// --------------------------------------------------
// LOAD SAVED NOTES
// --------------------------------------------------

async function loadNotes() {

    const container =
        document.getElementById("savedNotes");


    try {

        const response = await fetch(
            `${API_BASE}/api/alerts/${encodeURIComponent(alertId)}/notes`
        );


        const data = await response.json();


        if (!response.ok) {

            throw new Error(
                data.detail || "Failed to load notes"
            );
        }


        const notes = data.notes || [];


        if (notes.length === 0) {

            container.innerHTML =
                "<p>No investigation notes yet.</p>";

            return;
        }


        container.innerHTML = notes.map(note => `

            <div
                class="note-item"
                style="
                    background: #111827;
                    padding: 12px;
                    margin-bottom: 10px;
                    border-radius: 8px;
                    border-left: 4px solid #2563eb;
                "
            >

                <div style="font-size: 12px; color: #9ca3af;">
                    ${escapeHtml(note.created_at || "")}
                </div>

                <div style="margin-top: 6px;">
                    ${escapeHtml(note.note || "")}
                </div>

            </div>

        `).join("");


    } catch (error) {

        console.error(error);

        container.innerHTML =
            `<p>Error loading notes: ${escapeHtml(error.message)}</p>`;
    }
}



// --------------------------------------------------
// SAVE RESOLUTION NOTE
// --------------------------------------------------

async function saveResolution() {

    const resolution =
        document
            .getElementById("resolutionNotes")
            .value
            .trim();

    const message =
        document.getElementById("resolutionMessage");


    if (!resolution) {

        message.textContent =
            "Please enter a resolution note first.";

        message.style.color = "#f59e0b";

        return;
    }


    try {

        const response = await fetch(
            `${API_BASE}/api/alerts/${encodeURIComponent(alertId)}/resolution`,
            {
                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({
                    resolution_note: resolution
                })
            }
        );


        const data = await response.json();


        if (!response.ok) {

            throw new Error(
                data.detail || "Failed to save resolution"
            );
        }


        message.textContent =
            "Resolution note saved successfully.";

        message.style.color = "#22c55e";


        document.getElementById("resolutionNotes").value = "";


    } catch (error) {

        console.error(error);

        message.textContent =
            error.message;

        message.style.color = "#ef4444";
    }
}



// --------------------------------------------------
// HTML ESCAPING
// --------------------------------------------------

function escapeHtml(value) {

    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}



// --------------------------------------------------
// START
// --------------------------------------------------

loadAlert();