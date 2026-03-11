const { insertAuditLog } = require('./db');
const crypto = require('crypto');
const detectionEngine = require('./detection');

// --- Geo-Location Pool for Global Threat Map Visualization ---
// Maps known attacker IPs to real-world locations. Unknown IPs get a random location.
const geoLocationPool = [
    { lat: 55.7558, lng: 37.6173, country: "Russia" },
    { lat: 39.9042, lng: 116.4074, country: "China" },
    { lat: 35.6762, lng: 139.6503, country: "Japan" },
    { lat: 37.5665, lng: 126.9780, country: "South Korea" },
    { lat: 51.5074, lng: -0.1278, country: "United Kingdom" },
    { lat: 40.7128, lng: -74.0060, country: "United States" },
    { lat: -33.8688, lng: 151.2093, country: "Australia" },
    { lat: 52.5200, lng: 13.4050, country: "Germany" },
    { lat: 48.8566, lng: 2.3522, country: "France" },
    { lat: -23.5505, lng: -46.6333, country: "Brazil" },
    { lat: 35.6895, lng: 51.3890, country: "Iran" },
    { lat: 1.3521, lng: 103.8198, country: "Singapore" },
    { lat: 25.2048, lng: 55.2708, country: "UAE" },
    { lat: 50.4501, lng: 30.5234, country: "Ukraine" },
    { lat: 14.5995, lng: 120.9842, country: "Philippines" },
];

const ipGeoCache = new Map();
let geoIndex = 0;

function getGeoForIp(sourceIp) {
    if (ipGeoCache.has(sourceIp)) return ipGeoCache.get(sourceIp);
    // Assign a location from the pool in round-robin + slight random offset for realism
    const base = geoLocationPool[geoIndex % geoLocationPool.length];
    geoIndex++;
    const geo = {
        lat: base.lat + (Math.random() - 0.5) * 4,
        lng: base.lng + (Math.random() - 0.5) * 4,
        country: base.country
    };
    ipGeoCache.set(sourceIp, geo);
    return geo;
}

// Stateful Correlation Buffer (Simulating a Redis Stream or Flink Window)
// Keeps track of events by source IP to detect multi-step attacks
const stateBuffer = new Map();

function getBuffer(sourceIp) {
    if (!stateBuffer.has(sourceIp)) {
        stateBuffer.set(sourceIp, []);
    }
    return stateBuffer.get(sourceIp);
}

function addToBuffer(sourceIp, event) {
    const buffer = getBuffer(sourceIp);
    buffer.push(event);
    // Keep only the last 50 events per IP for memory efficiency
    if (buffer.length > 50) buffer.shift();
}

/**
 * SHA-256 Integrity Verification (Simulated implementation of Section 4)
 * Returns false if the binary hash doesn't match the trusted signatures.
 */
function verifyIntegrity(filePath, providedHash) {
    // In a real system, this checks the eBPF file hash against a trusted DB.
    const trustedHashes = {
        "/usr/sbin/sshd": "f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2",
        "/bin/bash": "a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447"
    };

    // If the path isn't monitored natively, assume OK for this demo
    if (!trustedHashes[filePath]) return true;
    return trustedHashes[filePath] === providedHash;
}

/**
 * The Java-style Heuristics Engine (Implementing Section 2 Rules)
 * Evaluates raw eBPF telemetry JSON objects.
 */
function evaluateRules(event) {
    // Integrity Check Engine
    if (event.syscall === "sys_execve" && event.fileHash) {
        if (!verifyIntegrity(event.command, event.fileHash)) {
            return {
                eventType: 'BINARY_INTEGRITY_FAILURE',
                title: 'ATR-15: Binary Integrity Failure (SHA-256 Mismatch)',
                desc: `Supply chain tamper detected on ${event.command}`
            };
        }
    }

    // RULE 01: Credential Dumping (Memory Injection)
    if (event.syscall === "sys_ptrace" && event.targetProcess === "lsass.exe") {
        return {
            eventType: 'CREDENTIAL_DUMPING',
            title: 'ATR-02: Credential Dumping Attempted',
            desc: `Process ${event.sourceProcess} injected into lsass.exe`
        };
    }

    // RULE 02: Reverse Shell / Unauthorized Bind
    if (event.syscall === "sys_bind" && ![80, 443, 22, 5432].includes(event.port)) {
        if (event.sourceProcess === "python3" || event.sourceProcess === "nc") {
            return {
                eventType: 'UNAUTHORIZED_BIND',
                title: 'ATR-08: Suspicious Network Bind (Reverse Shell)',
                desc: `${event.sourceProcess} bound to unauthorized port ${event.port}`
            };
        }
    }

    // RULE 04: BOLA API Exploit
    if (event.apiPath && event.apiPath.includes("/patient/")) {
        const reqId = event.apiPath.split('/').pop();
        if (reqId !== event.jwtSubjectId) {
            return {
                eventType: 'BOLA_API_EXPLOIT',
                title: 'ATR-05: Broken Object Level Authorization (BOLA)',
                desc: `JWT User ${event.jwtSubjectId} requested unauthorized patient ${reqId}`
            };
        }
    }

    // EVENT-CORRELATION: CORR-01 -> Brute Force followed by Success
    if (event.type === "LOGIN_SUCCESS") {
        const history = getBuffer(event.sourceIp);
        const recentFails = history.filter(e => e.type === "LOGIN_FAIL" && (Date.now() - e.timestamp < 300000)); // 5 mins
        if (recentFails.length > 5) {
            return {
                eventType: 'CREDENTIAL_BRUTE_FORCE_SUCCESS',
                title: 'CORR-01: Successful Authentication Post-Brute Force',
                desc: `${event.userId} authenticated after ${recentFails.length} rapid failures from ${event.sourceIp}`
            };
        }
    }

    // If no rules hit, return null (safe)
    return null;
}

/**
 * Main ingress pipeline called by the Express Router.
 */
function processTelemetryEvent(rawEvent, onAlertDetected) {
    if (!rawEvent || !rawEvent.sourceIp) return; // Drop invalid telemetry

    // 1. Tag event with processing timestamp
    rawEvent.timestamp = Date.now();

    // 2. Add to Stateful Buffer for correlation
    addToBuffer(rawEvent.sourceIp, rawEvent);

    // 3. Evaluate deterministic rules
    let detectedAlert = evaluateRules(rawEvent);

    // Evaluate Session 6 Rules
    if (!detectedAlert) {
        detectedAlert = detectionEngine.processEvent(rawEvent);
    }

    if (detectedAlert) {
        // Construct the final structured payload
        const finalSeverity = detectionEngine.determineSeverity(detectedAlert.eventType);

        // Auto-assign geo-coordinates for Global Threat Map visualization
        const sourceIp = rawEvent.sourceIp || rawEvent.ip || '0.0.0.0';
        const geo = getGeoForIp(sourceIp);

        const processedEvent = {
            id: `EVT_${Date.now()}_${Math.floor(Math.random() * 10E5)}`,
            time: new Date().toISOString(),
            type: detectedAlert.title,
            severity: finalSeverity,
            title: detectedAlert.title,
            source: rawEvent.sourceNode || rawEvent.sourceIp,
            desc: detectedAlert.desc,
            lat: rawEvent.lat || geo.lat,
            lng: rawEvent.lng || geo.lng,
            country: rawEvent.country || geo.country
        };

        console.log(`[ALERT TRIGGERED] -> (${finalSeverity}) Rule: ${processedEvent.title}`);

        // Write to Immutable Audit Log DB
        insertAuditLog(processedEvent, (err) => {
            if (!err && typeof onAlertDetected === 'function') {
                // Broadcast to React WebSocket
                onAlertDetected(processedEvent);
            }
        });
    }
}

// Keeping the mock dataset export for the API history seeder
const mockAlertsDataset = [];

module.exports = {
    processTelemetryEvent,
    mockAlertsDataset
};
