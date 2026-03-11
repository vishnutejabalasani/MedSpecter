const crypto = require('crypto');

class DetectionEngine {
    constructor() {
        this.eventMonitor = [];
        this.dbmsPoolHistory = new Map();
    }

    hash(input) {
        try {
            return crypto.createHash('sha256').update(input, 'utf8').digest('hex');
        } catch (e) {
            return null;
        }
    }

    evaluateAtomicRules(event) {
        const action = event.action;

        // 1. JVM Dynamic Class Loading (Webshell / Deserialization)
        if (action === "JVMTI_ClassLoad" && event.className === "Exploit.class")
            return this.createAlert("MALICIOUS_CLASS_LOAD", "Malicious dynamic class load (Webshell/Deserialization).", "Exploit.class loaded");

        // 2. Process Execution (Reverse Shells)
        if (action === "ProcessBuilder_Exec" && event.command && event.command.match(/.*(curl|wget).*\|.*bash.*/))
            return this.createAlert("REVERSE_SHELL", "Remote payload download and execution pipeline.", event.command);

        // 3. JNDI Injection (Log4Shell style)
        if (action === "JNDI_Lookup" && event.target && event.target.startsWith("ldap://"))
            return this.createAlert("JNDI_LDAP_LOOKUP", "JNDI LDAP lookup (Potential Log4Shell).", "Target: " + event.target);

        // 4. File Staging in Temporary Directories
        if (action === "FILE_CREATE" && event.file && event.file.endsWith(".jsp") && event.file.startsWith("/tmp"))
            return this.createAlert("WEBSHELL_STAGING", "JSP webshell staging in /tmp.", "File: " + event.file);

        // 5. Unauthorized Sensitive File Access
        if (action === "FILE_READ_DENIED" && event.file === "/etc/shadow")
            return this.createAlert("CREDENTIAL_DUMPING", "Unauthorized access attempt to shadow file.", `User: ${event.uid || 'unknown'}`);

        // 6. Destructive Schema Modification
        if (action === "SQL_DDL_Execution" && event.query && event.query.toUpperCase().includes("DROP TABLE"))
            return this.createAlert("SQL_DDL_EXECUTION", "Destructive SQL DDL (DROP) command.", "Query: " + event.query);

        // 7. Database Exfiltration Mass Extraction
        if (action === "SQL_DML_Bulk_Extraction" && event.rowsReturned > 10000)
            return this.createAlert("SQL_DML_BULK_EXTRACTION", "Mass DB extraction: >10,000 rows.", `Rows: ${event.rowsReturned}`);

        // 8. DBMS Root Authentication Failures
        if (action === "Auth_Failed_DBMS" && event.user === "root")
            return this.createAlert("AUTH_FAILED_DBMS", "DB auth failed for root user.", `Reason: ${event.reason || 'unknown'}`);

        // 9. JVM Resource Exhaustion
        if (action === "Java_OutOfMemoryError")
            return this.createAlert("RESOURCE_EXHAUSTION", "JVM OutOfMemoryError (DoS/leak).", `Host: ${event.host}`);

        // 10. Information Disclosure via Framework Actuators
        if (action === "Spring_Actuator_Access" && event.apiPath && event.apiPath.includes("/actuator/env"))
            return this.createAlert("ACTUATOR_ACCESS", "Spring environment actuator accessed.", `Path: ${event.apiPath}`);

        // 11. API Rate Limiting Threshold Hit
        if (action === "API_Rate_Limit_Exceeded")
            return this.createAlert("API_RATE_LIMIT", "API rate limit exceeded.", `IP: ${event.ip}`);

        // SHA-256 CHECK logic from java class
        if (action === "sys_execve" && event.command === "/usr/sbin/sshd") {
            const expectedHash = "f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2";
            if (event.file !== expectedHash)
                return this.createAlert("BINARY_INTEGRITY_FAILURE", "Binary Integrity Failure (SHA-256 Mismatch).", "tampered hash");
        }

        return null;
    }

    evaluateBaselineDeviation(event) {
        if (event.action === "JDBC_Connection_Create" && event.target) {
            if (!this.dbmsPoolHistory.has(event.target)) {
                this.dbmsPoolHistory.set(event.target, []);
            }
            const history = this.dbmsPoolHistory.get(event.target);

            if (history.length > 5) {
                const sum = history.reduce((a, b) => a + b, 0);
                const mean = sum / history.length;

                const variance = history.reduce((acc, val) => acc + Math.pow(val - mean, 2), 0) / history.length;
                const stdDev = Math.sqrt(variance);

                if (stdDev > 0 && event.poolSize > (mean + (3 * stdDev))) {
                    history.push(event.poolSize);
                    return this.createAlert("POOL_SIZE_ANOMALY", `Pool size anomaly -> Val: ${event.poolSize}, Mean: ${mean.toFixed(2)}, StdDev: ${stdDev.toFixed(2)}`, 'Deviation limit exceeded');
                }
            }
            history.push(event.poolSize);
        }
        return null;
    }

    evaluateCorrelations(event) {
        this.eventMonitor.push(event);
        const now = event.timestamp || Date.now();

        const bruteForceCount = this.eventMonitor.filter(e =>
            e.action === "Auth_Failed_Java_App" && e.ip === event.ip && (now - (e.timestamp || 0)) < 600000
        ).length;

        const hasSuccess = this.eventMonitor.some(e =>
            e.action === "Auth_Success_Java_App" && e.ip === event.ip && (now - (e.timestamp || 0)) < 300000
        );

        const hasExfil = this.eventMonitor.some(e =>
            e.action === "SQL_DML_Bulk_Extraction" && e.ip === event.ip && (now - (e.timestamp || 0)) < 300000
        );

        if (bruteForceCount >= 3 && hasSuccess && hasExfil)
            return this.createAlert("CREDENTIAL_BRUTE_FORCE_SUCCESS", "Credential brute-forcing followed by exfiltration.", `IP: ${event.ip}`);

        const hasJspCreate = this.eventMonitor.some(e =>
            e.action === "FILE_CREATE" && e.host === event.host && e.file && e.file.endsWith(".jsp") && (now - (e.timestamp || 0)) < 30000
        );

        const hasProcExec = this.eventMonitor.some(e =>
            e.action === "ProcessBuilder_Exec" && e.host === event.host && e.user === "java" && (now - (e.timestamp || 0)) < 30000
        );

        if (hasJspCreate && hasProcExec)
            return this.createAlert("WEBSHELL_EXECUTION", "Webshell deployment leading to immediate command execution.", `Host: ${event.host}`);

        const apiExceededCount = this.eventMonitor.filter(e =>
            e.action === "API_Rate_Limit_Exceeded" && e.ip === event.ip && (now - (e.timestamp || 0)) < 120000
        ).length;

        const hasOOM = this.eventMonitor.some(e =>
            e.action === "Java_OutOfMemoryError" && e.host === event.host && (now - (e.timestamp || 0)) < 120000
        );

        if (apiExceededCount >= 5 && hasOOM)
            return this.createAlert("RESOURCE_EXHAUSTION", "Volumetric API abuse resulting in JVM Heap exhaustion.", `IP: ${event.ip}`);

        return null;
    }

    createAlert(eventType, title, desc) {
        return {
            eventType: eventType,
            title: title,
            desc: desc
        };
    }

    processEvent(event) {
        let alert = this.evaluateAtomicRules(event);
        if (alert) return alert;

        alert = this.evaluateBaselineDeviation(event);
        if (alert) return alert;

        alert = this.evaluateCorrelations(event);
        if (alert) return alert;

        return null;
    }
}

// 1. Alert severity mapping (Mirroring Java Enum Logic)
const SecuritySeverity = {
    LOW: 'LOW',
    MEDIUM: 'MEDIUM',
    HIGH: 'HIGH',
    CRITICAL: 'CRITICAL'
};

function determineSeverity(eventType) {
    switch (eventType) {
        case "RANSOMWARE_BEHAVIOR":
        case "REVERSE_SHELL":
        case "MALICIOUS_CLASS_LOAD":
        case "BOLA_API_EXPLOIT":
        case "CREDENTIAL_BRUTE_FORCE_SUCCESS":
        case "WEBSHELL_EXECUTION":
        case "BINARY_INTEGRITY_FAILURE":
        case "JNDI_LDAP_LOOKUP":
        case "SQL_DDL_EXECUTION":
        case "SQL_DML_BULK_EXTRACTION":
            return SecuritySeverity.CRITICAL;

        case "BRUTE_FORCE":
        case "UNAUTHORIZED_BIND":
        case "CREDENTIAL_DUMPING":
        case "WEBSHELL_STAGING":
        case "POOL_SIZE_ANOMALY":
            return SecuritySeverity.HIGH;

        case "LOGIN_FAILURE":
        case "MALFORMED_TRAFFIC":
        case "AUTH_FAILED_DBMS":
        case "RESOURCE_EXHAUSTION":
        case "ACTUATOR_ACCESS":
            return SecuritySeverity.MEDIUM;

        default:
            return SecuritySeverity.LOW;
    }
}

module.exports = new DetectionEngine();
module.exports.determineSeverity = determineSeverity;
