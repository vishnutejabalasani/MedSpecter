# Session 4: Detection Engineering & Rule Implementation
**Project:** Secure System Monitor
**Domain:** Healthcare Infrastructure

---

## 1. Threat Landscape Pipeline
To effectively monitor the healthcare environment, the detection pipeline evaluates runtime telemetry against 11 primary threats:
1.  **Ransomware Detonation** (Rapid file encryption of EHR storage).
2.  **Credential Dumping** (Memory scraping of LSASS).
3.  **Lateral Movement** (Unusual SMB or RDP connections off-hours).
4.  **BOLA/IDOR API Exploitation** (Cross-patient data access).
5.  **Reverse Shell Execution** (Unauthorized port binding and external C2).
6.  **Supply Chain Trojan** (Modified core binaries, failing integrity checks).
7.  **Data Exfiltration** (Massive anomalous outbound traffic).
8.  **Privilege Escalation** (Unauthorized use of `sudo` or token manipulation).
9.  **Log Tampering** (Wiping or modifying `/var/log` or Windows Event Logs).
10. **IoT Medical Device DoS** (Sudden loss of infusion pump heartbeats).
11. **Brute Force Authentication** (High volume of failed logins across domains).

---

## 2. Rule-Based Detections (Java-style Heuristics)
The deterministic Heuristics Engine evaluates incoming events against specific condition/action signatures.

```java
// RULE 01: Credential Dumping (Memory Injection)
if (event.syscall.equals("sys_ptrace") && event.targetProcess.equals("lsass.exe")) {
    return new Alert(Severity.CRITICAL, "ATR-02: Local Credential Dumping Attempted");
}

// RULE 02: Reverse Shell / Unauthorized Bind
if (event.syscall.equals("sys_bind") && !StandardPorts.contains(event.port)) {
    if (event.sourceProcess.equals("python3") || event.sourceProcess.equals("nc")) {
        return new Alert(Severity.HIGH, "ATR-08: Suspicious Network Bind (Possible Reverse Shell)");
    }
}

// RULE 03: Log Data Tampering
if (event.syscall.equals("sys_unlink") && event.filePath.startsWith("/var/log/")) {
    return new Alert(Severity.CRITICAL, "ATR-04: Forensic Log Deletion Detected");
}

// RULE 04: BOLA API Exploit
if (event.apiPath.contains("/patient/")) {
    String reqId = extractPatientId(event.apiPath);
    if (!reqId.equals(event.jwtToken.getSubjectId())) {
        return new Alert(Severity.CRITICAL, "ATR-05: Broken Object Level Authorization (BOLA)");
    }
}

// RULE 05: Unprivileged System Alteration
if (event.syscall.equals("sys_chmod") && event.permissions.equals("0777")) {
    if (!event.user.equals("root") || event.filePath.equals("/etc/passwd")) {
        return new Alert(Severity.HIGH, "ATR-09: Unsafe Permission Modification");
    }
}

// RULE 06: Unexpected Child Process (Web RCE)
if (event.syscall.equals("sys_execve")) {
    if (event.parentProcess.equals("nginx") || event.parentProcess.equals("httpd")) {
        if (event.command.contains("bash") || event.command.contains("sh")) {
            return new Alert(Severity.CRITICAL, "ATR-01: Web Server spawned interactive shell (RCE)");
        }
    }
}

// RULE 07: Unusual Admin Tools
if (event.syscall.equals("sys_execve")) {
    if (event.command.contains("vssadmin delete shadows") || event.command.contains("wevtutil cl")) {
        return new Alert(Severity.CRITICAL, "ATR-11: Ransomware Precursor - Shadow Copy/Log Deletion");
    }
}

// RULE 08: Suspicious Outbound Connection
if (event.syscall.equals("tcp_v4_connect") && BlacklistASN.contains(event.destinationIp)) {
    return new Alert(Severity.HIGH, "ATR-12: Connection to Known Malicious Infrastructure");
}

// RULE 09: Malformed Protocol Traffic (Healthcare specific)
if (event.protocol.equals("HL7") && event.packetSize > 65535) {
    return new Alert(Severity.MEDIUM, "ATR-07: Malformed HL7 Packet (Size Violation, buffer overflow risk)");
}

// RULE 10: Anonymous Memory Staging (Fileless Malware)
if (event.syscall.equals("sys_mmap") && event.flags.contains("PROT_EXEC") && event.flags.contains("PROT_WRITE")) {
    return new Alert(Severity.HIGH, "ATR-13: W^X Violation - Memory Staging Detected");
}

// RULE 11: Rapid Privilege Escalation
if (event.syscall.equals("sys_setuid") && event.targetUid == 0 && !event.sourceProcess.equals("sudo")) {
     return new Alert(Severity.CRITICAL, "ATR-14: Unauthorized Root Escalation");
}

// RULE 12: Medical IoT Heartbeat Drop
if (event.type.equals("SENSOR_TIMEOUT") && event.durationSeconds > 30) {
    return new Alert(Severity.HIGH, "ATR-06: Critical Medical Sensor Disconnected");
}
```

---

## 3. Statistical Anomaly Detections
For threats lacking static signatures (like insider threats or novel ransomware), the ML engine utilizes statistical deviation:
1.  **High-Speed File Encryption (Ransomware):** `IF (disk_write_rate > (median_write_rate + 3 * MAD)) AND (file_entropy > 7.5) -> ALERT_CRITICAL`.
2.  **Volumetric Data Exfiltration:** `IF (outbound_bytes_per_minute > (historical_99th_percentile_for_user)) -> ALERT_HIGH`.
3.  **Lateral Movement Spawning:** `IF (unique_internal_IPs_contacted_per_hour > Z-Score(3.0)) -> ALERT_HIGH`.
4.  **Off-Hours Authentication Anomalies:** `IF (login_time NOT IN normal_working_hours) AND (user_role == "contractor") -> ALERT_MEDIUM`.
5.  **API Rate Limiting Anomalies:** `IF (requests_per_second / patient_id > 50) -> ALERT_HIGH (Scraping/DDoS)`.

---

## 4. SHA-256 File Integrity Verification
To combat supply-chain attacks (where trusted binaries are backdoored), the monitor implements a Runtime Integrity Check.
**Explanation:** Before critical processes (e.g., `sshd`, `postgres`) are fully loaded into memory, the eBPF sensor hooks the `sys_execve` call. It calculates a cryptographic hash (`SHA-256`) of the binary file on disk. This hash is compared against a trusted, cryptographically signed ledger. If the hash does not match the known-good state, the binary has been tampered with. The execution is blocked, and an `ATR-15: Binary Integrity Failure` alert is generated.

---

## 5. Event-Correlation Logic (Stateful Detection)
Advanced attackers execute multi-step kill chains. The engine utilizes a sliding-window memory buffer to correlate distinct, temporally related events.

```java
// CORRELATION RULE 01: Successful Brute Force
StatefulBuffer buffer = new StatefulBuffer(TimeWindow.MINUTES(5));
if (buffer.count(Event.LOGIN_FAIL, targetUser) > 10) {
    if (buffer.contains(Event.LOGIN_SUCCESS, targetUser)) {
        return new Alert(Severity.CRITICAL, "CORR-01: Brute Force followed by Successful Login");
    }
}

// CORRELATION RULE 02: Compromise & Exfiltration
StatefulBuffer sessionBuffer = new StatefulBuffer(TimeWindow.HOURS(1));
if (sessionBuffer.contains(Alert.CORR_01)) { // Previous rule triggered
    if (sessionBuffer.sum(Metric.OUTBOUND_BYTES, targetUser) > 100_000_000) { // >100MB
        return new Alert(Severity.CRITICAL, "CORR-02: Account Compromised Followed by Data Exfiltration");
    }
}

// CORRELATION RULE 03: RCE leading to Lateral Movement
StatefulBuffer networkBuffer = new StatefulBuffer(TimeWindow.MINUTES(2));
if (networkBuffer.contains(Alert.ATR_01)) { // Web RCE Detected
    if (networkBuffer.count(Event.TCP_SYN, targetIP) > 50) { 
        return new Alert(Severity.CRITICAL, "CORR-03: Web Exploitation followed by Internal Port Scanning");
    }
}
```

---

## 6. Detection Pipeline Explanation
The overall logical flow from raw telemetry to normalized alert:
1.  **Ingestion & Normalization:** Raw eBPF structs (`syscall`, `pid`, `uid`) are ingested via Kafka and transformed into standard JSON `TelemetryEvent` objects (adding contextual IP resolution).
2.  **Integrity Validation (SHA-256 Check):** If the event is an execution (`sys_execve`), calculate the file hash and pause processing until validated against the trusted baseline.
3.  **Fast Path (Heuristics Engine):** The event is run synchronously through a Java-style IF/THEN rule array (e.g., checking for `sys_ptrace` to `lsass`). Matches immediately fire to the Dashboard.
4.  **State Path (Correlation Engine):** The event is pushed onto a time-bound FIFO queue (e.g., a Redis stream). Correlation queries are run to check for multi-step attacks (like Brute Force -> Success).
5.  **Slow Path (Statistical Anomaly):** Aggregated metrics (bytes/sec, files/sec) are passed to an asynchronous ML inference model to identify deviations from normal behavioral profiles.
6.  **Alert Generation:** Triggers from any path are written to the immutable SQLite tracking database and pushed via WebSocket to the React UI for analyst triage.
