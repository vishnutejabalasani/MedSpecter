```sql
CREATE TABLE IF NOT EXISTS security_alerts (
    alert_id VARCHAR(64) PRIMARY KEY,
    event_id VARCHAR(64) NOT NULL,
    severity VARCHAR(16) NOT NULL,
    title VARCHAR(128) NOT NULL,
    source_system VARCHAR(64) NOT NULL,
    description TEXT,
    timestamp BIGINT NOT NULL,
    integrity_hash VARCHAR(64) NOT NULL UNIQUE
);
```

```java
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.*;
import java.util.*;
import java.util.concurrent.*;

// 1. Alert severity mapping
enum Severity {
    LOW, MEDIUM, HIGH, CRITICAL;

    public static Severity determineSeverity(String eventType) {
        switch (eventType) {
            case "RANSOMWARE_BEHAVIOR":
            case "REVERSE_SHELL":
                return CRITICAL;
            case "BRUTE_FORCE":
            case "UNAUTHORIZED_BIND":
                return HIGH;
            case "LOGIN_FAILURE":
            case "MALFORMED_TRAFFIC":
                return MEDIUM;
            default:
                return LOW;
        }
    }
}

// 3. Java Alert class
class Alert {
    private final String alertId;
    private final String eventId;
    private final Severity severity;
    private final String title;
    private final String sourceSystem;
    private final String description;
    private final long timestamp;
    private final String integrityHash;

    public Alert(String eventId, Severity severity, String title, String sourceSystem, String description) {
        this.alertId = UUID.randomUUID().toString();
        this.eventId = eventId;
        this.severity = severity;
        this.title = title;
        this.sourceSystem = sourceSystem;
        this.description = description;
        this.timestamp = System.currentTimeMillis();
        this.integrityHash = generateHash();
    }

    private String generateHash() {
        try {
            String data = alertId + eventId + severity.name() + timestamp;
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not found", e);
        }
    }

    public String getAlertId() { return alertId; }
    public String getEventId() { return eventId; }
    public Severity getSeverity() { return severity; }
    public String getTitle() { return title; }
    public String getSourceSystem() { return sourceSystem; }
    public String getDescription() { return description; }
    public long getTimestamp() { return timestamp; }
    public String getIntegrityHash() { return integrityHash; }
    
    @Override
    public String toString() {
        return String.format("[%s] %s | Source: %s | Hash: %s", severity, title, sourceSystem, integrityHash.substring(0, 16) + "...");
    }
}

// 4. AlertService class with JDBC handling
class AlertRepository {
    private final String jdbcUrl = "jdbc:sqlite:security_monitor.db";

    public AlertRepository() {
        try (Connection conn = DriverManager.getConnection(jdbcUrl);
             Statement stmt = conn.createStatement()) {
            stmt.execute("CREATE TABLE IF NOT EXISTS security_alerts (" +
                    "alert_id VARCHAR(64) PRIMARY KEY, " +
                    "event_id VARCHAR(64) NOT NULL, " +
                    "severity VARCHAR(16) NOT NULL, " +
                    "title VARCHAR(128) NOT NULL, " +
                    "source_system VARCHAR(64) NOT NULL, " +
                    "description TEXT, " +
                    "timestamp BIGINT NOT NULL, " +
                    "integrity_hash VARCHAR(64) NOT NULL UNIQUE, " +
                    "UNIQUE(event_id, title))"); // Prevent exact same alert for same event
        } catch (SQLException e) {
            System.err.println("Database initialization failed: " + e.getMessage());
        }
    }

    public boolean insertAlert(Alert alert) {
        String sql = "INSERT INTO security_alerts (alert_id, event_id, severity, title, source_system, description, timestamp, integrity_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
        try (Connection conn = DriverManager.getConnection(jdbcUrl);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
             
            pstmt.setString(1, alert.getAlertId());
            pstmt.setString(2, alert.getEventId());
            pstmt.setString(3, alert.getSeverity().name());
            pstmt.setString(4, alert.getTitle());
            pstmt.setString(5, alert.getSourceSystem());
            pstmt.setString(6, alert.getDescription());
            pstmt.setLong(7, alert.getTimestamp());
            pstmt.setString(8, alert.getIntegrityHash());
            
            pstmt.executeUpdate();
            return true;
        } catch (SQLException e) {
            if (e.getMessage().contains("UNIQUE constraint failed")) {
                // Duplicate prevention
                return false;
            }
            System.err.println("Failed to insert alert: " + e.getMessage());
            return false;
        }
    }

    // 6. Fetch alerts method
    public List<Alert> fetchRecentAlerts(int limit) {
        List<Alert> alerts = new ArrayList<>();
        String sql = "SELECT * FROM security_alerts ORDER BY timestamp DESC LIMIT ?";
        
        try (Connection conn = DriverManager.getConnection(jdbcUrl);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, limit);
            try (ResultSet rs = pstmt.executeQuery()) {
                // Mapping ResultSet back to domain objects simplified for demo
                while (rs.next()) {
                    // In a full implementation, you'd reconstruct the Alert using a private constructor
                    // that accepts the hash, rather than regenerating it.
                }
            }
        } catch (SQLException e) {
            System.err.println("Failed to fetch alerts: " + e.getMessage());
        }
        return alerts;
    }
}

class AlertEngine {
    private final AlertRepository repository;
    private final Map<Severity, Integer> severityCounts = new ConcurrentHashMap<>();

    public AlertEngine(AlertRepository repository) {
        this.repository = repository;
        for (Severity s : Severity.values()) severityCounts.put(s, 0);
    }

    public void processDetection(String eventId, String rawType, String title, String source, String desc) {
        Severity severity = Severity.determineSeverity(rawType);
        Alert alert = new Alert(eventId, severity, title, source, desc);
        
        boolean isNew = repository.insertAlert(alert);
        if (isNew) {
            severityCounts.put(severity, severityCounts.get(severity) + 1);
            // 7. Console output
            System.out.println(">> NEW ALERT: " + alert.toString());
        }
    }

    // 9. Severity distribution
    public void printDistribution() {
        System.out.println("\n--- Alert Severity Distribution ---");
        System.out.println("CRITICAL: " + severityCounts.get(Severity.CRITICAL));
        System.out.println("HIGH:     " + severityCounts.get(Severity.HIGH));
        System.out.println("MEDIUM:   " + severityCounts.get(Severity.MEDIUM));
        System.out.println("LOW:      " + severityCounts.get(Severity.LOW));
        System.out.println("-----------------------------------\n");
    }
}

// 10. End-to-end flow runner
public class Session7AlertApp {
    public static void main(String[] args) throws InterruptedException {
        AlertRepository repo = new AlertRepository();
        AlertEngine engine = new AlertEngine(repo);
        
        System.out.println("Starting Java Alert Processing Engine...\n");

        // 8. 10 Sample inputs
        String[][] samples = {
            {"EVT_01", "OUTBOUND_CONN", "Standard Sync", "AppServer", "Normal traffic"},
            {"EVT_02", "LOGIN_FAILURE", "Failed Auth", "API_Gateway", "Bad password"},
            {"EVT_03", "BRUTE_FORCE", "SSH Brute Force", "DB_Node_1", "15 failures in 30s"},
            {"EVT_04", "REVERSE_SHELL", "Bash Reverse Shell", "Web_Front", "nginx spawned bash"},
            {"EVT_05", "FILE_READ", "Log Access", "AppServer", "Read /var/log"},
            {"EVT_06", "UNAUTHORIZED_BIND", "Netcat Port Bind", "DB_Node_1", "nc -l 4444"},
            {"EVT_07", "RANSOMWARE_BEHAVIOR", "Mass File Encrypt", "File_Share", "Write 900MB/s"},
            {"EVT_07", "RANSOMWARE_BEHAVIOR", "Mass File Encrypt", "File_Share", "Write 900MB/s"}, // Duplicate test
            {"EVT_08", "MALFORMED_TRAFFIC", "Buffer Overflow Attempt", "Legacy_App", "Excessive payload"},
            {"EVT_09", "LOGIN_SUCCESS", "Admin Login", "AppServer", "Valid token"}
        };

        // 5. Real-time generation simulation
        ScheduledExecutorService executor = Executors.newScheduledThreadPool(1);
        CountDownLatch latch = new CountDownLatch(samples.length);

        for (int i = 0; i < samples.length; i++) {
            final String[] event = samples[i];
            executor.schedule(() -> {
                engine.processDetection(event[0], event[1], event[2], event[3], event[4]);
                latch.countDown();
            }, i * 300L, TimeUnit.MILLISECONDS);
        }

        latch.await();
        executor.shutdown();
        
        Thread.sleep(500); // Wait for async IO
        engine.printDistribution();
    }
}
```
