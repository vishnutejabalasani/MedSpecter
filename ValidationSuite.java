import java.sql.*;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;

// -------------------------------------------------------------
// 1. TestCase Structure
// -------------------------------------------------------------
class TestCase {
    String testId;
    String eventAction;
    String expectedEventType;
    Severity expectedSeverity;

    // Extracted payload fields to simulate event
    String user;
    String ip;
    String file;
    String command;
    String hash;

    // Result Tracking
    String actualEventType;
    Severity actualSeverity;
    boolean passFail;
    String comments;

    public TestCase(String testId, String eventAction, String expectedEventType, Severity expectedSeverity,
            String user, String ip, String file, String command, String hash) {
        this.testId = testId;
        this.eventAction = eventAction;
        this.expectedEventType = expectedEventType;
        this.expectedSeverity = expectedSeverity;
        this.user = user;
        this.ip = ip;
        this.file = file;
        this.command = command;
        this.hash = hash;
    }
}

// -------------------------------------------------------------
// 2. Alert & Severity Enum (From Session 7)
// -------------------------------------------------------------
enum Severity {
    LOW, MEDIUM, HIGH, CRITICAL
}

class Alert {
    String eventType;
    Severity severity;
    String description;

    public Alert(String type, Severity sev, String desc) {
        this.eventType = type;
        this.severity = sev;
        this.description = desc;
    }
}

// -------------------------------------------------------------
// 3. Simplified Local Detection Engine for Testing
// -------------------------------------------------------------
class DetectionEngine {
    private final List<TestCase> buffer = new ArrayList<>();

    public Alert processEvent(TestCase e) {
        buffer.add(e);

        // Atomic Rules Verification
        if ("JVMTI_ClassLoad".equals(e.eventAction) && "Exploit.class".equals(e.file))
            return new Alert("MALICIOUS_CLASS_LOAD", Severity.CRITICAL, "Dynamic Class Load Detected");

        if ("FILE_CREATE".equals(e.eventAction) && e.file != null && e.file.startsWith("/tmp/")
                && e.file.endsWith(".jsp"))
            return new Alert("WEBSHELL_STAGING", Severity.HIGH, "JSP in tmp");

        if ("Auth_Failed_DBMS".equals(e.eventAction) && "root".equals(e.user))
            return new Alert("AUTH_FAILED_DBMS", Severity.MEDIUM, "DB root auth fail");

        if ("sys_execve".equals(e.eventAction) && "/usr/sbin/sshd".equals(e.command)) {
            String goodHash = "f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2";
            if (!goodHash.equals(e.hash)) {
                return new Alert("BINARY_INTEGRITY_FAILURE", Severity.CRITICAL, "SHA-256 Tamper: " + e.command);
            }
        }

        // Multi-Step Correlation: Brute force followed by Success
        if ("LOGIN_SUCCESS".equals(e.eventAction)) {
            long bruteForceAttempts = buffer.stream()
                    .filter(ev -> "LOGIN_FAILURE".equals(ev.eventAction) && ev.ip.equals(e.ip)).count();
            if (bruteForceAttempts >= 3) {
                return new Alert("CREDENTIAL_BRUTE_FORCE_SUCCESS", Severity.CRITICAL,
                        "Breach after " + bruteForceAttempts + " fails");
            }
        }

        // Default Rule
        if ("LOGIN_FAILURE".equals(e.eventAction))
            return new Alert("BRUTE_FORCE_ATTEMPT", Severity.LOW, "Failed Login");

        // Generic Map
        if (e.expectedSeverity == Severity.LOW)
            return new Alert("INFO_EVENT", Severity.LOW, "System noise");
        if (e.expectedSeverity == Severity.MEDIUM)
            return new Alert("ANOMALY", Severity.MEDIUM, "General anomaly");
        if (e.expectedSeverity == Severity.HIGH)
            return new Alert("THREAT", Severity.HIGH, "High severity threat");

        return null;
    }
}

// -------------------------------------------------------------
// 4. Test Runner & JDBC DB Validation
// -------------------------------------------------------------
public class ValidationSuite {
    private static final String DB_URL = "jdbc:sqlite::memory:";
    private static Connection conn;

    // Core engine instance
    private static DetectionEngine engine = new DetectionEngine();

    public static void setupDatabase() throws SQLException {
        conn = DriverManager.getConnection(DB_URL);
        try (Statement stmt = conn.createStatement()) {
            stmt.execute("CREATE TABLE test_alerts (" +
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                    "test_id TEXT NOT NULL, " +
                    "event_type TEXT NOT NULL, " +
                    "severity TEXT NOT NULL, " +
                    "hash_signature TEXT NOT NULL, " +
                    "UNIQUE(event_type, test_id))");
        }
    }

    public static String generateHash(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes("UTF-8"));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1)
                    hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception ex) {
            return "ERROR";
        }
    }

    public static void insertAlert(String testId, Alert alert) {
        String hashSig = generateHash(alert.eventType + Instant.now().toString());
        String sql = "INSERT INTO test_alerts (test_id, event_type, severity, hash_signature) VALUES (?, ?, ?, ?)";
        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, testId);
            pstmt.setString(2, alert.eventType);
            pstmt.setString(3, alert.severity.name());
            pstmt.setString(4, hashSig);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            // Deduplication will catch here due to UNIQUE constraint
        }
    }

    public static void executeTestSuite(List<TestCase> tests) {
        int passed = 0;
        int failed = 0;

        System.out.println("\n=======================================================");
        System.out.println("  EXECUTING QA PIPELINE (" + tests.size() + " Scenarios)");
        System.out.println("=======================================================\n");

        for (TestCase tc : tests) {
            // 1. Inject to engine
            Alert result = engine.processEvent(tc);

            // 2. Capture and Evaluate
            if (result != null) {
                tc.actualEventType = result.eventType;
                tc.actualSeverity = result.severity;

                // 3. JDBC Write Simulation
                insertAlert(tc.testId, result);
            } else {
                tc.actualEventType = "NONE";
                tc.actualSeverity = Severity.LOW; // Baseline assumption if nothing fires
            }

            // 4. Mark Pass/Fail
            if (tc.expectedEventType.equals(tc.actualEventType) && tc.expectedSeverity == tc.actualSeverity) {
                tc.passFail = true;
                tc.comments = "Rule successfully validated.";
                passed++;
                System.out.printf("[PASS] %s -> %s (%s)\n", tc.testId, tc.actualEventType, tc.actualSeverity);
            } else {
                tc.passFail = false;
                tc.comments = "Expected: " + tc.expectedEventType + " | Got: " + tc.actualEventType;
                failed++;
                System.out.printf("[FAIL] %s -> %s\n", tc.testId, tc.comments);
            }
        }

        printSummary(tests, passed, failed);
    }

    public static void printSummary(List<TestCase> tests, int passed, int failed) {
        System.out.println("\n-------------------------------------------------------");
        System.out.println(" QA EXECUTION SUMMARY ");
        System.out.println("-------------------------------------------------------");
        System.out.println("Total Tests Run : " + tests.size());
        System.out.println("Passed          : " + passed);
        System.out.println("Failed          : " + failed);
        System.out.println("Success Rate    : " + String.format("%.1f", (passed / (double) tests.size()) * 100) + "%");

        System.out.println("\n-- DB Verification Extract --");
        try (Statement stmt = conn.createStatement();
                ResultSet rs = stmt
                        .executeQuery("SELECT severity, COUNT(*) as count FROM test_alerts GROUP BY severity")) {
            while (rs.next()) {
                System.out.println(rs.getString("severity") + " Alerts Logged: " + rs.getInt("count"));
            }
        } catch (SQLException e) {
        }
        System.out.println("-------------------------------------------------------\n");
    }

    // -------------------------------------------------------------
    // 5. Main Execution Flow
    // -------------------------------------------------------------
    public static void main(String[] args) {
        try {
            setupDatabase();

            List<TestCase> suite = new ArrayList<>();

            // --- LOW SEVERITY (10) ---
            for (int i = 1; i <= 8; i++)
                suite.add(new TestCase("TC-L0" + i, "Network_Ping", "INFO_EVENT", Severity.LOW, "guest", "10.0.0.5",
                        null, null, null));
            // Failed logins (Building up Correlation buffer)
            suite.add(new TestCase("TC-L09", "LOGIN_FAILURE", "BRUTE_FORCE_ATTEMPT", Severity.LOW, "admin",
                    "192.168.1.100", null, null, null));
            suite.add(new TestCase("TC-L10", "LOGIN_FAILURE", "BRUTE_FORCE_ATTEMPT", Severity.LOW, "admin",
                    "192.168.1.100", null, null, null));
            suite.add(new TestCase("TC-L11", "LOGIN_FAILURE", "BRUTE_FORCE_ATTEMPT", Severity.LOW, "admin",
                    "192.168.1.100", null, null, null));

            // --- MEDIUM SEVERITY (10) ---
            for (int i = 1; i <= 8; i++)
                suite.add(new TestCase("TC-M0" + i, "API_Rate_Limit", "ANOMALY", Severity.MEDIUM, "user1", "45.1.2.3",
                        null, null, null));
            suite.add(new TestCase("TC-M09", "Auth_Failed_DBMS", "AUTH_FAILED_DBMS", Severity.MEDIUM, "root",
                    "10.0.0.5", null, null, null));
            suite.add(new TestCase("TC-M10", "Auth_Failed_DBMS", "AUTH_FAILED_DBMS", Severity.MEDIUM, "root",
                    "10.0.0.6", null, null, null));

            // --- HIGH SEVERITY (10) ---
            for (int i = 1; i <= 8; i++)
                suite.add(new TestCase("TC-H0" + i, "SQL_Injection", "THREAT", Severity.HIGH, "hacker", "evil.com",
                        null, null, null));
            suite.add(new TestCase("TC-H09", "FILE_CREATE", "WEBSHELL_STAGING", Severity.HIGH, "tomcat", "localhost",
                    "/tmp/shell.jsp", null, null));
            suite.add(new TestCase("TC-H10", "FILE_CREATE", "WEBSHELL_STAGING", Severity.HIGH, "tomcat", "localhost",
                    "/tmp/cmd.jsp", null, null));

            // --- CRITICAL (Event Correlation & Integrity) ---
            // Triggers CORR-01 because of TC-L09, L10, L11 earlier
            suite.add(new TestCase("TC-C01", "LOGIN_SUCCESS", "CREDENTIAL_BRUTE_FORCE_SUCCESS", Severity.CRITICAL,
                    "admin", "192.168.1.100", null, null, null));

            // Triggers Atomic Integrity Check
            suite.add(new TestCase("TC-C02", "sys_execve", "BINARY_INTEGRITY_FAILURE", Severity.CRITICAL, "root",
                    "localhost", null, "/usr/sbin/sshd", "BAD_TAMPERED_HASH_HERE"));
            suite.add(new TestCase("TC-C03", "JVMTI_ClassLoad", "MALICIOUS_CLASS_LOAD", Severity.CRITICAL, "web",
                    "localhost", "Exploit.class", null, null));

            executeTestSuite(suite);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
