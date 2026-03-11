import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Random;

public class HackSimulator {

    // The endpoint of our MedSpecter Node.js Server
    private static final String TARGET_URL = "http://localhost:3000/api/telemetry/ingest";
    private static final Random random = new Random();

    // The array of simulated threats matching our Global Threat Map configurations
    private static final String[] BASE_EVENTS = {
            "{\"sourceIp\":\"10.0.0.1\",\"action\":\"JVMTI_ClassLoad\",\"className\":\"Exploit.class\",\"country\":\"Russia\",\"lat\":61.5,\"lng\":105.3}",
            "{\"sourceIp\":\"10.0.0.2\",\"action\":\"JNDI_Lookup\",\"target\":\"ldap://evil.com/a\",\"country\":\"China\",\"lat\":35.8,\"lng\":104.1}",
            "{\"sourceIp\":\"10.0.0.3\",\"action\":\"SQL_DML\",\"rowsReturned\":25000,\"country\":\"North Korea\",\"lat\":40.3,\"lng\":127.5}",
            "{\"sourceIp\":\"10.0.0.4\",\"action\":\"Auth_Failed_DBMS\",\"user\":\"root\",\"reason\":\"bad pass\",\"country\":\"Iran\",\"lat\":32.4,\"lng\":53.6}",
            "{\"sourceIp\":\"10.0.0.5\",\"action\":\"Spring_Actuator\",\"apiPath\":\"/env\",\"ip\":\"10.0.0.5\",\"country\":\"Brazil\",\"lat\":-14.2,\"lng\":-51.9}"
    };

    public static void main(String[] args) {
        System.out.println("===========================================");
        System.out.println("[MedSpecter Java Sensor Agent Initialized]");
        System.out.println("Target SOC Server: " + TARGET_URL);
        System.out.println("Beginning live telemetry loop...");
        System.out.println("===========================================\n");

        int eventIndex = 0;

        while (true) {
            try {
                // Select an event sequentially to ensure variety
                String baseJson = BASE_EVENTS[eventIndex % BASE_EVENTS.length];
                eventIndex++;

                // Slightly mutate the payload so exact duplicates aren't dropped by the Node
                // backend
                String mutatedJson = mutatePayload(baseJson);

                System.out.println("[Interceptor] Firing Threat Telemetry -> " + mutatedJson);

                // Send the HTTP POST request
                sendPostRequest(mutatedJson);

                // Wait 5 seconds before firing the next attack (Matches MedSpecter heartbeat)
                Thread.sleep(5000);

            } catch (InterruptedException e) {
                System.err.println("Simulation interrupted.");
                break;
            } catch (Exception e) {
                System.err.println(
                        "Failed to send telemetry. Is the Node.js MedSpecter server running? Error: " + e.getMessage());
                try {
                    Thread.sleep(5000);
                } catch (Exception ignored) {
                } // Wait before retrying
            }
        }
    }

    private static String mutatePayload(String json) {
        // A simple brute-force string replacement to append random numbers and simulate
        // unique events
        int randId = random.nextInt(1000);
        json = json.replace("\"Exploit.class\"", "\"Exploit.class_" + randId + "\"");
        json = json.replace("\"25000\"", "\"" + (20000 + random.nextInt(10000)) + "\"");
        json = json.replace("\"root\"", "\"root_" + (random.nextInt(10)) + "\"");
        return json;
    }

    private static void sendPostRequest(String jsonPayload) throws Exception {
        URL url = new URL(TARGET_URL);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setRequestProperty("Accept", "application/json");
        conn.setDoOutput(true);

        try (OutputStream os = conn.getOutputStream()) {
            byte[] input = jsonPayload.getBytes(StandardCharsets.UTF_8);
            os.write(input, 0, input.length);
        }

        int responseCode = conn.getResponseCode();
        if (responseCode == 202) {
            System.out.println("   -> Success [202 Accepted] SOC Received Alert.");
        } else {
            System.out.println("   -> Warning [HTTP " + responseCode + "] Unexpected response from SOC.");
        }
    }
}
