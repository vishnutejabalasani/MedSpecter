# MedSpecter: Technical Architecture & Project Documentation

MedSpecter is an advanced, real-time Security Operations Center (SOC) dashboard. It simulates a secure runtime environment capable of intercepting, analyzing, and plotting high-level cyber security threats via an immersive 3D geographic interface.

## 🛠 Technology Stack

### Frontend (Client-Side)
- **Framework**: React 19 (Bootstrapped with Vite for instant HMR and optimized builds)
- **Routing**: `react-router-dom` (v7) for seamless single-page application navigation
- **3D Visualization**: `react-globe.gl` & `three.js` (Renders the cinematic Global Threat Map with WebGL)
- **Data Visualization & Analytics**: `recharts` (Used for real-time area charts, radar charts, and bar graphs)
- **Fluid UI Animations**: `framer-motion` (Manages layout transitions, modal pop-ups, and alert entry animations)
- **Styling**: Custom CSS with Glassmorphism aesthetics, utilizing modern CSS variables for a cohesive dark-mode theme
- **Icons**: `lucide-react`

### Backend (Server-Side)
- **Server Environment**: Node.js
- **API Framework**: Express.js (Handles REST API routes for deep dive analytics and historical log fetching)
- **Real-time Streaming**: `ws` (WebSocket) (Pushes live, simulated telemetry events to the frontend)
- **Database**: MySQL via `mysql2` (Stores the cryptographic forensic ledger of all intercepted alerts)
- **Cryptography**: Native Node.js `crypto` module (Calculates SHA-256 hashes for log immutability)

### Artificial Intelligence
- **AI Engine**: Google Gemini API (`@google/genai`)
- **Integration**: The backend communicates directly with the Gemini model to parse cryptic JSON log payloads into plain-English "Deep Dive" summaries and actionable remediation steps.

---

## 🚀 Core Features

### 1. 3D Global Threat Map (`LiveThreatMap.jsx`)
A highlight of the application, this component renders a cinematic, auto-rotating holographic Earth.
- **Geo-Tracking:** Intercepts WebSocket alerts and maps incoming IP coordinates to physical countries.
- **Visuals:** Features glowing neon laser arcs (color-coded by severity) shooting from attacker origins (e.g., Russia, China, USA) directly into the defending Datacenter located in Hyderabad, India.
- **Animations:** Employs rippling impact shockwaves (`ringsData`) and floating 3D text labels to identify the attacking nation and threat level.

### 2. Live Incident Timeline (`App.jsx`)
A real-time, WebSocket-driven feed displaying simulated anomalous activity (e.g., `SQL_DML_Bulk_Extraction`, `JNDI_Lookup`).
- Alerts are color-coded (Red for Critical, Yellow for High, Blue for Medium).
- Features filtering by severity and real-time text searching.

### 3. AI-Powered "Deep Dive" Investigation (`server/ai.js`)
When an analyst clicks "Investigate Deep Dive" on an alert, the backend securely forwards the technical logs to the Google Gemini model. The UI subsequently displays:
- A "Layman Summary" of what the hacker was trying to achieve.
- Immediate "Remediation Steps" to neutralize the threat.

### 4. Cryptographic Forensic Ledger (`server/db.js`)
Simulates the immutability of a blockchain. 
- Every event written to the MySQL database is hashed using **SHA-256**.
- The hash incorporates the `timestamp`, `event_type`, `payload`, AND the **hash of the previous record**.
- If an attacker gains access to the database and attempts to alter or delete past logs to cover their tracks, the cryptographic chain will break, instantly alerting auditors to the tampering.

### 5. Runtime Flow Analytics (`App.jsx`)
Features responsive charts built with `recharts` that simulate network telemetry. 
- The Main Traffic Chart graphs inbound traffic, outbound traffic, and the volume of packets actively being blocked by the Heuristics engine.

### 6. Java Virtual Machine (JVM) & Spring Boot Ecosystem (Telemetry Source)
While the real-time Dashboard is powered by Node.js and React, the core narrative and **simulated threat intelligence data** running through the entire system represent vulnerabilities typical of an enterprise **Java/Spring Boot ecosystem.**
- **Log4Shell (`JNDI_Lookup`)**: Simulates the infamous Java Log4j zero-day vulnerability where an attacker manipulates the Java Naming and Directory Interface.
- **Spring Actuator Exploits (`Spring_Actuator_Access`)**: Simulates attackers discovering exposed `/actuator/env` endpoints, a common misconfiguration in Spring Boot microservices that leaks environment credentials.
- **Java Virtual Machine Telemetry (`JVMTI_ClassLoad` & `Java_OutOfMemoryError`)**: Simulates deep JVM agents monitoring byte-code execution. Alerts mirror real-time Java Native Interface (JNI) hooks detecting anomalous class loading or memory leaks designed to crash the Java heap. 
- **JDBC Connection Overload**: Simulates a malicious actor depleting the Tomcat server's Java Database Connectivity (JDBC) connection pool to cause a Denial of Service (DoS).
*Note: MedSpecter acts as the "Command Center" catching these exact Java-based vulnerabilities in real-time.*

---

## ⚙️ How It Works (Data Pipeline Flow)

1. **Simulation Generator (`server/index.js`)**: An interval loop acts as a mock Kafka stream or eBPF sensor, generating a random anomaly event every 5 seconds (assigning mock IP coordinates to simulate global attacks).
2. **Ingestion Engine (`server/ingestion.js`)**: The event is ingested, structured, mapped to a severity score (Critical, High, Medium, Info), and appended with localized metadata.
3. **Database Ledger (`server/db.js`)**: The system calculates the SHA-256 hash of the new event coupled with the previous event's hash, inserting the cryptographically secure row into MySQL.
4. **WebSocket Broadcast (`ws`)**: Simultaneously, the backend blasts the processed JSON alert object over the active WebSocket port.
5. **Frontend Interpretation**: The React application consumes the WebSocket JSON. It appends the new incident to the Timeline array and simultaneously passes the geo-coordinates to `react-globe.gl` to trigger the 3D laser animation.
