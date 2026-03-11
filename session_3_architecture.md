# Session 3: Software Architecture and System Design
**Project:** Secure System Monitor
**Domain:** Healthcare Infrastructure

---

## 1. Core Architecture Modules (7 Modules)
The Secure System Monitor is engineered using a decoupled, microservices-oriented event-driven architecture to ensure zero performance degradation on life-critical healthcare systems.

1.  **eBPF Telemetry Core (Module 1):** A lightweight kernel-level sensor deployed across EHR servers and medical IoT gateways. It hooks into the Linux kernel to intercept system calls (file access, network binds, process execution) asynchronously with near-zero overhead.
2.  **Telemetry Ingestion Broker (Module 2):** An Apache Kafka-based distributed streaming platform. It acts as a highly resilient buffer, securely receiving encrypted telemetry streams via mTLS from thousands of endpoint sensors, preventing data loss during traffic spikes.
3.  **Real-Time Stream Processor (Module 3):** Built on Apache Flink, this component subscribes to the ingestion broker. It cleanses, normalizes, and enriches raw telemetry data (e.g., mapping IP addresses to internal healthcare subnets) in real-time before passing it to the detection engines.
4.  **Deterministic Heuristics Engine (Module 4):** A fast, rule-based evaluation engine (utilizing tools like Falco or Sigma rules). It immediately flags explicitly malicious behavior signatures, such as `sys_ptrace` targeting `lsass.exe` or `chmod 0777 /etc/passwd`.
5.  **Probabilistic ML Anomaly Detector (Module 5):** An isolated inference microservice executing Isolation Forest or Autoencoder models. It analyzes enriched streams to identify subtle behavioral deviations from established baseline profiles (e.g., slow data exfiltration).
6.  **Immutable Time-Series Datastore (Module 6):** A high-write-throughput database (e.g., ClickHouse or TimescaleDB) configured with strict append-only permissions and at-rest AES-256 encryption. It serves as the authoritative, tamper-evident forensic ledger.
7.  **Command Center Dashboard (Module 7):** A React/Vite-based web client providing a real-time, WebSocket-driven visualization interface. Supported by a Node.js API backend, it allows Security Operations Center (SOC) analysts to view active alerts, investigate node status, and map threat surfaces dynamically.

---

## 2. High-Level Architecture Explanation
The architecture follows a strict decoupled pipeline: **Gather -> Buffer -> Analyze -> Act**. Lightweight eBPF sensors located on healthcare nodes non-blockingly gather execution telemetry. This raw data is transmitted securely via mTLS to a Kafka ingestion cluster, which acts as a shock absorber. A Flink stream processor normalizes the data, simultaneously routing it to a fast deterministic rules engine for known signatures, and a slower ML component for behavioral anomalies. Detected threats generate alerts pushed to a secure Time-Series Datastore for immutable forensic logging, while a WebSocket API instantly pushes the alert payload to a React-based Command Center dashboard for human analyst triage.

---

## 3. Data Flow Diagram (DFD) - Level 0 Context Diagram
**Description:** The DFD Level 0 models the Secure System Monitor as a single central complex interacting with external entities.
*   **External Entities:** Healthcare IT Assets (EHR DB, Clinical Workstations, IoT Devices), Security Operations Center (SOC) Analyst, IT Administrator Setup.
*   **Data Inputs:** Raw OS Telemetry, Medical Application Logs (HL7/DICOM flows), Configuration Commands.
*   **Data Outputs:** Real-Time Security Alerts (to SOC Analyst), Forensic Query Results, Network Block Requests (optional automated response).

---

## 4. Data Flow Diagram (DFD) - Level 1
**Description:** Decomposition of the central monitor into five core functional processes:
1.  **Process 1.0 (Telemetry Acquisition):** Receives raw system calls from Healthcare Nodes; outputs normalized event streams.
2.  **Process 2.0 (Stream Buffering):** Receives streams; queues and orders data; outputs ordered topics to processing engines.
3.  **Process 3.0 (Parallel Threat Detection):** Receives ordered topics. Forks data to Rule Engine (checking against Signature DB) and ML Engine (checking against Baseline Profile DB). Outputs Threat Alert Data.
4.  **Process 4.0 (Forensic Storage):** Receives Threat Alert Data and Raw Streams; writes to Encrypted Time-Series Data Store.
5.  **Process 5.0 (Visualization & Alerting):** Queries Forensics Data Store, receives live Threat Alert Data via WebSockets, and outputs visual dashboards to the SOC Analyst.

---

## 5. Use Case Diagram Explanation
**Description:** Illustrates the boundaries and actor interactions.
*   **Actors:** 
    *   *Primary:* SOC Analyst, System Administrator. 
    *   *System/Secondary:* eBPF Sensor Agent, Machine Learning Service.
*   **Use Cases (SOC Analyst):** `View Real-Time Dashboard`, `Acknowledge Alert`, `Query Forensic Timeline`, `Export HIPAA Compliance Report`.
*   **Use Cases (System Admin):** `Deploy Sensor Agent`, `Update Deployment Topology`, `Configure ML Baselines`.
*   **Relationships:** `<include>` relationships link `View Real-Time Dashboard` to an obligatory `Authenticate User (MFA)` use case.

---

## 6. Activity Diagram Explanation
**Description:** Maps the step-by-step workflow of a single telemetry event processing lifecycle.
*   **Start Node** -> `Sensor Hooks System Call` -> `Serialize to Protobuf` -> `Transmit to Broker via mTLS`.
*   **Decision Node:** Is the message format valid? 
    *   *If No:* `Drop packet and log metric`.
    *   *If Yes:* `Route to Flink Processor`.
*   **Parallel Execution Bar (Fork):** One path goes to `Evaluate deterministic RegEx/Yara rules`, the other goes to `Compute deviation score against ML Baseline`.
*   **Join Node:** Consolidate findings.
*   **Decision Node:** Is Anomaly Score > Threshold?
    *   *If Yes:* `Write to Incident DB` -> `Push WebSocket Alert to Frontend`.
    *   *If No:* `Write to Cold Storage Archive`.
*   **End Node.**

---

## 7. Sequence Diagram Explanation
**Scenario:** Detection of a possible BOLA (Broken Object Level Authorization) attack at the API Gateway.
1.  **Participant [API Gateway Sensor]:** Observes `sys_recvmsg` indicating JWT User `UID_902` is accessing `/patient/UID_444`. Sends `TelemetryEvent` to **[Kafka Broker]**.
2.  **Participant [Kafka Broker]:** Acknowledges receipt and pushes `Topic: API_Flows` to **[Flink Processor]**.
3.  **Participant [Flink Processor]:** Parses payload, recognizes a cross-identity request mismatch. Forwards parsed JSON to **[Heuristics Engine]**.
4.  **Participant [Heuristics Engine]:** Triggers Rule `ATR-05 (BOLA Exploit)`. Generates an `AlertPayload` marked **CRITICAL**.
5.  **Participant [Heuristics Engine]:** Sends `Insert` command to **[Time-Series DB]**.
6.  **Participant [Time-Series DB]:** Returns cryptographic hash confirming append-only write success.
7.  **Participant [Node.js API]:** Detects DB insert trigger. Broadcasts payload over active WebSocket to **[React Dashboard]**.

---

## 8. Class Diagram Structure
**Description:** Defines the Object-Oriented structure of the backend processing logic.
*   **Class `TelemetryEvent`:** Attributes: `event_id`, `timestamp`, `source_ip`, `syscall_type`, `raw_payload`. Methods: `serialize()`, `validate_checksum()`.
*   **Class `HealthcareAsset`:** Attributes: `asset_id`, `type` (Enum: EHR, IoT, WS), `baseline_profile_id`.
*   **Class `RuleEngine`:** Attributes: `rule_list`. Methods: `evaluate(TelemetryEvent): boolean`.
*   **Class `Alert` (Inherits from `TelemetryEvent`):** Attributes: `severity_level`, `mitre_tactic`, `clinical_impact_desc`. Methods: `escalate()`.
*   **Class `DatabaseConnector`:** Singleton class managing the secure connection pool to the encrypted datastore.

---

## 9. Vulnerability Points (Architecture Weaknesses)
While robust, the monitor's proposed architecture contains potential exploitation surfaces:
1.  **eBPF Probe Tampering:** If an attacker gains root privilege on the EHR server, they could unload the eBPF kernel module, effectively blinding the monitor to that node.
2.  **Kafka Topic Poisoning:** If mTLS certificates are stolen, an attacker could flood the ingestion broker with fabricated telemetry, inducing a Denial of Service and alert fatigue.
3.  **ML Model Poisoning:** Over time, an attacker executing a "low and slow" data exfiltration attack could subtly alter the dynamic baseline profiles, teaching the ML model to accept malicious behavior as normal.
4.  **Time-Series DB Resource Exhaustion:** Volumetric attacks generating millions of false-positive system calls could exhaust the storage capacity of the forensic database.
5.  **WebSocket Hijacking:** Vulnerabilities in the NodeJS backend could allow an attacker to intercept or inject false alerts into the SOC dashboard via Cross-Site WebSocket Hijacking (CSWSH).
6.  **Dashboard Cross-Site Scripting (XSS):** If raw telemetry payload data (which is attacker-controlled) is not properly sanitized before rendering on the React dashboard, it could lead to stored XSS against the security analyst.
7.  **Sensor "Heartbeat" Spoofing:** An attacker disconnecting a medical device could simulate the device's heartbeat packets, bypassing the `SENSOR_HEARTBEAT_LOSS` trigger.
8.  **Clock Synchronization Skew:** If NTP servers are compromised, event timestamps could drift, destroying the chronological integrity of the sequence analysis required for detecting lateral movement.
9.  **Unencrypted Memory on ML Node:** While data at rest and in transit is encrypted, telemetry processed in memory on the Flink/ML nodes is in cleartext, vulnerable to memory dumping.

---

## 10. Architecture Justification
This microservices architecture is specifically tailored for the zero-tolerance constraints of critical healthcare environments. Utilizing **eBPF** (Extended Berkeley Packet Filter) at the sensor level is critical; unlike traditional inline agents or proxies, eBPF operates asynchronously within the kernel, guaranteeing that monitoring will never block, slow down, or crash life-support applications or massive EHR databases. The introduction of **Apache Kafka** decouples the fast production of telemetry from the slower analysis phase, preventing the ingestion pipeline from collapsing during a ransomware network-flooding attack. By bifurcating the detection logic into parallel deterministic (Heuristics) and probabilistic (ML) tracks, the system achieves instant detection for known threats while retaining the capability to identify evasive, novel exploits without sacrificing processing speed. Finally, the centralized **React/WebSocket** frontend ensures that when a High-Severity incident occurs, the time-to-glass for the SOC analyst is strictly minimized to sub-second latency.
