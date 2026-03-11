const http = require('http');

const options = {
    hostname: 'localhost',
    port: 3000,
    path: '/api/telemetry/ingest',
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
    },
};

function sendTelemetry(event, delayMs) {
    setTimeout(() => {
        const req = http.request(options, (res) => {
            console.log(`[${new Date().toLocaleTimeString()}] Sent: ${event.type || event.syscall} -> HTTP ${res.statusCode}`);
        });

        req.on('error', (error) => {
            console.error('Connection error: Ensure server is running on port 3000', error.message);
        });

        req.write(JSON.stringify(event));
        req.end();
    }, delayMs);
}

// --- COMPLEX ATTACK SEQUENCE SIMULATION ---
console.log("=========================================");
console.log("Initiating Session 4 Complex Attack Chain");
console.log("Target: EHR Database / Active Directory");
console.log("=========================================\n");

const attackerIp = "185.22.11.90";
const targetUser = "dr_smith";

// 1. Supply Chain Tamper Attempt (Will be caught by SHA-256 rule)
sendTelemetry({
    sourceIp: attackerIp,
    syscall: "sys_execve",
    command: "/usr/sbin/sshd",
    // Invalid hash for sshd
    fileHash: "ba9e1bb6c7e907d06dafe4687e579bdac6b37e4e93b7605022da52e6ccc26fd2"
}, 1000);

// 2. Brute Force Sequence (Spamming LOGIN_FAIL to trigger stateful buffer)
for (let i = 0; i < 7; i++) {
    sendTelemetry({
        sourceIp: attackerIp,
        type: "LOGIN_FAIL",
        userId: targetUser
    }, 2000 + (i * 200));
}

// 3. The Compromise: Successful login immediately following the brute force
// This triggers CORR-01 (Successful Authentication Post-Brute Force)
sendTelemetry({
    sourceIp: attackerIp,
    type: "LOGIN_SUCCESS",
    userId: targetUser
}, 4000);

// 4. Broken Object Level Auth (BOLA / IDOR) Exploit
// Triggering ATR-05 rule via JWT mismatch
sendTelemetry({
    sourceIp: attackerIp,
    apiPath: "/api/v1/patient/UID_999",
    jwtSubjectId: "UID_212" // Mismatch!
}, 5500);

// 5. Memory Injection (Credential Dumping)
// Triggering ATR-02 Rule
sendTelemetry({
    sourceIp: attackerIp,
    syscall: "sys_ptrace",
    sourceProcess: "powershell.exe",
    targetProcess: "lsass.exe"
}, 7000);
