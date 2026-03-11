import React, { useState, useEffect } from 'react';
import { Routes, Route, Link, useLocation } from 'react-router-dom';
import {
  Activity, ShieldAlert, Cpu, Network, Lock,
  Server, AlertTriangle, CheckCircle, Database, LayoutDashboard,
  Bell, FileCode, Users, HelpCircle, Eye, Trash2, Shield, Info, ToggleLeft, ToggleRight,
  Search, Filter, Sparkles
} from 'lucide-react';
import {
  LineChart, Line, AreaChart, Area, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, RadarChart, PolarGrid,
  PolarAngleAxis, PolarRadiusAxis, Radar, BarChart, Bar
} from 'recharts';
// eslint-disable-next-line no-unused-vars
import { motion, AnimatePresence } from 'framer-motion';
import LiveThreatMap from './components/LiveThreatMap';

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null, errorInfo: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error("ErrorBoundary caught an error:", error, errorInfo);
    this.setState({ errorInfo });
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{ color: 'red', padding: '50px', background: 'black', height: '100vh', width: '100vw' }}>
          <h2>React App Crashed!</h2>
          <pre>{this.state.error && this.state.error.toString()}</pre>
          <pre>{this.state.errorInfo && this.state.errorInfo.componentStack}</pre>
        </div>
      );
    }
    return this.props.children;
  }
}

// --- MOCK DATA FOR THE REAL-TIME DASHBOARD ---
const generateNetworkTraffic = (points = 20) => Array.from({ length: points }, (_, i) => ({
  time: `11:${i < 10 ? '0' : ''}${i}`,
  inbound: Math.floor(Math.random() * 800) + 200,
  outbound: Math.floor(Math.random() * 1000) + 100,
  blocked: Math.floor(Math.random() * 50)
}));

const attackVectors = [
  { subject: 'Data Theft', A: 120, fullMark: 150 },
  { subject: 'Database Hack', A: 98, fullMark: 150 },
  { subject: 'System Overload', A: 86, fullMark: 150 },
  { subject: 'Scam Links', A: 99, fullMark: 150 },
  { subject: 'Stolen Passwords', A: 85, fullMark: 150 },
  { subject: 'Device Hijack', A: 65, fullMark: 150 },
];

const mockAlerts = [
  { id: 'EVT_1001', type: 'INFO', title: 'Outbound Connection', source: 'Clinical-WS-04', time: '08:01:12', desc: 'chrome.exe -> 10.0.5.20:443' },
  { id: 'EVT_1002', type: 'INFO', title: 'Process Execution', source: 'EHR-DB-01', time: '08:01:15', desc: '/usr/lib/postgresql/14/bin/postgres' },
  { id: 'EVT_1003', type: 'MEDIUM', title: 'Login Failure', source: 'API-Gateway', time: '08:03:00', desc: 'User: dr_smith | Reason: bad_password' },
  { id: 'EVT_1004', type: 'MEDIUM', title: 'Network Bind (UDP)', source: 'Internal-DNS', time: '08:04:12', desc: 'proc: named bound to port 53' },
  { id: 'EVT_1005', type: 'INFO', title: 'File Access (O_RDWR)', source: 'EHR-DB-01', time: '08:05:33', desc: '/var/lib/postgresql/data/pg_wal/001.log' },
  { id: 'EVT_1006', type: 'HIGH', title: 'Login Fail Burst (15 in 45s)', source: 'API-Gateway', time: '08:12:05', desc: 'Target: admin | Src: 45.22.11.9' },
  { id: 'EVT_1007', type: 'CRITICAL', title: 'Unexpected Child Process (ATR-01)', source: 'Patient-Portal', time: '08:14:22', desc: 'nginx spawned bash invoking curl (Reverse Shell attempt)' },
  { id: 'EVT_1008', type: 'HIGH', title: 'Suspicious Connect', source: 'Patient-Portal', time: '08:14:25', desc: 'curl -> 185.11.2.3:80' },
  { id: 'EVT_1009', type: 'CRITICAL', title: 'Malicious Payload Exec', source: 'Patient-Portal', time: '08:14:28', desc: './pay.sh executed by www-data' },
  { id: 'EVT_1010', type: 'HIGH', title: 'Permission Tamper (ATR-09)', source: 'Patient-Portal', time: '08:14:35', desc: 'chmod 0777 /etc/passwd (Failed)' },
  { id: 'EVT_1011', type: 'HIGH', title: 'Sensor Heartbeat Loss (ATR-06)', source: 'ICU-Gateway-A', time: '08:30:00', desc: 'Lost connection to [INF-A12, INF-A15] for > 30s' },
  { id: 'EVT_1012', type: 'MEDIUM', title: 'Malformed Med Traffic', source: 'DICOM-Router', time: '08:30:15', desc: 'buffer_overread on 10.10.5.22' },
  { id: 'EVT_1013', type: 'CRITICAL', title: 'BOLA Exploit (ATR-05)', source: 'API-Gateway', time: '09:15:00', desc: 'JWT sub UID_902 requested /users/UID_444/medical_history' },
  { id: 'EVT_1014', type: 'HIGH', title: 'Data Exfiltration (ATR-03)', source: 'API-Gateway', time: '09:15:01', desc: 'UID_902 transferred > 154MB' },
  { id: 'EVT_1015', type: 'CRITICAL', title: 'Memory Injection (ATR-02)', source: 'Admin-WS-01', time: '10:05:11', desc: 'powershell.exe ptrace on lsass.exe' },
  { id: 'EVT_1016', type: 'HIGH', title: 'Unauthorized Bind (ATR-08)', source: 'Admin-WS-01', time: '10:06:00', desc: 'nc.exe bound TCP 4444' },
  { id: 'EVT_1017', type: 'CRITICAL', title: 'Sensitive DB File Access', source: 'Backup-NAS', time: '10:08:45', desc: 'O_RDWR on /mnt/ehr_backups/db.bak by unknown.exe' },
  { id: 'EVT_1018', type: 'HIGH', title: 'Anon Memory Allocation', source: 'Backup-NAS', time: '10:08:46', desc: 'unknown.exe allocated 512MB (PROT_EXEC|PROT_WRITE)' },
  { id: 'EVT_1019', type: 'CRITICAL', title: 'File Deletion Burst (ATR-04)', source: 'Backup-NAS', time: '10:09:00', desc: 'unknown.exe unlinked /var/log/syslog' },
  { id: 'EVT_1020', type: 'CRITICAL', title: 'Ransomware Behavior (ATR-10)', source: 'Backup-NAS', time: '10:10:00', desc: 'disk_write at 950MB/s (Baseline: 10MB/s)' },
];

const mockDevices = [
  { host: 'EHR-DB-01 (PostgreSQL)', ip: '192.168.10.4', status: 'Protected', load: '68%', alerts: 1 },
  { host: 'Radiology-Imaging-Srv', ip: '192.168.10.15', status: 'Secured', load: '45%', alerts: 0 },
  { host: 'PAC-System-Core', ip: '192.168.20.2', status: 'Warning', load: '92%', alerts: 3 },
  { host: 'Infusion-Pump-GatewayB2', ip: '192.168.105.12', status: 'Protected', load: '12%', alerts: 0 },
];

// --- COMPONENTS ---

const Panel = ({ title, icon: Icon, children, className = '', style }) => (
  <motion.div
    initial={{ opacity: 0, y: 20 }}
    animate={{ opacity: 1, y: 0 }}
    transition={{ duration: 0.5 }}
    className={`panel ${className}`}
    style={style}
  >
    <div className="panel-header">
      <div className="panel-title">
        {Icon && <Icon size={18} />}
        {title}
      </div>
    </div>
    {children}
  </motion.div>
);

const StatCard = ({ title, value, unit, trend, isPositive, icon: Icon, tooltip }) => (
  <Panel title={
    <div style={{ display: 'flex', alignItems: 'center', width: '100%', justifyContent: 'space-between' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
        {Icon && <Icon size={18} />}
        {title}
      </div>
      {tooltip && (
        <div className="tooltip-container">
          <HelpCircle size={16} />
          <span className="tooltip-text">{tooltip}</span>
        </div>
      )}
    </div>
  } className="stat-card">
    <div className="stat-value">
      {value}<span style={{ fontSize: '1.25rem', color: 'var(--text-muted)' }}>{unit}</span>
    </div>
    <div className={`stat-trend ${isPositive ? 'trend-down' : 'trend-up'}`}>
      {isPositive ? <CheckCircle size={14} /> : <AlertTriangle size={14} />}
      <span>{trend} vs last hour</span>
    </div>
  </Panel>
);

// --- MAIN APPLICATION ---

const ExecutiveSummary = ({ alerts }) => {
  // Simple Risk Scoring Logic
  const criticalCount = alerts.filter(a => a.type === 'CRITICAL').length;
  const highCount = alerts.filter(a => a.type === 'HIGH').length;

  let riskLevel = 'LOW';
  let message = 'Network secure. All inbound anomalous data is being successfully filtered.';
  let bgColor = 'rgba(16, 185, 129, 0.1)';
  let color = 'var(--success)';
  let borderColor = 'rgba(16, 185, 129, 0.3)';

  if (criticalCount > 0) {
    riskLevel = 'HIGH';
    message = 'Immediate incident response required. Several critical threats (e.g., Reverse Shell) have breached boundary defenses.';
    bgColor = 'rgba(239, 68, 68, 0.1)';
    color = 'var(--danger)';
    borderColor = 'rgba(239, 68, 68, 0.3)';
  } else if (highCount > 2) {
    riskLevel = 'MEDIUM';
    message = 'Elevated scanning activity detected. Monitor automated blocking systems.';
    bgColor = 'rgba(245, 158, 11, 0.1)';
    color = 'var(--warning)';
    borderColor = 'rgba(245, 158, 11, 0.3)';
  }

  return (
    <div style={{
      gridColumn: '1 / -1',
      backgroundColor: bgColor,
      border: `1px solid ${borderColor}`,
      borderRadius: '16px',
      padding: '1.5rem 2rem',
      display: 'flex',
      alignItems: 'center',
      gap: '2rem',
      backdropFilter: 'blur(16px)'
    }}>
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.5rem', minWidth: '150px' }}>
        <ShieldAlert size={40} color={color} />
        <span style={{ color: color, fontWeight: 800, fontSize: '1.1rem', letterSpacing: '1px' }}>{riskLevel} RISK</span>
      </div>
      <div>
        <h2 style={{ fontSize: '1.5rem', fontWeight: 700, margin: '0 0 0.5rem 0', color: 'var(--text-main)' }}>Executive Summary</h2>
        <p style={{ fontSize: '1rem', color: 'var(--text-main)', margin: 0, lineHeight: 1.5 }}>
          {message}
        </p>
      </div>
    </div>
  );
};

const GuidedBanner = ({ show, text }) => {
  if (!show) return null;
  return (
    <motion.div
      initial={{ opacity: 0, height: 0, marginBottom: 0 }}
      animate={{ opacity: 1, height: 'auto', marginBottom: '1.5rem' }}
      exit={{ opacity: 0, height: 0, marginBottom: 0 }}
      style={{ gridColumn: '1 / -1', overflow: 'hidden' }}
    >
      <div className="guided-banner">
        <Info size={24} style={{ color: 'var(--primary)', flexShrink: 0 }} />
        <div>
          <strong style={{ display: 'block', marginBottom: '0.25rem', color: 'var(--primary)' }}>Guide:</strong>
          {text}
        </div>
      </div>
    </motion.div>
  );
};

function App() {
  const [trafficData, setTrafficData] = useState(generateNetworkTraffic());
  const [alerts, setAlerts] = useState(mockAlerts);
  const [isGuidedMode, setIsGuidedMode] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [aiAnalysis, setAiAnalysis] = useState({});
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const location = useLocation();

  const handleDeepDive = async (alert) => {
    if (aiAnalysis[alert.id]) return; // Already analyzed

    setIsAnalyzing(alert.id);
    try {
      const response = await fetch('http://localhost:3000/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ incident: alert })
      });
      const data = await response.json();
      setAiAnalysis(prev => ({ ...prev, [alert.id]: data.analysis }));
    } catch (err) {
      console.error("Failed to fetch AI analysis", err);
      setAiAnalysis(prev => ({ ...prev, [alert.id]: "Error connecting to AI inference engine." }));
    } finally {
      setIsAnalyzing(false);
    }
  };

  // AI Threat Score Generator (Deterministic based on ID for pure render)
  const getAiThreatScore = (alert) => {
    const hash = alert.id.split('').reduce((acc, char) => acc + char.charCodeAt(0), 0);
    switch (alert.type) {
      case 'CRITICAL': return { score: 90 + (hash % 10), confidence: 'High' };
      case 'HIGH': return { score: 75 + (hash % 15), confidence: 'Medium' };
      case 'MEDIUM': return { score: 50 + (hash % 20), confidence: 'Low' };
      default: return { score: 10 + (hash % 30), confidence: 'Low' };
    }
  };

  const filteredAlerts = alerts.filter(alert => {
    const matchesSearch =
      alert.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (alert.desc && alert.desc.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (alert.source && alert.source.toLowerCase().includes(searchTerm.toLowerCase()));

    const matchesSeverity = severityFilter === 'ALL' || alert.type === severityFilter;

    return matchesSearch && matchesSeverity;
  });

  // Fetch Historical Alerts & Connect WebSocket
  useEffect(() => {
    // 1. Fetch initial forensic history from SQLite Datastore
    fetch('http://localhost:3000/api/alerts')
      .then(res => res.json())
      .then(data => {
        if (Array.isArray(data) && data.length > 0) {
          // Map DB columns to our UI schema
          const mappedHistory = data.map(row => ({
            id: row.log_id || row.event_id,
            type: row.severity || row.type,
            title: row.event_type || row.title,
            source: row.source_system || row.source,
            time: new Date(row.timestamp).toLocaleTimeString(),
            desc: row.payload_json || row.description,
            previous_hash: row.previous_hash,
            current_hash: row.current_hash
          }));
          setAlerts(mappedHistory);
        }
      })
      .catch(err => console.error("Failed to fetch historical alerts", err));

    // 2. Establish Secure WebSocket to Flink/Ingestion Backend
    const ws = new WebSocket('ws://localhost:3000');

    ws.onopen = () => {
      console.log('Secure WebSocket Link Established to Command Center.');
    };

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        if (msg.type === 'NEW_ALERT' && msg.payload) {
          const newAlert = {
            id: msg.payload.id || msg.payload.event_id,
            type: msg.payload.severity || msg.payload.type,
            title: msg.payload.title || msg.payload.event_type,
            source: msg.payload.source || msg.payload.source_system,
            time: 'Just now', // Live indicator
            desc: msg.payload.desc || msg.payload.payload_json || msg.payload.description,
            lat: msg.payload.lat || null,
            lng: msg.payload.lng || null,
            country: msg.payload.country || "Unknown",
            previous_hash: msg.payload.previous_hash,
            current_hash: msg.payload.current_hash
          };

          setAlerts(prev => {
            // Check for duplicates
            if (prev.some(a => a.id === newAlert.id)) return prev;
            return [newAlert, ...prev].slice(0, 15); // Keep last 15 live
          });
        }
      } catch (e) {
        console.error("Failed to parse incoming WS telemetry", e);
      }
    };

    // 3. Keep the background traffic chart moving (as a UI element)
    const interval = setInterval(() => {
      setTrafficData(prev => {
        const newData = [...prev.slice(1)];
        const lastTime = parseInt(newData[newData.length - 1].time.split(':')[1]);
        const nextTime = (lastTime + 1) % 60;
        newData.push({
          time: `11:${nextTime < 10 ? '0' : ''}${nextTime}`,
          inbound: Math.floor(Math.random() * 800) + 200,
          outbound: Math.floor(Math.random() * 1000) + 100,
          blocked: Math.floor(Math.random() * 50)
        });
        return newData;
      });
    }, 2000);

    return () => {
      clearInterval(interval);
      ws.close();
    };
  }, []);

  return (
    <ErrorBoundary>
      <div className="app-container">
        {/* Sidebar Navigation */}
        <nav className="sidebar">
          <div className="brand">
            <ShieldAlert className="brand-icon" size={32} />
            <span className="brand-text">MedSpecter</span>
          </div>

          <div className="nav-menu">
            <Link to="/" className={`nav-item ${location.pathname === '/' ? 'active' : ''}`} style={{ textDecoration: 'none' }}>
              <LayoutDashboard size={20} /><span>Command Center</span>
            </Link>
            <Link to="/runtime" className={`nav-item ${location.pathname === '/runtime' ? 'active' : ''}`} style={{ textDecoration: 'none' }}>
              <Activity size={20} /><span>Runtime Monitor</span>
            </Link>
            <Link to="/alerts" className={`nav-item ${location.pathname === '/alerts' ? 'active' : ''}`} style={{ textDecoration: 'none' }}>
              <AlertTriangle size={20} /><span>Incident Alerts</span>
            </Link>
            <Link to="/map" className={`nav-item ${location.pathname === '/map' ? 'active' : ''}`} style={{ textDecoration: 'none' }}>
              <ShieldAlert size={20} /><span>Global Threat Map</span>
            </Link>
            <Link to="/network" className={`nav-item ${location.pathname === '/network' ? 'active' : ''}`} style={{ textDecoration: 'none' }}>
              <Network size={20} /><span>Network Flow</span>
            </Link>
          </div>

          <div style={{ marginTop: 'auto' }}>
            <Link to="/config" className={`nav-item ${location.pathname === '/config' ? 'active' : ''}`} style={{ textDecoration: 'none' }}>
              <Server size={20} /><span>System Config</span>
            </Link>
          </div>
        </nav>

        {/* Main Dashboard Workspace */}
        <main className="main-content">
          <header className="top-header">
            <div className="page-title">Runtime Telemetry Overview</div>
            <div className="header-actions">
              <button
                className={`guided-toggle ${isGuidedMode ? 'active' : ''}`}
                onClick={() => setIsGuidedMode(!isGuidedMode)}
              >
                {isGuidedMode ? <ToggleRight size={20} /> : <ToggleLeft size={20} />}
                Guided Mode
              </button>
              <div className="status-badge">
                <div className="status-indicator"></div>
                SENSOR GRID: ACTIVE
              </div>
              <div style={{ position: 'relative' }}>
                <Bell size={24} style={{ cursor: 'pointer', color: 'var(--text-muted)' }} />
                {alerts.length > 0 && (
                  <span style={{
                    position: 'absolute', top: -5, right: -5,
                    background: 'var(--danger)', color: 'white',
                    fontSize: '0.65rem', padding: '2px 6px',
                    borderRadius: '10px', fontWeight: 'bold'
                  }}>
                    {alerts.filter(a => a.type === 'CRITICAL').length || 1}
                  </span>
                )}
              </div>
            </div>
          </header>

          <Routes>
            <Route path="/" element={
              <>
                {/* Executive Summary (Full Width) */}
                <div className="dashboard-grid">
                  <ExecutiveSummary alerts={alerts} />

                  <GuidedBanner
                    show={isGuidedMode}
                    text="These metrics show the overall health of the hospital network. We continuously monitor standard activity and instantly block anything that looks like a cyber attack."
                  />

                  {/* Top KPI Cards (Redesigned for Layman Understanding) */}
                  <StatCard
                    title="Total Activities Monitored"
                    value="1.24" unit="M"
                    trend="+5.2%" isPositive={false}
                    icon={Cpu}
                    tooltip="The total number of routine computer actions we observed across the hospital's network today, such as opening files or running programs."
                  />
                  <StatCard
                    title="Threats Stopped"
                    value="42" unit=""
                    trend="-12%" isPositive={true}
                    icon={ShieldAlert}
                    tooltip="Suspicious behaviors automatically halted before they could cause harm to our databases or applications."
                  />
                  <StatCard
                    title="Monitored Devices"
                    value="3,842" unit=""
                    trend="Stable" isPositive={true}
                    icon={Server}
                    tooltip="Total number of active computers, servers, and connected medical devices currently protected by the system."
                  />
                  <StatCard
                    title="Response Time"
                    value="8" unit="ms"
                    trend="-2ms" isPositive={true}
                    icon={Activity}
                    tooltip="How quickly the system identifies and blocks a threat once it appears (Measured in milliseconds)."
                  />

                  <GuidedBanner
                    show={isGuidedMode}
                    text="This graph visualizes data flowing in and out of the hospital. The red spikes represent malicious traffic that our system successfully blocked before it reached patient records."
                  />

                  {/* Main Traffic Chart */}
                  <Panel title="Network & Telemetry Flow Streams" icon={Network} className="chart-panel-large" style={{ gridColumn: 'span 12', overflow: 'visible' }}>
                    <AreaChart width={850} height={200} data={trafficData} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
                      <defs>
                        <linearGradient id="colorIn" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="var(--primary)" stopOpacity={0.8} />
                          <stop offset="95%" stopColor="var(--primary)" stopOpacity={0} />
                        </linearGradient>
                        <linearGradient id="colorOut" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="var(--secondary)" stopOpacity={0.8} />
                          <stop offset="95%" stopColor="var(--secondary)" stopOpacity={0} />
                        </linearGradient>
                        <linearGradient id="colorBlock" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="var(--danger)" stopOpacity={0.8} />
                          <stop offset="95%" stopColor="var(--danger)" stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <XAxis dataKey="time" stroke="var(--border-color)" tick={{ fill: 'var(--text-muted)', fontSize: 12 }} />
                      <YAxis stroke="var(--border-color)" tick={{ fill: 'var(--text-muted)', fontSize: 12 }} />
                      <CartesianGrid strokeDasharray="3 3" stroke="var(--border-color)" vertical={false} />
                      <Tooltip
                        contentStyle={{ backgroundColor: 'var(--bg-elevated)', borderColor: 'var(--border-color)', borderRadius: '8px' }}
                        itemStyle={{ color: 'var(--text-main)' }}
                      />
                      <Area type="monotone" dataKey="inbound" stroke="var(--primary)" fillOpacity={1} fill="url(#colorIn)" />
                      <Area type="monotone" dataKey="outbound" stroke="var(--secondary)" fillOpacity={1} fill="url(#colorOut)" />
                      <Area type="monotone" dataKey="blocked" stroke="var(--danger)" fillOpacity={1} fill="url(#colorBlock)" />
                    </AreaChart>
                  </Panel>

                  <GuidedBanner
                    show={isGuidedMode}
                    text="This table monitors the hospital's most sensitive servers (like the EHR Database). If a server starts working abnormally hard (high load), it might indicate an ongoing attack."
                  />

                  {/* Monitored Assets Table */}
                  <Panel title={
                    <div style={{ display: 'flex', alignItems: 'center', width: '100%', justifyContent: 'space-between' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <Database size={18} />
                        System Health & Load
                      </div>
                      <div className="tooltip-container">
                        <HelpCircle size={16} />
                        <span className="tooltip-text">A list of critical hospital servers. Shows if their processing power is overloaded or if they are currently under attack.</span>
                      </div>
                    </div>
                  } className="threat-matrix">
                    <div style={{ overflowX: 'auto' }}>
                      <table className="data-table">
                        <thead>
                          <tr>
                            <th>Computer / Database Name</th>
                            <th>Network ID (IP)</th>
                            <th>Security Status</th>
                            <th>Processing Load</th>
                          </tr>
                        </thead>
                        <tbody>
                          {mockDevices.map((dev, idx) => (
                            <tr key={idx}>
                              <td style={{ fontWeight: 500, color: 'var(--text-main)' }}>{dev.host}</td>
                              <td style={{ fontFamily: 'monospace', color: 'var(--text-muted)' }}>{dev.ip}</td>
                              <td>
                                {dev.alerts > 0 ? (
                                  <span className={`badge ${dev.alerts > 1 ? 'badge-critical' : 'badge-high'}`}>
                                    <AlertTriangle size={12} /> Exceeds Baseline
                                  </span>
                                ) : (
                                  <span className="badge" style={{ backgroundColor: 'rgba(16, 185, 129, 0.15)', color: '#6ee7b7', border: '1px solid rgba(16,185,129,0.3)' }}>
                                    <Lock size={12} /> Secure
                                  </span>
                                )}
                              </td>
                              <td>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                  <span style={{ fontSize: '0.8rem', color: parseInt(dev.load) > 80 ? 'var(--warning)' : 'var(--text-muted)' }}>{dev.load}</span>
                                  <div style={{ flex: 1, height: '4px', background: 'rgba(255,255,255,0.1)', borderRadius: '2px' }}>
                                    <div style={{ width: dev.load, height: '100%', background: parseInt(dev.load) > 80 ? 'var(--warning)' : 'var(--primary)', borderRadius: '2px' }}></div>
                                  </div>
                                </div>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </Panel>

                  <GuidedBanner
                    show={isGuidedMode}
                    text="This chart breaks down the types of attacks we're seeing today. If 'Data Theft' is high, it means hackers are actively trying to steal patient records."
                  />

                  {/* Threat Vector Radar Chart */}
                  <Panel title={
                    <div style={{ display: 'flex', alignItems: 'center', width: '100%', justifyContent: 'space-between' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <ShieldAlert size={18} />
                        Current Threat Types Experienced
                      </div>
                      <div className="tooltip-container">
                        <HelpCircle size={16} />
                        <span className="tooltip-text">A breakdown showing which types of cyber threats have targeted the hospital most frequently today. Larger shapes indicate higher activity.</span>
                      </div>
                    </div>
                  } className="network-graph">
                    <div style={{ flex: 1, minHeight: 0 }}>
                      <ResponsiveContainer width="100%" height="100%">
                        <RadarChart cx="50%" cy="50%" outerRadius="70%" data={attackVectors}>
                          <PolarGrid stroke="var(--border-color)" />
                          <PolarAngleAxis dataKey="subject" tick={{ fill: 'var(--text-muted)', fontSize: 12 }} />
                          <PolarRadiusAxis angle={30} domain={[0, 150]} tick={false} axisLine={false} />
                          <Radar name="Threat Activity" dataKey="A" stroke="var(--danger)" fill="var(--danger)" fillOpacity={0.4} />
                          <Tooltip
                            contentStyle={{ backgroundColor: 'var(--bg-elevated)', borderColor: 'var(--border-color)', borderRadius: '8px' }}
                            itemStyle={{ color: 'var(--text-main)' }}
                          />
                        </RadarChart>
                      </ResponsiveContainer>
                    </div>
                  </Panel>

                  <GuidedBanner
                    show={isGuidedMode}
                    text="This is an un-hackable, blockchain-style record. Every security event gets a unique 'fingerprint' (SHA-256). If a hacker tries to delete or alter a past log to cover their tracks, the fingerprints won't match, and the system will alert us immediately."
                  />

                  {/* Compliance & Audit Logs Table (Session 5 - Blockchain Integrator) */}
                  <Panel title={
                    <div style={{ display: 'flex', alignItems: 'center', width: '100%', justifyContent: 'space-between' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <FileCode size={18} />
                        Secure Digital Paper Trail
                      </div>
                      <div className="tooltip-container">
                        <HelpCircle size={16} />
                        <span className="tooltip-text">An unchangeable, blockchain-style record of all security events. Used by auditors to prove the hospital's data has not been secretly modified by hackers.</span>
                      </div>
                    </div>
                  } className="compliance-panel" style={{ gridColumn: '1 / -1' }}>

                    {/* Filter & Search Bar */}
                    <div className="filter-bar">
                      <div className="search-wrapper">
                        <Search size={18} className="search-icon" />
                        <input
                          type="text"
                          placeholder="Search logs by IP, title, or system..."
                          value={searchTerm}
                          onChange={(e) => setSearchTerm(e.target.value)}
                          className="search-input"
                        />
                      </div>
                      <div className="filter-wrapper">
                        <Filter size={18} className="filter-icon" />
                        <select
                          value={severityFilter}
                          onChange={(e) => setSeverityFilter(e.target.value)}
                          className="severity-select"
                        >
                          <option value="ALL">All Severities</option>
                          <option value="CRITICAL">Critical Only</option>
                          <option value="HIGH">High Only</option>
                          <option value="MEDIUM">Medium Only</option>
                          <option value="INFO">Info Only</option>
                        </select>
                      </div>
                    </div>

                    <div style={{ overflowX: 'auto', maxHeight: '400px' }}>
                      <table className="data-table">
                        <thead>
                          <tr>
                            <th>Time Logged</th>
                            <th>Where It Happened</th>
                            <th>Action Taken</th>
                            <th>Technical Details</th>
                            <th>Security Signature</th>
                          </tr>
                        </thead>
                        <tbody>
                          {filteredAlerts.length === 0 ? (
                            <tr>
                              <td colSpan="5" style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>
                                No compliance logs match the current search filters.
                              </td>
                            </tr>
                          ) : filteredAlerts.map((log) => (
                            <tr key={log.id} style={{ borderBottom: '1px solid var(--border-color)' }}>
                              <td style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>{log.time}</td>
                              <td><span className="badge" style={{ backgroundColor: 'var(--bg-hover)', color: 'var(--text-main)', border: '1px solid var(--border-color)' }}>{log.source || 'SYS'}</span></td>
                              <td style={{ fontWeight: 500, color: 'var(--text-main)', fontSize: '0.9rem' }}>{log.title || log.type}</td>
                              <td style={{ fontFamily: 'monospace', fontSize: '0.75rem', color: 'var(--text-muted)', maxWidth: '250px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={log.desc}>{log.desc}</td>
                              <td>
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', fontFamily: 'monospace', fontSize: '0.7rem' }}>
                                  <span title="Previous Block Anchor" style={{ color: 'var(--text-muted)' }}>Prev: {log.previous_hash ? `${log.previous_hash.substring(0, 16)}...` : 'Legacy Entry'}</span>
                                  <span title="Validated Hash" style={{ color: '#10b981' }}>Curr: <Lock size={10} style={{ display: 'inline', verticalAlign: 'middle', marginTop: '-2px' }} /> {log.current_hash ? `${log.current_hash.substring(0, 16)}...` : ''}</span>
                                </div>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </Panel>

                </div>
              </>
            } />

            <Route path="/alerts" element={
              <div className="dashboard-grid" style={{ width: '100%' }}>
                <GuidedBanner
                  show={isGuidedMode}
                  text="This is a real-time log of security events. Notice how the system automatically flags severe threats (CRITICAL) and provides quick tools to investigate or block the attacker."
                />
                <GuidedBanner
                  show={isGuidedMode}
                  text="This is a real-time log of security events. Notice how the system automatically flags severe threats (CRITICAL) and provides quick tools to investigate or block the attacker."
                />

                <Panel title={
                  <div style={{ display: 'flex', alignItems: 'center', width: '100%', justifyContent: 'space-between' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '1.25rem' }}>
                      <AlertTriangle size={24} />
                      Live Incident Timeline
                    </div>
                  </div>
                } className="alerts-panel" style={{ gridColumn: '1 / -1', minHeight: '80vh' }}>

                  {/* Filter & Search Bar */}
                  <div className="filter-bar" style={{ marginBottom: '1.5rem', borderBottom: '1px solid var(--border-color)', paddingBottom: '1rem' }}>
                    <div className="search-wrapper">
                      <Search size={18} className="search-icon" />
                      <input
                        type="text"
                        placeholder="Search active incidents..."
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                        className="search-input"
                      />
                    </div>
                    <div className="filter-wrapper">
                      <Filter size={18} className="filter-icon" />
                      <select
                        value={severityFilter}
                        onChange={(e) => setSeverityFilter(e.target.value)}
                        className="severity-select"
                      >
                        <option value="ALL">All Severities</option>
                        <option value="CRITICAL">Critical Only</option>
                        <option value="HIGH">High Only</option>
                        <option value="MEDIUM">Medium/Low Only</option>
                      </select>
                    </div>
                  </div>

                  <div className="alert-list" style={{ gap: '1rem', display: 'flex', flexDirection: 'column' }}>
                    {filteredAlerts.length === 0 && (
                      <div style={{ textAlign: 'center', padding: '4rem', color: 'var(--text-muted)' }}>
                        <Shield style={{ opacity: 0.2, marginBottom: '1rem' }} size={64} />
                        <h3>No active incidents match your criteria</h3>
                      </div>
                    )}
                    <AnimatePresence>
                      {filteredAlerts.map(alert => {
                        const isCritical = alert.type === 'CRITICAL';
                        const isHigh = alert.type === 'HIGH';
                        const badgeColor = isCritical ? 'var(--danger)' : isHigh ? 'var(--warning)' : 'var(--primary)';
                        const bgGlow = isCritical ? 'rgba(239, 68, 68, 0.05)' : isHigh ? 'rgba(245, 158, 11, 0.05)' : 'rgba(14, 165, 233, 0.05)';

                        return (
                          <motion.div
                            key={alert.id}
                            initial={{ opacity: 0, scale: 0.95 }}
                            animate={{ opacity: 1, scale: 1 }}
                            exit={{ opacity: 0, scale: 0.9 }}
                            className="alert-item"
                            style={{
                              backgroundColor: bgGlow,
                              borderLeft: `4px solid ${badgeColor}`,
                              padding: '1.5rem',
                              display: 'flex',
                              flexDirection: 'column',
                              width: '100%'
                            }}
                          >
                            <div className="alert-header" style={{ marginBottom: '1rem', borderBottom: '1px solid rgba(255,255,255,0.05)', paddingBottom: '1rem' }}>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                                {isCritical ? <ShieldAlert size={22} color={badgeColor} /> : <AlertTriangle size={22} color={badgeColor} />}
                                <span style={{ fontWeight: 700, fontSize: '1.2rem', color: 'var(--text-main)', letterSpacing: '0.5px' }}>
                                  {alert.title}
                                </span>
                                <span style={{
                                  fontSize: '0.75rem', padding: '4px 10px', borderRadius: '12px',
                                  backgroundColor: badgeColor, color: '#fff', fontWeight: 'bold'
                                }}>
                                  {alert.type}
                                </span>
                                <span style={{ color: 'var(--text-muted)', fontSize: '0.85rem', marginLeft: 'auto', fontFamily: 'monospace' }}>
                                  Event ID: {alert.id}
                                </span>
                              </div>
                            </div>

                            <div style={{ display: 'grid', gridTemplateColumns: 'minmax(300px, 1fr) minmax(350px, 2fr)', gap: '2rem', marginBottom: '1.5rem' }}>
                              {/* Layman Explanation */}
                              <div>
                                <div style={{ fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '1px', color: 'var(--text-muted)', marginBottom: '0.5rem', fontWeight: 600 }}>Incident Summary</div>
                                <div style={{ fontSize: '0.95rem', color: 'var(--text-main)', lineHeight: 1.6 }}>
                                  We detected abnormal activity targeting <span style={{ color: 'var(--primary)', fontWeight: 600 }}>{alert.source}</span> at <span style={{ fontWeight: 600 }}>{alert.time}</span>.
                                  <br /><br />
                                  <span style={{ color: 'var(--text-muted)' }}>System noted technical detail:</span>
                                  <div style={{ fontFamily: 'monospace', background: 'rgba(0,0,0,0.3)', padding: '6px 10px', borderRadius: '4px', marginTop: '6px', border: '1px solid rgba(255,255,255,0.05)', color: 'var(--accent)' }}>
                                    {alert.desc}
                                  </div>
                                </div>
                              </div>

                              {/* Technical Cryptographic Integrity Block */}
                              <div>
                                <div style={{ fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '1px', color: 'var(--text-muted)', marginBottom: '0.5rem', fontWeight: 600 }}>Cryptographic Audit Chain</div>
                                <div style={{ background: 'rgba(0,0,0,0.2)', border: '1px solid rgba(255,255,255,0.05)', borderRadius: '6px', padding: '1rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                    <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Previous Block Anchor:</span>
                                    <span style={{ fontFamily: 'monospace', fontSize: '0.8rem', color: 'var(--text-main)' }}>{alert.previous_hash || '00000000000000000000000000000000'}</span>
                                  </div>
                                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                    <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Runtime Validated Hash:</span>
                                    <span style={{ fontFamily: 'monospace', fontSize: '0.8rem', color: 'var(--success)', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                                      <Lock size={12} /> {alert.current_hash || 'Pending Validation...'}
                                    </span>
                                  </div>
                                </div>

                                {/* AI Threat Model Inference */}
                                <div style={{ marginTop: '1rem', background: 'linear-gradient(90deg, rgba(99, 102, 241, 0.1) 0%, rgba(14, 165, 233, 0.05) 100%)', border: '1px solid rgba(99, 102, 241, 0.3)', borderRadius: '6px', padding: '0.75rem 1rem', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                    <Sparkles size={16} color="var(--secondary)" />
                                    <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-main)' }}>AI Anomaly Score</span>
                                  </div>
                                  <div style={{ display: 'flex', alignItems: 'baseline', gap: '0.25rem' }}>
                                    <span style={{ fontSize: '1.25rem', fontWeight: 800, color: getAiThreatScore(alert).score > 80 ? 'var(--danger)' : 'var(--warning)' }}>{getAiThreatScore(alert).score}</span>
                                    <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>/ 100</span>
                                  </div>
                                </div>
                              </div>

                              {isGuidedMode && isCritical && (
                                <motion.div
                                  initial={{ opacity: 0, height: 0 }}
                                  animate={{ opacity: 1, height: 'auto' }}
                                  className="critical-explanation"
                                  style={{ gridColumn: '1 / -1', marginTop: '-1rem', marginBottom: '1rem' }}
                                >
                                  <strong>Why this matters:</strong> This is a severe boundary breach. A critical alert like this usually indicates an active attempt to establish remote control over the hospital's network or extract massive amounts of protected data. Immediate isolation of the endpoint is recommended.
                                </motion.div>
                              )}
                            </div>

                            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', marginTop: 'auto', paddingTop: '1rem', borderTop: '1px solid rgba(255,255,255,0.05)' }}>

                              {/* AI Analysis Result Section */}
                              <AnimatePresence>
                                {aiAnalysis[alert.id] && (
                                  <motion.div
                                    initial={{ opacity: 0, height: 0 }}
                                    animate={{ opacity: 1, height: 'auto' }}
                                    className="ai-analysis-result"
                                    style={{
                                      background: 'rgba(99, 102, 241, 0.08)',
                                      border: '1px solid rgba(99, 102, 241, 0.2)',
                                      borderRadius: '8px',
                                      padding: '1.25rem',
                                      color: 'var(--text-main)',
                                      fontSize: '0.9rem',
                                      lineHeight: 1.6,
                                      marginTop: '0.5rem',
                                      marginBottom: '1rem'
                                    }}
                                  >
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem', color: 'var(--primary)' }}>
                                      <Sparkles size={16} />
                                      <span style={{ fontWeight: 600, letterSpacing: '0.5px' }}>AI Incident Analysis & Remediation</span>
                                    </div>
                                    <div style={{ whiteSpace: 'pre-wrap' }}>{aiAnalysis[alert.id]}</div>
                                  </motion.div>
                                )}
                              </AnimatePresence>

                              <div style={{ display: 'flex', gap: '0.75rem' }}>
                                <button
                                  onClick={() => handleDeepDive(alert)}
                                  disabled={isAnalyzing === alert.id}
                                  style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem', padding: '10px', background: 'rgba(14, 165, 233, 0.1)', border: '1px solid rgba(14, 165, 233, 0.3)', color: 'var(--primary)', borderRadius: '6px', cursor: isAnalyzing === alert.id ? 'wait' : 'pointer', fontSize: '0.9rem', fontWeight: 600, opacity: isAnalyzing === alert.id ? 0.7 : 1 }}
                                >
                                  {isAnalyzing === alert.id ? (
                                    <><Activity size={18} className="spin-icon" /> AI Investigating...</>
                                  ) : (
                                    <><Eye size={18} /> Investigate Deep Dive</>
                                  )}
                                </button>
                                <button style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem', padding: '10px', background: 'rgba(16, 185, 129, 0.1)', border: '1px solid rgba(16, 185, 129, 0.3)', color: 'var(--success)', borderRadius: '6px', cursor: 'pointer', fontSize: '0.9rem', fontWeight: 600 }}>
                                  <Shield size={18} /> Block Active Endpoint
                                </button>
                                <button style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '10px 16px', background: 'transparent', border: '1px solid var(--border-color)', color: 'var(--text-muted)', borderRadius: '6px', cursor: 'pointer', transition: 'all 0.2s', ':hover': { color: 'var(--danger)', borderColor: 'var(--danger-glow)' } }}>
                                  <Trash2 size={18} />
                                </button>
                              </div>
                            </div>
                          </motion.div>
                        )
                      })}
                    </AnimatePresence>
                  </div>
                </Panel>

              </div>
            } />

            <Route path="/map" element={
              <div style={{ width: '100%', height: 'calc(100vh - 100px)', padding: '0 1rem 1rem 1rem' }}>
                <GuidedBanner
                  show={isGuidedMode}
                  text="3D Spatial tracking allows SOC analysts to pinpoint the geographical origins of attacks in real-time."
                />

                <Panel title={
                  <div style={{ display: 'flex', alignItems: 'center', width: '100%', justifyContent: 'space-between' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '1.25rem' }}>
                      <ShieldAlert size={24} />
                      Global Threat Trajectory
                    </div>
                  </div>
                } style={{ width: '100%', height: '100%', padding: 0, overflow: 'hidden' }}>
                  <div style={{ flex: 1, minHeight: 0, position: 'relative', width: '100%' }}>
                    <LiveThreatMap alerts={alerts} />
                  </div>
                </Panel>
              </div>
            } />
            <Route path="/runtime" element={
              <div className="dashboard-grid" style={{ width: '100%' }}>
                <ExecutiveSummary alerts={alerts} />
                <StatCard title="Total Activities Monitored" value="1.24" unit="M" trend="+5.2%" isPositive={false} icon={Cpu} />
                <StatCard title="Threats Stopped" value="42" unit="" trend="-12%" isPositive={true} icon={ShieldAlert} />
                <StatCard title="Monitored Devices" value="3,842" unit="" trend="Stable" isPositive={true} icon={Server} />
                <StatCard title="Response Time" value="8" unit="ms" trend="-2ms" isPositive={true} icon={Activity} />
                <Panel title="Network & Telemetry Flow Streams" icon={Network} className="chart-panel-large" style={{ gridColumn: 'span 12', overflow: 'visible' }}>
                  <AreaChart width={850} height={300} data={trafficData} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
                    <defs>
                      <linearGradient id="colorIn" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="var(--primary)" stopOpacity={0.8} /><stop offset="95%" stopColor="var(--primary)" stopOpacity={0} /></linearGradient>
                      <linearGradient id="colorOut" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="var(--secondary)" stopOpacity={0.8} /><stop offset="95%" stopColor="var(--secondary)" stopOpacity={0} /></linearGradient>
                      <linearGradient id="colorBlock" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="var(--danger)" stopOpacity={0.8} /><stop offset="95%" stopColor="var(--danger)" stopOpacity={0} /></linearGradient>
                    </defs>
                    <XAxis dataKey="time" stroke="var(--border-color)" tick={{ fill: 'var(--text-muted)', fontSize: 12 }} />
                    <YAxis stroke="var(--border-color)" tick={{ fill: 'var(--text-muted)', fontSize: 12 }} />
                    <CartesianGrid strokeDasharray="3 3" stroke="var(--border-color)" vertical={false} />
                    <Tooltip contentStyle={{ backgroundColor: 'var(--bg-elevated)', borderColor: 'var(--border-color)', borderRadius: '8px' }} itemStyle={{ color: 'var(--text-main)' }} />
                    <Area type="monotone" dataKey="inbound" stroke="var(--primary)" fillOpacity={1} fill="url(#colorIn)" />
                    <Area type="monotone" dataKey="outbound" stroke="var(--secondary)" fillOpacity={1} fill="url(#colorOut)" />
                    <Area type="monotone" dataKey="blocked" stroke="var(--danger)" fillOpacity={1} fill="url(#colorBlock)" />
                  </AreaChart>
                </Panel>
              </div>
            } />
            <Route path="/network" element={
              <div className="dashboard-grid" style={{ width: '100%' }}>
                <Panel title="Network & Telemetry Flow Streams" icon={Network} className="chart-panel-large" style={{ gridColumn: 'span 12', overflow: 'visible' }}>
                  <AreaChart width={850} height={300} data={trafficData} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
                    <defs>
                      <linearGradient id="colorIn" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="var(--primary)" stopOpacity={0.8} /><stop offset="95%" stopColor="var(--primary)" stopOpacity={0} /></linearGradient>
                      <linearGradient id="colorOut" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="var(--secondary)" stopOpacity={0.8} /><stop offset="95%" stopColor="var(--secondary)" stopOpacity={0} /></linearGradient>
                      <linearGradient id="colorBlock" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="var(--danger)" stopOpacity={0.8} /><stop offset="95%" stopColor="var(--danger)" stopOpacity={0} /></linearGradient>
                    </defs>
                    <XAxis dataKey="time" stroke="var(--border-color)" tick={{ fill: 'var(--text-muted)', fontSize: 12 }} />
                    <YAxis stroke="var(--border-color)" tick={{ fill: 'var(--text-muted)', fontSize: 12 }} />
                    <CartesianGrid strokeDasharray="3 3" stroke="var(--border-color)" vertical={false} />
                    <Tooltip contentStyle={{ backgroundColor: 'var(--bg-elevated)', borderColor: 'var(--border-color)', borderRadius: '8px' }} itemStyle={{ color: 'var(--text-main)' }} />
                    <Area type="monotone" dataKey="inbound" stroke="var(--primary)" fillOpacity={1} fill="url(#colorIn)" />
                    <Area type="monotone" dataKey="outbound" stroke="var(--secondary)" fillOpacity={1} fill="url(#colorOut)" />
                    <Area type="monotone" dataKey="blocked" stroke="var(--danger)" fillOpacity={1} fill="url(#colorBlock)" />
                  </AreaChart>
                </Panel>
                <Panel title={<div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}><ShieldAlert size={18} />Current Threat Types Experienced</div>} className="network-graph" style={{ gridColumn: 'span 12' }}>
                  <div style={{ flex: 1, minHeight: 0 }}>
                    <ResponsiveContainer width="100%" height={400}>
                      <RadarChart cx="50%" cy="50%" outerRadius="70%" data={attackVectors}>
                        <PolarGrid stroke="var(--border-color)" />
                        <PolarAngleAxis dataKey="subject" tick={{ fill: 'var(--text-muted)', fontSize: 12 }} />
                        <PolarRadiusAxis angle={30} domain={[0, 150]} tick={false} axisLine={false} />
                        <Radar name="Threat Activity" dataKey="A" stroke="var(--danger)" fill="var(--danger)" fillOpacity={0.4} />
                        <Tooltip contentStyle={{ backgroundColor: 'var(--bg-elevated)', borderColor: 'var(--border-color)', borderRadius: '8px' }} itemStyle={{ color: 'var(--text-main)' }} />
                      </RadarChart>
                    </ResponsiveContainer>
                  </div>
                </Panel>
              </div>
            } />
            <Route path="/assets" element={
              <div className="dashboard-grid" style={{ width: '100%' }}>
                <Panel title={<div style={{ display: 'flex', alignItems: 'center', width: '100%', justifyContent: 'space-between' }}><div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}><Database size={18} />System Health & Load</div></div>} className="threat-matrix" style={{ gridColumn: '1 / -1' }}>
                  <div style={{ overflowX: 'auto' }}>
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>Computer / Database Name</th>
                          <th>Network ID (IP)</th>
                          <th>Security Status</th>
                          <th>Processing Load</th>
                        </tr>
                      </thead>
                      <tbody>
                        {mockDevices.map((dev, idx) => (
                          <tr key={idx}>
                            <td style={{ fontWeight: 500, color: 'var(--text-main)' }}>{dev.host}</td>
                            <td style={{ fontFamily: 'monospace', color: 'var(--text-muted)' }}>{dev.ip}</td>
                            <td>
                              {dev.alerts > 0 ? (
                                <span className={`badge ${dev.alerts > 1 ? 'badge-critical' : 'badge-high'}`}>
                                  <AlertTriangle size={12} /> Exceeds Baseline
                                </span>
                              ) : (
                                <span className="badge" style={{ backgroundColor: 'rgba(16, 185, 129, 0.15)', color: '#6ee7b7', border: '1px solid rgba(16,185,129,0.3)' }}>
                                  <Lock size={12} /> Secure
                                </span>
                              )}
                            </td>
                            <td>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                <span style={{ fontSize: '0.8rem', color: parseInt(dev.load) > 80 ? 'var(--warning)' : 'var(--text-muted)' }}>{dev.load}</span>
                                <div style={{ flex: 1, height: '4px', background: 'rgba(255,255,255,0.1)', borderRadius: '2px' }}>
                                  <div style={{ width: dev.load, height: '100%', background: parseInt(dev.load) > 80 ? 'var(--warning)' : 'var(--primary)', borderRadius: '2px' }}></div>
                                </div>
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </Panel>
              </div>
            } />
            <Route path="/compliance" element={
              <div className="dashboard-grid" style={{ width: '100%' }}>
                <Panel title={<div style={{ display: 'flex', alignItems: 'center', width: '100%', justifyContent: 'space-between' }}><div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}><FileCode size={18} />Secure Digital Paper Trail</div></div>} className="compliance-panel" style={{ gridColumn: '1 / -1', minHeight: '80vh' }}>
                  <div className="filter-bar">
                    <div className="search-wrapper">
                      <Search size={18} className="search-icon" />
                      <input type="text" placeholder="Search logs by IP, title, or system..." value={searchTerm} onChange={(e) => setSearchTerm(e.target.value)} className="search-input" />
                    </div>
                    <div className="filter-wrapper">
                      <Filter size={18} className="filter-icon" />
                      <select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)} className="severity-select">
                        <option value="ALL">All Severities</option>
                        <option value="CRITICAL">Critical Only</option>
                        <option value="HIGH">High Only</option>
                        <option value="MEDIUM">Medium Only</option>
                        <option value="INFO">Info Only</option>
                      </select>
                    </div>
                  </div>
                  <div style={{ overflowX: 'auto', maxHeight: 'none' }}>
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>Time Logged</th>
                          <th>Where It Happened</th>
                          <th>Action Taken</th>
                          <th>Technical Details</th>
                          <th>Security Signature</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredAlerts.length === 0 ? (
                          <tr>
                            <td colSpan="5" style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>
                              No compliance logs match the current search filters.
                            </td>
                          </tr>
                        ) : filteredAlerts.map((log) => (
                          <tr key={log.id} style={{ borderBottom: '1px solid var(--border-color)' }}>
                            <td style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>{log.time}</td>
                            <td><span className="badge" style={{ backgroundColor: 'var(--bg-hover)', color: 'var(--text-main)', border: '1px solid var(--border-color)' }}>{log.source || 'SYS'}</span></td>
                            <td style={{ fontWeight: 500, color: 'var(--text-main)', fontSize: '0.9rem' }}>{log.title || log.type}</td>
                            <td style={{ fontFamily: 'monospace', fontSize: '0.75rem', color: 'var(--text-muted)', maxWidth: '250px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={log.desc}>{log.desc}</td>
                            <td>
                              <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', fontFamily: 'monospace', fontSize: '0.7rem' }}>
                                <span title="Previous Block Anchor" style={{ color: 'var(--text-muted)' }}>Prev: {log.previous_hash ? `${log.previous_hash.substring(0, 16)}...` : 'Legacy Entry'}</span>
                                <span title="Validated Hash" style={{ color: '#10b981' }}>Curr: <Lock size={10} style={{ display: 'inline', verticalAlign: 'middle', marginTop: '-2px' }} /> {log.current_hash ? `${log.current_hash.substring(0, 16)}...` : ''}</span>
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </Panel>
              </div>
            } />
            <Route path="/config" element={
              <div className="dashboard-grid" style={{ width: '100%' }}>
                <Panel title={<div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}><Server size={18} />System Configuration</div>} style={{ gridColumn: '1 / -1' }}>
                  <div style={{ padding: '2rem', color: 'var(--text-muted)' }}>
                    <p>System configuration options are currently locked by the administrator.</p>
                    <div style={{ marginTop: '1rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '1rem', background: 'rgba(255,255,255,0.05)', borderRadius: '8px' }}>
                        <div>
                          <strong style={{ color: 'var(--text-main)', display: 'block' }}>Strict Deep Packet Inspection</strong>
                          <span style={{ fontSize: '0.85rem' }}>Toggles intense scanning of all inbound and outbound traffic.</span>
                        </div>
                        <div style={{ width: '40px', height: '24px', background: 'var(--primary)', borderRadius: '12px', position: 'relative' }}>
                          <div style={{ width: '20px', height: '20px', background: 'white', borderRadius: '50%', position: 'absolute', right: '2px', top: '2px' }}></div>
                        </div>
                      </div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '1rem', background: 'rgba(255,255,255,0.05)', borderRadius: '8px' }}>
                        <div>
                          <strong style={{ color: 'var(--text-main)', display: 'block' }}>Automated Threat Blocking</strong>
                          <span style={{ fontSize: '0.85rem' }}>System automatically neutralizes high-confidence threats.</span>
                        </div>
                        <div style={{ width: '40px', height: '24px', background: 'var(--primary)', borderRadius: '12px', position: 'relative' }}>
                          <div style={{ width: '20px', height: '20px', background: 'white', borderRadius: '50%', position: 'absolute', right: '2px', top: '2px' }}></div>
                        </div>
                      </div>
                    </div>
                  </div>
                </Panel>
              </div>
            } />
          </Routes>
        </main>
      </div>
    </ErrorBoundary>
  );
}

export default App;
