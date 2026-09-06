const express = require('express');
const multer = require('multer');
const pino = require('pino');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const os = require('os');
const { default: makeWASocket, Browsers, delay, useMultiFileAuthState, makeCacheableSignalKeyStore } = require("@whiskeysockets/baileys");
const bodyParser = require('body-parser');
const WebSocket = require('ws');
const http = require('http');
const cors = require('cors');

const app = express();
const upload = multer({ storage: multer.memoryStorage() });
const server = http.createServer(app);
const wss = new WebSocket.Server({ server, path: '/ws' });

const activeSessions = new Map();
const sessionLogs = new Map();
const sessionConnections = new Map();
const sessionSocks = new Map();
const sessionIntervals = new Map();

// ======================
// 🔑 KEY APPROVAL SYSTEM
// ======================
const keysFilePath = path.join(__dirname, 'api_keys.json');

function loadKeys() {
    try {
        if (fs.existsSync(keysFilePath)) {
            return JSON.parse(fs.readFileSync(keysFilePath, 'utf-8'));
        }
    } catch (e) {
        console.error('[KEYS] Load error:', e.message);
    }
    return { keys: [] };
}

function saveKeys(data) {
    fs.writeFileSync(keysFilePath, JSON.stringify(data, null, 2));
}

function generateKey() {
    return 'KEY-' + crypto.randomBytes(16).toString('hex').toUpperCase();
}

// Admin password (change this!)
const ADMIN_PASSWORD = process.env.ADMIN_PASS || 'admin123';

// Middleware
app.use(cors());
app.use(bodyParser.urlencoded({ extended: true, limit: '100mb' }));
app.use(bodyParser.json({ limit: '100mb' }));
app.use(bodyParser.raw({ limit: '100mb' }));
app.use(express.static('public'));

const sessionsDir = path.join(__dirname, 'sessions');
if (!fs.existsSync(sessionsDir)) {
    fs.mkdirSync(sessionsDir, { recursive: true });
}

// ======================
// 📊 SERVER MONITOR DATA
// ======================
const SERVER_START_TIME = new Date();

function getServerMonitor() {
    const cpus = os.cpus();
    const totalMem = os.totalmem();
    const freeMem = os.freemem();
    const usedMem = totalMem - freeMem;
    const memUsage = process.memoryUsage();

    // CPU usage calculation
    let cpuLoad = 0;
    cpus.forEach(cpu => {
        const total = Object.values(cpu.times).reduce((a, b) => a + b, 0);
        const idle = cpu.times.idle;
        cpuLoad += ((total - idle) / total) * 100;
    });
    cpuLoad = (cpuLoad / cpus.length).toFixed(1);

    const uptimeSec = process.uptime();
    const days = Math.floor(uptimeSec / 86400);
    const hours = Math.floor((uptimeSec % 86400) / 3600);
    const minutes = Math.floor((uptimeSec % 3600) / 60);
    const seconds = Math.floor(uptimeSec % 60);

    return {
        cpu: {
            usage: cpuLoad + '%',
            cores: cpus.length,
            model: cpus[0]?.model || 'Unknown'
        },
        ram: {
            total: (totalMem / 1024 / 1024 / 1024).toFixed(2) + ' GB',
            used: (usedMem / 1024 / 1024 / 1024).toFixed(2) + ' GB',
            free: (freeMem / 1024 / 1024 / 1024).toFixed(2) + ' GB',
            processHeap: Math.round(memUsage.heapUsed / 1024 / 1024) + ' MB',
            processRSS: Math.round(memUsage.rss / 1024 / 1024) + ' MB'
        },
        uptime: {
            days,
            hours,
            minutes,
            seconds,
            full: `${days}d ${hours}h ${minutes}m ${seconds}s`
        },
        startTime: SERVER_START_TIME.toISOString(),
        platform: os.platform(),
        hostname: os.hostname(),
        nodeVersion: process.version,
        activeSessions: activeSessions.size
    };
}

// ======================
// 🔑 KEY MIDDLEWARE
// ======================
function requireApprovedKey(req, res, next) {
    const apiKey = req.headers['x-api-key'] || req.body?.apiKey || req.query?.apiKey;
    if (!apiKey) {
        return res.status(401).json({ success: false, message: 'API Key required. Header: x-api-key' });
    }
    const keysData = loadKeys();
    const keyEntry = keysData.keys.find(k => k.key === apiKey);
    if (!keyEntry) {
        return res.status(401).json({ success: false, message: 'Invalid API Key' });
    }
    if (keyEntry.status !== 'approved') {
        return res.status(403).json({ success: false, message: `Key is ${keyEntry.status}. Wait for approval.` });
    }
    req.apiKeyInfo = keyEntry;
    next();
}

// ======================
// WEBSOCKET MANAGEMENT
// ======================
wss.on('connection', (ws) => {
    console.log('[WS] New client connected');
    ws.on('message', (message) => {
        try {
            const data = JSON.parse(message);
            if (data.type === 'subscribe') {
                ws.sessionKey = data.sessionKey;
                if (sessionLogs.has(data.sessionKey)) {
                    ws.send(JSON.stringify({ type: 'initial_logs', data: sessionLogs.get(data.sessionKey) }));
                }
            }
            if (data.type === 'ping') {
                ws.send(JSON.stringify({ type: 'pong' }));
            }
        } catch (error) {
            console.error('[WS] Message error:', error);
        }
    });
    ws.on('close', () => console.log('[WS] Client disconnected'));
    ws.on('error', (err) => console.error('[WS] Error:', err));
});

function broadcastLogs(sessionKey, message) {
    if (!sessionLogs.has(sessionKey)) sessionLogs.set(sessionKey, []);
    const logs = sessionLogs.get(sessionKey);
    const timestamp = new Date().toLocaleTimeString('en-US', { hour12: true, hour: '2-digit', minute: '2-digit', second: '2-digit' });
    const fullMessage = `[${timestamp}] ${message}`;
    logs.push(fullMessage);
    if (logs.length > 2000) logs.shift();

    wss.clients.forEach((client) => {
        if (client.readyState === WebSocket.OPEN && client.sessionKey === sessionKey) {
            try {
                client.send(JSON.stringify({ type: 'log', data: fullMessage, timestamp: Date.now() }));
            } catch (err) {
                console.error('[WS] Broadcast error:', err.message);
            }
        }
    });
}

// ======================
// 🔑 KEY API ENDPOINTS
// ======================

// Generate new key (public)
app.post('/key/generate', (req, res) => {
    const { ownerName } = req.body;
    const newKey = generateKey();
    const keysData = loadKeys();
    const entry = {
        key: newKey,
        owner: ownerName || 'Unknown',
        status: 'pending',
        createdAt: new Date().toISOString(),
        approvedAt: null,
        usedCount: 0
    };
    keysData.keys.push(entry);
    saveKeys(keysData);
    res.json({
        success: true,
        message: 'Key generated! Wait for admin approval.',
        key: newKey,
        status: 'pending'
    });
});

// Check key status (public)
app.get('/key/status/:key', (req, res) => {
    const keysData = loadKeys();
    const entry = keysData.keys.find(k => k.key === req.params.key);
    if (!entry) return res.status(404).json({ success: false, message: 'Key not found' });
    res.json({ success: true, key: entry.key, status: entry.status, owner: entry.owner, createdAt: entry.createdAt });
});

// Admin: List all keys
app.get('/admin/keys', (req, res) => {
    const pass = req.headers['x-admin-pass'] || req.query.pass;
    if (pass !== ADMIN_PASSWORD) return res.status(401).json({ success: false, message: 'Wrong admin password' });
    const keysData = loadKeys();
    res.json({ success: true, total: keysData.keys.length, keys: keysData.keys });
});

// Admin: Approve key
app.post('/admin/key/approve', (req, res) => {
    const pass = req.headers['x-admin-pass'] || req.body?.pass;
    if (pass !== ADMIN_PASSWORD) return res.status(401).json({ success: false, message: 'Wrong admin password' });
    const { key } = req.body;
    const keysData = loadKeys();
    const entry = keysData.keys.find(k => k.key === key);
    if (!entry) return res.status(404).json({ success: false, message: 'Key not found' });
    entry.status = 'approved';
    entry.approvedAt = new Date().toISOString();
    saveKeys(keysData);
    res.json({ success: true, message: `Key ${key} approved!`, key: entry });
});

// Admin: Reject key
app.post('/admin/key/reject', (req, res) => {
    const pass = req.headers['x-admin-pass'] || req.body?.pass;
    if (pass !== ADMIN_PASSWORD) return res.status(401).json({ success: false, message: 'Wrong admin password' });
    const { key } = req.body;
    const keysData = loadKeys();
    const entry = keysData.keys.find(k => k.key === key);
    if (!entry) return res.status(404).json({ success: false, message: 'Key not found' });
    entry.status = 'rejected';
    saveKeys(keysData);
    res.json({ success: true, message: `Key ${key} rejected!` });
});

// Admin: Delete key
app.post('/admin/key/delete', (req, res) => {
    const pass = req.headers['x-admin-pass'] || req.body?.pass;
    if (pass !== ADMIN_PASSWORD) return res.status(401).json({ success: false, message: 'Wrong admin password' });
    const { key } = req.body;
    const keysData = loadKeys();
    keysData.keys = keysData.keys.filter(k => k.key !== key);
    saveKeys(keysData);
    res.json({ success: true, message: `Key ${key} deleted!` });
});

// ======================
// API ENDPOINTS (KEY PROTECTED)
// ======================

app.post('/send', requireApprovedKey, upload.single('sms'), async (req, res) => {
    try {
        const { creds, targetNumber, targetType, timeDelay, hatersName, tagAll } = req.body;
        const smsFile = req.file;

        if (!creds) return res.status(400).json({ success: false, message: 'Credentials are required' });
        if (!targetNumber) return res.status(400).json({ success: false, message: 'Target number is required' });
        if (!smsFile) return res.status(400).json({ success: false, message: 'SMS file is required' });

        const sessionKey = crypto.randomBytes(8).toString('hex');
        const sessionDir = path.join(sessionsDir, sessionKey);
        if (!fs.existsSync(sessionDir)) fs.mkdirSync(sessionDir, { recursive: true });

        try {
            const credsJson = Buffer.from(creds, 'base64').toString('utf-8');
            const parsedCreds = JSON.parse(credsJson);
            fs.writeFileSync(path.join(sessionDir, 'creds.json'), JSON.stringify(parsedCreds, null, 2));
        } catch (error) {
            fs.rmSync(sessionDir, { recursive: true, force: true });
            return res.status(400).json({ success: false, message: 'Invalid credentials format' });
        }

        const fileContent = smsFile.buffer.toString('utf-8');
        const messages = fileContent.split('\n').map(line => {
            const trimmed = line.trim();
            if (!trimmed) return null;
            return `${hatersName || ''} ${trimmed}`.trim();
        }).filter(msg => msg !== null && msg.length > 0);

        if (messages.length === 0) {
            fs.rmSync(sessionDir, { recursive: true, force: true });
            return res.status(400).json({ success: false, message: 'No valid messages found in SMS file' });
        }

        const doTagAll = tagAll === 'true' || tagAll === '1' || tagAll === true;

        activeSessions.set(sessionKey, {
            running: true,
            targetNumber,
            targetType: targetType || 'inbox',
            startTime: new Date(),
            sentCount: 0,
            failedCount: 0,
            lastActivity: new Date(),
            totalMessages: messages.length,
            paused: false,
            messageIndex: 0,
            credsPath: path.join(sessionDir, 'creds.json'),
            timeDelay: parseInt(timeDelay, 10) || 5,
            tagAll: doTagAll,
            apiKeyUsed: req.apiKeyInfo?.key
        });
        sessionLogs.set(sessionKey, []);

        broadcastLogs(sessionKey, '═══════════════════════════════════');
        broadcastLogs(sessionKey, '    🚀 SESSION STARTED SUCCESSFULLY');
        broadcastLogs(sessionKey, '═══════════════════════════════════');
        broadcastLogs(sessionKey, `🔑 API Key: ${req.apiKeyInfo?.key?.substring(0, 12)}...`);
        broadcastLogs(sessionKey, `📊 Total Messages: ${messages.length}`);
        broadcastLogs(sessionKey, `📱 Target Number: ${targetNumber}`);
        broadcastLogs(sessionKey, `📤 Type: ${targetType || 'inbox'}`);
        broadcastLogs(sessionKey, `🏷️ Tag All: ${doTagAll ? '✅ YES' : '❌ NO'}`);
        broadcastLogs(sessionKey, `⏱️  Delay: ${timeDelay}s per message`);
        broadcastLogs(sessionKey, `👤 Sender: ${hatersName || 'N/A'}`);
        broadcastLogs(sessionKey, '═══════════════════════════════════');
        broadcastLogs(sessionKey, '⏳ Initializing connection...');

        sendMessagesProcess(sessionKey, messages, path.join(sessionDir, 'creds.json'), targetNumber, targetType || 'inbox', parseInt(timeDelay, 10) * 1000, doTagAll)
            .catch(err => {
                console.error('[SEND ERROR]', err);
                const session = activeSessions.get(sessionKey);
                if (session) { session.running = false; activeSessions.set(sessionKey, session); }
                broadcastLogs(sessionKey, `❌ [FATAL ERROR] ${err.message}`);
            });

        res.json({ success: true, sessionKey, message: 'Session started successfully', totalMessages: messages.length });
    } catch (error) {
        console.error('[SEND ENDPOINT ERROR]', error);
        res.status(500).json({ success: false, message: `Server error: ${error.message}` });
    }
});

app.post('/stop', requireApprovedKey, (req, res) => {
    try {
        const { sessionKey } = req.body;
        if (!activeSessions.has(sessionKey)) return res.status(404).json({ success: false, message: 'Session not found' });
        const session = activeSessions.get(sessionKey);
        session.running = false;
        activeSessions.set(sessionKey, session);
        if (sessionIntervals.has(sessionKey)) { clearInterval(sessionIntervals.get(sessionKey)); sessionIntervals.delete(sessionKey); }
        if (sessionSocks.has(sessionKey)) {
            try { const sock = sessionSocks.get(sessionKey); if (sock && sock.end) sock.end(); } catch (err) { console.error('[STOP] Socket close error:', err); }
            sessionSocks.delete(sessionKey);
        }
        broadcastLogs(sessionKey, '⛔ [SYSTEM] Session stopped by user');
        res.json({ success: true, message: `Session ${sessionKey} stopped` });
    } catch (error) {
        res.status(500).json({ success: false, message: `Error: ${error.message}` });
    }
});

app.get('/status/:sessionKey', (req, res) => {
    try {
        const { sessionKey } = req.params;
        if (!activeSessions.has(sessionKey)) return res.status(404).json({ success: false, message: 'Session not found' });
        const session = activeSessions.get(sessionKey);
        const progress = session.totalMessages > 0 ? Math.round(((session.sentCount + session.failedCount) / session.totalMessages) * 100) : 0;
        const uptime = new Date() - new Date(session.startTime);
        const uptimeSeconds = Math.floor(uptime / 1000);
        res.json({
            success: true, sessionKey, running: session.running,
            targetNumber: session.targetNumber, targetType: session.targetType,
            sentCount: session.sentCount, failedCount: session.failedCount,
            totalMessages: session.totalMessages, progress: progress + '%',
            lastActivity: session.lastActivity,
            uptime: `${Math.floor(uptimeSeconds / 60)}m ${uptimeSeconds % 60}s`,
            startTime: session.startTime, timeDelay: session.timeDelay,
            tagAll: session.tagAll
        });
    } catch (error) {
        res.status(500).json({ success: false, message: `Error: ${error.message}` });
    }
});

app.get('/logs/:sessionKey', (req, res) => {
    try {
        const { sessionKey } = req.params;
        if (!sessionLogs.has(sessionKey)) return res.status(404).json({ success: false, message: 'Session logs not found' });
        const logs = sessionLogs.get(sessionKey);
        res.json({ success: true, sessionKey, logs, total: logs.length });
    } catch (error) {
        res.status(500).json({ success: false, message: `Error: ${error.message}` });
    }
});

app.get('/sessions', (req, res) => {
    try {
        const sessions = [];
        activeSessions.forEach((session, key) => {
            const progress = session.totalMessages > 0 ? Math.round(((session.sentCount + session.failedCount) / session.totalMessages) * 100) : 0;
            sessions.push({ sessionKey: key, running: session.running, targetNumber: session.targetNumber, sentCount: session.sentCount, failedCount: session.failedCount, totalMessages: session.totalMessages, progress: progress + '%', startTime: session.startTime });
        });
        res.json({ success: true, activeSessions: sessions.length, sessions });
    } catch (error) {
        res.status(500).json({ success: false, message: `Error: ${error.message}` });
    }
});

// ======================
// 📊 MONITOR ENDPOINT
// ======================
app.get('/monitor', (req, res) => {
    try {
        res.json({ success: true, ...getServerMonitor() });
    } catch (error) {
        res.status(500).json({ success: false, message: `Error: ${error.message}` });
    }
});

app.get('/health', (req, res) => {
    try {
        const mon = getServerMonitor();
        res.json({
            status: 'OK',
            activeSessions: mon.activeSessions,
            memoryUsage: { heapUsed: mon.ram.processHeap, heapTotal: mon.ram.processRSS },
            uptime: mon.uptime.full,
            cpu: mon.cpu.usage,
            startTime: mon.startTime,
            timestamp: new Date()
        });
    } catch (error) {
        res.status(500).json({ success: false, message: `Error: ${error.message}` });
    }
});

// ======================
// 🖥️ DASHBOARD (HTML)
// ======================
app.get('/', (req, res) => {
    const html = `<!DOCTYPE html>
<html lang="en">
<head>
<title>WhatsApp Sender - Full System</title>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;background:linear-gradient(135deg,#0f0c29,#302b63,#24243e);min-height:100vh;padding:15px;color:#e0e0e0}
.container{max-width:1400px;margin:0 auto}
.header{background:rgba(255,255,255,0.05);backdrop-filter:blur(10px);padding:20px;border-radius:15px;margin-bottom:20px;border:1px solid rgba(255,255,255,0.1)}
.header h1{color:#fff;font-size:24px;margin-bottom:5px}
.header p{color:#888;font-size:13px}

/* Monitor Cards */
.monitor-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-bottom:20px}
.mon-card{background:rgba(255,255,255,0.05);backdrop-filter:blur(10px);padding:15px;border-radius:12px;border:1px solid rgba(255,255,255,0.08);text-align:center}
.mon-card .label{font-size:11px;color:#888;text-transform:uppercase;letter-spacing:1px;margin-bottom:5px}
.mon-card .value{font-size:22px;font-weight:700;color:#00ff88}
.mon-card .sub{font-size:11px;color:#666;margin-top:3px}
.mon-card.cpu .value{color:#ff6b6b}
.mon-card.ram .value{color:#ffd93d}
.mon-card.uptime .value{color:#6bcbff}
.mon-card.sessions .value{color:#c084fc}

.content{display:grid;grid-template-columns:1fr 1fr;gap:20px}
.card{background:rgba(255,255,255,0.05);backdrop-filter:blur(10px);padding:20px;border-radius:15px;border:1px solid rgba(255,255,255,0.08)}
.card h2{color:#fff;margin-bottom:15px;font-size:16px;display:flex;align-items:center;gap:8px}
.form-group{margin-bottom:12px}
label{display:block;margin-bottom:4px;color:#aaa;font-size:13px;font-weight:500}
input,textarea,select{width:100%;padding:10px;background:rgba(255,255,255,0.08);border:1px solid rgba(255,255,255,0.15);border-radius:8px;font-size:13px;color:#fff;font-family:inherit}
input:focus,textarea:focus,select:focus{outline:none;border-color:#667eea;box-shadow:0 0 0 3px rgba(102,126,234,0.2)}
textarea{resize:vertical;min-height:80px}
select option{background:#1a1a2e;color:#fff}
.checkbox-group{display:flex;align-items:center;gap:8px;padding:8px 0}
.checkbox-group input[type=checkbox]{width:auto;accent-color:#667eea}

button{width:100%;padding:12px;background:linear-gradient(135deg,#667eea,#764ba2);color:#fff;border:none;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer;transition:all 0.3s}
button:hover{transform:translateY(-2px);box-shadow:0 8px 20px rgba(102,126,234,0.4)}
button.danger{background:linear-gradient(135deg,#f44336,#e91e63)}
button.success{background:linear-gradient(135deg,#4caf50,#2e7d32)}
button.sm{padding:6px 12px;font-size:12px;width:auto;border-radius:6px}

.logs-container{background:#0a0a0a;color:#0f0;padding:15px;border-radius:10px;font-family:'Courier New',monospace;font-size:11px;max-height:350px;overflow-y:auto;line-height:1.6;border:1px solid #222}
.sessions-list{max-height:350px;overflow-y:auto}
.session-item{background:rgba(255,255,255,0.05);padding:12px;margin-bottom:8px;border-radius:8px;border-left:3px solid #667eea}
.session-item p{margin:3px 0;color:#aaa;font-size:12px}
.session-item strong{color:#ddd}
.progress-bar{width:100%;height:6px;background:rgba(255,255,255,0.1);border-radius:10px;overflow:hidden;margin-top:6px}
.progress-fill{height:100%;background:linear-gradient(90deg,#667eea,#764ba2);transition:width 0.3s}

/* Key Panel */
.key-panel{margin-top:20px}
.key-item{display:flex;justify-content:space-between;align-items:center;background:rgba(255,255,255,0.05);padding:10px 15px;border-radius:8px;margin-bottom:8px;font-size:12px}
.key-item .key-text{font-family:monospace;color:#ffd93d;word-break:break-all}
.badge{padding:3px 8px;border-radius:20px;font-size:10px;font-weight:700;text-transform:uppercase}
.badge.pending{background:#ff980033;color:#ff9800}
.badge.approved{background:#4caf5033;color:#4caf50}
.badge.rejected{background:#f4433633;color:#f44336}
.btn-group{display:flex;gap:5px}

.success{color:#4caf50}.error{color:#f44336}.warning{color:#ff9800}.info{color:#2196f3}
.full-width{grid-column:1/-1}

@media(max-width:768px){.content{grid-template-columns:1fr}.monitor-grid{grid-template-columns:repeat(2,1fr)}}
::-webkit-scrollbar{width:6px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:#333;border-radius:3px}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>🚀 WhatsApp Message Sender</h1>
        <p>Key Approval System • @All Tag • Full Monitor</p>
    </div>

    <!-- 📊 MONITOR SECTION -->
    <div class="monitor-grid">
        <div class="mon-card cpu">
            <div class="label">CPU Usage</div>
            <div class="value" id="cpuUsage">--</div>
            <div class="sub" id="cpuCores">-- cores</div>
        </div>
        <div class="mon-card ram">
            <div class="label">RAM Usage</div>
            <div class="value" id="ramUsed">--</div>
            <div class="sub" id="ramDetail">Heap: --</div>
        </div>
        <div class="mon-card uptime">
            <div class="label">Server Uptime</div>
            <div class="value" id="uptimeVal">--</div>
            <div class="sub" id="startTime">Started: --</div>
        </div>
        <div class="mon-card sessions">
            <div class="label">Active Sessions</div>
            <div class="value" id="activeSessions">0</div>
            <div class="sub" id="nodeVer">Node: --</div>
        </div>
    </div>

    <div class="content">
        <!-- SEND FORM -->
        <div class="card">
            <h2>📤 Send Messages</h2>
            <form id="sendForm">
                <div class="form-group">
                    <label>🔑 API Key</label>
                    <input type="text" id="apiKey" placeholder="KEY-XXXXXXXX..." required>
                </div>
                <div class="form-group">
                    <label>Sender Name</label>
                    <input type="text" id="hatersName" placeholder="e.g., Bot">
                </div>
                <div class="form-group">
                    <label>Target Number</label>
                    <input type="text" id="targetNumber" placeholder="e.g., 923001234567" required>
                </div>
                <div class="form-group">
                    <label>Target Type</label>
                    <select id="targetType">
                        <option value="inbox">Personal Chat</option>
                        <option value="group">Group</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Delay (seconds)</label>
                    <input type="number" id="timeDelay" value="5" min="1" required>
                </div>
                <div class="form-group">
                    <div class="checkbox-group">
                        <input type="checkbox" id="tagAll" checked>
                        <label for="tagAll" style="margin:0;cursor:pointer">🏷️ Tag @All in every message (Group)</label>
                    </div>
                </div>
                <div class="form-group">
                    <label>Credentials (Base64)</label>
                    <textarea id="creds" placeholder="Paste base64 encoded creds..." required></textarea>
                </div>
                <div class="form-group">
                    <label>SMS File (.txt)</label>
                    <input type="file" id="smsFile" accept=".txt" required>
                </div>
                <button type="submit">🚀 Start Sending</button>
            </form>
        </div>

        <!-- SESSIONS -->
        <div class="card">
            <h2>📊 Active Sessions</h2>
            <div class="sessions-list" id="sessionsList">
                <p style="color:#666;text-align:center">No active sessions</p>
            </div>
        </div>

        <!-- LOGS -->
        <div class="card full-width">
            <h2>📋 Live Logs</h2>
            <div class="form-group">
                <input type="text" id="sessionKey" placeholder="Enter session key to view logs...">
            </div>
            <div class="logs-container" id="logsContainer">
                <div style="color:#555">Logs will appear here...</div>
            </div>
        </div>

        <!-- 🔑 KEY MANAGEMENT -->
        <div class="card full-width key-panel">
            <h2>🔑 Key Management</h2>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px">
                <div>
                    <h3 style="color:#aaa;font-size:14px;margin-bottom:10px">Generate New Key</h3>
                    <div class="form-group">
                        <input type="text" id="keyOwnerName" placeholder="Your name...">
                    </div>
                    <button onclick="generateNewKey()" class="sm">🔑 Generate Key</button>
                    <div id="generatedKeyResult" style="margin-top:10px;font-size:12px"></div>
                </div>
                <div>
                    <h3 style="color:#aaa;font-size:14px;margin-bottom:10px">Admin Panel</h3>
                    <div class="form-group">
                        <input type="password" id="adminPass" placeholder="Admin password...">
                    </div>
                    <button onclick="loadAdminKeys()" class="sm success">📋 Load Keys</button>
                    <div id="adminKeysList" style="margin-top:10px;max-height:200px;overflow-y:auto"></div>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
let ws = null;
let currentSessionKey = null;

function connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(protocol + '//' + window.location.host + '/ws');
    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        if (data.type === 'log') addLog(data.data);
        else if (data.type === 'initial_logs') {
            document.getElementById('logsContainer').innerHTML = '';
            data.data.forEach(log => addLog(log));
        }
    };
    ws.onclose = () => setTimeout(connectWebSocket, 3000);
}

function addLog(message) {
    const c = document.getElementById('logsContainer');
    const d = document.createElement('div');
    d.textContent = message;
    if (message.includes('SUCCESS') || message.includes('✓')) d.className = 'success';
    else if (message.includes('ERROR') || message.includes('FATAL') || message.includes('❌')) d.className = 'error';
    else if (message.includes('SYSTEM') || message.includes('RECONNECT') || message.includes('⏳')) d.className = 'info';
    c.appendChild(d);
    c.scrollTop = c.scrollHeight;
}

document.getElementById('sessionKey').addEventListener('change', (e) => {
    currentSessionKey = e.target.value;
    if (currentSessionKey && ws?.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'subscribe', sessionKey: currentSessionKey }));
    }
});

document.getElementById('sendForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData();
    fd.append('apiKey', document.getElementById('apiKey').value);
    fd.append('hatersName', document.getElementById('hatersName').value);
    fd.append('targetNumber', document.getElementById('targetNumber').value);
    fd.append('targetType', document.getElementById('targetType').value);
    fd.append('timeDelay', document.getElementById('timeDelay').value);
    fd.append('tagAll', document.getElementById('tagAll').checked);
    fd.append('creds', document.getElementById('creds').value);
    fd.append('sms', document.getElementById('smsFile').files[0]);
    try {
        const r = await fetch('/send', { method: 'POST', body: fd });
        const res = await r.json();
        if (res.success) {
            alert('✅ Session started! Key: ' + res.sessionKey);
            document.getElementById('sessionKey').value = res.sessionKey;
            document.getElementById('sessionKey').dispatchEvent(new Event('change'));
            document.getElementById('sendForm').reset();
        } else alert('❌ ' + res.message);
    } catch (err) { alert('Error: ' + err.message); }
});

async function updateDashboard() {
    try {
        const hr = await (await fetch('/monitor')).json();
        document.getElementById('cpuUsage').textContent = hr.cpu.usage;
        document.getElementById('cpuCores').textContent = hr.cpu.cores + ' cores';
        document.getElementById('ramUsed').textContent = hr.ram.used;
        document.getElementById('ramDetail').textContent = 'Heap: ' + hr.ram.processHeap;
        document.getElementById('uptimeVal').textContent = hr.uptime.full;
        document.getElementById('startTime').textContent = 'Started: ' + new Date(hr.startTime).toLocaleString();
        document.getElementById('activeSessions').textContent = hr.activeSessions;
        document.getElementById('nodeVer').textContent = 'Node: ' + hr.nodeVersion;

        const sr = await (await fetch('/sessions')).json();
        const sl = document.getElementById('sessionsList');
        if (sr.sessions.length === 0) sl.innerHTML = '<p style="color:#666;text-align:center">No active sessions</p>';
        else sl.innerHTML = sr.sessions.map(s => \`
            <div class="session-item">
                <p><strong>Key:</strong> \${s.sessionKey}</p>
                <p><strong>Target:</strong> \${s.targetNumber}</p>
                <p><strong>Progress:</strong> \${s.sentCount + s.failedCount}/\${s.totalMessages}</p>
                <div class="progress-bar"><div class="progress-fill" style="width:\${s.progress}"></div></div>
                <p style="margin-top:6px"><strong>Status:</strong> <span class="\${s.running ? 'info' : 'warning'}">\${s.running ? '🟢 Running' : '🟡 Stopped'}</span></p>
            </div>
        \`).join('');
    } catch (e) { console.error('Dashboard error:', e); }
}

async function generateNewKey() {
    const name = document.getElementById('keyOwnerName').value || 'User';
    try {
        const r = await fetch('/key/generate', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ownerName: name }) });
        const res = await r.json();
        document.getElementById('generatedKeyResult').innerHTML = res.success
            ? '<div style="color:#4caf50">✅ Key: <code style="background:#222;padding:4px 8px;border-radius:4px;word-break:break-all">' + res.key + '</code><br><span style="color:#ff9800">⏳ Status: Pending approval</span></div>'
            : '<div style="color:#f44336">❌ ' + res.message + '</div>';
    } catch (e) { document.getElementById('generatedKeyResult').innerHTML = '<div style="color:#f44336">Error: ' + e.message + '</div>'; }
}

async function loadAdminKeys() {
    const pass = document.getElementById('adminPass').value;
    try {
        const r = await fetch('/admin/keys', { headers: { 'x-admin-pass': pass } });
        const res = await r.json();
        if (!res.success) { document.getElementById('adminKeysList').innerHTML = '<div style="color:#f44336;font-size:12px">❌ ' + res.message + '</div>'; return; }
        if (res.keys.length === 0) { document.getElementById('adminKeysList').innerHTML = '<div style="color:#666;font-size:12px">No keys found</div>'; return; }
        document.getElementById('adminKeysList').innerHTML = res.keys.map(k => \`
            <div class="key-item">
                <div>
                    <div class="key-text">\${k.key}</div>
                    <div style="color:#888;font-size:10px">\${k.owner} • \${new Date(k.createdAt).toLocaleDateString()}</div>
                </div>
                <span class="badge \${k.status}">\${k.status}</span>
                <div class="btn-group">
                    <button class="sm success" onclick="approveKey('\${k.key}')">✅</button>
                    <button class="sm danger" onclick="rejectKey('\${k.key}')">❌</button>
                </div>
            </div>
        \`).join('');
    } catch (e) { document.getElementById('adminKeysList').innerHTML = '<div style="color:#f44336;font-size:12px">Error: ' + e.message + '</div>'; }
}

async function approveKey(key) {
    const pass = document.getElementById('adminPass').value;
    await fetch('/admin/key/approve', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ key, pass }) });
    loadAdminKeys();
}

async function rejectKey(key) {
    const pass = document.getElementById('adminPass').value;
    await fetch('/admin/key/reject', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ key, pass }) });
    loadAdminKeys();
}

connectWebSocket();
updateDashboard();
setInterval(updateDashboard, 3000);
</script>
</body>
</html>`;
    res.send(html);
});

// ======================
// MESSAGE SENDING PROCESS (WITH @ALL TAG)
// ======================
async function sendMessagesProcess(sessionKey, messages, credsPath, targetNumber, targetType, delayMs, tagAll) {
    let sock = null;
    let reconnectAttempts = 0;
    const maxReconnectAttempts = 50;
    let messageIndex = 0;
    const session = activeSessions.get(sessionKey);
    if (!session) return;

    const connectAndSend = async () => {
        try {
            if (!activeSessions.get(sessionKey)?.running) { broadcastLogs(sessionKey, '⛔ Session terminated'); cleanup(); return; }

            const { state, saveCreds } = await useMultiFileAuthState(path.dirname(credsPath));
            sock = makeWASocket({
                logger: pino({ level: 'silent' }),
                printQRInTerminal: false,
                browser: Browsers.windows('Chrome'),
                auth: { creds: state.creds, keys: makeCacheableSignalKeyStore(state.keys, pino({ level: 'silent' })) },
                connectTimeoutMs: 60000,
                defaultQueryTimeoutMs: 60000,
                keepAliveIntervalMs: 30000,
                emitOwnEvents: true,
                syncFullHistory: false,
                maxMsgsInMemory: 100,
                fireInitQueries: true,
                markOnlineAfterMs: 15000,
            });
            sessionSocks.set(sessionKey, sock);

            sock.ev.on('connection.update', async (update) => {
                const { connection, lastDisconnect, qr } = update;
                if (qr) broadcastLogs(sessionKey, '📱 [QR] Please scan QR code');

                if (connection === 'open') {
                    reconnectAttempts = 0;
                    broadcastLogs(sessionKey, '✓ [CONNECTED] WhatsApp connected');

                    // Get group participants for @all tag
                    let groupParticipants = [];
                    if (tagAll && targetType === 'group') {
                        try {
                            const groupMeta = await sock.groupMetadata(targetNumber + '@g.us');
                            groupParticipants = groupMeta.participants.map(p => p.id);
                            broadcastLogs(sessionKey, `🏷️ [TAG] Found ${groupParticipants.length} participants for @all`);
                        } catch (e) {
                            broadcastLogs(sessionKey, `⚠️ [TAG] Could not fetch participants: ${e.message}`);
                        }
                    }

                    while (messageIndex < messages.length && activeSessions.get(sessionKey)?.running) {
                        if (!sock || !sock.user) { broadcastLogs(sessionKey, '⚠️ Socket disconnected'); break; }

                        const message = messages[messageIndex];
                        try {
                            const recipient = targetType === 'inbox'
                                ? targetNumber + '@s.whatsapp.net'
                                : targetNumber + '@g.us';

                            const msgOptions = { text: message, linkPreview: false };

                            // Add @all mentions
                            if (tagAll && targetType === 'group' && groupParticipants.length > 0) {
                                msgOptions.mentions = groupParticipants;
                                // Add @all text prefix
                                const mentionTags = groupParticipants.map(jid => '@' + jid.split('@')[0]).join(' ');
                                msgOptions.text = mentionTags + '\n\n' + message;
                            }

                            await sock.sendMessage(recipient, msgOptions);
                            messageIndex++;

                            const sess = activeSessions.get(sessionKey);
                            if (sess) { sess.sentCount = messageIndex; sess.lastActivity = new Date(); activeSessions.set(sessionKey, sess); }

                            broadcastLogs(sessionKey, `✓ [${messageIndex}/${messages.length}] ${message.substring(0, 50)}...`);
                            await delay(delayMs + Math.random() * 3000);
                        } catch (sendError) {
                            const sess = activeSessions.get(sessionKey);
                            if (sess) { sess.failedCount++; sess.lastActivity = new Date(); activeSessions.set(sessionKey, sess); }
                            broadcastLogs(sessionKey, `✗ [${messageIndex + 1}/${messages.length}] Failed: ${sendError.message}`);
                            if (sendError.message.includes('not-authorized') || sendError.message.includes('401')) {
                                broadcastLogs(sessionKey, '❌ [AUTH ERROR] Credentials invalid');
                                activeSessions.get(sessionKey).running = false;
                                cleanup(); return;
                            }
                            await delay(10000);
                        }
                    }

                    if (messageIndex >= messages.length && activeSessions.get(sessionKey)?.running) {
                        broadcastLogs(sessionKey, '═══════════════════════════════════');
                        broadcastLogs(sessionKey, '✓ [COMPLETE] All messages sent!');
                        broadcastLogs(sessionKey, `📊 Total: ${messages.length} | Sent: ${messageIndex} | Failed: ${activeSessions.get(sessionKey).failedCount}`);
                        broadcastLogs(sessionKey, '═══════════════════════════════════');
                        const sess = activeSessions.get(sessionKey);
                        if (sess) sess.running = false;
                        await delay(5000);
                        cleanup();
                    }
                } else if (connection === 'close') {
                    const shouldReconnect = lastDisconnect?.error?.output?.statusCode !== 401;
                    if (shouldReconnect && activeSessions.get(sessionKey)?.running && messageIndex < messages.length) {
                        if (reconnectAttempts < maxReconnectAttempts) {
                            reconnectAttempts++;
                            broadcastLogs(sessionKey, `🔄 [RECONNECT] Attempt ${reconnectAttempts}/${maxReconnectAttempts}`);
                            await delay(20000);
                            await connectAndSend();
                        } else {
                            broadcastLogs(sessionKey, '❌ Max reconnection attempts reached');
                            const sess = activeSessions.get(sessionKey);
                            if (sess) sess.running = false;
                            cleanup();
                        }
                    } else { broadcastLogs(sessionKey, '🛑 Connection closed'); cleanup(); }
                }
            });
            sock.ev.on('creds.update', saveCreds);
        } catch (error) {
            broadcastLogs(sessionKey, `⚠️ [ERROR] ${error.message}`);
            if (reconnectAttempts < maxReconnectAttempts && activeSessions.get(sessionKey)?.running) {
                reconnectAttempts++;
                await delay(30000);
                await connectAndSend();
            } else {
                const sess = activeSessions.get(sessionKey);
                if (sess) sess.running = false;
                cleanup();
            }
        }
    };

    const cleanup = () => {
        if (sock) try { sock.end(); } catch (err) { console.error('[CLEANUP]', err); }
        sessionSocks.delete(sessionKey);
        setTimeout(() => {
            const credsDir = path.dirname(credsPath);
            if (fs.existsSync(credsDir)) fs.rmSync(credsDir, { recursive: true, force: true });
        }, 1800000);
    };

    await connectAndSend();
}

// ======================
// CLEANUP SCHEDULER
// ======================
setInterval(() => {
    const now = new Date();
    const toClean = [];
    activeSessions.forEach((session, key) => {
        if (!session.running && (now - new Date(session.lastActivity)) > 10800000) toClean.push(key);
    });
    toClean.forEach(key => {
        const dir = path.join(sessionsDir, key);
        if (fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true });
        activeSessions.delete(key); sessionLogs.delete(key); sessionSocks.delete(key); sessionIntervals.delete(key);
    });
}, 600000);

// ======================
// START SERVER
// ======================
const PORT = process.env.PORT || 20359;
server.listen(PORT, () => {
    console.log(`
╔═══════════════════════════════════════════════╗
║  🚀 WhatsApp Message Sender - Full System     ║
║  🔑 Key Approval | 🏷️ @All Tag | 📊 Monitor  ║
║  Port: ${PORT}                                  ║
║  http://localhost:${PORT}                        ║
╚═══════════════════════════════════════════════╝
`);
});

process.on('uncaughtException', (err) => console.error('[UNCAUGHT]', err));
process.on('unhandledRejection', (reason) => console.error('[UNHANDLED]', reason));
process.on('SIGINT', () => {
    console.log('\n[SHUTDOWN] Closing...');
    activeSessions.forEach((_, key) => { if (sessionSocks.has(key)) try { sessionSocks.get(key).end(); } catch (e) {} });
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 10000);
});

module.exports = app;