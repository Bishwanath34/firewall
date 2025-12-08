const express = require('express');
const axios = require('axios');
const cors = require('cors');
const fs = require('fs');
const pem = require('pem');
const https = require('https');
const tlsFingerprint = require('read-tls-client-hello');

// Shared global logs
let auditLogs = [];

// Generate self-signed certs (one-time)
async function ensureCerts() {
  return new Promise((resolve, reject) => {
    if (fs.existsSync('cert.pem') && fs.existsSync('key.pem')) return resolve();
    pem.createCertificate({ days: 365, selfSigned: true, keyBits: 2048 }, (err, keys) => {
      if (err) return reject(err);
      fs.writeFileSync('key.pem', keys.serviceKey);
      fs.writeFileSync('cert.pem', keys.certificate);
      console.log('Generated TLS certs');
      resolve();
    });
  });
}

// Core functions
function buildContext(req) {
  return {
    ip: req.socket.remoteAddress,
    method: req.method,
    path: req.path,
    userAgent: req.headers['user-agent'] || 'unknown',
    timestamp: new Date().toISOString(),
    userId: req.headers['x-user-id'] || 'anonymous',
    role: req.headers['x-user-role'] || 'guest'
  };
}

async function checkRiskRule(ctx) {
  let risk = 0.0;
  const reasons = [];
  if (!ctx.userId || ctx.userId === 'anonymous') { risk += 0.15; reasons.push('no_user_id'); }
  if (ctx.path.startsWith('/admin')) { risk += 0.45; reasons.push('admin_path'); }
  if (ctx.path.startsWith('/admin') && ctx.role === 'guest') { risk += 0.25; reasons.push('guest_on_admin_path'); }
  if (ctx.path.startsWith('/honeypot')) { risk += 0.75; reasons.push('honeypot_path'); }
  const label = risk >= 0.7 ? 'high_risk' : risk >= 0.35 ? 'medium_risk' : 'normal';
  return { risk, label, reasons };
}

async function scoreWithML(ctx) {
  try {
    const res = await axios.post('http://localhost:5000/score', {
      method: ctx.method, path: ctx.path, role: ctx.role,
      userId: ctx.userId, userAgent: ctx.userAgent, risk_rule: ctx.risk_rule
    }, { validateStatus: () => true });
    return { ml_risk: res.data.ml_risk || 0.0, ml_label: res.data.ml_label || 'normal' };
  } catch (err) {
    console.error('ML service error:', err.message);
    return { ml_risk: 0.0, ml_label: 'normal' };
  }
}

const RBAC = {
  guest: { allow: ['/info'], deny: ['/admin', '/admin/secret', '/admin/*'] },
  user: { allow: ['/info', '/profile'], deny: ['/admin', '/admin/*'] },
  admin: { allow: ['*'], deny: [] }
};

function checkRBAC(role, pathReq) {
  const rules = RBAC[role] || RBAC.guest;
  if (pathReq.startsWith('/honeypot')) return false;
  if (rules.allow.includes('*')) return true;
  for (const d of rules.deny) {
    if (pathReq.startsWith(d.replace('*', ''))) return false;
  }
  for (const a of rules.allow) {
    if (pathReq.startsWith(a.replace('*', ''))) return true;
  }
  return false;
}

// TLS Inspection + Forwarding
async function inspectAndForward(req, res) {
  // if (!req.url.startsWith('/fw')) {
  //   return res.status(404).json({ error: 'Use /fw/* endpoints only' });
  // }

  const ctx = buildContext(req);
  const forwardPath = req.url.replace(/^\/fw/, '');
  const target = 'https://localhost:9001' + forwardPath; 

  // TLS DPI rules
  let tlsRisk = 0.0;
  const tlsReasons = [];

  // JA3 BOT SIGNALS (primary contributor)
  if (req.tlsFingerprint?.botScore) {
    tlsRisk += req.tlsFingerprint.botScore;  // Full botScore contribution
    tlsReasons.push(...req.tlsFingerprint.signals);
  }

  // Protocol downgrade detection
  if (req.headers['x-forwarded-proto'] !== 'https') {
    tlsRisk += 0.20;
    tlsReasons.push('protocol_downgrade');
  }

  // Weak cipher suites
  if (req.socket.getCipher && 
      (req.socket.getCipher().name.includes('RC4') || 
      req.socket.getCipher().name.includes('CBC') || 
      req.socket.getCipher().name.includes('3DES'))) {
    tlsRisk += 0.30;
    tlsReasons.push('weak_cipher_suite');
  }

  // Suspicious User-Agent patterns (additional signal)
  const ua = req.headers['user-agent'] || '';
  if ((ua.includes('curl') || ua.includes('wget') || ua.includes('Python-urllib')) && ctx.role === 'guest') {
    tlsRisk += 0.15;
    tlsReasons.push('suspicious_ua');
  }

  // Cap at 1.0
  tlsRisk = Math.min(tlsRisk, 1.0);

  const ruleDecision = await checkRiskRule(ctx);
  const ml = await scoreWithML({
    ...ctx,
    risk_rule: ruleDecision.risk,
    // JA3 + TLS Features
    ja3_bot_score: req.tlsFingerprint?.botScore || 0.0,
    ja3_hash: req.tlsFingerprint?.ja3Lite || '',
    tls_signals_count: req.tlsFingerprint?.signals?.length || 0,
    tls_cipher_strength: req.socket.getCipher()?.name || 'unknown',
    tls_issuer: req.tlsFingerprint?.tlsInfo?.issuer || 'unknown'
  });
  const finalRisk = Math.max(ruleDecision.risk, ml.ml_risk, tlsRisk);
  const finalLabel = finalRisk >= 0.7 ? 'high_risk' : finalRisk >= 0.4 ? 'medium_risk' : 'normal';
  const rbacAllowed = checkRBAC(ctx.role, forwardPath);

  const entry = {
    time: new Date().toISOString(),
    context: ctx,
    tls: { 
      risk: tlsRisk, 
      reasons: tlsReasons,
      fingerprint: req.tlsFingerprint  // Full JA3 data
    },
    decision: { allow: rbacAllowed && finalRisk < 0.95, label: finalLabel, rbac: rbacAllowed, risk: finalRisk },
    targetPath: forwardPath,
    ruleRisk: ruleDecision.risk,
    mlRisk: ml.ml_risk,
    tlsRisk,
    reasons: [...ruleDecision.reasons, ...tlsReasons]
  };
  auditLogs.push(entry);

  if (!rbacAllowed || finalRisk >= 0.95) {
    return res.status(403).json({
      error: 'Access denied by AI-NGFW',
      reason: !rbacAllowed ? 'RBAC violation' : 'Critical risk',
      risk: finalRisk,
      tlsRisk,
      reasons: entry.reasons
    });
  }

  // Forward to TLS backend
  try {
    const response = await axios({
      method: req.method,
      url: target,
      data: req.body,
      headers: { ...req.headers, host: undefined },
      httpsAgent: new (require('https').Agent)({
        rejectUnauthorized: false,  // Trust backend-cert.pem
        keepAlive: true
      }),
      validateStatus: () => true,
      timeout: 10000
    });

    // Set NGFW headers
    res.set('x-ngfw-rule-risk', ruleDecision.risk.toString());
    res.set('x-ngfw-ml-risk', ml.ml_risk.toString());
    res.set('x-ngfw-tls-risk', tlsRisk.toString());
    res.set('x-ngfw-final-risk', finalRisk.toString());
    res.set('x-ngfw-label', finalLabel);

    return res.status(response.status).json(response.data);
  } catch (err) {
    console.error('Backend error:', err.message);
    auditLogs.push({ ...entry, statusCode: 500, error: err.message });
    return res.status(500).json({ error: 'TLS Backend unavailable' });
  }
}

  // Admin endpoints (HTTPS only)
function createAdminEndpoints(app) {
  app.use(cors({ 
    origin: [
      'http://localhost:3000',  // Admin dashboard
      'http://localhost:3001',  // Dummy site  
      'http://localhost:3002'   // Any other dev ports
    ],
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'x-user-id', 'x-user-role', 'x-tls-sim'],
    credentials: true
  }));

  app.use(express.json());

  app.get('/health', (req, res) => res.json({
    status: 'ok',
    service: 'AI-NGFW Gateway',
    time: new Date().toISOString(),
    logCount: auditLogs.length
  }));

  app.get('/admin/logs', (req, res) => {
    console.log('Logs requested:', auditLogs.length, 'entries');
    res.json(auditLogs);
  });
  
  app.use('/fw', inspectAndForward);

  // Export logs (JSON / CSV, SIEM-style)
  function normalizeLogForSIEM(entry) {
  const ctx = entry.context || {};
  const dec = entry.decision || {};

  const isAllowed =
    entry.statusCode !== undefined && entry.statusCode !== null
      ? entry.statusCode < 400
      : dec.allow;

    return {
      // Core SIEM fields
      timestamp: entry.time || ctx.timestamp,
      event_type: "firewall_decision",
      source_ip: ctx.ip || "unknown",
      http_method: ctx.method || "GET",
      url_path: ctx.path || entry.targetPath || "/",
      user_id: ctx.userId || "anonymous",
      user_role: ctx.role || "guest",

      // Decision outcome
      action: isAllowed ? "allowed" : "blocked",
      status_code: entry.statusCode ?? null,

      // Risk / AI fields
      risk_score: dec.risk ?? null,
      rule_risk: dec.rule_risk ?? null,
      ml_risk: dec.ml_risk ?? null,
      risk_label: dec.label || "normal",
      ml_label: dec.ml_label || "normal",

      // Meta
      gateway_service: "ai-ngfw-gateway",
      protected_service: "dummy-backend",
      reasons: dec.reasons || [],
    };
  }

  function logsToCSV(logs) {
    const normalized = logs.map(normalizeLogForSIEM);

    const headers = [
      "timestamp",
      "event_type",
      "source_ip",
      "http_method",
      "url_path",
      "user_id",
      "user_role",
      "action",
      "status_code",
      "risk_score",
      "rule_risk",
      "ml_risk",
      "risk_label",
      "ml_label",
      "gateway_service",
      "protected_service",
    ];

  function esc(v) {
    if (v === undefined || v === null) return '""';
    const s = String(v).replace(/"/g, '""');
    return `"${s}"`;
  }

  const rows = normalized.map((e) => [
    esc(e.timestamp),
    esc(e.event_type),
    esc(e.source_ip),
    esc(e.http_method),
    esc(e.url_path),
    esc(e.user_id),
    esc(e.user_role),
    esc(e.action),
    esc(e.status_code),
    esc(e.risk_score),
    esc(e.rule_risk),
    esc(e.ml_risk),
    esc(e.risk_label),
    esc(e.ml_label),
    esc(e.gateway_service),
    esc(e.protected_service),
  ]);

    const csv = [headers.join(","), ...rows.map((r) => r.join(","))].join("\n");
    return csv;
  }

  app.get("/admin/logs/export", (req, res) => {
    try {
      const format = (req.query.format || "json").toLowerCase();

      const normalized = auditLogs.map(normalizeLogForSIEM);

      if (format === "csv") {
        const csv = logsToCSV(auditLogs);
        res.setHeader("Content-Type", "text/csv; charset=utf-8");
        res.setHeader("Content-Disposition", 'attachment; filename="logs.csv"');
        return res.send(csv);
      }

      // default: JSON (SIEM-style events)
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.setHeader("Content-Disposition", 'attachment; filename="logs.json"');
      return res.send(JSON.stringify(normalized, null, 2));
    } catch (err) {
      console.error("Error exporting logs:", err);
      return res.status(500).json({
        error: "Failed to export logs",
        details: err.message,
      });
    }
  });
}

// START TLS-ONLY SERVER
async function startServer() {
  await ensureCerts();
  
  const tlsOptions = {
    key: fs.readFileSync('key.pem'),
    cert: fs.readFileSync('cert.pem')
  };

  const app = express();
  app.use((req, res, next) => {
    console.log('TLS Client:', req.socket.remoteAddress, req.method, req.url);
    req.tlsInfo = {
      cipher: req.socket.getCipher ? req.socket.getCipher().name : 'unknown',
      version: req.socket.getProtocol ? req.socket.getProtocol() : 'unknown'
    };
    next();
  });

  // JA3 Fingerprinting
  app.use((req, res, next) => {
    try {
      const socket = req.socket;
      const peerCert = socket.getPeerCertificate(false) || {};
      
      // Extract TLS metadata
      const tlsInfo = {
        version: socket.getProtocol() || 'unknown',
        cipher: socket.getCipher()?.name || 'unknown',
        sni: socket.servername || req.headers.host || 'unknown',
        issuer: peerCert.issuer?.CN || 'unknown',
        subject: peerCert.subject?.CN || 'unknown'
      };
      
      // JA3-Lite fingerprint
      const ja3Lite = [
        tlsInfo.version.replace('TLSv', ''),
        tlsInfo.cipher,
        tlsInfo.sni,
        tlsInfo.issuer
      ].join('|').slice(0, 64);
      
      req.tlsFingerprint = {
        ja3Lite: ja3Lite,
        botScore: 0.0,
        signals: [],
        tlsInfo: tlsInfo
      };
      
      // Bot risk signals (contributes to tlsRisk, no blocking)
      const ua = (req.headers['user-agent'] || '').toLowerCase();
      if (ua.includes('curl') || ua.includes('python-urllib') || ua.includes('wget') || ua.includes('node-fetch')) {
        req.tlsFingerprint.botScore += 0.35;
        req.tlsFingerprint.signals.push('scripted_ua');
      }
      
      if (tlsInfo.cipher.includes('RC4') || tlsInfo.cipher.includes('CBC') || tlsInfo.cipher.includes('3DES')) {
        req.tlsFingerprint.botScore += 0.25;
        req.tlsFingerprint.signals.push('weak_cipher');
      }
      
      if (!tlsInfo.sni || tlsInfo.sni === 'localhost' || tlsInfo.sni === '127.0.0.1') {
        req.tlsFingerprint.botScore += 0.10;
        req.tlsFingerprint.signals.push('local_sni');
      }
      
      if (tlsInfo.issuer === 'unknown' || tlsInfo.issuer.includes('self-signed')) {
        req.tlsFingerprint.botScore += 0.15;
        req.tlsFingerprint.signals.push('selfsigned_cert');
      }
      
      // Log for debugging (no blocking)
      console.log(`JA3: ${ja3Lite.slice(0, 32)}... | BotScore: ${req.tlsFingerprint.botScore.toFixed(2)} | Signals: ${req.tlsFingerprint.signals.length}`);
      
    } catch (err) {
      console.log('JA3-Lite failed:', err.message);
    }
    
    next();
  });

  createAdminEndpoints(app);

  https.createServer(tlsOptions, app).listen(4001, () => {
    console.log('AI-NGFW Gateway running at https://localhost:4001');
    console.log('Admin Logs: https://localhost:4001/admin/logs');
    console.log('Endpoints: https://localhost:4001/fw/*');
    console.log('Dashboard: localhost:3000');
    console.log('Trust cert.pem in browser/OS for testing');
  });
}

startServer().catch(console.error);