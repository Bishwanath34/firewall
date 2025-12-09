const express = require("express");
const axios = require("axios");
const cors = require("cors");

// Global logs + rate-limit storage
let auditLogs = [];
const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW = 60 * 1000;
const MAX_REQUESTS_PER_WINDOW = 20;

// ENV variables
const ML_URL = process.env.ML_URL;              // Example: https://ml-service.onrender.com/score
const BACKEND_URL = process.env.BACKEND_URL;    // Example: https://dummy-backend.onrender.com
const PORT = process.env.PORT || 4001;

// -------------------------
// Context Builder
// -------------------------
function buildContext(req) {
  return {
    ip: req.ip || req.socket.remoteAddress,
    method: req.method,
    path: req.path,
    userAgent: req.headers["user-agent"] || "unknown",
    timestamp: new Date().toISOString(),
    userId: req.headers["x-user-id"] || "anonymous",
    role: req.headers["x-user-role"] || "guest"
  };
}

// -------------------------
// Rule-based risk engine
// -------------------------
async function checkRiskRule(ctx) {
  let risk = 0.0;
  const reasons = [];

  if (ctx.userId === "anonymous") {
    risk += 0.15;
    reasons.push("no_user_id");
  }

  if (ctx.path.startsWith("/admin")) {
    risk += 0.45;
    reasons.push("admin_path");
  }

  if (ctx.path.startsWith("/admin") && ctx.role === "guest") {
    risk += 0.25;
    reasons.push("guest_on_admin_path");
  }

  if (ctx.path.startsWith("/honeypot")) {
    risk += 0.75;
    reasons.push("honeypot_access");
  }

  return {
    risk,
    label: risk >= 0.7 ? "high_risk" : risk >= 0.35 ? "medium_risk" : "normal",
    reasons
  };
}

// -------------------------
// ML Scoring via external service
// -------------------------
async function scoreWithML(ctx) {
  try {
    const res = await axios.post(
      ML_URL,
      {
        method: ctx.method,
        path: ctx.path,
        role: ctx.role,
        userId: ctx.userId,
        userAgent: ctx.userAgent,
        risk_rule: ctx.risk_rule
      },
      { validateStatus: () => true }
    );

    return {
      ml_risk: res.data.ml_risk || 0,
      ml_label: res.data.ml_label || "normal"
    };
  } catch (err) {
    console.log("ML unreachable:", err.message);
    return { ml_risk: 0, ml_label: "normal" };
  }
}

// -------------------------
// RBAC Rules
// -------------------------
const RBAC = {
  guest: {
    allow: ["/info"],
    deny: ["/admin"]
  },
  user: {
    allow: ["/info", "/profile"],
    deny: ["/admin"]
  },
  admin: { allow: ["*"], deny: [] }
};

function checkRBAC(role, path) {
  const r = RBAC[role] || RBAC.guest;
  if (r.allow.includes("*")) return true;
  for (const d of r.deny) if (path.startsWith(d)) return false;
  for (const a of r.allow) if (path.startsWith(a)) return true;
  return false;
}

// -------------------------
// Rate limiting
// -------------------------
function checkRate(ip) {
  const now = Date.now();
  const entry = rateLimitMap.get(ip) || { count: 0, reset: now + RATE_LIMIT_WINDOW };

  if (now > entry.reset) {
    entry.count = 0;
    entry.reset = now + RATE_LIMIT_WINDOW;
  }

  entry.count++;
  rateLimitMap.set(ip, entry);

  return {
    allowed: entry.count <= MAX_REQUESTS_PER_WINDOW,
    remaining: MAX_REQUESTS_PER_WINDOW - entry.count,
    reset: Math.ceil((entry.reset - now) / 1000)
  };
}

// -------------------------
// Main Firewall Logic
// -------------------------
async function inspectAndForward(req, res) {
  const ctx = buildContext(req);
  const rate = checkRate(ctx.ip);

  if (!rate.allowed) {
    auditLogs.push({ time: new Date(), ctx, reason: "rate_limit" });
    return res.status(429).json({ error: "Too Many Requests" });
  }

  const forwardPath = req.url.replace(/^\/fw/, "");
  const target = BACKEND_URL + forwardPath;

  const rule = await checkRiskRule(ctx);
  const ml = await scoreWithML({ ...ctx, risk_rule: rule.risk });

  const finalRisk = Math.max(rule.risk, ml.ml_risk);
  const rbacAllowed = checkRBAC(ctx.role, forwardPath);

  auditLogs.push({
    time: new Date().toISOString(),
    ctx,
    rule,
    ml,
    finalRisk,
    allowed: rbacAllowed && finalRisk < 0.95
  });

  if (!rbacAllowed || finalRisk >= 0.95) {
    return res.status(403).json({ error: "Blocked", risk: finalRisk });
  }

  try {
    const response = await axios({
      method: req.method,
      url: target,
      data: req.body,
      headers: { ...req.headers, host: undefined },
      validateStatus: () => true
    });

    return res.status(response.status).json(response.data);
  } catch (err) {
    return res.status(500).json({ error: "Backend offline" });
  }
}

// -------------------------
// Admin API
// -------------------------
function adminEndpoints(app) {
  app.get("/health", (req, res) =>
    res.json({ status: "ok", logs: auditLogs.length })
  );

  app.get("/admin/logs", (req, res) => res.json(auditLogs));

  app.get("/admin/logs/export", (req, res) => {
    res.setHeader("Content-Type", "application/json");
    res.send(JSON.stringify(auditLogs, null, 2));
  });

  app.use("/fw", inspectAndForward);
}

// -------------------------
// Start server (HTTP only)
// -------------------------
function start() {
  const app = express();
  app.use(cors());
  app.use(express.json());
  adminEndpoints(app);

  app.listen(PORT, () => {
    console.log(`AI-NGFW running @ http://localhost:${PORT}`);
  });
}

start();
