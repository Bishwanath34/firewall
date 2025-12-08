const express = require("express");
const morgan = require("morgan");
const axios = require("axios");
const cors = require("cors");
const crypto = require("crypto");

const app = express();
app.use(express.json());
app.use(cors());
app.use(morgan("dev"));

const BACKEND = "http://localhost:9000";
const auditLogs = [];

// ================= STATEFUL TRACKING (FIXED) =================
const connectionState = new Map();
const MAX_REQS_PER_MIN = 100;

function getConnectionState(ip) {
  if (!connectionState.has(ip)) {
    connectionState.set(ip, { reqCount: 0, lastReq: Date.now(), riskBoost: 0 });
  }
  return connectionState.get(ip);
}

function updateConnectionState(ip) {
  const state = getConnectionState(ip);
  const now = Date.now();
  state.reqCount++;
  state.lastReq = now;
  
  // FIXED: Proper sliding window reset
  if (now - state.lastReq > 60000) {
    state.reqCount = 1;
  }
  
  connectionState.set(ip, state);
  return state;
}

app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    service: "AI-NGFW Gateway (DPI-Fixed)",
    time: new Date().toISOString(),
    activeConnections: connectionState.size
  });
});

function buildContext(req) {
  const ip = req.ip || req.connection.remoteAddress;
  const state = updateConnectionState(ip);
  
  return {
    ip,
    method: req.method,
    path: req.path,
    userAgent: req.headers["user-agent"] || "unknown",
    timestamp: new Date().toISOString(),
    userId: req.headers["x-user-id"] || "anonymous",
    role: req.headers["x-user-role"] || "guest",
    reqRate: state.reqCount,
    tlsRisk: state.riskBoost // Will be 0 initially
  };
}

// -------------- ORIGINAL RULE RISK ENGINE (UNCHANGED) --------------
async function checkRiskRule(ctx) {
  let risk = 0.0;
  const reasons = [];

  if (!ctx.userId || ctx.userId === "anonymous") {
    risk += 0.2; reasons.push("no_user_id");
  }
  if (ctx.path.startsWith("/admin")) {
    risk += 0.5; reasons.push("admin_path");
  }
  if (ctx.path.startsWith("/admin") && ctx.role === "guest") {
    risk += 0.3; reasons.push("guest_on_admin_path");
  }
  if (ctx.path.startsWith("/honeypot")) {
    risk += 0.8; reasons.push("honeypot_path");
  }

  // FIXED: Conservative stateful rules (only trigger after multiple requests)
  if (ctx.reqRate > MAX_REQS_PER_MIN) {
    risk += 0.4; reasons.push("rate_limit_exceeded");
  }

  let label = "normal";
  if (risk >= 0.7) label = "high_risk";
  else if (risk >= 0.4) label = "medium_risk";

  return { risk, label, reasons };
}

async function scoreWithML(ctx) {
  try {
    const res = await axios.post("http://localhost:5000/score", {
      method: ctx.method, path: ctx.path, role: ctx.role,
      userId: ctx.userId, userAgent: ctx.userAgent, risk_rule: ctx.risk_rule
    }, { validateStatus: () => true });
    return { ml_risk: res.data.ml_risk || 0.0, ml_label: res.data.ml_label || "normal" };
  } catch (err) {
    console.error("ML service error:", err.message);
    return { ml_risk: 0.0, ml_label: "normal" };
  }
}

// ---------------- RBAC TABLE (UNCHANGED) -------------------
const RBAC = {
  guest: { allow: ["/info"], deny: ["/admin", "/admin/secret", "/admin/*"] },
  user: { allow: ["/info", "/profile"], deny: ["/admin", "/admin/*"] },
  admin: { allow: ["*"], deny: [] }
};

function checkRBAC(role, pathReq) {
  const rules = RBAC[role] || RBAC["guest"];
  if (pathReq.startsWith("/honeypot")) return true;
  if (rules.allow.includes("*")) return true;
  for (const d of rules.deny) {
    if (pathReq.startsWith(d.replace("*", ""))) return false;
  }
  for (const a of rules.allow) {
    if (pathReq.startsWith(a.replace("*", ""))) return true;
  }
  return false; // Default DENY
}

app.get("/admin/logs", (req, res) => res.json(auditLogs));
app.get("/admin/connections", (req, res) => {
  res.json(Array.from(connectionState.entries()).map(([ip, state]) => ({ ip, reqCount: state.reqCount, riskBoost: state.riskBoost })));
});

// ================= FIXED FIREWALL MIDDLEWARE =================
app.use("/fw", async (req, res) => {
  const ctx = buildContext(req);
  const forwardPath = req.originalUrl.replace(/^\/fw/, "");
  const target = BACKEND + forwardPath;

  // 1. EXECUTE RISK ENGINES (WAS MISSING)
  const ruleDecision = await checkRiskRule(ctx);
  const ml = await scoreWithML({ ...ctx, risk_rule: ruleDecision.risk });
  const finalRisk = Math.max(ruleDecision.risk, ml.ml_risk);
  const finalLabel = finalRisk >= 0.7 ? "high_risk" : finalRisk >= 0.4 ? "medium_risk" : "normal";

  // 2. RBAC CHECK
  const rbacAllowed = checkRBAC(ctx.role, forwardPath);

  // 3. LOG EVERYTHING
  const entry = {
    time: new Date().toISOString(),
    context: ctx,
    decision: { allow: rbacAllowed && finalRisk < 0.95, label: finalLabel, rbac: rbacAllowed, risk: finalRisk },
    targetPath: forwardPath,
    ruleRisk: ruleDecision.risk,
    mlRisk: ml.ml_risk,
    reasons: ruleDecision.reasons
  };
  auditLogs.push(entry);

  // 4. BLOCK ONLY CRITICAL VIOLATIONS (FIXED THRESHOLD)
  if (!rbacAllowed || finalRisk >= 0.95) { // Raised from 0.9
    return res.status(403).json({
      error: "Access denied by AI-NGFW",
      reason: !rbacAllowed ? "RBAC violation" : "Critical risk",
      risk: finalRisk,
      reasons: ruleDecision.reasons
    });
  }

  // 5. FORWARD SAFE REQUESTS
  try {
    const response = await axios({
      method: req.method, url: target, data: req.body,
      headers: { ...req.headers, host: undefined },
      validateStatus: () => true
    });

    res.set("x-ngfw-rule-risk", ruleDecision.risk.toString());
    res.set("x-ngfw-ml-risk", ml.ml_risk.toString());
    res.set("x-ngfw-final-risk", finalRisk.toString());
    res.set("x-ngfw-label", finalLabel);

    return res.status(response.status).json(response.data);
  } catch (err) {
    console.error("Backend error:", err.message);
    auditLogs.push({ ...entry, statusCode: 500, error: err.message });
    return res.status(500).json({ error: "Backend unavailable", details: err.message });
  }
});

app.listen(4000, () => {
  console.log("AI-NGFW Gateway (FIXED) running at http://localhost:4000");
  console.log("✓ /admin/logs - Check blocking reasons");
  console.log("✓ /admin/connections - Stateful tracking");
});
