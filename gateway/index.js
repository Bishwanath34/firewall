const express = require("express");
const morgan = require("morgan");
const axios = require("axios");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors());
app.use(morgan("dev"));

const BACKEND = "http://localhost:9000";
const auditLogs = []; // Simple array - NO blockchain

app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    service: "AI-NGFW Gateway (No Blockchain)",
    time: new Date().toISOString(),
    logCount: auditLogs.length
  });
});

function buildContext(req) {
  return {
    ip: req.ip || req.connection.remoteAddress,
    method: req.method,
    path: req.path,
    userAgent: req.headers["user-agent"] || "unknown",
    timestamp: new Date().toISOString(),
    userId: req.headers["x-user-id"] || "anonymous",
    role: req.headers["x-user-role"] || "guest"
  };
}

// -------------- RULE RISK ENGINE --------------
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

// ---------------- RBAC TABLE -------------------
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
  return false;
}

// -------------- ADMIN ENDPOINTS (NO BLOCKCHAIN) ---------------
app.get("/admin/logs", (req, res) => res.json(auditLogs));

app.use("/fw", async (req, res) => {
  const ctx = buildContext(req);
  const forwardPath = req.originalUrl.replace(/^\/fw/, "");
  const target = BACKEND + forwardPath;

  // Risk analysis
  const ruleDecision = await checkRiskRule(ctx);
  const ml = await scoreWithML({ ...ctx, risk_rule: ruleDecision.risk });
  const finalRisk = Math.max(ruleDecision.risk, ml.ml_risk);
  const finalLabel = finalRisk >= 0.7 ? "high_risk" : finalRisk >= 0.4 ? "medium_risk" : "normal";
  const rbacAllowed = checkRBAC(ctx.role, forwardPath);

  // Simple log entry (NO hash chain)
  const entry = {
    time: new Date().toISOString(),
    context: ctx,
    decision: { 
      allow: rbacAllowed && finalRisk < 0.95, 
      label: finalLabel, 
      rbac: rbacAllowed, 
      risk: finalRisk 
    },
    targetPath: forwardPath,
    ruleRisk: ruleDecision.risk,
    mlRisk: ml.ml_risk,
    reasons: ruleDecision.reasons
  };
  auditLogs.push(entry);

  // Block only critical violations
  if (!rbacAllowed || finalRisk >= 0.95) {
    return res.status(403).json({
      error: "Access denied by AI-NGFW",
      reason: !rbacAllowed ? "RBAC violation" : "Critical risk",
      risk: finalRisk,
      reasons: ruleDecision.reasons
    });
  }

  // Forward safe requests
  try {
    const response = await axios({
      method: req.method, 
      url: target, 
      data: req.body,
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
    return res.status(500).json({ error: "Backend unavailable" });
  }
});

app.listen(4000, () => {
  console.log("AI-NGFW Gateway (Blockchain Removed) running at http://localhost:4000");
  console.log("✓ Simple audit logs at /admin/logs");
  console.log("✓ No blockchain/tamper-proofing");
});
