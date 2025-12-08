const express = require("express");
const morgan = require("morgan");
const axios = require("axios");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors());
app.use(morgan("dev"));

const BACKEND = "http://localhost:9000";

const auditLogs = [];


app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    service: "AI-NGFW Gateway (CP1)",
    time: new Date().toISOString(),
  });
});



function buildContext(req) {
  return {
    ip: req.ip,
    method: req.method,

    path: req.path,
    userAgent: req.headers["user-agent"] || "unknown",
    timestamp: new Date().toISOString(),
    userId: req.headers["x-user-id"] || "anonymous",
    role: req.headers["x-user-role"] || "guest",
  };
}

// -------------- RULE RISK ENGINE --------------

async function checkRiskRule(ctx) {
  let risk = 0.0;
  const reasons = [];

  // Rule 1: anonymous / no user id
  if (!ctx.userId || ctx.userId === "anonymous") {
    risk += 0.2;
    reasons.push("no_user_id");
  }

  // Rule 2: accessing /admin area
  if (ctx.path.startsWith("/admin")) {
    risk += 0.5;
    reasons.push("admin_path");
  }

  // Rule 3: guest trying admin
  if (ctx.path.startsWith("/admin") && ctx.role === "guest") {
    risk += 0.3;
    reasons.push("guest_on_admin_path");
  }

  // Rule 4: HONEYPOT — extremely high risk
  if (ctx.path.startsWith("/honeypot")) {
    risk += 0.8;
    reasons.push("honeypot_path");
  }

  // Label from rule-risk
  let label = "normal";
  if (risk >= 0.7) label = "high_risk";
  else if (risk >= 0.4) label = "medium_risk";

  return { risk, label, reasons };
}

// -------------- ML RISK ENGINE ----------------

async function scoreWithML(ctx) {
  try {
    const res = await axios.post(
      "http://localhost:5000/score",
      {
        method: ctx.method,
        path: ctx.path,
        role: ctx.role,
        userId: ctx.userId,
        userAgent: ctx.userAgent,
        risk_rule: ctx.risk_rule,
      },
      { validateStatus: () => true }
    );

    return {
      ml_risk: res.data.ml_risk,
      ml_label: res.data.ml_label,
    };
  } catch (err) {
    console.error("ML service error:", err.message);
    return { ml_risk: 0.0, ml_label: "normal" };
  }
}

// ---------------- RBAC TABLE -------------------

const RBAC = {
  guest: {
    allow: ["/info"],
    deny: ["/admin", "/admin/secret", "/admin/*"],
  },
  user: {
    allow: ["/info", "/profile"],
    deny: ["/admin", "/admin/*"],
  },
  admin: {
    allow: ["*"],
    deny: [],
  },
};

function checkRBAC(role, pathReq) {
  const rules = RBAC[role] || RBAC["guest"];

  // SPECIAL CASE: HONEYPOT SHOULD NOT BE BLOCKED BY RBAC
  if (pathReq.startsWith("/honeypot")) return true;

  // Admin => everything
  if (rules.allow.includes("*")) return true;

  // Deny rules first
  for (const d of rules.deny) {
    if (pathReq.startsWith(d.replace("*", ""))) return false;
  }

  // Allow rules
  for (const a of rules.allow) {
    if (pathReq.startsWith(a.replace("*", ""))) return true;
  }

  return false;
}

// -------------- ADMIN: VIEW LOGS ---------------

app.get("/admin/logs", (req, res) => {
  res.json(auditLogs);
});


app.use("/fw", async (req, res) => {
  const ctx = buildContext(req);


  const forwardPath = req.originalUrl.replace(/^\/fw/, "");
  const target = BACKEND + forwardPath;

  try {
    const response = await axios({
      method: req.method,
      url: target,
      data: req.body,
      headers: { ...req.headers, host: undefined },
      validateStatus: () => true, 
    });

    const entry = {
      time: new Date().toISOString(),
      context: ctx,

      decision: {
        allow: true,
        label: "pass_through",
      },
      targetPath: forwardPath,
      statusCode: response.status,
    };

    res.set("x-ngfw-rule-risk", ruleDecision.risk.toString());
    res.set("x-ngfw-ml-risk", ml.ml_risk.toString());
    res.set("x-ngfw-final-risk", finalRisk.toString());
    res.set("x-ngfw-label", finalLabel);

    return res.status(response.status).json(response.data);
  } catch (err) {
    console.error("Error forwarding to backend:", err.message);

    const errorEntry = {
      time: new Date().toISOString(),
      context: ctx,
      decision: {
        allow: false,
        label: "gateway_error",
      },
      targetPath: forwardPath,
      statusCode: 500,
      error: err.message,
    };

    auditLogs.push(errorEntry);

    return res.status(500).json({
      error: "Error forwarding to backend",
      details: err.message,
    });
  }
});


app.listen(4000, () => {
  console.log("AI-NGFW Gateway running at http://localhost:4000");
});
