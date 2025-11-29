const express = require("express");
const morgan = require("morgan");
const axios = require("axios");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
app.use(express.json());
app.use(cors());
app.use(morgan("dev"));

// ---------------- BASIC CONFIG ----------------

// Backend we are protecting
const BACKEND = "http://localhost:9000";

// In-memory audit log (for dashboard)
const auditLogs = [];

// ---- TAMPER-EVIDENT "BLOCKCHAIN" LOG CONFIG ---

const DB_DIR = path.join(__dirname, "..", "db");
const CHAIN_FILE = path.join(DB_DIR, "audit_chain.jsonl");

// Make sure db folder exists
if (!fs.existsSync(DB_DIR)) {
  fs.mkdirSync(DB_DIR, { recursive: true });
}

let lastHash = null;
let lastIndex = -1;

// Compute hash for a block
function computeHash(block) {
  const h = crypto.createHash("sha256");
  h.update(
    String(block.index) +
      "|" +
      block.time +
      "|" +
      (block.context.path || "") +
      "|" +
      (block.context.userId || "") +
      "|" +
      (block.context.role || "") +
      "|" +
      (block.decision.label || "") +
      "|" +
      String(block.statusCode) +
      "|" +
      (block.prevHash || "")
  );
  return h.digest("hex");
}

// Load last block (if file already exists) so we continue the chain
function loadLastBlock() {
  try {
    if (!fs.existsSync(CHAIN_FILE)) return;
    const raw = fs.readFileSync(CHAIN_FILE, "utf8").trim();
    if (!raw) return;
    const lines = raw.split("\n").filter(Boolean);
    if (!lines.length) return;
    const last = JSON.parse(lines[lines.length - 1]);
    lastHash = last.hash || null;
    lastIndex = typeof last.index === "number" ? last.index : lines.length - 1;
  } catch (e) {
    console.error("Failed to load last chain block:", e.message);
  }
}
loadLastBlock();

// Append a new entry as a block in the chain file
function appendToAuditChain(entry) {
  try {
    const block = {
      index: lastIndex + 1,
      time: entry.time,
      context: {
        path: entry.context?.path,
        userId: entry.context?.userId,
        role: entry.context?.role,
      },
      decision: {
        label: entry.decision?.label,
        risk: entry.decision?.risk,
      },
      statusCode: entry.statusCode,
      prevHash: lastHash,
    };
    block.hash = computeHash(block);

    fs.appendFileSync(CHAIN_FILE, JSON.stringify(block) + "\n");
    lastHash = block.hash;
    lastIndex = block.index;
  } catch (e) {
    console.error("Failed to append to audit chain:", e.message);
  }
}

// ---- HELPER: LOAD FULL AUDIT CHAIN ----
function loadChain() {
  if (!fs.existsSync(CHAIN_FILE)) {
    return [];
  }

  const raw = fs.readFileSync(CHAIN_FILE, "utf8").trim();
  if (!raw) return [];

  const lines = raw
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean);

  const chain = [];
  for (const line of lines) {
    try {
      chain.push(JSON.parse(line));
    } catch (err) {
      console.error("Failed to parse chain line:", err);
    }
  }
  return chain;
}

// ---------------- HEALTH CHECK ----------------

app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    service: "AI-NGFW Gateway",
    time: new Date().toISOString(),
  });
});

// -------------- CONTEXT BUILDER ----------------

function buildContext(req) {
  return {
    ip: req.ip,
    method: req.method,
    path: req.path,
    userAgent: req.headers["user-agent"] || "unknown",
    timestamp: new Date().toISOString(),
    userId: req.headers["x-user-id"] || "anonymous",
    role: req.headers["x-user-role"] || "guest",
    risk_rule: 0, // rule-risk stored here for ML input
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

// -------------- ADMIN: VIEW / VERIFY CHAIN -----

app.get("/admin/chain", (req, res) => {
  try {
    if (!fs.existsSync(CHAIN_FILE)) {
      return res.json({ valid: true, length: 0, chain: [] });
    }
    const raw = fs.readFileSync(CHAIN_FILE, "utf8").trim();
    if (!raw) {
      return res.json({ valid: true, length: 0, chain: [] });
    }

    const lines = raw.split("\n").filter(Boolean);
    const chain = lines.map((l) => JSON.parse(l));

    let valid = true;
    let prevHash = null;

    for (const block of chain) {
      const expected = computeHash({
        index: block.index,
        time: block.time,
        context: block.context,
        decision: block.decision,
        statusCode: block.statusCode,
        prevHash: block.prevHash,
      });

      if (block.hash !== expected || block.prevHash !== prevHash) {
        valid = false;
        break;
      }
      prevHash = block.hash;
    }

    res.json({
      valid,
      length: chain.length,
      chain,
    });
  } catch (e) {
    console.error("Failed to read chain:", e.message);
    res.status(500).json({
      error: "Failed to load chain",
      details: e.message,
    });
  }
});

// -------------- ADMIN: SIMPLE CHAIN STATUS -----

app.get("/admin/chain/status", (req, res) => {
  try {
    if (!fs.existsSync(CHAIN_FILE)) {
      return res.json({ valid: true });
    }

    const raw = fs.readFileSync(CHAIN_FILE, "utf8").trim();
    if (!raw) {
      return res.json({ valid: true });
    }

    const lines = raw.split("\n").filter(Boolean);
    let prevHash = null;

    for (const line of lines) {
      const block = JSON.parse(line);
      const expected = computeHash({
        index: block.index,
        time: block.time,
        context: block.context,
        decision: block.decision,
        statusCode: block.statusCode,
        prevHash: block.prevHash,
      });

      if (block.hash !== expected || block.prevHash !== prevHash) {
        return res.json({ valid: false });
      }
      prevHash = block.hash;
    }

    return res.json({ valid: true });
  } catch (e) {
    console.error("Chain status check failed:", e.message);
    return res.json({ valid: false });
  }
});

// -------------- PUBLIC: FULL VERIFY-CHAIN ------

app.get("/verify-chain", (req, res) => {
  try {
    const chain = loadChain();

    if (chain.length === 0) {
      return res.json({
        valid: true,
        message: "No blocks in chain yet.",
        blocks: 0,
      });
    }

    let isValid = true;
    let firstError = null;

    for (let i = 0; i < chain.length; i++) {
      const block = chain[i];

      const expectedPrevHash = i === 0 ? null : chain[i - 1].hash;
      if (block.prevHash !== expectedPrevHash) {
        isValid = false;
        firstError = {
          type: "PREV_HASH_MISMATCH",
          index: i,
          expectedPrevHash,
          actualPrevHash: block.prevHash,
        };
        break;
      }

      const recomputedHash = computeHash(block);
      if (block.hash !== recomputedHash) {
        isValid = false;
        firstError = {
          type: "HASH_MISMATCH",
          index: i,
          expectedHash: recomputedHash,
          actualHash: block.hash,
        };
        break;
      }
    }

    if (isValid) {
      return res.json({
        valid: true,
        message: "Audit chain is valid.",
        blocks: chain.length,
      });
    } else {
      return res.json({
        valid: false,
        message: "Audit chain has been tampered with.",
        blocks: chain.length,
        error: firstError,
      });
    }
  } catch (err) {
    console.error("Error verifying chain:", err);
    return res.status(500).json({
      valid: false,
      message: "Internal error while verifying chain.",
      error: err.message,
    });
  }
});

// -------------- MAIN FIREWALL ROUTE ------------

app.use("/fw", async (req, res) => {
  const ctx = buildContext(req);

  // 1) RBAC check
  const allowedByRole = checkRBAC(ctx.role, ctx.path);
  if (!allowedByRole) {
    const entry = {
      time: new Date().toISOString(),
      context: ctx,
      decision: {
        allow: false,
        risk: 1,
        label: "rbac_block",
        reasons: ["rbac_denied"],
      },
      targetPath: req.originalUrl.replace("/fw", ""),
      statusCode: 403,
    };
    auditLogs.push(entry);
    appendToAuditChain(entry);

    return res.status(403).json({
      message: "Blocked by AI-NGFW (RBAC Policy)",
      role: ctx.role,
      path: ctx.path,
    });
  }

  // 2) Rule engine
  const ruleDecision = await checkRiskRule(ctx);
  ctx.risk_rule = ruleDecision.risk;

  // 3) ML engine
  const ml = await scoreWithML(ctx);

  // 4) Combine
  const finalRisk = Math.max(ruleDecision.risk, ml.ml_risk);

  let finalLabel = "normal";
  if (finalRisk >= 0.7) finalLabel = "high_risk";
  else if (finalRisk >= 0.4) finalLabel = "medium_risk";

  const allow = finalRisk < 0.8;

  const fullDecision = {
    allow,
    risk: finalRisk,
    label: finalLabel,
    rule_risk: ruleDecision.risk,
    rule_label: ruleDecision.label,
    ml_risk: ml.ml_risk,
    ml_label: ml.ml_label,
  };

  // BLOCKED
  if (!allow) {
    const blockedEntry = {
      time: new Date().toISOString(),
      context: ctx,
      decision: fullDecision,
      targetPath: req.originalUrl.replace("/fw", ""),
      statusCode: 403,
    };
    auditLogs.push(blockedEntry);
    appendToAuditChain(blockedEntry);

    return res.status(403).json({
      message: "Blocked by AI-NGFW",
      decision: fullDecision,
    });
  }

  // 5) FORWARD TO BACKEND
  const forwardPath = req.originalUrl.replace("/fw", "");
  const target = BACKEND + forwardPath;

  try {
    const response = await axios({
      method: req.method,
      url: target,
      data: req.body,
      headers: { ...req.headers, host: undefined },
      validateStatus: () => true,
    });

    const allowedEntry = {
      time: new Date().toISOString(),
      context: ctx,
      decision: fullDecision,
      targetPath: forwardPath,
      statusCode: response.status,
    };
    auditLogs.push(allowedEntry);
    appendToAuditChain(allowedEntry);

    res.set("x-ngfw-rule-risk", ruleDecision.risk.toString());
    res.set("x-ngfw-ml-risk", ml.ml_risk.toString());
    res.set("x-ngfw-final-risk", finalRisk.toString());
    res.set("x-ngfw-label", finalLabel);

    return res.status(response.status).json(response.data);
  } catch (err) {
    const errorEntry = {
      time: new Date().toISOString(),
      context: ctx,
      decision: fullDecision,
      targetPath: forwardPath,
      statusCode: 500,
      error: err.message,
    };
    auditLogs.push(errorEntry);
    appendToAuditChain(errorEntry);

    return res.status(500).json({
      error: "Error forwarding to backend",
      details: err.message,
    });
  }
});

// -------------- START SERVER -------------------

app.listen(4000, () => {
  console.log("AI-NGFW Gateway running at http://localhost:4000");
});
