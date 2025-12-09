const https = require("https");
const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.raw({ type: "*/*" })); 

// ----------------------------
//  API ROUTES
// ----------------------------

app.get("/info", (req, res) => {
  res.json({
    service: "Dummy Backend Info",
    version: "1.0",
    time: new Date().toISOString(),
    user: req.headers["x-user-id"] || "anonymous",
  });
});

app.get("/profile", (req, res) => {
  res.json({
    user: req.headers["x-user-id"] || "anonymous",
    role: req.headers["x-user-role"] || "guest",
    bio: "This is dummy profile data protected by the firewall.",
    timestamp: new Date().toISOString(),
  });
});

app.get("/admin/secret", (req, res) => {
  console.log("ADMIN SECRET accessed by:", req.headers["x-user-id"], req.headers["x-user-role"]);
  res.json({
    secret: "TOP SECRET ADMIN DATA",
    note: "If you see this as guest, firewall rules are bypassed!",
    sensitive: true,
    timestamp: new Date().toISOString(),
  });
});

app.get("/honeypot/db-export", (req, res) => {
  console.log("HONEYPOT TRAPPED:", req.headers["x-user-id"], req.socket.remoteAddress);
  res.json({
    warning: "Honeypot endpoint accessed!",
    message: "This simulates a sensitive DB export endpoint.",
    fakeDump: {
      dbPassword: "fakeadminpass",
      privateKey: "FAKEPRIVATEKEYABC123",
      envFile: "APIKEY=fakekey123",
    },
    rowsLeaked: 5000,
    timestamp: new Date().toISOString(),
  });
});

// 404 fallback
app.use((req, res) => {
  res.status(404).json({
    error: "Endpoint not found",
    path: req.path,
    method: req.method,
  });
});

// ----------------------------
// HTTPS SERVER CONFIG
// ----------------------------

function startServer() {
  const PORT = process.env.PORT || 9001;

  const keyPath = path.join(__dirname, "backend-key.pem");
  const certPath = path.join(__dirname, "backend-cert.pem");

  if (!fs.existsSync(keyPath) || !fs.existsSync(certPath)) {
    console.error("❌ TLS certificate or key missing. Ensure backend-key.pem and backend-cert.pem exist.");
    process.exit(1);
  }

  const tlsOptions = {
    key: fs.readFileSync(keyPath),
    cert: fs.readFileSync(certPath),
    rejectUnauthorized: false,
  };

  https.createServer(tlsOptions, app).listen(PORT, "0.0.0.0", () => {
    console.log("----------------------------------------------------");
    console.log(`✔ Dummy Backend is running at https://localhost:${PORT}`);
    console.log("✔ Endpoints: /info, /profile, /admin/secret, /honeypot/db-export");
    console.log("✔ Using static TLS certificate");
    console.log("----------------------------------------------------");
  });
}

startServer();
