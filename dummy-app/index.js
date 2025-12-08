const express = require("express");
const morgan = require("morgan");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(morgan("dev"));
app.use(cors());

// Root – quick check
app.get("/", (req, res) => {
  res.json({ message: "AI-NGFW Dummy App Running", time: new Date() });
});

// Normal informational endpoint
app.get("/info", (req, res) => {
  res.json({
    service: "Dummy Backend Info",
    version: "1.0",
    time: new Date().toISOString()
  });
});

// Normal user profile endpoint
app.get("/profile", (req, res) => {
  res.json({
    user: req.headers["x-user-id"] || "anonymous",
    role: req.headers["x-user-role"] || "guest",
    bio: "This is dummy profile data protected by the firewall."
  });
});

// Admin-only secret endpoint (this should normally be blocked for guests)
app.get("/admin/secret", (req, res) => {
  res.json({
    secret: "TOP SECRET ADMIN DATA",
    note: "If you see this as guest, firewall rules are misconfigured!"
  });
});

// HONEYPOT endpoint – fake DB export
app.get("/honeypot/db-export", (req, res) => {
  console.log("⚠️  HONEYPOT ACCESSED on backend! This should be very rare.");
  res.json({
    warning: "Honeypot endpoint accessed!",
    message:
      "This simulates a sensitive DB export endpoint. In production, this would trigger heavy alerts.",
    fakeDump: {
      dbPassword: "fake_admin_pass",
      privateKey: "FAKE_PRIVATE_KEY_ABC123",
      envFile: "API_KEY=fake_key_123",
      rowsLeaked: 5000
    }
  });
});

app.listen(9000, () => {
  console.log("Dummy backend running on http://localhost:9000");
});
