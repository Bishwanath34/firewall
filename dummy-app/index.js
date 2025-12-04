const express = require("express");
const morgan = require("morgan");
const cors = require("cors");
const { Pool } = require("pg");

const app = express();
app.use(express.json());
app.use(cors());
app.use(morgan("dev"));

// ---------------- POSTGRES CONFIG ----------------

// For hackathon demo, we provide a default connection string,
// but you can override with process.env.DATABASE_URL if needed.
const pool = new Pool({
  connectionString:
    process.env.DATABASE_URL ||
    "postgres://postgres:postgres@localhost:5432/ngfw_demo",
});

// Initialize DB: create table + seed some sample users
async function initDb() {
  console.log("[DB] Initializing database...");

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(50) NOT NULL,
      role VARCHAR(20) NOT NULL,
      email VARCHAR(100) NOT NULL
    );
  `);

  const result = await pool.query(`SELECT COUNT(*) AS count FROM users;`);
  const count = parseInt(result.rows[0].count, 10);

  if (count === 0) {
    console.log("[DB] Seeding sample users...");
    await pool.query(
      `
      INSERT INTO users (username, role, email)
      VALUES 
        ('alice', 'user', 'alice@example.com'),
        ('bob', 'admin', 'bob@example.com'),
        ('guest123', 'guest', 'guest@example.com');
    `
    );
  }

  console.log("[DB] Ready.");
}

// Call initialization (no top-level await)
initDb().catch((err) => {
  console.error("[DB] Initialization failed:", err.message);
});

// ---------------- BASIC ROUTES -------------------

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1"); // simple check
    res.json({
      status: "ok",
      service: "Dummy Backend (Postgres)",
      db: "connected",
      time: new Date().toISOString(),
    });
  } catch (err) {
    res.status(500).json({
      status: "error",
      service: "Dummy Backend (Postgres)",
      db: "error",
      error: err.message,
    });
  }
});

// This is the simple info endpoint your firewall already protects
app.get("/info", (req, res) => {
  res.json({
    service: "Dummy Backend",
    description:
      "Backend behind the AI-NGFW. Now powered by a real Postgres database.",
    docs: "/users, /profile, /admin/secret",
  });
});

// ---------------- POSTGRES-BACKED ROUTES ---------

// 1) List all users from the Postgres table
app.get("/users", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, username, role, email FROM users ORDER BY id ASC;"
    );
    res.json({
      count: result.rowCount,
      users: result.rows,
    });
  } catch (err) {
    console.error("[DB] Error in /users:", err.message);
    res.status(500).json({ error: "Failed to fetch users", details: err.message });
  }
});

// 2) Profile: look up a user by username (e.g. alice, bob, guest123)
// You can call: GET /profile?username=alice
app.get("/profile", async (req, res) => {
  try {
    const username = req.query.username || "alice"; // default for demo
    const result = await pool.query(
      "SELECT id, username, role, email FROM users WHERE username = $1;",
      [username]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: "User not found", username });
    }

    res.json({
      user: result.rows[0],
      note: "This data is served from Postgres.",
    });
  } catch (err) {
    console.error("[DB] Error in /profile:", err.message);
    res.status(500).json({ error: "Failed to fetch profile", details: err.message });
  }
});

// 3) Simple admin-only style route just for firewall demo
app.get("/admin/secret", async (req, res) => {
  // You *could* also hit DB here, but for demo it's fine as static
  res.json({
    message: "Top secret admin data from dummy backend.",
    tip: "Your AI-NGFW and RBAC should protect this path.",
  });
});

// ---------------- START SERVER -------------------

const PORT = 9000;
app.listen(PORT, () => {
  console.log(`Dummy backend (Postgres) running at http://localhost:${PORT}`);
});
