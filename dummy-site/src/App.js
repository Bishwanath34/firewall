import React, { useState } from "react";
import axios from "axios";

const GATEWAY_URL = "http://localhost:4000";

function App() {
  const [userId, setUserId] = useState("alice");
  const [role, setRole] = useState("user");
  const [lastRequest, setLastRequest] = useState(null);
  const [loading, setLoading] = useState(false);

  const callApi = async (path) => {
    try {
      setLoading(true);
      setLastRequest(null);

      const res = await axios.get(`${GATEWAY_URL}/fw${path}`, {
        headers: {
          "x-user-id": userId || "anonymous",
          "x-user-role": role || "guest",
        },
        validateStatus: () => true, // don't throw on 403, 500, etc.
      });

      setLastRequest({
        path,
        status: res.status,
        data: res.data,
      });
    } catch (err) {
      setLastRequest({
        path,
        status: "ERROR",
        data: { error: err.message },
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      style={{
        minHeight: "100vh",
        background: "#020617",
        color: "white",
        fontFamily: "system-ui, -apple-system, BlinkMacSystemFont, sans-serif",
      }}
    >
      {/* Header */}
      <header
        style={{
          padding: "16px 24px",
          borderBottom: "1px solid #1f2937",
          marginBottom: 24,
        }}
      >
        <h1 style={{ margin: 0, fontSize: 24 }}>Dummy Web App (Protected by AI–NGFW)</h1>
        <p style={{ margin: 0, marginTop: 4, color: "#9ca3af", fontSize: 14 }}>
          This is the user-side application. All requests go through the firewall gateway
          at <code style={{ color: "#e5e7eb" }}>http://localhost:4000/fw/…</code>
        </p>
      </header>

      <main
        style={{
          maxWidth: 900,
          margin: "0 auto",
          padding: "0 16px 40px",
        }}
      >
        {/* User "session" section */}
        <section
          style={{
            marginBottom: 24,
            padding: 16,
            borderRadius: 8,
            border: "1px solid #1f2937",
            background: "#030712",
          }}
        >
          <h2 style={{ marginTop: 0, marginBottom: 12, fontSize: 18 }}>User Session</h2>
          <p style={{ marginTop: 0, color: "#9ca3af", fontSize: 14 }}>
            Pretend you are a user or an attacker. Choose an identity and role, then call
            different endpoints. The admin can watch everything on the security dashboard.
          </p>

          <div style={{ display: "flex", gap: 16, flexWrap: "wrap", marginTop: 12 }}>
            <div style={{ flex: 1, minWidth: 180 }}>
              <label style={{ display: "block", fontSize: 14, marginBottom: 4 }}>
                User ID
              </label>
              <input
                value={userId}
                onChange={(e) => setUserId(e.target.value)}
                placeholder="alice, bob…"
                style={{
                  width: "100%",
                  padding: "6px 8px",
                  borderRadius: 4,
                  border: "1px solid #374151",
                  background: "#020617",
                  color: "white",
                }}
              />
            </div>

            <div style={{ flex: 1, minWidth: 180 }}>
              <label style={{ display: "block", fontSize: 14, marginBottom: 4 }}>
                Role
              </label>
              <select
                value={role}
                onChange={(e) => setRole(e.target.value)}
                style={{
                  width: "100%",
                  padding: "6px 8px",
                  borderRadius: 4,
                  border: "1px solid #374151",
                  background: "#020617",
                  color: "white",
                }}
              >
                <option value="guest">guest</option>
                <option value="user">user</option>
                <option value="admin">admin</option>
              </select>
            </div>
          </div>
        </section>

        {/* Normal actions */}
        <section
          style={{
            marginBottom: 24,
            padding: 16,
            borderRadius: 8,
            border: "1px solid #1f2937",
            background: "#030712",
          }}
        >
          <h2 style={{ marginTop: 0, marginBottom: 12, fontSize: 18 }}>Normal Actions</h2>
          <p style={{ marginTop: 0, color: "#9ca3af", fontSize: 14 }}>
            These simulate normal user behavior. In most cases, the firewall should allow
            them if the role is appropriate.
          </p>

          <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginTop: 12 }}>
            <button
              onClick={() => callApi("/info")}
              disabled={loading}
              style={{
                padding: "8px 12px",
                borderRadius: 6,
                border: "none",
                background: "#16a34a",
                color: "white",
                cursor: "pointer",
                fontSize: 14,
              }}
            >
              GET /info
            </button>

            <button
              onClick={() => callApi("/profile")}
              disabled={loading}
              style={{
                padding: "8px 12px",
                borderRadius: 6,
                border: "none",
                background: "#2563eb",
                color: "white",
                cursor: "pointer",
                fontSize: 14,
              }}
            >
              GET /profile
            </button>
          </div>
        </section>

        {/* "Attacker" actions */}
        <section
          style={{
            marginBottom: 24,
            padding: 16,
            borderRadius: 8,
            border: "1px solid #1f2937",
            background: "#030712",
          }}
        >
          <h2 style={{ marginTop: 0, marginBottom: 12, fontSize: 18 }}>Suspicious / Attack Actions</h2>
          <p style={{ marginTop: 0, color: "#9ca3af", fontSize: 14 }}>
            These endpoints simulate attackers probing admin areas or honeypots. The
            firewall should either block them or flag them as high risk.
          </p>

          <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginTop: 12 }}>
            <button
              onClick={() => callApi("/admin/secret")}
              disabled={loading}
              style={{
                padding: "8px 12px",
                borderRadius: 6,
                border: "none",
                background: "#ea580c",
                color: "white",
                cursor: "pointer",
                fontSize: 14,
              }}
            >
              GET /admin/secret
            </button>

            <button
              onClick={() => callApi("/honeypot/db-export")}
              disabled={loading}
              style={{
                padding: "8px 12px",
                borderRadius: 6,
                border: "none",
                background: "#b91c1c",
                color: "white",
                cursor: "pointer",
                fontSize: 14,
              }}
            >
              GET /honeypot/db-export (Honeypot)
            </button>
          </div>
        </section>

        {/* Last response */}
        <section
          style={{
            padding: 16,
            borderRadius: 8,
            border: "1px solid #1f2937",
            background: "#030712",
          }}
        >
          <h2 style={{ marginTop: 0, marginBottom: 12, fontSize: 18 }}>Last Response</h2>

          {loading && (
            <p style={{ color: "#9ca3af", fontSize: 14 }}>
              Sending request…
            </p>
          )}

          {!loading && !lastRequest && (
            <p style={{ color: "#6b7280", fontSize: 14 }}>
              No request yet. Click one of the buttons above to call the API via the firewall.
            </p>
          )}

          {!loading && lastRequest && (
            <div
              style={{
                fontFamily: "monospace",
                fontSize: 13,
                whiteSpace: "pre-wrap",
                background: "#020617",
                borderRadius: 6,
                padding: 10,
                border: "1px solid #1f2937",
              }}
            >
              <div style={{ marginBottom: 6 }}>
                <span style={{ color: "#9ca3af" }}>Path:</span> {lastRequest.path}
              </div>
              <div style={{ marginBottom: 6 }}>
                <span style={{ color: "#9ca3af" }}>Status:</span> {lastRequest.status}
              </div>
              <div>
                <span style={{ color: "#9ca3af" }}>Body:</span>{" "}
                {JSON.stringify(lastRequest.data, null, 2)}
              </div>
            </div>
          )}
        </section>
      </main>
    </div>
  );
}

export default App;
