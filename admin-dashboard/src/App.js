import React, { useEffect, useState } from 'react';
import axios from 'axios';
import {
  AppBar, Toolbar, Typography, Container, Box, Paper, Button, Chip,
  Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
  ToggleButton, ToggleButtonGroup,
} from '@mui/material';
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend,
  BarChart, Bar, ResponsiveContainer,
} from 'recharts';

const TLS_GATEWAY = 'https://localhost:4001';

function App() {
  const [logs, setLogs] = useState([]);
  const [filter, setFilter] = useState('all');

  // Load logs via HTTPS (browser needs cert trust)
  const loadLogs = async () => {
    try {
      const res = await axios.get(`${TLS_GATEWAY}/admin/logs`, {
        headers: { 'Accept': 'application/json' }
      });
      setLogs(res.data);
    } catch (err) {
      console.error('Logs error:', err.message);
    }
  };

  useEffect(() => {
    loadLogs();
    const id = setInterval(loadLogs, 1000);
    return () => clearInterval(id);
  }, []);

  // TLS Simulator (direct HTTPS calls)
  const simulateRequest = async (path, userId, role) => {
    try {
      console.log('Traffic simulation:', path, userId, role);
      await axios.get(`${TLS_GATEWAY}${path}`, {
        headers: { 
          'x-user-id': userId, 
          'x-user-role': role 
        },
        timeout: 5000
      });
      await loadLogs();
    } catch (err) {
      console.log('Traffic simulation result:', err.response?.status || err.message);
      await loadLogs();
    }
  };

  const simulateNormalUserInfo = () => simulateRequest('/fw/info', 'alice', 'user');
  const simulateSuspiciousGuestAdmin = () => simulateRequest('/fw/admin/secret', 'anonymous', 'guest');
  const simulateGuestAdminRBAC = () => simulateRequest('/fw/admin/secret', 'guest123', 'guest');

  // Filtered logs & stats (unchanged logic)
  const filteredLogs = logs.filter(entry => {
    if (filter === 'all') return true;
    if (filter === 'allowed') return entry.decision?.allow !== false;
    if (filter === 'blocked') return entry.decision?.allow === false;
    return true;
  }).sort((a, b) => new Date(b.time) - new Date(a.time));

  const totalRequests = logs.length;
  const allowedCount = logs.filter(e => e.decision?.allow !== false).length;
  const highRiskCount = logs.filter(e => 
    e.decision?.label === 'high_risk' || 
    (e.decision?.risk || 0) >= 0.7 ||
    (e.tls?.risk || 0) > 0.5
  ).length;

  // export logs
  const handleExport = async (format) => {
    try {
      const res = await axios.get(
        `${TLS_GATEWAY}/admin/logs/export?format=${format}`,
        {
          responseType: "blob", // get file as Blob
        }
      );

      const blob = res.data;
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");

      link.href = url;
      link.download = format === "csv" ? "logs.csv" : "logs.json";

      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error("Error exporting logs", err);
      alert("Failed to export logs. Check gateway console for details.");
    }
  };

  // User summary
  const userSummaryMap = {};
  logs.forEach(e => {
    const uid = e.context?.userId || 'anonymous';
    if (!userSummaryMap[uid]) userSummaryMap[uid] = { total: 0, blocked: 0, highRisk: 0 };
    userSummaryMap[uid].total += 1;
    if (e.decision?.allow === false) userSummaryMap[uid].blocked += 1;
    if (e.decision?.label === 'high_risk' || (e.tls?.risk || 0) > 0.5) userSummaryMap[uid].highRisk += 1;
  });
  const userSummary = Object.entries(userSummaryMap).map(([userId, stats]) => ({
    userId, ...stats
  }));

  // Helpers
  const formatTime = (iso) => {
    if (!iso) return '-';
    try { return new Date(iso).toLocaleTimeString(); } catch { return iso; }
  };

  const shortPath = (p) => {
    if (!p) return '';
    if (p.length < 30) return p;
    return p.slice(0, 27) + '...';
  };

  const displayLogs = filteredLogs.slice(0, 50);

  // Chart data
  const logsSortedByTime = [...logs].sort((a, b) => new Date(a.time) - new Date(b.time));
  const timeSeriesData = logsSortedByTime.map((e, idx) => ({
    index: idx + 1,
    timeLabel: formatTime(e.time),
    risk: e.decision?.risk ?? 0,
    // tlsRisk: e.tls?.risk ?? 0,
    allowed: e.decision?.allow ? 1 : 0,
  }));

  const pathMap = {};
  logs.forEach(e => {
    const p = e.context?.path || e.targetPath || '';
    if (!pathMap[p]) pathMap[p] = { path: p, total: 0, allowed: 0, blocked: 0 };
    pathMap[p].total += 1;
    if (e.decision?.allow !== false) pathMap[p].allowed += 1;
    else pathMap[p].blocked += 1;
  });
  const pathStats = Object.values(pathMap);

  return (
    <>
      <AppBar position="static" color="primary">
        <Toolbar>
          <Typography variant="h6" sx={{ flexGrow: 1 }}>
            AI-NGFW Dashboard
          </Typography>
          <Typography variant="body2" color="inherit">
            https://localhost:4001
          </Typography>
        </Toolbar>
      </AppBar>

      <Container maxWidth="lg" sx={{ mt: 4 }}>
        {/* Stats */}
        <Box sx={{ display: 'flex', gap: 2, mb: 3, flexWrap: 'wrap' }}>
          <Paper sx={{ flex: 1, p: 2, minWidth: 200, background: '#111827', color: 'white' }}>
            <Typography variant="subtitle2">Total Requests</Typography>
            <Typography variant="h4">{totalRequests}</Typography>
          </Paper>
          <Paper sx={{ flex: 1, p: 2, minWidth: 200, background: '#065f46', color: 'white' }}>
            <Typography variant="subtitle2">Allowed</Typography>
            <Typography variant="h4">{allowedCount}</Typography>
          </Paper>
          <Paper sx={{ flex: 1, p: 2, minWidth: 200, background: '#7f1d1d', color: 'white' }}>
            <Typography variant="subtitle2">Blocked</Typography>
            <Typography variant="h4">{highRiskCount}</Typography>
          </Paper>
        </Box>

        {/* Charts */}
        <Box sx={{ display: 'flex', gap: 2, mb: 3, flexWrap: 'wrap' }}>
          <Paper sx={{ flex: 1, p: 2, minWidth: 400, background: '#020617', color: 'white' }}>
            <Typography variant="h6" gutterBottom>Risk Trends</Typography>
            {timeSeriesData.length === 0 ? (
              <Typography variant="body2" sx={{ color: '#6b7280' }}>No data yet</Typography>
            ) : (
              <ResponsiveContainer width="100%" height={260}>
                <LineChart data={timeSeriesData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="timeLabel" angle={-30} height={60} />
                  <YAxis />
                  <Tooltip />
                  <Legend />
                  <Line type="monotone" dataKey="risk" name="Risk" stroke="#3b82f6" strokeWidth={2} />
                  {/* <Line type="monotone" dataKey="tlsRisk" name="TLS Risk" stroke="#f59e0b" strokeWidth={2} /> */}
                </LineChart>
              </ResponsiveContainer>
            )}
          </Paper>
          <Paper sx={{ flex: 1, p: 2, minWidth: 400, background: '#020617', color: 'white' }}>
            <Typography variant="h6" gutterBottom>Path Analysis</Typography>
            {pathStats.length === 0 ? (
              <Typography variant="body2" sx={{ color: '#6b7280' }}>No data</Typography>
            ) : (
              <ResponsiveContainer width="100%" height={260}>
                <BarChart data={pathStats.slice(0, 10)}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="path" angle={-30} height={60} />
                  <YAxis />
                  <Tooltip />
                  <Legend />
                  <Bar dataKey="allowed" fill="#10b981" />
                  <Bar dataKey="blocked" fill="#ef4444" />
                </BarChart>
              </ResponsiveContainer>
            )}
          </Paper>
        </Box>

        {/* Live Feed + Simulator */}
        <Box sx={{ display: 'flex', gap: 2, mb: 3, flexWrap: 'wrap' }}>
          <Paper sx={{ flex: 2, p: 2, background: '#020617', color: 'white', fontFamily: 'monospace' }}>
            <Typography variant="h6" gutterBottom>Live Traffic</Typography>
            <Box sx={{ maxHeight: 200, overflowY: 'auto', border: '1px solid #1f2937', p: 1, borderRadius: 1 }}>
              {displayLogs.slice(0, 10).map((entry, idx) => {
                const isAllowed = entry.decision?.allow !== false;
                return (
                  <Box key={idx} sx={{ display: 'flex', gap: 1, mb: 0.5, fontSize: 12 }}>
                    <span style={{ color: '#6b7280' }}>{formatTime(entry.time)}</span>
                    <span>{entry.context?.method} {shortPath(entry.targetPath)}</span>
                    <span>user: {entry.context?.userId}, role: {entry.context?.role}</span>
                    <span style={{ color: isAllowed ? '#4ade80' : '#f87171' }}>
                      {isAllowed ? 'ALLOWED' : 'BLOCKED'}
                    </span>
                    {/* {entry.tls?.risk > 0 && (
                      <Chip label={`TLS:${entry.tls.risk.toFixed(1)}`} size="small" color="warning" />
                    )} */}
                  </Box>
                );
              })}
              {displayLogs.length === 0 && <Typography sx={{ color: '#6b7280' }}>No traffic</Typography>}
            </Box>
          </Paper>

          <Paper sx={{ flex: 1, p: 2, background: '#020617', color: 'white', minWidth: 260 }}>
            <Typography variant="h6" gutterBottom>Simulator</Typography>
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
              <Button fullWidth variant="contained" color="success" onClick={simulateNormalUserInfo}>
                Normal /info
              </Button>
              <Button fullWidth variant="contained" color="warning" onClick={simulateSuspiciousGuestAdmin}>
                Guest /admin
              </Button>
              <Button fullWidth variant="contained" color="error" onClick={simulateGuestAdminRBAC}>
                RBAC Block
              </Button>
            </Box>
          </Paper>
        </Box>

        {/* Tables */}
        <Paper sx={{ p: 2, background: '#020617' }}>
          <Typography variant="h6" color="white" sx={{ mb: 2 }}>
            Firewall Logs ({filteredLogs.length})
          </Typography>
          <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
              {/* Export buttons */}
              <Button
                variant="outlined"
                size="small"
                onClick={() => handleExport("json")}
                sx={{
                  borderColor: "#4b5563",
                  color: "white",
                  "&:hover": { borderColor: "#9ca3af" },
                }}
              >
                Export JSON
              </Button>
              <Button
                variant="outlined"
                size="small"
                onClick={() => handleExport("csv")}
                sx={{
                  borderColor: "#4b5563",
                  color: "white",
                  "&:hover": { borderColor: "#9ca3af" },
                }}
              >
                Export CSV
              </Button>

              {/* Filter buttons */}
              <ToggleButtonGroup
                value={filter}
                exclusive
                onChange={(_, v) => v && setFilter(v)}
                size="small"
                color="primary"
              >
                <ToggleButton
                  value="all"
                  sx={{
                    color: "white",
                    borderColor: "#4b5563",
                    "&.Mui-selected": {
                      backgroundColor: "#2563eb",
                      color: "#fff",
                    },
                  }}
                >
                  ALL
                </ToggleButton>
                <ToggleButton
                  value="allowed"
                  sx={{
                    color: "white",
                    borderColor: "#4b5563",
                    "&.Mui-selected": {
                      backgroundColor: "#16a34a",
                      color: "#fff",
                    },
                  }}
                >
                  ALLOWED
                </ToggleButton>
                <ToggleButton
                  value="blocked"
                  sx={{
                    color: "white",
                    borderColor: "#4b5563",
                    "&.Mui-selected": {
                      backgroundColor: "#b91c1c",
                      color: "#fff",
                    },
                  }}
                >
                  BLOCKED
                </ToggleButton>
              </ToggleButtonGroup>
            </Box>
          <ToggleButtonGroup value={filter} exclusive onChange={(_, v) => v && setFilter(v)} size="small">
            <ToggleButton value="all">ALL</ToggleButton>
            <ToggleButton value="allowed">ALLOWED</ToggleButton>
            <ToggleButton value="blocked">BLOCKED</ToggleButton>
          </ToggleButtonGroup>
          <TableContainer sx={{ maxHeight: 400, mt: 2 }}>
            <Table stickyHeader>
              <TableHead>
                <TableRow>
                  <TableCell sx={{ color: 'white', background: '#111827' }}>Time</TableCell>
                  <TableCell sx={{ color: 'white', background: '#111827' }}>Path</TableCell>
                  <TableCell sx={{ color: 'white', background: '#111827' }}>User</TableCell>
                  <TableCell sx={{ color: 'white', background: '#111827' }}>Risk</TableCell>
                  {/* <TableCell sx={{ color: 'white', background: '#111827' }}>TLS</TableCell> */}
                  <TableCell sx={{ color: 'white', background: '#111827' }}>Decision</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {filteredLogs.map((entry, idx) => (
                  <TableRow key={idx} hover>
                    <TableCell sx={{ color: 'white' }}>{formatTime(entry.time)}</TableCell>
                    <TableCell sx={{ color: 'white' }}>{entry.targetPath}</TableCell>
                    <TableCell sx={{ color: 'white' }}>{entry.context?.userId}</TableCell>
                    <TableCell sx={{ color: 'white' }}>
                      <Chip label={(entry.decision?.risk || 0).toFixed(2)} size="small"
                        color={(entry.decision?.risk || 0) > 0.7 ? 'error' : 'success'} />
                    </TableCell>
                    {/* <TableCell sx={{ color: 'white' }}>
                      {(entry.tls?.risk || 0) > 0 ? (
                        <Chip label={entry.tls.risk.toFixed(2)} size="small" color="warning" />
                      ) : '0.00'}
                    </TableCell> */}
                    <TableCell sx={{ color: 'white' }}>
                      <Chip label={entry.decision?.allow !== false ? 'ALLOWED' : 'BLOCKED'} 
                        color={entry.decision?.allow !== false ? 'success' : 'error'} />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </Paper>
      </Container>
    </>
  );
}

export default App;