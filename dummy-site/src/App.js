import React from 'react';
import axios from 'axios';
import { Container, Typography, Paper, Box, Button, Alert } from '@mui/material';

const TLS_GATEWAY = 'https://localhost:4001';

function App() {
  const [status, setStatus] = React.useState('Ready to test...');
  const [loading, setLoading] = React.useState(false);

  // Configure axios for self-signed TLS + CORS
  axios.defaults.httpsAgent = {
    rejectUnauthorized: false
  };

  const testEndpoint = async (path, label) => {
    setLoading(true);
    setStatus(`Testing ${label}...`);
    
    try {
      const res = await axios.get(`${TLS_GATEWAY}${path}`, {
        headers: { 
          'x-user-id': 'testuser', 
          'x-user-role': 'guest',
          'Accept': 'application/json'
        },
        timeout: 8000
      });
      setStatus(`${label}: ${res.status} - ${JSON.stringify(res.data).slice(0, 80)}...`);
    } catch (err) {
      const status = err.response?.status || 'NETWORK_ERROR';
      const message = err.response?.data?.error || err.message;
      setStatus(`${label}: ${status} - ${message}`);
    } finally {
      setLoading(false);
    }
  };

  const openLogs = () => {
    window.open(`${TLS_GATEWAY}/admin/logs`, '_blank');
  };

  return (
    <Container maxWidth="md" sx={{ mt: 4, p: 3 }}>
      <Paper sx={{ p: 4, textAlign: 'center', background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)', color: 'white' }}>
        <Typography variant="h3" gutterBottom>
          Dummy Site (Protected by AI-NGFW)
        </Typography>
        <Typography variant="h6" sx={{ mb: 4 }}>
          Proxy: https://localhost:4001 | Backend: https://localhost:9001
        </Typography>
        
        <Alert severity="info" sx={{ mb: 3, justifyContent: 'center' }}>
          <Typography variant="body2">
            All traffic → Decrypted → DPI → Re-encrypted → Backend
          </Typography>
        </Alert>

        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, maxWidth: 500, mx: 'auto' }}>
          <Button 
            fullWidth 
            variant="contained" 
            size="large"
            onClick={() => testEndpoint('/fw/info', 'Normal Access')}
            disabled={loading}
            sx={{ py: 2 }}
          >
            Test Normal /info (Should PASS)
          </Button>
          
          <Button 
            fullWidth 
            variant="contained" 
            color="warning"
            size="large"
            onClick={() => testEndpoint('/fw/admin/secret', 'Admin Access')}
            disabled={loading}
            sx={{ py: 2 }}
          >
            Test Admin /secret (Should BLOCK)
          </Button>
          
          <Button 
            fullWidth 
            variant="contained" 
            color="error"
            size="large"
            onClick={() => testEndpoint('/fw/honeypot/db-export', 'Honeypot Trap')}
            disabled={loading}
            sx={{ py: 2 }}
          >
            Test Honeypot (Should BLOCK)
          </Button>
          
          <Button 
            fullWidth 
            variant="outlined" 
            size="large"
            onClick={openLogs}
            disabled={loading}
            sx={{ py: 2, borderColor: 'white', color: 'white', '&:hover': { borderColor: 'white' } }}
          >
            Open Firewall Logs
          </Button>
        </Box>

        <Paper sx={{ mt: 4, p: 3, background: '#f8fafc' }}>
          <Typography variant="h6" gutterBottom color="textSecondary">
            Latest Test:
          </Typography>
          <Box sx={{ p: 2, background: '#e2e8f0', borderRadius: 1, minHeight: 60, display: 'flex', alignItems: 'center' }}>
            <Typography variant="body1" sx={{ fontFamily: 'monospace', fontSize: 14 }}>
              {status}
            </Typography>
          </Box>
          <Typography variant="caption" sx={{ mt: 1, display: 'block', color: 'text.secondary' }}>
            Expected: Normal=200 | Admin=403 | Honeypot=403
          </Typography>
        </Paper>
      </Paper>
    </Container>
  );
}

export default App;
