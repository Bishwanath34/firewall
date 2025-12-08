const https = require('https');
const express = require('express');
const cors = require('cors');
const fs = require('fs');
const pem = require('pem');

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.raw({ type: '*/*' })); // Accept all content types

// Generate self-signed cert for backend (one-time)
async function ensureCerts() {
  return new Promise((resolve, reject) => {
    if (fs.existsSync('backend-cert.pem') && fs.existsSync('backend-key.pem')) {
      resolve();
    } else {
      pem.createCertificate({ days: 365, selfSigned: true, keyBits: 2048, commonName: 'localhost' }, (err, keys) => {
        if (err) return reject(err);
        fs.writeFileSync('backend-key.pem', keys.serviceKey);
        fs.writeFileSync('backend-cert.pem', keys.certificate);
        console.log('✓ Backend TLS certs generated');
        resolve();
      });
    }
  });
}

app.get('/info', (req, res) => {
  res.json({
    service: 'Dummy Backend Info',
    version: '1.0',
    time: new Date().toISOString(),
    user: req.headers['x-user-id'] || 'anonymous'
  });
});

app.get('/profile', (req, res) => {
  res.json({
    user: req.headers['x-user-id'] || 'anonymous',
    role: req.headers['x-user-role'] || 'guest',
    bio: 'This is dummy profile data protected by the firewall.',
    timestamp: new Date().toISOString()
  });
});

app.get('/admin/secret', (req, res) => {
  console.log('ADMIN SECRET accessed by:', req.headers['x-user-id'], req.headers['x-user-role']);
  res.json({
    secret: 'TOP SECRET ADMIN DATA',
    note: 'If you see this as guest, firewall rules are bypassed!',
    sensitive: true,
    timestamp: new Date().toISOString()
  });
});

app.get('/honeypot/db-export', (req, res) => {
  console.log('HONEYPOT TRAPPED:', req.headers['x-user-id'], req.socket.remoteAddress);
  res.json({
    warning: 'Honeypot endpoint accessed!',
    message: 'This simulates a sensitive DB export endpoint.',
    fakeDump: {
      dbPassword: 'fakeadminpass',
      privateKey: 'FAKEPRIVATEKEYABC123',
      envFile: 'APIKEY=fakekey123'
    },
    rowsLeaked: 5000,
    timestamp: new Date().toISOString()
  });
});

app.use((req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    path: req.path,
    method: req.method
  });
});

async function startServer() {
  await ensureCerts();

  const tlsOptions = {
    key: fs.readFileSync('backend-key.pem'),
    cert: fs.readFileSync('backend-cert.pem'),
    requestCert: false,
    rejectUnauthorized: false
  };

  https.createServer(tlsOptions, app).listen(9001, () => {
    console.log('🚀 Dummy Backend (TLS-ONLY) running at https://localhost:9001');
    console.log('Available endpoints: /info, /profile, /admin/secret, /honeypot/db-export');
    console.log('Remember to trust backend cert in browser/OS');
  });
}

startServer().catch(console.error);
