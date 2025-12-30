/**
 * Happy Phone Signaling Server
 * 
 * Zero-knowledge relay server that:
 * - Registers users by their user ID
 * - Routes encrypted payloads between clients
 * - Tracks online status
 * - Cannot decrypt messages
 * - Provides TEE attestation endpoint
 */

const express = require('express');
const { createServer } = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const { execSync } = require('child_process');
const fs = require('fs');

const app = express();
const httpServer = createServer(app);
const io = new Server(httpServer, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST']
  }
});

const PORT = process.env.PORT || 3000;

// User registry: userId -> { socket, publicKey, displayName }
const users = new Map();

// Middleware
app.use(cors());
app.use(express.json());

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    users: users.size,
    timestamp: new Date().toISOString(),
    tee: getTEEStatus()
  });
});

// TEE Attestation endpoint (GET - basic info)
app.get('/attestation', async (req, res) => {
  try {
    const attestation = await getAttestation();
    res.json(attestation);
  } catch (error) {
    res.status(500).json({
      error: 'Failed to get attestation',
      message: error.message,
      teeAvailable: false
    });
  }
});

// TEE Attestation endpoint (POST - with challenge-response for crypto verification)
app.post('/attestation', express.json(), async (req, res) => {
  try {
    const { nonce } = req.body;
    const attestation = await getAttestation(nonce);
    res.json(attestation);
  } catch (error) {
    res.status(500).json({
      error: 'Failed to get attestation',
      message: error.message,
      teeAvailable: false
    });
  }
});

// Cache TEE status
let cachedTEEStatus = null;

/**
 * Check if running in a TEE
 */
function getTEEStatus() {
  if (cachedTEEStatus !== null) return cachedTEEStatus;
  
  try {
    // Check Azure IMDS for confidential VM (most reliable)
    try {
      const metadata = execSync(
        'curl -s -H "Metadata:true" "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01"',
        { encoding: 'utf8', timeout: 2000 }
      );
      const compute = JSON.parse(metadata);
      // DCasv5/DCadsv5 are AMD SEV-SNP confidential VMs
      if (compute.vmSize && compute.vmSize.includes('DC') && compute.vmSize.includes('as')) {
        cachedTEEStatus = 'sev-snp';
        return cachedTEEStatus;
      }
      // Check for CVM image SKU
      if (compute.sku && compute.sku.includes('cvm')) {
        cachedTEEStatus = 'sev-snp';
        return cachedTEEStatus;
      }
    } catch {}

    // Check for AMD SEV via /proc/cpuinfo (doesn't need root)
    try {
      const cpuinfo = fs.readFileSync('/proc/cpuinfo', 'utf8');
      if (cpuinfo.includes('sev_snp') || cpuinfo.includes('sev')) {
        cachedTEEStatus = 'sev';
        return cachedTEEStatus;
      }
    } catch {}

    // Check sev-guest device
    if (fs.existsSync('/dev/sev-guest')) {
      cachedTEEStatus = 'sev-guest';
      return cachedTEEStatus;
    }
    
    cachedTEEStatus = 'none';
    return cachedTEEStatus;
  } catch {
    cachedTEEStatus = 'none';
    return cachedTEEStatus;
  }
}

/**
 * Get hardware attestation report
 * @param {string} nonceB64 - Base64-encoded 64-byte nonce from client (optional)
 */
async function getAttestation(nonceB64 = null) {
  const teeStatus = getTEEStatus();
  
  const attestation = {
    teeType: teeStatus,
    timestamp: new Date().toISOString(),
    serverVersion: '1.0.0',
  };

  if (teeStatus === 'none') {
    attestation.warning = 'Server is NOT running in a Trusted Execution Environment';
    return attestation;
  }

  try {
    // Try to get SEV-SNP attestation report with client's nonce
    if (fs.existsSync('/dev/sev-guest')) {
      let reportCmd;
      
      if (nonceB64) {
        // Client provided a nonce - include it in the report request
        // The nonce goes into the report_data field (64 bytes)
        // This proves freshness and prevents replay attacks
        const reportDataFile = '/tmp/snp_report_data_' + process.pid;
        
        try {
          // Decode nonce and pad to 64 bytes
          const nonceBuffer = Buffer.from(nonceB64, 'base64');
          const reportData = Buffer.alloc(64);
          nonceBuffer.copy(reportData, 0, 0, Math.min(nonceBuffer.length, 64));
          fs.writeFileSync(reportDataFile, reportData);
          
          // Request report with custom report_data
          // Using snpguest tool from virtee/snpguest
          reportCmd = `snpguest report ${reportDataFile} /tmp/snp_report_${process.pid}.bin 2>/dev/null && ` +
                      `base64 /tmp/snp_report_${process.pid}.bin && ` +
                      `rm -f ${reportDataFile} /tmp/snp_report_${process.pid}.bin`;
        } catch (e) {
          console.error('Failed to create report data file:', e);
        }
      } else {
        // No nonce - just get a report (less secure, can be replayed)
        reportCmd = 'snpguest report /dev/null /tmp/snp_report.bin 2>/dev/null && ' +
                    'base64 /tmp/snp_report.bin && ' +
                    'rm -f /tmp/snp_report.bin';
      }
      
      if (reportCmd) {
        try {
          const reportB64 = execSync(reportCmd, { encoding: 'utf8', timeout: 5000 });
          if (reportB64 && reportB64.trim()) {
            attestation.report = reportB64.trim();
            attestation.reportType = 'sev-snp';
          }
        } catch (e) {
          // snpguest not available, try sev-guest-get-report
          try {
            const report = execSync('sev-guest-get-report 2>/dev/null', { encoding: 'utf8' });
            if (report && !report.includes('report_unavailable')) {
              attestation.report = Buffer.from(report.trim()).toString('base64');
              attestation.reportType = 'sev-snp';
            }
          } catch {
            // No report tool available
            attestation.reportError = 'SNP report tool not available (install snpguest)';
          }
        }
      }
      
      // Try to get VCEK certificate from host memory (Azure provides this)
      try {
        if (fs.existsSync('/var/run/amd-sev/vcek.pem')) {
          attestation.vcek = fs.readFileSync('/var/run/amd-sev/vcek.pem', 'utf8');
        } else {
          // Try to fetch from extended guest request
          const vcekCmd = 'snpguest fetch vcek pem /tmp/vcek_${PID} 2>/dev/null && ' +
                          'cat /tmp/vcek_${PID}/vcek.pem && ' +
                          'rm -rf /tmp/vcek_${PID}';
          try {
            const vcek = execSync(vcekCmd.replace(/\$\{PID\}/g, process.pid), { encoding: 'utf8', timeout: 10000 });
            if (vcek && vcek.includes('BEGIN CERTIFICATE')) {
              attestation.vcek = vcek.trim();
            }
          } catch {}
        }
      } catch {}
    }

    // Get VM metadata from Azure IMDS
    try {
      const metadata = execSync(
        'curl -s -H "Metadata:true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"',
        { encoding: 'utf8', timeout: 5000 }
      );
      const vmInfo = JSON.parse(metadata);
      attestation.vm = {
        vmId: vmInfo.compute?.vmId,
        vmSize: vmInfo.compute?.vmSize,
        location: vmInfo.compute?.location,
        securityProfile: vmInfo.compute?.securityProfile
      };
    } catch {
      // IMDS not available
    }

    // Get boot measurements if available
    if (fs.existsSync('/sys/kernel/security/tpm0/binary_bios_measurements')) {
      attestation.measurementsAvailable = true;
    }

  } catch (error) {
    attestation.attestationError = error.message;
  }

  return attestation;
}

// Socket.IO connection handling
io.on('connection', (socket) => {
  console.log(`[${new Date().toISOString()}] Client connected: ${socket.id}`);

  // Register user
  socket.on('register', (data) => {
    const { userId, publicKey, displayName } = data;
    
    if (!userId) {
      socket.emit('error', { message: 'userId is required' });
      return;
    }

    // Store user
    users.set(userId, {
      socket,
      socketId: socket.id,
      publicKey,
      displayName,
      registeredAt: new Date().toISOString()
    });

    socket.userId = userId;
    console.log(`[${new Date().toISOString()}] User registered: ${userId}`);
    
    socket.emit('registered', { userId });
  });

  // Relay encrypted message
  socket.on('message', (data) => {
    const { to, payload, type } = data;
    const from = socket.userId;

    if (!from) {
      socket.emit('error', { message: 'Not registered' });
      return;
    }

    const recipient = users.get(to);
    if (recipient) {
      recipient.socket.emit('message', { from, payload, type });
      console.log(`[${new Date().toISOString()}] Message relayed: ${from} -> ${to}`);
    } else {
      socket.emit('error', { message: 'User offline', userId: to });
    }
  });

  // Contact request
  socket.on('contact-request', (data) => {
    const { to, challenge, payload } = data;
    const from = socket.userId;

    const recipient = users.get(to);
    if (recipient) {
      recipient.socket.emit('contact-request', { from, challenge, payload });
      console.log(`[${new Date().toISOString()}] Contact request: ${from} -> ${to}`);
    }
  });

  // Contact response
  socket.on('contact-response', (data) => {
    const { to, response, payload } = data;
    const from = socket.userId;

    const recipient = users.get(to);
    if (recipient) {
      recipient.socket.emit('contact-response', { from, response, payload });
      console.log(`[${new Date().toISOString()}] Contact response: ${from} -> ${to}`);
    }
  });

  // Call offer (WebRTC signaling)
  socket.on('call-offer', (data) => {
    const { to, offer, payload } = data;
    const from = socket.userId;

    const recipient = users.get(to);
    if (recipient) {
      recipient.socket.emit('call-offer', { from, offer, payload });
      console.log(`[${new Date().toISOString()}] Call offer: ${from} -> ${to}`);
    }
  });

  // Call answer
  socket.on('call-answer', (data) => {
    const { to, answer, payload } = data;
    const from = socket.userId;

    const recipient = users.get(to);
    if (recipient) {
      recipient.socket.emit('call-answer', { from, answer, payload });
      console.log(`[${new Date().toISOString()}] Call answer: ${from} -> ${to}`);
    }
  });

  // ICE candidate
  socket.on('ice-candidate', (data) => {
    const { to, candidate } = data;
    const from = socket.userId;

    const recipient = users.get(to);
    if (recipient) {
      recipient.socket.emit('ice-candidate', { from, candidate });
    }
  });

  // Call end
  socket.on('call-end', (data) => {
    const { to } = data;
    const from = socket.userId;

    const recipient = users.get(to);
    if (recipient) {
      recipient.socket.emit('call-end', { from });
      console.log(`[${new Date().toISOString()}] Call ended: ${from} -> ${to}`);
    }
  });

  // Check online status
  socket.on('check-online', (data) => {
    const { userId } = data;
    const isOnline = users.has(userId);
    socket.emit('online-status', { userId, online: isOnline });
  });

  // Disconnect
  socket.on('disconnect', () => {
    if (socket.userId) {
      users.delete(socket.userId);
      console.log(`[${new Date().toISOString()}] User disconnected: ${socket.userId}`);
    }
  });
});

// Start server
httpServer.listen(PORT, () => {
  console.log(`
╔════════════════════════════════════════════════════════════╗
║          Happy Phone Signaling Server                      ║
╠════════════════════════════════════════════════════════════╣
║  Port: ${PORT}                                               ║
║  TEE Status: ${getTEEStatus().padEnd(43)}║
║  Started: ${new Date().toISOString()}            ║
╚════════════════════════════════════════════════════════════╝
  `);
});
