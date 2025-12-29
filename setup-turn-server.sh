#!/bin/bash
set -e

echo "=== Installing coturn TURN server on Azure VM ==="
echo ""

# Update system
echo "Step 1: Updating system..."
sudo apt-get update
sudo apt-get upgrade -y

# Install coturn
echo ""
echo "Step 2: Installing coturn..."
sudo apt-get install -y coturn

# Generate a secure shared secret
echo ""
echo "Step 3: Generating secure credentials..."
TURN_SECRET=$(openssl rand -hex 32)
TURN_USER="happyphone"
echo "TURN Username: $TURN_USER"
echo "TURN Secret: $TURN_SECRET"
echo ""
echo "Save these credentials! You'll need them for your clients."

# Get public IP
PUBLIC_IP=$(curl -s ifconfig.me)
echo "Public IP: $PUBLIC_IP"

# Backup original config
sudo cp /etc/turnserver.conf /etc/turnserver.conf.backup

# Create coturn configuration
echo ""
echo "Step 4: Configuring coturn..."
sudo tee /etc/turnserver.conf > /dev/null <<EOF
# TURN server name and realm
realm=signal.happy.land
server-name=signal.happy.land

# Listening interfaces
listening-port=3478
listening-ip=0.0.0.0

# External IP (for cloud deployments)
external-ip=$PUBLIC_IP

# Enable long-term credentials mechanism
lt-cred-mech

# User credentials
user=$TURN_USER:$TURN_SECRET

# Enable fingerprints in TURN messages
fingerprint

# Logging
log-file=/var/log/turnserver.log
verbose

# Security options
no-multicast-peers
no-cli
no-loopback-peers
no-tcp-relay

# Quotas
max-bps=1000000
total-quota=100
stale-nonce=600

# SSL/TLS (optional, for secure TURN)
# cert=/etc/letsencrypt/live/signal.happy.land/fullchain.pem
# pkey=/etc/letsencrypt/live/signal.happy.land/privkey.pem
# cipher-list="ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512"

# Deny private IP ranges (optional security)
denied-peer-ip=10.0.0.0-10.255.255.255
denied-peer-ip=192.168.0.0-192.168.255.255
denied-peer-ip=172.16.0.0-172.31.255.255
EOF

# Enable coturn service
echo ""
echo "Step 5: Enabling coturn service..."
sudo sed -i 's/#TURNSERVER_ENABLED=1/TURNSERVER_ENABLED=1/' /etc/default/coturn

# Start coturn
echo ""
echo "Step 6: Starting coturn..."
sudo systemctl enable coturn
sudo systemctl restart coturn

# Check status
echo ""
echo "Step 7: Checking status..."
sudo systemctl status coturn --no-pager

echo ""
echo "=== Installation Complete! ==="
echo ""
echo "TURN Server Details:"
echo "  URL: turn:signal.happy.land:3478"
echo "  Username: $TURN_USER"
echo "  Secret: $TURN_SECRET"
echo ""
echo "Next steps:"
echo "1. Open UDP port 3478 in Azure NSG (Network Security Group)"
echo "2. Configure clients with these environment variables:"
echo "   export HAPPYPHONE_TURN_SERVER=turn:signal.happy.land:3478"
echo "   export HAPPYPHONE_TURN_USER=$TURN_USER"
echo "   export HAPPYPHONE_TURN_PASS=$TURN_SECRET"
echo ""
echo "Test TURN server:"
echo "  sudo tail -f /var/log/turnserver.log"
echo ""
