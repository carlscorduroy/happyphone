#!/bin/bash
set -e

echo "=== Setting up Happy Phone Signaling Server in TEE ==="
echo ""

# Update system
echo "Step 1: Updating system packages..."
sudo apt-get update
sudo apt-get upgrade -y

# Install Node.js 20 LTS
echo ""
echo "Step 2: Installing Node.js 20 LTS..."
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# Install build tools
echo ""
echo "Step 3: Installing build tools..."
sudo apt-get install -y build-essential git nginx certbot python3-certbot-nginx

# Install SEV-SNP attestation tools
echo ""
echo "Step 4: Installing AMD SEV-SNP attestation tools..."
sudo apt-get install -y linux-modules-extra-$(uname -r)

# Verify we're in a Confidential VM
echo ""
echo "Step 5: Verifying Confidential VM..."
if [ -d /sys/kernel/security/cvm ]; then
    echo "✓ Running in Confidential VM"
    ls -la /sys/kernel/security/cvm/ || true
else
    echo "⚠ Warning: Not detected as Confidential VM"
fi

# Create app user
echo ""
echo "Step 6: Creating happyphone user..."
sudo useradd -r -s /bin/bash -d /opt/happyphone -m happyphone || echo "User already exists"

# Clone/prepare server code
echo ""
echo "Step 7: Setting up server directory..."
sudo mkdir -p /opt/happyphone-signal
sudo chown happyphone:happyphone /opt/happyphone-signal

echo ""
echo "=== Initial Setup Complete ==="
echo ""
echo "Next steps:"
echo "1. Copy your signaling server code to /opt/happyphone-signal"
echo "2. Run the deployment script to install dependencies and start server"
echo "3. Configure nginx and SSL certificates"
echo ""
echo "To transfer server code from local machine:"
echo "  scp -i ~/.ssh/happyphone-tee -r /opt/happyphone-signal/* azureuser@\$(cat /tmp/azure-tee-ip.txt):/tmp/"
echo "  ssh -i ~/.ssh/happyphone-tee azureuser@\$(cat /tmp/azure-tee-ip.txt) 'sudo mv /tmp/happyphone-signal/* /opt/happyphone-signal/ && sudo chown -R happyphone:happyphone /opt/happyphone-signal'"
echo ""
