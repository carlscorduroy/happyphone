#!/bin/bash
set -e

echo "=== Opening TURN server port in Azure NSG ==="
echo ""

# Your Azure configuration
RESOURCE_GROUP="HAPPYPHONE-SIGNAL-TEE_GROUP"
NSG_NAME="happyphone-signal-tee-nsg"

echo "Configuration:"
echo "  Resource Group: $RESOURCE_GROUP"
echo "  NSG: $NSG_NAME"
echo ""

# Check if Azure CLI is installed
if ! command -v az &> /dev/null; then
    echo "❌ Azure CLI not found. Install with: brew install azure-cli"
    exit 1
fi

# Check if logged in
echo "Step 1: Checking Azure login..."
if ! az account show &> /dev/null; then
    echo "Not logged in. Logging in..."
    az login
else
    echo "✓ Already logged in"
fi

# Add UDP rule for TURN
echo ""
echo "Step 2: Adding UDP port 3478 rule..."
az network nsg rule create \
  --resource-group $RESOURCE_GROUP \
  --nsg-name $NSG_NAME \
  --name AllowTURN \
  --priority 1003 \
  --destination-port-ranges 3478 \
  --protocol Udp \
  --access Allow \
  --description "TURN server for WebRTC NAT traversal" \
  --output table

echo ""
echo "✅ Firewall rule added!"
echo ""
echo "TURN port 3478/UDP is now open."
echo ""
echo "To verify:"
echo "  az network nsg rule list --resource-group $RESOURCE_GROUP --nsg-name $NSG_NAME --output table"
echo ""
