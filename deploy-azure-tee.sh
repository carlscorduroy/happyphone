#!/bin/bash
set -e

# Configuration
RESOURCE_GROUP="happyphone-tee"
LOCATION="eastus"
VM_NAME="happyphone-signal-tee"
VM_SIZE="Standard_DC4as_v5"
IMAGE="Canonical:0001-com-ubuntu-confidential-vm-jammy:22_04-lts-cvm:latest"
ADMIN_USER="azureuser"

echo "=== Deploying Happy Phone to Azure Confidential Computing ==="
echo ""
echo "Configuration:"
echo "  Resource Group: $RESOURCE_GROUP"
echo "  Location: $LOCATION"
echo "  VM Size: $VM_SIZE (4 vCPUs, 16GB RAM, AMD SEV-SNP)"
echo "  OS: Ubuntu 22.04 LTS (Confidential VM image)"
echo ""

# Create resource group
echo "Step 1: Creating resource group..."
az group create \
  --name $RESOURCE_GROUP \
  --location $LOCATION \
  --output table

# Create network security group
echo ""
echo "Step 2: Creating network security group..."
az network nsg create \
  --resource-group $RESOURCE_GROUP \
  --name happyphone-nsg \
  --output table

# Add security rules
echo ""
echo "Step 3: Adding security rules..."
# SSH
az network nsg rule create \
  --resource-group $RESOURCE_GROUP \
  --nsg-name happyphone-nsg \
  --name AllowSSH \
  --priority 1000 \
  --destination-port-ranges 22 \
  --protocol Tcp \
  --access Allow \
  --output table

# HTTPS/WSS
az network nsg rule create \
  --resource-group $RESOURCE_GROUP \
  --nsg-name happyphone-nsg \
  --name AllowHTTPS \
  --priority 1001 \
  --destination-port-ranges 443 \
  --protocol Tcp \
  --access Allow \
  --output table

# HTTP (for Let's Encrypt)
az network nsg rule create \
  --resource-group $RESOURCE_GROUP \
  --nsg-name happyphone-nsg \
  --name AllowHTTP \
  --priority 1002 \
  --destination-port-ranges 80 \
  --protocol Tcp \
  --access Allow \
  --output table

# TURN server
az network nsg rule create \
  --resource-group $RESOURCE_GROUP \
  --nsg-name happyphone-nsg \
  --name AllowTURN \
  --priority 1003 \
  --destination-port-ranges 3478 \
  --protocol Udp \
  --access Allow \
  --output table

# Create public IP
echo ""
echo "Step 4: Creating public IP..."
az network public-ip create \
  --resource-group $RESOURCE_GROUP \
  --name happyphone-public-ip \
  --sku Standard \
  --allocation-method Static \
  --output table

# Get the IP address
PUBLIC_IP=$(az network public-ip show \
  --resource-group $RESOURCE_GROUP \
  --name happyphone-public-ip \
  --query ipAddress -o tsv)

echo ""
echo "Public IP allocated: $PUBLIC_IP"
echo "IMPORTANT: Update DNS to point signal.happy.land to $PUBLIC_IP"
echo ""

# Create virtual network
echo "Step 5: Creating virtual network..."
az network vnet create \
  --resource-group $RESOURCE_GROUP \
  --name happyphone-vnet \
  --subnet-name happyphone-subnet \
  --output table

# Create network interface
echo ""
echo "Step 6: Creating network interface..."
az network nic create \
  --resource-group $RESOURCE_GROUP \
  --name happyphone-nic \
  --vnet-name happyphone-vnet \
  --subnet happyphone-subnet \
  --public-ip-address happyphone-public-ip \
  --network-security-group happyphone-nsg \
  --output table

# Generate SSH key if it doesn't exist
if [ ! -f ~/.ssh/happyphone-tee ]; then
  echo ""
  echo "Step 7: Generating SSH key..."
  ssh-keygen -t rsa -b 4096 -f ~/.ssh/happyphone-tee -N "" -C "happyphone-tee"
fi

# Create the Confidential VM
echo ""
echo "Step 8: Creating Confidential Computing VM..."
echo "This may take 5-10 minutes..."
az vm create \
  --resource-group $RESOURCE_GROUP \
  --name $VM_NAME \
  --size $VM_SIZE \
  --image $IMAGE \
  --admin-username $ADMIN_USER \
  --ssh-key-values ~/.ssh/happyphone-tee.pub \
  --nics happyphone-nic \
  --security-type ConfidentialVM \
  --os-disk-security-encryption-type VMGuestStateOnly \
  --enable-secure-boot true \
  --enable-vtpm true \
  --output table

echo ""
echo "=== Deployment Complete! ==="
echo ""
echo "VM Details:"
echo "  Name: $VM_NAME"
echo "  Public IP: $PUBLIC_IP"
echo "  SSH Key: ~/.ssh/happyphone-tee"
echo ""
echo "Next steps:"
echo "1. Update DNS: point signal.happy.land to $PUBLIC_IP"
echo "2. SSH into VM: ssh -i ~/.ssh/happyphone-tee $ADMIN_USER@$PUBLIC_IP"
echo "3. Run setup script to install Node.js and deploy server"
echo ""
echo "SSH command:"
echo "  ssh -i ~/.ssh/happyphone-tee $ADMIN_USER@$PUBLIC_IP"
echo ""
