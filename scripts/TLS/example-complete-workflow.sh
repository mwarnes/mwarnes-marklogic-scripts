#!/bin/bash

# ================================================================
# Example: Complete Certificate Workflow
# ================================================================
#
# This example demonstrates the complete workflow:
# 1. Create a Certificate Authority (CA)
# 2. Generate a server CSR for oauth.warnesnet.com
# 3. Generate a client CSR for user authentication
# 4. Sign both CSRs with the CA
#
# ================================================================

set -e

# Navigate to the TLS scripts directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "==================================================================="
echo "Complete Certificate Workflow Example"
echo "==================================================================="
echo

# Step 1: Create Certificate Authority
echo "Step 1: Creating Certificate Authority..."
./generate-ca-certificate.sh create-ca \
    --cn "Test-CA" \
    --org "Example Corp" \
    --country "US" \
    --password "ca-password123"

echo
echo "Step 2: Generating server certificate for oauth.warnesnet.com..."
./generate-csr.sh server-csr \
    --cn "oauth.warnesnet.com" \
    --org "MarkLogic Corp" \
    --dns "oauth.warnesnet.com,*.oauth.warnesnet.com" \
    --ip "172.16.10.42" \
    --no-encrypt

echo
echo "Step 3: Signing server certificate with CA..."
./generate-ca-certificate.sh sign-csr \
    --ca-cert ca-certificate.pem \
    --ca-key ca-private-key.pem \
    --csr oauth.warnesnet.com.csr \
    --output oauth.warnesnet.com-certificate.pem \
    --password "ca-password123"

echo
echo "Step 4: Generating client certificate for user authentication..."
./generate-csr.sh client-csr \
    --cn "john.doe" \
    --email "john.doe@example.com" \
    --org "Example Corp" \
    --no-encrypt

echo
echo "Step 5: Signing client certificate with CA..."
./generate-ca-certificate.sh sign-csr \
    --ca-cert ca-certificate.pem \
    --ca-key ca-private-key.pem \
    --csr john.doe.csr \
    --output john.doe-certificate.pem \
    --password "ca-password123"

echo
echo "==================================================================="
echo "Certificate Workflow Complete!"
echo "==================================================================="
echo "Files created:"
echo
echo "Certificate Authority:"
echo "  ca-private-key.pem         (CA private key - keep secure!)"
echo "  ca-certificate.pem         (CA certificate - share with clients)"
echo "  ca-bundle.pem              (CA bundle)"
echo
echo "Server Certificate (oauth.warnesnet.com):"
echo "  oauth.warnesnet.com-private-key.pem"
echo "  oauth.warnesnet.com.csr"
echo "  oauth.warnesnet.com-certificate.pem"
echo
echo "Client Certificate (john.doe):"
echo "  john.doe-private-key.pem"
echo "  john.doe.csr"
echo "  john.doe-certificate.pem"
echo
echo "Next steps:"
echo "1. Install CA certificate in client trust stores"
echo "2. Configure MarkLogic with server certificate"
echo "3. Use client certificate for authentication"
echo