#!/bin/bash

# ================================================================
# MarkLogic TLS Client Certificate Testing
# ================================================================
#
# This example demonstrates generating client certificates specifically
# for MarkLogic certificate-based authentication testing.
#
# These certificates are configured with:
# - Extended Key Usage: TLS Web Client Authentication (clientAuth)
# - NO server authentication capabilities
# - Email in Subject Alternative Name for user identification
#
# Perfect for testing MarkLogic's certificate-based authentication.
# ================================================================

set -e

# Navigate to the TLS scripts directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "==================================================================="
echo "MarkLogic Client Certificate Authentication Setup"
echo "==================================================================="
echo

# Ensure we have a CA
if [ ! -f "ca-certificate.pem" ] || [ ! -f "ca-private-key.pem" ]; then
    echo "Step 1: Creating Certificate Authority for MarkLogic testing..."
    ./generate-ca-certificate.sh create-ca \
        --cn "MarkLogic-Test-CA" \
        --org "MarkLogic Security Testing" \
        --country "US" \
        --password "marklogic123"
    echo
else
    echo "Step 1: Using existing Certificate Authority..."
    echo
fi

# Generate client certificate for user authentication
echo "Step 2: Generating client certificate for MarkLogic authentication..."
./generate-csr.sh client-csr \
    --cn "john.doe" \
    --email "john.doe@marklogic.com" \
    --org "MarkLogic Corp" \
    --ou "Engineering" \
    --no-encrypt

echo
echo "Step 3: Signing client certificate with CA..."
./generate-ca-certificate.sh sign-csr \
    --ca-cert ca-certificate.pem \
    --ca-key ca-private-key.pem \
    --csr john.doe.csr \
    --output john.doe-client-certificate.pem \
    --password "testpass123"

echo
echo "Step 4: Generating additional test user certificate..."
./generate-csr.sh client-csr \
    --cn "jane.smith" \
    --email "jane.smith@marklogic.com" \
    --org "MarkLogic Corp" \
    --ou "QA" \
    --no-encrypt

./generate-ca-certificate.sh sign-csr \
    --ca-cert ca-certificate.pem \
    --ca-key ca-private-key.pem \
    --csr jane.smith.csr \
    --output jane.smith-client-certificate.pem \
    --password "testpass123"

echo
echo "==================================================================="
echo "MarkLogic Client Certificates Generated Successfully!"
echo "==================================================================="
echo
echo "Files created for MarkLogic testing:"
echo
echo "Certificate Authority:"
echo "  ca-certificate.pem                    (Install in MarkLogic trust store)"
echo "  ca-bundle.pem                         (CA bundle for client trust stores)"
echo
echo "Client Certificate 1 (john.doe):"
echo "  john.doe-private-key.pem              (Client private key)"
echo "  john.doe.csr                          (Certificate request)"
echo "  john.doe-client-certificate.pem       (Client certificate)"
echo
echo "Client Certificate 2 (jane.smith):"
echo "  jane.smith-private-key.pem            (Client private key)"
echo "  jane.smith.csr                        (Certificate request)"
echo "  jane.smith-client-certificate.pem     (Client certificate)"
echo
echo "==================================================================="
echo "MarkLogic Configuration Steps:"
echo "==================================================================="
echo
echo "1. Install CA Certificate in MarkLogic:"
echo "   - Admin UI → Security → Certificate Authorities"
echo "   - Import ca-certificate.pem"
echo "   - Name: 'Test-Client-CA'"
echo
echo "2. Create Certificate Template:"
echo "   - Admin UI → Security → Certificate Templates"
echo "   - Name: 'client-cert-template'"
echo "   - Certificate Authority: 'Test-Client-CA'"
echo
echo "3. Configure App Server for Client Authentication:"
echo "   - Admin UI → Configure → App Servers → [Your App Server]"
echo "   - SSL Client Certificate Authorities: 'Test-Client-CA'"
echo "   - SSL Client Certificate: 'required' or 'optional'"
echo
echo "4. Create External Security Objects (if using LDAP/AD):"
echo "   - Map certificate subjects to LDAP users"
echo "   - Configure certificate-to-user mapping"
echo
echo "==================================================================="
echo "Testing Commands:"
echo "==================================================================="
echo
echo "# Test client certificate with curl:"
echo "curl -v https://your-marklogic-server:8443/path \\"
echo "  --cert john.doe-client-certificate.pem \\"
echo "  --key john.doe-private-key.pem \\"
echo "  --cacert ca-certificate.pem"
echo
echo "# Verify certificate has client authentication:"
echo "openssl x509 -text -noout -in john.doe-client-certificate.pem | grep -A 5 'Extended Key Usage'"
echo
echo "# Create PKCS#12 bundle for browser import:"
echo "openssl pkcs12 -export -out john.doe-client.p12 \\"
echo "  -inkey john.doe-private-key.pem \\"
echo "  -in john.doe-client-certificate.pem \\"
echo "  -certfile ca-certificate.pem"
echo