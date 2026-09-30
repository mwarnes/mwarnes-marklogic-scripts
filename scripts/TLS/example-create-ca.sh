#!/bin/bash

# ================================================================
# Example: Create CA for ca1.example.com
# ================================================================
#
# This example shows how to create a Certificate Authority (CA)
# for ca1.example.com with CN=CA1 as requested.
#
# The generated CA can be used to sign certificate requests for
# testing and development purposes.
#
# ================================================================

set -e

# Navigate to the TLS scripts directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "==================================================================="
echo "Creating Certificate Authority for ca1.example.com (CN=CA1)"
echo "==================================================================="
echo

# Create CA with default settings for ca1.example.com
echo "Creating CA certificate with the following attributes:"
echo "  Common Name: CA1"
echo "  Organization: Example Corp"
echo "  Locality: Example City"
echo "  Country: US"
echo "  Email: ca@example.com"
echo

# Generate the CA
./generate-ca-certificate.sh create-ca \
    --cn "CA1" \
    --org "Example Corp" \
    --locality "Example City" \
    --country "US" \
    --email "ca@example.com" \
    --key-size 2048 \
    --validity 3650

echo
echo "==================================================================="
echo "CA Certificate created successfully!"
echo "==================================================================="
echo "Files created:"
echo "  - ca-private-key.pem  (Keep this secure and backed up!)"
echo "  - ca-certificate.pem  (Share with clients for trust)"
echo "  - ca-bundle.pem       (Certificate bundle)"
echo
echo "Next steps:"
echo "1. Install ca-certificate.pem in client trust stores"
echo "2. Use the CA to sign server certificate requests:"
echo "   ./generate-ca-certificate.sh sign-csr \\"
echo "     --ca-cert ca-certificate.pem \\"
echo "     --ca-key ca-private-key.pem \\"
echo "     --csr server.csr \\"
echo "     --output server-cert.pem"
echo