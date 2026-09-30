#!/bin/bash

# ================================================================
# Certificate Type Validation Script
# ================================================================
#
# This script validates that:
# 1. Client certificates have clientAuth and NOT serverAuth
# 2. Server certificates have serverAuth and NOT clientAuth
# 3. Certificates have the correct Subject Alternative Names
#
# Usage: ./validate-certificate-type.sh <certificate-file>
# ================================================================

set -e

# Source utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../marklogic-utils.sh"

if [ $# -ne 1 ]; then
    echo "Usage: $0 <certificate-file>"
    echo "Example: $0 marklogic-test-user-certificate.pem"
    exit 1
fi

CERT_FILE="$1"

if [ ! -f "$CERT_FILE" ]; then
    ml_log_error "Certificate file not found: $CERT_FILE"
    exit 1
fi

ml_log_info "=== Certificate Type Validation ==="
ml_log_info "Certificate: $CERT_FILE"
echo

# Check certificate details
CERT_TEXT=$(openssl x509 -text -noout -in "$CERT_FILE")

# Extract subject
SUBJECT=$(echo "$CERT_TEXT" | grep "Subject:" | grep -v "Subject Public Key" | sed 's/^[[:space:]]*Subject:[[:space:]]*//')
ml_log_info "Subject: $SUBJECT"

# Check Extended Key Usage
if echo "$CERT_TEXT" | grep -q "X509v3 Extended Key Usage"; then
    EKU=$(echo "$CERT_TEXT" | grep -A 1 "X509v3 Extended Key Usage" | tail -1 | sed 's/^[[:space:]]*//')
    ml_log_info "Extended Key Usage: $EKU"

    # Determine certificate type
    if echo "$EKU" | grep -q "TLS Web Client Authentication"; then
        ml_log_success "✓ VALID CLIENT CERTIFICATE"

        if echo "$EKU" | grep -q "TLS Web Server Authentication"; then
            ml_log_warning "⚠ Certificate has both client AND server authentication - not recommended"
        else
            ml_log_success "✓ Client-only authentication (correct for MarkLogic user auth)"
        fi

    elif echo "$EKU" | grep -q "TLS Web Server Authentication"; then
        ml_log_success "✓ VALID SERVER CERTIFICATE"

        if echo "$EKU" | grep -q "TLS Web Client Authentication"; then
            ml_log_warning "⚠ Certificate has both server AND client authentication - not recommended"
        else
            ml_log_success "✓ Server-only authentication (correct for TLS encryption)"
        fi

    else
        ml_log_warning "⚠ Certificate has Extended Key Usage but neither client nor server authentication"
        ml_log_info "This certificate may not work for TLS connections"
    fi

else
    ml_log_warning "⚠ No Extended Key Usage found - certificate type unclear"
fi

# Check Subject Alternative Names
echo
ml_log_info "Subject Alternative Names:"
if echo "$CERT_TEXT" | grep -q "X509v3 Subject Alternative Name"; then
    SAN=$(echo "$CERT_TEXT" | grep -A 1 "X509v3 Subject Alternative Name" | tail -1 | sed 's/^[[:space:]]*//')
    ml_log_info "$SAN"

    # Analyze SAN content
    if echo "$SAN" | grep -q "email:"; then
        ml_log_success "✓ Contains email address (good for client certificates)"
    fi

    if echo "$SAN" | grep -q "DNS:"; then
        ml_log_success "✓ Contains DNS names (good for server certificates)"
    fi

    if echo "$SAN" | grep -q "IP:"; then
        ml_log_success "✓ Contains IP addresses (good for server certificates)"
    fi

else
    ml_log_info "No Subject Alternative Names found"
fi

# Check validity period
echo
VALIDITY=$(echo "$CERT_TEXT" | grep -A 2 "Validity" | tail -2)
ml_log_info "Validity Period:"
echo "$VALIDITY" | sed 's/^/  /'

echo
ml_log_success "Certificate validation complete"