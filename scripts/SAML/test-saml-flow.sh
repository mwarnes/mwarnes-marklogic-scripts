#!/bin/bash

# ================================================================
# SAML Flow Testing Script
# ================================================================
#
# This script tests the complete SAML authentication flow:
# 1. Access protected MarkLogic resource
# 2. Follow SAML redirect to Keycloak
# 3. Login with test credentials
# 4. Follow SAML response back to MarkLogic
# 5. Access protected resource with SAML session
#
# Usage: ./test-saml-flow.sh
# ================================================================

set -euo pipefail

# Configuration
MARKLOGIC_URL="http://oauth.warnesnet.com:9002/manage"
KEYCLOAK_BASE="https://oauth.warnesnet.com:8443"
TEST_USER="martin"
TEST_PASS="L1tespeed1!?kc"
COOKIE_JAR="/tmp/saml-test-cookies.txt"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Clean up previous cookies
rm -f "$COOKIE_JAR"

echo "========================================"
echo "SAML Authentication Flow Test"
echo "========================================"
echo

log_info "Step 1: Accessing protected MarkLogic resource..."
log_info "URL: $MARKLOGIC_URL"

# Step 1: Access protected resource and capture redirect
RESPONSE=$(curl -i -s -k -c "$COOKIE_JAR" -L "$MARKLOGIC_URL" 2>/dev/null)
echo "$RESPONSE" > /tmp/step1-response.txt

# Check if we get SAML redirect
if echo "$RESPONSE" | grep -q "Location.*saml"; then
    SAML_URL=$(echo "$RESPONSE" | grep "Location:" | head -1 | sed 's/Location: //' | tr -d '\r')
    log_success "SAML redirect detected"
    log_info "Redirect URL: $SAML_URL"
else
    log_error "No SAML redirect found. Authentication may not be configured correctly."
    echo "Response headers:"
    echo "$RESPONSE" | head -20
    exit 1
fi

echo
log_info "Step 2: Following SAML redirect to Keycloak..."

# Step 2: Follow SAML redirect to get Keycloak login form
KEYCLOAK_RESPONSE=$(curl -i -s -k -b "$COOKIE_JAR" -c "$COOKIE_JAR" -L "$SAML_URL" 2>/dev/null)
echo "$KEYCLOAK_RESPONSE" > /tmp/step2-response.txt

# Extract login form details
if echo "$KEYCLOAK_RESPONSE" | grep -q "form.*action"; then
    # Extract the login form action URL
    LOGIN_ACTION=$(echo "$KEYCLOAK_RESPONSE" | grep -o 'action="[^"]*"' | head -1 | sed 's/action="//;s/"//')
    log_success "Keycloak login form found"
    log_info "Login action: $LOGIN_ACTION"

    # Make sure we have full URL
    if [[ "$LOGIN_ACTION" == /* ]]; then
        LOGIN_ACTION="$KEYCLOAK_BASE$LOGIN_ACTION"
    fi
else
    log_error "Keycloak login form not found"
    echo "Response content:"
    echo "$KEYCLOAK_RESPONSE" | tail -50
    exit 1
fi

echo
log_info "Step 3: Authenticating with test credentials..."
log_info "Username: $TEST_USER"
log_info "Password: [hidden]"

# Step 3: Submit login credentials
LOGIN_RESPONSE=$(curl -i -s -k -b "$COOKIE_JAR" -c "$COOKIE_JAR" -L \
    --data-urlencode "username=$TEST_USER" \
    --data-urlencode "password=$TEST_PASS" \
    --data-urlencode "credentialId=" \
    "$LOGIN_ACTION" 2>/dev/null)
echo "$LOGIN_RESPONSE" > /tmp/step3-response.txt

# Check if login was successful and we get SAML response
if echo "$LOGIN_RESPONSE" | grep -q "SAMLResponse\|Location.*oauth.warnesnet.com"; then
    log_success "Authentication successful"

    # Check if we're redirected back to MarkLogic
    if echo "$LOGIN_RESPONSE" | grep -q "Location.*oauth.warnesnet.com"; then
        CALLBACK_URL=$(echo "$LOGIN_RESPONSE" | grep "Location:" | tail -1 | sed 's/Location: //' | tr -d '\r')
        log_info "SAML callback URL: $CALLBACK_URL"
    else
        log_warning "No direct redirect found, looking for SAML form submission..."
        # Sometimes Keycloak returns a form that auto-submits
        if echo "$LOGIN_RESPONSE" | grep -q "SAMLResponse"; then
            log_info "SAML Response form found - this would normally auto-submit in browser"
        fi
    fi
else
    log_error "Authentication failed or unexpected response"
    echo "Login response:"
    echo "$LOGIN_RESPONSE" | tail -30
    exit 1
fi

echo
log_info "Step 4: Attempting to access MarkLogic with SAML session..."

# Step 4: Try to access MarkLogic resource again with session
FINAL_RESPONSE=$(curl -i -s -k -b "$COOKIE_JAR" -L "$MARKLOGIC_URL" 2>/dev/null)
echo "$FINAL_RESPONSE" > /tmp/step4-response.txt

# Check if we can now access the protected resource
if echo "$FINAL_RESPONSE" | grep -q "HTTP/1.1 200\|MarkLogic.*Admin\|Management Console"; then
    log_success "SAML authentication flow completed successfully!"
    log_success "Access to protected resource granted"

    echo
    echo "========================================"
    log_success "SAML FLOW TEST PASSED"
    echo "========================================"
    echo "✅ SAML redirect working"
    echo "✅ Keycloak authentication successful"
    echo "✅ SAML session established"
    echo "✅ Protected resource accessible"

elif echo "$FINAL_RESPONSE" | grep -q "Location.*saml"; then
    log_warning "Still getting SAML redirects - session may not be properly established"
    log_info "This could be due to:"
    log_info "1. Session cookies not properly maintained"
    log_info "2. SAML assertion not properly processed"
    log_info "3. User not properly mapped in MarkLogic"
else
    log_warning "Access denied or unexpected response"
    echo "Final response headers:"
    echo "$FINAL_RESPONSE" | head -10
fi

echo
log_info "Response files saved to /tmp/ for debugging:"
log_info "- /tmp/step1-response.txt (initial redirect)"
log_info "- /tmp/step2-response.txt (Keycloak form)"
log_info "- /tmp/step3-response.txt (login response)"
log_info "- /tmp/step4-response.txt (final access attempt)"
log_info "- $COOKIE_JAR (session cookies)"

# Clean up
rm -f "$COOKIE_JAR"