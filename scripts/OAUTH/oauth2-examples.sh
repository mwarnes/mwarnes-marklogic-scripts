#!/bin/bash

# ================================================================
# OAuth2 Configuration Examples
# ================================================================
#
# This script demonstrates various OAuth2 configuration scenarios
# using the MLEAProxy OAuth2 configuration scripts.
#
# Author: Martin Warnes
# Version: 1.0.5
# Date: October 2025
#
# ================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "🔐 OAuth2 Configuration Examples"
echo "================================"
echo

# Example 1: MLEAProxy Development Setup
echo "📝 Example 1: MLEAProxy Development Setup"
echo "----------------------------------------"
echo
cat << 'EOF'
#!/bin/bash
# Set environment variables for MLEAProxy development
WELL_KNOWN_URL="http://localhost:8080/oauth/.well-known/config"
MARKLOGIC_HOST="oauth.warnesnet.com"
MARKLOGIC_PORT="8002"
MARKLOGIC_USER="admin"
MARKLOGIC_PASS="admin"
CONFIG_NAME="MLEAProxy-Dev"
CONFIG_DESCRIPTION="MLEAProxy development configuration"
USERNAME_ATTRIBUTE="preferred_username"
ROLE_ATTRIBUTE="marklogic-roles"
PRIVILEGE_ATTRIBUTE=""
CACHE_TIMEOUT="300"
CLIENT_ID="marklogic"
FETCH_JWKS="false"
INSECURE="true"
APP_SERVER="App-Services"
CLIENT_SECRET="secret"
TEST_USERNAME="admin"
TEST_PASSWORD="admin"
API_ENDPOINT_URL="http://oauth.warnesnet.com:8002/manage/LATEST/"
VERBOSE="false"
PERFORMANCE_TEST="false"
DETAILED_OUTPUT="true"
DECODE_TOKENS="true"

# Start MLEAProxy
cd MLEAProxy && mvn spring-boot:run &

# Configure MarkLogic with MLEAProxy OAuth
./scripts/configure-marklogic-oauth2.sh \
    --well-known-url "$WELL_KNOWN_URL" \
    --config-name "$CONFIG_NAME" \
    --marklogic-host "$MARKLOGIC_HOST" \
    --marklogic-port "$MARKLOGIC_PORT" \
    --marklogic-user "$MARKLOGIC_USER" \
    --marklogic-pass "$MARKLOGIC_PASS" \
    --client-id "$CLIENT_ID" \
    --username-attribute "$USERNAME_ATTRIBUTE" \
    --role-attribute "$ROLE_ATTRIBUTE" \
    --cache-timeout "$CACHE_TIMEOUT"

# Configure App Server to use OAuth external security
./scripts/configure-appserver-security.sh \
    --appserver "$APP_SERVER" \
    --external-security "$CONFIG_NAME" \
    --marklogic-host "$MARKLOGIC_HOST" \
    --marklogic-port "$MARKLOGIC_PORT" \
    --marklogic-user "$MARKLOGIC_USER" \
    --marklogic-pass "$MARKLOGIC_PASS"

# Test the configuration
./scripts/validate-oauth2-config.sh \
    --well-known-url "$WELL_KNOWN_URL" \
    --marklogic-host "$MARKLOGIC_HOST" \
    --marklogic-port "$MARKLOGIC_PORT" \
    --marklogic-user "$MARKLOGIC_USER" \
    --marklogic-pass "$MARKLOGIC_PASS" \
    --app-server "$APP_SERVER" \
    --client-id "$CLIENT_ID" \
    --client-secret "$CLIENT_SECRET" \
    --test-username "$TEST_USERNAME" \
    --test-password "$TEST_PASSWORD" \
    --api-endpoint-url "$API_ENDPOINT_URL" \
    --insecure \
    --detailed \
    --decode-tokens
EOF
echo

# Example 2: Keycloak Production Setup
echo "📝 Example 2: Keycloak Production Setup"
echo "---------------------------------------"
echo
cat << 'EOF'
#!/bin/bash
# Set environment variables for Keycloak OAuth configuration
WELL_KNOWN_URL="https://oauth.warnesnet.com:8443/realms/progress-marklogic/.well-known/openid_configuration"
MARKLOGIC_HOST="http://oauth.warnesnet.com"
MARKLOGIC_PORT="8002"
MARKLOGIC_USER="admin"
MARKLOGIC_PASS="admin"
CONFIG_NAME="OAuth2-Config"
CONFIG_DESCRIPTION="OAuth2 configuration created by script"
USERNAME_ATTRIBUTE="preferred_username"
ROLE_ATTRIBUTE="marklogic-roles"
PRIVILEGE_ATTRIBUTE=""
CACHE_TIMEOUT="300"
CLIENT_ID="marklogic-oauth"
FETCH_JWKS="false"
INSECURE="true"
# Set environment variables for Keycloak OAuth validation
APP_SERVER="Manage2"
CLIENT_SECRET="4UZyJkjWsGV5JtpsWfgkL1qW5vZ5hhmv"
TEST_USERNAME="martin"
TEST_PASSWORD="L1tespeed1!?kc"
API_ENDPOINT_URL="http://oauth.warnesnet.com:8002/manage/LATEST/"
VERBOSE="false"
PERFORMANCE_TEST="false"
DETAILED_OUTPUT="true"
DECODE_TOKENS="true"

# Configure MarkLogic with Keycloak OAuth
./scripts/configure-marklogic-oauth2.sh \
    --well-known-url "$WELL_KNOWN_URL" \
    --config-name "$CONFIG_NAME" \
    --marklogic-host "$MARKLOGIC_HOST" \
    --marklogic-port "$MARKLOGIC_PORT" \
    --marklogic-user "$MARKLOGIC_USER" \
    --marklogic-pass "$MARKLOGIC_PASS" \
    --client-id "$CLIENT_ID" \
    --username-attribute "$USERNAME_ATTRIBUTE" \
    --role-attribute "$ROLE_ATTRIBUTE" \
    --cache-timeout "$CACHE_TIMEOUT"

# Configure App Server to use OAuth external security
./scripts/configure-appserver-security.sh \
    --appserver "$APP_SERVER" \
    --external-security "$CONFIG_NAME" \
    --marklogic-host "$MARKLOGIC_HOST" \
    --marklogic-port "$MARKLOGIC_PORT" \
    --marklogic-user "$MARKLOGIC_USER" \
    --marklogic-pass "$MARKLOGIC_PASS"

# Validate production configuration
./scripts/validate-oauth2-config.sh \
    --well-known-url "$WELL_KNOWN_URL" \
    --marklogic-host "$MARKLOGIC_HOST" \
    --marklogic-port "$MARKLOGIC_PORT" \
    --marklogic-user "$MARKLOGIC_USER" \
    --marklogic-pass "$MARKLOGIC_PASS" \
    --app-server "$APP_SERVER" \
    --client-id "$CLIENT_ID" \
    --client-secret "$CLIENT_SECRET" \
    --test-username "$TEST_USERNAME" \
    --test-password "$TEST_PASSWORD" \
    --api-endpoint-url "$API_ENDPOINT_URL" \
    --insecure \
    --detailed \
    --decode-tokens
EOF
echo

# Example 3: Azure AD Enterprise Setup
echo "📝 Example 3: Azure AD Enterprise Setup"
echo "---------------------------------------"
echo
cat << 'EOF'
#!/bin/bash
# Set environment variables for Azure AD OAuth configuration
AZURE_TENANT_ID="12345678-1234-1234-1234-123456789012"
WELL_KNOWN_URL="https://login.microsoftonline.com/${AZURE_TENANT_ID}/v2.0/.well-known/openid_configuration"
MARKLOGIC_HOST="marklogic.azure.company.com"
MARKLOGIC_PORT="8002"
MARKLOGIC_USER="ml-admin"
MARKLOGIC_PASS="$AZURE_ML_PASS"
CONFIG_NAME="AzureAD-Enterprise"
CONFIG_DESCRIPTION="Azure AD Enterprise OAuth configuration"
USERNAME_ATTRIBUTE="upn"
ROLE_ATTRIBUTE="roles"
PRIVILEGE_ATTRIBUTE=""
CACHE_TIMEOUT="900"
CLIENT_ID="your-azure-client-id"
FETCH_JWKS="true"
INSECURE="true"
APP_SERVER="App-Services"
CLIENT_SECRET="your-azure-client-secret"
TEST_USERNAME="test.user@company.com"
TEST_PASSWORD="TestPassword123!"
API_ENDPOINT_URL="https://marklogic.azure.company.com:8002/manage/LATEST/"
VERBOSE="false"
PERFORMANCE_TEST="false"
DETAILED_OUTPUT="true"
DECODE_TOKENS="true"

# Configure MarkLogic with Azure AD OAuth
./scripts/configure-marklogic-oauth2.sh \
    --well-known-url "$WELL_KNOWN_URL" \
    --config-name "$CONFIG_NAME" \
    --marklogic-host "$MARKLOGIC_HOST" \
    --marklogic-port "$MARKLOGIC_PORT" \
    --marklogic-user "$MARKLOGIC_USER" \
    --marklogic-pass "$MARKLOGIC_PASS" \
    --client-id "$CLIENT_ID" \
    --username-attribute "$USERNAME_ATTRIBUTE" \
    --role-attribute "$ROLE_ATTRIBUTE" \
    --cache-timeout "$CACHE_TIMEOUT"

# Configure App Server to use OAuth external security
./scripts/configure-appserver-security.sh \
    --appserver "$APP_SERVER" \
    --external-security "$CONFIG_NAME" \
    --marklogic-host "$MARKLOGIC_HOST" \
    --marklogic-port "$MARKLOGIC_PORT" \
    --marklogic-user "$MARKLOGIC_USER" \
    --marklogic-pass "$MARKLOGIC_PASS"

# Test Azure AD integration
./scripts/validate-oauth2-config.sh \
    --well-known-url "$WELL_KNOWN_URL" \
    --marklogic-host "$MARKLOGIC_HOST" \
    --marklogic-port "$MARKLOGIC_PORT" \
    --marklogic-user "$MARKLOGIC_USER" \
    --marklogic-pass "$MARKLOGIC_PASS" \
    --app-server "$APP_SERVER" \
    --client-id "$CLIENT_ID" \
    --client-secret "$CLIENT_SECRET" \
    --test-username "$TEST_USERNAME" \
    --test-password "$TEST_PASSWORD" \
    --api-endpoint-url "$API_ENDPOINT_URL" \
    --insecure \
    --detailed \
    --decode-tokens
EOF
echo

# Example 4: Validate Configuration
echo "📝 Example 4: Validate Configuration"
echo "-----------------------------------"
echo
cat << 'EOF'
#!/bin/bash
# Set environment variables for validation
WELL_KNOWN_URL="http://localhost:8080/oauth/.well-known/config"
MARKLOGIC_HOST="oauth.warnesnet.com"
MARKLOGIC_PORT="8002"
MARKLOGIC_USER="admin"
MARKLOGIC_PASS="admin"
CONFIG_NAME="MLEAProxy-OAuth"
CLIENT_ID="marklogic"
INSECURE="true"
APP_SERVER="App-Services"
CLIENT_SECRET="secret"
TEST_USERNAME="admin"
TEST_PASSWORD="admin"
API_ENDPOINT_URL="http://oauth.warnesnet.com:8002/manage/LATEST/"
VERBOSE="true"
PERFORMANCE_TEST="false"
DETAILED_OUTPUT="true"
DECODE_TOKENS="true"

# Validate existing OAuth2 configuration
./scripts/validate-oauth2-config.sh \
  --well-known-url "$WELL_KNOWN_URL" \
  --marklogic-host "$MARKLOGIC_HOST" \
  --marklogic-port "$MARKLOGIC_PORT" \
  --marklogic-user "$MARKLOGIC_USER" \
  --marklogic-pass "$MARKLOGIC_PASS" \
  --app-server "$APP_SERVER" \
  --client-id "$CLIENT_ID" \
  --client-secret "$CLIENT_SECRET" \
  --test-username "$TEST_USERNAME" \
  --test-password "$TEST_PASSWORD" \
  --api-endpoint-url "$API_ENDPOINT_URL" \
  --insecure \
  --verbose \
  --detailed \
  --decode-tokens

# This will test:
# 1. OAuth2 server connectivity
# 2. Discovery endpoint validation
# 3. Token generation flows
# 4. MarkLogic configuration verification
# 5. End-to-end authentication validation
EOF
echo

# Example 5: CI/CD Integration
echo "📝 Example 5: CI/CD Integration"
echo "------------------------------"
echo
cat << 'EOF'
#!/bin/bash
# Set environment variables for CI/CD pipeline
WELL_KNOWN_URL="http://localhost:8080/oauth/.well-known/config"
MARKLOGIC_HOST="oauth.warnesnet.com"
MARKLOGIC_PORT="8002"
MARKLOGIC_USER="admin"
MARKLOGIC_PASS="admin"
CONFIG_NAME="CI-Test"
CONFIG_DESCRIPTION="CI/CD pipeline test configuration"
USERNAME_ATTRIBUTE="preferred_username"
ROLE_ATTRIBUTE="marklogic-roles"
CACHE_TIMEOUT="300"
CLIENT_ID="marklogic"
INSECURE="true"
APP_SERVER="App-Services"
CLIENT_SECRET="secret"
TEST_USERNAME="admin"
TEST_PASSWORD="admin"
API_ENDPOINT_URL="http://oauth.warnesnet.com:8002/manage/LATEST/"
VERBOSE="false"
PERFORMANCE_TEST="true"
DETAILED_OUTPUT="true"
DECODE_TOKENS="true"

# Automated testing in CI/CD pipeline

# 1. Start services
docker run -d --name marklogic -p 8000:8000 -p 8002:8002 marklogic/marklogic-server:latest
cd MLEAProxy && mvn spring-boot:run &

# 2. Wait for services to start
sleep 60

# 3. Validate OAuth2 configuration
./scripts/validate-oauth2-config.sh \
    --well-known-url "$WELL_KNOWN_URL" \
    --marklogic-host "$MARKLOGIC_HOST" \
    --marklogic-port "$MARKLOGIC_PORT" \
    --marklogic-user "$MARKLOGIC_USER" \
    --marklogic-pass "$MARKLOGIC_PASS" \
    --app-server "$APP_SERVER" \
    --client-id "$CLIENT_ID" \
    --client-secret "$CLIENT_SECRET" \
    --test-username "$TEST_USERNAME" \
    --test-password "$TEST_PASSWORD" \
    --api-endpoint-url "$API_ENDPOINT_URL" \
    --insecure \
    --performance \
    --detailed \
    --decode-tokens

# 4. Cleanup
docker stop marklogic && docker rm marklogic
pkill -f spring-boot:run
EOF
echo

echo "✅ All examples provided. Choose the one that matches your environment."
echo "📚 For more details, see the complete documentation in README.md"