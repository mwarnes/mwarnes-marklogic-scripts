#!/bin/bash

# MarkLogic AppServer Setup Script
# This script creates a complete MarkLogic AppServer with TLS configuration
# Uses pre-generated certificates for oauth.warnesnet.com

set -euo pipefail

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
MARKLOGIC_HOST="${1:-oauth.warnesnet.com}"
ADMIN_USER="${2:-admin}"
ADMIN_PASS="${3:-admin}"
MARKLOGIC_PORT="8002"

# Generate random AppServer configuration
RANDOM_SUFFIX=$((RANDOM % 9000 + 1000))
APPSERVER_NAME="Test-AppServer-$RANDOM_SUFFIX"
APPSERVER_PORT=$((RANDOM % 101 + 10000))
CERTIFICATE_TEMPLATE_NAME="oauth-warnesnet-com-tls-cert"

# Certificate files
CERTIFICATE_FILE="oauth.warnesnet.com-certificate.pem"
PRIVATE_KEY_FILE="oauth.warnesnet.com-private-key.pem"
CA_CERTIFICATE_FILE="marklogic-test-ca.pem"

# Logging functions
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

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# Function to check if file exists
check_file() {
    local file="$1"
    if [[ ! -f "$file" ]]; then
        log_error "Required file not found: $file"
        return 1
    fi
    log_success "Found required file: $file"
    return 0
}

# Function to test MarkLogic connectivity
test_marklogic_connectivity() {
    log_step "Testing MarkLogic connectivity to $MARKLOGIC_HOST:$MARKLOGIC_PORT..."

    if curl -s -f --connect-timeout 10 --max-time 30 --anyauth -u "$ADMIN_USER:$ADMIN_PASS" \
        "http://$MARKLOGIC_HOST:$MARKLOGIC_PORT/manage/v2" \
        -H "Accept: application/json" >/dev/null; then
        log_success "MarkLogic connectivity verified"
        return 0
    else
        log_error "Cannot connect to MarkLogic at $MARKLOGIC_HOST:$MARKLOGIC_PORT"
        log_info "Please verify:"
        log_info "  - Server is running"
        log_info "  - Network connectivity"
        log_info "  - Credentials: $ADMIN_USER:$ADMIN_PASS"
        return 1
    fi
}

# Function to upload certificate template
upload_certificate_template() {
    log_step "Uploading certificate template to MarkLogic..."

    # Encode certificate and private key
    local cert_content
    local key_content

    cert_content=$(base64 -i "$CERTIFICATE_FILE" | tr -d '\n')
    key_content=$(base64 -i "$PRIVATE_KEY_FILE" | tr -d '\n')

    # Create certificate template
    local response
    response=$(curl -s -w "HTTP_STATUS:%{http_code}" --anyauth -u "$ADMIN_USER:$ADMIN_PASS" \
        -H "Content-Type: application/json" \
        -d "{
            \"certificate-template-name\": \"$CERTIFICATE_TEMPLATE_NAME\",
            \"certificate-template-description\": \"TLS certificate for $MARKLOGIC_HOST AppServer\",
            \"certificate-template\": {
                \"certificate\": \"$cert_content\",
                \"private-key\": \"$key_content\"
            }
        }" \
        "http://$MARKLOGIC_HOST:$MARKLOGIC_PORT/manage/v2/certificate-templates")

    local http_status
    http_status=$(echo "$response" | grep -o "HTTP_STATUS:[0-9]*" | cut -d: -f2)
    local body
    body=$(echo "$response" | sed 's/HTTP_STATUS:[0-9]*$//')

    if [[ "$http_status" == "201" ]]; then
        log_success "Certificate template uploaded successfully"
        return 0
    else
        log_error "Failed to upload certificate template (HTTP $http_status)"
        echo "$body" | jq '.' 2>/dev/null || echo "$body"
        return 1
    fi
}

# Function to create AppServer
create_appserver() {
    log_step "Creating AppServer '$APPSERVER_NAME' on port $APPSERVER_PORT..."

    # Create AppServer configuration
    local appserver_config
    appserver_config=$(cat <<EOF
{
    "server-name": "$APPSERVER_NAME",
    "server-type": "http",
    "group-name": "Default",
    "modules-database": "Modules",
    "content-database": "Documents",
    "root": "/",
    "port": $APPSERVER_PORT,
    "ssl-certificate-template": "$CERTIFICATE_TEMPLATE_NAME",
    "ssl-allow-sslv3": false,
    "ssl-allow-tls": true,
    "ssl-disable-sslv3": true,
    "ssl-disable-tlsv1": false,
    "ssl-disable-tlsv1-1": false,
    "ssl-disable-tlsv1-2": false,
    "ssl-hostname": "$MARKLOGIC_HOST",
    "authentication": "digest",
    "default-user": "",
    "privilege": "",
    "concurrent-request-limit": 0,
    "log-errors": true,
    "debug-allow": true,
    "profile-allow": false,
    "default-xquery-version": "1.0-ml",
    "multi-version-concurrency-control": "nonblocking-timestamp",
    "distribute-timestamps": "fast",
    "output-sgml-character-entities": "none",
    "output-encoding": "utf-8",
    "output-method": "default",
    "output-byte-order-mark": "no",
    "output-cdata-section-namespace-uri": "",
    "output-cdata-section-localname": "",
    "output-doctype-public": "",
    "output-doctype-system": "",
    "output-escape-uri-attributes": "no",
    "output-include-content-type": "yes",
    "output-indent": "no",
    "output-indent-untyped": "no",
    "output-media-type": "",
    "output-normalization-form": "none",
    "output-omit-xml-declaration": "no",
    "output-standalone": "omit",
    "output-undeclare-prefixes": "no",
    "output-version": "",
    "output-include-default-attributes": "no",
    "error-handler": "",
    "url-rewriter": "",
    "rewrite-resolves-globally": false
}
EOF
)

    # Create AppServer
    local response
    response=$(curl -s -w "HTTP_STATUS:%{http_code}" --anyauth -u "$ADMIN_USER:$ADMIN_PASS" \
        -H "Content-Type: application/json" \
        -d "$appserver_config" \
        "http://$MARKLOGIC_HOST:$MARKLOGIC_PORT/manage/v2/servers")

    local http_status
    http_status=$(echo "$response" | grep -o "HTTP_STATUS:[0-9]*" | cut -d: -f2)
    local body
    body=$(echo "$response" | sed 's/HTTP_STATUS:[0-9]*$//')

    if [[ "$http_status" == "201" ]]; then
        log_success "AppServer created successfully"
        return 0
    else
        log_error "Failed to create AppServer (HTTP $http_status)"
        echo "$body" | jq '.' 2>/dev/null || echo "$body"
        return 1
    fi
}

# Function to create security role
create_security_role() {
    log_step "Creating security role '$APPSERVER_NAME-role'..."

    local role_config
    role_config=$(cat <<EOF
{
    "role-name": "$APPSERVER_NAME-role",
    "description": "Security role for $APPSERVER_NAME",
    "role": [],
    "privilege": [
        {
            "privilege-name": "any-uri",
            "action": "http://marklogic.com/xdmp/privileges/any-uri",
            "kind": "execute"
        }
    ],
    "permission": [
        {
            "role-name": "$APPSERVER_NAME-role",
            "capability": "read"
        },
        {
            "role-name": "$APPSERVER_NAME-role",
            "capability": "insert"
        },
        {
            "role-name": "$APPSERVER_NAME-role",
            "capability": "update"
        }
    ]
}
EOF
)

    local response
    response=$(curl -s -w "HTTP_STATUS:%{http_code}" --anyauth -u "$ADMIN_USER:$ADMIN_PASS" \
        -H "Content-Type: application/json" \
        -d "$role_config" \
        "http://$MARKLOGIC_HOST:$MARKLOGIC_PORT/manage/v2/roles")

    local http_status
    http_status=$(echo "$response" | grep -o "HTTP_STATUS:[0-9]*" | cut -d: -f2)
    local body
    body=$(echo "$response" | sed 's/HTTP_STATUS:[0-9]*$//')

    if [[ "$http_status" == "201" ]]; then
        log_success "Security role created successfully"
        return 0
    else
        log_warning "Failed to create security role (HTTP $http_status) - may already exist"
        return 0  # Continue even if role creation fails
    fi
}

# Function to create test user
create_test_user() {
    log_step "Creating test user '$APPSERVER_NAME-user'..."

    local user_config
    user_config=$(cat <<EOF
{
    "user-name": "$APPSERVER_NAME-user",
    "description": "Test user for $APPSERVER_NAME",
    "password": "testpass123",
    "role": [
        "$APPSERVER_NAME-role"
    ]
}
EOF
)

    local response
    response=$(curl -s -w "HTTP_STATUS:%{http_code}" --anyauth -u "$ADMIN_USER:$ADMIN_PASS" \
        -H "Content-Type: application/json" \
        -d "$user_config" \
        "http://$MARKLOGIC_HOST:$MARKLOGIC_PORT/manage/v2/users")

    local http_status
    http_status=$(echo "$response" | grep -o "HTTP_STATUS:[0-9]*" | cut -d: -f2)
    local body
    body=$(echo "$response" | sed 's/HTTP_STATUS:[0-9]*$//')

    if [[ "$http_status" == "201" ]]; then
        log_success "Test user created successfully"
        return 0
    else
        log_warning "Failed to create test user (HTTP $http_status) - may already exist"
        return 0  # Continue even if user creation fails
    fi
}

# Function to test AppServer
test_appserver() {
    log_step "Testing AppServer accessibility..."

    # Wait a moment for the server to be ready
    sleep 2

    # Test HTTP access (should work)
    if curl -s -f --connect-timeout 5 --max-time 10 \
        "http://$MARKLOGIC_HOST:$APPSERVER_PORT/" >/dev/null 2>&1; then
        log_success "AppServer is accessible via HTTP on port $APPSERVER_PORT"
    else
        log_warning "AppServer may not be ready yet on HTTP port $APPSERVER_PORT"
    fi

    # Test HTTPS access (should work with TLS certificate)
    if curl -s -f --connect-timeout 5 --max-time 10 -k \
        "https://$MARKLOGIC_HOST:$APPSERVER_PORT/" >/dev/null 2>&1; then
        log_success "AppServer is accessible via HTTPS on port $APPSERVER_PORT"
    else
        log_info "HTTPS access may need additional configuration or time to initialize"
    fi
}

# Function to display summary
display_summary() {
    echo
    log_info "=== Setup Complete ==="
    log_info "MarkLogic Host: $MARKLOGIC_HOST"
    log_info "AppServer Name: $APPSERVER_NAME"
    log_info "AppServer Port: $APPSERVER_PORT"
    log_info "Certificate Template: $CERTIFICATE_TEMPLATE_NAME"
    log_info "Security Role: $APPSERVER_NAME-role"
    log_info "Test User: $APPSERVER_NAME-user (password: testpass123)"
    echo
    log_info "=== Access URLs ==="
    log_info "HTTP:  http://$MARKLOGIC_HOST:$APPSERVER_PORT/"
    log_info "HTTPS: https://$MARKLOGIC_HOST:$APPSERVER_PORT/"
    echo
    log_info "=== Management Commands ==="
    log_info "View AppServer:"
    log_info "  curl --anyauth -u $ADMIN_USER:*** \"http://$MARKLOGIC_HOST:$MARKLOGIC_PORT/manage/v2/servers/$APPSERVER_NAME\""
    echo
    log_info "Remove AppServer:"
    log_info "  curl -X DELETE --anyauth -u $ADMIN_USER:*** \"http://$MARKLOGIC_HOST:$MARKLOGIC_PORT/manage/v2/servers/$APPSERVER_NAME\""
    echo
    log_info "Remove certificate template:"
    log_info "  curl -X DELETE --anyauth -u $ADMIN_USER:*** \"http://$MARKLOGIC_HOST:$MARKLOGIC_PORT/manage/v2/certificate-templates/$CERTIFICATE_TEMPLATE_NAME\""
    echo
}

# Main execution
main() {
    log_info "=== MarkLogic AppServer Setup ==="
    log_info "Setting up complete MarkLogic AppServer with TLS"
    echo

    log_info "Configuration:"
    log_info "  MarkLogic Host: $MARKLOGIC_HOST"
    log_info "  Admin User: $ADMIN_USER"
    log_info "  AppServer Name: $APPSERVER_NAME"
    log_info "  AppServer Port: $APPSERVER_PORT"
    echo

    # Change to script directory
    cd "$SCRIPT_DIR"

    # Validate prerequisites
    log_step "Validating prerequisites..."
    check_file "$CERTIFICATE_FILE" || exit 1
    check_file "$PRIVATE_KEY_FILE" || exit 1
    check_file "$CA_CERTIFICATE_FILE" || exit 1

    # Test connectivity
    test_marklogic_connectivity || exit 1

    # Setup steps
    upload_certificate_template || exit 1
    create_appserver || exit 1
    create_security_role
    create_test_user

    # Test the setup
    test_appserver

    # Display summary
    display_summary

    log_success "MarkLogic AppServer setup completed successfully!"
}

# Handle script arguments
if [[ "${1:-}" == "--help" ]] || [[ "${1:-}" == "-h" ]]; then
    echo "Usage: $0 [MARKLOGIC_HOST] [ADMIN_USER] [ADMIN_PASS]"
    echo
    echo "Arguments:"
    echo "  MARKLOGIC_HOST    MarkLogic server hostname (default: oauth.warnesnet.com)"
    echo "  ADMIN_USER        MarkLogic admin username (default: admin)"
    echo "  ADMIN_PASS        MarkLogic admin password (default: admin)"
    echo
    echo "Example:"
    echo "  $0 oauth.warnesnet.com admin admin"
    echo
    exit 0
fi

# Run main function
main "$@"