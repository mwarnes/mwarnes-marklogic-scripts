#!/bin/bash

# ================================================================
# MarkLogic Complete Environment Setup Script
# ================================================================
#
# This script creates a complete MarkLogic test environment including:
# 1. Certificate Authority (CA) generation
# 2. Server certificate creation and signing
# 3. MarkLogic AppServer configuration
# 4. Security roles and users setup
# 5. TLS configuration and validation
#
# Usage: ./setup-complete-marklogic-environment.sh [options]
#
# Options:
#   --host <hostname>     Target MarkLogic host (default: localhost)
#   --admin-user <user>   MarkLogic admin username (default: admin)
#   --admin-pass <pass>   MarkLogic admin password (default: admin)
#   --port <port>         Specific AppServer port (default: random 10000-10100)
#   --name <name>         Specific AppServer name (default: auto-generated)
#   --dry-run             Show what would be done without executing
#   --help               Show this help message
#
# ================================================================

set -e

# Source utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../marklogic-utils.sh"

# ================================================================
# CONFIGURATION VARIABLES
# ================================================================

# Default values
ML_HOST="${ML_HOST:-localhost}"
ML_ADMIN_USER="${ML_ADMIN_USER:-admin}"
ML_ADMIN_PASS="${ML_ADMIN_PASS:-admin}"
ML_MANAGE_PORT="${ML_MANAGE_PORT:-8002}"

# Certificate configuration
CA_NAME="MarkLogic-Test-CA"
CA_PASSWORD="ml-test-ca-2025"
CERT_ORGANIZATION="MarkLogic Test Environment"
CERT_COUNTRY="US"

# AppServer configuration
APPSERVER_PORT=""
APPSERVER_NAME=""
RANDOM_SUFFIX=""

# Script options
DRY_RUN=false
HELP=false

# ================================================================
# HELPER FUNCTIONS
# ================================================================

show_help() {
    cat << EOF
MarkLogic Complete Environment Setup Script

USAGE:
    $0 [OPTIONS]

OPTIONS:
    --host <hostname>     Target MarkLogic host (default: localhost)
    --admin-user <user>   MarkLogic admin username (default: admin)
    --admin-pass <pass>   MarkLogic admin password (default: admin)
    --port <port>         Specific AppServer port (default: random 10000-10100)
    --name <name>         Specific AppServer name (default: auto-generated)
    --dry-run             Show what would be done without executing
    --help               Show this help message

EXAMPLES:
    # Basic setup with defaults
    $0

    # Custom host and credentials
    $0 --host marklogic.example.com --admin-user admin --admin-pass mypassword

    # Specific port and name
    $0 --port 10050 --name "Test-AppServer-Custom"

    # Dry run to see what would be executed
    $0 --dry-run

DESCRIPTION:
    This script creates a complete MarkLogic test environment including:

    1. Certificate Authority (CA) for signing certificates
    2. Server certificate for TLS encryption
    3. MarkLogic AppServer configuration
    4. Security roles for certificate authentication
    5. Test users with appropriate permissions
    6. TLS configuration and validation

    The script uses existing TLS certificate management tools and creates
    a fully functional HTTPS AppServer ready for testing.

EOF
}

generate_random_suffix() {
    echo $(( RANDOM % 9000 + 1000 ))
}

validate_port() {
    local port=$1
    if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 10000 ] || [ "$port" -gt 10100 ]; then
        ml_log_error "Port must be a number between 10000 and 10100"
        return 1
    fi
    return 0
}

check_port_availability() {
    local host=$1
    local port=$2

    if ! command -v nc >/dev/null 2>&1; then
        ml_log_warning "netcat (nc) not available - cannot check port availability"
        return 0
    fi

    if nc -z "$host" "$port" 2>/dev/null; then
        ml_log_error "Port $port is already in use on $host"
        return 1
    fi

    return 0
}

check_marklogic_connectivity() {
    ml_log_step "Checking MarkLogic connectivity..."

    if ! curl -s --connect-timeout 5 \
         -u "$ML_ADMIN_USER:$ML_ADMIN_PASS" \
         "http://$ML_HOST:$ML_MANAGE_PORT/manage/v2" >/dev/null; then
        ml_log_error "Cannot connect to MarkLogic at $ML_HOST:$ML_MANAGE_PORT"
        ml_log_error "Please verify:"
        ml_log_error "  - MarkLogic is running"
        ml_log_error "  - Host and port are correct"
        ml_log_error "  - Admin credentials are valid"
        return 1
    fi

    ml_log_success "MarkLogic connectivity verified"
    return 0
}

generate_certificates() {
    ml_log_step "Generating Certificate Authority..."

    if [ "$DRY_RUN" = true ]; then
        ml_log_info "DRY RUN: Would generate CA certificate with name: $CA_NAME"
        ml_log_info "DRY RUN: Would use password: $CA_PASSWORD"
        return 0
    fi

    # Generate CA if it doesn't exist
    if [ ! -f "ca-certificate.pem" ] || [ ! -f "ca-private-key.pem" ]; then
        ./generate-ca-certificate.sh create-ca \
            --cn "$CA_NAME" \
            --org "$CERT_ORGANIZATION" \
            --country "$CERT_COUNTRY" \
            --password "$CA_PASSWORD"

        ml_log_success "Certificate Authority created successfully"
    else
        ml_log_info "Certificate Authority already exists - using existing CA"
    fi

    ml_log_step "Generating server certificate for $ML_HOST..."

    # Generate server certificate
    ./generate-csr.sh server-csr \
        --cn "$ML_HOST" \
        --org "$CERT_ORGANIZATION" \
        --dns "$ML_HOST,*.$(echo $ML_HOST | cut -d. -f2-)" \
        --no-encrypt

    # Sign the certificate
    ./generate-ca-certificate.sh sign-csr \
        --ca-cert ca-certificate.pem \
        --ca-key ca-private-key.pem \
        --csr "$ML_HOST.csr" \
        --output "$ML_HOST-certificate.pem" \
        --password "$CA_PASSWORD"

    ml_log_success "Server certificate generated and signed"
}

create_appserver() {
    ml_log_step "Creating MarkLogic AppServer..."

    if [ "$DRY_RUN" = true ]; then
        ml_log_info "DRY RUN: Would create AppServer:"
        ml_log_info "  Name: $APPSERVER_NAME"
        ml_log_info "  Port: $APPSERVER_PORT"
        ml_log_info "  Host: $ML_HOST"
        return 0
    fi

    # Create AppServer configuration JSON
    local appserver_config=$(cat << EOF
{
  "app-server-name": "$APPSERVER_NAME",
  "group-name": "Default",
  "port": $APPSERVER_PORT,
  "root": "/",
  "content-database": "Documents",
  "modules-database": "Modules",
  "error-handler": "/MarkLogic/rest-api/error-handler.xqy",
  "url-rewriter": "/MarkLogic/rest-api/rewriter.xqy",
  "rewrite-resolves-globally": true,
  "error-format": "json",
  "debug-allow": true,
  "profile-allow": false,
  "default-xquery-version": "1.0-ml",
  "multi-version-concurrency-control": "nonblocking-timestamp",
  "distribute-timestamps": "fast",
  "output-sgml-character-entities": "none",
  "output-encoding": "utf-8",
  "output-method": "default",
  "output-byte-order-mark": "default",
  "output-cdata-section-namespace-uri": "",
  "output-cdata-section-localname": "",
  "output-doctype-public": "",
  "output-doctype-system": "",
  "output-escape-uri-attributes": "default",
  "output-include-content-type": "default",
  "output-include-default-attributes": "default",
  "output-indent": "default",
  "output-indent-untyped": "default",
  "output-media-type": "",
  "output-normalization-form": "none",
  "output-omit-xml-declaration": "default",
  "output-standalone": "default",
  "output-undeclare-prefixes": "default",
  "output-version": "",
  "privilege": "",
  "concurrent-request-limit": 0,
  "log-errors": true,
  "keep-log-files": 7,
  "rotate-log-files": "daily",
  "session-timeout": 1800,
  "max-inference-size": 100,
  "default-inference-size": 100,
  "static-expires": 3600,
  "pre-commit-trigger-depth": 1000,
  "pre-commit-trigger-limit": 5000,
  "collation": "http://marklogic.com/collation/codepoint",
  "coordinate-system": "wgs84",
  "authentication": "digest",
  "internal-security": true,
  "ssl-certificate-template": "",
  "ssl-allow-sslv3": false,
  "ssl-allow-tls": true,
  "ssl-hostname": "",
  "ssl-ciphers": "ALL:!LOW:!EXPORT:!MD5:!RC4:!PSK:!SRP:!CAMELLIA:!SEED",
  "ssl-require-client-certificate": false,
  "compute-content-length": true,
  "concurrent-request-timeout": 1800,
  "request-timeout": 1800
}
EOF
    )

    # Create the AppServer
    local response=$(curl -s -X POST \
        --anyauth -u "$ML_ADMIN_USER:$ML_ADMIN_PASS" \
        -H "Content-Type: application/json" \
        -d "$appserver_config" \
        "http://$ML_HOST:$ML_MANAGE_PORT/manage/v2/servers")

    if echo "$response" | grep -q "error"; then
        ml_log_error "Failed to create AppServer"
        echo "$response" | jq . 2>/dev/null || echo "$response"
        return 1
    fi

    ml_log_success "AppServer '$APPSERVER_NAME' created on port $APPSERVER_PORT"
}

configure_tls() {
    ml_log_step "Configuring TLS for AppServer..."

    if [ "$DRY_RUN" = true ]; then
        ml_log_info "DRY RUN: Would configure TLS with certificate: $ML_HOST-certificate.pem"
        return 0
    fi

    # Import server certificate into MarkLogic
    local cert_pem=$(cat "$ML_HOST-certificate.pem" | sed ':a;N;$!ba;s/\n/\\n/g')
    local key_pem=$(cat "$ML_HOST-private-key.pem" | sed ':a;N;$!ba;s/\n/\\n/g')

    # Create certificate template
    local cert_template=$(cat << EOF
{
  "template-name": "$APPSERVER_NAME-tls-cert",
  "template-description": "TLS certificate for $APPSERVER_NAME",
  "key-type": "rsa",
  "key-options": {},
  "req": {
    "version": 0,
    "subject": {
      "CN": "$ML_HOST",
      "O": "$CERT_ORGANIZATION"
    }
  },
  "cert": "$cert_pem",
  "privkey": "$key_pem"
}
EOF
    )

    # Create certificate template in MarkLogic
    curl -s -X POST \
        --anyauth -u "$ML_ADMIN_USER:$ML_ADMIN_PASS" \
        -H "Content-Type: application/json" \
        -d "$cert_template" \
        "http://$ML_HOST:$ML_MANAGE_PORT/manage/v2/certificate-templates" >/dev/null

    # Update AppServer to use TLS
    local ssl_config=$(cat << EOF
{
  "ssl-certificate-template": "$APPSERVER_NAME-tls-cert",
  "ssl-allow-sslv3": false,
  "ssl-allow-tls": true,
  "ssl-hostname": "$ML_HOST"
}
EOF
    )

    curl -s -X PUT \
        --anyauth -u "$ML_ADMIN_USER:$ML_ADMIN_PASS" \
        -H "Content-Type: application/json" \
        -d "$ssl_config" \
        "http://$ML_HOST:$ML_MANAGE_PORT/manage/v2/servers/$APPSERVER_NAME/properties" >/dev/null

    ml_log_success "TLS configuration applied to AppServer"
}

create_security_objects() {
    ml_log_step "Creating security roles and users..."

    if [ "$DRY_RUN" = true ]; then
        ml_log_info "DRY RUN: Would create security roles and test users"
        return 0
    fi

    # Create test role
    local role_config=$(cat << EOF
{
  "role-name": "test-app-user",
  "description": "Role for testing $APPSERVER_NAME application",
  "role": ["rest-reader", "rest-writer"],
  "privilege": [
    {
      "privilege-name": "http://marklogic.com/xdmp/privileges/xdbc-eval",
      "action": "http://marklogic.com/xdmp/privileges/execute"
    }
  ],
  "collection": [],
  "permission": []
}
EOF
    )

    # Create the role
    curl -s -X POST \
        --anyauth -u "$ML_ADMIN_USER:$ML_ADMIN_PASS" \
        -H "Content-Type: application/json" \
        -d "$role_config" \
        "http://$ML_HOST:$ML_MANAGE_PORT/manage/v2/roles" >/dev/null

    # Create test user
    local user_config=$(cat << EOF
{
  "user-name": "test-user",
  "description": "Test user for $APPSERVER_NAME",
  "password": "test-password-123",
  "role": ["test-app-user"]
}
EOF
    )

    # Create the user
    curl -s -X POST \
        --anyauth -u "$ML_ADMIN_USER:$ML_ADMIN_PASS" \
        -H "Content-Type: application/json" \
        -d "$user_config" \
        "http://$ML_HOST:$ML_MANAGE_PORT/manage/v2/users" >/dev/null

    ml_log_success "Security roles and users created"
}

validate_setup() {
    ml_log_step "Validating complete setup..."

    if [ "$DRY_RUN" = true ]; then
        ml_log_info "DRY RUN: Would validate HTTPS connectivity and certificate"
        return 0
    fi

    # Test HTTPS connectivity
    local test_url="https://$ML_HOST:$APPSERVER_PORT"

    # Wait for server to be available
    ml_log_info "Waiting for AppServer to start..."
    sleep 5

    # Test with our CA certificate
    if curl -s --cacert ca-certificate.pem \
         --connect-timeout 10 \
         -u "test-user:test-password-123" \
         "$test_url" >/dev/null 2>&1; then
        ml_log_success "HTTPS connectivity validated successfully"
    else
        ml_log_warning "HTTPS test failed - this may be expected if the server needs more time to start"
        ml_log_info "Manual test command:"
        ml_log_info "  curl --cacert ca-certificate.pem -u test-user:test-password-123 $test_url"
    fi

    # Validate certificate
    if [ -f "$ML_HOST-certificate.pem" ]; then
        ./validate-certificate-type.sh "$ML_HOST-certificate.pem"
    fi
}

cleanup_on_error() {
    if [ "$?" -ne 0 ] && [ "$DRY_RUN" = false ]; then
        ml_log_warning "Script failed - you may want to clean up created resources"
        ml_log_info "To remove AppServer: curl -X DELETE --anyauth -u $ML_ADMIN_USER:*** http://$ML_HOST:$ML_MANAGE_PORT/manage/v2/servers/$APPSERVER_NAME"
        ml_log_info "To remove certificate template: curl -X DELETE --anyauth -u $ML_ADMIN_USER:*** http://$ML_HOST:$ML_MANAGE_PORT/manage/v2/certificate-templates/$APPSERVER_NAME-tls-cert"
    fi
}

# ================================================================
# ARGUMENT PARSING
# ================================================================

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --host)
                ML_HOST="$2"
                shift 2
                ;;
            --admin-user)
                ML_ADMIN_USER="$2"
                shift 2
                ;;
            --admin-pass)
                ML_ADMIN_PASS="$2"
                shift 2
                ;;
            --port)
                APPSERVER_PORT="$2"
                if ! validate_port "$APPSERVER_PORT"; then
                    exit 1
                fi
                shift 2
                ;;
            --name)
                APPSERVER_NAME="$2"
                shift 2
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --help)
                show_help
                exit 0
                ;;
            *)
                ml_log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done

    # Set defaults if not specified
    if [ -z "$APPSERVER_PORT" ]; then
        APPSERVER_PORT=$(( RANDOM % 101 + 10000 ))
    fi

    if [ -z "$APPSERVER_NAME" ]; then
        RANDOM_SUFFIX=$(generate_random_suffix)
        APPSERVER_NAME="Test-AppServer-$RANDOM_SUFFIX"
    fi
}

# ================================================================
# MAIN EXECUTION
# ================================================================

main() {
    # Setup error handling
    trap cleanup_on_error EXIT

    # Show header
    ml_show_header "MarkLogic Complete Environment Setup" "1.0.0" "Creates CA, certificates, AppServer, and security configuration"

    # Parse command line arguments
    parse_arguments "$@"

    # Show configuration
    ml_log_info "Configuration:"
    ml_log_info "  MarkLogic Host: $ML_HOST"
    ml_log_info "  Admin User: $ML_ADMIN_USER"
    ml_log_info "  AppServer Name: $APPSERVER_NAME"
    ml_log_info "  AppServer Port: $APPSERVER_PORT"
    ml_log_info "  CA Name: $CA_NAME"
    ml_log_info "  Organization: $CERT_ORGANIZATION"
    if [ "$DRY_RUN" = true ]; then
        ml_log_info "  Mode: DRY RUN (no changes will be made)"
    fi
    echo

    # Validate prerequisites
    if [ "$DRY_RUN" = false ]; then
        ml_log_step "Validating prerequisites..."

        # Check required tools
        for tool in curl jq openssl; do
            if ! command -v "$tool" >/dev/null 2>&1; then
                ml_log_error "Required tool not found: $tool"
                exit 1
            fi
        done

        # Check MarkLogic connectivity
        if ! check_marklogic_connectivity; then
            exit 1
        fi

        # Check port availability
        if ! check_port_availability "$ML_HOST" "$APPSERVER_PORT"; then
            exit 1
        fi

        ml_log_success "All prerequisites validated"
        echo
    fi

    # Execute setup steps
    generate_certificates
    echo

    create_appserver
    echo

    configure_tls
    echo

    create_security_objects
    echo

    validate_setup
    echo

    # Show completion summary
    ml_log_success "MarkLogic environment setup completed successfully!"
    echo
    ml_log_info "==================================================================="
    ml_log_info "SETUP SUMMARY"
    ml_log_info "==================================================================="
    ml_log_info "AppServer URL: https://$ML_HOST:$APPSERVER_PORT"
    ml_log_info "Test User: test-user"
    ml_log_info "Test Password: test-password-123"
    ml_log_info "CA Certificate: ca-certificate.pem"
    ml_log_info "Server Certificate: $ML_HOST-certificate.pem"
    ml_log_info "Private Key: $ML_HOST-private-key.pem"
    echo
    ml_log_info "==================================================================="
    ml_log_info "TESTING COMMANDS"
    ml_log_info "==================================================================="
    ml_log_info "# Test HTTPS connectivity:"
    ml_log_info "curl --cacert ca-certificate.pem \\"
    ml_log_info "     -u test-user:test-password-123 \\"
    ml_log_info "     https://$ML_HOST:$APPSERVER_PORT"
    echo
    ml_log_info "# Test certificate validation:"
    ml_log_info "./validate-certificate-type.sh $ML_HOST-certificate.pem"
    echo
    ml_log_info "# Access via browser (install ca-certificate.pem as trusted CA):"
    ml_log_info "https://$ML_HOST:$APPSERVER_PORT"

    # Clear error trap on successful completion
    trap - EXIT
}

# Execute main function with all arguments
main "$@"