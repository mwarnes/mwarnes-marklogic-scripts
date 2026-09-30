#!/bin/bash

# ================================================================
# Certificate Signing Request (CSR) Generation Script
# ================================================================
#
# This script generates Certificate Signing Requests (CSRs) for
# servers or clients that can be signed by a Certificate Authority.
# Works perfectly with the generate-ca-certificate.sh script.
#
# Features:
# - Generate server certificates with Subject Alternative Names (SAN)
# - Generate client certificates for authentication
# - Customizable certificate attributes (CN, O, OU, L, C, Email)
# - Support for different key sizes and encryption algorithms
# - Wildcard and multi-domain certificate support
# - Integration with MarkLogic certificate management
# - Automatic CSR validation
#
# Author: Martin Warnes
# Version: 1.0.1
# Date: November 2025
#
# Usage:
#   ./generate-csr.sh [COMMAND] [OPTIONS]
#
# Commands:
#   server-csr          Generate server certificate CSR
#   client-csr          Generate client certificate CSR
#   show-csr            Display CSR details
#   verify-csr          Verify CSR format and content
#   sign-with-ca        Generate CSR and sign with CA (convenience command)
#
# Examples:
#   # Generate server CSR for server.example.com
#   ./generate-csr.sh server-csr \\
#     --cn "server.example.com" \\
#     --san "DNS:server.example.com,DNS:*.server.example.com,IP:192.0.2.42"
#
#   # Generate client certificate CSR
#   ./generate-csr.sh client-csr \\
#     --cn "john.doe" \\
#     --email "john.doe@example.com" \\
#     --org "ACME Corp"
#
#   # Generate CSR and sign it immediately
#   ./generate-csr.sh sign-with-ca \\
#     --cn "server.example.com" \\
#     --ca-cert ca-certificate.pem \\
#     --ca-key ca-private-key.pem
#
#   # Show CSR details
#   ./generate-csr.sh show-csr --csr server.csr
#
# ================================================================

set -euo pipefail

# Source common utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../marklogic-utils.sh"
source "$SCRIPT_DIR/tls-utils.sh"

# ================================================================
# CONFIGURATION VARIABLES
# ================================================================

# Command and options
COMMAND=""

# Certificate subject attributes
COMMON_NAME=""
ORGANIZATION=""
ORGANIZATIONAL_UNIT=""
LOCALITY=""
STATE=""
COUNTRY=""
EMAIL=""

# Certificate type and options
CERT_TYPE=""  # server or client
KEY_SIZE="2048"
HASH_ALGORITHM="sha256"

# Subject Alternative Names (for server certificates)
SUBJECT_ALT_NAMES=""
IP_ADDRESSES=""
DNS_NAMES=""

# File paths
ROLLBACK_MANIFEST=""
PRIVATE_KEY_FILE=""
CSR_FILE=""
CERT_FILE=""
CA_CERT_FILE=""
CA_KEY_FILE=""
CA_PASSWORD="${TLS_CA_PASSWORD:-}"

# OpenSSL configuration
OPENSSL_CONFIG_FILE=""

# Key encryption
ENCRYPT_KEY="true"
KEY_PASSWORD="${TLS_KEY_PASSWORD:-}"

# Certificate validity (when signing with CA)
VALIDITY_DAYS="365"

# Dry run mode
DRY_RUN="false"

# ================================================================
# UTILITY FUNCTIONS
# ================================================================

# Show usage information
show_usage() {
    cat << EOF
Certificate Signing Request (CSR) Generation Script

USAGE:
    $0 [COMMAND] [OPTIONS]

COMMANDS:
    server-csr          Generate server certificate CSR
    client-csr          Generate client certificate CSR
    show-csr            Display CSR details
    verify-csr          Verify CSR format and content
    sign-with-ca        Generate CSR and sign with CA (convenience command)

CERTIFICATE SUBJECT OPTIONS:
    --cn <name>         Common Name (required)
    --org <name>        Organization name
    --ou <unit>         Organizational Unit
    --locality <city>   Locality/City name
    --state <state>     State/Province name
    --country <code>    Country code (2 letters)
    --email <email>     Email address

SERVER CERTIFICATE OPTIONS:
    --san <list>        Subject Alternative Names (comma-separated)
                        Format: DNS:name1,DNS:name2,IP:1.2.3.4
    --dns <names>       DNS names (comma-separated, simpler format)
    --ip <addresses>    IP addresses (comma-separated)

CERTIFICATE OPTIONS:
    --key-size <size>   RSA key size in bits (default: 2048)
    --hash <algorithm>  Hash algorithm (default: sha256)
    --validity <days>   Certificate validity when signing (default: 365)
    --no-encrypt       Don't encrypt the private key with password

FILE OPTIONS:
    --key <file>        Private key file (default: <cn>-private-key.pem)
    --csr <file>        CSR file (default: <cn>.csr)
    --cert <file>       Certificate file (default: <cn>-certificate.pem)
    --ca-cert <file>    CA certificate file (for signing)
    --ca-key <file>     CA private key file (for signing)
    --ca-password <pw>  Rejected; use TLS_CA_PASSWORD or a hidden prompt

GENERAL OPTIONS:
    --dry-run           Show what would be done without executing
    --rollback FILE     Remove only unchanged outputs recorded by a protected manifest
    --help              Show this help message

PASSWORD INPUT:
    TLS_KEY_PASSWORD    Private-key password for unattended use; otherwise hidden prompt
    TLS_CA_PASSWORD     CA signing password for unattended use; otherwise hidden prompt
    Password-valued command-line arguments are rejected.

EXAMPLES:
    # Server certificate for MarkLogic
    $0 server-csr --cn "server.example.com" \\
                  --san "DNS:server.example.com,DNS:*.server.example.com"

    # Client certificate for user authentication
    $0 client-csr --cn "john.doe@example.com" \\
                  --email "john.doe@example.com" \\
                  --org "ACME Corp"

    # Wildcard certificate
    $0 server-csr --cn "*.example.com" \\
                  --dns "*.example.com,example.com"

    # Generate and sign immediately
    $0 sign-with-ca --cn "server.local" \\
                    --ca-cert ca-certificate.pem \\
                    --ca-key ca-private-key.pem

EOF
}

# Parse command line arguments
parse_arguments() {
    if [ $# -eq 0 ]; then
        show_usage
        exit 1
    fi

    # Handle help first
    for arg in "$@"; do
        if [ "$arg" = "--help" ] || [ "$arg" = "-h" ]; then
            show_usage
            exit 0
        fi
    done

    if [ "$1" = "--rollback" ]; then
        [ "$#" -ge 2 ] || { ml_log_error "--rollback requires a manifest file"; exit 1; }
        COMMAND="rollback"
        ROLLBACK_MANIFEST="$2"
        shift 2
    else
        COMMAND="$1"
        shift
    fi

    while [[ $# -gt 0 ]]; do
        case $1 in
            --cn)
                COMMON_NAME="$2"
                shift 2
                ;;
            --org)
                ORGANIZATION="$2"
                shift 2
                ;;
            --ou)
                ORGANIZATIONAL_UNIT="$2"
                shift 2
                ;;
            --locality)
                LOCALITY="$2"
                shift 2
                ;;
            --state)
                STATE="$2"
                shift 2
                ;;
            --country)
                COUNTRY="$2"
                shift 2
                ;;
            --email)
                EMAIL="$2"
                shift 2
                ;;
            --san)
                SUBJECT_ALT_NAMES="$2"
                shift 2
                ;;
            --dns)
                DNS_NAMES="$2"
                shift 2
                ;;
            --ip)
                IP_ADDRESSES="$2"
                shift 2
                ;;
            --key-size)
                KEY_SIZE="$2"
                shift 2
                ;;
            --hash)
                HASH_ALGORITHM="$2"
                shift 2
                ;;
            --validity)
                VALIDITY_DAYS="$2"
                shift 2
                ;;
            --key)
                PRIVATE_KEY_FILE="$2"
                shift 2
                ;;
            --csr)
                CSR_FILE="$2"
                shift 2
                ;;
            --cert)
                CERT_FILE="$2"
                shift 2
                ;;
            --ca-cert)
                CA_CERT_FILE="$2"
                shift 2
                ;;
            --ca-key)
                CA_KEY_FILE="$2"
                shift 2
                ;;
            --ca-password)
                ml_log_error "--ca-password VALUE is rejected; use TLS_CA_PASSWORD or a hidden prompt"
                exit 1
                ;;
            --no-encrypt)
                ENCRYPT_KEY="false"
                shift
                ;;
            --dry-run)
                DRY_RUN="true"
                shift
                ;;
            --yes)
                YES="true"
                shift
                ;;
            *)
                ml_log_error "Unknown option"
                show_usage
                exit 1
                ;;
        esac
    done
}

# Validate dependencies
check_dependencies() {
    ml_log_step "Checking dependencies..."

    # Check for OpenSSL
    if ! command -v openssl >/dev/null 2>&1; then
        ml_log_error "OpenSSL is required but not installed"
        return 1
    fi
    if ! command -v jq >/dev/null 2>&1; then
        ml_log_error "jq is required for protected output manifests"
        return 1
    fi

    local openssl_version
    openssl_version=$(openssl version | cut -d' ' -f2)
    ml_log_info "OpenSSL version: $openssl_version"

    ml_log_success "All dependencies found"
    return 0
}

# Set default file names based on Common Name
set_default_filenames() {
    if [ -z "$COMMON_NAME" ]; then
        ml_log_error "Common Name (--cn) is required"
        return 1
    fi

    # Sanitize common name for filename (replace special chars with dashes)
    local safe_name
    safe_name=$(echo "$COMMON_NAME" | sed 's/[^a-zA-Z0-9.-]/-/g' | sed 's/\*/-wildcard/g')

    # Set default filenames if not specified
    if [ -z "$PRIVATE_KEY_FILE" ]; then
        PRIVATE_KEY_FILE="${safe_name}-private-key.pem"
    fi

    if [ -z "$CSR_FILE" ]; then
        CSR_FILE="${safe_name}.csr"
    fi

    if [ -z "$CERT_FILE" ]; then
        CERT_FILE="${safe_name}-certificate.pem"
    fi

    ml_log_verbose "Using filenames: key=$PRIVATE_KEY_FILE, csr=$CSR_FILE, cert=$CERT_FILE"
}

csr_check_output_paths() {
    local key_dir csr_dir manifest="$CSR_FILE.rollback.json" path
    for path in "$PRIVATE_KEY_FILE" "$CSR_FILE" "$manifest"; do
        case "$path" in *$'\n'*|*$'\r'*) ml_log_error "Output path contains a line break"; return 1 ;; esac
        [ ! -e "$path" ] && [ ! -L "$path" ] || { ml_log_error "Refusing to overwrite existing output: $path"; return 1; }
    done
    key_dir=$(cd "$(dirname "$PRIVATE_KEY_FILE")" && pwd -P) || return 1
    csr_dir=$(cd "$(dirname "$CSR_FILE")" && pwd -P) || return 1
    [ "$key_dir" = "$csr_dir" ] || { ml_log_error "Private key and CSR must be written in the same directory for rollback tracking"; return 1; }
}

# Process Subject Alternative Names
process_san_names() {
    local san_list=""

    # Add DNS names from --dns option
    if [ -n "$DNS_NAMES" ]; then
        IFS=',' read -ra dns_array <<< "$DNS_NAMES"
        for dns in "${dns_array[@]}"; do
            dns=$(echo "$dns" | xargs)  # trim whitespace
            if [ -n "$san_list" ]; then
                san_list="${san_list},DNS:${dns}"
            else
                san_list="DNS:${dns}"
            fi
        done
    fi

    # Add IP addresses from --ip option
    if [ -n "$IP_ADDRESSES" ]; then
        IFS=',' read -ra ip_array <<< "$IP_ADDRESSES"
        for ip in "${ip_array[@]}"; do
            ip=$(echo "$ip" | xargs)  # trim whitespace
            if [ -n "$san_list" ]; then
                san_list="${san_list},IP:${ip}"
            else
                san_list="IP:${ip}"
            fi
        done
    fi

    # Combine with existing SAN if provided
    if [ -n "$SUBJECT_ALT_NAMES" ]; then
        if [ -n "$san_list" ]; then
            SUBJECT_ALT_NAMES="${SUBJECT_ALT_NAMES},${san_list}"
        fi
    else
        SUBJECT_ALT_NAMES="$san_list"
    fi

    ml_log_verbose "Processed SAN: $SUBJECT_ALT_NAMES"
}

# Generate OpenSSL configuration
generate_openssl_config() {
    local original_umask
    original_umask=$(umask)
    umask 077
    OPENSSL_CONFIG_FILE=$(mktemp) || { umask "$original_umask"; return 1; }
    chmod 600 "$OPENSSL_CONFIG_FILE" || { rm -f "$OPENSSL_CONFIG_FILE"; umask "$original_umask"; return 1; }
    umask "$original_umask"

    cat > "$OPENSSL_CONFIG_FILE" << EOF
[ req ]
default_bits = $KEY_SIZE
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[ req_distinguished_name ]
EOF

    if [ -n "$COUNTRY" ]; then
        echo "C = $COUNTRY" >> "$OPENSSL_CONFIG_FILE"
    fi
    if [ -n "$STATE" ]; then
        echo "ST = $STATE" >> "$OPENSSL_CONFIG_FILE"
    fi
    if [ -n "$LOCALITY" ]; then
        echo "L = $LOCALITY" >> "$OPENSSL_CONFIG_FILE"
    fi
    if [ -n "$ORGANIZATION" ]; then
        echo "O = $ORGANIZATION" >> "$OPENSSL_CONFIG_FILE"
    fi
    if [ -n "$ORGANIZATIONAL_UNIT" ]; then
        echo "OU = $ORGANIZATIONAL_UNIT" >> "$OPENSSL_CONFIG_FILE"
    fi
    echo "CN = $COMMON_NAME" >> "$OPENSSL_CONFIG_FILE"
    if [ -n "$EMAIL" ]; then
        echo "emailAddress = $EMAIL" >> "$OPENSSL_CONFIG_FILE"
    fi

    # Add extensions based on certificate type
    cat >> "$OPENSSL_CONFIG_FILE" << EOF

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
EOF

    if [ "$CERT_TYPE" = "server" ]; then
        echo "extendedKeyUsage = serverAuth" >> "$OPENSSL_CONFIG_FILE"
        if [ -n "$SUBJECT_ALT_NAMES" ]; then
            echo "subjectAltName = $SUBJECT_ALT_NAMES" >> "$OPENSSL_CONFIG_FILE"
        fi
    elif [ "$CERT_TYPE" = "client" ]; then
        echo "extendedKeyUsage = clientAuth" >> "$OPENSSL_CONFIG_FILE"
        if [ -n "$EMAIL" ]; then
            echo "subjectAltName = email:$EMAIL" >> "$OPENSSL_CONFIG_FILE"
        fi
    fi

    ml_log_verbose "Generated OpenSSL configuration file: $OPENSSL_CONFIG_FILE"
}

# Get password for private key encryption
get_key_password() {
    if [ "$ENCRYPT_KEY" = "true" ] && [ -z "$KEY_PASSWORD" ]; then
        echo
        ml_log_info "Private key encryption password is recommended for security"
        echo -n "Enter password for private key (or press Enter for no password): "
        IFS= read -r -s KEY_PASSWORD
        echo

        if [ -n "$KEY_PASSWORD" ] && [ ${#KEY_PASSWORD} -lt 4 ]; then
            ml_log_error "Password must be at least 4 characters long"
            return 1
        fi

        if [ -z "$KEY_PASSWORD" ]; then
            ENCRYPT_KEY="false"
            ml_log_warning "Private key will not be encrypted"
        fi
    fi
}

# ================================================================
# CSR GENERATION FUNCTIONS
# ================================================================

# Generate a key and CSR for either certificate usage.
generate_csr_for_type() {
    CERT_TYPE="$1"
    ml_log_step "Generating $CERT_TYPE certificate CSR for: $COMMON_NAME"
    if [ "$DRY_RUN" = "true" ]; then
        ml_log_info "[DRY-RUN] Would generate a $CERT_TYPE key and CSR; no password prompt, temp file, or key operation"
        return 0
    fi
    set_default_filenames || return 1
    process_san_names || return 1
    csr_check_output_paths || return 1
    get_key_password || return 1
    generate_openssl_config || return 1
    umask 077

    local openssl_status
    if [ "$ENCRYPT_KEY" = "true" ]; then
        if openssl genrsa -aes256 -passout stdin -out "$PRIVATE_KEY_FILE" "$KEY_SIZE" <<< "$KEY_PASSWORD"; then
            openssl_status=0
        else
            openssl_status=$?
        fi
    else
        if openssl genrsa -out "$PRIVATE_KEY_FILE" "$KEY_SIZE"; then openssl_status=0; else openssl_status=$?; fi
    fi
    if [ "$openssl_status" -ne 0 ]; then
        rm -f "$PRIVATE_KEY_FILE" "$CSR_FILE" "$OPENSSL_CONFIG_FILE"
        ml_log_error "Could not generate private key"
        return 1
    fi
    chmod 600 "$PRIVATE_KEY_FILE" || { rm -f "$PRIVATE_KEY_FILE" "$CSR_FILE" "$OPENSSL_CONFIG_FILE"; return 1; }

    if [ "$ENCRYPT_KEY" = "true" ]; then
        if openssl req -new -key "$PRIVATE_KEY_FILE" -passin stdin -out "$CSR_FILE" -config "$OPENSSL_CONFIG_FILE" <<< "$KEY_PASSWORD"; then
            openssl_status=0
        else
            openssl_status=$?
        fi
    else
        if openssl req -new -key "$PRIVATE_KEY_FILE" -out "$CSR_FILE" -config "$OPENSSL_CONFIG_FILE"; then openssl_status=0; else openssl_status=$?; fi
    fi
    rm -f "$OPENSSL_CONFIG_FILE"
    if [ "$openssl_status" -ne 0 ] || ! verify_csr_internal; then
        rm -f "$PRIVATE_KEY_FILE" "$CSR_FILE"
        ml_log_error "Could not generate or verify CSR"
        return 1
    fi
    chmod 600 "$CSR_FILE" || { rm -f "$PRIVATE_KEY_FILE" "$CSR_FILE"; return 1; }
    tls_write_output_manifest "${CSR_FILE}.rollback.json" "$PRIVATE_KEY_FILE" "$CSR_FILE" || {
        rm -f "$PRIVATE_KEY_FILE" "$CSR_FILE"
        return 1
    }
    ml_log_success "$CERT_TYPE certificate CSR created; protected rollback manifest recorded"
    printf '%s\n' "CSR: $CSR_FILE" "Private key: $PRIVATE_KEY_FILE"
}

generate_server_csr() { generate_csr_for_type server; }
generate_client_csr() { generate_csr_for_type client; }

# Show CSR details
show_csr() {
    ml_log_step "Displaying CSR details"

    if [ -z "$CSR_FILE" ]; then
        ml_log_error "CSR file must be specified with --csr option"
        return 1
    fi

    if [ ! -f "$CSR_FILE" ]; then
        ml_log_error "CSR file not found: $CSR_FILE"
        return 1
    fi

    ml_log_info "CSR file: $CSR_FILE"
    echo

    # Show CSR details
    openssl req -in "$CSR_FILE" -text -noout

    return 0
}

# Verify CSR format and content (internal use)
verify_csr_internal() {
    if [ ! -f "$CSR_FILE" ]; then
        ml_log_error "CSR file not found: $CSR_FILE"
        return 1
    fi

    # Verify CSR format
    if ! openssl req -in "$CSR_FILE" -noout 2>/dev/null; then
        ml_log_error "Invalid CSR format: $CSR_FILE"
        return 1
    fi

    return 0
}

# Verify CSR (external command)
verify_csr() {
    ml_log_step "Verifying CSR format and content"

    if [ -z "$CSR_FILE" ]; then
        ml_log_error "CSR file must be specified with --csr option"
        return 1
    fi

    if verify_csr_internal; then
        ml_log_success "CSR format and content verification passed"

        # Show basic CSR info
        ml_log_info "CSR Details:"
        openssl req -in "$CSR_FILE" -text -noout | grep -A10 "Subject:"
        return 0
    fi
    return 1
}

# Generate CSR and sign with CA (convenience command)
sign_with_ca() {
    ml_log_step "Generating CSR and signing with CA"

    if [ -z "$CA_CERT_FILE" ] || [ -z "$CA_KEY_FILE" ]; then
        ml_log_error "CA certificate and key files are required (--ca-cert and --ca-key)"
        return 1
    fi

    if [ ! -f "$CA_CERT_FILE" ]; then
        ml_log_error "CA certificate file not found: $CA_CERT_FILE"
        return 1
    fi

    if [ ! -f "$CA_KEY_FILE" ]; then
        ml_log_error "CA private key file not found: $CA_KEY_FILE"
        return 1
    fi
    set_default_filenames || return 1
    [ "$CERT_FILE" != "$PRIVATE_KEY_FILE" ] && [ "$CERT_FILE" != "$CSR_FILE" ] || { ml_log_error "Certificate, key, and CSR outputs must be different paths"; return 1; }
    [ ! -e "$CERT_FILE" ] && [ ! -L "$CERT_FILE" ] || { ml_log_error "Refusing to overwrite existing certificate: $CERT_FILE"; return 1; }
    [ ! -e "${CERT_FILE}.rollback.json" ] || { ml_log_error "Rollback manifest already exists for certificate output"; return 1; }

    # Determine certificate type based on SAN or other indicators
    if [ -n "$SUBJECT_ALT_NAMES" ] || [ -n "$DNS_NAMES" ] || [ -n "$IP_ADDRESSES" ]; then
        CERT_TYPE="server"
        ml_log_info "Generating server certificate (detected from SAN/DNS/IP options)"
        generate_server_csr
    else
        CERT_TYPE="client"
        ml_log_info "Generating client certificate (no SAN detected)"
        generate_client_csr
    fi

    if [ $? -ne 0 ]; then
        return 1
    fi

    # Get CA password if not provided
    if [ -z "$CA_PASSWORD" ]; then
        printf 'CA private key password: ' >&2
        IFS= read -r -s CA_PASSWORD || return 1
        printf '\n' >&2
    fi

    # Sign the CSR with CA using OpenSSL directly
    ml_log_info "Signing CSR with CA..."

    # Create a temporary config for signing with extensions
    local sign_config
    sign_config=$(mktemp) || return 1
    chmod 600 "$sign_config" || { rm -f "$sign_config"; return 1; }
    cat > "$sign_config" << EOF
[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
EOF

    if [ "$CERT_TYPE" = "server" ]; then
        echo "extendedKeyUsage = serverAuth" >> "$sign_config"
        if [ -n "$SUBJECT_ALT_NAMES" ]; then
            echo "subjectAltName = $SUBJECT_ALT_NAMES" >> "$sign_config"
        fi
    elif [ "$CERT_TYPE" = "client" ]; then
        echo "extendedKeyUsage = clientAuth" >> "$sign_config"
        if [ -n "$EMAIL" ]; then
            echo "subjectAltName = email:$EMAIL" >> "$sign_config"
        fi
    fi

    if echo "$CA_PASSWORD" | openssl x509 -req -in "$CSR_FILE" -CA "$CA_CERT_FILE" \
        -CAkey "$CA_KEY_FILE" -passin stdin -CAcreateserial -out "$CERT_FILE" \
        -days "$VALIDITY_DAYS" -sha256 -extensions v3_req -extfile "$sign_config"; then

        # Clean up temp config and record an unchanged-output rollback manifest.
        rm -f "$sign_config"
        chmod 600 "$CERT_FILE" || { rm -f "$CERT_FILE"; return 1; }
        tls_write_output_manifest "${CERT_FILE}.rollback.json" "$CERT_FILE" || { rm -f "$CERT_FILE"; return 1; }
        ml_log_success "Certificate signed and saved: $CERT_FILE"
        ml_log_warning "CA serial state is consumed and cannot be automatically rolled back"
        ml_log_info "Files created:"
        ml_log_info "  Private Key: $PRIVATE_KEY_FILE"
        ml_log_info "  CSR: $CSR_FILE"
        ml_log_info "  Certificate: $CERT_FILE"

    else
        # Remove only the new partial output; the CA serial may already have advanced.
        rm -f "$sign_config" "$CERT_FILE"
        ml_log_error "Failed to sign CSR with CA"
        return 1
    fi

    return 0
}

# Validate values interpolated into the OpenSSL configuration.
csr_validate_inputs() {
    local common_name_pattern='^[A-Za-z0-9 .,*:_@-]+$'
    [[ -n "$COMMON_NAME" && "$COMMON_NAME" =~ $common_name_pattern ]] || { ml_log_error "Common name contains unsupported characters"; return 1; }
    [[ "$KEY_SIZE" =~ ^[0-9]{4,5}$ ]] && [ "$KEY_SIZE" -ge 1024 ] && [ "$KEY_SIZE" -le 16384 ] || { ml_log_error "Key size must be 1024-16384 bits"; return 1; }
    [[ "$VALIDITY_DAYS" =~ ^[0-9]{1,5}$ ]] && [ "$VALIDITY_DAYS" -ge 1 ] && [ "$VALIDITY_DAYS" -le 36500 ] || { ml_log_error "Validity must be 1-36500 days"; return 1; }
    case "$HASH_ALGORITHM" in sha256|sha384|sha512) ;; *) ml_log_error "Hash algorithm must be sha256, sha384, or sha512"; return 1 ;; esac
    [[ "$COUNTRY$STATE$LOCALITY$ORGANIZATION$ORGANIZATIONAL_UNIT$EMAIL$SUBJECT_ALT_NAMES$DNS_NAMES$IP_ADDRESSES" != *[[:cntrl:]]* ]] || { ml_log_error "Subject fields must not contain control characters"; return 1; }
    [[ "$SUBJECT_ALT_NAMES$DNS_NAMES$IP_ADDRESSES" =~ ^[A-Za-z0-9.*,:_-]*$ ]] || { ml_log_error "SAN values contain unsupported characters"; return 1; }
}

# ================================================================
# MAIN EXECUTION
# ================================================================

main() {
    ml_show_header "Certificate Signing Request (CSR) Generation" "1.0.0" "Generate server and client CSRs for Certificate Authority signing"

    # Parse command line arguments
    parse_arguments "$@"
    if [ "$COMMAND" = "rollback" ]; then
        [ "$DRY_RUN" != "true" ] || { tls_rollback_output_manifest "$ROLLBACK_MANIFEST"; exit $?; }
        command -v jq >/dev/null 2>&1 || { ml_log_error "jq is required for rollback manifests"; exit 1; }
        command -v openssl >/dev/null 2>&1 || { ml_log_error "OpenSSL is required for rollback manifests"; exit 1; }
        tls_rollback_output_manifest "$ROLLBACK_MANIFEST"
        exit $?
    fi
    case "$COMMAND" in server-csr|client-csr|show-csr|verify-csr|sign-with-ca) ;; *) ml_log_error "Unknown command: $COMMAND"; show_usage; exit 1 ;; esac
    case "$COMMAND" in server-csr|client-csr|sign-with-ca) csr_validate_inputs || exit 1 ;; esac
    if [ "$DRY_RUN" = "true" ]; then
        ml_log_info "[DRY-RUN] Would run '$COMMAND'; no password prompt, OpenSSL operation, temporary file, or output file"
        exit 0
    fi

    # Check dependencies
    if ! check_dependencies; then
        exit 1
    fi

    # Execute and retain command status under set -e.
    local exit_code=0
    case "$COMMAND" in
        server-csr) generate_server_csr || exit_code=$? ;;
        client-csr) generate_client_csr || exit_code=$? ;;
        show-csr) show_csr || exit_code=$? ;;
        verify-csr) verify_csr || exit_code=$? ;;
        sign-with-ca) sign_with_ca || exit_code=$? ;;
    esac

    if [ $exit_code -eq 0 ]; then
        ml_log_success "Operation completed successfully"
    else
        ml_log_error "Operation failed"
    fi

    exit $exit_code
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi