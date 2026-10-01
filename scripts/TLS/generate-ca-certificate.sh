#!/bin/bash

# ================================================================
# Certificate Authority (CA) Generation Script
# ================================================================
#
# This script generates a private key with password protection and
# root certificate that can be used for signing certificate requests.
# Perfect for creating test Certificate Authorities for development
# and testing environments.
#
# Features:
# - Generate password-protected private key
# - Create self-signed root certificate
# - Customizable certificate attributes (CN, O, OU, L, C, Email)
# - Support for different key sizes and validity periods
# - Certificate chain validation
# - CA certificate bundle creation
# - Integration with MarkLogic certificate management
#
# Author: Martin Warnes
# Version: 1.0.1
# Date: November 2025
#
# Usage:
#   ./generate-ca-certificate.sh [COMMAND] [OPTIONS]
#
# Commands:
#   create-ca           Create new Certificate Authority
#   show-ca             Display CA certificate details
#   verify-ca           Verify CA certificate and private key
#   export-ca           Export CA certificate in various formats
#   sign-csr            Sign a Certificate Signing Request with this CA
#
# Examples:
#   # Create CA with default settings (ca1.example.com)
#   ./generate-ca-certificate.sh create-ca
#
#   # Create CA with custom attributes
#   ./generate-ca-certificate.sh create-ca \\
#     --cn "MyCA" \\
#     --org "My Organization" \\
#     --email "ca@example.com" \\
#     --country "GB" \\
#     --state "England" \\
#     --locality "London"
#
#   # Create CA with custom key size and validity
#   ./generate-ca-certificate.sh create-ca \\
#     --cn "Test-CA" \\
#     --key-size 4096 \\
#     --validity-days 7300
#
#   # Show CA certificate details
#   ./generate-ca-certificate.sh show-ca --ca-cert ca-certificate.pem
#
#   # Sign a CSR with the CA
#   ./generate-ca-certificate.sh sign-csr \\
#     --ca-cert ca-certificate.pem \\
#     --ca-key ca-private-key.pem \\
#     --csr server.csr \\
#     --output signed-cert.pem
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

# Certificate Authority attributes
CA_COMMON_NAME="CA1"
CA_ORGANIZATION=""
CA_ORGANIZATIONAL_UNIT=""
CA_LOCALITY=""
CA_STATE=""
CA_COUNTRY=""
CA_EMAIL=""

# Certificate options
KEY_SIZE="2048"
VALIDITY_DAYS="3650"  # 10 years default
HASH_ALGORITHM="sha256"

# File paths
CA_KEY_FILE="ca-private-key.pem"
CA_CERT_FILE="ca-certificate.pem"
CA_BUNDLE_FILE="ca-bundle.pem"
CSR_FILE=""
OUTPUT_FILE=""
PASSWORD="${TLS_CA_PASSWORD:-}"
ROLLBACK_MANIFEST=""

# OpenSSL configuration
OPENSSL_CONFIG_FILE=""

# Dry run mode
DRY_RUN="false"

# ================================================================
# UTILITY FUNCTIONS
# ================================================================

# Show usage information
show_usage() {
    cat << EOF
Certificate Authority (CA) Generation Script

USAGE:
    $0 [COMMAND] [OPTIONS]

COMMANDS:
    create-ca           Create new Certificate Authority
    show-ca             Display CA certificate details
    verify-ca           Verify CA certificate and private key
    export-ca           Export CA certificate in various formats
    sign-csr            Sign a Certificate Signing Request with this CA

CREATE-CA OPTIONS:
    --cn <name>         Common Name for the CA (default: CA1)
    --org <name>        Organization name
    --ou <unit>         Organizational Unit
    --locality <city>   Locality/City name
    --state <state>     State/Province name
    --country <code>    Country code (2 letters)
    --email <email>     Email address

CERTIFICATE OPTIONS:
    --key-size <size>   RSA key size in bits (default: 2048)
    --validity <days>   Certificate validity in days (default: 3650)
    --hash <algorithm>  Hash algorithm (default: sha256)

FILE OPTIONS:
    --ca-key <file>     CA private key file (default: ca-private-key.pem)
    --ca-cert <file>    CA certificate file (default: ca-certificate.pem)
    --ca-bundle <file>  CA bundle file (default: ca-bundle.pem)
    --csr <file>        Certificate Signing Request file
    --output <file>     Output file path
    --password <pass>   Rejected; use TLS_CA_PASSWORD or a hidden prompt

GENERAL OPTIONS:
    --dry-run           Show what would be done without executing
    --rollback FILE     Remove only unchanged outputs recorded by a protected manifest
    --yes               Skip the rollback confirmation prompt (automation only)
    --help              Show this help message

PASSWORD INPUT:
    TLS_CA_PASSWORD     CA private-key password for unattended use; otherwise hidden prompt
    Password-valued command-line arguments are rejected.

RECOVERY:
    Rolling back a signed certificate file does not reverse the CA serial increment.
    Preserve CA private keys and serial files; provider/CA issuance is not automatically reversible.

EXAMPLES:
    # Create CA with default settings
    $0 create-ca

    # Create CA with custom attributes
    $0 create-ca --cn "MyCA" --org "ACME Corp" --country "US"

    # Show CA certificate information
    $0 show-ca --ca-cert ca-certificate.pem

    # Sign a CSR
    $0 sign-csr --ca-cert ca-cert.pem --ca-key ca-key.pem --csr server.csr --output server-cert.pem

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
                CA_COMMON_NAME="$2"
                shift 2
                ;;
            --org)
                CA_ORGANIZATION="$2"
                shift 2
                ;;
            --ou)
                CA_ORGANIZATIONAL_UNIT="$2"
                shift 2
                ;;
            --locality)
                CA_LOCALITY="$2"
                shift 2
                ;;
            --state)
                CA_STATE="$2"
                shift 2
                ;;
            --country)
                CA_COUNTRY="$2"
                shift 2
                ;;
            --email)
                CA_EMAIL="$2"
                shift 2
                ;;
            --key-size)
                KEY_SIZE="$2"
                shift 2
                ;;
            --validity)
                VALIDITY_DAYS="$2"
                shift 2
                ;;
            --hash)
                HASH_ALGORITHM="$2"
                shift 2
                ;;
            --ca-key)
                CA_KEY_FILE="$2"
                shift 2
                ;;
            --ca-cert)
                CA_CERT_FILE="$2"
                shift 2
                ;;
            --ca-bundle)
                CA_BUNDLE_FILE="$2"
                shift 2
                ;;
            --csr)
                CSR_FILE="$2"
                shift 2
                ;;
            --output)
                OUTPUT_FILE="$2"
                shift 2
                ;;
            --password)
                ml_log_error "--password VALUE is rejected; use TLS_CA_PASSWORD or a hidden prompt"
                exit 1
                ;;
            --dry-run)
                DRY_RUN="true"
                shift
                ;;
            --yes)
                YES="true"
                shift
                ;;
            --help)
                show_usage
                exit 0
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
        ml_log_error "jq is required for protected rollback manifests"
        return 1
    fi

    local openssl_version
    openssl_version=$(openssl version | cut -d' ' -f2)
    ml_log_info "OpenSSL version: $openssl_version"

    ml_log_success "All dependencies found"
    return 0
}

# Generate OpenSSL configuration for CA
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
req_extensions = v3_ca
prompt = no

[ req_distinguished_name ]
EOF

    if [ -n "$CA_COUNTRY" ]; then
        echo "C = $CA_COUNTRY" >> "$OPENSSL_CONFIG_FILE"
    fi
    if [ -n "$CA_STATE" ]; then
        echo "ST = $CA_STATE" >> "$OPENSSL_CONFIG_FILE"
    fi
    if [ -n "$CA_LOCALITY" ]; then
        echo "L = $CA_LOCALITY" >> "$OPENSSL_CONFIG_FILE"
    fi
    if [ -n "$CA_ORGANIZATION" ]; then
        echo "O = $CA_ORGANIZATION" >> "$OPENSSL_CONFIG_FILE"
    fi
    if [ -n "$CA_ORGANIZATIONAL_UNIT" ]; then
        echo "OU = $CA_ORGANIZATIONAL_UNIT" >> "$OPENSSL_CONFIG_FILE"
    fi
    echo "CN = $CA_COMMON_NAME" >> "$OPENSSL_CONFIG_FILE"
    if [ -n "$CA_EMAIL" ]; then
        echo "emailAddress = $CA_EMAIL" >> "$OPENSSL_CONFIG_FILE"
    fi

    cat >> "$OPENSSL_CONFIG_FILE" << EOF

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical,CA:true
keyUsage = critical,digitalSignature,cRLSign,keyCertSign
EOF

    ml_log_verbose "Generated OpenSSL configuration file: $OPENSSL_CONFIG_FILE"
}

# Prompt for password if not provided
get_ca_password() {
    if [ -z "$PASSWORD" ]; then
        ml_log_info "CA private key password is required for security"
        printf 'Enter password for CA private key: ' >&2
        IFS= read -r -s PASSWORD || return 1
        printf '\n' >&2
        printf 'Confirm password: ' >&2
        IFS= read -r -s PASSWORD_CONFIRM || return 1
        printf '\n' >&2

        if [ "$PASSWORD" != "$PASSWORD_CONFIRM" ]; then
            ml_log_error "Passwords do not match"
            return 1
        fi

        if [ ${#PASSWORD} -lt 8 ]; then
            ml_log_error "Password must be at least 8 characters long"
            return 1
        fi
    fi
    case "$PASSWORD" in *$'\n'*|*$'\r'*) ml_log_error "CA password must not contain line breaks"; return 1 ;; esac
    [ ${#PASSWORD} -ge 8 ] || { ml_log_error "CA password must be at least 8 characters long"; return 1; }
}

# ================================================================
# CA GENERATION FUNCTIONS
# ================================================================

# Create a new CA only at unused output paths; keep generated files owner-only.
ca_create() {
    ml_log_step "Creating Certificate Authority: $CA_COMMON_NAME"
    local key_dir cert_dir bundle_dir old_umask path
    key_dir=$(cd "$(dirname "$CA_KEY_FILE")" && pwd -P) || return 1
    cert_dir=$(cd "$(dirname "$CA_CERT_FILE")" && pwd -P) || return 1
    bundle_dir=$(cd "$(dirname "$CA_BUNDLE_FILE")" && pwd -P) || return 1
    [ "$key_dir" = "$cert_dir" ] && [ "$cert_dir" = "$bundle_dir" ] || { ml_log_error "CA outputs must share a directory for rollback tracking"; return 1; }
    for path in "$CA_KEY_FILE" "$CA_CERT_FILE" "$CA_BUNDLE_FILE" "${CA_CERT_FILE}.rollback.json"; do
        [[ "$path" != *[[:cntrl:]]* ]] || { ml_log_error "CA output path contains a control character"; return 1; }
        [ ! -e "$path" ] && [ ! -L "$path" ] || { ml_log_error "Refusing to overwrite existing CA output: $path"; return 1; }
    done
    get_ca_password || return 1
    generate_openssl_config || return 1

    old_umask=$(umask)
    umask 077
    if ! printf '%s\n' "$PASSWORD" | openssl genrsa -aes256 -passout stdin -out "$CA_KEY_FILE" "$KEY_SIZE"; then
        umask "$old_umask"
        rm -f "$CA_KEY_FILE" "$CA_CERT_FILE" "$CA_BUNDLE_FILE" "$OPENSSL_CONFIG_FILE"
        ml_log_error "Failed to generate CA private key"
        return 1
    fi
    chmod 600 "$CA_KEY_FILE" || { umask "$old_umask"; rm -f "$CA_KEY_FILE" "$OPENSSL_CONFIG_FILE"; return 1; }
    if ! printf '%s\n' "$PASSWORD" | openssl req -new -x509 -key "$CA_KEY_FILE" -passin stdin \
        -out "$CA_CERT_FILE" -days "$VALIDITY_DAYS" -config "$OPENSSL_CONFIG_FILE" -extensions v3_ca -"$HASH_ALGORITHM"; then
        umask "$old_umask"
        rm -f "$CA_KEY_FILE" "$CA_CERT_FILE" "$CA_BUNDLE_FILE" "$OPENSSL_CONFIG_FILE"
        ml_log_error "Failed to generate CA certificate"
        return 1
    fi
    if ! cp "$CA_CERT_FILE" "$CA_BUNDLE_FILE"; then
        umask "$old_umask"
        rm -f "$CA_KEY_FILE" "$CA_CERT_FILE" "$CA_BUNDLE_FILE" "$OPENSSL_CONFIG_FILE"
        ml_log_error "Failed to create CA bundle"
        return 1
    fi
    chmod 600 "$CA_CERT_FILE" "$CA_BUNDLE_FILE"
    umask "$old_umask"
    rm -f "$OPENSSL_CONFIG_FILE"

    if ! ca_verify; then
        rm -f "$CA_KEY_FILE" "$CA_CERT_FILE" "$CA_BUNDLE_FILE"
        ml_log_error "Generated CA failed verification; newly created outputs were removed"
        return 1
    fi
    if ! tls_write_output_manifest "${CA_CERT_FILE}.rollback.json" "$CA_KEY_FILE" "$CA_CERT_FILE" "$CA_BUNDLE_FILE"; then
        rm -f "$CA_KEY_FILE" "$CA_CERT_FILE" "$CA_BUNDLE_FILE"
        ml_log_error "Could not record protected rollback manifest; generated outputs were removed"
        return 1
    fi
    ml_log_success "Certificate Authority created; protected rollback manifest records its generated files"
    ml_log_warning "Keep the CA private key securely backed up; rollback removes only unchanged generated files"
}

# Show CA certificate details
ca_show() {
    ml_log_step "Displaying CA certificate details"

    if [ ! -f "$CA_CERT_FILE" ]; then
        ml_log_error "CA certificate file not found: $CA_CERT_FILE"
        return 1
    fi

    # Validate certificate format
    if ! tls_validate_certificate "$CA_CERT_FILE"; then
        return 1
    fi

    ml_log_info "Certificate file: $CA_CERT_FILE"
    echo

    # Show certificate details
    openssl x509 -in "$CA_CERT_FILE" -text -noout

    return 0
}

# Verify CA certificate and private key
ca_verify() {
    ml_log_step "Verifying CA certificate and private key"

    if [ ! -f "$CA_CERT_FILE" ]; then
        ml_log_error "CA certificate file not found: $CA_CERT_FILE"
        return 1
    fi

    if [ ! -f "$CA_KEY_FILE" ]; then
        ml_log_error "CA private key file not found: $CA_KEY_FILE"
        return 1
    fi

    # Validate certificate format
    if ! tls_validate_certificate "$CA_CERT_FILE"; then
        return 1
    fi

    # Check if certificate is a CA certificate
    if ! openssl x509 -in "$CA_CERT_FILE" -text -noout | grep -q "CA:TRUE"; then
        ml_log_error "Certificate is not a CA certificate"
        return 1
    fi

    # Get password for private key verification
    if [ -z "$PASSWORD" ]; then
        printf 'CA private key password: ' >&2
        IFS= read -r -s PASSWORD || return 1
        printf '\n' >&2
    fi

    # Verify private key can be read with password
    if ! printf '%s\n' "$PASSWORD" | openssl rsa -in "$CA_KEY_FILE" -passin stdin -noout 2>/dev/null; then
        ml_log_error "Cannot read private key with provided password"
        return 1
    fi

    # Compare SHA-256 digests of public keys without exposing the private key.
    local cert_hash key_hash
    cert_hash=$(openssl x509 -in "$CA_CERT_FILE" -pubkey -noout 2>/dev/null | openssl dgst -sha256 | awk '{print $NF}') || return 1
    key_hash=$(printf '%s\n' "$PASSWORD" | openssl pkey -pubout -in "$CA_KEY_FILE" -passin stdin 2>/dev/null | openssl dgst -sha256 | awk '{print $NF}') || return 1

    if [ "$cert_hash" != "$key_hash" ]; then
        ml_log_error "Certificate and private key do not match"
        return 1
    fi

    ml_log_success "CA certificate and private key verification passed"
    return 0
}

# Export CA certificate in several formats without overwriting existing files.
ca_export() {
    ml_log_step "Exporting CA certificate"
    [ -r "$CA_CERT_FILE" ] || { ml_log_error "CA certificate is not readable"; return 1; }
    [ -n "$OUTPUT_FILE" ] || OUTPUT_FILE="ca-export"
    [[ "$OUTPUT_FILE" != *[[:cntrl:]]* ]] || { ml_log_error "Export path contains control characters"; return 1; }
    local pem_file="${OUTPUT_FILE}.pem" der_file="${OUTPUT_FILE}.der" p7b_file="${OUTPUT_FILE}.p7b" manifest="${OUTPUT_FILE}.rollback.json" old_umask file
    for file in "$pem_file" "$der_file" "$p7b_file" "$manifest"; do
        [ ! -e "$file" ] && [ ! -L "$file" ] || { ml_log_error "Refusing to overwrite existing export: $file"; return 1; }
    done
    old_umask=$(umask)
    umask 077
    if ! cp "$CA_CERT_FILE" "$pem_file" || ! openssl x509 -in "$CA_CERT_FILE" -outform DER -out "$der_file" || ! openssl crl2pkcs7 -nocrl -certfile "$CA_CERT_FILE" -out "$p7b_file"; then
        umask "$old_umask"
        rm -f "$pem_file" "$der_file" "$p7b_file"
        ml_log_error "Could not export every requested CA format"
        return 1
    fi
    chmod 600 "$pem_file" "$der_file" "$p7b_file" || { umask "$old_umask"; rm -f "$pem_file" "$der_file" "$p7b_file"; return 1; }
    umask "$old_umask"
    tls_write_output_manifest "$manifest" "$pem_file" "$der_file" "$p7b_file" || { rm -f "$pem_file" "$der_file" "$p7b_file"; return 1; }
    ml_log_success "CA exports created with a protected rollback manifest"
}

# Sign a Certificate Signing Request
ca_sign_csr() {
    ml_log_step "Signing Certificate Signing Request"

    if [ -z "$CSR_FILE" ]; then
        ml_log_error "CSR file must be specified with --csr option"
        return 1
    fi

    if [ ! -f "$CSR_FILE" ]; then
        ml_log_error "CSR file not found: $CSR_FILE"
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

    if [ -z "$OUTPUT_FILE" ]; then
        OUTPUT_FILE="signed-certificate.pem"
    fi
    [[ "$OUTPUT_FILE" != *[[:cntrl:]]* ]] || { ml_log_error "Output path contains control characters"; return 1; }
    [ ! -e "$OUTPUT_FILE" ] && [ ! -L "$OUTPUT_FILE" ] || { ml_log_error "Refusing to overwrite existing signed certificate: $OUTPUT_FILE"; return 1; }
    [ ! -e "${OUTPUT_FILE}.rollback.json" ] || { ml_log_error "Rollback manifest already exists for output"; return 1; }

    # Verify CSR format
    if ! openssl req -in "$CSR_FILE" -noout 2>/dev/null; then
        ml_log_error "Invalid CSR format: $CSR_FILE"
        return 1
    fi

    get_ca_password || return 1

    ml_log_info "CSR file: $CSR_FILE"
    ml_log_info "Output file: $OUTPUT_FILE"

    # Show CSR details
    ml_log_info "CSR Details:"
    openssl req -in "$CSR_FILE" -text -noout | grep -A10 "Subject:"

    if [ "$DRY_RUN" = "true" ]; then
        ml_log_info "DRY RUN: Would sign CSR with CA"
        return 0
    fi

    # Sign the CSR; the password is supplied over stdin, never argv.
    ml_log_info "Signing CSR with CA..."
    local old_umask openssl_status
    old_umask=$(umask)
    umask 077
    if printf '%s\n' "$PASSWORD" | openssl x509 -req -in "$CSR_FILE" -CA "$CA_CERT_FILE" \
        -CAkey "$CA_KEY_FILE" -passin stdin -CAcreateserial -out "$OUTPUT_FILE" \
        -days "$VALIDITY_DAYS" -copy_extensions copyall -"$HASH_ALGORITHM"; then
        openssl_status=0
    else
        openssl_status=$?
    fi
    umask "$old_umask"
    if [ "$openssl_status" -ne 0 ]; then
        rm -f "$OUTPUT_FILE"
        ml_log_error "Failed to sign CSR (OpenSSL status $openssl_status)"
        return 1
    fi
    chmod 600 "$OUTPUT_FILE" || { rm -f "$OUTPUT_FILE"; return 1; }
    tls_write_output_manifest "${OUTPUT_FILE}.rollback.json" "$OUTPUT_FILE" || { rm -f "$OUTPUT_FILE"; return 1; }
    ml_log_success "Certificate signed and saved: $OUTPUT_FILE"
    ml_log_warning "CA serial number was consumed and is not automatically rolled back"
    ml_log_info "Signed certificate details:"
    openssl x509 -in "$OUTPUT_FILE" -noout -subject -dates
    return 0
}

# ================================================================
# MAIN EXECUTION
# ================================================================

main() {
    ml_show_header "Certificate Authority (CA) Generation" "1.0.0" "Generate CA material and sign CSRs"
    parse_arguments "$@"

    if [ "$COMMAND" = "rollback" ]; then
        if [ "$DRY_RUN" = "true" ]; then tls_rollback_output_manifest "$ROLLBACK_MANIFEST"; exit $?; fi
        command -v jq >/dev/null 2>&1 || { ml_log_error "jq is required for rollback manifests"; exit 1; }
        command -v openssl >/dev/null 2>&1 || { ml_log_error "OpenSSL is required for rollback manifests"; exit 1; }
        tls_rollback_output_manifest "$ROLLBACK_MANIFEST"
        exit $?
    fi
    case "$COMMAND" in create-ca|show-ca|verify-ca|export-ca|sign-csr) ;; *) ml_log_error "Unknown command: $COMMAND"; show_usage; exit 1 ;; esac
    [[ "$KEY_SIZE" =~ ^[0-9]{4,5}$ ]] && [ "$KEY_SIZE" -ge 1024 ] && [ "$KEY_SIZE" -le 16384 ] || { ml_log_error "Key size must be 1024-16384 bits"; exit 1; }
    [[ "$VALIDITY_DAYS" =~ ^[0-9]{1,5}$ ]] && [ "$VALIDITY_DAYS" -ge 1 ] && [ "$VALIDITY_DAYS" -le 36500 ] || { ml_log_error "Validity must be 1-36500 days"; exit 1; }
    case "$HASH_ALGORITHM" in sha256|sha384|sha512) ;; *) ml_log_error "Hash algorithm must be sha256, sha384, or sha512"; exit 1 ;; esac
    local common_name_pattern='^[A-Za-z0-9 .,*:_@-]+$'
    [[ "$CA_COMMON_NAME" =~ $common_name_pattern ]] || { ml_log_error "CA common name contains unsupported characters"; exit 1; }
    local subject_fields_pattern='^[A-Za-z0-9 .,&()_-]*$'
    [[ "$CA_ORGANIZATION$CA_ORGANIZATIONAL_UNIT$CA_LOCALITY$CA_STATE" =~ $subject_fields_pattern ]] || { ml_log_error "CA subject fields contain unsupported characters"; exit 1; }
    [ -z "$CA_COUNTRY" ] || [[ "$CA_COUNTRY" =~ ^[A-Za-z]{2}$ ]] || { ml_log_error "Country must be a two-letter code"; exit 1; }
    [[ "$CA_EMAIL" =~ ^[A-Za-z0-9._+@-]*$ ]] || { ml_log_error "CA email contains unsupported characters"; exit 1; }
    local path
    for path in "$CA_KEY_FILE" "$CA_CERT_FILE" "$CA_BUNDLE_FILE" "$CSR_FILE" "$OUTPUT_FILE"; do
        [[ "$path" != *[[:cntrl:]]* ]] || { ml_log_error "File path contains a control character"; exit 1; }
    done
    if [ "$COMMAND" = "sign-csr" ]; then
        [ -n "$CSR_FILE" ] && [ -r "$CSR_FILE" ] && [ -r "$CA_CERT_FILE" ] && [ -r "$CA_KEY_FILE" ] || { ml_log_error "Readable CSR, CA certificate, and CA key files are required"; exit 1; }
    fi
    if [ "$DRY_RUN" = "true" ]; then
        ml_log_info "[DRY-RUN] Would run '$COMMAND'; no password prompt, OpenSSL key/signing operation, temp file, or output file"
        exit 0
    fi
    check_dependencies || exit 1

    local exit_code=0
    case "$COMMAND" in
        create-ca) ca_create || exit_code=$? ;;
        show-ca) ca_show || exit_code=$? ;;
        verify-ca) ca_verify || exit_code=$? ;;
        export-ca) ca_export || exit_code=$? ;;
        sign-csr) ca_sign_csr || exit_code=$? ;;
    esac
    if [ "$exit_code" -eq 0 ]; then ml_log_success "Operation completed successfully"; else ml_log_error "Operation failed"; fi
    exit "$exit_code"
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi