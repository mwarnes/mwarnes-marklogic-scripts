#!/bin/bash

# ================================================================
# TLS Certificate Validation Script
# ================================================================
#
# This script validates TLS certificates, keys, and SSL configurations
# for MarkLogic environments. It provides comprehensive validation
# including certificate format checking, expiry monitoring, chain
# verification, and SSL connection testing.
#
# Features:
# - Certificate and private key validation
# - Certificate/key pair matching verification
# - Certificate chain validation
# - SSL connection testing and analysis
# - Certificate expiry monitoring
# - CSR validation and analysis
# - PKCS12 keystore validation
# - Detailed certificate information extraction
#
# Author: Martin Warnes
# Version: 1.0.1
# Date: November 2025
#
# Usage:
#   ./validate-tls.sh [COMMAND] [OPTIONS]
#
# Commands:
#   validate-cert       Validate certificate file
#   validate-key        Validate private key file
#   validate-pair       Validate certificate/key pair
#   validate-chain      Validate certificate chain
#   validate-csr        Validate Certificate Signing Request
#   validate-p12        Validate PKCS12 keystore
#   test-connection     Test SSL/TLS connection
#   check-expiry        Check certificate expiration
#   show-cert-info      Show detailed certificate information
#   show-csr-info       Show CSR information
#   test-protocols      Test SSL/TLS protocol support
#
# Examples:
#   # Validate certificate
#   ./validate-tls.sh validate-cert --cert-file server.crt
#
#   # Validate certificate/key pair
#   ./validate-tls.sh validate-pair --cert-file server.crt --key-file server.key
#
#   # Validate certificate chain
#   ./validate-tls.sh validate-chain --cert-file server.crt --ca-file ca.crt --intermediate-file intermediate.crt
#
#   # Test SSL connection
#   ./validate-tls.sh test-connection --host marklogic.example.com --port 8443
#
#   # Check certificate expiry
#   ./validate-tls.sh check-expiry --cert-file server.crt --warn-days 30
#
# ================================================================

set -euo pipefail

# Source utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/tls-utils.sh"

# ================================================================
# CONFIGURATION VARIABLES
# ================================================================

# Default values
COMMAND=""
CERT_FILE=""
KEY_FILE=""
CA_FILE=""
INTERMEDIATE_FILE=""
CSR_FILE=""
P12_FILE=""
P12_PASSWORD="${TLS_P12_PASSWORD:-}"
HOST=""
PORT="8443"
WARN_DAYS="30"
OUTPUT_FORMAT="text"
VERBOSE="false"
DRY_RUN="false"

# ================================================================
# VALIDATION FUNCTIONS
# ================================================================

# Comprehensive certificate validation
validate_certificate_comprehensive() {
    ml_log_step "Comprehensive certificate validation: $CERT_FILE"

    local validation_passed=true

    # Basic format validation
    if ! tls_validate_certificate "$CERT_FILE"; then
        validation_passed=false
    fi

    if [ "$validation_passed" = "false" ]; then
        return 1
    fi

    # Show certificate information
    echo
    tls_get_certificate_info "$CERT_FILE"

    # Expiry helper returns days on stdout and status 0/2/3/1 for healthy/near/expired/error.
    echo
    local days_remaining expiry_status
    if days_remaining=$(tls_check_certificate_expiry "$CERT_FILE" "$WARN_DAYS"); then
        ml_log_info "Days remaining: $days_remaining"
    else
        expiry_status=$?
        case "$expiry_status" in
            2) ml_log_warning "Certificate is near expiry ($days_remaining day(s) remain)" ;;
            3) ml_log_error "Certificate is expired ($days_remaining day(s))"; validation_passed=false ;;
            *) ml_log_error "Could not determine certificate expiry"; validation_passed=false ;;
        esac
    fi

    # Validate certificate chain if issuer is not self
    local subject issuer
    subject=$(openssl x509 -in "$CERT_FILE" -noout -subject | sed 's/subject=//')
    issuer=$(openssl x509 -in "$CERT_FILE" -noout -issuer | sed 's/issuer=//')

    if [ "$subject" != "$issuer" ]; then
        ml_log_info "Certificate is not self-signed"
        if [ -n "$CA_FILE" ]; then
            echo
            ml_log_step "Validating certificate chain"
            if ! tls_verify_certificate_chain "$CERT_FILE" "$CA_FILE" "$INTERMEDIATE_FILE"; then
                validation_passed=false
            fi
        else
            ml_log_warning "Certificate is not self-signed but no CA file provided for chain validation"
        fi
    else
        ml_log_info "Certificate is self-signed"
    fi

    if [ "$validation_passed" = "true" ]; then
        ml_log_success "Certificate validation passed"
        return 0
    else
        ml_log_error "Certificate validation failed"
        return 1
    fi
}

# Validate certificate and key pair
validate_cert_key_pair() {
    ml_log_step "Validating certificate and private key pair"

    if ! tls_validate_certificate "$CERT_FILE"; then
        return 1
    fi

    if ! tls_validate_private_key "$KEY_FILE"; then
        return 1
    fi

    if ! tls_verify_cert_key_match "$CERT_FILE" "$KEY_FILE"; then
        return 1
    fi

    ml_log_success "Certificate and private key validation passed"
    return 0
}

# Validate PKCS12 without putting passwords in argv or leaving extracted keys behind.
validate_pkcs12_keystore() {
    ml_log_step "Validating PKCS12 keystore: $P12_FILE"
    [ -r "$P12_FILE" ] || { ml_log_error "PKCS12 file is not readable"; return 1; }
    if [ "$DRY_RUN" = "true" ]; then
        ml_log_info "[DRY-RUN] Would validate PKCS12 contents; no password prompt or temporary output"
        return 0
    fi

    local temp_dir temp_cert temp_key expiry_result days_remaining
    temp_dir=$(mktemp -d) || return 1
    chmod 700 "$temp_dir" || { rm -rf "$temp_dir"; return 1; }
    temp_cert="$temp_dir/certificate.pem"
    temp_key="$temp_dir/private-key.pem"
    if ! tls_extract_from_pkcs12 "$P12_FILE" "$P12_PASSWORD" "$temp_cert" "$temp_key"; then
        rm -rf "$temp_dir"
        ml_log_error "Invalid PKCS12 format or incorrect password"
        return 1
    fi

    ml_log_success "PKCS12 keystore format is valid"
    tls_get_certificate_info "$temp_cert"
    if days_remaining=$(tls_check_certificate_expiry "$temp_cert" "$WARN_DAYS"); then
        expiry_result=0
    else
        expiry_result=$?
    fi
    rm -rf "$temp_dir"
    case "$expiry_result" in
        0) ml_log_info "Days remaining: $days_remaining"; return 0 ;;
        2) ml_log_warning "PKCS12 certificate is near expiry ($days_remaining day(s) remain)"; return 2 ;;
        3) ml_log_error "PKCS12 certificate has expired ($days_remaining day(s))"; return 3 ;;
        *) ml_log_error "Could not determine PKCS12 certificate expiry"; return 1 ;;
    esac
}

# Test SSL connection with detailed analysis
test_ssl_connection_detailed() {
    ml_log_step "Testing SSL connection to $HOST:$PORT"

    # Basic connectivity test
    if ! nc -z "$HOST" "$PORT" 2>/dev/null; then
        ml_log_error "Cannot connect to $HOST:$PORT - connection refused"
        ml_log_error "Check that:"
        ml_log_error "  1. MarkLogic Server is running"
        ml_log_error "  2. App server is configured on port $PORT"
        ml_log_error "  3. Firewall allows connections to port $PORT"
        return 1
    fi

    ml_log_success "TCP connection to $HOST:$PORT successful"
    echo

    # SSL handshake test
    if ! echo | openssl s_client -connect "$HOST:$PORT" -servername "$HOST" -verify_return_error -verify_hostname "$HOST" 2>/dev/null >/dev/null; then
        ml_log_error "SSL handshake failed"
        ml_log_error "Common causes:"
        ml_log_error "  1. SSL not enabled on app server"
        ml_log_error "  2. Invalid certificate configuration"
        ml_log_error "  3. Certificate/key mismatch"
        ml_log_error "  4. Unsupported TLS version"
        return 1
    fi

    ml_log_success "SSL handshake successful"
    echo

    # Get detailed connection information
    export TLS_CA_FILE="${CA_FILE:-${TLS_CA_FILE:-}}"
    tls_get_ssl_connection_info "$HOST" "$PORT" || return 1

    echo
    echo

    # Protocol probes may be skipped when neither timeout nor gtimeout is available.
    tls_test_ssl_protocols "$HOST" "$PORT" || {
        local probe_status=$?
        [ "$probe_status" -eq 3 ] || return "$probe_status"
    }

    return 0
}

# ================================================================
# COMMAND LINE INTERFACE
# ================================================================

show_usage() {
    cat << EOF
Usage: $0 [COMMAND] [OPTIONS]

TLS Certificate Validation Script

COMMANDS:
    validate-cert       Validate certificate file
    validate-key        Validate private key file
    validate-pair       Validate certificate/key pair
    validate-chain      Validate certificate chain
    validate-csr        Validate Certificate Signing Request
    validate-p12        Validate PKCS12 keystore
    test-connection     Test SSL/TLS connection
    check-expiry        Check certificate expiration
    show-cert-info      Show detailed certificate information
    show-csr-info       Show CSR information
    test-protocols      Test SSL/TLS protocol support

VALIDATE-CERT OPTIONS:
    --cert-file FILE              Certificate file path (required)
    --ca-file FILE                CA certificate file (for chain validation)
    --intermediate-file FILE      Intermediate certificate file
    --warn-days DAYS              Days before expiry to warn (default: 30)

VALIDATE-KEY OPTIONS:
    --key-file FILE               Private key file path (required)

VALIDATE-PAIR OPTIONS:
    --cert-file FILE              Certificate file path (required)
    --key-file FILE               Private key file path (required)

VALIDATE-CHAIN OPTIONS:
    --cert-file FILE              Certificate file path (required)
    --ca-file FILE                CA certificate file (required)
    --intermediate-file FILE      Intermediate certificate file (optional)

VALIDATE-CSR OPTIONS:
    --csr-file FILE               CSR file path (required)

VALIDATE-P12 OPTIONS:
    --p12-file FILE               PKCS12 keystore file path (required)
    --p12-password PASS           Rejected; use TLS_P12_PASSWORD or a hidden prompt
    --warn-days DAYS              Days before expiry to warn (default: 30)

TEST-CONNECTION OPTIONS:
    --host HOSTNAME               Hostname to test (required)
    --port PORT                   Port to test (default: 8443)

CHECK-EXPIRY OPTIONS:
    --cert-file FILE              Certificate file path (required)
    --warn-days DAYS              Days before expiry to warn (default: 30)

SHOW-CERT-INFO OPTIONS:
    --cert-file FILE              Certificate file path (required)

SHOW-CSR-INFO OPTIONS:
    --csr-file FILE               CSR file path (required)

TEST-PROTOCOLS OPTIONS:
    --host HOSTNAME               Hostname to test (required)
    --port PORT                   Port to test (default: 8443)

GLOBAL OPTIONS:
    --verbose                     Enable safe verbose output
    --dry-run                     Preview only; no file reads, writes, or network probes
    --output-format FORMAT       Output format: text|json (default: text)
    --help                        Show this help message

EXAMPLES:
    # Validate certificate with expiry check
    $0 validate-cert --cert-file server.crt --warn-days 60

    # Validate certificate/key pair
    $0 validate-pair --cert-file server.crt --key-file server.key

    # Validate complete certificate chain
    $0 validate-chain --cert-file server.crt --ca-file ca.crt --intermediate-file intermediate.crt

    # Test SSL connection with protocol analysis
    $0 test-connection --host marklogic.example.com --port 8443

    # Validate PKCS12 keystore (prompt hidden; or set TLS_P12_PASSWORD)
    $0 validate-p12 --p12-file keystore.p12

    # Check certificate expiry with custom warning period
    $0 check-expiry --cert-file server.crt --warn-days 90

    # Show detailed certificate information
    $0 show-cert-info --cert-file server.crt

    # Validate CSR before submission to CA
    $0 validate-csr --csr-file server.csr

    # Test SSL protocol and cipher support
    $0 test-protocols --host marklogic.example.com --port 8443

EOF
}

# Parse command line arguments
parse_arguments() {
    if [ $# -eq 0 ]; then
        show_usage
        exit 1
    fi
    if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
        show_usage
        exit 0
    fi

    COMMAND="$1"
    shift

    # Parse remaining arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --cert-file)
                CERT_FILE="$2"
                shift 2
                ;;
            --key-file)
                KEY_FILE="$2"
                shift 2
                ;;
            --ca-file)
                CA_FILE="$2"
                shift 2
                ;;
            --intermediate-file)
                INTERMEDIATE_FILE="$2"
                shift 2
                ;;
            --csr-file)
                CSR_FILE="$2"
                shift 2
                ;;
            --p12-file)
                P12_FILE="$2"
                shift 2
                ;;
            --p12-password)
                ml_log_error "--p12-password VALUE is rejected; use TLS_P12_PASSWORD or a hidden prompt"
                exit 1
                ;;
            --host)
                HOST="$2"
                shift 2
                ;;
            --port)
                PORT="$2"
                shift 2
                ;;
            --warn-days)
                WARN_DAYS="$2"
                shift 2
                ;;
            --output-format)
                OUTPUT_FORMAT="$2"
                shift 2
                ;;
            --verbose)
                VERBOSE="true"
                shift
                ;;
            --dry-run)
                DRY_RUN="true"
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

# Main execution function
main() {
    ml_show_header "TLS Certificate Validation" "1.0.0" \
        "Validate TLS certificates and SSL configurations"

    # Never enable xtrace: it can reveal passwords and private-key paths.
    case "$COMMAND" in
        validate-cert|validate-key|validate-pair|validate-chain|validate-csr|validate-p12|test-connection|check-expiry|show-cert-info|show-csr-info|test-protocols) ;;
        *) ml_log_error "Unknown command: $COMMAND"; show_usage; exit 1 ;;
    esac
    [[ "$WARN_DAYS" =~ ^[0-9]+$ ]] || { ml_log_error "Warning days must be a non-negative integer"; exit 1; }
    case "$COMMAND" in
        validate-cert|check-expiry|show-cert-info) [ -n "$CERT_FILE" ] || { ml_log_error "--cert-file is required"; exit 1; } ;;
        validate-key) [ -n "$KEY_FILE" ] || { ml_log_error "--key-file is required"; exit 1; } ;;
        validate-pair) [ -n "$CERT_FILE" ] && [ -n "$KEY_FILE" ] || { ml_log_error "--cert-file and --key-file are required"; exit 1; } ;;
        validate-chain) [ -n "$CERT_FILE" ] && [ -n "$CA_FILE" ] || { ml_log_error "--cert-file and --ca-file are required"; exit 1; } ;;
        validate-csr|show-csr-info) [ -n "$CSR_FILE" ] || { ml_log_error "--csr-file is required"; exit 1; } ;;
        validate-p12) [ -n "$P12_FILE" ] || { ml_log_error "--p12-file is required"; exit 1; } ;;
        test-connection|test-protocols) [ -n "$HOST" ] || { ml_log_error "--host is required"; exit 1; } ;;
    esac

    if [ "$DRY_RUN" = "true" ]; then
        ml_log_info "[DRY-RUN] Would run '$COMMAND'; no certificate was read, no temp file was created, and no network probe was made"
        exit 0
    fi
    command -v openssl >/dev/null 2>&1 || { ml_log_error "OpenSSL is required but not found"; exit 1; }
    if [ "$COMMAND" = "validate-p12" ] && [ -z "$P12_PASSWORD" ] && [ -t 0 ]; then
        printf 'PKCS12 password (press Enter if empty): ' >&2
        IFS= read -r -s P12_PASSWORD || exit 1
        printf '\n' >&2
    fi

    local exit_code=0
    case "$COMMAND" in
        validate-cert) validate_certificate_comprehensive || exit_code=$? ;;
        validate-key) tls_validate_private_key "$KEY_FILE" || exit_code=$? ;;
        validate-pair) validate_cert_key_pair || exit_code=$? ;;
        validate-chain) tls_verify_certificate_chain "$CERT_FILE" "$CA_FILE" "$INTERMEDIATE_FILE" || exit_code=$? ;;
        validate-csr) tls_validate_csr "$CSR_FILE" || exit_code=$? ;;
        validate-p12) validate_pkcs12_keystore || exit_code=$? ;;
        test-connection) test_ssl_connection_detailed || exit_code=$? ;;
        check-expiry) tls_check_certificate_expiry "$CERT_FILE" "$WARN_DAYS" || exit_code=$? ;;
        show-cert-info) tls_get_certificate_info "$CERT_FILE" || exit_code=$? ;;
        show-csr-info) tls_get_csr_info "$CSR_FILE" || exit_code=$? ;;
        test-protocols) export TLS_CA_FILE="${CA_FILE:-${TLS_CA_FILE:-}}"; tls_test_ssl_protocols "$HOST" "$PORT" || exit_code=$? ;;
    esac

    if [ "$exit_code" -eq 0 ]; then
        echo
        case "$COMMAND" in
            validate-cert|validate-pair|validate-chain) ml_show_footer "Certificate validation completed" ;;
            test-connection|test-protocols) ml_show_footer "SSL/TLS testing completed" ;;
            *) ml_show_footer "" ;;
        esac
    fi
    exit "$exit_code"
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    parse_arguments "$@"
    main
fi