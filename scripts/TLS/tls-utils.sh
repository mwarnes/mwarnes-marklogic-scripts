#!/bin/bash

# ================================================================
# TLS Certificate Management Utilities
# ================================================================
#
# Common utility functions for TLS/SSL certificate management
# in MarkLogic environments. These functions provide validation,
# certificate parsing, and certificate chain verification utilities.
#
# Author: Martin Warnes
# Version: 1.0.1
# Date: November 2025
#
# ================================================================

# Source common utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../marklogic-utils.sh"

# ================================================================
# CERTIFICATE VALIDATION FUNCTIONS
# ================================================================

# Validate certificate file format
tls_validate_certificate() {
    local cert_file="$1"

    if [ ! -f "$cert_file" ]; then
        ml_log_error "Certificate file not found: $cert_file"
        return 1
    fi

    # Check if it's a valid certificate
    if ! openssl x509 -in "$cert_file" -noout 2>/dev/null; then
        ml_log_error "Invalid certificate format: $cert_file"
        return 1
    fi

    ml_log_success "Certificate format is valid: $cert_file"
    return 0
}

# Run OpenSSL key operations with a passphrase from the environment or a protected pipe.
tls_run_private_key_openssl() {
    local key_file="$1"
    shift
    case "${TLS_KEY_PASSWORD:-}" in
        *$'\n'*|*$'\r'*) ml_log_error "Private-key password must not contain line breaks"; return 1 ;;
    esac
    if [ -n "${TLS_KEY_PASSWORD:-}" ]; then
        printf '%s\n' "$TLS_KEY_PASSWORD" | openssl pkey -in "$key_file" -passin stdin "$@" 2>/dev/null
    else
        openssl pkey -in "$key_file" -passin pass: "$@" 2>/dev/null
    fi
}

# Validate private key format; prompt without echo only if an encrypted key needs it.
tls_validate_private_key() {
    local key_file="$1" key_password
    [ -f "$key_file" ] || { ml_log_error "Private key file not found: $key_file"; return 1; }
    if tls_run_private_key_openssl "$key_file" -check -noout >/dev/null; then
        ml_log_success "Private key format is valid: $key_file"
        return 0
    fi
    if [ -z "${TLS_KEY_PASSWORD:-}" ] && [ -t 0 ]; then
        printf 'Private key password: ' >&2
        IFS= read -r -s key_password || return 1
        printf '\n' >&2
        TLS_KEY_PASSWORD="$key_password"
        if tls_run_private_key_openssl "$key_file" -check -noout >/dev/null; then
            ml_log_success "Private key format is valid: $key_file"
            return 0
        fi
    fi
    ml_log_error "Invalid private key format or incorrect TLS_KEY_PASSWORD"
    return 1
}

# Check if certificate and private key match
tls_verify_cert_key_match() {
    local cert_file="$1"
    local key_file="$2"

    if ! tls_validate_certificate "$cert_file" || ! tls_validate_private_key "$key_file"; then
        return 1
    fi

    # Compare SHA-256 digests of the public keys; never log private-key material.
    local cert_hash key_hash cert_public key_public
    cert_public=$(openssl x509 -in "$cert_file" -pubkey -noout 2>/dev/null) || return 1
    key_public=$(tls_run_private_key_openssl "$key_file" -pubout) || return 1
    cert_hash=$(printf '%s' "$cert_public" | openssl dgst -sha256 | awk '{print $NF}') || return 1
    key_hash=$(printf '%s' "$key_public" | openssl dgst -sha256 | awk '{print $NF}') || return 1

    if [ "$cert_hash" = "$key_hash" ]; then
        ml_log_success "Certificate and private key match"
        return 0
    else
        ml_log_error "Certificate and private key do not match"
        return 1
    fi
}

# ================================================================
# CERTIFICATE INFORMATION EXTRACTION
# ================================================================

# Extract certificate information
tls_get_certificate_info() {
    local cert_file="$1"

    if ! tls_validate_certificate "$cert_file"; then
        return 1
    fi

    echo "Certificate Information:"
    echo "======================"

    # Basic certificate info
    openssl x509 -in "$cert_file" -text -noout | grep -A1 "Subject:"
    openssl x509 -in "$cert_file" -text -noout | grep -A1 "Issuer:"
    openssl x509 -in "$cert_file" -text -noout | grep -A2 "Validity"

    # Certificate fingerprints
    echo
    echo "Fingerprints:"
    echo "============"
    echo "SHA256: $(openssl x509 -in "$cert_file" -fingerprint -sha256 -noout | cut -d'=' -f2)"
    echo "SHA1:   $(openssl x509 -in "$cert_file" -fingerprint -sha1 -noout | cut -d'=' -f2)"

    # Subject Alternative Names
    echo
    echo "Subject Alternative Names:"
    echo "========================="
    local sans
    sans=$(openssl x509 -in "$cert_file" -text -noout | grep -A1 "Subject Alternative Name" | tail -1 | sed 's/^ *//')
    if [ -n "$sans" ]; then
        echo "$sans"
    else
        echo "None"
    fi

    # Key usage and extended key usage
    echo
    echo "Key Usage:"
    echo "=========="
    openssl x509 -in "$cert_file" -text -noout | grep -A1 "Key Usage:" | tail -1 | sed 's/^ *//' || echo "Not specified"

    echo
    echo "Extended Key Usage:"
    echo "=================="
    openssl x509 -in "$cert_file" -text -noout | grep -A1 "Extended Key Usage:" | tail -1 | sed 's/^ *//' || echo "Not specified"
}

# Return days remaining on stdout. Status: 0=healthy, 2=near expiry, 3=expired, 1=error.
tls_check_certificate_expiry() {
    local cert_file="$1" warn_days="${2:-30}" expiry_date expiry_epoch current_epoch remaining_seconds days_remaining
    [[ "$warn_days" =~ ^[0-9]+$ ]] || { ml_log_error "Warning threshold must be a non-negative integer"; return 1; }
    tls_validate_certificate "$cert_file" || return 1
    expiry_date=$(openssl x509 -in "$cert_file" -noout -enddate 2>/dev/null | cut -d'=' -f2) || return 1
    [ -n "$expiry_date" ] || { ml_log_error "Could not read certificate expiry date"; return 1; }

    if command -v gdate >/dev/null 2>&1; then
        expiry_epoch=$(gdate -u -d "$expiry_date" +%s 2>/dev/null) || return 1
    elif date -u -d "$expiry_date" +%s >/dev/null 2>&1; then
        expiry_epoch=$(date -u -d "$expiry_date" +%s 2>/dev/null) || return 1
    else
        expiry_epoch=$(date -u -j -f "%b %e %H:%M:%S %Y %Z" "$expiry_date" +%s 2>/dev/null) || {
            ml_log_error "Could not parse certificate expiry date on this platform"
            return 1
        }
    fi
    current_epoch=$(date -u +%s) || return 1
    remaining_seconds=$((expiry_epoch - current_epoch))
    days_remaining=$((remaining_seconds / 86400))
    printf '%s\n' "$days_remaining"

    if [ "$remaining_seconds" -lt 0 ]; then
        ml_log_error "Certificate has expired"
        return 3
    elif [ "$days_remaining" -le "$warn_days" ]; then
        ml_log_warning "Certificate expires in $days_remaining day(s)"
        return 2
    fi
    ml_log_success "Certificate expires in $days_remaining day(s)"
    return 0
}

# ================================================================
# CERTIFICATE CHAIN VERIFICATION
# ================================================================

# Verify a certificate chain using quoted argv; never evaluate a command string.
tls_verify_certificate_chain() {
    local cert_file="$1" ca_file="$2" intermediate_file="${3:-}"
    tls_validate_certificate "$cert_file" || return 1
    [ -r "$ca_file" ] || { ml_log_error "CA certificate file is not readable"; return 1; }
    local -a verify_args=(verify -CAfile "$ca_file")
    if [ -n "$intermediate_file" ]; then
        [ -r "$intermediate_file" ] || { ml_log_error "Intermediate certificate file is not readable"; return 1; }
        verify_args+=(-untrusted "$intermediate_file")
    fi
    verify_args+=("$cert_file")
    if openssl "${verify_args[@]}"; then
        ml_log_success "Certificate chain verification passed"
        return 0
    fi
    ml_log_error "Certificate chain verification failed"
    return 1
}

# Build certificate chain file
tls_build_chain_file() {
    local cert_file="$1" intermediate_file="$2" output_file="$3"
    if [ "${DRY_RUN:-false}" = "true" ]; then
        ml_log_info "[DRY-RUN] Would build a certificate chain at the requested output path; no file was written"
        return 0
    fi
    [ ! -e "$output_file" ] || { ml_log_error "Refusing to overwrite existing output file: $output_file"; return 1; }
    if ! tls_validate_certificate "$cert_file"; then
        return 1
    fi

    if [ ! -f "$intermediate_file" ]; then
        ml_log_error "Intermediate certificate file not found: $intermediate_file"
        return 1
    fi

    # Combine certificate with intermediate; never leave a partial chain on failure.
    if ! cat "$cert_file" "$intermediate_file" > "$output_file"; then
        rm -f "$output_file"
        ml_log_error "Failed to build certificate chain"
        return 1
    fi
    tls_write_output_manifest "${output_file}.rollback.json" "$output_file" || { rm -f "$output_file"; return 1; }
    ml_log_success "Certificate chain built: $output_file"
    return 0
}

# ================================================================
# KEYSTORE MANAGEMENT FUNCTIONS
# ================================================================

# Convert PEM to PKCS12/PFX format without exposing passwords in argv.
tls_create_pkcs12() {
    local cert_file="$1" key_file="$2" output_file="$3" password="${4:-}" friendly_name="${5:-marklogic-cert}"
    if [ "${DRY_RUN:-false}" = "true" ]; then
        ml_log_info "[DRY-RUN] Would create a PKCS12 file; no key or output file was written"
        return 0
    fi
    [ -n "$password" ] || { ml_log_error "PKCS12 export password is required"; return 1; }
    case "$password" in *$'\n'*|*$'\r'*) ml_log_error "PKCS12 password must not contain line breaks"; return 1 ;; esac
    [ ! -e "$output_file" ] || { ml_log_error "Refusing to overwrite existing PKCS12 file: $output_file"; return 1; }
    tls_verify_cert_key_match "$cert_file" "$key_file" || return 1

    local pass_file old_umask openssl_status
    pass_file=$(mktemp) || return 1
    chmod 600 "$pass_file" || { rm -f "$pass_file"; return 1; }
    printf '%s' "$password" > "$pass_file" || { rm -f "$pass_file"; return 1; }
    old_umask=$(umask)
    umask 077
    if openssl pkcs12 -export -out "$output_file" -inkey "$key_file" -in "$cert_file" \
        -name "$friendly_name" -passout "file:$pass_file"; then
        openssl_status=0
    else
        openssl_status=$?
    fi
    umask "$old_umask"
    rm -f "$pass_file"
    if [ "$openssl_status" -ne 0 ]; then
        rm -f "$output_file"
        ml_log_error "Failed to create PKCS12 keystore"
        return 1
    fi
    chmod 600 "$output_file" || { rm -f "$output_file"; return 1; }
    tls_write_output_manifest "${output_file}.rollback.json" "$output_file" || { rm -f "$output_file"; return 1; }
    ml_log_success "PKCS12 keystore created: $output_file"
}

# Extract PKCS12 contents to new, owner-only files without exposing passwords in argv.
tls_extract_from_pkcs12() {
    local p12_file="$1" password="${2:-}" cert_output="$3" key_output="$4"
    if [ "${DRY_RUN:-false}" = "true" ]; then
        ml_log_info "[DRY-RUN] Would extract PKCS12 contents; no output files were written"
        return 0
    fi
    [ -r "$p12_file" ] || { ml_log_error "PKCS12 file is not readable"; return 1; }
    [ ! -e "$cert_output" ] && [ ! -e "$key_output" ] || { ml_log_error "Refusing to overwrite existing certificate/key output"; return 1; }
    local pass_file="" pass_option="pass:" old_umask openssl_status
    if [ -n "$password" ]; then
        case "$password" in *$'\n'*|*$'\r'*) ml_log_error "PKCS12 password must not contain line breaks"; return 1 ;; esac
        pass_file=$(mktemp) || return 1
        chmod 600 "$pass_file" || { rm -f "$pass_file"; return 1; }
        printf '%s' "$password" > "$pass_file" || { rm -f "$pass_file"; return 1; }
        pass_option="file:$pass_file"
    fi
    old_umask=$(umask)
    umask 077
    if openssl pkcs12 -in "$p12_file" -clcerts -nokeys -out "$cert_output" -passin "$pass_option"; then
        if openssl pkcs12 -in "$p12_file" -nocerts -nodes -out "$key_output" -passin "$pass_option"; then
            openssl_status=0
        else
            openssl_status=$?
        fi
    else
        openssl_status=$?
    fi
    umask "$old_umask"
    [ -z "$pass_file" ] || rm -f "$pass_file"
    if [ "$openssl_status" -ne 0 ]; then
        rm -f "$cert_output" "$key_output"
        ml_log_error "Failed to extract PKCS12 contents"
        return 1
    fi
    chmod 600 "$cert_output" "$key_output" || { rm -f "$cert_output" "$key_output"; return 1; }
    tls_write_output_manifest "${cert_output}.rollback.json" "$cert_output" "$key_output" || { rm -f "$cert_output" "$key_output"; return 1; }
    ml_log_success "Certificate and private key extracted to protected files"
}

# ================================================================
# CSR (Certificate Signing Request) FUNCTIONS
# ================================================================

# Validate CSR format
tls_validate_csr() {
    local csr_file="$1"

    if [ ! -f "$csr_file" ]; then
        ml_log_error "CSR file not found: $csr_file"
        return 1
    fi

    if ! openssl req -in "$csr_file" -noout 2>/dev/null; then
        ml_log_error "Invalid CSR format: $csr_file"
        return 1
    fi

    ml_log_success "CSR format is valid: $csr_file"
    return 0
}

# Get CSR information
tls_get_csr_info() {
    local csr_file="$1"

    if ! tls_validate_csr "$csr_file"; then
        return 1
    fi

    echo "Certificate Signing Request Information:"
    echo "======================================"

    # Subject information
    echo "Subject:"
    openssl req -in "$csr_file" -noout -subject | sed 's/subject=//'

    # Public key info
    echo
    echo "Public Key:"
    openssl req -in "$csr_file" -noout -pubkey | openssl rsa -pubin -text -noout 2>/dev/null | grep "Public-Key" || \
    openssl req -in "$csr_file" -noout -pubkey | openssl pkey -pubin -text -noout 2>/dev/null | grep -E "(Public-Key|NIST CURVE)"

    # Subject Alternative Names (if present)
    echo
    echo "Subject Alternative Names:"
    local sans
    sans=$(openssl req -in "$csr_file" -text -noout | grep -A1 "Requested Extensions" -A10 | grep -A1 "Subject Alternative Name" | tail -1 | sed 's/^ *//')
    if [ -n "$sans" ]; then
        echo "$sans"
    else
        echo "None"
    fi
}

# ================================================================
# SSL/TLS CONNECTION TESTING FUNCTIONS
# ================================================================

# Test SSL protocols and cipher suites
tls_test_ssl_protocols() {
    local host="$1"
    local port="$2"
    if [ "${DRY_RUN:-false}" = "true" ]; then
        ml_log_info "[DRY-RUN] Would probe TLS protocols and ciphers; no handshake was attempted"
        return 0
    fi
    if ! command -v openssl >/dev/null 2>&1; then
        ml_log_error "OpenSSL not found"
        return 1
    fi
    local timeout_command
    if command -v timeout >/dev/null 2>&1; then
        timeout_command=timeout
    elif command -v gtimeout >/dev/null 2>&1; then
        timeout_command=gtimeout
    else
        ml_log_warning "TLS protocol/cipher probes skipped: install timeout or gtimeout; the separate verified handshake can still succeed"
        return 3
    fi

    echo "SSL/TLS Protocol Test Results:"
    echo "============================"

    # Test different TLS versions
    local protocols=("ssl3" "tls1" "tls1_1" "tls1_2" "tls1_3")
    local protocol_names=("SSLv3" "TLS 1.0" "TLS 1.1" "TLS 1.2" "TLS 1.3")

    for i in "${!protocols[@]}"; do
        local protocol="${protocols[$i]}"
        local protocol_name="${protocol_names[$i]}"

        if echo | "$timeout_command" 10 openssl s_client -connect "$host:$port" -servername "$host" -verify_return_error -verify_hostname "$host" -"$protocol" -quiet 2>/dev/null >/dev/null; then
            ml_log_success "$protocol_name: Supported"
        else
            ml_log_info "$protocol_name: Not supported"
        fi
    done

    echo
    echo "Cipher Suite Test:"
    echo "=================="

    # Test common cipher suites
    local ciphers=(
        "ECDHE-RSA-AES256-GCM-SHA384"
        "ECDHE-RSA-AES128-GCM-SHA256"
        "ECDHE-RSA-AES256-SHA384"
        "ECDHE-RSA-AES128-SHA256"
        "DHE-RSA-AES256-GCM-SHA384"
        "DHE-RSA-AES128-GCM-SHA256"
        "AES256-GCM-SHA384"
        "AES128-GCM-SHA256"
    )

    for cipher in "${ciphers[@]}"; do
        if echo | "$timeout_command" 5 openssl s_client -connect "$host:$port" -servername "$host" -verify_return_error -verify_hostname "$host" -cipher "$cipher" -quiet 2>/dev/null >/dev/null; then
            ml_log_success "$cipher: Supported"
        else
            ml_log_info "$cipher: Not supported"
        fi
    done
}

# Get detailed SSL connection info
tls_get_ssl_connection_info() {
    local host="$1"
    local port="$2"
    if [ "${DRY_RUN:-false}" = "true" ]; then
        ml_log_info "[DRY-RUN] Would inspect a verified TLS connection; no handshake or temp file was created"
        return 0
    fi

    if ! command -v openssl >/dev/null 2>&1; then
        ml_log_error "OpenSSL not found"
        return 1
    fi

    # Store public handshake output in a protected temporary file.
    local temp_file
    temp_file=$(mktemp) || return 1
    chmod 600 "$temp_file" || { rm -f "$temp_file"; return 1; }

    if echo | openssl s_client -connect "$host:$port" -servername "$host" -verify_return_error -verify_hostname "$host" 2>/dev/null 1>"$temp_file"; then
        echo "SSL Connection Details:"
        echo "======================"

        # Extract connection information
        echo "Protocol: $(grep "Protocol" "$temp_file" | head -1 | cut -d':' -f2 | xargs)"
        echo "Cipher: $(grep "Cipher" "$temp_file" | head -1 | cut -d':' -f2 | xargs)"

        # Certificate chain
        echo
        echo "Certificate Chain:"
        echo "=================="
        local chain_depth
        chain_depth=$(grep -c "BEGIN CERTIFICATE" "$temp_file")
        echo "Chain depth: $chain_depth certificate(s)"

        # Extract and show each certificate in the chain
        local cert_num=0
        while read -r line; do
            if [[ "$line" == "-----BEGIN CERTIFICATE-----" ]]; then
                cert_num=$((cert_num + 1))
                echo
                echo "Certificate $cert_num:"
                echo "=============="

                # Extract this certificate
                local cert_start_line cert_end_line cert_content
                cert_start_line=$(grep -n "BEGIN CERTIFICATE" "$temp_file" | sed -n "${cert_num}p" | cut -d':' -f1)
                cert_end_line=$(tail -n +$cert_start_line "$temp_file" | grep -n "END CERTIFICATE" | head -1 | cut -d':' -f1)
                cert_end_line=$((cert_start_line + cert_end_line - 1))

                cert_content=$(sed -n "${cert_start_line},${cert_end_line}p" "$temp_file")

                # Get certificate subject and issuer
                echo "$cert_content" | openssl x509 -noout -subject -issuer 2>/dev/null | sed 's/^/  /'
            fi
        done < "$temp_file"

        rm -f "$temp_file"
        return 0
    else
        rm -f "$temp_file"
        ml_log_error "Failed to establish verified SSL connection"
        return 1
    fi
}

# Record and roll back only unchanged files created beside a protected manifest.
tls_file_sha256() {
    local digest
    digest=$(openssl dgst -sha256 "$1" 2>/dev/null) || return 1
    printf '%s\n' "${digest##* }"
}

tls_write_output_manifest() {
    if [ "${DRY_RUN:-false}" = "true" ]; then
        ml_log_info "[DRY-RUN] Would record a protected rollback manifest; no file was written"
        return 3
    fi
    local manifest="$1" manifest_dir file file_dir abs_path hash files='[]' json temp
    shift
    [ "$#" -gt 0 ] || { ml_log_error "No generated files were supplied for the manifest"; return 1; }
    [ ! -e "$manifest" ] && [ ! -L "$manifest" ] || { ml_log_error "Manifest already exists: $manifest"; return 1; }
    manifest_dir=$(cd "$(dirname "$manifest")" && pwd -P) || return 1
    for file in "$@"; do
        [ -f "$file" ] && [ ! -L "$file" ] || { ml_log_error "Generated output is not a regular file: $file"; return 1; }
        [[ "$file" != *[[:cntrl:]]* ]] || { ml_log_error "Generated file path contains a control character"; return 1; }
        file_dir=$(cd "$(dirname "$file")" && pwd -P) || return 1
        [ "$file_dir" = "$manifest_dir" ] || { ml_log_error "Manifest and generated files must share one directory"; return 1; }
        abs_path="$file_dir/$(basename "$file")"
        hash=$(tls_file_sha256 "$file") || return 1
        files=$(jq -cn --argjson files "$files" --arg path "$abs_path" --arg sha "$hash" '$files + [{path:$path,sha256:$sha}]') || return 1
    done
    json=$(jq -cn --argjson files "$files" '{version:1,files:$files}') || return 1
    temp=$(mktemp "${manifest}.XXXXXX") || return 1
    chmod 600 "$temp" || { rm -f "$temp"; return 1; }
    printf '%s\n' "$json" > "$temp" || { rm -f "$temp"; return 1; }
    if ! ln "$temp" "$manifest"; then
        rm -f "$temp"
        ml_log_error "Could not create exclusive rollback manifest"
        return 1
    fi
    rm -f "$temp"
    ml_log_warning "Protected rollback manifest created: $manifest"
}

tls_rollback_output_manifest() {
    local manifest="$1" manifest_dir file expected actual files_json count=0
    [ "${DRY_RUN:-false}" != "true" ] || { ml_log_info "[DRY-RUN] Would verify and remove unchanged generated files from the manifest"; return 0; }
    [ -f "$manifest" ] && [ ! -L "$manifest" ] && [ -O "$manifest" ] || { ml_log_error "Manifest must be a regular file owned by the current user"; return 1; }
    if [[ -n "$(find "$manifest" \( -perm -004 -o -perm -040 -o -perm -001 -o -perm -010 -o -perm -002 -o -perm -020 \) -print -quit 2>/dev/null)" ]]; then
        ml_log_error "Rollback manifest must not be accessible to group or other users"
        return 1
    fi
    jq -e '(.version == 1) and (.files|type == "array") and (.files|length > 0) and all(.files[]; (.path|type == "string" and length > 1) and (.sha256|test("^[0-9a-f]{64}$"))) and (([.files[].path]|unique|length) == (.files|length))' "$manifest" >/dev/null 2>&1 || { ml_log_error "Invalid rollback manifest"; return 1; }
    manifest_dir=$(cd "$(dirname "$manifest")" && pwd -P) || return 1
    files_json=$(jq -c '.files' "$manifest") || return 1
    while IFS=$'\t' read -r file expected; do
        local target_dir
        target_dir=$(cd "$(dirname "$file")" && pwd -P) || return 1
        [ "$target_dir" = "$manifest_dir" ] || { ml_log_error "Rollback target is outside the manifest directory"; return 1; }
        [ -f "$file" ] && [ ! -L "$file" ] || { ml_log_error "Rollback target is missing or not a regular file: $file"; return 1; }
        actual=$(tls_file_sha256 "$file") || return 1
        [ "$actual" = "$expected" ] || { ml_log_error "Rollback target has changed; refusing removal: $file"; return 1; }
        count=$((count + 1))
    done < <(jq -r '.[] | [.path,.sha256] | @tsv' <<< "$files_json")
    ml_confirm "Remove $count unchanged generated file(s) and the manifest?" n || return 1
    while IFS=$'\t' read -r file expected; do rm -f "$file"; done < <(jq -r '.[] | [.path,.sha256] | @tsv' <<< "$files_json")
    rm -f "$manifest"
    ml_log_success "Unchanged generated files removed"
}

# ================================================================
# UTILITY EXPORT FUNCTIONS
# ================================================================

# Make functions available to other scripts
export -f tls_validate_certificate
export -f tls_validate_private_key
export -f tls_verify_cert_key_match
export -f tls_get_certificate_info
export -f tls_check_certificate_expiry
export -f tls_verify_certificate_chain
export -f tls_build_chain_file
export -f tls_create_pkcs12
export -f tls_extract_from_pkcs12
export -f tls_validate_csr
export -f tls_get_csr_info
export -f tls_test_ssl_protocols
export -f tls_get_ssl_connection_info