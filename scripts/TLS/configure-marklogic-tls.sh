#!/bin/bash

# ================================================================
# MarkLogic TLS Certificate Management Script
# ================================================================
#
# This script helps manage TLS/SSL certificates for MarkLogic Server
# including certificate template creation, CSR generation, certificate
# import, and SSL configuration for app servers.
#
# Features:
# - Create certificate templates via REST API
# - Generate Certificate Signing Requests (CSR)
# - Import signed certificates
# - Configure app servers for SSL/TLS
# - Support for external certificates (SAN, wildcard)
# - Certificate validation and testing
#
# Author: Martin Warnes
# Version: 1.0.6
# Date: September 2026
#
# Usage:
#   ./configure-marklogic-tls.sh [COMMAND] [OPTIONS]
#
# Commands:
#   create-template     Create certificate template
#   generate-csr        Generate Certificate Signing Request
#   import-cert         Import signed certificate
#   configure-ssl       Configure app server SSL
#   test-ssl            Test SSL configuration
#   list-templates      List existing certificate templates
#   show-template       Show template details
#
# Examples:
#   # Create certificate template
#   ./configure-marklogic-tls.sh create-template --name web-server-ssl --common-name marklogic.example.com
#
#   # Generate CSR from template
#   ./configure-marklogic-tls.sh generate-csr --template web-server-ssl > web-server.csr
#
#   # Import signed certificate
#   ./configure-marklogic-tls.sh import-cert --template web-server-ssl --cert-file signed-cert.pem --key-file signed-key.pem
#
#   # Configure app server SSL
#   ./configure-marklogic-tls.sh configure-ssl --appserver App-Services --template web-server-ssl
#
#   # Test SSL configuration
#   ./configure-marklogic-tls.sh test-ssl --host marklogic.example.com --port 8443
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

# Default values
COMMAND=""
TEMPLATE_NAME=""
COMMON_NAME=""
SUBJECT_ALT_NAMES=""
DNS_NAME=""
IP_ADDR=""
COUNTRY="US"
STATE=""
LOCALITY=""
ORGANIZATION=""
ORGANIZATIONAL_UNIT=""
EMAIL=""
KEY_SIZE="2048"
CERT_FILE=""
KEY_FILE=""
APPSERVER_NAME=""
SSL_HOSTNAME=""
MIN_TLS_VERSION="1.2"
SSL_PORT=""
TEST_HOST=""
TEST_PORT="8443"
MARKLOGIC_HOST="${MARKLOGIC_HOST:-localhost}"
MARKLOGIC_PORT="${MARKLOGIC_PORT:-8002}"
MARKLOGIC_USER="${MARKLOGIC_USER:-admin}"
MARKLOGIC_PASS="${MARKLOGIC_PASS:-}"
ALLOW_HTTP="${MARKLOGIC_ALLOW_HTTP:-false}"
FORCE="false"
DRY_RUN="false"

# ================================================================
# TLS UTILITY FUNCTIONS
# ================================================================

# Build safely encoded certificate-template JSON; never log the payload.
tls_create_template_json() {
    jq -n --arg name "$TEMPLATE_NAME" --arg key_size "$KEY_SIZE" --arg country "$COUNTRY" \
        --arg state "$STATE" --arg locality "$LOCALITY" --arg org "$ORGANIZATION" \
        --arg unit "$ORGANIZATIONAL_UNIT" --arg common_name "$COMMON_NAME" --arg email "$EMAIL" \
        '{"template-name":$name,"template-description":"TLS certificate template created by script","key-type":"rsa","key-options":{"key-length":$key_size},"req":{"version":"0","subject":{"countryName":$country,"stateOrProvinceName":$state,"localityName":$locality,"organizationName":$org,"organizationalUnitName":$unit,"commonName":$common_name,"emailAddress":$email}}}'
}

tls_validate_endpoint_url() {
    local url="$1" authority
    case "$url" in http://*|https://*) ;; *) ml_log_error "URL must use HTTP or HTTPS"; return 1 ;; esac
    authority="${url#*://}"
    authority="${authority%%/*}"
    if [ -z "$authority" ] || [[ "$authority" == *"@"* || "$url" == *"?"* || "$url" == *"#"* || "$url" == *[[:space:]]* ]]; then
        ml_log_error "URL contains unsupported credentials, query, fragment, or whitespace"
        return 1
    fi
}

tls_api_path_segment() {
    local value="$1"
    [[ -n "$value" && "$value" != "." && "$value" != ".." && "$value" != *"/"* && "$value" != *"?"* && "$value" != *"#"* && "$value" != *$'\n'* && "$value" != *$'\r'* ]] || return 1
    jq -nr --arg value "$value" '$value|@uri'
}

tls_validate_csr_sans() {
    if [ -n "$SUBJECT_ALT_NAMES" ]; then
        [ -z "$DNS_NAME" ] || { ml_log_error "Use either --subject-alt-names or --dns-name, not both"; return 1; }
        [[ "$SUBJECT_ALT_NAMES" != *,* ]] || { ml_log_error "MarkLogic supports one DNS name and one IP address per CSR; use --dns-name and --ip-addr"; return 1; }
        DNS_NAME="$SUBJECT_ALT_NAMES"
    fi
    if [ -n "$DNS_NAME" ]; then
        [[ "$DNS_NAME" =~ ^[A-Za-z0-9.*-]+$ && "$DNS_NAME" != .* && "$DNS_NAME" != *. && "$DNS_NAME" != *..* && "$DNS_NAME" != *.-* && "$DNS_NAME" != *-. && "$DNS_NAME" != -* && "$DNS_NAME" != *- ]] || { ml_log_error "Invalid DNS name for CSR"; return 1; }
        if [[ "$DNS_NAME" == *"*"* ]]; then
            [[ "${DNS_NAME:0:2}" == "*." && -n "${DNS_NAME:2}" && "${DNS_NAME:2}" != *"*"* ]] || { ml_log_error "Only a leading *. DNS wildcard is allowed"; return 1; }
        fi
    fi
    [[ -z "$IP_ADDR" || "$IP_ADDR" =~ ^[0-9A-Fa-f:.]+$ ]] || { ml_log_error "Invalid IP address for CSR"; return 1; }
}

tls_save_protected_snapshot() {
    local label="$1" json="$2" file
    printf '%s' "$json" | jq empty >/dev/null 2>&1 || { ml_log_error "Could not validate $label snapshot"; return 1; }
    file=$(mktemp) || return 1
    chmod 600 "$file" || { rm -f "$file"; return 1; }
    printf '%s\n' "$json" > "$file" || { rm -f "$file"; return 1; }
    ml_log_warning "Protected $label snapshot saved to $file; server-side redaction may require manual restoration"
}

tls_backup_resource() {
    local endpoint="$1" label="$2" response status_code body
    case "$endpoint" in *\?*) endpoint="${endpoint}&format=json" ;; *) endpoint="${endpoint}?format=json" ;; esac
    if ! response=$(ml_api_request GET "$endpoint" "$MARKLOGIC_USER" "$MARKLOGIC_PASS"); then
        ml_log_error "Could not read $label; refusing mutation"
        return 1
    fi
    status_code=$(ml_extract_status_code "$response")
    [ "$status_code" = "200" ] || { ml_log_error "Could not snapshot $label (HTTP $status_code); refusing mutation"; return 1; }
    body=$(ml_extract_response_body "$response")
    tls_save_protected_snapshot "$label" "$body"
}

# Create certificate template
tls_create_template() {
    ml_log_step "Creating certificate template: $TEMPLATE_NAME"

    # Validate required fields
    if [ -z "$TEMPLATE_NAME" ]; then
        ml_log_error "Template name is required"
        return 1
    fi

    if [ -z "$COMMON_NAME" ]; then
        ml_log_error "Common name is required"
        return 1
    fi

    if [ -z "$ORGANIZATION" ]; then
        ml_log_error "Organization is required"
        return 1
    fi

    # Check if template already exists
    local template_status
    if ml_check_template_exists "$TEMPLATE_NAME" "$MARKLOGIC_USER" "$MARKLOGIC_PASS"; then
        template_status=0
    else
        template_status=$?
    fi

    case $template_status in
        0)  # Exists
            if [ "$FORCE" != "true" ]; then
                ml_log_error "Template '$TEMPLATE_NAME' already exists. Use --force to overwrite."
                return 1
            else
                ml_log_warning "Overwriting existing template '$TEMPLATE_NAME'"
            fi
            ;;
        1)  # Does not exist - continue to create
            ;;
        2)  # Error
            ml_log_error "Failed to check template existence (error)"
            return 1
            ;;
        3)  # Unknown in dry-run
            ml_log_info "[DRY-RUN] Template existence unknown - would check before creating"
            return 0
            ;;
        *)
            ml_log_error "Unexpected status from template check: $template_status"
            return 1
            ;;
    esac

    # Create template JSON
    local template_json
    template_json=$(tls_create_template_json) || return 1

    # Apply template to MarkLogic
    local response status_code
    if ml_api_call_with_dryrun response "POST" "/manage/v2/certificate-templates" \
        "$MARKLOGIC_USER" "$MARKLOGIC_PASS" "$template_json"; then
        status_code=$(ml_extract_status_code "$response")
    else
        case $? in
            3) ml_log_info "[DRY-RUN] Would create certificate template '$TEMPLATE_NAME'"; return 0 ;;
            *) ml_log_error "Failed to create certificate template"; return 1 ;;
        esac
    fi

    case "$status_code" in
        201)
            ml_log_success "Certificate template '$TEMPLATE_NAME' created successfully"
            return 0
            ;;
        409)
            if [ "$FORCE" = "true" ]; then
                ml_log_info "Updating existing template..."
                tls_update_template "$template_json"
                return $?
            else
                ml_log_error "Template already exists (HTTP $status_code)"
                return 1
            fi
            ;;
        400)
            ml_log_error "Bad request - check template parameters (HTTP $status_code; response suppressed)"
            return 1
            ;;
        *)
            ml_log_error "Failed to create template (HTTP $status_code)"
            return 1
            ;;
    esac
}

# Update existing certificate template
tls_update_template() {
    local template_json="$1" template_path response status_code
    template_path=$(tls_api_path_segment "$TEMPLATE_NAME") || { ml_log_error "Invalid template name"; return 1; }
    if [ "$DRY_RUN" = "true" ]; then
        ml_log_info "[DRY-RUN] Would update the exact certificate template; remote state is unknown"
        return 0
    fi
    if ! ml_confirm "Replace certificate template '$TEMPLATE_NAME'? A protected snapshot will be saved first." n; then
        ml_log_warning "Template update cancelled"
        return 1
    fi
    tls_backup_resource "/manage/v2/certificate-templates/$template_path" "certificate template '$TEMPLATE_NAME'" || return 1
    if ml_api_call_with_dryrun response "PUT" "/manage/v2/certificate-templates/$template_path" \
        "$MARKLOGIC_USER" "$MARKLOGIC_PASS" "$template_json"; then
        status_code=$(ml_extract_status_code "$response")
    else
        case $? in
            3) ml_log_info "[DRY-RUN] Would update certificate template '$TEMPLATE_NAME'"; return 0 ;;
            *) ml_log_error "Failed to update certificate template"; return 1 ;;
        esac
    fi

    case "$status_code" in
        204|200)
            ml_log_success "Certificate template '$TEMPLATE_NAME' updated successfully"
            return 0
            ;;
        *)
            ml_log_error "Failed to update template (HTTP $status_code)"
            return 1
            ;;
    esac
}

# Check if certificate template exists
# Returns: 0=exists, 1=not found, 2=error, 3=unknown/dry-run
ml_check_template_exists() {
    local template_name="$1" user="$2" pass="$3" template_path
    template_path=$(tls_api_path_segment "$template_name") || return 2
    local response status_code
    if ml_api_call_with_dryrun response "GET" "/manage/v2/certificate-templates/$template_path" \
        "$user" "$pass"; then
        status_code=$(ml_extract_status_code "$response")
    else
        case $? in
            3) return 3 ;; # Unknown in dry-run
            *) return 2 ;; # Error
        esac
    fi

    case "$status_code" in
        200)
            return 0  # Exists
            ;;
        404)
            return 1  # Does not exist
            ;;
        *)
            ml_log_error "Error checking template existence (HTTP $status_code)"
            return 2  # Error
            ;;
    esac
}

# Generate CSR from template
tls_generate_csr() {
    ml_log_step "Generating CSR from template: $TEMPLATE_NAME"

    local template_path template_status template_response template_status_code template_body common_name csr_json
    template_path=$(tls_api_path_segment "$TEMPLATE_NAME") || { ml_log_error "Invalid template name"; return 1; }
    if ml_check_template_exists "$TEMPLATE_NAME" "$MARKLOGIC_USER" "$MARKLOGIC_PASS"; then
        template_status=0
    else
        template_status=$?
    fi
    case $template_status in
        0)  # Exists - proceed
            ;;
        1)  # Does not exist
            ml_log_error "Template '$TEMPLATE_NAME' does not exist"
            return 1
            ;;
        3)  # Unknown in dry-run
            ml_log_info "[DRY-RUN] Cannot verify template existence - would generate CSR for '$TEMPLATE_NAME'"
            return 0
            ;;
        *)  # Error
            ml_log_error "Error checking template existence"
            return 1
            ;;
    esac

    common_name="$COMMON_NAME"
    if [ -z "$common_name" ]; then
        if ! template_response=$(ml_api_request GET "/manage/v2/certificate-templates/$template_path?format=json" "$MARKLOGIC_USER" "$MARKLOGIC_PASS"); then
            ml_log_error "Could not read the template common name"
            return 1
        fi
        template_status_code=$(ml_extract_status_code "$template_response")
        [ "$template_status_code" = "200" ] || { ml_log_error "Could not read template common name (HTTP $template_status_code)"; return 1; }
        template_body=$(ml_extract_response_body "$template_response")
        common_name=$(printf '%s' "$template_body" | jq -r '."certificate-template-default".req.subject.commonName // empty') || return 1
    fi
    [ -n "$common_name" ] || { ml_log_error "Template has no common name; pass --common-name or recreate it with one"; return 1; }
    csr_json=$(jq -n --arg common_name "$common_name" --arg dns_name "$DNS_NAME" --arg ip_addr "$IP_ADDR" \
        '{"operation":"generate-certificate-request","common-name":$common_name} + (if $dns_name == "" then {} else {"dns-name":$dns_name} end) + (if $ip_addr == "" then {} else {"ip-addr":$ip_addr} end)') || return 1

    if ! ml_confirm "Generate a new CSR for '$TEMPLATE_NAME'? This may replace server-side key material." n; then
        ml_log_warning "CSR generation cancelled"
        return 1
    fi
    tls_backup_resource "/manage/v2/certificate-templates/$template_path" "certificate template '$TEMPLATE_NAME'" || return 1

    # Generate CSR via MarkLogic API
    local response status_code
    if ml_api_call_with_dryrun response "POST" "/manage/v2/certificate-templates/$template_path?format=json" "$MARKLOGIC_USER" "$MARKLOGIC_PASS" "$csr_json"; then
        status_code=$(ml_extract_status_code "$response")
    else
        case $? in
            3) ml_log_info "[DRY-RUN] Would generate CSR for template '$TEMPLATE_NAME'"; return 0 ;;
            *) ml_log_error "Failed to generate CSR"; return 1 ;;
        esac
    fi

    case "$status_code" in
        200|201)
            local response_body
            response_body=$(ml_extract_response_body "$response")

            # Emit only to stdout; callers may redirect after reviewing it.
            printf '%s\n' "$response_body"
            return 0
            ;;
        *)
            ml_log_error "Failed to generate CSR (HTTP $status_code)"
            return 1
            ;;
    esac
}

# Import certificate/key pairs or a certificate matching a pending template CSR.
tls_import_certificate() {
    ml_log_step "Importing certificate to template: $TEMPLATE_NAME"
    local template_path template_status response status_code import_json import_data import_endpoint content_type
    template_path=$(tls_api_path_segment "$TEMPLATE_NAME") || { ml_log_error "Invalid template name"; return 1; }
    [ -r "$CERT_FILE" ] || { ml_log_error "Certificate file is not readable"; return 1; }
    if [ -n "$KEY_FILE" ]; then [ -r "$KEY_FILE" ] || { ml_log_error "Private-key file is not readable"; return 1; }; fi
    if [ "$DRY_RUN" = "true" ]; then
        if [ -n "$KEY_FILE" ]; then
            ml_log_info "[DRY-RUN] Would import the supplied certificate/key pair into template '$TEMPLATE_NAME'"
        else
            ml_log_info "[DRY-RUN] Would POST the certificate to /manage/v2/certificates for matching against a pending CSR"
        fi
        return 0
    fi

    if ml_check_template_exists "$TEMPLATE_NAME" "$MARKLOGIC_USER" "$MARKLOGIC_PASS"; then template_status=0; else template_status=$?; fi
    case "$template_status" in
        0) ;;
        1) ml_log_error "Template '$TEMPLATE_NAME' does not exist"; return 1 ;;
        3) ml_log_info "[DRY-RUN] Template state is unknown; no import performed"; return 0 ;;
        *) ml_log_error "Could not verify template existence"; return 1 ;;
    esac
    tls_validate_certificate "$CERT_FILE" || return 1
    if [ -n "$KEY_FILE" ]; then tls_verify_cert_key_match "$CERT_FILE" "$KEY_FILE" || return 1; fi
    if [ -n "$KEY_FILE" ]; then
        ml_confirm "Import certificate and matching key into template '$TEMPLATE_NAME'? A protected snapshot will be saved first." n || {
            ml_log_warning "Certificate import cancelled"
            return 1
        }
    else
        ml_confirm "Import this certificate by matching it to a pending CSR? A protected template snapshot will be saved first." n || {
            ml_log_warning "Certificate import cancelled"
            return 1
        }
    fi
    tls_backup_resource "/manage/v2/certificate-templates/$template_path" "certificate template '$TEMPLATE_NAME'" || return 1

    if [ -n "$KEY_FILE" ]; then
        import_json=$(jq -n --rawfile cert "$CERT_FILE" --rawfile pkey "$KEY_FILE" \
            '{"operation":"insert-host-certificates","certificates":[{"certificate":{"cert":$cert,"pkey":$pkey}}]}') || {
            ml_log_error "Could not build protected certificate import request"
            return 1
        }
        import_endpoint="/manage/v2/certificate-templates/$template_path"
        import_data="$import_json"
        content_type="application/json"
    else
        import_data=$(<"$CERT_FILE") || { ml_log_error "Could not read certificate file"; return 1; }
        import_data+=$'\n'
        import_endpoint="/manage/v2/certificates?trusted=false&format=html"
        content_type="text/html"
    fi

    if ! ml_api_call_with_dryrun response "POST" "$import_endpoint" \
        "$MARKLOGIC_USER" "$MARKLOGIC_PASS" "$import_data" "$content_type"; then
        ml_log_error "Certificate import request failed"
        return 1
    fi
    status_code=$(ml_extract_status_code "$response")
    case "$status_code" in
        200|201|204)
            if [ -n "$KEY_FILE" ]; then
                ml_log_success "Certificate imported to template '$TEMPLATE_NAME'"
            else
                ml_log_success "Certificate matched to a pending CSR and imported (expected template '$TEMPLATE_NAME')"
            fi
            return 0
            ;;
        *)
            if [ "$status_code" = "400" ] && [ -z "$KEY_FILE" ]; then
                ml_log_error "Certificate was not accepted as a match for a pending CSR (HTTP 400; response suppressed)"
            else
                ml_log_error "Certificate import failed (HTTP $status_code; response suppressed)"
            fi
            return 1
            ;;
    esac
}

# Configure one app server after a protected snapshot and explicit confirmation.
tls_configure_appserver_ssl() {
    ml_log_step "Configuring SSL for app server: $APPSERVER_NAME"
    local template_path appserver_path group_id group_path template_status response status_code prior_config ssl_config ssl_min_version
    template_path=$(tls_api_path_segment "$TEMPLATE_NAME") || { ml_log_error "Invalid template name"; return 1; }
    appserver_path=$(tls_api_path_segment "$APPSERVER_NAME") || { ml_log_error "Invalid app-server name"; return 1; }
    group_id="${APPSERVER_GROUP:-Default}"
    group_path=$(tls_api_path_segment "$group_id") || { ml_log_error "Invalid app-server group"; return 1; }
    case "$MIN_TLS_VERSION" in 1.2|1.3) ;; *) ml_log_error "Minimum TLS version must be 1.2 or 1.3"; return 1 ;; esac
    if [ -n "$SSL_PORT" ]; then
        [[ "$SSL_PORT" =~ ^[0-9]{1,5}$ ]] && [ "$SSL_PORT" -ge 1 ] && [ "$SSL_PORT" -le 65535 ] || { ml_log_error "SSL port must be between 1 and 65535"; return 1; }
    fi
    if [ -n "$SSL_HOSTNAME" ]; then
        [[ "$SSL_HOSTNAME" =~ ^[A-Za-z0-9.*-]+$ ]] || { ml_log_error "Invalid SSL hostname"; return 1; }
    fi
    if [ "$DRY_RUN" = "true" ]; then
        ml_log_info "[DRY-RUN] Would bind certificate template '$TEMPLATE_NAME' to app server '$APPSERVER_NAME' with minimum TLS $MIN_TLS_VERSION; remote state is unknown"
        return 0
    fi

    if ml_check_template_exists "$TEMPLATE_NAME" "$MARKLOGIC_USER" "$MARKLOGIC_PASS"; then template_status=0; else template_status=$?; fi
    case "$template_status" in
        0) ;;
        1) ml_log_error "Certificate template '$TEMPLATE_NAME' does not exist"; return 1 ;;
        *) ml_log_error "Could not verify certificate-template state"; return 1 ;;
    esac
    if ! response=$(ml_api_request GET "/manage/v2/servers/$appserver_path/properties?group-id=$group_path&format=json" "$MARKLOGIC_USER" "$MARKLOGIC_PASS"); then
        ml_log_error "Could not read app-server configuration"
        return 1
    fi
    status_code=$(ml_extract_status_code "$response")
    [ "$status_code" = "200" ] || { ml_log_error "App server not found (HTTP $status_code)"; return 1; }
    prior_config=$(ml_extract_response_body "$response")
    if ! ml_confirm "Configure SSL on app server '$APPSERVER_NAME'? A protected snapshot will be saved first." n; then
        ml_log_warning "SSL configuration cancelled"
        return 1
    fi
    tls_save_protected_snapshot "app-server '$APPSERVER_NAME' properties" "$prior_config" || return 1

    ssl_min_version="TLSv$MIN_TLS_VERSION"
    if ! ssl_config=$(jq -n --arg template "$TEMPLATE_NAME" --arg min_tls "$ssl_min_version" --arg hostname "$SSL_HOSTNAME" --arg port "$SSL_PORT" \
        '{"ssl-certificate-template":$template,"ssl-min-allow-tls":$min_tls} + (if $hostname == "" then {} else {"ssl-hostname":$hostname} end) + (if $port == "" then {} else {"port":($port|tonumber)} end)'); then
        ml_log_error "Could not build SSL configuration JSON"
        return 1
    fi
    if ! ml_api_call_with_dryrun response "PUT" "/manage/v2/servers/$appserver_path/properties?group-id=$group_path" "$MARKLOGIC_USER" "$MARKLOGIC_PASS" "$ssl_config"; then
        ml_log_error "App-server SSL update request failed"
        return 1
    fi
    status_code=$(ml_extract_status_code "$response")
    case "$status_code" in
        204)
            ml_log_success "SSL configured for app server '$APPSERVER_NAME'"
            ml_log_warning "A MarkLogic Server restart may be required; protected snapshot is for manual recovery if needed"
            return 0
            ;;
        202)
            ml_log_success "SSL configuration accepted for app server '$APPSERVER_NAME'"
            ml_log_warning "Management API initiated a restart; wait for the server to return before testing TLS"
            return 0
            ;;
        *)
            ml_log_error "Failed to configure SSL (HTTP $status_code; response suppressed)"
            return 1
            ;;
    esac
    return 1
}

# Test SSL using verified, read-only handshakes; dry-run never connects.
tls_test_ssl() {
    local host="${1:-${ML_HOST:-localhost}}" port="${2:-8443}"
    if [ "${DRY_RUN:-false}" = "true" ]; then
        ml_log_info "[DRY-RUN] Would perform a verified TLS handshake and protocol probes; no network request was sent"
        return 0
    fi
    tls_get_ssl_connection_info "$host" "$port" || return 1
    if tls_test_ssl_protocols "$host" "$port"; then
        return 0
    else
        local status=$?
        [ "$status" -eq 3 ] && return 0
        return "$status"
    fi
}

# List certificate templates
tls_list_templates() {
    ml_log_step "Listing certificate templates"

    local response status_code
    if ml_api_call_with_dryrun response "GET" "/manage/v2/certificate-templates?format=json" "$MARKLOGIC_USER" "$MARKLOGIC_PASS"; then
        status_code=$(ml_extract_status_code "$response")
    else
        case $? in
            3) ml_log_info "[DRY-RUN] Would list certificate templates"; return 0 ;;
            *) ml_log_error "Failed to list certificate templates"; return 1 ;;
        esac
    fi

    case "$status_code" in
        200)
            local response_body
            response_body=$(ml_extract_response_body "$response")

            # Parse and display templates
            if command -v jq >/dev/null 2>&1; then
                local templates
                templates=$(echo "$response_body" | jq -r '.["certificate-templates-default-list"]["list-items"]["list-item"][]? | .nameref')

                if [ -n "$templates" ]; then
                    ml_log_success "Certificate templates found:"
                    echo "$templates" | while read -r template; do
                        echo "  - $template"
                    done
                else
                    ml_log_info "No certificate templates found"
                fi
            else
                ml_log_error "jq is required to display certificate-template names"
                return 1
            fi
            return 0
            ;;
        *)
            ml_log_error "Failed to list templates (HTTP $status_code)"
            return 1
            ;;
    esac
}

# Show template details
tls_show_template() {
    ml_log_step "Showing template details: $TEMPLATE_NAME"

    local template_path response status_code
    template_path=$(tls_api_path_segment "$TEMPLATE_NAME") || { ml_log_error "Invalid template name"; return 1; }
    if ml_api_call_with_dryrun response "GET" "/manage/v2/certificate-templates/$template_path" "$MARKLOGIC_USER" "$MARKLOGIC_PASS"; then
        status_code=$(ml_extract_status_code "$response")
    else
        case $? in
            3) ml_log_info "[DRY-RUN] Would show template '$TEMPLATE_NAME'"; return 0 ;;
            *) ml_log_error "Failed to get template details"; return 1 ;;
        esac
    fi

    case "$status_code" in
        200)
            ml_log_success "Template exists; certificate and key material are omitted from output"
            return 0
            ;;
        404)
            ml_log_error "Template '$TEMPLATE_NAME' not found"
            return 1
            ;;
        *)
            ml_log_error "Failed to get template details (HTTP $status_code)"
            return 1
            ;;
    esac
}

# ================================================================
# COMMAND LINE INTERFACE
# ================================================================

show_usage() {
    cat << EOF
Usage: $0 [COMMAND] [OPTIONS]

MarkLogic TLS Certificate Management Script

COMMANDS:
    create-template     Create certificate template
    generate-csr        Generate Certificate Signing Request
    import-cert         Import signed certificate
    configure-ssl       Configure app server SSL
    test-ssl            Test SSL configuration
    list-templates      List existing certificate templates
    show-template       Show template details

CREATE-TEMPLATE OPTIONS:
    --name NAME                   Certificate template name (required)
    --common-name CN              Certificate common name (required)
    --country CODE                Country code (default: US)
    --state STATE                 State or province name
    --locality CITY               City or locality name
    --organization ORG            Organization name (required)
    --organizational-unit OU      Organizational unit name
    --email EMAIL                 Email address
    --key-size SIZE               RSA key size (default: 2048)
    --force                       Request overwrite; prompts and saves a protected snapshot first

GENERATE-CSR OPTIONS:
    --template NAME               Template name (required)
    --common-name NAME            Override the template common name (optional)
    --dns-name DNS                Add one DNS Subject Alternative Name
    --ip-addr IP                  Add one IP Subject Alternative Name
    --subject-alt-names DNS        Legacy alias for one DNS name only
    --output-file FILE            Rejected; capture stdout after review

IMPORT-CERT OPTIONS:
    --template NAME               Template name (required)
    --cert-file FILE              Certificate file path (required)
    --key-file FILE               Matching key for external certificates; omit for a MarkLogic-generated CSR

CONFIGURE-SSL OPTIONS:
    --template NAME               Template name (required)
    --appserver NAME              App server name (required)
    --ssl-hostname HOSTNAME       SSL hostname override
    --ssl-port PORT               SSL port number
    --min-tls-version VERSION     Minimum TLS version (default: 1.2)

TEST-SSL OPTIONS:
    --host HOSTNAME               Hostname to test (default: localhost)
    --port PORT                   Port to test (default: 8443)

TRANSPORT OPTION:
    Remote hostnames default to HTTPS; loopback hosts may use HTTP.
    MARKLOGIC_ALLOW_HTTP=true    Allow unencrypted remote HTTP for isolated tests only

SHOW-TEMPLATE OPTIONS:
    --name NAME                   Template name (required)

$(ml_show_common_usage)

Recovery:
    Template and app-server updates save protected snapshots before mutation.
    MarkLogic may redact key material, so restore is manual where exports are incomplete.
    CSR is emitted to stdout; redirects are user-controlled and are not automatically rolled back.

EXAMPLES:
    # Create certificate template
    $0 create-template --name web-ssl --common-name marklogic.example.com \\
        --organization "Example Corp" --state California --locality "San Francisco"

    # Generate a CSR with DNS and IP Subject Alternative Names
    $0 generate-csr --template web-ssl --dns-name marklogic.example.com --ip-addr 192.0.2.10 > web-ssl.csr

    # Import the signed certificate for a MarkLogic-generated CSR
    $0 import-cert --template web-ssl --cert-file signed-cert.pem

    # Import external certificate with private key
    $0 import-cert --template external-ssl --cert-file external.crt --key-file external.key

    # Configure app server SSL
    $0 configure-ssl --template web-ssl --appserver App-Services --ssl-port 8443

    # Configure with SSL hostname (for external certificates)
    $0 configure-ssl --template external-ssl --appserver App-Services \\
        --ssl-hostname "*.example.com" --ssl-port 8443

    # Test SSL configuration
    $0 test-ssl --host marklogic.example.com --port 8443

    # List all templates
    $0 list-templates

    # Show template details
    $0 show-template --name web-ssl

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

    # Parse remaining arguments including common ones
    while [[ $# -gt 0 ]]; do
        case $1 in
            --name)
                TEMPLATE_NAME="$2"
                shift 2
                ;;
            --common-name)
                COMMON_NAME="$2"
                shift 2
                ;;
            --subject-alt-names)
                SUBJECT_ALT_NAMES="$2"
                shift 2
                ;;
            --dns-name)
                DNS_NAME="$2"
                shift 2
                ;;
            --ip-addr)
                IP_ADDR="$2"
                shift 2
                ;;
            --country)
                COUNTRY="$2"
                shift 2
                ;;
            --state)
                STATE="$2"
                shift 2
                ;;
            --locality)
                LOCALITY="$2"
                shift 2
                ;;
            --organization)
                ORGANIZATION="$2"
                shift 2
                ;;
            --organizational-unit)
                ORGANIZATIONAL_UNIT="$2"
                shift 2
                ;;
            --email)
                EMAIL="$2"
                shift 2
                ;;
            --key-size)
                KEY_SIZE="$2"
                shift 2
                ;;
            --template)
                TEMPLATE_NAME="$2"
                shift 2
                ;;
            --output-file)
                ml_log_error "--output-file is rejected; capture CSR stdout after review"
                exit 1
                ;;
            --cert-file)
                CERT_FILE="$2"
                shift 2
                ;;
            --key-file)
                KEY_FILE="$2"
                shift 2
                ;;
            --appserver)
                APPSERVER_NAME="$2"
                shift 2
                ;;
            --ssl-hostname)
                SSL_HOSTNAME="$2"
                shift 2
                ;;
            --ssl-port)
                SSL_PORT="$2"
                shift 2
                ;;
            --min-tls-version)
                MIN_TLS_VERSION="$2"
                shift 2
                ;;
            --host)
                TEST_HOST="$2"
                shift 2
                ;;
            --port)
                TEST_PORT="$2"
                shift 2
                ;;
            --force)
                FORCE="true"
                shift
                ;;
            --help)
                show_usage
                exit 0
                ;;
            *)
                # Try to parse common arguments
                ml_parse_common_args "$@"
                break
                ;;
        esac
    done
}

# Main execution function
main() {
    ml_show_header "MarkLogic TLS Certificate Management" "1.0.6" \
        "Configure TLS/SSL certificates for MarkLogic Server"

    ml_check_dependencies || exit 1
    case "$MARKLOGIC_HOST" in
        http://*|https://*) ;;
        localhost|localhost:*|127.0.0.1|127.0.0.1:*) MARKLOGIC_HOST="http://$MARKLOGIC_HOST" ;;
        *) MARKLOGIC_HOST="https://$MARKLOGIC_HOST" ;;
    esac
    tls_validate_endpoint_url "$MARKLOGIC_HOST" || exit 1
    local authority="${MARKLOGIC_HOST#*://}" host_for_transport
    case "$authority" in */) MARKLOGIC_HOST="${MARKLOGIC_HOST%/}"; authority="${MARKLOGIC_HOST#*://}" ;; */*) ml_log_error "MarkLogic host must not include a path"; exit 1 ;; esac
    if [[ "$MARKLOGIC_HOST" == http://* ]]; then
        host_for_transport="${authority%%:*}"
        case "$host_for_transport" in
            localhost|127.0.0.1) ;;
            *)
                [ "$ALLOW_HTTP" = "true" ] || { ml_log_error "Unencrypted remote HTTP is disabled; use HTTPS or set MARKLOGIC_ALLOW_HTTP=true for isolated testing"; exit 1; }
                ml_log_warning "Unencrypted HTTP enabled: Management API credentials and certificate private keys may be exposed on the network"
                ;;
        esac
    fi
    ml_parse_host_url "$MARKLOGIC_HOST"
    [[ -n "$ML_HOST" && "$ML_HOST" =~ ^[A-Za-z0-9.-]+$ ]] || { ml_log_error "Invalid MarkLogic host"; exit 1; }
    [[ "$ML_PORT" =~ ^[0-9]{1,5}$ ]] && [ "$ML_PORT" -ge 1 ] && [ "$ML_PORT" -le 65535 ] || { ml_log_error "Invalid MarkLogic port"; exit 1; }

    if [ "$COMMAND" != "generate-csr" ] && { [ -n "$DNS_NAME" ] || [ -n "$IP_ADDR" ] || [ -n "$SUBJECT_ALT_NAMES" ]; }; then
        ml_log_error "CSR Subject Alternative Name options are valid only with generate-csr"
        exit 1
    fi

    case "$COMMAND" in
        create-template)
            [ -n "$TEMPLATE_NAME" ] && [ -n "$COMMON_NAME" ] && [ -n "$ORGANIZATION" ] || { ml_log_error "Template name, common name, and organization are required"; exit 1; }
            [[ "$KEY_SIZE" =~ ^[0-9]{4,5}$ ]] && [ "$KEY_SIZE" -ge 1024 ] && [ "$KEY_SIZE" -le 16384 ] || { ml_log_error "Key size must be between 1024 and 16384 bits"; exit 1; }
            tls_api_path_segment "$TEMPLATE_NAME" >/dev/null || { ml_log_error "Invalid template name"; exit 1; }
            ;;
        generate-csr)
            tls_api_path_segment "$TEMPLATE_NAME" >/dev/null || { ml_log_error "Invalid template name"; exit 1; }
            tls_validate_csr_sans || exit 1
            ;;
        import-cert)
            tls_api_path_segment "$TEMPLATE_NAME" >/dev/null || { ml_log_error "Invalid template name"; exit 1; }
            [ -n "$CERT_FILE" ] && [ -r "$CERT_FILE" ] || { ml_log_error "Readable --cert-file is required"; exit 1; }
            [ -z "$KEY_FILE" ] || [ -r "$KEY_FILE" ] || { ml_log_error "Private-key file is not readable"; exit 1; }
            ;;
        configure-ssl)
            tls_api_path_segment "$TEMPLATE_NAME" >/dev/null || { ml_log_error "Invalid template name"; exit 1; }
            tls_api_path_segment "$APPSERVER_NAME" >/dev/null || { ml_log_error "Invalid app-server name"; exit 1; }
            ;;
        test-ssl)
            [ -n "${TEST_HOST:-}" ] || TEST_HOST="${ML_HOST:-localhost}"
            [[ "$TEST_PORT" =~ ^[0-9]{1,5}$ ]] && [ "$TEST_PORT" -ge 1 ] && [ "$TEST_PORT" -le 65535 ] || { ml_log_error "Invalid TLS test port"; exit 1; }
            [[ "$TEST_HOST" =~ ^[A-Za-z0-9.-]+$ ]] || { ml_log_error "Invalid TLS test host"; exit 1; }
            ;;
        list-templates) ;;
        show-template) tls_api_path_segment "$TEMPLATE_NAME" >/dev/null || { ml_log_error "Invalid template name"; exit 1; } ;;
        *) ml_log_error "Unknown command: $COMMAND"; show_usage; exit 1 ;;
    esac

    if [ "$DRY_RUN" = "true" ]; then
        case "$COMMAND" in
            create-template) ml_log_info "[DRY-RUN] Would create or guarded-update certificate template '$TEMPLATE_NAME'; remote state is unknown" ;;
            generate-csr) ml_log_info "[DRY-RUN] Would request a CSR from template '$TEMPLATE_NAME'; no local file will be written" ;;
            import-cert)
                if [ -n "$KEY_FILE" ]; then ml_log_info "[DRY-RUN] Would import a certificate/key pair into '$TEMPLATE_NAME'"
                else ml_log_info "[DRY-RUN] Would match the certificate against a pending CSR via /manage/v2/certificates"; fi
                ;;
            configure-ssl) ml_log_info "[DRY-RUN] Would bind template '$TEMPLATE_NAME' to app server '$APPSERVER_NAME'; remote state is unknown" ;;
            test-ssl) ml_log_info "[DRY-RUN] Would perform a verified TLS handshake; no network probe was made" ;;
            list-templates) ml_log_info "[DRY-RUN] Would list certificate templates; remote state is unknown" ;;
            show-template) ml_log_info "[DRY-RUN] Would read template '$TEMPLATE_NAME'; sensitive fields are omitted" ;;
        esac
        ml_log_info "[DRY-RUN] No password prompt, API request, key operation, or local file write"
        exit 0
    fi

    if [ "$COMMAND" = "import-cert" ]; then
        tls_validate_certificate "$CERT_FILE" || exit 1
        if [ -n "$KEY_FILE" ]; then tls_verify_cert_key_match "$CERT_FILE" "$KEY_FILE" || exit 1; fi
    fi
    if [ "$COMMAND" != "test-ssl" ]; then
        [ -n "$MARKLOGIC_USER" ] || { ml_log_error "MarkLogic user is required"; exit 1; }
        MARKLOGIC_PASS=$(ml_resolve_password) || exit 1
        ml_test_connectivity || exit 1
    fi

    local exit_code=0
    case "$COMMAND" in
        create-template) tls_create_template || exit_code=$? ;;
        generate-csr) tls_generate_csr || exit_code=$? ;;
        import-cert) tls_import_certificate || exit_code=$? ;;
        configure-ssl) tls_configure_appserver_ssl || exit_code=$? ;;
        test-ssl) tls_test_ssl "$TEST_HOST" "$TEST_PORT" || exit_code=$? ;;
        list-templates) tls_list_templates || exit_code=$? ;;
        show-template) tls_show_template || exit_code=$? ;;
    esac
    if [ "$exit_code" -eq 0 ]; then
        case "$COMMAND" in
            create-template) ml_show_footer "Generate a CSR, submit it to a CA, then import the signed certificate." ;;
            configure-ssl) ml_show_footer "Review the protected app-server snapshot for manual restoration if needed." ;;
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