#!/bin/bash

# ================================================================
# MarkLogic Configuration Verification Script
# ================================================================
#
# This script uses the MarkLogic REST API to verify the expected
# outcomes of authentication configuration scripts.
#
# Author: Martin Warnes
# Version: 1.0.0
# Date: November 2025
#
# Usage:
#   ./verify-marklogic-config.sh [OPTIONS]
#
# ================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/marklogic-utils.sh"
DRY_RUN=false

# ================================================================
# CONFIGURATION VARIABLES
# ================================================================

# Default values
MARKLOGIC_HOST="${MARKLOGIC_HOST:-oauth.warnesnet.com}"
MARKLOGIC_PORT="${MARKLOGIC_PORT:-8002}"
MARKLOGIC_USER="${MARKLOGIC_USER:-admin}"
MARKLOGIC_PASS="${MARKLOGIC_PASS:-}"
TEST_ENDPOINT=""  # default: <target>/manage/v2 (set after host parsing)
APPSERVER_NAME="Manage2"
CONFIG_NAME=""
CONFIG_TYPE=""
VERBOSE="false"

# ================================================================
# UTILITY FUNCTIONS
# ================================================================

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" >&2
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" >&2
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

log_verbose() {
    if [ "$VERBOSE" = "true" ]; then
        echo -e "${CYAN}[DEBUG]${NC} $1" >&2
    fi
}

show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Read-only verification of MarkLogic authentication configurations using the Management REST API.

OPTIONS:
    --config-name NAME            Name of configuration to verify
    --config-type TYPE            Type: oauth2, saml, ldap, kerberos, tls (certificate template), appserver, list
    --marklogic-host HOST         MarkLogic host (default: oauth.warnesnet.com)
    --marklogic-port PORT         MarkLogic port (default: 8002)
    --marklogic-user USER         MarkLogic user (default: admin)
    --marklogic-pass PASS         Rejected; use MARKLOGIC_PASS or a hidden prompt
    --test-endpoint URL           Test endpoint URL (default: <marklogic-host>:<port>/manage/v2)
    --appserver-name NAME         App server name (default: Manage2)
    --verbose                     Enable verbose logging
    --help                        Show this help message

This is a read-only diagnostic; it does not support a misleading --dry-run mode.
Set MARKLOGIC_PASS for unattended use, or run interactively for a hidden prompt.

EXAMPLES:
    # Verify SAML configuration
    $0 --config-name keycloak-saml --config-type saml

    # Verify OAuth2 configuration
    $0 --config-name MLEAProxy-OAuth --config-type oauth2

    # List all external security configurations
    $0 --config-type list

    # Verify app server configuration
    $0 --config-type appserver --appserver-name Manage2

EOF
}

# ================================================================
# API VERIFICATION FUNCTIONS
# ================================================================

api_path_segment() {
    local value="$1"
    [[ -n "$value" && "$value" != "." && "$value" != ".." && "$value" != *"/"* && "$value" != *"?"* && "$value" != *"#"* && "$value" != *$'\n'* && "$value" != *$'\r'* ]] || return 1
    jq -nr --arg value "$value" '$value|@uri'
}

# Test MarkLogic connectivity using protected shared credentials.
test_marklogic_connectivity() {
    log_info "Testing MarkLogic connectivity..."
    local response status_code
    if ! response=$(ml_api_request GET "/manage/v2" "$MARKLOGIC_USER" "$MARKLOGIC_PASS"); then
        log_error "Cannot connect to MarkLogic"
        return 1
    fi
    status_code=$(ml_extract_status_code "$response")
    case "$status_code" in
        200|401|403) log_success "MarkLogic is accessible at $ML_DISPLAY_URL"; return 0 ;;
        *) log_error "Unexpected response from MarkLogic (HTTP $status_code)"; return 1 ;;
    esac
}

# Test endpoint connectivity
test_endpoint_connectivity() {
    log_info "Testing the configured read-only endpoint"
    
    local response status_code
    response=$(curl -s -w "%{http_code}" -m 10 --connect-timeout 5 \
        "$TEST_ENDPOINT" 2>/dev/null)
    status_code="${response: -3}"
    
    case "$status_code" in
        200|401|403)
            log_success "Test endpoint is accessible"
            return 0
            ;;
        000)
            log_error "Cannot connect to test endpoint: $TEST_ENDPOINT"
            return 1
            ;;
        *)
            log_warning "Test endpoint returned HTTP $status_code"
            return 0
            ;;
    esac
}

# List all external security configurations
list_external_security() {
    log_info "Listing all external security configurations..."
    
    local response status_code response_body
    response=$(ml_api_request GET "/manage/v2/external-security?format=json" "$MARKLOGIC_USER" "$MARKLOGIC_PASS") || return 1
    status_code=$(ml_extract_status_code "$response")
    response_body=$(ml_extract_response_body "$response")
    
    case "$status_code" in
        200)
            log_success "External security configurations retrieved"
            echo "$response_body" | jq -r '.["external-security-default-list"]["list-items"]["list-item"][]?.nameref // "No configurations found"' 2>/dev/null || echo "$response_body"
            return 0
            ;;
        401)
            log_error "Authentication failed - check credentials"
            return 1
            ;;
        *)
            log_error "Failed to retrieve configurations (HTTP $status_code)"
            return 1
            ;;
    esac
}

# Verify specific external security configuration
verify_external_security() {
    local config_name="$1"
    
    log_info "Verifying external security configuration: $config_name"
    
    local config_path response status_code response_body
    config_path=$(api_path_segment "$config_name") || return 1
    response=$(ml_api_request GET "/manage/v2/external-security/$config_path?format=json" "$MARKLOGIC_USER" "$MARKLOGIC_PASS") || return 1
    status_code=$(ml_extract_status_code "$response")
    response_body=$(ml_extract_response_body "$response")
    
    case "$status_code" in
        200)
            log_success "Configuration found: $config_name"
            local auth_type
            auth_type=$(echo "$response_body" | jq -r '.authentication // "unknown"' 2>/dev/null)
            log_verbose "Authentication type: $auth_type"
            return 0
            ;;
        404)
            log_error "Configuration not found: $config_name"
            return 1
            ;;
        401)
            log_error "Authentication failed - check credentials"
            return 1
            ;;
        *)
            log_error "Failed to retrieve configuration (HTTP $status_code)"
            return 1
            ;;
    esac
}

# Verify a TLS certificate template exists and report its certificate(s)
verify_tls_template() {
    local template_name="$1" template_path response status_code body count i days end cn
    log_info "Verifying certificate template: $template_name"
    template_path=$(api_path_segment "$template_name") || return 1
    response=$(ml_api_request GET "/manage/v2/certificate-templates/$template_path?format=json" "$MARKLOGIC_USER" "$MARKLOGIC_PASS") || return 1
    status_code=$(ml_extract_status_code "$response")
    case "$status_code" in
        200) log_success "Certificate template found: $template_name" ;;
        404) log_error "Certificate template not found: $template_name"; return 1 ;;
        401) log_error "Authentication failed - check credentials"; return 1 ;;
        *) log_error "Failed to retrieve certificate template (HTTP $status_code)"; return 1 ;;
    esac
    response=$(ml_api_request POST "/manage/v2/certificate-templates/$template_path?format=json" "$MARKLOGIC_USER" "$MARKLOGIC_PASS" '{"operation":"get-certificates-for-template"}') || return 1
    [ "$(ml_extract_status_code "$response")" = "200" ] || { log_error "Could not read certificates for the template"; return 1; }
    body=$(ml_extract_response_body "$response")
    count=$(printf '%s' "$body" | jq '[."certificate-list".certificate[]? | select((.authority|tostring) != "true")] | length')
    if [ "${count:-0}" -eq 0 ]; then
        log_warning "Template has no certificate installed (pending CSR or not yet imported)"
        return 0
    fi
    for ((i=0; i<count; i++)); do
        local pem
        pem=$(printf '%s' "$body" | jq -r --argjson i "$i" '[."certificate-list".certificate[]? | select((.authority|tostring) != "true")][$i].pem')
        end=$(printf '%s\n' "$pem" | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
        cn=$(printf '%s\n' "$pem" | openssl x509 -noout -subject -nameopt RFC2253 2>/dev/null | sed 's/^subject=//')
        if printf '%s\n' "$pem" | openssl x509 -noout -checkend 0 >/dev/null 2>&1; then
            log_success "Certificate $((i+1)): $cn (expires $end)"
        else
            log_error "Certificate $((i+1)): $cn EXPIRED $end"; return 1
        fi
    done
    return 0
}

# Verify app server configuration
verify_appserver_config() {
    local appserver_name="$1"
    
    log_info "Verifying app server configuration: $appserver_name"
    
    local appserver_path response status_code response_body
    appserver_path=$(api_path_segment "$appserver_name") || return 1
    response=$(ml_api_request GET "/manage/v2/servers/$appserver_path/properties?group-id=Default&format=json" "$MARKLOGIC_USER" "$MARKLOGIC_PASS") || return 1
    status_code=$(ml_extract_status_code "$response")
    response_body=$(ml_extract_response_body "$response")
    
    case "$status_code" in
        200)
            log_success "App server found: $appserver_name"
            
            # Extract security configuration
            local auth_mode external_security
            auth_mode=$(echo "$response_body" | jq -r '.authentication // "not set"' 2>/dev/null)
            external_security=$(echo "$response_body" | jq -r '(.["external-security"] // "not set") | if type == "array" then (if length == 0 then "not set" else join(", ") end) else . end' 2>/dev/null)
            
            log_info "Authentication mode: $auth_mode"
            log_info "External security: $external_security"
            
            return 0
            ;;
        404)
            log_error "App server not found: $appserver_name"
            return 1
            ;;
        401)
            log_error "Authentication failed - check credentials"
            return 1
            ;;
        *)
            log_error "Failed to retrieve app server configuration (HTTP $status_code)"
            return 1
            ;;
    esac
}

# Test SAML specific configuration
verify_saml_config() {
    local config_name="$1"
    
    log_info "Verifying SAML configuration: $config_name"
    
    # First verify the external security exists
    if verify_external_security "$config_name"; then
        log_info "Checking SAML specific properties..."
        
        local config_path response status_code response_body
        config_path=$(api_path_segment "$config_name") || return 1
        response=$(ml_api_request GET "/manage/v2/external-security/$config_path/properties?format=json" "$MARKLOGIC_USER" "$MARKLOGIC_PASS") || return 1
        status_code=$(ml_extract_status_code "$response")
        response_body=$(ml_extract_response_body "$response")
        
        if [ "$status_code" = "200" ]; then
            # Check SAML specific fields
            local auth_type
            auth_type=$(echo "$response_body" | jq -r '.authentication // "not set"' 2>/dev/null)
            
            if [ "$auth_type" = "saml" ]; then
                log_success "Configuration is properly set for SAML authentication"
                
                # saml-issuer is the SP entity ID MarkLogic sends; saml-entity-id / saml-destination describe the IdP.
                # Certificates and keys are reported as present/absent only.
                local issuer idp_entity destination idp_cert sp_cert
                issuer=$(echo "$response_body" | jq -r '.["saml-server"]["saml-issuer"] // "not set"' 2>/dev/null)
                idp_entity=$(echo "$response_body" | jq -r '.["saml-server"]["saml-entity-id"] // "not set"' 2>/dev/null)
                destination=$(echo "$response_body" | jq -r '.["saml-server"]["saml-destination"] // "not set"' 2>/dev/null)
                idp_cert=$(echo "$response_body" | jq -r 'if (.["saml-server"]["saml-idp-certificate-authority"] // "") != "" then "present" else "MISSING" end' 2>/dev/null)
                sp_cert=$(echo "$response_body" | jq -r 'if (.["saml-server"]["saml-sp-certificate"] // "") != "" then "present" else "not set (AuthnRequests unsigned)" end' 2>/dev/null)

                log_info "SP entity ID (saml-issuer): $issuer"
                log_info "IdP entity ID (saml-entity-id): $idp_entity"
                log_info "IdP SSO URL (saml-destination): $destination"
                log_info "IdP signing certificate: $idp_cert"
                log_info "SP certificate: $sp_cert"
                [ "$idp_cert" = "present" ] || { log_warning "No IdP certificate: MarkLogic cannot validate assertion signatures"; return 1; }
                
                return 0
            else
                log_warning "Configuration exists but authentication type is: $auth_type"
                return 1
            fi
        fi
    fi
    
    return 1
}

# ================================================================
# MAIN VERIFICATION LOGIC
# ================================================================

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --config-name|--config-type|--marklogic-host|--marklogic-port|--marklogic-user|--test-endpoint|--appserver-name)
                if [ "$#" -lt 2 ] || [ -z "${2:-}" ]; then log_error "$1 requires a non-empty value"; return 1; fi
                ;;
        esac
        case $1 in
            --config-name)
                CONFIG_NAME="$2"
                shift 2
                ;;
            --config-type)
                CONFIG_TYPE="$2"
                shift 2
                ;;
            --marklogic-host)
                MARKLOGIC_HOST="$2"
                shift 2
                ;;
            --marklogic-port)
                MARKLOGIC_PORT="$2"
                shift 2
                ;;
            --marklogic-user)
                MARKLOGIC_USER="$2"
                shift 2
                ;;
            --marklogic-pass)
                log_error "--marklogic-pass VALUE is rejected"
                log_error "Use MARKLOGIC_PASS or the hidden interactive prompt"
                return 1
                ;;
            --test-endpoint)
                TEST_ENDPOINT="$2"
                shift 2
                ;;
            --appserver-name)
                APPSERVER_NAME="$2"
                shift 2
                ;;
            --verbose)
                VERBOSE="true"
                shift
                ;;
            --help)
                show_usage
                exit 0
                ;;
            *)
                log_error "Unknown option"
                show_usage
                exit 1
                ;;
        esac
    done
}

# Main execution function
main() {
    log_info "=== MarkLogic Configuration Verification (read-only) ==="
    log_info "Version 1.0.0 - MarkLogic Security Hub"

    case "$CONFIG_TYPE" in
        list) ;;
        saml|oauth2|ldap|kerberos|tls)
            [ -n "$CONFIG_NAME" ] || { log_error "--config-name is required for $CONFIG_TYPE verification"; exit 1; }
            ;;
        appserver)
            [ -n "$APPSERVER_NAME" ] || { log_error "--appserver-name is required"; exit 1; }
            ;;
        *) log_error "Valid --config-type is required"; show_usage; exit 1 ;;
    esac
    if [ -z "$TEST_ENDPOINT" ]; then
        ml_parse_host_url "$MARKLOGIC_HOST"
        TEST_ENDPOINT="$ML_DISPLAY_URL/manage/v2"
    fi
    case "$TEST_ENDPOINT" in
        http://*|https://*) ;;
        *) log_error "Test endpoint must use HTTP or HTTPS"; exit 1 ;;
    esac
    local endpoint_authority="${TEST_ENDPOINT#*://}"
    endpoint_authority="${endpoint_authority%%/*}"
    if [ -z "$endpoint_authority" ] || [[ "$endpoint_authority" == *"@"* || "$TEST_ENDPOINT" == *"?"* || "$TEST_ENDPOINT" == *"#"* || "$TEST_ENDPOINT" == *[[:space:]]* ]]; then
        log_error "Test endpoint must not contain userinfo, query, fragment, or whitespace"
        exit 1
    fi
    ml_check_dependencies || exit 1
    ml_parse_host_url "$MARKLOGIC_HOST"
    MARKLOGIC_PASS=$(ml_resolve_password) || exit 1
    test_marklogic_connectivity || exit 1
    test_endpoint_connectivity || exit 1
    echo

    case "$CONFIG_TYPE" in
        list) list_external_security ;;
        saml) verify_saml_config "$CONFIG_NAME" ;;
        oauth2|ldap|kerberos) verify_external_security "$CONFIG_NAME" ;;
        tls) verify_tls_template "$CONFIG_NAME" ;;
        appserver) verify_appserver_config "$APPSERVER_NAME" ;;
    esac
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    parse_arguments "$@"
    main
fi