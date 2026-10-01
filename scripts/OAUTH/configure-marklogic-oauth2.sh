#!/bin/bash

# ================================================================
# MarkLogic OAuth2 Configuration Script
# ================================================================
# 
# This script creates MarkLogic OAuth2 external security configuration
# based on OAuth2 Authorization Server .well-known discovery endpoint
# 
# Features:
# - Fetches configuration from .well-known/openid_configuration or .well-known/config
# - Creates MarkLogic external security configuration via REST API
# - Optionally fetches and configures JWT secrets from JWKS endpoint
# - Tests configuration with MLEAProxy OAuth server
# - Validates token verification
#
# Author: Martin Warnes
# Version: 1.0.4
# Date: October 2025
#
# Usage:
#   ./configure-marklogic-oauth2.sh [OPTIONS]
#
# Examples:
#   # Configure with MLEAProxy (development/testing)
#   ./configure-marklogic-oauth2.sh --well-known-url http://localhost:8080/oauth/.well-known/config --marklogic-host oauth.warnesnet.com --config-name MLEAProxy-OAuth
#
#   # Configure with MLEAProxy and fetch JWKS keys
#   ./configure-marklogic-oauth2.sh --well-known-url http://localhost:8080/oauth/.well-known/config --marklogic-host oauth.warnesnet.com --config-name MLEAProxy-OAuth --fetch-jwks-keys
#
#   # Configure with Keycloak
#   ./configure-marklogic-oauth2.sh --well-known-url https://keycloak.example.com/auth/realms/marklogic/.well-known/openid_configuration --marklogic-host oauth.warnesnet.com --config-name Keycloak-OAuth
#
#   # Configure with Azure AD
#   ./configure-marklogic-oauth2.sh --well-known-url https://login.microsoftonline.com/{tenant-id}/v2.0/.well-known/openid_configuration --marklogic-host oauth.warnesnet.com --config-name AzureAD-OAuth
#
# ================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../marklogic-utils.sh"
source "$SCRIPT_DIR/oauth2-utils.sh"

# ================================================================
# CONFIGURATION VARIABLES
# ================================================================

# Default values
WELL_KNOWN_URL=""
MARKLOGIC_HOST="${MARKLOGIC_HOST:-localhost}"
REMOVE_CONFIG="false"
FORCE_UPDATE="false"
YES="false"
MARKLOGIC_PORT="${MARKLOGIC_PORT:-8002}"
MARKLOGIC_USER="${MARKLOGIC_USER:-admin}"
MARKLOGIC_PASS="${MARKLOGIC_PASS:-}"
CONFIG_NAME="OAuth2-Config"
CONFIG_DESCRIPTION="OAuth2 configuration created by script"
USERNAME_ATTRIBUTE="preferred_username"
ROLE_ATTRIBUTE="marklogic-roles"
PRIVILEGE_ATTRIBUTE=""
CACHE_TIMEOUT="300"
CLIENT_ID="marklogic"
FETCH_JWKS="false"
VERBOSE="false"
DRY_RUN="false"
INSECURE="false"

# Authorization Code flow (v12.1+) - only used when --oauth-flow-type authorization-code
OAUTH_FLOW_TYPE="resource-server"
CLIENT_SECRET="${OAUTH_CLIENT_SECRET:-}"
REDIRECT_URI=""
AUTHORIZATION_SERVER_URI=""
TOKEN_SERVER_URI_OVERRIDE=""
JWT_ISSUER_URI_OVERRIDE=""
OAUTH_SCOPE="openid profile"
CLIENT_AUTH_METHOD="Client secret"

# URL parsing variables (set by parse_marklogic_host function)
MARKLOGIC_PROTOCOL=""
MARKLOGIC_HOST_ONLY=""
MARKLOGIC_PORT_FROM_URL=""
MARKLOGIC_IS_HTTPS="false"

# ================================================================
# UTILITY FUNCTIONS
# ================================================================

# Reuse the shared MarkLogic URL parser and keep the management target unambiguous.
parse_marklogic_host() {
    local host_url="$1" authority
    case "$host_url" in http://*|https://*) ;; *) host_url="http://$host_url" ;; esac
    oauth2_validate_url "$host_url" || return 1
    authority="${host_url#*://}"
    case "$authority" in
        */) host_url="${host_url%/}" ;;
        */*) log_error "MarkLogic host must not include a path"; return 1 ;;
    esac
    ml_parse_host_url "$host_url" || return 1
    [[ -n "$ML_HOST" && "$ML_HOST" =~ ^[A-Za-z0-9.-]+$ ]] || { log_error "Invalid MarkLogic host"; return 1; }
    [[ "$ML_PORT" =~ ^[0-9]{1,5}$ ]] && [ "$ML_PORT" -ge 1 ] && [ "$ML_PORT" -le 65535 ] || { log_error "Invalid MarkLogic port"; return 1; }
    MARKLOGIC_PROTOCOL="$ML_PROTOCOL"
    MARKLOGIC_HOST_ONLY="$ML_HOST"
    MARKLOGIC_PORT_FROM_URL="$ML_PORT"
    MARKLOGIC_IS_HTTPS="$ML_IS_HTTPS"
    log_verbose "Parsed MarkLogic target: protocol=$ML_PROTOCOL, host=$ML_HOST, port=$ML_PORT"
}

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

# Get curl flags based on configuration
get_curl_flags() {
    if [ "$INSECURE" = "true" ]; then
        log_warning "TLS certificate verification disabled by explicit --insecure option"
        printf '%s\n' --insecure
    fi
}

log_verbose() {
    if [ "$VERBOSE" = "true" ]; then
        echo -e "${CYAN}[DEBUG]${NC} $1" >&2
    fi
}

show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Creates MarkLogic OAuth2 external security configuration from OAuth2 Authorization Server discovery endpoints.

OPTIONS:
    --well-known-url URL          OAuth2 .well-known discovery endpoint URL (required)
    --marklogic-host URL          MarkLogic host URL (default: localhost, or MARKLOGIC_HOST env)
    --marklogic-port PORT         MarkLogic manage port (default: 8002)
    --marklogic-user USER         MarkLogic admin user (default: admin)
    --marklogic-pass PASS         Rejected; use MARKLOGIC_PASS or a hidden prompt
    --config-name NAME            External security configuration name (default: OAuth2-Config)
    --config-description DESC     Configuration description
    --username-attribute ATTR     JWT claim for username (default: preferred_username)
    --role-attribute ATTR         JWT claim for roles (default: marklogic-roles)
    --privilege-attribute ATTR    JWT claim for privileges (optional)
    --cache-timeout SECONDS       Token cache timeout (default: 300)
    --client-id ID                OAuth client ID (default: marklogic)
    --fetch-jwks-keys             Fetch and validate provider JWKS before changes (default: disabled)
    --remove                      Remove/delete the external security configuration
    --force                       Confirm and update an existing configuration after backup
    --yes                         Skip interactive confirmation (for automation)
    --insecure                    Ignore TLS certificate errors (explicit opt-in; discouraged)
    --verbose                     Enable verbose logging
    --dry-run                     Preview only; no metadata fetch, API call, temp file, or local write
    --help                        Show this help message

AUTHORIZATION CODE FLOW (MarkLogic 12.1+, requires app server SSL):
    --oauth-flow-type TYPE         'resource-server' (default) or 'authorization-code'
    --client-secret SECRET        Rejected; use OAUTH_CLIENT_SECRET or a hidden prompt
    --redirect-uri URL            MarkLogic app server URL, e.g. https://host:8000
                                   (required for authorization-code)
    --authorization-server-uri URL  Authorization endpoint (required for authorization-code;
                                   auto-filled from --well-known-url discovery when omitted)
    --token-server-uri URL        Token endpoint override (auto-filled from discovery when omitted)
    --jwt-issuer-uri URL          Token issuer URI override (auto-filled from discovery when omitted)
                                   NOTE: despite the Admin Interface tooltip, this is required for
                                   most IdPs when using RS256/JWKS validation, not just Entra/Cognito
    --oauth-scope SCOPES          Space-separated scopes to request (default: "openid profile")
    --client-auth-method METHOD   Client authentication method (default: "Client secret")

EXAMPLES:
    # MLEAProxy (development/testing)
    $0 --well-known-url http://localhost:8080/oauth/.well-known/config \\
       --config-name MLEAProxy-OAuth

    # MLEAProxy with JWKS key fetching
    $0 --well-known-url http://localhost:8080/oauth/.well-known/config \\
       --config-name MLEAProxy-OAuth --fetch-jwks-keys

    # Keycloak
    $0 --well-known-url https://keycloak.example.com/auth/realms/marklogic/.well-known/openid_configuration \\
       --config-name Keycloak-OAuth --marklogic-host production.marklogic.com

    # Azure AD
    $0 --well-known-url https://login.microsoftonline.com/TENANT-ID/v2.0/.well-known/openid_configuration \\
       --config-name AzureAD-OAuth --username-attribute upn --role-attribute roles

    # Authentik - Authorization Code flow for QConsole SSO (MarkLogic 12.1+)
    # Set OAUTH_CLIENT_SECRET via a secret manager or enter it at the hidden prompt.
    $0 --well-known-url https://authentik.example.com/application/o/marklogic-qconsole/.well-known/openid-configuration \\
       --config-name Authentik-QConsole-SSO --oauth-flow-type authorization-code \\
       --client-id marklogic-qconsole \\
       --redirect-uri https://marklogic.example.com:8000 \\
       --oauth-scope "openid profile marklogic_roles" \\
       --marklogic-host marklogic.example.com

    # Remove configuration
    $0 --config-name MLEAProxy-OAuth --remove

ENVIRONMENT VARIABLES:
    MARKLOGIC_HOST               Override default MarkLogic host
    MARKLOGIC_USER               Override default MarkLogic user
    MARKLOGIC_PASS               MarkLogic password for unattended use
    OAUTH_CLIENT_SECRET          OAuth client secret for unattended use

EOF
}

# Reuse strict OAuth endpoint validation without echoing potentially sensitive URLs.
validate_url() {
    oauth2_validate_url "$1"
}

# Check if command exists
check_dependency() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        log_error "Required command '$cmd' not found. Please install it."
        exit 1
    fi
}

# Check required dependencies
check_dependencies() {
    log_info "Checking dependencies..."
    check_dependency "curl"
    check_dependency "jq"
    log_success "All dependencies found"
}

# Test MarkLogic connectivity
test_marklogic_connection() {
    log_info "Testing MarkLogic connectivity..."
    
    # Use parsed URL components or fallback to original values
    local protocol="${MARKLOGIC_PROTOCOL:-http}"
    local host="${MARKLOGIC_HOST_ONLY:-$MARKLOGIC_HOST}"
    local port="${MARKLOGIC_PORT_FROM_URL:-$MARKLOGIC_PORT}"
    local test_url="$protocol://$host:$port"
    
    if [ "$DRY_RUN" = "true" ]; then
        log_info "[DRY-RUN] Would test MarkLogic connectivity; no preflight request was sent"
        return 0
    fi
    local response status_code
    if ! response=$(ml_api_request GET "/manage/v2" "$MARKLOGIC_USER" "$MARKLOGIC_PASS"); then
        log_error "Cannot connect to MarkLogic at $test_url"
        return 1
    fi
    status_code=$(ml_extract_status_code "$response")

    case "$status_code" in
        200|401|403)
            log_success "MarkLogic is accessible at $test_url"
            return 0
            ;;
        000)
            log_error "Cannot connect to MarkLogic at $test_url"
            log_error "Common solutions:"
            log_error "  1. Start MarkLogic: sudo /etc/init.d/MarkLogic start"
            log_error "  2. Check if running: sudo service MarkLogic status"
            log_error "  3. Verify port $MARKLOGIC_PORT is correct (usually 8001 or 8002)"
            log_error "  4. Check firewall settings"
            return 1
            ;;
        *)
            log_error "Unexpected response from MarkLogic (HTTP $status_code)"
            return 1
            ;;
    esac
}

# ================================================================
# OAUTH2 DISCOVERY FUNCTIONS
# ================================================================

# Fetch OAuth2 discovery data without creating local payload files.
fetch_oauth_config() {
    local well_known_url="$1" response curl_flags
    if [ "$DRY_RUN" = "true" ]; then
        log_info "[DRY-RUN] Would fetch OAuth2 discovery metadata; remote values remain unknown"
        return 3
    fi
    oauth2_validate_url "$well_known_url" || return 1
    curl_flags=$(get_curl_flags)
    log_info "Fetching OAuth2 discovery metadata from the configured endpoint"
    response=$(oauth2_http_get "$well_known_url" "$DEFAULT_TIMEOUT" "" "$curl_flags") || {
        log_error "Failed to fetch OAuth2 discovery metadata"
        return 1
    }
    oauth2_validate_json "$response" || { log_error "Invalid JSON from OAuth2 discovery endpoint"; return 1; }
    printf '%s\n' "$response"
}

# Extract configuration values from OAuth2 discovery response
parse_oauth_config() {
    local config_json="$1"
    
    log_info "Parsing OAuth2 configuration..."
    
    log_verbose "Parsing OAuth discovery document (${#config_json} bytes)"
    
    # Extract required fields
    ISSUER=$(echo "$config_json" | jq -r '.issuer // .iss // "unknown-issuer"')
    TOKEN_ENDPOINT=$(echo "$config_json" | jq -r '.token_endpoint // ""')
    JWKS_URI=$(echo "$config_json" | jq -r '.jwks_uri // ""')
    AUTHORIZATION_ENDPOINT=$(echo "$config_json" | jq -r '.authorization_endpoint // ""')
    
    if [ -n "$TOKEN_ENDPOINT" ] && ! oauth2_validate_url "$TOKEN_ENDPOINT"; then log_error "Invalid token endpoint URL"; return 1; fi
    if [ -n "$JWKS_URI" ] && [ "$JWKS_URI" != "null" ] && ! oauth2_validate_url "$JWKS_URI"; then log_error "Invalid JWKS endpoint URL"; return 1; fi
    if [ -n "$AUTHORIZATION_ENDPOINT" ] && ! oauth2_validate_url "$AUTHORIZATION_ENDPOINT"; then log_error "Invalid authorization endpoint URL"; return 1; fi
    log_verbose "OAuth2 issuer and endpoints parsed"

    # For the Authorization Code flow, use discovery values as defaults unless
    # explicitly overridden on the command line
    if [ "$OAUTH_FLOW_TYPE" = "authorization-code" ]; then
        if [ -z "$AUTHORIZATION_SERVER_URI" ]; then
            AUTHORIZATION_SERVER_URI="$AUTHORIZATION_ENDPOINT"
        fi
        if [ -z "$TOKEN_SERVER_URI_OVERRIDE" ]; then
            TOKEN_SERVER_URI_OVERRIDE="$TOKEN_ENDPOINT"
        fi
        if [ -z "$JWT_ISSUER_URI_OVERRIDE" ]; then
            JWT_ISSUER_URI_OVERRIDE="$ISSUER"
        fi
    fi
    
    # Require a known, valid issuer; an explicit override is supported for providers with incomplete metadata.
    if [ -n "$JWT_ISSUER_URI_OVERRIDE" ]; then
        ISSUER="$JWT_ISSUER_URI_OVERRIDE"
    fi
    if [ -z "$ISSUER" ] || [ "$ISSUER" = "null" ] || [ "$ISSUER" = "unknown-issuer" ]; then
        log_error "No OAuth issuer found in discovery; set --jwt-issuer-uri"
        return 1
    fi
    oauth2_validate_url "$ISSUER" || { log_error "Invalid OAuth issuer URL"; return 1; }
    
    if [ "$JWKS_URI" = "null" ] || [ "$JWKS_URI" = "" ]; then
        if [ "$FETCH_JWKS" = "true" ]; then
            log_error "JWKS fetching was requested, but discovery contains no JWKS URI"
            return 1
        fi
        log_warning "No JWKS URI found in OAuth2 configuration"
        FETCH_JWKS="false"
    fi
    
    log_success "OAuth2 configuration parsed successfully"
}

# Fetch a complete, non-empty JWKS inventory only in live mode.
fetch_jwks_keys() {
    local jwks_uri="$1" curl_flags jwks_response key_count
    if [ "$DRY_RUN" = "true" ]; then
        log_info "[DRY-RUN] Would fetch and validate JWKS; no metadata or key data was downloaded"
        return 3
    fi
    if [ "$FETCH_JWKS" != "true" ] || [ -z "$jwks_uri" ] || [ "$jwks_uri" = "null" ]; then
        log_info "JWKS fetching is disabled"
        return 0
    fi
    oauth2_validate_url "$jwks_uri" || return 1
    log_info "Fetching JWKS from the configured discovery endpoint"
    curl_flags=$(get_curl_flags)
    jwks_response=$(oauth2_fetch_jwks "$jwks_uri" "$curl_flags") || {
        log_error "JWKS retrieval/validation failed; refusing to continue without a valid inventory"
        return 1
    }
    key_count=$(oauth2_jwks_key_count "$jwks_response") || return 1
    log_info "Validated $key_count JWKS key(s)"
    printf '%s\n' "$jwks_response"
}

# ================================================================
# MARKLOGIC CONFIGURATION FUNCTIONS
# ================================================================

# Create JSON without interpolating untrusted strings or exposing the client secret to jq argv.
create_external_security_config() {
    if [ "$DRY_RUN" = "true" ]; then
        log_info "[DRY-RUN] Would create/update OAuth external security; remote state is unknown"
        return 3
    fi
    local config_json jwks_uri="" client_secret_file=""
    local -a secret_jq_args
    [ -z "$JWKS_URI" ] || [ "$JWKS_URI" = "null" ] || jwks_uri="$JWKS_URI"
    if [ "$OAUTH_FLOW_TYPE" = "authorization-code" ]; then
        [ -n "$CLIENT_SECRET" ] || { log_error "Authorization-code flow requires OAUTH_CLIENT_SECRET"; return 1; }
        client_secret_file=$(oauth2_write_temp_file "$CLIENT_SECRET") || return 1
        secret_jq_args=(--rawfile client_secret "$client_secret_file")
    else
        secret_jq_args=(--arg client_secret "")
    fi

    if ! config_json=$(jq -n --arg name "$CONFIG_NAME" --arg description "$CONFIG_DESCRIPTION" --arg timeout "$CACHE_TIMEOUT" \
        --arg flow "$OAUTH_FLOW_TYPE" --arg client_id "$CLIENT_ID" --arg issuer "$ISSUER" --arg auth_issuer "$JWT_ISSUER_URI_OVERRIDE" \
        --arg authorization_uri "$AUTHORIZATION_SERVER_URI" --arg token_uri "$TOKEN_SERVER_URI_OVERRIDE" --arg scope "$OAUTH_SCOPE" \
        --arg auth_method "$CLIENT_AUTH_METHOD" --arg redirect_uri "$REDIRECT_URI" --arg username_attr "$USERNAME_ATTRIBUTE" \
        --arg role_attr "$ROLE_ATTRIBUTE" --arg privilege_attr "$PRIVILEGE_ATTRIBUTE" --arg jwks_uri "$jwks_uri" \
        "${secret_jq_args[@]}" \
        '{"external-security-name":$name,"description":$description,"authentication":"oauth","cache-timeout":$timeout,"authorization":"oauth","oauth-server":(if $flow == "authorization-code" then {"oauth-flow-type":"Authorization code","oauth-vendor":"Other","oauth-authorization-server-uri":$authorization_uri,"oauth-token-server-uri":$token_uri,"oauth-scope":$scope,"oauth-client-authentication-method":$auth_method,"oauth-client-id":$client_id,"oauth-client-secret":$client_secret,"oauth-redirect-uri":$redirect_uri,"oauth-token-type":"JSON Web Tokens","oauth-username-attribute":$username_attr,"oauth-role-attribute":$role_attr,"oauth-privilege-attribute":$privilege_attr,"oauth-jwt-alg":"RS256","oauth-jwt-issuer-uri":$auth_issuer} + (if $jwks_uri == "" then {} else {"oauth-jwks-uri":$jwks_uri} end) else {"oauth-vendor":"Other","oauth-flow-type":"Resource server","oauth-client-id":$client_id,"oauth-jwt-issuer-uri":$issuer,"oauth-token-type":"JSON Web Tokens","oauth-username-attribute":$username_attr,"oauth-role-attribute":$role_attr,"oauth-privilege-attribute":$privilege_attr,"oauth-jwt-alg":"RS256"} + (if $jwks_uri == "" then {} else {"oauth-jwks-uri":$jwks_uri} end) end)}'); then
        oauth2_cleanup_temp_file "$client_secret_file"
        return 1
    fi
    oauth2_cleanup_temp_file "$client_secret_file"
    # Return only to the caller for protected API submission; never log the payload.
    printf '%s\n' "$config_json"
}

# Apply configuration to MarkLogic
apply_marklogic_config() {
    local config_json="$1"
    
    local endpoint="/manage/v2/external-security"
    log_info "Applying OAuth configuration to MarkLogic"
    
    if [ "$DRY_RUN" = "true" ]; then
        log_info "[DRY-RUN] Would POST OAuth configuration to $endpoint; remote state is unknown"
        return 0
    fi
    
    # MarkLogic 12.1 answers a duplicate POST with HTTP 500 (XDMP-UNDFUN) or 400 (MANAGE-CONFLICTINGCONFIG), not 409,
    # so look first.
    local exists_status
    if ml_check_external_security_exists "$(oauth2_api_path_segment "$CONFIG_NAME")" "$MARKLOGIC_USER" "$MARKLOGIC_PASS"; then exists_status=0; else exists_status=$?; fi
    case $exists_status in
        0)
            if [ "$FORCE_UPDATE" != "true" ]; then
                log_error "External security '$CONFIG_NAME' already exists; use --force to request a guarded update"
                return 1
            fi
            update_marklogic_config "$config_json"
            return $?
            ;;
        1) ;;
        *) log_error "Could not check whether '$CONFIG_NAME' already exists"; return 1 ;;
    esac

    local response status_code
    if ! ml_api_call_with_dryrun response "POST" "$endpoint" "$MARKLOGIC_USER" "$MARKLOGIC_PASS" "$config_json"; then
        log_error "OAuth configuration request failed"
        return 1
    fi
    status_code=$(ml_extract_status_code "$response")
    log_verbose "MarkLogic response code: $status_code"

    case "$status_code" in
        201|200) log_success "External security configuration created successfully"; return 0 ;;
        000) log_error "Connection failed to MarkLogic management API"; return 1 ;;
        400) log_error "Bad request - check OAuth configuration parameters (response body suppressed)"; return 1 ;;
        401) log_error "Unauthorized - check MarkLogic credentials"; return 1 ;;
        403) log_error "MarkLogic user lacks permission to configure external security"; return 1 ;;
        409)
            if [ "$FORCE_UPDATE" != "true" ]; then
                log_error "Configuration already exists; use --force to request a guarded update"
                return 1
            fi
            update_marklogic_config "$config_json"
            return $?
            ;;
        *) log_error "Failed to create configuration (HTTP $status_code; response body suppressed)"; return 1 ;;
    esac
}

# Keep an exact protected export before mutations; MarkLogic may redact secrets, so restore is manual.
backup_existing_configuration() {
    local endpoint="$1" response status_code body file
    # /properties?format=json returns the full JSON (the bare resource URL returns XML and omits oauth-server).
    if ! response=$(ml_api_request GET "$endpoint/properties?format=json" "$MARKLOGIC_USER" "$MARKLOGIC_PASS"); then
        log_error "Could not read existing configuration; refusing to mutate it"
        return 1
    fi
    status_code=$(ml_extract_status_code "$response")
    if [ "$status_code" != "200" ]; then
        log_error "Could not back up existing configuration (HTTP $status_code); refusing to mutate it"
        return 1
    fi
    body=$(ml_extract_response_body "$response")
    printf '%s' "$body" | jq empty >/dev/null 2>&1 || { log_error "Existing configuration response is not valid JSON"; return 1; }
    file=$(mktemp) || return 1
    chmod 600 "$file" || { rm -f "$file"; return 1; }
    printf '%s\n' "$body" > "$file" || { rm -f "$file"; return 1; }
    log_warning "Protected configuration export saved to $file; MarkLogic may redact secrets, so automatic rollback is unavailable"
}

resolve_oauth_client_secret() {
    [ -n "$CLIENT_SECRET" ] && return 0
    if [ ! -t 0 ]; then
        log_error "Set OAUTH_CLIENT_SECRET for non-interactive authorization-code configuration"
        return 1
    fi
    printf 'OAuth client secret: ' >&2
    IFS= read -r -s CLIENT_SECRET || return 1
    printf '\n' >&2
    [ -n "$CLIENT_SECRET" ] || { log_error "OAuth client secret cannot be empty"; return 1; }
}

# Update existing MarkLogic configuration
update_marklogic_config() {
    local config_json="$1" config_path endpoint
    config_path=$(oauth2_api_path_segment "$CONFIG_NAME") || { log_error "Invalid external-security name"; return 1; }
    endpoint="/manage/v2/external-security/$config_path"
    log_info "Updating existing MarkLogic configuration..."
    
    if [ "$DRY_RUN" = "true" ]; then
        log_info "[DRY-RUN] Would PUT OAuth configuration to $endpoint; no request body shown"
        return 0
    fi
    
    if ! ml_confirm "Replace existing external security '$CONFIG_NAME'? A protected export will be saved first." n; then
        log_warning "Update cancelled"
        return 1
    fi
    backup_existing_configuration "$endpoint" || return 1

    local response status_code
    # PUT is accepted on /properties only (the bare resource URL is 404 for PUT).
    if ! ml_api_call_with_dryrun response "PUT" "$endpoint/properties" "$MARKLOGIC_USER" "$MARKLOGIC_PASS" "$config_json"; then
        log_error "OAuth configuration update request failed"
        return 1
    fi
    status_code=$(ml_extract_status_code "$response")
    
    case "$status_code" in
        204|200) log_success "External security configuration updated successfully"; return 0 ;;
        *) log_error "Failed to update configuration (HTTP $status_code; response body suppressed)"; return 1 ;;
    esac
}

# Validate the created configuration
validate_configuration() {
    log_info "Validating MarkLogic OAuth2 configuration..."
    
    local config_path endpoint response status_code
    config_path=$(oauth2_api_path_segment "$CONFIG_NAME") || { log_error "Invalid external-security name"; return 1; }
    endpoint="/manage/v2/external-security/$config_path"
    if [ "$DRY_RUN" = "true" ]; then
        log_info "[DRY-RUN] Would GET the exact external-security resource; state remains unknown"
        return 0
    fi
    if ! response=$(ml_api_request GET "$endpoint" "$MARKLOGIC_USER" "$MARKLOGIC_PASS"); then
        log_error "Could not validate the external-security resource"
        return 1
    fi
    status_code=$(ml_extract_status_code "$response")
    
    case "$status_code" in
        200) log_success "Configuration validation successful"; return 0 ;;
        404) log_error "Configuration not found - creation may have failed"; return 1 ;;
        *) log_error "Failed to validate configuration (HTTP $status_code)"; return 1 ;;
    esac
}

# ================================================================
# MAIN SCRIPT LOGIC
# ================================================================

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --well-known-url)
                WELL_KNOWN_URL="$2"
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
            --config-name)
                CONFIG_NAME="$2"
                shift 2
                ;;
            --config-description)
                CONFIG_DESCRIPTION="$2"
                shift 2
                ;;
            --username-attribute)
                USERNAME_ATTRIBUTE="$2"
                shift 2
                ;;
            --role-attribute)
                ROLE_ATTRIBUTE="$2"
                shift 2
                ;;
            --privilege-attribute)
                PRIVILEGE_ATTRIBUTE="$2"
                shift 2
                ;;
            --cache-timeout)
                CACHE_TIMEOUT="$2"
                shift 2
                ;;
            --client-id)
                CLIENT_ID="$2"
                shift 2
                ;;
            --fetch-jwks-keys)
                FETCH_JWKS="true"
                shift
                ;;
            --oauth-flow-type)
                OAUTH_FLOW_TYPE="$2"
                shift 2
                ;;
            --redirect-uri)
                REDIRECT_URI="$2"
                shift 2
                ;;
            --authorization-server-uri)
                AUTHORIZATION_SERVER_URI="$2"
                shift 2
                ;;
            --token-server-uri)
                TOKEN_SERVER_URI_OVERRIDE="$2"
                shift 2
                ;;
            --jwt-issuer-uri)
                JWT_ISSUER_URI_OVERRIDE="$2"
                shift 2
                ;;
            --oauth-scope)
                OAUTH_SCOPE="$2"
                shift 2
                ;;
            --client-auth-method)
                CLIENT_AUTH_METHOD="$2"
                shift 2
                ;;
            --remove|--delete)
                REMOVE_CONFIG="true"
                shift
                ;;
            --force)
                FORCE_UPDATE="true"
                shift
                ;;
            --yes)
                YES="true"
                shift
                ;;
            --insecure)
                INSECURE="true"
                shift
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
                log_error "Unknown option"
                show_usage
                exit 1
                ;;
        esac
    done
    
    MARKLOGIC_USER="${MARKLOGIC_USER:-admin}"
    MARKLOGIC_PASS="${MARKLOGIC_PASS:-}"
}

# Remove external security configuration
remove_external_security_config() {
    local config_path endpoint response status_code
    config_path=$(oauth2_api_path_segment "$CONFIG_NAME") || { log_error "Invalid external-security name"; return 1; }
    endpoint="/manage/v2/external-security/$config_path"
    log_info "Removing external security configuration: $CONFIG_NAME"
    
    if [ "$DRY_RUN" = "true" ]; then
        log_info "[DRY-RUN] Would DELETE only the named external-security resource; remote state is unknown"
        return 0
    fi
    
    if ! ml_confirm "Permanently remove external security '$CONFIG_NAME'?" n; then
        log_warning "Removal cancelled"
        return 1
    fi
    backup_existing_configuration "$endpoint" || return 1

    if ! ml_api_call_with_dryrun response "DELETE" "$endpoint" "$MARKLOGIC_USER" "$MARKLOGIC_PASS"; then
        log_error "OAuth configuration removal request failed"
        return 1
    fi
    status_code=$(ml_extract_status_code "$response")

    
    case "$status_code" in
        204|200) log_success "External security configuration '$CONFIG_NAME' removed successfully"; return 0 ;;
        000) log_error "Connection failed to MarkLogic management API"; return 1 ;;
        401) log_error "Unauthorized - check MarkLogic credentials"; return 1 ;;
        403) log_error "MarkLogic user lacks permission to remove external security"; return 1 ;;
        404) log_error "External security configuration '$CONFIG_NAME' not found"; return 1 ;;
        500) log_error "MarkLogic refused (HTTP 500). The usual cause is SEC-EXTERNALSECURITYINUSE: an app server still uses '$CONFIG_NAME'. Run: configure-appserver-security.sh --appserver <name> --remove-security, then retry"; return 1 ;;
        *) log_error "Failed to remove configuration (HTTP $status_code; response body suppressed)"; return 1 ;;
    esac
}

# Main execution function
main() {
    log_info "=== MarkLogic OAuth2 Configuration Script ==="
    log_info "Version 1.0.0 - MLEAProxy Development Team"
    echo
    
    # Parse MarkLogic host early to show proper URL in logs
    parse_marklogic_host "$MARKLOGIC_HOST" || exit 1
    
    # Handle remove operation before requiring discovery inputs.
    if [ "$REMOVE_CONFIG" = "true" ]; then
        if [ "$CONFIG_NAME" = "OAuth2-Config" ]; then
            log_error "Configuration name is required for remove operation"
            log_error "Use --config-name to specify the configuration to remove"
            exit 1
        fi
        if [ "$DRY_RUN" = "true" ]; then
            log_info "[DRY-RUN] Would delete only external security '$CONFIG_NAME'; remote state and backup contents remain unknown"
            log_info "[DRY-RUN] No password prompt, request, temporary file, or local write"
            exit 0
        fi
        check_dependencies
        MARKLOGIC_PASS=$(ml_resolve_password) || exit 1
        test_marklogic_connection || exit 1
        remove_external_security_config
        exit $?
    fi
    
    # Validate required parameters for create/update
    if [ -z "$WELL_KNOWN_URL" ]; then
        log_error "OAuth2 .well-known URL is required"
        echo
        show_usage
        exit 1
    fi

    if [ "$OAUTH_FLOW_TYPE" != "resource-server" ] && [ "$OAUTH_FLOW_TYPE" != "authorization-code" ]; then
        log_error "Invalid --oauth-flow-type '$OAUTH_FLOW_TYPE' (expected 'resource-server' or 'authorization-code')"
        exit 1
    fi

    if [ "$OAUTH_FLOW_TYPE" = "authorization-code" ]; then
        if [ -z "$REDIRECT_URI" ]; then
            log_error "--redirect-uri is required when --oauth-flow-type authorization-code"
            log_error "This must be the MarkLogic app server's own URL, e.g. https://marklogic.example.com:8000"
            exit 1
        fi
        validate_url "$REDIRECT_URI" || exit 1
        if [[ ! "$REDIRECT_URI" =~ ^https:// ]]; then
            log_error "Authorization-code flow requires an HTTPS redirect URI"
            exit 1
        fi
    fi

    validate_url "$WELL_KNOWN_URL" || exit 1
    oauth2_api_path_segment "$CONFIG_NAME" >/dev/null || { log_error "Invalid external-security name"; exit 1; }
    [[ "$CACHE_TIMEOUT" =~ ^[0-9]+$ ]] || { log_error "Cache timeout must be a non-negative integer"; exit 1; }
    local display_host_url="$ML_DISPLAY_URL"

    if [ "$DRY_RUN" = "true" ]; then
        log_info "[DRY-RUN] Would fetch and validate OAuth discovery metadata, then create/update '$CONFIG_NAME'"
        [ "$FETCH_JWKS" != "true" ] || log_info "[DRY-RUN] Would fetch and validate the discovered JWKS inventory"
        log_info "[DRY-RUN] Remote discovery and MarkLogic state are unknown; no request or local file was created"
        exit 0
    fi
    
    # Check dependencies and resolve credentials only after dry-run has exited.
    check_dependencies
    MARKLOGIC_PASS=$(ml_resolve_password) || exit 1
    test_marklogic_connection || exit 1
    echo
    
    # Fetch and parse OAuth2 configuration
    local oauth_config
    oauth_config=$(fetch_oauth_config "$WELL_KNOWN_URL") || exit 1
    parse_oauth_config "$oauth_config"

    if [ "$OAUTH_FLOW_TYPE" = "authorization-code" ]; then
        if [ -z "$AUTHORIZATION_SERVER_URI" ]; then
            log_error "Could not determine the authorization endpoint from discovery, and --authorization-server-uri was not set"
            exit 1
        fi
        if [ -z "$TOKEN_SERVER_URI_OVERRIDE" ]; then
            log_error "Could not determine the token endpoint from discovery, and --token-server-uri was not set"
            exit 1
        fi
        if [ -z "$JWT_ISSUER_URI_OVERRIDE" ] || [ "$JWT_ISSUER_URI_OVERRIDE" = "unknown-issuer" ]; then
            log_error "Could not determine the token issuer URI from discovery; set --jwt-issuer-uri"
            exit 1
        fi
        validate_url "$AUTHORIZATION_SERVER_URI" || exit 1
        validate_url "$TOKEN_SERVER_URI_OVERRIDE" || exit 1
        validate_url "$JWT_ISSUER_URI_OVERRIDE" || exit 1
        log_info "Authorization-code endpoints and issuer validated"
    fi
    echo
    
    # Validate the provider key set before applying configuration when requested.
    if [ "$FETCH_JWKS" = "true" ]; then
        fetch_jwks_keys "$JWKS_URI" >/dev/null || exit 1
    fi
    echo
    
    # Keep credentials out of argv and delay prompting until all remote inputs validated.
    if [ "$OAUTH_FLOW_TYPE" = "authorization-code" ]; then
        resolve_oauth_client_secret || exit 1
    fi

    # Create and apply MarkLogic configuration
    local ml_config
    ml_config=$(create_external_security_config) || exit 1
    CLIENT_SECRET=""
    apply_marklogic_config "$ml_config" || exit 1
    ml_config=""
    echo
    
    # Validate configuration
    if [ "$DRY_RUN" != "true" ]; then
        validate_configuration || exit 1
        echo
    fi
    
    # Summary
    log_success "=== Configuration Complete ==="
    log_info "External Security Name: $CONFIG_NAME"
    log_info "OAuth Flow Type: $OAUTH_FLOW_TYPE"
    log_info "OAuth Issuer: $ISSUER"
    log_info "JWKS URI: ${JWKS_URI:-Not configured}"
    log_info "MarkLogic Host: $display_host_url"
    
    if [ "$DRY_RUN" = "true" ]; then
        log_warning "This was a DRY RUN - no changes were made"
    fi

    if [ "$OAUTH_FLOW_TYPE" = "authorization-code" ]; then
        echo
        log_warning "Authorization Code flow reminders:"
        log_warning "  - The app server bound to this config must have SSL enabled (a certificate"
        log_warning "    template assigned) - MarkLogic requires TLS for this flow"
        log_warning "  - Register '$REDIRECT_URI' as an exact redirect URI on your IdP client/provider"
        log_warning "  - Ensure the IdP client's allowed grant types include 'authorization_code'"
        log_warning "    (some IdPs, e.g. Authentik, default this to empty, which fails silently)"
    fi
    
    echo
    log_info "Next steps:"
    log_info "1. Configure app servers to use external security: $CONFIG_NAME"
    echo
    log_info "   To configure app servers, run:"
    if [ "$MARKLOGIC_HOST_ONLY" != "oauth.warnesnet.com" ]; then
        log_info "   ./scripts/configure-appserver-security.sh --appserver <SERVER_NAME> --external-security $CONFIG_NAME --marklogic-host $display_host_url"
    else
        log_info "   ./scripts/configure-appserver-security.sh --appserver <SERVER_NAME> --external-security $CONFIG_NAME"
    fi
    echo
    log_info "   Examples:"
    if [ "$MARKLOGIC_HOST_ONLY" != "oauth.warnesnet.com" ]; then
        log_info "   ./scripts/configure-appserver-security.sh --appserver App-Services --external-security $CONFIG_NAME --marklogic-host $display_host_url"
        log_info "   ./scripts/configure-appserver-security.sh --appserver Manage --external-security $CONFIG_NAME --marklogic-host $display_host_url --dry-run"
    else
        log_info "   ./scripts/configure-appserver-security.sh --appserver App-Services --external-security $CONFIG_NAME"
        log_info "   ./scripts/configure-appserver-security.sh --appserver Manage --external-security $CONFIG_NAME --dry-run"
    fi
    echo
    log_info "2. Test the OAuth2 configuration:"
    if [ "$MARKLOGIC_HOST_ONLY" != "oauth.warnesnet.com" ]; then
        log_info "   ./scripts/validate-oauth2-config.sh --well-known-url $WELL_KNOWN_URL --config-name $CONFIG_NAME --marklogic-host $display_host_url"
    else
        log_info "   ./scripts/validate-oauth2-config.sh --well-known-url $WELL_KNOWN_URL --config-name $CONFIG_NAME"
    fi
    echo
    log_info "3. Verify role mapping and user permissions"

}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    parse_arguments "$@"
    main
fi