#!/bin/bash

# ================================================================
# OAuth2 Configuration Validation Script
# ================================================================
#
# This script validates OAuth2 configurations for MarkLogic
# and provides comprehensive testing of the authentication flow.
#
# Features:
# - Validate OAuth2 discovery endpoints
# - Test token generation and validation
# - Verify MarkLogic external security configuration
# - End-to-end authentication flow testing
# - Performance and reliability testing
#
# Author: Martin Warnes
# Version: 1.0.3
# Date: October 2025
#
# ================================================================

set -euo pipefail

# Load utility functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/oauth2-utils.sh"

# ================================================================
# CONFIGURATION
# ================================================================

# Default values
WELL_KNOWN_URL=""
MARKLOGIC_HOST="${MARKLOGIC_HOST:-localhost}"
MARKLOGIC_MANAGE_PORT="${MARKLOGIC_PORT:-8002}"
MARKLOGIC_USER="${MARKLOGIC_USER:-admin}"
MARKLOGIC_PASS="${MARKLOGIC_PASS:-}"
APP_SERVER=""
CLIENT_ID="${OAUTH_CLIENT_ID:-marklogic-oauth}"
CLIENT_SECRET="${OAUTH_CLIENT_SECRET:-}"
TEST_USERNAME="${OAUTH_TEST_USERNAME:-}"
TEST_PASSWORD="${OAUTH_TEST_PASSWORD:-}"
API_ENDPOINT_URL=""
VERBOSE="false"
PERFORMANCE_TEST="false"  
DETAILED_OUTPUT="false"
DECODE_TOKENS="false"
INSECURE="false"
DRY_RUN="false"

# Test results tracking
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
WARNINGS=0

# ================================================================
# UTILITY FUNCTIONS  
# ================================================================

# Reuse the shared parser; insecure TLS is never enabled implicitly.
parse_marklogic_host() {
    local host_url="$1" authority
    case "$host_url" in http://*|https://*) ;; *) host_url="http://$host_url" ;; esac
    oauth2_validate_url "$host_url" || return 1
    authority="${host_url#*://}"
    case "$authority" in */) host_url="${host_url%/}" ;; */*) oauth2_log_error "MarkLogic host must not include a path"; return 1 ;; esac
    MARKLOGIC_PORT="$MARKLOGIC_MANAGE_PORT"
    ml_parse_host_url "$host_url" || return 1
    [[ -n "$ML_HOST" && "$ML_HOST" =~ ^[A-Za-z0-9.-]+$ ]] || { oauth2_log_error "Invalid MarkLogic host"; return 1; }
    [[ "$ML_PORT" =~ ^[0-9]{1,5}$ ]] && [ "$ML_PORT" -ge 1 ] && [ "$ML_PORT" -le 65535 ] || { oauth2_log_error "Invalid MarkLogic management port"; return 1; }
    MARKLOGIC_PROTOCOL="$ML_PROTOCOL"
    MARKLOGIC_HOST_ONLY="$ML_HOST"
    MARKLOGIC_PORT_FROM_URL="$ML_PORT"
    MARKLOGIC_IS_HTTPS="$ML_IS_HTTPS"
    MARKLOGIC_MANAGE_PORT="$ML_PORT"
}

# Get curl flags for SSL handling
get_curl_flags() {
    if [ "$INSECURE" = "true" ]; then
        oauth2_log_warning "TLS certificate verification disabled by explicit --insecure option"
        printf '%s\n' --insecure
    fi
}

# Decode and display token information
decode_and_display_token() {
    local token="$1"
    local token_type="${2:-Access Token}"
    
    if [ -z "$token" ]; then
        oauth2_log_warning "No token provided for decoding"
        return 1
    fi
    
    # Skip decoding if disabled
    if [ "$DECODE_TOKENS" != "true" ]; then
        oauth2_log_info "$token_type received (decoding disabled)"
        return 0
    fi
    
    oauth2_log_info "=== $token_type Details ==="
    
    # Validate JWT structure
    if ! oauth2_validate_jwt "$token"; then
        oauth2_log_error "Invalid JWT structure"
        return 1
    fi
    
    # Decode header and payload
    local header payload
    header=$(oauth2_jwt_decode_header "$token")
    payload=$(oauth2_jwt_decode_payload "$token")
    
    if [ -z "$header" ] || [ -z "$payload" ]; then
        oauth2_log_error "Failed to decode JWT"
        return 1
    fi
    
    # Display header information
    oauth2_log_info "📋 JWT Header:"
    local alg typ kid
    alg=$(echo "$header" | jq -r '.alg // "unknown"')
    typ=$(echo "$header" | jq -r '.typ // "unknown"')
    kid=$(echo "$header" | jq -r '.kid // "unknown"')
    
    oauth2_log_info "  • Algorithm: $alg"
    oauth2_log_info "  • Type: $typ"
    if [ "$kid" != "unknown" ]; then
        oauth2_log_info "  • Key ID: $kid"
    fi
    
    # Display payload information
    oauth2_log_info "📋 JWT Payload:"
    local iss sub aud exp iat nbf jti scope client_id username preferred_username email realm_access resource_access roles
    iss=$(echo "$payload" | jq -r '.iss // "unknown"')
    sub=$(echo "$payload" | jq -r '.sub // "unknown"')
    aud=$(echo "$payload" | jq -r '.aud // "unknown"')
    exp=$(echo "$payload" | jq -r '.exp // "unknown"')
    iat=$(echo "$payload" | jq -r '.iat // "unknown"')
    nbf=$(echo "$payload" | jq -r '.nbf // "unknown"')
    jti=$(echo "$payload" | jq -r '.jti // "unknown"')
    scope=$(echo "$payload" | jq -r '.scope // "unknown"')
    client_id=$(echo "$payload" | jq -r '.client_id // .clientId // "unknown"')
    username=$(echo "$payload" | jq -r '.username // "unknown"')
    preferred_username=$(echo "$payload" | jq -r '.preferred_username // "unknown"')
    email=$(echo "$payload" | jq -r '.email // "unknown"')
    realm_access=$(echo "$payload" | jq -r '.realm_access.roles // empty' 2>/dev/null)
    resource_access=$(echo "$payload" | jq -r '.resource_access // empty' 2>/dev/null)
    roles=$(echo "$payload" | jq -r '.roles // empty' 2>/dev/null)
    marklogic_roles=$(echo "$payload" | jq -r '."marklogic-roles" // empty' 2>/dev/null)
    
    oauth2_log_info "  • Issuer: $iss"
    oauth2_log_info "  • Subject: $sub"
    oauth2_log_info "  • Audience: $aud"
    
    if [ "$client_id" != "unknown" ]; then
        oauth2_log_info "  • Client ID: $client_id"
    fi
    
    if [ "$scope" != "unknown" ]; then
        oauth2_log_info "  • Scope: $scope"
    fi
    
    if [ "$username" != "unknown" ]; then
        oauth2_log_info "  • Username: $username"
    fi
    
    if [ "$preferred_username" != "unknown" ]; then
        oauth2_log_info "  • Preferred Username: $preferred_username"
    fi
    
    if [ "$email" != "unknown" ]; then
        oauth2_log_info "  • Email: $email"
    fi
    
    if [ "$jti" != "unknown" ]; then
        oauth2_log_info "  • JWT ID: $jti"
    fi
    
    # Display role information
    if [ -n "$realm_access" ]; then
        oauth2_log_info "🔐 Realm Roles:"
        echo "$realm_access" | jq -r '.[]' 2>/dev/null | sed 's/^/    • /' || oauth2_log_info "    • None"
    fi
    
    if [ -n "$resource_access" ]; then
        oauth2_log_info "🔐 Resource Roles:"
        echo "$resource_access" | jq -r 'to_entries[] | "  \(.key): \(.value.roles | join(", "))"' 2>/dev/null | sed 's/^/    • /' || oauth2_log_info "    • None"
    fi
    
    if [ -n "$marklogic_roles" ]; then
        oauth2_log_info "🔐 MarkLogic Roles:"
        echo "$marklogic_roles" | jq -r '.[]' 2>/dev/null | sed 's/^/    • /' || oauth2_log_info "    • None"
    elif [ -n "$roles" ]; then
        oauth2_log_info "🔐 Custom Roles:"
        echo "$roles" | jq -r '.[]' 2>/dev/null | sed 's/^/    • /' || oauth2_log_info "    • None"
    fi
    
    # Display time-related claims
    oauth2_log_info "📅 Time Claims:"
    local current_time
    current_time=$(date +%s)
    
    if [ "$iat" != "unknown" ]; then
        local iat_date
        iat_date=$(date -r "$iat" 2>/dev/null || echo "invalid")
        oauth2_log_info "  • Issued At: $iat_date ($iat)"
    fi
    
    if [ "$nbf" != "unknown" ]; then
        local nbf_date
        nbf_date=$(date -r "$nbf" 2>/dev/null || echo "invalid")
        oauth2_log_info "  • Not Before: $nbf_date ($nbf)"
    fi
    
    if [ "$exp" != "unknown" ]; then
        local exp_date time_to_expiry
        exp_date=$(date -r "$exp" 2>/dev/null || echo "invalid")
        time_to_expiry=$((exp - current_time))
        
        oauth2_log_info "  • Expires At: $exp_date ($exp)"
        
        if [ $time_to_expiry -lt 0 ]; then
            oauth2_log_warning "  • Status: EXPIRED ($((-time_to_expiry)) seconds ago)"
        else
            oauth2_log_info "  • Status: Valid (expires in $(oauth2_seconds_to_human "$time_to_expiry"))"
        fi
    fi
    
    # Display custom claims if verbose mode
    if [ "$VERBOSE" = "true" ]; then
        oauth2_log_info "📋 All Claims:"
        echo "$payload" | jq . | sed 's/^/    /'
    fi
    
    echo
}

# ================================================================
# LOGGING AND REPORTING
# ================================================================

log_test_start() {
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    oauth2_log_info "🧪 TEST $TOTAL_TESTS: $1"
}

log_test_pass() {
    PASSED_TESTS=$((PASSED_TESTS + 1))
    oauth2_log_success "✅ PASS: $1"
}

log_test_fail() {
    FAILED_TESTS=$((FAILED_TESTS + 1))
    oauth2_log_error "❌ FAIL: $1"
}

log_test_warning() {
    WARNINGS=$((WARNINGS + 1))
    oauth2_log_warning "⚠️  WARNING: $1"
}

show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Validates OAuth2 configuration for MarkLogic integration.

OPTIONS:
    --well-known-url URL          OAuth2 .well-known discovery endpoint URL (required)
    --marklogic-host URL          MarkLogic host URL (default: localhost)
    --marklogic-manage-port PORT  MarkLogic manage port (default: 8002)
    --marklogic-user USER         MarkLogic admin user (default: admin)
    --marklogic-pass PASS         Rejected; use MARKLOGIC_PASS or a hidden prompt
    --app-server NAME             App server name to test OAuth against (required)
    --client-id ID                OAuth client ID (default: marklogic)
    --client-secret SECRET        Rejected; use OAUTH_CLIENT_SECRET
    --test-username USER          Optional username for password-grant test
    --test-password PASS          Rejected; use OAUTH_TEST_PASSWORD or a hidden prompt
    --api-endpoint-url URL        Custom API endpoint URL for authentication testing
    --performance                 Run performance tests
    --detailed                    Show detailed test output
    --decode-tokens               Explicitly display token claims (default: disabled)
    --no-decode-tokens            Skip token decoding and display
    --dry-run                     Preview checks without network requests
    --verbose                     Enable verbose logging
    --insecure                    Explicitly disable TLS verification (discouraged)
    --help                        Show this help message

EXAMPLES:
    # Validate OAuth-configured app server
    $0 --well-known-url http://localhost:8080/oauth/.well-known/config --app-server Manage2

    # Validate production OAuth2 setup
    $0 --well-known-url https://auth.example.com/.well-known/openid_configuration \\
       --app-server ProductionApp \\
       --marklogic-host production.marklogic.com \\
       --performance --detailed

ENVIRONMENT VARIABLES:
    OAUTH2_DEBUG                  Enable debug logging
    MARKLOGIC_HOST               Override MarkLogic host
    MARKLOGIC_USER               Override MarkLogic user
    MARKLOGIC_PASS               MarkLogic password for unattended use
    OAUTH_CLIENT_SECRET          OAuth client secret for unattended use
    OAUTH_TEST_PASSWORD          Test-user password for unattended use

EOF
}

# ================================================================
# VALIDATION TESTS
# ================================================================

# Test 1: OAuth2 Server Connectivity
test_oauth_server_connectivity() {
    log_test_start "OAuth2 Server Connectivity"
    
    # Extract server info from well-known URL
    local server_host server_port
    server_host=$(echo "$WELL_KNOWN_URL" | sed 's#.*://##' | cut -d: -f1 | cut -d/ -f1)
    server_port=$(echo "$WELL_KNOWN_URL" | sed 's#.*://##' | cut -d: -f2 | cut -d/ -f1)
    
    # If no port specified, use default (80 for HTTP, 443 for HTTPS)
    if [ "$server_port" = "$server_host" ]; then
        if [[ "$WELL_KNOWN_URL" =~ ^https:// ]]; then
            server_port="443"
        else
            server_port="80"
        fi
    fi
    
    # Test basic connectivity
    if oauth2_check_port "$server_host" "$server_port"; then
        log_test_pass "OAuth2 server is reachable ($server_host:$server_port)"
    else
        log_test_fail "OAuth2 server is not reachable ($server_host:$server_port)"
        return 1
    fi
    
    # Test well-known endpoint directly
    local response
    if response=$(oauth2_http_get "$WELL_KNOWN_URL" 10 "" "$(get_curl_flags)"); then
        log_test_pass "OAuth2 well-known endpoint responds"
    else
        log_test_fail "OAuth2 well-known endpoint does not respond"
        return 1
    fi
}

# Test 2: OAuth2 Discovery Endpoint
test_oauth_discovery_endpoints() {
    log_test_start "OAuth2 Discovery Endpoint"
    
    # Test the explicitly provided discovery endpoint without logging its URL or body.
    oauth2_log_info "Testing configured OAuth2 discovery endpoint"
    
    if config=$(oauth2_http_get "$WELL_KNOWN_URL" 10 "" "$(get_curl_flags)"); then
        # Validate it's valid JSON
        if echo "$config" | jq . >/dev/null 2>&1; then
            log_test_pass "OAuth2 configuration retrieved successfully"
            
            # Validate configuration structure
            local issuer token_endpoint jwks_uri
            issuer=$(echo "$config" | jq -r '.issuer // empty')
            token_endpoint=$(echo "$config" | jq -r '.token_endpoint // empty')
            jwks_uri=$(echo "$config" | jq -r '.jwks_uri // empty')
            
            [ -z "$issuer" ] || oauth2_validate_url "$issuer" || { log_test_fail "Invalid issuer URL in discovery"; return 1; }
            [ -z "$token_endpoint" ] || oauth2_validate_url "$token_endpoint" || { log_test_fail "Invalid token endpoint URL in discovery"; return 1; }
            [ -z "$jwks_uri" ] || oauth2_validate_url "$jwks_uri" || { log_test_fail "Invalid JWKS URI in discovery"; return 1; }
            oauth2_log_info "Discovery issuer and endpoint fields parsed"
            
            # Store for later tests
            export OAUTH_CONFIG="$config"
            export OAUTH_ISSUER="$issuer"
            export OAUTH_TOKEN_ENDPOINT="$token_endpoint"
            export OAUTH_JWKS_URI="$jwks_uri"
        else
            log_test_fail "OAuth2 endpoint returned invalid JSON"
            return 1
        fi
    else
        log_test_fail "Failed to retrieve OAuth2 configuration from the configured discovery endpoint"
        return 1
    fi
    
    # Test JWKS endpoint if available
    if [ -n "$OAUTH_JWKS_URI" ]; then
        oauth2_log_info "Testing JWKS endpoint..."
        
        if jwks=$(oauth2_fetch_jwks "$OAUTH_JWKS_URI" "$(get_curl_flags)"); then
            log_test_pass "JWKS endpoint is accessible"
            
            local key_count
            key_count=$(oauth2_jwks_key_count "$jwks")
            oauth2_log_info "JWKS contains $key_count keys"
            
            # List key IDs
            if [ "$VERBOSE" = "true" ]; then
                oauth2_log_info "Key IDs:"
                oauth2_jwks_list_key_ids "$jwks"
            fi
            
            export OAUTH_JWKS="$jwks"
        else
            log_test_warning "JWKS endpoint is not accessible"
        fi
    fi
}

# Test 3: Token Generation
# Secrets are read only from the environment or hidden prompts, never value-taking CLI flags.
test_token_generation() {
    log_test_start "OAuth2 Token Generation"
    if [ -z "$OAUTH_TOKEN_ENDPOINT" ]; then
        log_test_fail "No token endpoint available for testing"
        return 1
    fi
    local token_flags=""
    [ "$INSECURE" != "true" ] || token_flags="--insecure"

    if [ -z "$CLIENT_SECRET" ] && [ -t 0 ]; then
        printf 'OAuth client secret (press Enter to skip client-credentials test): ' >&2
        IFS= read -r -s CLIENT_SECRET || return 1
        printf '\n' >&2
    fi
    if [ -n "$CLIENT_SECRET" ]; then
        if access_token=$(oauth2_get_token_client_credentials "$OAUTH_TOKEN_ENDPOINT" "$CLIENT_ID" "$CLIENT_SECRET" "openid" "$token_flags"); then
            log_test_pass "Client credentials flow successful"
            if oauth2_validate_jwt "$access_token"; then
                log_test_pass "Generated token has valid JWT structure"
                decode_and_display_token "$access_token" "Client Credentials Token"
                export TEST_ACCESS_TOKEN="$access_token"
            else
                log_test_fail "Generated token has invalid JWT structure"
            fi
        else
            log_test_fail "Client credentials flow failed"
        fi
    else
        log_test_warning "Client-credentials test skipped; set OAUTH_CLIENT_SECRET to enable it"
    fi

    if [ -z "$TEST_USERNAME" ]; then
        oauth2_log_info "Password-grant test skipped; set OAUTH_TEST_USERNAME to enable it"
        return 0
    fi
    if [ -z "$TEST_PASSWORD" ] && [ -t 0 ]; then
        printf 'Password-grant test password: ' >&2
        IFS= read -r -s TEST_PASSWORD || return 1
        printf '\n' >&2
    fi
    if [ -z "$TEST_PASSWORD" ]; then
        log_test_warning "Password-grant test skipped; set OAUTH_TEST_PASSWORD to enable it"
        return 0
    fi
    if password_token=$(oauth2_get_token_password "$OAUTH_TOKEN_ENDPOINT" "$TEST_USERNAME" "$TEST_PASSWORD" "$CLIENT_ID" "$CLIENT_SECRET" "openid" "$token_flags"); then
        log_test_pass "Password flow successful"
        decode_and_display_token "$password_token" "Password Grant Token"
        export TEST_PASSWORD_TOKEN="$password_token"
    else
        log_test_warning "Password-grant test failed; provider details and credentials were suppressed"
    fi
}

# Test 4: MarkLogic Configuration
test_marklogic_configuration() {
    log_test_start "MarkLogic Configuration"
    
    if [ -z "$APP_SERVER" ]; then
        log_test_fail "No app server provided for MarkLogic testing"
        return 1
    fi
    
    # MarkLogic host already parsed in main()
    # Test MarkLogic connectivity
    oauth2_log_info "Testing MarkLogic connectivity..."
    
    local manage_port_reachable=false
    if oauth2_check_port "$MARKLOGIC_HOST_ONLY" "$MARKLOGIC_MANAGE_PORT"; then
        log_test_pass "MarkLogic manage port is reachable"
        manage_port_reachable=true
    else
        log_test_warning "MarkLogic manage port is not reachable - some tests will be limited"
        log_test_warning "This may be expected in environments where manage port is not accessible"
    fi
    
    # Initialize MARKLOGIC_API_PORT (will be set from app server config or default)
    MARKLOGIC_API_PORT=""
    
    # Only try to get app server configuration if manage port is reachable
    if [ "$manage_port_reachable" = "true" ]; then
        # Get app server configuration to determine port and authentication settings
        oauth2_log_info "Getting app server configuration to determine port..."
        
        # First check if app server exists
        local app_server_path server_response
        app_server_path=$(oauth2_api_path_segment "$APP_SERVER") || { log_test_fail "Invalid app-server name"; return 1; }
        
        if server_response=$(ml_api_request GET "/manage/v2/servers/$app_server_path?group-id=Default" "$MARKLOGIC_USER" "$MARKLOGIC_PASS") && [ "$(ml_extract_status_code "$server_response")" = "200" ]; then
        log_test_pass "App server '$APP_SERVER' exists"
        
        # Get detailed properties to find port and authentication settings
        local properties_response
        
        if properties_response=$(ml_api_request GET "/manage/v2/servers/$app_server_path/properties?group-id=Default" "$MARKLOGIC_USER" "$MARKLOGIC_PASS") && [ "$(ml_extract_status_code "$properties_response")" = "200" ]; then
            properties_response=$(ml_extract_response_body "$properties_response")
            # Get the actual port from the properties
            MARKLOGIC_API_PORT=$(echo "$properties_response" | jq -r '.port // "unknown"')
            
            if [ "$MARKLOGIC_API_PORT" != "unknown" ] && [ "$MARKLOGIC_API_PORT" != "null" ]; then
                oauth2_log_info "App server port: $MARKLOGIC_API_PORT"
                export MARKLOGIC_API_PORT
            else
                log_test_fail "Could not determine app server port from configuration"
                return 1
            fi
                
                # Check if OAuth is configured
                local auth_method external_auth
                auth_method=$(echo "$properties_response" | jq -r '.authentication // "unknown"')
                external_auth=$(echo "$properties_response" | jq -r '.["external-security"] // "none"')
                
                oauth2_log_info "App server authentication: $auth_method"
                oauth2_log_info "External security: $external_auth"
                
                if [ "$auth_method" = "oauth" ] || ([ "$auth_method" = "application-level" ] && [ "$external_auth" != "none" ]); then
                    log_test_pass "App server is configured for OAuth authentication"
                    
                    # Extract external security configuration name from app server config
                    if [ "$external_auth" != "none" ] && [ "$external_auth" != "null" ]; then
                        local config_name
                        config_name=$(echo "$external_auth" | jq -r '.[0] // empty' 2>/dev/null || echo "$external_auth")
                        if [ -n "$config_name" ] && [ "$config_name" != "null" ]; then
                            oauth2_log_info "External security configuration: $config_name"
                            
                            # Test the external security configuration
                            oauth2_log_info "Testing external security configuration..."
                            
                            if oauth2_test_marklogic_config "$MARKLOGIC_HOST" "$MARKLOGIC_MANAGE_PORT" "$config_name" "$MARKLOGIC_USER" "$MARKLOGIC_PASS"; then
                                log_test_pass "MarkLogic external security configuration exists"
                                
                                # Get configuration details
                                local config_path config_response
                                config_path=$(oauth2_api_path_segment "$config_name") || { log_test_fail "Invalid external-security name"; return 1; }
                                
                                if config_response=$(ml_api_request GET "/manage/v2/external-security/$config_path" "$MARKLOGIC_USER" "$MARKLOGIC_PASS") && [ "$(ml_extract_status_code "$config_response")" = "200" ]; then
                                    config_response=$(ml_extract_response_body "$config_response")
                                    local ext_auth_method cache_timeout
                                    ext_auth_method=$(echo "$config_response" | jq -r '.["external-security-config"] | .authentication // "unknown"')
                                    cache_timeout=$(echo "$config_response" | jq -r '.["external-security-config"] | .["cache-timeout"] // "unknown"')
                                    
                                    oauth2_log_info "Authentication method: $ext_auth_method"
                                    oauth2_log_info "Cache timeout: $cache_timeout seconds"
                                    
                                    [ "$DETAILED_OUTPUT" != "true" ] || oauth2_log_info "External-security payload omitted to avoid exposing provider settings"
                                fi
                            else
                                log_test_fail "MarkLogic external security configuration not accessible"
                            fi
                        fi
                    fi
                elif [ "$auth_method" = "application-level" ]; then
                    log_test_warning "App server uses application-level auth but no external security configured"
                else
                    log_test_warning "App server may not be properly configured for OAuth (auth: $auth_method, external: $external_auth)"
                fi
                
                [ "$DETAILED_OUTPUT" != "true" ] || oauth2_log_info "Full app-server properties omitted to avoid exposing configuration details"
            else
                log_test_fail "Could not retrieve app server properties"
                return 1
            fi
        else
            log_test_fail "App server '$APP_SERVER' not accessible"
            return 1
        fi
    else
        # Manage port not reachable - use default port for testing
        log_test_warning "Manage port not accessible - using default app server port for testing"
        
        # Try common MarkLogic app server ports
        local default_ports=("8000" "8080" "8010" "8020")
        local port_found=false
        
        for port in "${default_ports[@]}"; do
            if oauth2_check_port "$MARKLOGIC_HOST_ONLY" "$port"; then
                MARKLOGIC_API_PORT="$port"
                oauth2_log_info "Found accessible port: $port (assuming this is the OAuth-configured app server)"
                export MARKLOGIC_API_PORT
                port_found=true
                break
            fi
        done
        
        if [ "$port_found" = "false" ]; then
            log_test_warning "No common app server ports are reachable - end-to-end testing may not work"
            MARKLOGIC_API_PORT="8000"  # Default fallback
            export MARKLOGIC_API_PORT
        fi
    fi
    
    # Test MarkLogic OAuth-configured app server port
    oauth2_log_info "Testing MarkLogic OAuth app server port..."
    
    if oauth2_check_port "$MARKLOGIC_HOST_ONLY" "$MARKLOGIC_API_PORT"; then
        log_test_pass "MarkLogic OAuth app server port is reachable (port $MARKLOGIC_API_PORT)"
    else
        log_test_warning "MarkLogic OAuth app server port is not reachable (may affect token testing)"
    fi
}

# Test a custom endpoint using a protected Authorization header; omit response bodies.
test_custom_api_endpoint() {
    local token="$1" endpoint_url="$2"
    [ -n "$endpoint_url" ] || return 1
    oauth2_log_info "Testing configured custom API endpoint"
    oauth2_test_token_against_marklogic "$token" "$MARKLOGIC_HOST_ONLY" "${MARKLOGIC_API_PORT:-8000}" "/" "$endpoint_url"
}

# Test 5: End-to-End Token Validation
test_end_to_end_validation() {
    log_test_start "End-to-End Token Validation"
    
    # Test password flow token first (preferred for end-to-end testing)
    if [ -n "${TEST_PASSWORD_TOKEN:-}" ]; then
        oauth2_log_info "Testing password-flow token against MarkLogic; token claims are omitted"
        local result
        if oauth2_test_token_against_marklogic "$TEST_PASSWORD_TOKEN" "$MARKLOGIC_HOST_ONLY" "$MARKLOGIC_API_PORT" "/" ""; then
            result=0
        else
            result=$?
        fi
        
        case $result in
            0)
                log_test_pass "Password flow token validated successfully by MarkLogic"
                ;;
            1)
                log_test_fail "Password flow token rejected by MarkLogic - check external security configuration"
                ;;
            2)
                log_test_pass "OAuth integration working - password token accepted by MarkLogic!"
                log_test_warning "User authentication succeeded but lacks sufficient permissions (HTTP 403)"
                oauth2_log_info "✅ This confirms OAuth2 external security is working correctly"
                oauth2_log_info "💡 To fix permissions: assign the required roles to the test user in MarkLogic"
                ;;
            3)
                log_test_warning "Unexpected response from MarkLogic API with password flow token"
                ;;
        esac
        
        # Test custom API endpoint if provided
        if [ -n "$API_ENDPOINT_URL" ]; then
            oauth2_log_info ""
            oauth2_log_info "🔗 Testing custom API endpoint with password flow token..."
            
            local api_result
            if test_custom_api_endpoint "$TEST_PASSWORD_TOKEN" "$API_ENDPOINT_URL"; then api_result=0; else api_result=$?; fi
            
            case $api_result in
                0)
                    log_test_pass "Custom API endpoint test successful with password flow token"
                    ;;
                1)
                    log_test_fail "Custom API endpoint rejected password flow token"
                    ;;
                2)
                    log_test_pass "Custom API endpoint accepted password flow token but access denied"
                    oauth2_log_info "✅ This confirms OAuth2 authentication is working for the custom endpoint"
                    ;;
                3)
                    log_test_warning "Custom API endpoint returned unexpected response"
                    ;;
            esac
        fi
    else
        oauth2_log_warning "No password flow token available - falling back to client credentials token"
        
        # Test client credentials token against MarkLogic API as fallback
        if [ -n "${TEST_ACCESS_TOKEN:-}" ]; then
            oauth2_log_info "🎯 Testing with client credentials token (service account)"
            
            oauth2_log_info "Testing client-credentials token; token claims are omitted"
            
            local result
            if oauth2_test_token_against_marklogic "$TEST_ACCESS_TOKEN" "$MARKLOGIC_HOST_ONLY" "$MARKLOGIC_API_PORT" "/" ""; then result=0; else result=$?; fi
            
            case $result in
                0)
                    log_test_pass "Client credentials token validated successfully by MarkLogic"
                    oauth2_log_info "ℹ️  Note: This validates OAuth integration but not user-specific authentication"
                    ;;
                1)
                    log_test_fail "Client credentials token rejected by MarkLogic - check external security configuration"
                    ;;
                2)
                    log_test_pass "OAuth integration working - token accepted by MarkLogic!"
                    log_test_warning "Service account authenticated but lacks sufficient permissions (HTTP 403)"
                    oauth2_log_info "✅ This confirms OAuth2 external security is working correctly"
                    oauth2_log_info "💡 To fix permissions: assign roles to the service account in MarkLogic"
                    ;;
                3)
                    log_test_warning "Unexpected response from MarkLogic API with client credentials token"
                    ;;
            esac
            
            # Test custom API endpoint if provided
            if [ -n "$API_ENDPOINT_URL" ]; then
                oauth2_log_info ""
                oauth2_log_info "🔗 Testing custom API endpoint with client credentials token..."
                
                local api_result
                if test_custom_api_endpoint "$TEST_ACCESS_TOKEN" "$API_ENDPOINT_URL"; then api_result=0; else api_result=$?; fi
                
                case $api_result in
                    0)
                        log_test_pass "Custom API endpoint test successful with client credentials token"
                        ;;
                    1)
                        log_test_fail "Custom API endpoint rejected client credentials token"
                        ;;
                    2)
                        log_test_pass "Custom API endpoint accepted client credentials token but access denied"
                        oauth2_log_info "✅ This confirms OAuth2 authentication is working for the custom endpoint"
                        ;;
                    3)
                        log_test_warning "Custom API endpoint returned unexpected response"
                        ;;
                esac
            fi
        else
            log_test_fail "No tokens available for end-to-end testing"
            log_test_fail "Both password flow and client credentials flow failed"
            return 1
        fi
    fi
    
    # Test different API endpoints with password flow token
    if [ "$PERFORMANCE_TEST" = "true" ]; then
        if [ -n "${TEST_PASSWORD_TOKEN:-}" ]; then
            oauth2_log_info "Testing multiple endpoints on OAuth-configured app server with password flow token..."
            
            local endpoints=("/" "/error-handler.xqy" "/rewriter.xml")
            local successful_endpoints=0
            
            for endpoint in "${endpoints[@]}"; do
                if oauth2_test_token_against_marklogic "$TEST_PASSWORD_TOKEN" "$MARKLOGIC_HOST_ONLY" "$MARKLOGIC_API_PORT" "$endpoint" "" >/dev/null 2>&1; then
                    successful_endpoints=$((successful_endpoints + 1))
                fi
            done
            
            oauth2_log_info "Password flow token worked with $successful_endpoints/${#endpoints[@]} endpoints"
        else
            oauth2_log_info "Skipping endpoint testing - no password flow token available"
        fi
    fi
}

# Test 6: Performance Testing
test_performance() {
    if [ "$PERFORMANCE_TEST" != "true" ]; then
        return 0
    fi
    
    log_test_start "Performance Testing"
    if [ -z "$CLIENT_SECRET" ]; then
        log_test_warning "Performance token test skipped; configure OAUTH_CLIENT_SECRET"
        return 0
    fi
    
    # Test token generation performance
    oauth2_log_info "Testing token generation performance..."
    
    local iterations=10
    local start_time end_time total_time
    start_time=$(date +%s.%N)
    
    local perf_token_flags=""
    if [ "$INSECURE" = "true" ]; then
        perf_token_flags="--insecure"
    fi
    
    for ((i=1; i<=iterations; i++)); do
        oauth2_get_token_client_credentials "$OAUTH_TOKEN_ENDPOINT" "$CLIENT_ID" "$CLIENT_SECRET" "openid" "$perf_token_flags" >/dev/null 2>&1 || {
            log_test_warning "Token generation failed on iteration $i"
        }
    done
    
    end_time=$(date +%s.%N)
    total_time=$(echo "$end_time - $start_time" | bc -l)
    avg_time=$(echo "scale=3; $total_time / $iterations" | bc -l)
    
    oauth2_log_info "Generated $iterations tokens in ${total_time%.*} seconds"
    oauth2_log_info "Average time per token: ${avg_time} seconds"
    
    if (( $(echo "$avg_time < 1.0" | bc -l) )); then
        log_test_pass "Token generation performance is good (<1s per token)"
    else
        log_test_warning "Token generation is slow (>1s per token)"
    fi
    
    # Test concurrent token validation
    if [ -n "${TEST_ACCESS_TOKEN:-}" ]; then
        oauth2_log_info "Testing concurrent API requests..."
        
        local concurrent_requests=5
        local pids=()
        
        start_time=$(date +%s.%N)
        
        for ((i=1; i<=concurrent_requests; i++)); do
            (oauth2_test_token_against_marklogic "$TEST_ACCESS_TOKEN" "$MARKLOGIC_HOST_ONLY" "$MARKLOGIC_API_PORT" "/" "" >/dev/null 2>&1) &
            pids+=($!)
        done
        
        # Wait for all requests to complete
        for pid in "${pids[@]}"; do
            wait "$pid"
        done
        
        end_time=$(date +%s.%N)
        total_time=$(echo "$end_time - $start_time" | bc -l)
        
        oauth2_log_info "Completed $concurrent_requests concurrent requests in ${total_time%.*} seconds"
        
        if (( $(echo "$total_time < 5.0" | bc -l) )); then
            log_test_pass "Concurrent request performance is good (<5s for $concurrent_requests requests)"
        else
            log_test_warning "Concurrent requests are slow (>5s for $concurrent_requests requests)"
        fi
    fi
}

# Test 7: Security Validation
test_security_validation() {
    log_test_start "Security Validation"
    
    # Test HTTPS usage (if applicable)
    if [[ "$WELL_KNOWN_URL" =~ ^https:// ]]; then
        log_test_pass "OAuth2 server uses HTTPS"
    else
        log_test_warning "OAuth2 server uses HTTP (not recommended for production)"
    fi
    
    if [ "${MARKLOGIC_PROTOCOL:-http}" = "https" ]; then
        log_test_pass "MarkLogic API uses HTTPS"
    else
        log_test_warning "MarkLogic API uses HTTP (not recommended for production)"
    fi
    
    # Test token expiration
    if [ -n "${TEST_ACCESS_TOKEN:-}" ]; then
        local exp_claim
        exp_claim=$(oauth2_jwt_get_claim "$TEST_ACCESS_TOKEN" "exp")
        
        if [ -n "$exp_claim" ]; then
            log_test_pass "Access token has expiration claim"
            
            local token_lifetime current_time
            current_time=$(date +%s)
            token_lifetime=$((exp_claim - current_time))
            
            if [ $token_lifetime -lt 3600 ]; then
                log_test_pass "Token lifetime is reasonable (<1 hour)"
            elif [ $token_lifetime -lt 86400 ]; then
                log_test_warning "Token lifetime is long (<24 hours)"
            else
                log_test_warning "Token lifetime is very long (>24 hours)"
            fi
        else
            log_test_warning "Access token has no expiration claim"
        fi
    fi
    
    # Test JWT algorithm
    if [ -n "${TEST_ACCESS_TOKEN:-}" ]; then
        local alg
        alg=$(oauth2_jwt_get_claim "$TEST_ACCESS_TOKEN" "alg" 2>/dev/null) || {
            local header
            header=$(oauth2_jwt_decode_header "$TEST_ACCESS_TOKEN")
            alg=$(echo "$header" | jq -r '.alg // "unknown"')
        }
        
        case "$alg" in
            "RS256"|"RS384"|"RS512"|"ES256"|"ES384"|"ES512")
                log_test_pass "JWT uses secure signing algorithm: $alg"
                ;;
            "HS256"|"HS384"|"HS512")
                log_test_warning "JWT uses HMAC algorithm: $alg (RSA/ECDSA preferred)"
                ;;
            "none")
                log_test_fail "JWT uses no signature algorithm (security risk)"
                ;;
            *)
                log_test_warning "JWT uses unknown algorithm: $alg"
                ;;
        esac
    fi
}

# ================================================================
# MAIN EXECUTION
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
            --marklogic-manage-port)
                MARKLOGIC_MANAGE_PORT="$2"
                shift 2
                ;;
            --marklogic-user)
                MARKLOGIC_USER="$2"
                shift 2
                ;;
            --marklogic-pass)
                oauth2_log_error "--marklogic-pass VALUE is rejected; use MARKLOGIC_PASS or a hidden prompt"
                exit 1
                ;;
            --app-server)
                APP_SERVER="$2"
                shift 2
                ;;
            --client-id)
                CLIENT_ID="$2"
                shift 2
                ;;
            --client-secret)
                oauth2_log_error "--client-secret VALUE is rejected; use OAUTH_CLIENT_SECRET or a hidden prompt"
                exit 1
                ;;
            --test-username)
                TEST_USERNAME="$2"
                shift 2
                ;;
            --test-password)
                oauth2_log_error "--test-password VALUE is rejected; use OAUTH_TEST_PASSWORD or a hidden prompt"
                exit 1
                ;;
            --api-endpoint-url)
                API_ENDPOINT_URL="$2"
                shift 2
                ;;
            --performance)
                PERFORMANCE_TEST="true"
                shift
                ;;
            --detailed)
                DETAILED_OUTPUT="true"
                shift
                ;;
            --decode-tokens)
                DECODE_TOKENS="true"
                shift
                ;;
            --no-decode-tokens)
                DECODE_TOKENS="false"
                shift
                ;;
            --verbose)
                VERBOSE="true"
                export OAUTH2_DEBUG="true"
                shift
                ;;
            --insecure)
                INSECURE="true"
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
                oauth2_log_error "Unknown option"
                show_usage
                exit 1
                ;;
        esac
    done
    
}

# Generate test report
generate_report() {
    echo
    oauth2_log_info "=== VALIDATION REPORT ==="
    echo
    
    # Test summary
    local success_rate
    if [ $TOTAL_TESTS -gt 0 ]; then
        success_rate=$((PASSED_TESTS * 100 / TOTAL_TESTS))
    else
        success_rate=0
    fi
    
    oauth2_log_info "📊 Test Summary:"
    oauth2_log_info "   Total Tests: $TOTAL_TESTS"
    oauth2_log_info "   Passed: $PASSED_TESTS"
    oauth2_log_info "   Failed: $FAILED_TESTS"
    oauth2_log_info "   Warnings: $WARNINGS"
    oauth2_log_info "   Success Rate: $success_rate%"
    echo
    
    # Overall assessment
    if [ $FAILED_TESTS -eq 0 ] && [ $WARNINGS -le 2 ]; then
        oauth2_log_success "🎉 EXCELLENT - Configuration is working well"
    elif [ $FAILED_TESTS -eq 0 ]; then
        oauth2_log_success "✅ GOOD - Configuration is working with minor issues"
    elif [ $FAILED_TESTS -le 2 ]; then
        oauth2_log_warning "⚠️  NEEDS ATTENTION - Configuration has some issues"
    else
        oauth2_log_error "❌ CRITICAL - Configuration has major issues"
    fi
    
    echo
    oauth2_log_info "📋 Recommendations:"
    
    if [ $FAILED_TESTS -gt 0 ]; then
        oauth2_log_info "• Review and fix failing tests"
        oauth2_log_info "• Check OAuth2 server and MarkLogic connectivity"
        oauth2_log_info "• Verify external security configuration"
    fi
    
    if [ $WARNINGS -gt 3 ]; then
        oauth2_log_info "• Address security warnings for production use"
        oauth2_log_info "• Consider using HTTPS for all communications"
        oauth2_log_info "• Review token expiration policies"
    fi
    
    if [ "$PERFORMANCE_TEST" = "true" ]; then
        oauth2_log_info "• Monitor token generation and validation performance"
        oauth2_log_info "• Consider implementing token caching strategies"
    fi
    
    oauth2_log_info "• Test with real user accounts and applications"
    oauth2_log_info "• Implement monitoring and alerting for production use"
}

# Continue through independent read-only tests and keep the final accounting reliable under set -e.
run_validation_test() {
    local failures_before="$FAILED_TESTS"
    if "$@"; then return 0; fi
    [ "$FAILED_TESTS" -gt "$failures_before" ] || log_test_fail "$1 exited unexpectedly"
}

# Main validation function
main() {
    oauth2_log_info "=== OAuth2 Configuration Validation ==="
    oauth2_log_info "Version 1.0.0 - MLEAProxy Development Team"
    echo
    
    # Validate required parameters
    if [ -z "$WELL_KNOWN_URL" ]; then
        oauth2_log_error "OAuth2 well-known URL is required"
        echo
        show_usage
        exit 1
    fi
    
    if [ -z "$APP_SERVER" ]; then
        oauth2_log_error "--app-server is required"
        echo
        show_usage
        exit 1
    fi
    
    oauth2_validate_url "$WELL_KNOWN_URL" || exit 1
    oauth2_api_path_segment "$APP_SERVER" >/dev/null || { oauth2_log_error "Invalid app-server name"; exit 1; }
    [ -z "$API_ENDPOINT_URL" ] || oauth2_validate_url "$API_ENDPOINT_URL" || exit 1
    parse_marklogic_host "$MARKLOGIC_HOST" || exit 1

    if [ "$DRY_RUN" = "true" ]; then
        oauth2_log_info "[DRY-RUN] Would validate OAuth discovery, optional token flows, MarkLogic app-server state, and token access"
        oauth2_log_info "[DRY-RUN] Remote state is unknown; no password prompt, request, or local file was created"
        exit 0
    fi

    command -v curl >/dev/null 2>&1 || { oauth2_log_error "curl is required"; exit 1; }
    command -v jq >/dev/null 2>&1 || { oauth2_log_error "jq is required"; exit 1; }
    if [ "$DECODE_TOKENS" = "true" ]; then command -v base64 >/dev/null 2>&1 || { oauth2_log_error "base64 is required to decode tokens"; exit 1; }; fi
    MARKLOGIC_PASS=$(ml_resolve_password) || exit 1

    oauth2_log_info "Configuration:"
    oauth2_log_info "• OAuth2 discovery URL: validated (value omitted)"
    oauth2_log_info "• MarkLogic Host: $MARKLOGIC_HOST_ONLY"
    oauth2_log_info "• MarkLogic Manage Port: $MARKLOGIC_MANAGE_PORT"
    oauth2_log_info "• App Server: $APP_SERVER"
    [ -z "$API_ENDPOINT_URL" ] || oauth2_log_info "• Custom API endpoint: configured (value omitted)"
    oauth2_log_info "• Performance Testing: $PERFORMANCE_TEST"
    oauth2_log_info "• Detailed Output: $DETAILED_OUTPUT"
    oauth2_log_info "• Token Decoding: $DECODE_TOKENS"
    echo
    
    # Run validation tests
    run_validation_test test_oauth_server_connectivity
    run_validation_test test_oauth_discovery_endpoints
    run_validation_test test_token_generation
    run_validation_test test_marklogic_configuration
    run_validation_test test_end_to_end_validation
    run_validation_test test_performance
    run_validation_test test_security_validation
    
    # Generate final report
    generate_report
    
    # Exit with appropriate code
    if [ $FAILED_TESTS -eq 0 ]; then
        exit 0
    else
        exit 1
    fi
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    parse_arguments "$@"
    main
fi