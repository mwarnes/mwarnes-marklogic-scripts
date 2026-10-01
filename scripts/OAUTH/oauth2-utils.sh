#!/bin/bash

# ================================================================
# OAuth2 Utility Functions Library
# ================================================================
#
# This library provides utility functions for OAuth2 operations
# including JWT token manipulation, JWKS processing, and 
# MarkLogic API interactions.
#
# Author: Martin Warnes
# Version: 1.0.2
# Date: October 2025
#
# Usage:
#   source oauth2-utils.sh
#
# ================================================================

# Prevent multiple includes
# if [ "${OAUTH2_UTILS_LOADED:-}" = "true" ]; then
#     return 0
# fi
# export OAUTH2_UTILS_LOADED=true

# ================================================================
# CONSTANTS AND CONFIGURATION
# ================================================================

# Reuse the shared protected MarkLogic request helper and its color/timeout constants when sourced alone.
if ! declare -F ml_api_request >/dev/null 2>&1; then
    OAUTH2_UTILS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    source "$OAUTH2_UTILS_DIR/../marklogic-utils.sh"
fi

# ================================================================
# LOGGING FUNCTIONS
# ================================================================

oauth2_log_info() {
    echo -e "${COLOR_BLUE}[OAUTH2-INFO]${COLOR_NC} $1" >&2
}

oauth2_log_success() {
    echo -e "${COLOR_GREEN}[OAUTH2-SUCCESS]${COLOR_NC} $1" >&2
}

oauth2_log_warning() {
    echo -e "${COLOR_YELLOW}[OAUTH2-WARNING]${COLOR_NC} $1" >&2
}

oauth2_log_error() {
    echo -e "${COLOR_RED}[OAUTH2-ERROR]${COLOR_NC} $1" >&2
}

oauth2_log_debug() {
    if [ "${OAUTH2_DEBUG:-false}" = "true" ]; then
        echo -e "${COLOR_CYAN}[OAUTH2-DEBUG]${COLOR_NC} $1" >&2
    fi
}

# ================================================================
# VALIDATION FUNCTIONS  
# ================================================================

# Validate URL format
oauth2_validate_url() {
    local url="$1" authority
    case "$url" in http://*|https://*) ;; *) oauth2_log_error "URL must use HTTP or HTTPS"; return 1 ;; esac
    authority="${url#*://}"
    authority="${authority%%/*}"
    if [ -z "$authority" ] || [[ "$authority" == *"@"* || "$url" == *"?"* || "$url" == *"#"* || "$url" == *$'\n'* || "$url" == *$'\r'* || "$url" == *[[:space:]]* ]]; then
        oauth2_log_error "URL must not contain userinfo, query values, fragments, or whitespace"
        return 1
    fi
    return 0
}

# Validate JSON format
oauth2_api_path_segment() {
    local value="$1"
    [[ -n "$value" && "$value" != "." && "$value" != ".." && "$value" != *"/"* && "$value" != *"?"* && "$value" != *"#"* && "$value" != *$'\n'* && "$value" != *$'\r'* ]] || return 1
    jq -nr --arg value "$value" '$value|@uri'
}

oauth2_validate_json() {
    local json_string="$1"
    
    if ! echo "$json_string" | jq empty 2>/dev/null; then
        oauth2_log_error "Invalid JSON format"
        return 1
    fi
    
    return 0
}

# Write sensitive request material to a mode-0600 temporary file.
oauth2_write_temp_file() {
    local data="$1" file
    file=$(mktemp) || return 1
    chmod 600 "$file" || { rm -f "$file"; return 1; }
    printf '%s' "$data" > "$file" || { rm -f "$file"; return 1; }
    printf '%s' "$file"
}

oauth2_cleanup_temp_file() {
    [ -n "$1" ] || return 0
    [ -f "$1" ] || return 0
    rm -f "$1"
}

oauth2_create_curl_header_file() {
    local header="$1" file safe_header
    case "$header" in *$'\n'*|*$'\r'*) oauth2_log_error "HTTP header must not contain line breaks"; return 1 ;; esac
    file=$(mktemp) || return 1
    chmod 600 "$file" || { rm -f "$file"; return 1; }
    safe_header=${header//\\/\\\\}
    safe_header=${safe_header//\"/\\\"}
    printf 'header = "%s"\n' "$safe_header" > "$file" || { rm -f "$file"; return 1; }
    printf '%s' "$file"
}

oauth2_curl_extra_flags() {
    case "${1:-}" in
        "") return 0 ;;
        --insecure|-k) oauth2_log_warning "TLS certificate verification disabled by explicit request"; printf '%s\n' --insecure ;;
        *) oauth2_log_error "Unsupported curl flag"; return 1 ;;
    esac
}

oauth2_form_encode() {
    local encoded
    encoded=$(printf '%s' "$1" | jq -sRr '@uri' | sed 's/%20/+/g') || return 1
    printf '%s' "$encoded"
}

# Validate JWT token format (basic structure check)
oauth2_validate_jwt() {
    local token="$1"
    
    # JWT should have 3 parts separated by dots
    local part_count
    part_count=$(echo "$token" | tr '.' '\n' | wc -l)
    
    if [ "$part_count" -ne 3 ]; then
        oauth2_log_error "Invalid JWT format - should have 3 parts separated by dots"
        return 1
    fi
    
    return 0
}

# Check if required dependencies are available
oauth2_check_dependencies() {
    local required_commands=("curl" "jq" "base64")
    local missing_commands=()
    
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing_commands+=("$cmd")
        fi
    done
    
    if [ ${#missing_commands[@]} -ne 0 ]; then
        oauth2_log_error "Missing required commands: ${missing_commands[*]}"
        oauth2_log_error "Please install missing dependencies and try again"
        return 1
    fi
    
    oauth2_log_debug "All dependencies found: ${required_commands[*]}"
    return 0
}

# ================================================================
# HTTP CLIENT FUNCTIONS
# ================================================================

# HTTP GET with quoted arguments and optional protected single-header config.
oauth2_http_get() {
    local url="$1" timeout="${2:-$DEFAULT_TIMEOUT}" headers="${3:-}" extra_flags="${4:-}"
    oauth2_validate_url "$url" || return 1
    if [ "${DRY_RUN:-false}" = "true" ]; then oauth2_log_info "DRY_RUN: Would GET the configured endpoint"; return 3; fi
    oauth2_log_debug "HTTP GET to configured endpoint"

    local -a curl_args=(curl -sS -f -L --max-redirs 3 --proto-redir "=http,https" --connect-timeout "$timeout" --max-time "$timeout")
    local curl_flag header_file="" response status
    curl_flag=$(oauth2_curl_extra_flags "$extra_flags") || return 1
    [ -z "$curl_flag" ] || curl_args+=("$curl_flag")
    if [ -n "$headers" ]; then
        header_file=$(oauth2_create_curl_header_file "$headers") || return 1
        curl_args+=(--config "$header_file")
    fi
    if response=$("${curl_args[@]}" "$url" 2>/dev/null); then status=0; else status=$?; fi
    [ -z "$header_file" ] || rm -f "$header_file" || oauth2_log_warning "Could not remove temporary OAuth header file"
    if [ "$status" -ne 0 ]; then
        oauth2_log_error "HTTP GET failed"
        return "$status"
    fi
    printf '%s\n' "$response"
}

# Protected form POST returning response body plus HTTP status for callers that need error details.
oauth2_http_post_form_response() {
    local url="$1" form_data="$2" timeout="${3:-$DEFAULT_TIMEOUT}"
    local headers="${4:-}" extra_flags="${5:-}" data_file response status curl_flag
    oauth2_validate_url "$url" || return 1
    if [ "${DRY_RUN:-false}" = "true" ]; then oauth2_log_info "DRY_RUN: Would POST form data to the configured endpoint"; return 3; fi
    if [ -n "$headers" ] && [[ "$headers" != *"Content-Type: application/x-www-form-urlencoded"* ]]; then
        oauth2_log_error "Unsupported form request header"
        return 1
    fi
    data_file=$(oauth2_write_temp_file "$form_data") || return 1
    local -a curl_args=(curl -sS -w $'\n%{http_code}' --connect-timeout "$timeout" --max-time "$timeout" \
        -H "Content-Type: application/x-www-form-urlencoded" --data-binary "@$data_file")
    curl_flag=$(oauth2_curl_extra_flags "$extra_flags") || { rm -f "$data_file"; return 1; }
    [ -z "$curl_flag" ] || curl_args+=("$curl_flag")
    if response=$("${curl_args[@]}" "$url" 2>/dev/null); then status=0; else status=$?; fi
    rm -f "$data_file" || oauth2_log_warning "Could not remove protected form-data file"
    if [ "$status" -ne 0 ]; then
        oauth2_log_error "HTTP POST failed"
        return "$status"
    fi
    printf '%s' "$response"
}

# HTTP POST with form data; never log or place the form body in process arguments.
oauth2_http_post_form() {
    local response status body
    if response=$(oauth2_http_post_form_response "$@"); then :; else return $?; fi
    status="${response##*$'\n'}"
    body="${response%$'\n'*}"
    case "$status" in
        2??) printf '%s\n' "$body"; return 0 ;;
        *) oauth2_log_error "HTTP POST failed (HTTP $status)"; return 1 ;;
    esac
}

# HTTP POST with JSON data; auth headers and bodies are supplied through protected files.
oauth2_http_request_json() {
    local method="$1" url="$2" json_data="$3" timeout="${4:-$DEFAULT_TIMEOUT}" auth_header="${5:-}"
    local data_file header_file="" response status
    case "$method" in POST|PUT) ;; *) oauth2_log_error "Unsupported JSON HTTP method"; return 1 ;; esac
    oauth2_validate_url "$url" || return 1
    oauth2_validate_json "$json_data" || return 1
    if [ "${DRY_RUN:-false}" = "true" ]; then oauth2_log_info "DRY_RUN: Would $method JSON to the configured endpoint"; return 3; fi
    data_file=$(oauth2_write_temp_file "$json_data") || return 1
    if [ -n "$auth_header" ]; then
        header_file=$(oauth2_create_curl_header_file "$auth_header") || { rm -f "$data_file"; return 1; }
    fi
    local -a curl_args=(curl -sS -X "$method" -w "%{http_code}" --connect-timeout "$timeout" --max-time "$timeout" \
        -H "Content-Type: application/json" --data-binary "@$data_file")
    [ -z "$header_file" ] || curl_args+=(--config "$header_file")
    if response=$("${curl_args[@]}" "$url" 2>/dev/null); then status=0; else status=$?; fi
    rm -f "$data_file" || oauth2_log_warning "Could not remove protected JSON body file"
    [ -z "$header_file" ] || rm -f "$header_file" || oauth2_log_warning "Could not remove protected OAuth header file"
    if [ "$status" -ne 0 ]; then oauth2_log_error "HTTP $method JSON failed"; return "$status"; fi
    printf '%s' "$response"
}

oauth2_http_post_json() { oauth2_http_request_json POST "$@"; }
oauth2_http_put_json() { oauth2_http_request_json PUT "$@"; }

# ================================================================
# JWT TOKEN FUNCTIONS
# ================================================================

# Decode JWT header
oauth2_jwt_decode_header() {
    local token="$1"
    
    oauth2_validate_jwt "$token" || return 1
    
    local header
    header=$(echo "$token" | cut -d. -f1)
    
    # Add padding if needed for base64 decoding
    local padding=$((4 - ${#header} % 4))
    if [ $padding -ne 4 ]; then
        header="${header}$(printf '%*s' $padding | tr ' ' '=')"
    fi
    
    echo "$header" | base64 -d 2>/dev/null | jq . 2>/dev/null || {
        oauth2_log_error "Failed to decode JWT header"
        return 1
    }
}

# Decode JWT payload
oauth2_jwt_decode_payload() {
    local token="$1"
    
    oauth2_validate_jwt "$token" || return 1
    
    local payload
    payload=$(echo "$token" | cut -d. -f2)
    
    # Add padding if needed for base64 decoding
    local padding=$((4 - ${#payload} % 4))
    if [ $padding -ne 4 ]; then
        payload="${payload}$(printf '%*s' $padding | tr ' ' '=')"
    fi
    
    echo "$payload" | base64 -d 2>/dev/null | jq . 2>/dev/null || {
        oauth2_log_error "Failed to decode JWT payload"
        return 1
    }
}

# Extract JWT claim value
oauth2_jwt_get_claim() {
    local token="$1"
    local claim="$2"
    
    local payload
    payload=$(oauth2_jwt_decode_payload "$token") || return 1
    echo "$payload" | jq -r --arg claim "$claim" 'getpath($claim | split(".")) // empty'
}

# Check if JWT token is expired
oauth2_jwt_is_expired() {
    local token="$1"
    
    local exp_claim current_time
    exp_claim=$(oauth2_jwt_get_claim "$token" "exp") || return 1
    current_time=$(date +%s)
    
    if [ -z "$exp_claim" ]; then
        oauth2_log_warning "No expiration claim found in JWT"
        return 1
    fi
    
    if [ "$current_time" -gt "$exp_claim" ]; then
        oauth2_log_debug "JWT token is expired (exp: $exp_claim, now: $current_time)"
        return 0 # Token is expired
    else
        oauth2_log_debug "JWT token is valid (exp: $exp_claim, now: $current_time)"
        return 1 # Token is not expired
    fi
}

# Get JWT token time until expiration
oauth2_jwt_time_to_expiry() {
    local token="$1"
    
    local exp_claim current_time
    exp_claim=$(oauth2_jwt_get_claim "$token" "exp") || return 1
    current_time=$(date +%s)
    
    if [ -z "$exp_claim" ]; then
        echo "unknown"
        return 1
    fi
    
    local time_diff=$((exp_claim - current_time))
    
    if [ $time_diff -le 0 ]; then
        echo "expired"
    else
        echo "$time_diff"
    fi
}

# ================================================================
# OAUTH2 DISCOVERY FUNCTIONS
# ================================================================

# Fetch OAuth2 well-known configuration
oauth2_fetch_well_known() {
    local base_url="$1"
    local endpoint_path="${2:-.well-known/openid_configuration}"
    if [ "${DRY_RUN:-false}" = "true" ]; then oauth2_log_info "DRY_RUN: Would fetch OAuth2 discovery metadata"; return 3; fi
    
    # Remove trailing slash from base URL
    base_url="${base_url%/}"
    
    local well_known_url="$base_url/$endpoint_path"
    
    oauth2_log_debug "Fetching OAuth2 well-known configuration from the configured endpoint"
    
    local config
    config=$(oauth2_http_get "$well_known_url") || return 1
    
    oauth2_validate_json "$config" || return 1
    
    echo "$config"
}

# Extract specific endpoint from OAuth2 configuration
oauth2_get_endpoint() {
    local config="$1"
    local endpoint_name="$2"
    
    local endpoint_url
    endpoint_url=$(echo "$config" | jq -r --arg name "$endpoint_name" '.[$name] // empty')
    
    if [ -z "$endpoint_url" ]; then
        oauth2_log_warning "Endpoint '$endpoint_name' not found in OAuth2 configuration"
        return 1
    fi
    
    echo "$endpoint_url"
}

# Fetch JWKS from JWKS URI
oauth2_fetch_jwks() {
    local jwks_uri="$1"
    local extra_flags="${2:-}"
    if [ "${DRY_RUN:-false}" = "true" ]; then oauth2_log_info "DRY_RUN: Would fetch the configured JWKS endpoint"; return 3; fi
    
    oauth2_log_debug "Fetching JWKS from the configured endpoint"
    
    local jwks
    jwks=$(oauth2_http_get "$jwks_uri" "$DEFAULT_TIMEOUT" "" "$extra_flags") || return 1
    
    oauth2_validate_json "$jwks" || return 1
    
    # Treat missing, failed, or empty key inventories as errors, never as an empty set.
    local key_count
    key_count=$(oauth2_jwks_key_count "$jwks") || return 1
    oauth2_jwks_list_key_ids "$jwks" >/dev/null || return 1
    oauth2_log_debug "JWKS contains $key_count keys"
    echo "$jwks"
}

# ================================================================
# OAUTH2 TOKEN FUNCTIONS
# ================================================================

# Generate OAuth2 token using client credentials flow
oauth2_get_token_client_credentials() {
    local token_endpoint="$1"
    if [ "${DRY_RUN:-false}" = "true" ]; then oauth2_log_info "DRY_RUN: Would request an OAuth2 client-credentials token"; return 3; fi
    local client_id="$2"
    local client_secret="$3"
    local scope="${4:-}"
    local extra_flags="${5:-}"
    
    oauth2_log_debug "Requesting token using client credentials flow"
    
    local encoded_client_id encoded_secret encoded_scope="" form_data
    encoded_client_id=$(oauth2_form_encode "$client_id") || return 1
    encoded_secret=$(oauth2_form_encode "$client_secret") || return 1
    [ -z "$scope" ] || encoded_scope=$(oauth2_form_encode "$scope") || return 1
    form_data="grant_type=client_credentials&client_id=$encoded_client_id&client_secret=$encoded_secret"
    [ -z "$scope" ] || form_data="$form_data&scope=$encoded_scope"

    local response
    response=$(oauth2_http_post_form "$token_endpoint" "$form_data" "$DEFAULT_TIMEOUT" "" "$extra_flags") || return 1
    
    oauth2_validate_json "$response" || return 1
    
    # Extract access token
    local access_token
    access_token=$(echo "$response" | jq -r '.access_token // empty')
    
    if [ -z "$access_token" ]; then
        oauth2_log_error "No access token in the token endpoint response"
        return 1
    fi
    
    echo "$access_token"
}

# Generate OAuth2 token using password flow
oauth2_get_token_password() {
    local token_endpoint="$1"
    if [ "${DRY_RUN:-false}" = "true" ]; then oauth2_log_info "DRY_RUN: Would request an OAuth2 password-grant token"; return 3; fi
    local username="$2"
    local password="$3"
    local client_id="$4"
    local client_secret="${5:-}"
    local scope="${6:-}"
    local extra_flags="${7:-}"

    oauth2_log_debug "Requesting token using password flow"

    local encoded_username encoded_password encoded_client_id encoded_secret="" encoded_scope="" form_data
    encoded_username=$(oauth2_form_encode "$username") || return 1
    encoded_password=$(oauth2_form_encode "$password") || return 1
    encoded_client_id=$(oauth2_form_encode "$client_id") || return 1
    [ -z "$client_secret" ] || encoded_secret=$(oauth2_form_encode "$client_secret") || return 1
    [ -z "$scope" ] || encoded_scope=$(oauth2_form_encode "$scope") || return 1
    form_data="grant_type=password&username=$encoded_username&password=$encoded_password&client_id=$encoded_client_id"
    [ -z "$client_secret" ] || form_data="$form_data&client_secret=$encoded_secret"
    [ -z "$scope" ] || form_data="$form_data&scope=$encoded_scope"

    # The helper stores the secret-bearing form body in a protected temporary file.
    local response status_code temp_response
    temp_response=$(oauth2_http_post_form_response "$token_endpoint" "$form_data" "$DEFAULT_TIMEOUT" "" "$extra_flags") || {
        oauth2_log_error "Failed to connect to token endpoint"
        return 1
    }
    response="${temp_response%$'\n'*}"
    status_code="${temp_response##*$'\n'}"
    oauth2_log_debug "Password flow response status: $status_code"
    
    # Check status code
    case "$status_code" in
        200)
            oauth2_log_debug "Password flow successful - extracting token"
            ;;
        400)
            oauth2_log_error "❌ Password flow failed - Bad Request (400)"
            local error_reason
            error_reason=$(echo "$response" | jq -r '.error // "unknown_error"' 2>/dev/null)
            oauth2_log_error "   Provider rejected the request; error details were suppressed"
            oauth2_log_error "   Provider response details were suppressed to avoid logging credentials"
            
            case "$error_reason" in
                "invalid_grant"|"invalid_user_credentials")
                    oauth2_log_error "   → Test-user credentials were rejected"
                    ;;
                "invalid_client")
                    oauth2_log_error "   → Client configuration was rejected"
                    ;;
                "unsupported_grant_type")
                    oauth2_log_error "   → Password flow is disabled for this client"
                    ;;
                "invalid_scope")
                    oauth2_log_error "   → Requested scope is not available"
                    ;;
            esac
            return 1
            ;;
        401)
            oauth2_log_error "❌ Password flow failed - Unauthorized (401)"
            oauth2_log_error "   → Check the supplied test-user credentials"
            return 1
            ;;
        403)
            oauth2_log_error "❌ Password flow failed - Forbidden (403)"
            oauth2_log_error "   → Test user may be disabled or password flow not allowed"
            return 1
            ;;
        *)
            oauth2_log_error "❌ Password flow failed - HTTP $status_code"
            oauth2_log_error "   Token endpoint returned an unsuccessful response"
            return 1
            ;;
    esac
    
    # Validate JSON response
    if ! oauth2_validate_json "$response"; then
        oauth2_log_error "Invalid JSON response from token endpoint"
        return 1
    fi
    
    # Extract access token
    local access_token
    access_token=$(echo "$response" | jq -r '.access_token // empty')
    
    if [ -z "$access_token" ]; then
        oauth2_log_error "No access token in successful response"
        return 1
    fi
    
    echo "$access_token"
}

# ================================================================
# MARKLOGIC INTEGRATION FUNCTIONS
# ================================================================

# Test MarkLogic external security configuration with the shared protected-auth helper.
oauth2_test_marklogic_config() {
    local marklogic_host="$1" marklogic_port="$2" config_name="$3" username="$4" password="$5"
    local MARKLOGIC_HOST="$marklogic_host" MARKLOGIC_PORT="$marklogic_port"
    local ML_PROTOCOL ML_HOST ML_PORT ML_IS_HTTPS ML_DISPLAY_URL
    local config_path response status_code

    if [ "${DRY_RUN:-false}" = "true" ]; then
        oauth2_log_info "DRY_RUN: Would check external-security state; result remains unknown"
        return 3
    fi
    config_path=$(oauth2_api_path_segment "$config_name") || return 1
    ml_parse_host_url "$marklogic_host"
    response=$(ml_api_request GET "/manage/v2/external-security/$config_path/properties?format=json" "$username" "$password") || {
        oauth2_log_error "MarkLogic configuration request failed"
        return 1
    }
    status_code=$(ml_extract_status_code "$response")
    case "$status_code" in
        200) oauth2_log_success "MarkLogic configuration exists and is accessible"; return 0 ;;
        404) oauth2_log_error "MarkLogic configuration not found"; return 1 ;;
        401) oauth2_log_error "MarkLogic authentication failed"; return 1 ;;
        *) oauth2_log_error "MarkLogic configuration test failed (HTTP $status_code)"; return 1 ;;
    esac
}

# Test OAuth token against MarkLogic without exposing it in curl argv or logs.
oauth2_test_token_against_marklogic() {
    local token="$1" marklogic_host="$2" marklogic_port="${3:-8000}"
    local endpoint="${4:-/v1/documents}" custom_url="${5:-}" api_url header_file response status_code request_status
    if [ -n "$custom_url" ]; then
        api_url="$custom_url"
    else
        api_url="${MARKLOGIC_PROTOCOL:-http}://$marklogic_host:$marklogic_port$endpoint"
    fi
    oauth2_validate_url "$api_url" || return 3
    if [ "${DRY_RUN:-false}" = "true" ]; then oauth2_log_info "DRY_RUN: Would test the OAuth token against MarkLogic"; return 3; fi
    header_file=$(oauth2_create_curl_header_file "Authorization: Bearer $token") || return 3

    local -a curl_args=(curl -sS -w "%{http_code}" --connect-timeout "$DEFAULT_TIMEOUT" --max-time "$DEFAULT_TIMEOUT" \
        --config "$header_file" -H "Accept: application/json")
    if [ "${INSECURE:-false}" = "true" ]; then
        oauth2_log_warning "TLS certificate verification disabled by explicit request"
        curl_args+=(--insecure)
    fi
    if response=$("${curl_args[@]}" "$api_url" 2>/dev/null); then request_status=0; else request_status=$?; fi
    rm -f "$header_file" || oauth2_log_warning "Could not remove temporary OAuth header file"
    if [ "$request_status" -ne 0 ]; then
        oauth2_log_warning "OAuth token request failed at the transport layer"
        return 3
    fi
    status_code="${response: -3}"
    case "$status_code" in
        200) oauth2_log_success "Token validated successfully by MarkLogic"; return 0 ;;
        302) oauth2_log_success "Token accepted by MarkLogic (HTTP 302 redirect)"; return 0 ;;
        401) oauth2_log_warning "Token rejected by MarkLogic (401 Unauthorized)"; return 1 ;;
        403) oauth2_log_warning "Token accepted but access denied (403 Forbidden)"; return 2 ;;
        *) oauth2_log_warning "Unexpected response from MarkLogic API (HTTP $status_code)"; return 3 ;;
    esac
}

# ================================================================
# JWKS PROCESSING FUNCTIONS
# ================================================================

# Extract RSA public key components from JWKS
oauth2_jwks_get_rsa_key() {
    local jwks="$1" key_id="${2:-}" key_data
    oauth2_validate_json "$jwks" || return 1
    if [ -n "$key_id" ]; then
        key_data=$(echo "$jwks" | jq -c --arg kid "$key_id" '.keys[] | select(.kty == "RSA" and .kid == $kid)' | head -n 1)
    else
        key_data=$(echo "$jwks" | jq -c '.keys[] | select(.kty == "RSA")' | head -n 1)
    fi
    
    if [ -z "$key_data" ] || [ "$key_data" = "null" ]; then
        oauth2_log_error "No matching RSA key found in JWKS"
        return 1
    fi
    
    echo "$key_data"
}

# List all key IDs in JWKS
oauth2_jwks_list_key_ids() {
    local jwks="$1"
    oauth2_validate_json "$jwks" || return 1
    echo "$jwks" | jq -er '(.keys | type == "array" and length > 0) as $valid | if $valid then .keys[] | .kid // error("missing kid") else error("empty keys") end' 2>/dev/null || {
        oauth2_log_error "JWKS key inventory is empty or invalid"
        return 1
    }
}

# Get key count from JWKS
oauth2_jwks_key_count() {
    local jwks="$1"
    oauth2_validate_json "$jwks" || return 1
    echo "$jwks" | jq -er 'if (.keys | type) == "array" and (.keys | length) > 0 then .keys | length else error("empty keys") end' 2>/dev/null || {
        oauth2_log_error "JWKS key inventory is empty or invalid"
        return 1
    }
}

# ================================================================
# UTILITY HELPER FUNCTIONS
# ================================================================

# Generate random string for testing
oauth2_generate_random_string() {
    local length="${1:-32}"
    
    head /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c "$length"
}

# Convert seconds to human readable time
oauth2_seconds_to_human() {
    local seconds="$1"
    
    if [ "$seconds" -lt 60 ]; then
        echo "${seconds}s"
    elif [ "$seconds" -lt 3600 ]; then
        echo "$((seconds / 60))m $((seconds % 60))s"
    else
        echo "$((seconds / 3600))h $((seconds % 3600 / 60))m $((seconds % 60))s"
    fi
}

# Check if port is open
oauth2_check_port() {
    local host="$1"
    local port="$2"
    local timeout="${3:-5}"
    
    if command -v nc >/dev/null 2>&1; then
        nc -z -w "$timeout" "$host" "$port" 2>/dev/null
    elif command -v telnet >/dev/null 2>&1; then
        timeout "$timeout" telnet "$host" "$port" </dev/null >/dev/null 2>&1
    else
        # Fallback using curl
        curl -s --connect-timeout "$timeout" "http://$host:$port" >/dev/null 2>&1
    fi
}

# Wait for service to be available
oauth2_wait_for_service() {
    local host="$1"
    local port="$2"
    local max_attempts="${3:-30}"
    local delay="${4:-2}"
    
    oauth2_log_info "Waiting for service at $host:$port..."
    
    local attempt=1
    while [ "$attempt" -le "$max_attempts" ]; do
        if oauth2_check_port "$host" "$port"; then
            oauth2_log_success "Service is available at $host:$port"
            return 0
        fi
        
        oauth2_log_debug "Attempt $attempt/$max_attempts - service not ready"
        sleep "$delay"
        ((attempt++))
    done
    
    oauth2_log_error "Service at $host:$port did not become available within $((max_attempts * delay)) seconds"
    return 1
}

# ================================================================
# INITIALIZATION
# ================================================================

# Check dependencies when library is loaded
if ! oauth2_check_dependencies; then
    oauth2_log_error "OAuth2 utilities library initialization failed"
    return 1
fi

oauth2_log_debug "OAuth2 utilities library loaded successfully"