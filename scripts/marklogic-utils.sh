#!/bin/bash

# ================================================================
# MarkLogic Common Utility Functions Library
# ================================================================
#
# This library provides common utility functions for MarkLogic
# security configuration scripts including logging, connectivity
# testing, and REST API interactions.
#
# Author: Martin Warnes
# Version: 1.0.2
# Date: November 2025
#
# Usage:
#   source marklogic-utils.sh
#
# ================================================================

# Prevent multiple includes
if [ "${MARKLOGIC_UTILS_LOADED:-}" = "true" ]; then
    return 0
fi
export MARKLOGIC_UTILS_LOADED=true

# ================================================================
# CONSTANTS AND CONFIGURATION
# ================================================================

# Colors for output
readonly COLOR_RED='\033[0;31m'
readonly COLOR_GREEN='\033[0;32m'
readonly COLOR_YELLOW='\033[1;33m'
readonly COLOR_BLUE='\033[0;34m'
readonly COLOR_CYAN='\033[0;36m'
readonly COLOR_PURPLE='\033[0;35m'
readonly COLOR_NC='\033[0m' # No Color

# Default timeout for HTTP requests
readonly DEFAULT_TIMEOUT=30

# Default MarkLogic ports
readonly DEFAULT_ADMIN_PORT=8001
readonly DEFAULT_MANAGE_PORT=8002

# ================================================================
# LOGGING FUNCTIONS
# ================================================================

ml_log_info() {
    echo -e "${COLOR_BLUE}[INFO]${COLOR_NC} $1" >&2
}

ml_log_success() {
    echo -e "${COLOR_GREEN}[SUCCESS]${COLOR_NC} $1" >&2
}

ml_log_warning() {
    echo -e "${COLOR_YELLOW}[WARNING]${COLOR_NC} $1" >&2
}

ml_log_error() {
    echo -e "${COLOR_RED}[ERROR]${COLOR_NC} $1" >&2
}

ml_log_verbose() {
    if [ "${VERBOSE:-false}" = "true" ]; then
        echo -e "${COLOR_CYAN}[DEBUG]${COLOR_NC} $1" >&2
    fi
}

ml_log_step() {
    echo -e "${COLOR_PURPLE}[STEP]${COLOR_NC} $1" >&2
}

# ================================================================
# UTILITY FUNCTIONS
# ================================================================

# Check if command exists
ml_check_dependency() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        ml_log_error "Required command '$cmd' not found. Please install it."
        return 1
    fi
    return 0
}

# Check all required dependencies
ml_check_dependencies() {
    ml_log_info "Checking dependencies..."
    ml_check_dependency "curl" || return 1
    ml_check_dependency "jq" || return 1
    ml_check_dependency "openssl" || return 1
    ml_log_success "All dependencies found"
}

# Validate URL format
ml_validate_url() {
    local url="$1"
    if [[ ! "$url" =~ ^https?:// ]]; then
        ml_log_error "Invalid URL format: $url"
        return 1
    fi
    return 0
}

# Parse MarkLogic host URL and extract components
ml_parse_host_url() {
    local host_url="$1"

    # If no protocol specified, assume http
    if [[ ! "$host_url" =~ ^https?:// ]]; then
        host_url="http://$host_url"
    fi

    # Extract protocol, host, and port
    local protocol host port
    protocol=$(echo "$host_url" | sed 's#://.*##')
    host=$(echo "$host_url" | sed 's#.*://##' | cut -d: -f1 | cut -d/ -f1)
    port=$(echo "$host_url" | sed 's#.*://##' | cut -d: -f2 | cut -d/ -f1)

    # If port is same as host, no port was specified
    if [ "$port" = "$host" ]; then
        port=""
    fi

    # If the URL itself carried no port, fall back to an explicitly
    # provided --marklogic-port (MARKLOGIC_PORT) rather than silently
    # discarding it.
    if [ -z "$port" ] && [ -n "${MARKLOGIC_PORT:-}" ]; then
        port="$MARKLOGIC_PORT"
    fi

    # Export parsed components
    export ML_PROTOCOL="$protocol"
    export ML_HOST="$host"
    export ML_PORT="$port"
    export ML_IS_HTTPS="false"

    if [ "$protocol" = "https" ]; then
        export ML_IS_HTTPS="true"
    fi

    # Build display URL for user output
    if [ -n "$port" ]; then
        export ML_DISPLAY_URL="$protocol://$host:$port"
    else
        export ML_DISPLAY_URL="$protocol://$host"
    fi

    ml_log_verbose "Parsed MarkLogic URL: protocol=$protocol, host=$host, port=$port, is_https=$ML_IS_HTTPS"
}

# Get curl flags for HTTPS/SSL handling
ml_get_curl_flags() {
    local flags=""
    if [ "${INSECURE:-false}" = "true" ]; then
        ml_log_warning "TLS certificate verification disabled"
        flags="$flags -k"
    fi

    # Add timeout
    flags="$flags --connect-timeout 10 -m ${DEFAULT_TIMEOUT}"

    echo "$flags"
}

# Test MarkLogic connectivity
ml_test_connectivity() {
    local host="${1:-${ML_HOST:-localhost}}"
    local port="${2:-${ML_PORT:-8002}}"
    local protocol="${3:-${ML_PROTOCOL:-http}}"

    ml_log_info "Testing MarkLogic connectivity..."

    local test_url="$protocol://$host:$port"
    local response status_code

    local curl_flags
    curl_flags=$(ml_get_curl_flags)
    response=$(curl -s -w "%{http_code}" $curl_flags "$test_url" 2>/dev/null)
    status_code="${response: -3}"

    case "$status_code" in
        200|401|403)
            ml_log_success "MarkLogic is accessible at $test_url"
            return 0
            ;;
        000)
            ml_log_error "Cannot connect to MarkLogic at $test_url"
            ml_log_error "Common solutions:"
            ml_log_error "  1. Start MarkLogic: sudo /etc/init.d/MarkLogic start"
            ml_log_error "  2. Check if running: sudo service MarkLogic status"
            ml_log_error "  3. Verify port $port is correct (usually 8001 or 8002)"
            ml_log_error "  4. Check firewall settings"
            return 1
            ;;
        *)
            ml_log_warning "Unexpected response from MarkLogic (HTTP $status_code)"
            ml_log_info "Continuing anyway - may be a version-specific response"
            return 0
            ;;
    esac
}

# Make authenticated MarkLogic API request
ml_api_request() {
    local method="${1:-GET}"
    local endpoint="$2"
    local user="$3"
    local pass="$4"
    local data="${5:-}"
    local content_type="${6:-application/json}"

    local protocol="${ML_PROTOCOL:-http}"
    local host="${ML_HOST:-localhost}"
    local port="${ML_PORT:-8002}"

    # Check dry-run before credential validation/prompting
    if [ "${DRY_RUN:-false}" = "true" ]; then
        # Safe dry-run preview: method and sanitized endpoint only
        local safe_endpoint resource_name
        safe_endpoint=$(echo "$endpoint" | sed 's/\?.*$//' | sed 's/\/[a-f0-9]\{8,\}\(.*\)/\/<ID>\1/g')
        resource_name=$(basename "$safe_endpoint")
        ml_log_info "[DRY-RUN] $method $safe_endpoint (resource: $resource_name)" >&2
        # Return the agreed dry-run sentinel exit code
        return 3
    fi

    # Require caller-supplied credentials for live requests only
    if [ -z "$user" ] || [ -z "$pass" ]; then
        ml_log_error "ml_api_request requires explicit user and password arguments"
        ml_log_error "Usage: ml_api_request METHOD ENDPOINT USER PASS [DATA] [CONTENT_TYPE]"
        return 1
    fi

    local url="$protocol://$host:$port$endpoint"
    local curl_flags
    curl_flags=$(ml_get_curl_flags)

    # Redact query parameters in verbose logging
    local safe_url
    safe_url=$(echo "$url" | sed 's/\?.*$//')
    ml_log_verbose "Making $method request to: $safe_url"

    local response curl_exit
    local temp_creds temp_data=""

    # Create protected credential config file
    temp_creds=$(mktemp)
    chmod 600 "$temp_creds"
    # Curl config is line-oriented; reject control newlines, then escape its quoted values.
    case "$user$pass" in
        *$'\r'*|*$'\n'*)
            ml_log_error "Username or password must not contain line breaks"
            rm -f "$temp_creds" 2>/dev/null
            return 1
            ;;
    esac
    local safe_user safe_pass
    safe_user=${user//\\/\\\\}
    safe_user=${safe_user//\"/\\\"}
    safe_pass=${pass//\\/\\\\}
    safe_pass=${safe_pass//\"/\\\"}
    printf 'user = "%s:%s"\n' "$safe_user" "$safe_pass" > "$temp_creds"

    # Ensure cleanup on any exit from this function without affecting caller traps
    _ml_cleanup_temp_files() {
        rm -f "$temp_creds" "$temp_data" 2>/dev/null
    }

    if [ -n "$data" ]; then
        # Create protected data file for request body
        temp_data=$(mktemp)
        chmod 600 "$temp_data"
        printf '%s' "$data" > "$temp_data"

        response=$(curl -s -w "%{http_code}" --anyauth \
            --config "$temp_creds" \
            $curl_flags \
            -H "Content-Type: $content_type" \
            -X "$method" \
            --data-binary @"$temp_data" \
            "$url" 2>/dev/null)
        curl_exit=$?
    else
        response=$(curl -s -w "%{http_code}" --anyauth \
            --config "$temp_creds" \
            $curl_flags \
            -X "$method" \
            "$url" 2>/dev/null)
        curl_exit=$?
    fi

    # Always clean up before returning
    _ml_cleanup_temp_files

    # Propagate curl's exit status on transport failure
    if [ $curl_exit -ne 0 ]; then
        ml_log_error "Transport error: curl exit code $curl_exit"
        return $curl_exit
    fi

    echo "$response"
}

# Extract HTTP status code from curl response
ml_extract_status_code() {
    local response="$1"
    echo "${response: -3}"
}

# Extract response body from curl response
ml_extract_response_body() {
    local response="$1"
    echo "${response%???}"
}

# Check if MarkLogic external security configuration exists
# Returns: 0=exists, 1=not found, 2=error, 3=unknown/dry-run
ml_check_external_security_exists() {
    local config_name="$1"
    local user="$2"
    local pass="$3"

    # Check dry-run before requiring credentials
    if [ "${DRY_RUN:-false}" = "true" ]; then
        ml_log_info "[DRY-RUN] Would check existence of external security '$config_name' (existence unknown in dry-run)"
        return 3  # Unknown state in dry-run
    fi

    # Require caller-supplied credentials
    if [ -z "$user" ] || [ -z "$pass" ]; then
        ml_log_error "ml_check_external_security_exists requires explicit user and password arguments"
        return 2
    fi

    local response api_result
    # Guard command substitution to preserve exit status under set -e
    if response=$(ml_api_request "GET" "/manage/v2/external-security/$config_name" "$user" "$pass"); then
        api_result=0
    else
        api_result=$?
    fi

    # Handle dry-run sentinel - return distinct unknown state
    if [ $api_result -eq 3 ]; then
        ml_log_info "[DRY-RUN] Would check existence of external security '$config_name' (existence unknown in dry-run)"
        return 3  # Distinct unknown state
    elif [ $api_result -ne 0 ]; then
        ml_log_error "ml_api_request failed with exit code $api_result"
        return 2  # Error state
    fi

    local status_code
    status_code=$(ml_extract_status_code "$response")

    case "$status_code" in
        200)
            return 0  # Exists
            ;;
        404)
            return 1  # Does not exist
            ;;
        *)
            ml_log_warning "Unexpected response checking external security (HTTP $status_code)"
            return 2  # Error
            ;;
    esac
}

# Generate random string for testing
ml_generate_random_string() {
    local length="${1:-16}"
    openssl rand -hex "$length" 2>/dev/null | head -c "$length"
}

# Create temporary file with cleanup
ml_create_temp_file() {
    local temp_file
    temp_file=$(mktemp)

    # Register cleanup on exit
    trap "rm -f '$temp_file'" EXIT

    echo "$temp_file"
}

# Pretty print JSON if jq is available
ml_pretty_print_json() {
    local json="$1"

    if command -v jq >/dev/null 2>&1; then
        echo "$json" | jq . 2>/dev/null || echo "$json"
    else
        echo "$json"
    fi
}

# Resolve MarkLogic password from environment or prompt
# Usage: password=$(ml_resolve_password)
# Returns password or exits with error in non-interactive+no-env case
ml_resolve_password() {
    # If dry-run mode, no password needed
    if [ "${DRY_RUN:-false}" = "true" ]; then
        return 0
    fi

    # Try environment variable first
    if [ -n "${MARKLOGIC_PASS:-}" ]; then
        echo "$MARKLOGIC_PASS"
        return 0
    fi

    # Check if we're in an interactive terminal
    if [ ! -t 0 ]; then
        ml_log_error "No password available: MARKLOGIC_PASS not set and not running interactively"
        ml_log_error "Set MARKLOGIC_PASS environment variable for non-interactive use"
        return 1
    fi

    # Interactive prompt without echo
    echo -n "MarkLogic password: " >&2
    read -s password
    echo >&2  # Add newline after hidden input

    if [ -z "$password" ]; then
        ml_log_error "Password cannot be empty"
        return 1
    fi

    echo "$password"
}

# Wait for user confirmation
ml_confirm() {
    local message="$1"
    local default="${2:-n}"

    if [ "${YES:-false}" = "true" ]; then
        return 0
    fi

    local prompt
    if [ "$default" = "y" ]; then
        prompt="$message [Y/n]: "
    else
        prompt="$message [y/N]: "
    fi

    read -r -p "$prompt" response
    response=${response:-$default}

    case "$response" in
        [yY][eE][sS]|[yY])
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

# Show script header
ml_show_header() {
    local script_name="$1"
    local version="${2:-1.0.0}"
    local description="$3"

    echo
    ml_log_info "=== $script_name ==="
    ml_log_info "Version $version - MarkLogic Security Hub"
    if [ -n "$description" ]; then
        ml_log_info "$description"
    fi
    echo
}

# Show script footer with next steps
ml_show_footer() {
    local next_steps="$1"

    echo
    ml_log_success "=== Script Complete ==="
    if [ -n "$next_steps" ]; then
        ml_log_info "Next steps:"
        echo "$next_steps"
    fi
    echo
}

# Parse common MarkLogic connection parameters
ml_parse_common_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
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
                ml_log_error "--marklogic-pass VALUE is no longer supported for security"
                ml_log_error "Use MARKLOGIC_PASS environment variable or interactive prompt"
                return 1
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
            --yes)
                YES="true"
                shift
                ;;
            *)
                # Return remaining arguments
                break
                ;;
        esac
    done

    # Set defaults from environment (no default credentials)
    MARKLOGIC_HOST="${MARKLOGIC_HOST:-localhost}"
    MARKLOGIC_USER="${MARKLOGIC_USER:-}"
    MARKLOGIC_PORT="${MARKLOGIC_PORT:-8002}"
}

# Show common usage options
ml_show_common_usage() {
    cat << 'EOF'
COMMON OPTIONS:
    --marklogic-host URL          MarkLogic host URL (default: localhost, or $MARKLOGIC_HOST)
    --marklogic-port PORT         MarkLogic manage port (default: 8002)
    --marklogic-user USER         MarkLogic admin user (required)
    --insecure                    Ignore SSL certificate verification errors (with warning)
    --verbose                     Enable verbose logging
    --dry-run                     Show what would be done without executing
    --yes                         Answer yes to all prompts
    --help                        Show this help message

ENVIRONMENT VARIABLES:
    MARKLOGIC_HOST               Override default MarkLogic host
    MARKLOGIC_USER               Override default MarkLogic user
    MARKLOGIC_PASS               MarkLogic admin password (unattended use)
    MARKLOGIC_PORT               Override default MarkLogic port

PASSWORD INPUT:
    For unattended operation, set MARKLOGIC_PASS environment variable.
    For interactive use, password will be prompted securely.
    Dry-run operations do not require a password.

EOF
}

# Handle MarkLogic API request with dry-run support
# Usage: if ml_api_call_with_dryrun response_var "POST" "/endpoint" "$user" "$pass" "$data"; then
#          status_code=$(ml_extract_status_code "$response_var")
#          # ... handle status codes
#        else
#          case $? in
#            3) ml_log_info "Preview completed" ;; # dry-run
#            *) ml_log_error "Request failed" ;;    # real failure
#          esac
#        fi
ml_api_call_with_dryrun() {
    local response_var_name="$1"
    shift

    local api_response
    api_response=$(ml_api_request "$@")
    local api_result=$?

    # Preserve distinct exit codes: 3=dry-run sentinel, others=real failures
    if [ $api_result -eq 3 ]; then
        ml_log_info "[DRY-RUN] Request preview completed - would proceed with live operation in non-dry-run mode"
        return 3  # Preserve dry-run sentinel for caller
    elif [ $api_result -ne 0 ]; then
        ml_log_error "ml_api_request failed with exit code $api_result"
        return $api_result  # Preserve real failure code
    fi

    # Safe response assignment without eval or variable shadowing
    # Use a different local name to avoid collision with caller's variable
    printf -v "$response_var_name" '%s' "$api_response"

    return 0  # Success - caller can proceed with HTTP status handling
}

# Export all functions for use in other scripts
export -f ml_log_info ml_log_success ml_log_warning ml_log_error ml_log_verbose ml_log_step
export -f ml_check_dependency ml_check_dependencies ml_validate_url ml_parse_host_url
export -f ml_get_curl_flags ml_test_connectivity ml_api_request ml_api_call_with_dryrun
export -f ml_extract_status_code ml_extract_response_body ml_check_external_security_exists
export -f ml_generate_random_string ml_create_temp_file ml_pretty_print_json ml_resolve_password
export -f ml_confirm ml_show_header ml_show_footer ml_parse_common_args ml_show_common_usage