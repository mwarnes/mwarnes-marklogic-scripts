#!/bin/bash

# ================================================================
# MarkLogic App Server Security Configuration Script
# ================================================================
# 
# This script configures MarkLogic app servers to use external security
# configurations (OAuth, SAML, LDAP, etc.) via the Management REST API
# 
# Features:
# - Updates app server external security configuration
# - Supports multiple app servers in one run
# - Validates external security configurations exist
# - Shows current app server configuration
# - Dry-run mode for testing
#
# Author: Martin Warnes
# Version: 1.0.3
# Date: October 2025
#
# Usage:
#   ./configure-appserver-security.sh [OPTIONS]
#
# Examples:
#   # Configure single app server
#   ./configure-appserver-security.sh --appserver App-Services --external-security MLEAProxy-OAuth
#
#   # Configure multiple app servers
#   ./configure-appserver-security.sh --appserver "App-Services,Documents" --external-security MLEAProxy-OAuth
#
#   # Show current configuration
#   ./configure-appserver-security.sh --appserver App-Services --show-current
#
#   # Remove external security (set to none)
#   ./configure-appserver-security.sh --appserver App-Services --remove-security
#
# ================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/marklogic-utils.sh"

# ================================================================
# CONFIGURATION VARIABLES
# ================================================================

# Default values
MARKLOGIC_HOST="${MARKLOGIC_HOST:-oauth.warnesnet.com}"
MARKLOGIC_PORT="${MARKLOGIC_PORT:-8002}"
MARKLOGIC_USER="${MARKLOGIC_USER:-admin}"
MARKLOGIC_PASS="${MARKLOGIC_PASS:-}"
APPSERVER_NAMES=""
EXTERNAL_SECURITY=""
AUTHENTICATION_METHOD=""
SHOW_CURRENT="false"
REMOVE_SECURITY="false"
LIST_APPSERVERS="false"
VERBOSE="false"
DRY_RUN="false"

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

Configures MarkLogic app servers to use external security configurations.

OPTIONS:
    --appserver NAMES             App server name(s) - comma-separated for multiple (required)
    --external-security NAME      External security configuration name
    --authentication-method TYPE  oauth, saml, ldap (applied as basic), kerberos (kerberos-ticket), certificate, basic - REQUIRED when configuring security
    --show-current                Show current app server security configuration (read-only)
    --remove-security             Remove external security (set authentication to basic)
    --list-appservers             List all available app servers (read-only)
    --marklogic-host HOST         MarkLogic host (default: oauth.warnesnet.com)
    --marklogic-port PORT         MarkLogic manage port (default: 8002)
    --marklogic-user USER         MarkLogic admin user (default: admin)
    --marklogic-pass PASS         Rejected; use MARKLOGIC_PASS or a hidden prompt
    --verbose                     Enable verbose logging
    --dry-run                     Show what would be done without executing
    --yes                         Confirm live configuration changes without prompting
    --help                        Show this help message

Changes require manual recovery; preserve the current app-server settings before applying them.

EXAMPLES:
    # Configure single app server with OAuth
    $0 --appserver App-Services --external-security MLEAProxy-OAuth --authentication-method oauth

    # Configure with SAML authentication
    $0 --appserver App-Services --external-security SAML-Config --authentication-method saml

    # Configure with LDAP authentication
    $0 --appserver App-Services --external-security LDAP-Config --authentication-method ldap

    # Configure multiple app servers
    $0 --appserver "App-Services,Documents,Admin" --external-security SAML-Config --authentication-method saml

    # Show current configuration
    $0 --appserver App-Services --show-current

    # Remove external security from app server
    $0 --appserver App-Services --remove-security

    # Dry run to see what would be changed
    $0 --appserver App-Services --external-security OAuth-Config --authentication-method oauth --dry-run

ENVIRONMENT VARIABLES:
    MARKLOGIC_HOST               Override default MarkLogic host
    MARKLOGIC_USER               Override default MarkLogic user
    MARKLOGIC_PASS               MarkLogic password for unattended use

This script changes app-server settings. No automatic rollback is provided; preserve prior configuration for manual recovery.

EOF
}

api_path_segment() {
    local value="$1"
    [[ -n "$value" && "$value" != "." && "$value" != ".." && "$value" != *"/"* && "$value" != *"?"* && "$value" != *"#"* && "$value" != *$'\n'* && "$value" != *$'\r'* ]] || return 1
    jq -nr --arg value "$value" '$value|@uri'
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

# Test MarkLogic connectivity through the shared protected-credential request helper.
test_marklogic_connection() {
    log_info "Testing MarkLogic connectivity..."
    local response status_code test_url="${ML_DISPLAY_URL:-$MARKLOGIC_HOST:$MARKLOGIC_PORT}"
    if ! response=$(ml_api_request GET "/manage/v2" "$MARKLOGIC_USER" "$MARKLOGIC_PASS"); then
        log_error "Cannot connect to MarkLogic at $test_url"
        return 1
    fi
    status_code=$(ml_extract_status_code "$response")
    case "$status_code" in
        200|401|403) log_success "MarkLogic is accessible at $test_url"; return 0 ;;
        *) log_error "Unexpected response from MarkLogic (HTTP $status_code)"; return 1 ;;
    esac
}

# ================================================================
# APP SERVER CONFIGURATION FUNCTIONS
# ================================================================

# List available app servers
list_appservers() {
    if [ "$DRY_RUN" = "true" ]; then
        log_info "[DRY-RUN] Would list app servers with GET /manage/v2/servers?format=json"
        return 0
    fi
    log_info "Available app servers on $MARKLOGIC_HOST:"
    local response status_code servers_body
    response=$(ml_api_request GET "/manage/v2/servers?format=json" "$MARKLOGIC_USER" "$MARKLOGIC_PASS") || return 1
    status_code=$(ml_extract_status_code "$response")
    servers_body=$(ml_extract_response_body "$response")
    case "$status_code" in
        200)
            echo "$servers_body" | jq -r '.["server-default-list"]["list-items"]["list-item"][].nameref' 2>/dev/null | sort || {
                log_warning "Could not parse server list"
                echo "$servers_body"
            }
            ;;
        *) log_error "Failed to list app servers (HTTP $status_code)"; return 1 ;;
    esac
}

# Get server ID from server name
get_server_id() {
    local appserver_name="$1" response status_code servers_body server_id
    log_verbose "Looking up server ID for: $appserver_name"
    response=$(ml_api_request GET "/manage/v2/servers?format=json" "$MARKLOGIC_USER" "$MARKLOGIC_PASS") || return 1
    status_code=$(ml_extract_status_code "$response")
    servers_body=$(ml_extract_response_body "$response")
    if [ "$status_code" = "200" ]; then
        server_id=$(echo "$servers_body" | jq -r --arg name "$appserver_name" \
            '.["server-default-list"]["list-items"]["list-item"][] | select(.nameref == $name) | .idref' 2>/dev/null)
        if [ -n "$server_id" ] && [ "$server_id" != "null" ]; then echo "$server_id"; return 0; fi
    fi
    log_verbose "Could not find server ID for: $appserver_name"
    return 1
}

# Get current app server configuration
get_appserver_config() {
    local appserver_name="$1" group_name="${2:-Default}" server_path group_path response status_code config_body
    server_path=$(api_path_segment "$appserver_name") || return 1
    group_path=$(api_path_segment "$group_name") || return 1
    log_verbose "Getting configuration for app server: $appserver_name (group: $group_name)"
    response=$(ml_api_request GET "/manage/v2/servers/$server_path/properties?group-id=$group_path&format=json" "$MARKLOGIC_USER" "$MARKLOGIC_PASS") || return 1
    status_code=$(ml_extract_status_code "$response")
    config_body=$(ml_extract_response_body "$response")
    case "$status_code" in
        200) printf '%s\n' "$config_body"; return 0 ;;
        404) log_error "App server '$appserver_name' not found"; return 1 ;;
        *) log_error "Failed to get app server configuration (HTTP $status_code)"; return 1 ;;
    esac
}

# Show current app server security configuration
show_appserver_security() {
    local appserver_name="$1"
    if [ "$DRY_RUN" = "true" ]; then
        log_info "[DRY-RUN] --show-current is read-only and requires a live GET; no request was sent"
        return 0
    fi
    log_info "Current security configuration for app server: $appserver_name"
    
    local config
    config=$(get_appserver_config "$appserver_name") || return 1
    
    local authentication external_security
    authentication=$(echo "$config" | jq -r '.authentication // "basic"')
    external_security=$(echo "$config" | jq -r '(."external-security" // "none") | if type == "array" then (.[0] // "none") else . end')
    
    echo
    echo "  Authentication: $authentication"
    echo "  External Security: $external_security"
    
    if [ "$external_security" != "none" ] && [ "$external_security" != "null" ]; then
        # Try to get details about the external security configuration
        local ext_path ext_response ext_status ext_body
        ext_path=$(api_path_segment "$external_security") || return 1
        ext_response=$(ml_api_request GET "/manage/v2/external-security/$ext_path?format=json" "$MARKLOGIC_USER" "$MARKLOGIC_PASS") || return 1
        ext_status=$(ml_extract_status_code "$ext_response")
        
        if [ "$ext_status" = "200" ]; then
            ext_body=$(ml_extract_response_body "$ext_response")
            local auth_type description
            auth_type=$(echo "$ext_body" | jq -r '(.["external-security-default"] // .) | .authentication // "unknown"')
            description=$(echo "$ext_body" | jq -r '(.["external-security-default"] // .) | .description // ""')
            
            echo "  External Security Type: $auth_type"
            if [ "$description" != "" ]; then
                echo "  Description: $description"
            fi
        fi
    fi
    echo
}

# Validate external security configuration exists
validate_external_security() {
    local config_name="$1" config_path response status_code
    log_verbose "Validating external security configuration: $config_name"
    config_path=$(api_path_segment "$config_name") || return 1
    response=$(ml_api_request GET "/manage/v2/external-security/$config_path?format=json" "$MARKLOGIC_USER" "$MARKLOGIC_PASS") || return 1
    status_code=$(ml_extract_status_code "$response")
    case "$status_code" in
        200)
            log_verbose "External security configuration '$config_name' exists"
            return 0
            ;;
        404)
            log_error "External security configuration '$config_name' not found"
            log_error "Please create the external security configuration first"
            return 1
            ;;
        *)
            log_error "Failed to validate external security configuration (HTTP $status_code)"
            return 1
            ;;
    esac
}

# Configure app server security
configure_appserver_security() {
    local appserver_name="$1"
    local config_name="$2"
    local remove_security="$3"
    local auth_method="$4"
    
    local appserver_path appserver_url
    appserver_path=$(api_path_segment "$appserver_name") || return 1
    appserver_url="/manage/v2/servers/$appserver_path/properties?group-id=Default&format=json"

    if [ "$remove_security" = "true" ]; then
        log_info "Removing external security from app server: $appserver_name"
    else
        log_info "Configuring app server '$appserver_name' to use external security '$config_name'"
    fi

    if [ "$DRY_RUN" = "true" ]; then
        if [ "$remove_security" = "true" ]; then
            log_info "[DRY-RUN] Would PUT $appserver_url and set authentication=basic, external-security=null"
        else
            log_info "[DRY-RUN] Would PUT $appserver_url and set authentication=$auth_method, external-security=$config_name"
        fi
        return 0
    fi

    # Get current configuration first to preserve required fields
    log_verbose "Getting current app server configuration..."
    local current_config
    current_config=$(get_appserver_config "$appserver_name") || return 1
    
    # Extract required fields from current configuration
    local server_group server_name port
    server_group=$(echo "$current_config" | jq -r '."group-name" // "Default"')
    server_name=$(echo "$current_config" | jq -r --arg fallback "$appserver_name" '."server-name" // $fallback')
    port=$(echo "$current_config" | jq -r '.port // 8000')
    [[ "$port" =~ ^[0-9]{1,5}$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ] || { log_error "Invalid app-server port in current configuration"; return 1; }
    
    log_verbose "Current server group: $server_group"
    log_verbose "Current server name: $server_name"
    log_verbose "Current port: $port"
    
    # Use provided authentication method or basic for removal
    local authentication_method="basic"
    if [ "$remove_security" != "true" ]; then
        authentication_method="$auth_method"
        # MarkLogic's app-server "authentication" values are application-level, digest, basic,
        # digestbasic, certificate, kerberos-ticket, oauth and saml. LDAP has no value of its own:
        # it is "basic" (or digestbasic) combined with an LDAP external-security object.
        case "$authentication_method" in
            ldap) authentication_method="basic"; log_info "LDAP is applied as authentication=basic plus the external-security object" ;;
            kerberos) authentication_method="kerberos-ticket"; log_info "Kerberos is applied as authentication=kerberos-ticket (MarkLogic requires internal security to be disabled on the app server)" ;;
        esac
        log_info "Using authentication method: $authentication_method"
    fi

    # Validate external security exists (unless removing)
    if [ "$remove_security" != "true" ]; then
        validate_external_security "$config_name" || return 1
    fi
    
    # Prepare a JSON payload with quoted values.
    local update_payload
    if [ "$remove_security" = "true" ]; then
        update_payload=$(jq -n --arg server "$server_name" --arg group "$server_group" --argjson port "$port" \
            '{"server-name":$server,"group-name":$group,"port":$port,"authentication":"basic","external-security":null}') || return 1
    else
        update_payload=$(jq -n --arg server "$server_name" --arg group "$server_group" --argjson port "$port" \
            --arg authentication "$authentication_method" --arg external_security "$config_name" \
            '{"server-name":$server,"group-name":$group,"port":$port,"authentication":$authentication,"external-security":$external_security}') || return 1
    fi
    
    if ! ml_confirm "Change app-server security for '$appserver_name'? Automatic rollback is unavailable; preserve the prior configuration for manual recovery." "n"; then
        log_info "App-server update cancelled"
        return 0
    fi
    log_verbose "Updating app server security configuration..."

    local response status_code response_body
    response=$(ml_api_request PUT "$appserver_url" "$MARKLOGIC_USER" "$MARKLOGIC_PASS" "$update_payload") || {
        log_error "App-server update request failed"
        return 1
    }
    status_code=$(ml_extract_status_code "$response")
    response_body=$(ml_extract_response_body "$response")
    
    case "$status_code" in
        204|200)
            if [ "$remove_security" = "true" ]; then
                log_success "Removed external security from app server '$appserver_name'"
            else
                log_success "App server '$appserver_name' configured to use external security '$config_name'"
            fi
            return 0
            ;;
        400)
            log_error "Bad request - check app server name and external security configuration"
            echo "$response_body" | jq . 2>/dev/null || echo "$response_body" >&2
            return 1
            ;;
        404)
            log_error "App server '$appserver_name' not found"
            return 1
            ;;
        *)
            log_error "Failed to update app server configuration (HTTP $status_code)"
            echo "$response_body" | jq . 2>/dev/null || echo "$response_body" >&2
            return 1
            ;;
    esac
}

# Process multiple app servers
process_appservers() {
    local appserver_list="$1"
    local config_name="$2"
    local remove_security="$3"
    local show_current="$4"
    
    # Split comma-separated app server names
    IFS=',' read -ra APPSERVERS <<< "$appserver_list"
    
    local success_count=0 failure_count=0
    local total_count=${#APPSERVERS[@]}
    
    for appserver in "${APPSERVERS[@]}"; do
        # Trim surrounding whitespace without a subprocess.
        appserver="${appserver#"${appserver%%[![:space:]]*}"}"
        appserver="${appserver%"${appserver##*[![:space:]]}"}"
        
        if [ -z "$appserver" ] || [[ "$appserver" == *"/"* || "$appserver" == *"?"* || "$appserver" == *"#"* || "$appserver" == *$'\n'* || "$appserver" == *$'\r'* ]]; then
            log_error "Invalid app-server name in list"
            failure_count=$((failure_count + 1))
            continue
        fi
        if [ "$show_current" = "true" ]; then
            if show_appserver_security "$appserver"; then success_count=$((success_count + 1)); else failure_count=$((failure_count + 1)); fi
        else
            if configure_appserver_security "$appserver" "$config_name" "$remove_security" "$AUTHENTICATION_METHOD"; then success_count=$((success_count + 1)); else failure_count=$((failure_count + 1)); fi
        fi
        
        # Add separator between app servers (except for the last one)
        if [ "$success_count" -lt "$total_count" ]; then
            echo
        fi
    done
    
    log_info "Successfully processed $success_count of $total_count app servers"
    [ "$failure_count" -eq 0 ]
}

# ================================================================
# MAIN SCRIPT LOGIC
# ================================================================

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --appserver|--external-security|--authentication-method|--marklogic-host|--marklogic-port|--marklogic-user)
                if [ "$#" -lt 2 ] || [ -z "${2:-}" ]; then log_error "$1 requires a non-empty value"; return 1; fi
                ;;
        esac
        case $1 in
            --appserver)
                APPSERVER_NAMES="$2"
                shift 2
                ;;
            --external-security)
                EXTERNAL_SECURITY="$2"
                shift 2
                ;;
            --authentication-method)
                AUTHENTICATION_METHOD="$2"
                shift 2
                ;;
            --show-current)
                SHOW_CURRENT="true"
                shift
                ;;
            --remove-security)
                REMOVE_SECURITY="true"
                shift
                ;;
            --list-appservers)
                LIST_APPSERVERS="true"
                shift
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
    log_info "=== MarkLogic App Server Security Configuration Script ==="
    log_info "Version 1.0.0 - MarkLogic Security Hub"
    check_dependencies

    if [ "$LIST_APPSERVERS" = "true" ]; then
        if [ "$DRY_RUN" = "true" ]; then
            log_info "[DRY-RUN] Would GET /manage/v2/servers"
            exit 0
        fi
    elif [ -z "$APPSERVER_NAMES" ]; then
        log_error "App server name(s) required (--appserver)"
        show_usage
        exit 1
    fi

    if [ "$SHOW_CURRENT" != "true" ] && [ "$LIST_APPSERVERS" != "true" ] && [ "$REMOVE_SECURITY" != "true" ] && [ -z "$EXTERNAL_SECURITY" ]; then
        log_error "External security configuration name required (--external-security)"
        show_usage
        exit 1
    fi
    if [ "$SHOW_CURRENT" != "true" ] && [ "$LIST_APPSERVERS" != "true" ] && [ "$REMOVE_SECURITY" != "true" ]; then
        case "$AUTHENTICATION_METHOD" in oauth|saml|ldap|kerberos|certificate|basic) ;; *) log_error "A valid --authentication-method is required"; show_usage; exit 1 ;; esac
    fi
    if [ "$REMOVE_SECURITY" = "true" ] && [ -n "$EXTERNAL_SECURITY" ]; then
        log_error "Cannot use --remove-security with --external-security"
        show_usage
        exit 1
    fi
    if [ -n "$EXTERNAL_SECURITY" ] && [[ "$EXTERNAL_SECURITY" == *"/"* || "$EXTERNAL_SECURITY" == *"?"* || "$EXTERNAL_SECURITY" == *"#"* || "$EXTERNAL_SECURITY" == *$'\n'* || "$EXTERNAL_SECURITY" == *$'\r'* ]]; then
        log_error "Invalid external-security name"
        exit 1
    fi

    ml_parse_host_url "$MARKLOGIC_HOST"
    if [ "$DRY_RUN" != "true" ]; then
        [ -n "$MARKLOGIC_USER" ] || { log_error "MarkLogic user is required"; exit 1; }
        MARKLOGIC_PASS=$(ml_resolve_password) || exit 1
        test_marklogic_connection || exit 1
    fi

    if [ "$LIST_APPSERVERS" = "true" ]; then
        list_appservers
        exit $?
    fi

    local process_status
    if process_appservers "$APPSERVER_NAMES" "$EXTERNAL_SECURITY" "$REMOVE_SECURITY" "$SHOW_CURRENT"; then
        process_status=0
    else
        process_status=$?
    fi
    [ "$process_status" -eq 0 ] || exit "$process_status"

    if [ "$SHOW_CURRENT" != "true" ]; then
        log_info "Processed app servers: $APPSERVER_NAMES"
        if [ "$DRY_RUN" = "true" ]; then log_warning "DRY RUN - no requests or changes were made"; fi
    fi
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    parse_arguments "$@"
    main
fi