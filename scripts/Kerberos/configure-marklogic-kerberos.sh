#!/bin/bash

# ================================================================
# MarkLogic Kerberos Authentication Configuration Script
# ================================================================
#
# This script helps configure Kerberos authentication for MarkLogic Server
# including external security setup, app server configuration, service
# principal management, and keytab file handling.
#
# Features:
# - Configure external Kerberos security in MarkLogic
# - Set up app servers for Kerberos authentication
# - Generate and manage service principal names (SPNs)
# - Keytab file creation and validation
# - Kerberos ticket testing and troubleshooting
# - Support for multiple authentication modes (negotiate, basic+negotiate)
# - Cross-platform support (Windows AD, Linux MIT Kerberos)
#
# Author: Martin Warnes
# Version: 1.0.2
# Date: November 2025
#
# Usage:
#   ./configure-marklogic-kerberos.sh [COMMAND] [OPTIONS]
#
# Commands:
#   create-external-security    Create Kerberos external security
#   delete-external-security   Delete Kerberos external security
#   configure-appserver        Configure app server for Kerberos
#   create-spn                 Create service principal name
#   create-keytab              Create keytab file
#   test-kerberos              Test Kerberos authentication
#   validate-keytab            Validate keytab file
#   show-principals            Show existing principals
#   test-ticket                Test Kerberos ticket acquisition
#
# Examples:
#   # Create external Kerberos security
#   ./configure-marklogic-kerberos.sh create-external-security --name kerberos-auth \\
#       --kdc-host ad.example.com --realm EXAMPLE.COM
#
#   # Configure app server for Kerberos
#   ./configure-marklogic-kerberos.sh configure-appserver --appserver App-Services \\
#       --external-security kerberos-auth --auth-mode negotiate
#
#   # Create service principal and keytab
#   ./configure-marklogic-kerberos.sh create-spn --service HTTP \\
#       --hostname oauth.warnesnet.com --realm EXAMPLE.COM
#
#   # Test Kerberos authentication
#   KERBEROS_TEST_PASSWORD is read from the environment, or kinit prompts without echo
#   ./configure-marklogic-kerberos.sh test-ticket --principal user@EXAMPLE.COM \\
#       --service HTTP/oauth.warnesnet.com@EXAMPLE.COM
#
# ================================================================

set -euo pipefail

# Source common utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../marklogic-utils.sh"
source "$SCRIPT_DIR/kerberos-utils.sh"

# Default MarkLogic host (can be overridden by environment variable)
MARKLOGIC_HOST="${MARKLOGIC_HOST:-localhost}"
MARKLOGIC_PORT="${MARKLOGIC_PORT:-8002}"
MARKLOGIC_USER="${MARKLOGIC_USER:-}"
MARKLOGIC_PASS="${MARKLOGIC_PASS:-}"

# ================================================================
# CONFIGURATION VARIABLES
# ================================================================

# Default values
COMMAND=""
EXTERNAL_SECURITY_NAME=""
KDC_HOST=""
KDC_PORT="88"
REALM=""
LDAP_SERVER=""
LDAP_BASE=""
LDAP_BIND_METHOD="simple"
LDAP_USERNAME=""
LDAP_PASSWORD="${LDAP_BIND_PASSWORD:-}"
APPSERVER_NAME=""
AUTH_MODE="negotiate"
SERVICE_TYPE="HTTP"
HOSTNAME=""
PRINCIPAL_NAME=""
KEYTAB_FILE=""
TEST_PRINCIPAL=""
TEST_PASSWORD="${KERBEROS_TEST_PASSWORD:-}"
TEST_SERVICE=""
FORCE="false"
DRY_RUN="false"
VERBOSE="false"

kerberos_resolve_secret() {
    local env_name="$1" prompt="$2" value=""
    case "$env_name" in
        LDAP_BIND_PASSWORD) value="${LDAP_BIND_PASSWORD:-}" ;;
        *) ml_log_error "Unsupported secret input name"; return 1 ;;
    esac
    if [ -n "$value" ]; then printf '%s' "$value"; return 0; fi
    if [ ! -t 0 ]; then
        ml_log_error "Set $env_name for unattended use or run interactively for a hidden prompt"
        return 1
    fi
    read -r -s -p "$prompt" value
    printf '\n' >&2
    [ -n "$value" ] || { ml_log_error "$env_name cannot be empty"; return 1; }
    printf '%s' "$value"
}

kerberos_encode_path_segment() {
    local value="$1"
    [[ -n "$value" && "$value" != "." && "$value" != ".." && "$value" != *"/"* && "$value" != *"?"* && "$value" != *"#"* && "$value" != *$'\n'* && "$value" != *$'\r'* ]] || return 1
    jq -nr --arg value "$value" '$value|@uri'
}

kerberos_validate_resource_name() {
    local name="$1"
    [[ -n "$name" && "$name" != "." && "$name" != ".." && "$name" != *"/"* && "$name" != *"?"* && "$name" != *"#"* && "$name" != *$'\n'* && "$name" != *$'\r'* ]]
}

kerberos_check_external_security_exists() {
    local safe_name
    safe_name=$(kerberos_encode_path_segment "$1") || return 2
    ml_check_external_security_exists "$safe_name" "$2" "$3"
}

kerberos_create_secret_file() {
    if [ "$DRY_RUN" = "true" ]; then
        ml_log_error "Refusing to create an LDAP secret file in DRY_RUN"
        return 1
    fi
    local secret="$1" file
    file=$(mktemp) || return 1
    chmod 600 "$file" || { rm -f "$file"; return 1; }
    printf '%s' "$secret" > "$file" || { rm -f "$file"; return 1; }
    printf '%s' "$file"
}

kerberos_cleanup_secret_file() {
    [ -n "$1" ] && [ -f "$1" ] && rm -f "$1"
}

kerberos_validate_command_inputs() {
    case "$COMMAND" in
        create-external-security)
            [ -n "$EXTERNAL_SECURITY_NAME" ] && [ -n "$REALM" ] && [ -n "$HOSTNAME" ] || { ml_log_error "Creation requires --name, --realm, and --hostname"; return 1; }
            ;;
        delete-external-security) [ -n "$EXTERNAL_SECURITY_NAME" ] || { ml_log_error "Deletion requires --name"; return 1; } ;;
        configure-appserver) [ -n "$APPSERVER_NAME" ] && [ -n "$EXTERNAL_SECURITY_NAME" ] || { ml_log_error "App-server configuration requires --appserver and --external-security"; return 1; } ;;
        create-spn) [ -n "$HOSTNAME" ] && [ -n "$REALM" ] || { ml_log_error "SPN creation requires --hostname and --realm"; return 1; } ;;
        validate-keytab) [ -n "$KEYTAB_FILE" ] || { ml_log_error "--keytab-file is required"; return 1; } ;;
        test-ticket) [ -n "$TEST_PRINCIPAL" ] || { ml_log_error "--principal is required"; return 1; } ;;
        test-kerberos) [ -n "$APPSERVER_NAME" ] && [ -n "$TEST_PRINCIPAL" ] || { ml_log_error "Kerberos authentication testing requires --appserver and --principal"; return 1; } ;;
    esac

    if [ -n "$EXTERNAL_SECURITY_NAME" ] && ! kerberos_validate_resource_name "$EXTERNAL_SECURITY_NAME"; then ml_log_error "Invalid external-security name"; return 1; fi
    if [ -n "$APPSERVER_NAME" ] && ! kerberos_validate_resource_name "$APPSERVER_NAME"; then ml_log_error "Invalid app-server name"; return 1; fi
    if ! [[ "$SERVICE_TYPE" =~ ^[[:alnum:]_.-]+$ ]]; then ml_log_error "Invalid service type"; return 1; fi
    if [ -n "$REALM" ] && ! [[ "$REALM" =~ ^[[:alnum:]_.-]+$ ]]; then ml_log_error "Invalid Kerberos realm"; return 1; fi
    if [ -n "$HOSTNAME" ] && ! [[ "$HOSTNAME" =~ ^[[:alnum:].-]+$ ]]; then ml_log_error "Invalid service hostname"; return 1; fi
    if [ -n "$TEST_PRINCIPAL" ] && [[ "$TEST_PRINCIPAL" == *$'\n'* || "$TEST_PRINCIPAL" == *$'\r'* ]]; then ml_log_error "Principal must not contain line breaks"; return 1; fi
    if [ -n "$LDAP_SERVER" ]; then
        [[ "$LDAP_SERVER" =~ ^(ldap|ldaps)://[[:alnum:]._-]+(:([0-9]{1,5}))?$ ]] || { ml_log_error "Invalid LDAP server URI"; return 1; }
        local ldap_port="${BASH_REMATCH[4]:-}"
        if [ -n "$ldap_port" ] && { [ "$ldap_port" -lt 1 ] || [ "$ldap_port" -gt 65535 ]; }; then ml_log_error "Invalid LDAP server port"; return 1; fi
        case "$LDAP_BIND_METHOD" in simple|SASL|sasl) ;; *) ml_log_error "Invalid LDAP bind method"; return 1 ;; esac
    fi
    if [ -n "$KDC_PORT" ] && { ! [[ "$KDC_PORT" =~ ^[0-9]{1,5}$ ]] || [ "$KDC_PORT" -lt 1 ] || [ "$KDC_PORT" -gt 65535 ]; }; then ml_log_error "Invalid KDC port"; return 1; fi
    if [ -n "$TEST_SERVICE" ] && [[ "$TEST_SERVICE" == *$'\n'* || "$TEST_SERVICE" == *$'\r'* ]]; then ml_log_error "Service principal must not contain line breaks"; return 1; fi
    # ponytail: basic DN/control-character checks only; MarkLogic/LDAP performs the full syntax validation.
    if [ -n "$LDAP_BASE" ] && [[ "$LDAP_BASE" == *$'\n'* || "$LDAP_BASE" == *$'\r'* || "$LDAP_BASE" != *=* ]]; then ml_log_error "Invalid LDAP base DN"; return 1; fi
    if [ -n "$LDAP_USERNAME" ] && [[ "$LDAP_USERNAME" == *$'\n'* || "$LDAP_USERNAME" == *$'\r'* || "$LDAP_USERNAME" != *=* ]]; then ml_log_error "Invalid LDAP bind DN"; return 1; fi
    case "$AUTH_MODE" in negotiate|basic+negotiate) ;; *) ml_log_error "Invalid Kerberos authentication mode"; return 1 ;; esac
}

# ================================================================
# KERBEROS CONFIGURATION FUNCTIONS
# ================================================================

# Create external security configuration JSON
kerberos_create_external_security_json() {
    local external_security_json
    external_security_json=$(jq -n \
        --arg name "$EXTERNAL_SECURITY_NAME" \
        --arg realm "$REALM" \
        --arg hostname "$HOSTNAME" \
        '{"external-security-name":$name,"description":"Kerberos external security configuration created by script","authentication":"kerberos","cache-timeout":300,"authorization":"internal","kerberos-principal":("HTTP/" + $hostname + "@" + $realm),"kerberos-ticket-lifetime":900,"kerberos-user-principal-pattern":("{user}@" + $realm)}') || return 1

    if [ -n "$LDAP_SERVER" ]; then
        if [ -z "$LDAP_BASE" ] || [ -z "$LDAP_USERNAME" ] || [ -z "$LDAP_PASSWORD" ]; then
            ml_log_error "LDAP authorization requires a base DN, bind DN, and LDAP_BIND_PASSWORD"
            return 1
        fi
        local password_file
        password_file=$(kerberos_create_secret_file "$LDAP_PASSWORD") || return 1
        if external_security_json=$(jq -n --argjson config "$external_security_json" \
            --arg uri "$LDAP_SERVER" --arg base "$LDAP_BASE" --arg method "$LDAP_BIND_METHOD" --arg username "$LDAP_USERNAME" \
            --rawfile password "$password_file" \
            '$config + {"authorization":"ldap","ldap-server-uri":$uri,"ldap-base":$base,"ldap-bind-method":$method,"ldap-username":$username,"ldap-password":$password}'); then
            kerberos_cleanup_secret_file "$password_file"
        else
            kerberos_cleanup_secret_file "$password_file"
            return 1
        fi
    fi

    # The payload may contain an LDAP bind password; never log it.
    printf '%s\n' "$external_security_json"
}

# Create Kerberos external security
kerberos_create_external_security() {
    ml_log_step "Creating Kerberos external security: $EXTERNAL_SECURITY_NAME"

    # Validate required fields
    if [ -z "$EXTERNAL_SECURITY_NAME" ]; then
        ml_log_error "External security name is required"
        return 1
    fi

    if [ -z "$REALM" ]; then
        ml_log_error "Kerberos realm is required"
        return 1
    fi

    if [ -z "$HOSTNAME" ]; then
        ml_log_error "Service hostname is required"
        return 1
    fi

    # Check if external security already exists
    local existence_status
    if kerberos_check_external_security_exists "$EXTERNAL_SECURITY_NAME" "$MARKLOGIC_USER" "$MARKLOGIC_PASS"; then
        existence_status=0
    else
        existence_status=$?
    fi

    case $existence_status in
        0)  # Exists
            if [ "$FORCE" != "true" ]; then
                ml_log_error "External security '$EXTERNAL_SECURITY_NAME' already exists. Use --force to overwrite."
                return 1
            else
                ml_log_warning "Overwriting existing external security '$EXTERNAL_SECURITY_NAME'"
            fi
            ;;
        1)  # Does not exist - continue to create
            ;;
        2)  # Error
            ml_log_error "Failed to check external security existence (error)"
            return 1
            ;;
        3)  # Unknown in dry-run
            ml_log_info "[DRY-RUN] External security existence unknown - would check before creating"
            return 0
            ;;
        *)
            ml_log_error "Unexpected status from existence check: $existence_status"
            return 1
            ;;
    esac

    # Create external security JSON
    local external_security_json
    external_security_json=$(kerberos_create_external_security_json)

    # Apply external security to MarkLogic
    local response status_code
    if ml_api_call_with_dryrun response "POST" "/manage/v2/external-security" \
        "$MARKLOGIC_USER" "$MARKLOGIC_PASS" "$external_security_json"; then
        status_code=$(ml_extract_status_code "$response")
    else
        case $? in
            3) ml_log_info "[DRY-RUN] Would create Kerberos external security '$EXTERNAL_SECURITY_NAME'"; return 0 ;;
            *) ml_log_error "Failed to create Kerberos external security"; return 1 ;;
        esac
    fi

    case "$status_code" in
        201)
            ml_log_success "Kerberos external security '$EXTERNAL_SECURITY_NAME' created successfully"
            kerberos_show_next_steps
            return 0
            ;;
        409)
            if [ "$FORCE" = "true" ]; then
                ml_log_info "Updating existing external security..."
                kerberos_update_external_security "$external_security_json"
                return $?
            else
                ml_log_error "External security already exists (HTTP $status_code)"
                return 1
            fi
            ;;
        400)
            ml_log_error "Bad request - check external security parameters (HTTP $status_code)"
            ml_log_info "Response body suppressed because the request may contain LDAP credentials"
            return 1
            ;;
        *)
            ml_log_error "Failed to create external security (HTTP $status_code)"
            return 1
            ;;
    esac
}

# Update existing external security
kerberos_update_external_security() {
    local external_security_json="$1" security_path
    security_path=$(kerberos_encode_path_segment "$EXTERNAL_SECURITY_NAME") || return 1

    local response status_code
    if ml_api_call_with_dryrun response "PUT" "/manage/v2/external-security/$security_path" \
        "$MARKLOGIC_USER" "$MARKLOGIC_PASS" "$external_security_json"; then
        status_code=$(ml_extract_status_code "$response")
    else
        case $? in
            3) ml_log_info "[DRY-RUN] Would update Kerberos external security '$EXTERNAL_SECURITY_NAME'"; return 0 ;;
            *) ml_log_error "Failed to update Kerberos external security"; return 1 ;;
        esac
    fi

    case "$status_code" in
        204|200)
            ml_log_success "Kerberos external security '$EXTERNAL_SECURITY_NAME' updated successfully"
            kerberos_show_next_steps
            return 0
            ;;
        *)
            ml_log_error "Failed to update external security (HTTP $status_code)"
            return 1
            ;;
    esac
}

# Delete external security configuration
kerberos_delete_external_security() {
    ml_log_step "Deleting external security: $EXTERNAL_SECURITY_NAME"
    local security_path
    security_path=$(kerberos_encode_path_segment "$EXTERNAL_SECURITY_NAME") || return 1

    # Validate required fields
    if [ -z "$EXTERNAL_SECURITY_NAME" ]; then
        ml_log_error "External security name is required"
        return 1
    fi

    # Dry run mode - skip existence check since it requires API call
    if [ "$DRY_RUN" = "true" ]; then
        ml_log_info "[DRY RUN] Would delete external security '$EXTERNAL_SECURITY_NAME'"
        ml_log_verbose "[DRY RUN] DELETE /manage/v2/external-security/$security_path"
        ml_log_info "[DRY RUN] Use without --dry-run to actually delete"
        return 0
    fi

    # Check if external security exists (only when not in dry-run)
    local existence_status
    if kerberos_check_external_security_exists "$EXTERNAL_SECURITY_NAME" "$MARKLOGIC_USER" "$MARKLOGIC_PASS"; then
        existence_status=0
    else
        existence_status=$?
    fi

    case $existence_status in
        0)  # Exists - continue to delete
            ;;
        1)  # Does not exist
            ml_log_error "External security '$EXTERNAL_SECURITY_NAME' does not exist"
            return 1
            ;;
        2)  # Error
            ml_log_error "Failed to check external security existence (error)"
            return 1
            ;;
        3)  # Unknown - shouldn't happen here since we're not in dry-run mode
            ml_log_error "Unexpected unknown status from existence check"
            return 1
            ;;
        *)
            ml_log_error "Unexpected status from existence check: $existence_status"
            return 1
            ;;
    esac

    if ! ml_confirm "Delete Kerberos external security '$EXTERNAL_SECURITY_NAME'? Reliable rollback is unavailable; preserve recovery information separately." "n"; then
        ml_log_info "Deletion cancelled"
        return 0
    fi

    # Make DELETE request
    local response status_code
    if ml_api_call_with_dryrun response "DELETE" "/manage/v2/external-security/$security_path" \
        "$MARKLOGIC_USER" "$MARKLOGIC_PASS"; then
        status_code=$(ml_extract_status_code "$response")
    else
        case $? in
            3) ml_log_info "[DRY-RUN] Would delete Kerberos external security '$EXTERNAL_SECURITY_NAME'"; return 0 ;;
            *) ml_log_error "Failed to delete Kerberos external security"; return 1 ;;
        esac
    fi

    case "$status_code" in
        204|200)
            ml_log_success "External security '$EXTERNAL_SECURITY_NAME' deleted successfully"
            return 0
            ;;
        404)
            ml_log_error "External security '$EXTERNAL_SECURITY_NAME' not found (HTTP $status_code)"
            return 1
            ;;
        409)
            ml_log_error "External security '$EXTERNAL_SECURITY_NAME' is in use and cannot be deleted (HTTP $status_code)"
            ml_log_info "Remove external security from all app servers before deleting"
            return 1
            ;;
        400)
            ml_log_error "Bad request - check external security name (HTTP $status_code)"
            local response_body
            response_body=$(ml_extract_response_body "$response")
            ml_pretty_print_json "$response_body"
            return 1
            ;;
        *)
            ml_log_error "Failed to delete external security (HTTP $status_code)"
            local response_body
            response_body=$(ml_extract_response_body "$response")
            ml_pretty_print_json "$response_body"
            return 1
            ;;
    esac
}

# Configure app server for Kerberos authentication
kerberos_configure_appserver() {
    ml_log_step "Configuring app server '$APPSERVER_NAME' for Kerberos authentication"

    local appserver_path
    appserver_path=$(kerberos_encode_path_segment "$APPSERVER_NAME") || return 1
    local existence_status
    if kerberos_check_external_security_exists "$EXTERNAL_SECURITY_NAME" "$MARKLOGIC_USER" "$MARKLOGIC_PASS"; then
        existence_status=0
    else
        existence_status=$?
    fi

    case $existence_status in
        0)  # Exists - continue
            ;;
        1)  # Does not exist
            ml_log_error "External security '$EXTERNAL_SECURITY_NAME' does not exist"
            return 1
            ;;
        2)  # Error
            ml_log_error "Failed to check external security existence (error)"
            return 1
            ;;
        3)  # Unknown in dry-run
            ml_log_info "[DRY-RUN] External security existence unknown - would verify before configuring app server"
            return 0
            ;;
        *)
            ml_log_error "Unexpected status from existence check: $existence_status"
            return 1
            ;;
    esac

    # Get current app server configuration
    local response status_code
    if ml_api_call_with_dryrun response "GET" "/manage/v2/servers/$appserver_path/properties" \
        "$MARKLOGIC_USER" "$MARKLOGIC_PASS"; then
        status_code=$(ml_extract_status_code "$response")
    else
        case $? in
            3) ml_log_info "[DRY-RUN] Would read app server '$APPSERVER_NAME' configuration"; return 0 ;;
            *) ml_log_error "Failed to read app server configuration"; return 1 ;;
        esac
    fi

    if [ "$status_code" != "200" ]; then
        ml_log_error "App server '$APPSERVER_NAME' not found (HTTP $status_code)"
        return 1
    fi

    # Build Kerberos configuration
    local kerberos_config
    kerberos_config=$(jq -n --arg authentication "$AUTH_MODE" --arg external_security "$EXTERNAL_SECURITY_NAME" \
        '{"authentication":$authentication,"external-security":$external_security}') || return 1

    if ! ml_confirm "Apply Kerberos authentication settings to app server '$APPSERVER_NAME'?" "n"; then
        ml_log_info "App-server update cancelled"
        return 0
    fi

    # Update app server configuration
    if ml_api_call_with_dryrun response "PUT" "/manage/v2/servers/$appserver_path/properties" \
        "$MARKLOGIC_USER" "$MARKLOGIC_PASS" "$kerberos_config"; then
        status_code=$(ml_extract_status_code "$response")
    else
        case $? in
            3) ml_log_info "[DRY-RUN] Would configure Kerberos on app server '$APPSERVER_NAME'"; return 0 ;;
            *) ml_log_error "Failed to configure Kerberos on app server"; return 1 ;;
        esac
    fi

    case "$status_code" in
        204)
            ml_log_success "Kerberos authentication configured for app server '$APPSERVER_NAME'"
            ml_log_info "External Security: $EXTERNAL_SECURITY_NAME"
            ml_log_info "Authentication Mode: $AUTH_MODE"

            ml_log_warning "MarkLogic Server restart may be required for authentication changes to take effect"
            return 0
            ;;
        *)
            ml_log_error "Failed to configure Kerberos authentication (HTTP $status_code)"
            local response_body
            response_body=$(ml_extract_response_body "$response")
            ml_pretty_print_json "$response_body"
            return 1
            ;;
    esac
}

# Show next steps after configuration
kerberos_show_next_steps() {
    echo
    ml_log_info "Next steps:"
    ml_log_info "1. Create service principal: HTTP/${HOSTNAME}@${REALM}"
    ml_log_info "2. Create keytab file for the service principal"
    ml_log_info "3. Place keytab file in MarkLogic data directory"
    ml_log_info "4. Configure app servers to use this external security"
    ml_log_info "5. Test Kerberos authentication"
}

# ================================================================
# SERVICE PRINCIPAL AND KEYTAB MANAGEMENT
# ================================================================

# Create service principal name
kerberos_create_spn() {
    ml_log_step "Creating service principal: $SERVICE_TYPE/$HOSTNAME@$REALM"

    # Validate required fields
    if [ -z "$SERVICE_TYPE" ] || [ -z "$HOSTNAME" ] || [ -z "$REALM" ]; then
        ml_log_error "Service type, hostname, and realm are required"
        return 1
    fi

    local spn="$SERVICE_TYPE/$HOSTNAME@$REALM"

    # Detect platform and provide appropriate commands
    if command -v kadmin >/dev/null 2>&1; then
        # MIT Kerberos (Linux/Unix)
        ml_log_info "MIT Kerberos detected. Use the following commands:"
        echo
        echo "# Connect to Kerberos admin server:"
        echo "kadmin -p admin@$REALM"
        echo
        echo "# Create the service principal:"
        echo "addprinc -randkey $spn"
        echo
        echo "# Create keytab file:"
        echo "ktadd -k /path/to/marklogic.keytab $spn"
        echo
        echo "# Exit kadmin:"
        echo "quit"

    elif command -v setspn >/dev/null 2>&1; then
        # Windows Active Directory
        ml_log_info "Windows Active Directory detected. Use the following commands:"
        echo
        echo "# Create the service principal name:"
        echo "setspn -A $SERVICE_TYPE/$HOSTNAME <service-account>"
        echo
        echo "# Create keytab file:"
        echo "ktpass -princ $spn -mapuser <service-account> -crypto ALL -ptype KRB5_NT_PRINCIPAL -out marklogic.keytab"

    else
        # Generic instructions
        ml_log_info "Generic Kerberos setup instructions:"
        echo
        echo "Service Principal Name: $spn"
        echo
        echo "For MIT Kerberos:"
        echo "  kadmin -p admin@$REALM"
        echo "  addprinc -randkey $spn"
        echo "  ktadd -k /path/to/marklogic.keytab $spn"
        echo
        echo "For Windows AD:"
        echo "  setspn -A $SERVICE_TYPE/$HOSTNAME <service-account>"
        echo "  ktpass -princ $spn -mapuser <service-account> -crypto ALL -ptype KRB5_NT_PRINCIPAL -out marklogic.keytab"
    fi

    echo
    ml_log_warning "After creating the keytab file:"
    ml_log_warning "1. Copy it to MarkLogic data directory"
    ml_log_warning "2. Set appropriate file permissions (readable by MarkLogic process)"
    ml_log_warning "3. Update MarkLogic configuration if needed"

    return 0
}

# Validate keytab file
kerberos_validate_keytab() {
    if [ "$DRY_RUN" = "true" ]; then
        ml_log_info "[DRY-RUN] Would check keytab file and inspect it with klist -kt"
        return 0
    fi
    ml_log_step "Validating keytab file: $KEYTAB_FILE"

    if [ ! -f "$KEYTAB_FILE" ]; then
        ml_log_error "Keytab file not found: $KEYTAB_FILE"
        return 1
    fi

    # Check file permissions
    local file_perms
    file_perms=$(stat -c "%a" "$KEYTAB_FILE" 2>/dev/null || stat -f "%A" "$KEYTAB_FILE" 2>/dev/null)
    ml_log_info "File permissions: $file_perms"

    if [ "${file_perms: -1}" != "0" ] && [ "${file_perms: -1}" != "4" ]; then
        ml_log_warning "Keytab file is readable by others. Consider changing permissions to 640 or 600."
    fi

    # Check if klist is available
    if command -v klist >/dev/null 2>&1; then
        ml_log_info "Keytab contents:"
        if klist -kt "$KEYTAB_FILE"; then
            ml_log_success "Keytab file format is valid"
        else
            ml_log_error "Invalid keytab file format"
            return 1
        fi
    else
        ml_log_warning "klist command not found. Cannot validate keytab contents."
        ml_log_info "Install Kerberos client tools to validate keytab files"
    fi

    return 0
}

# Show principals in keytab
kerberos_show_principals() {
    if [ "$DRY_RUN" = "true" ]; then
        ml_log_info "[DRY-RUN] Would list principals from the selected keytab or current cache"
        return 0
    fi
    if [ -n "$KEYTAB_FILE" ]; then
        ml_log_step "Showing principals in keytab: $KEYTAB_FILE"
        kerberos_validate_keytab
    else
        ml_log_step "Showing system principals"

        if command -v klist >/dev/null 2>&1; then
            if klist 2>/dev/null; then
                ml_log_success "Current Kerberos tickets displayed"
            else
                ml_log_info "No current Kerberos tickets"
            fi
        else
            ml_log_error "klist command not found. Install Kerberos client tools."
            return 1
        fi
    fi
}

# ================================================================
# KERBEROS TESTING FUNCTIONS
# ================================================================

kerberos_test_ticket_in_cache() {
    kerberos_acquire_ticket "$TEST_PRINCIPAL" "$TEST_PASSWORD" "" || return 1
    if [ -n "$TEST_SERVICE" ]; then
        kerberos_test_service_ticket "$TEST_SERVICE" || return 1
    fi
    return 0
}

# Test Kerberos ticket acquisition without changing the caller's ticket cache.
kerberos_test_ticket() {
    if [ "$DRY_RUN" = "true" ]; then
        ml_log_info "[DRY-RUN] Would acquire a test ticket in a private cache"
        return 0
    fi
    [ -n "$TEST_PRINCIPAL" ] || { ml_log_error "Test principal is required"; return 1; }
    command -v kinit >/dev/null 2>&1 || { ml_log_error "kinit command not found"; return 1; }
    if [ -z "$TEST_PASSWORD" ] && [ ! -t 0 ]; then
        ml_log_error "Set KERBEROS_TEST_PASSWORD for non-interactive ticket tests"
        return 1
    fi
    ml_log_step "Testing Kerberos ticket acquisition for '$TEST_PRINCIPAL' in a private cache"
    kerberos_run_with_private_cache kerberos_test_ticket_in_cache
}

# Test Kerberos authentication with MarkLogic
kerberos_http_auth_in_private_cache() {
    local app_server_port="$1" curl_output
    kerberos_acquire_ticket "$TEST_PRINCIPAL" "$TEST_PASSWORD" "" || return 1
    if curl_output=$(curl -s -f --negotiate -u : "${ML_PROTOCOL:-http}://${ML_HOST}:${app_server_port}/"); then
        ml_log_success "Kerberos authentication test succeeded"
        return 0
    fi
    ml_log_error "Kerberos authentication test failed; check the app-server configuration and test principal"
    return 1
}

kerberos_test_authentication() {
    if [ "$DRY_RUN" = "true" ]; then
        ml_log_info "[DRY-RUN] Would retrieve app-server details and test Kerberos authentication in a private cache"
        return 0
    fi
    [ -n "$APPSERVER_NAME" ] || { ml_log_error "App server name is required for authentication testing"; return 1; }
    [ -n "$TEST_PRINCIPAL" ] || { ml_log_error "A test principal is required to use a private ticket cache"; return 1; }
    if [ -z "$TEST_PASSWORD" ] && [ ! -t 0 ]; then
        ml_log_error "Set KERBEROS_TEST_PASSWORD for non-interactive authentication tests"
        return 1
    fi

    local appserver_path response status_code app_server_port
    appserver_path=$(kerberos_encode_path_segment "$APPSERVER_NAME") || return 1
    if ! ml_api_call_with_dryrun response "GET" "/manage/v2/servers/$appserver_path/properties?format=json" \
        "$MARKLOGIC_USER" "$MARKLOGIC_PASS"; then
        ml_log_error "Failed to read app-server configuration"
        return 1
    fi
    status_code=$(ml_extract_status_code "$response")
    [ "$status_code" = "200" ] || { ml_log_error "Failed to read app-server configuration (HTTP $status_code)"; return 1; }
    app_server_port=$(ml_extract_response_body "$response" | jq -r '.port // empty')
    [[ "$app_server_port" =~ ^[0-9]{1,5}$ ]] && [ "$app_server_port" -ge 1 ] && [ "$app_server_port" -le 65535 ] || {
        ml_log_error "Could not determine a valid app-server port"
        return 1
    }
    kerberos_run_with_private_cache kerberos_http_auth_in_private_cache "$app_server_port"
}

# ================================================================
# COMMAND LINE INTERFACE
# ================================================================

show_usage() {
    cat << EOF
Usage: $0 [COMMAND] [OPTIONS]

MarkLogic Kerberos Authentication Configuration Script

COMMANDS:
    create-external-security    Create Kerberos external security
    delete-external-security   Delete Kerberos external security (manual recovery only)
    configure-appserver        Configure app server for Kerberos
    create-spn                 Display service-principal setup commands (read-only)
    validate-keytab            Validate keytab file (read-only)
    show-principals            Show existing principals (read-only)
    test-ticket                Test Kerberos ticket acquisition in a private cache
    test-kerberos              Test Kerberos authentication in a private cache

CREATE-EXTERNAL-SECURITY OPTIONS:
    --name NAME                   External security name (required)
    --realm REALM                 Kerberos realm (required)
    --hostname HOSTNAME           Service hostname (required)
    --kdc-host HOST               KDC hostname (optional)
    --kdc-port PORT               KDC port (default: 88)
    --ldap-server URI             LDAP server URI (for authorization)
    --ldap-base DN                LDAP base DN
    --ldap-bind-method METHOD     LDAP bind method (default: simple)
    --ldap-username USER          LDAP bind username
    --ldap-password PASS          Rejected; use LDAP_BIND_PASSWORD or a hidden prompt
    --force                       Overwrite existing external security

DELETE-EXTERNAL-SECURITY OPTIONS:
    --name NAME                   External security name to delete (required)
    --dry-run                     Show what would be done without executing
    --verbose                     Enable verbose logging

CONFIGURE-APPSERVER OPTIONS:
    --appserver NAME              App server name (required)
    --external-security NAME      External security name (required)
    --auth-mode MODE              Authentication mode: negotiate, basic+negotiate (default: negotiate)

CREATE-SPN OPTIONS:
    --service SERVICE             Service type (default: HTTP)
    --hostname HOSTNAME           Service hostname (required)
    --realm REALM                 Kerberos realm (required)

VALIDATE-KEYTAB OPTIONS:
    --keytab-file FILE            Keytab file path (required)

SHOW-PRINCIPALS OPTIONS:
    --keytab-file FILE            Keytab file path (optional, shows current tickets if not provided)

TEST-TICKET OPTIONS:
    --principal PRINCIPAL         Test principal name (required)
    --password PASSWORD           Rejected; use KERBEROS_TEST_PASSWORD or kinit's hidden prompt
    --service SERVICE             Service principal for ticket test (optional)
    --test-service SERVICE        Explicit alias for the test service principal

TEST-KERBEROS OPTIONS:
    --appserver NAME              App server name (required)
    --principal PRINCIPAL         Test principal name (required)

KERBEROS PASSWORD INPUT:
    Set KERBEROS_TEST_PASSWORD for unattended ticket tests; interactive kinit prompts without echo.
    Set LDAP_BIND_PASSWORD for LDAP authorization; interactive use prompts without echo.
    Ticket tests use a private cache and do not alter the caller's cache.

RECOVERY:
    External-security deletes/overwrites and app-server updates have no automatic rollback.
    Preserve exact prior configuration and document manual recovery before changes.

$(ml_show_common_usage)

EXAMPLES:
    # Create Kerberos external security
    $0 create-external-security --name kerberos-auth \\
        --realm EXAMPLE.COM --hostname marklogic.example.com

    # Create with LDAP authorization (interactive prompt for LDAP_BIND_PASSWORD)
    $0 create-external-security --name kerberos-ldap-auth \\
        --realm EXAMPLE.COM --hostname marklogic.example.com \\
        --ldap-server "ldap://ad.example.com:389" \\
        --ldap-base "DC=example,DC=com" \\
        --ldap-username "CN=svc-marklogic,CN=Users,DC=example,DC=com"

    # Configure app server for Kerberos
    $0 configure-appserver --appserver App-Services \\
        --external-security kerberos-auth --auth-mode negotiate

    # Show SPN creation commands
    $0 create-spn --service HTTP --hostname marklogic.example.com \\
        --realm EXAMPLE.COM

    # Validate keytab file
    $0 validate-keytab --keytab-file /opt/MarkLogic/marklogic.keytab

    # Test ticket acquisition; uses a private cache and a hidden prompt if needed
    $0 test-ticket --principal user@EXAMPLE.COM \\
        --service HTTP/marklogic.example.com@EXAMPLE.COM

    # Test Kerberos authentication
    $0 test-kerberos --appserver App-Services --principal user@EXAMPLE.COM

    # Delete external security (dry run first)
    $0 delete-external-security --name kerberos-auth --dry-run

    # Delete external security
    $0 delete-external-security --name kerberos-auth

EOF
}

# Parse command line arguments
parse_arguments() {
    if [ "$#" -eq 0 ]; then show_usage; return 1; fi
    if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then show_usage; exit 0; fi
    COMMAND="$1"
    shift

    while [ "$#" -gt 0 ]; do
        case "$1" in
            --name|--realm|--hostname|--kdc-host|--kdc-port|--ldap-server|--ldap-base|--ldap-bind-method|--ldap-username|--appserver|--external-security|--auth-mode|--service|--test-service|--keytab-file|--principal|--marklogic-host|--marklogic-port|--marklogic-user)
                if [ "$#" -lt 2 ] || [ -z "${2:-}" ]; then ml_log_error "$1 requires a non-empty value"; return 1; fi
                ;;
        esac
        case "$1" in
            --name) EXTERNAL_SECURITY_NAME="$2"; shift 2 ;;
            --realm) REALM="$2"; shift 2 ;;
            --hostname) HOSTNAME="$2"; shift 2 ;;
            --kdc-host) KDC_HOST="$2"; shift 2 ;;
            --kdc-port) KDC_PORT="$2"; shift 2 ;;
            --ldap-server) LDAP_SERVER="$2"; shift 2 ;;
            --ldap-base) LDAP_BASE="$2"; shift 2 ;;
            --ldap-bind-method) LDAP_BIND_METHOD="$2"; shift 2 ;;
            --ldap-username) LDAP_USERNAME="$2"; shift 2 ;;
            --ldap-password)
                ml_log_error "--ldap-password VALUE is rejected"
                ml_log_error "Set LDAP_BIND_PASSWORD or use the hidden interactive prompt"
                return 1
                ;;
            --appserver) APPSERVER_NAME="$2"; shift 2 ;;
            --external-security) EXTERNAL_SECURITY_NAME="$2"; shift 2 ;;
            --auth-mode) AUTH_MODE="$2"; shift 2 ;;
            --service)
                if [ "$COMMAND" = "test-ticket" ] || [ "$COMMAND" = "test-kerberos" ]; then TEST_SERVICE="$2"; else SERVICE_TYPE="$2"; fi
                shift 2
                ;;
            --test-service) TEST_SERVICE="$2"; shift 2 ;;
            --keytab-file) KEYTAB_FILE="$2"; shift 2 ;;
            --principal) TEST_PRINCIPAL="$2"; shift 2 ;;
            --password)
                ml_log_error "--password VALUE is rejected"
                ml_log_error "Set KERBEROS_TEST_PASSWORD or use kinit's hidden prompt"
                return 1
                ;;
            --marklogic-host) MARKLOGIC_HOST="$2"; shift 2 ;;
            --marklogic-port) MARKLOGIC_PORT="$2"; shift 2 ;;
            --marklogic-user) MARKLOGIC_USER="$2"; shift 2 ;;
            --marklogic-pass)
                ml_log_error "--marklogic-pass VALUE is no longer supported"
                ml_log_error "Use MARKLOGIC_PASS or an interactive hidden prompt"
                return 1
                ;;
            --insecure) INSECURE=true; shift ;;
            --verbose) VERBOSE=true; shift ;;
            --dry-run) DRY_RUN=true; shift ;;
            --yes) YES=true; shift ;;
            --force) FORCE=true; shift ;;
            --help|-h) show_usage; exit 0 ;;
            *) ml_log_error "Unknown argument"; show_usage; return 1 ;;
        esac
    done
}

# Main execution function
main() {
    ml_show_header "MarkLogic Kerberos Authentication" "1.0.0" \
        "Configure Kerberos authentication for MarkLogic Server"

    ml_check_dependencies || exit 1
    kerberos_validate_command_inputs || exit 1

    local needs_marklogic=false
    case "$COMMAND" in
        create-external-security|delete-external-security|configure-appserver|test-kerberos) needs_marklogic=true ;;
    esac
    if [ "$DRY_RUN" != "true" ] && [ "$needs_marklogic" = true ]; then
        [ -n "$MARKLOGIC_USER" ] || { ml_log_error "MarkLogic user is required (--marklogic-user or MARKLOGIC_USER)"; exit 1; }
        MARKLOGIC_PASS=$(ml_resolve_password) || exit 1
    fi
    if [ "$DRY_RUN" != "true" ] && [ "$COMMAND" = "create-external-security" ] && [ -n "$LDAP_SERVER" ] && [ -z "$LDAP_PASSWORD" ]; then
        LDAP_PASSWORD=$(kerberos_resolve_secret LDAP_BIND_PASSWORD "LDAP bind password: ") || exit 1
    fi
    if [ "$DRY_RUN" != "true" ] && [[ "$COMMAND" =~ ^(test-ticket|test-kerberos)$ ]] && [ -z "$TEST_PASSWORD" ] && [ ! -t 0 ]; then
        ml_log_error "Set KERBEROS_TEST_PASSWORD for non-interactive ticket tests"
        exit 1
    fi

    ml_parse_host_url "$MARKLOGIC_HOST"
    if [ "$DRY_RUN" != "true" ] && [ "$needs_marklogic" = true ]; then
        ml_test_connectivity || exit 1
        echo
    fi

    set +e
    case "$COMMAND" in
        create-external-security) kerberos_create_external_security ;;
        delete-external-security) kerberos_delete_external_security ;;
        configure-appserver) kerberos_configure_appserver ;;
        create-spn) kerberos_create_spn ;;
        validate-keytab) kerberos_validate_keytab ;;
        show-principals) kerberos_show_principals ;;
        test-ticket) kerberos_test_ticket ;;
        test-kerberos) kerberos_test_authentication ;;
        *) ml_log_error "Unknown command: $COMMAND"; show_usage; exit 1 ;;
    esac
    local exit_code=$?
    set -e

    if [ "$exit_code" -eq 0 ]; then
        echo
        case "$COMMAND" in
            create-external-security)
                ml_show_footer "1. Create service principal: $0 create-spn --service HTTP --hostname $HOSTNAME --realm $REALM
2. Create and configure keytab file
3. Configure app server: $0 configure-appserver --appserver <NAME> --external-security $EXTERNAL_SECURITY_NAME
4. Test authentication: $0 test-kerberos --appserver <NAME> --principal <principal>"
                ;;
            configure-appserver)
                ml_show_footer "1. Restart MarkLogic Server if needed
2. Test authentication: $0 test-kerberos --appserver $APPSERVER_NAME --principal <principal>
3. Verify with Kerberos-enabled client"
                ;;
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