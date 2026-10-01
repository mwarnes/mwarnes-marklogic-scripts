#!/bin/bash

# ================================================================
# MarkLogic LDAP Authentication Configuration Script
# ================================================================
#
# This script helps configure LDAP authentication for MarkLogic Server
# including external security setup, app server configuration, user
# mapping, group management, and LDAP directory integration.
#
# Features:
# - Configure external LDAP security in MarkLogic
# - Set up app servers for LDAP authentication
# - Test LDAP connectivity and authentication
# - User and group mapping configuration
# - Support for Active Directory and OpenLDAP
# - SSL/TLS LDAP connections (LDAPS)
# - Bind authentication methods (simple, SASL)
# - User search and attribute mapping
#
# Author: Martin Warnes
# Version: 1.0.3
# Date: May 2026
#
# Usage:
#   ./configure-marklogic-ldap.sh [COMMAND] [OPTIONS]
#
# Commands:
#   create-external-security    Create LDAP external security
#   configure-appserver        Configure app server for LDAP
#   test-ldap                  Test LDAP connectivity and authentication
#   search-users               Search for LDAP users
#   search-groups              Search for LDAP groups
#   validate-config            Validate LDAP configuration
#   show-schema                Show LDAP schema information
#
# Examples:
#   # Create external LDAP security for Active Directory
#   ./configure-marklogic-ldap.sh create-external-security --name ldap-auth \\
#       --ldap-server "ldaps://ad.example.com:636" \\
#       --ldap-base "DC=example,DC=com" \\
#       --bind-method simple --bind-username "CN=svc-marklogic,CN=Users,DC=example,DC=com"
#
#   # Create for OpenLDAP
#   ./configure-marklogic-ldap.sh create-external-security --name openldap-auth \\
#       --ldap-server "ldap://ldap.example.com:389" \\
#       --ldap-base "ou=people,dc=example,dc=com" \\
#       --bind-method simple --bind-username "cn=marklogic,ou=services,dc=example,dc=com"
#
#   # Configure app server for LDAP
#   ./configure-marklogic-ldap.sh configure-appserver --appserver App-Services \\
#       --external-security ldap-auth --auth-mode digest
#
#   # Test LDAP authentication
#   ./configure-marklogic-ldap.sh test-ldap --external-security ldap-auth \\
#       --test-user jdoe  (set LDAP_TEST_PASSWORD in the environment or enter it at the hidden prompt)
#
# ================================================================

set -euo pipefail

# Source common utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../marklogic-utils.sh"
source "$SCRIPT_DIR/ldap-utils.sh"

# ================================================================
# CONFIGURATION VARIABLES
# ================================================================

# MarkLogic connection settings
MARKLOGIC_HOST="${MARKLOGIC_HOST:-localhost}"
MARKLOGIC_PORT="${MARKLOGIC_PORT:-8002}"
MARKLOGIC_USER="${MARKLOGIC_USER:-}"
MARKLOGIC_PASS="${MARKLOGIC_PASS:-}"

# Default values
COMMAND=""
EXTERNAL_SECURITY_NAME=""
LDAP_SERVER=""
LDAP_BASE=""
LDAP_BIND_METHOD="simple"
LDAP_USERNAME=""
LDAP_PASSWORD="${LDAP_BIND_PASSWORD:-}"
LDAP_ATTRIBUTE="uid"
AUTHORIZATION="internal"
MEMBEROF_ATTRIBUTE=""
MEMBER_ATTRIBUTE=""
NESTED_LOOKUP="false"
START_TLS="false"
CERTIFICATE_FILE=""
CLIENT_CERT_FILE=""
CLIENT_KEY_FILE=""
CA_FILE=""
APPSERVER_NAME=""
AUTH_MODE="digest"
APPSERVER_GROUP="${APPSERVER_GROUP:-Default}"
SEARCH_FILTER=""
SEARCH_BASE=""
SEARCH_SCOPE="sub"
TEST_USER=""
TEST_PASSWORD="${LDAP_TEST_PASSWORD:-}"
MAX_RESULTS="100"
FORCE="false"
DRY_RUN="false"

# Resolve protocol credentials only for live operations; never accept a secret in argv.
ldap_resolve_secret() {
    local env_name="$1" prompt="$2" value=""
    case "$env_name" in
        LDAP_BIND_PASSWORD) value="${LDAP_BIND_PASSWORD:-}" ;;
        LDAP_TEST_PASSWORD) value="${LDAP_TEST_PASSWORD:-}" ;;
        *) ml_log_error "Unsupported secret input name"; return 1 ;;
    esac
    if [ -n "$value" ]; then
        printf '%s' "$value"
        return 0
    fi
    if [ ! -t 0 ]; then
        ml_log_error "Set $env_name for unattended use or run interactively for a hidden prompt"
        return 1
    fi
    read -r -s -p "$prompt" value
    printf '\n' >&2
    [ -n "$value" ] || { ml_log_error "$env_name cannot be empty"; return 1; }
    printf '%s' "$value"
}

# ponytail: structural DN check, not a full RFC4514 parser; the LDAP server remains the syntax authority.
ldap_validate_dn_input() {
    local dn="$1" escaped=false found_equal=false attribute="" char next backslash=$'\\' i
    [[ -n "$dn" && "$dn" != *$'\n'* && "$dn" != *$'\r'* ]] || return 1
    for ((i = 0; i < ${#dn}; i++)); do
        char=${dn:i:1}
        if [ "$escaped" = true ]; then
            escaped=false
            [ "$found_equal" = true ] || return 1
            if [[ "$char" =~ ^[[:xdigit:]]$ ]]; then
                ((i + 1 < ${#dn})) || return 1
                next=${dn:i+1:1}
                [[ "$next" =~ ^[[:xdigit:]]$ ]] || return 1
                i=$((i + 1))
            elif [[ "$char" != "," && "$char" != "+" && "$char" != '"' && "$char" != "$backslash" && "$char" != "<" && "$char" != ">" && "$char" != ";" && "$char" != "=" && "$char" != "#" && "$char" != " " ]]; then
                return 1
            fi
            continue
        fi
        if [ "$char" = "$backslash" ]; then escaped=true
        elif [ "$char" = "=" ]; then
            [ "$found_equal" != true ] && [ -n "$attribute" ] && ldap_validate_attribute_descriptor "$attribute" || return 1
            found_equal=true
        elif [ "$char" = "," ] || [ "$char" = "+" ]; then
            [ "$found_equal" = true ] || return 1
            found_equal=false
            attribute=""
        elif [ "$found_equal" != true ]; then
            attribute+="$char"
        fi
    done
    [ "$escaped" = false ] && [ "$found_equal" = true ]
}

# ponytail: checks balanced filters and RFC4515 escapes; it does not parse the full filter grammar.
ldap_validate_filter_input() {
    local filter="$1" backslash=$'\\' depth=0 char next i
    [[ "$filter" == \(*\) && "$filter" != *$'\n'* && "$filter" != *$'\r'* ]] || return 1
    for ((i = 0; i < ${#filter}; i++)); do
        char=${filter:i:1}
        if [ "$char" = "$backslash" ]; then
            ((i + 2 < ${#filter})) || return 1
            next=${filter:i+1:2}
            [[ "$next" =~ ^[[:xdigit:]]{2}$ ]] || return 1
            i=$((i + 2))
        elif [ "$char" = "(" ]; then
            depth=$((depth + 1))
        elif [ "$char" = ")" ]; then
            depth=$((depth - 1))
            [ "$depth" -ge 0 ] || return 1
        fi
    done
    [ "$depth" -eq 0 ]
}

# ponytail: accepts DNS/IPv4 hosts only; add bracketed IPv6 parsing if deployments need literals.
ldap_validate_server_uri() {
    local uri="$1" port
    [[ "$uri" =~ ^(ldap|ldaps)://([[:alnum:]._-]+)(:([0-9]{1,5}))?$ ]] || return 1
    port="${BASH_REMATCH[4]:-}"
    [ -z "$port" ] || { [ "$port" -ge 1 ] && [ "$port" -le 65535 ]; }
}

ldap_validate_resource_name() {
    local name="$1"
    [[ -n "$name" && "$name" != "." && "$name" != ".." && "$name" != *"/"* && "$name" != *"?"* && "$name" != *"#"* && "$name" != *$'\n'* && "$name" != *$'\r'* ]]
}

ldap_encode_path_segment() {
    local value="$1"
    [[ -n "$value" && "$value" != "." && "$value" != ".." && "$value" != *"/"* && "$value" != *"?"* && "$value" != *"#"* && "$value" != *$'\n'* && "$value" != *$'\r'* ]] || return 1
    jq -nr --arg value "$value" '$value|@uri'
}

ldap_check_external_security_exists() {
    local safe_name
    safe_name=$(ldap_encode_path_segment "$1") || return 2
    ml_check_external_security_exists "$safe_name" "$2" "$3"
}

ldap_run_search() {
    local bind_dn="$1" password="$2" password_file="" status
    shift 2
    # $1 is the command (ldapsearch); everything after it may include the filter and a list of
    # attributes to return. Options such as -D/-y/-Z must come BEFORE those positional arguments,
    # otherwise ldapsearch reads them as attribute names and silently searches anonymously.
    local cmd="$1"
    shift
    local -a bind_args=()

    if [ -n "$bind_dn" ] && [ -n "$password" ]; then
        password_file=$(ldap_create_password_file "$password") || return 1
        bind_args+=(-D "$bind_dn" -y "$password_file")
    elif [ -n "$bind_dn" ] || [ -n "$password" ]; then
        ml_log_error "Both LDAP bind DN and password are required for authenticated searches"
        return 1
    fi
    [ "$START_TLS" = "true" ] && bind_args+=(-Z)
    if "$cmd" ${bind_args[@]+"${bind_args[@]}"} "$@"; then status=0; else status=$?; fi
    [ -z "$password_file" ] || ldap_cleanup_password_file "$password_file"
    return "$status"
}

ldap_validate_command_inputs() {
    case "$COMMAND" in
        create-external-security)
            [ -n "$EXTERNAL_SECURITY_NAME" ] && [ -n "$LDAP_SERVER" ] && [ -n "$LDAP_BASE" ] && [ -n "$LDAP_USERNAME" ] || { ml_log_error "Creation requires --name, --ldap-server, --ldap-base, and --bind-username"; return 1; }
            ;;
        configure-appserver)
            [ -n "$APPSERVER_NAME" ] && [ -n "$EXTERNAL_SECURITY_NAME" ] || { ml_log_error "App-server configuration requires --appserver and --external-security"; return 1; }
            ;;
        delete-external-security)
            [ -n "$EXTERNAL_SECURITY_NAME" ] || { ml_log_error "Deletion requires --name"; return 1; }
            ;;
        test-ldap)
            [ -n "$EXTERNAL_SECURITY_NAME" ] && [ -n "$TEST_USER" ] || { ml_log_error "LDAP testing requires --external-security and --test-user"; return 1; }
            ;;
        search-users|search-groups|validate-config|show-schema)
            [ -n "$LDAP_SERVER" ] || [ -n "$EXTERNAL_SECURITY_NAME" ] || { ml_log_error "Provide --ldap-server or --external-security"; return 1; }
            ;;
    esac
    [ -z "$LDAP_SERVER" ] || ldap_validate_server_uri "$LDAP_SERVER" || { ml_log_error "Invalid LDAP server URI"; return 1; }
    if [ -n "$LDAP_BASE" ] && ! ldap_validate_dn_input "$LDAP_BASE"; then ml_log_error "Invalid LDAP base DN"; return 1; fi
    if [ -n "$LDAP_USERNAME" ] && ! ldap_validate_dn_input "$LDAP_USERNAME"; then ml_log_error "Invalid LDAP bind DN"; return 1; fi
    if [ -n "$SEARCH_BASE" ] && ! ldap_validate_dn_input "$SEARCH_BASE"; then ml_log_error "Invalid LDAP search base DN"; return 1; fi
    if [ -n "$EXTERNAL_SECURITY_NAME" ] && ! ldap_validate_resource_name "$EXTERNAL_SECURITY_NAME"; then ml_log_error "Invalid external security name"; return 1; fi
    if [ -n "$APPSERVER_NAME" ] && ! ldap_validate_resource_name "$APPSERVER_NAME"; then ml_log_error "Invalid app server name"; return 1; fi
    case "$LDAP_BIND_METHOD" in
        simple|external) ;;
        MD5|md5) ml_log_error "Bind method MD5 is deprecated and rejected by MarkLogic 12 (SEC-LDAPMD5DEPRECATED); use simple over ldaps:// or --start-tls"; return 1 ;;
        SASL|sasl) ml_log_error "MarkLogic has no SASL bind method (valid values are simple and external); for a certificate-protected connection use --bind-method simple with --client-cert and --client-key"; return 1 ;;
        *) ml_log_error "Bind method must be simple or external"; return 1 ;;
    esac
    if [ -n "$CLIENT_CERT_FILE$CLIENT_KEY_FILE" ]; then
        [ -n "$CLIENT_CERT_FILE" ] && [ -n "$CLIENT_KEY_FILE" ] || { ml_log_error "--client-cert and --client-key must be given together"; return 1; }
        [ -r "$CLIENT_CERT_FILE" ] || { ml_log_error "Client certificate file is not readable"; return 1; }
        [ -r "$CLIENT_KEY_FILE" ] || { ml_log_error "Client key file is not readable"; return 1; }
    fi
    case "$AUTH_MODE" in digest|basic|application-level) ;; *) ml_log_error "Invalid authentication mode"; return 1 ;; esac
    if ! ldap_validate_attribute_descriptor "$LDAP_ATTRIBUTE"; then ml_log_error "Invalid LDAP attribute descriptor"; return 1; fi
    case "$AUTHORIZATION" in internal|ldap) ;; *) ml_log_error "--authorization must be internal or ldap"; return 1 ;; esac
    if [ -n "$MEMBEROF_ATTRIBUTE" ] && ! ldap_validate_attribute_descriptor "$MEMBEROF_ATTRIBUTE"; then ml_log_error "Invalid --memberof-attribute"; return 1; fi
    if [ -n "$MEMBER_ATTRIBUTE" ] && ! ldap_validate_attribute_descriptor "$MEMBER_ATTRIBUTE"; then ml_log_error "Invalid --member-attribute"; return 1; fi
    case "$SEARCH_SCOPE" in base|one|sub) ;; *) ml_log_error "Search scope must be base, one, or sub"; return 1 ;; esac
    if ! [[ "$MAX_RESULTS" =~ ^[1-9][0-9]*$ ]]; then ml_log_error "Maximum results must be a positive integer"; return 1; fi
    [ -z "$SEARCH_FILTER" ] || ldap_validate_filter_input "$SEARCH_FILTER" || { ml_log_error "Malformed LDAP search filter"; return 1; }
}

# ================================================================
# LDAP CONFIGURATION FUNCTIONS
# ================================================================

# Create external security configuration JSON
ldap_create_external_security_json() {
    local ldap_server_config external_security_json password_file=""

    ldap_server_config=$(jq -n \
        --arg uri "$LDAP_SERVER" \
        --arg base "$LDAP_BASE" \
        --arg attribute "$LDAP_ATTRIBUTE" \
        --arg method "$LDAP_BIND_METHOD" \
        '{"ldap-server-uri":$uri,"ldap-base":$base,"ldap-attribute":$attribute,"ldap-bind-method":$method}') || return 1

    if [ -n "$LDAP_USERNAME" ]; then
        if [ -n "$LDAP_PASSWORD" ]; then
            password_file=$(ldap_create_password_file "$LDAP_PASSWORD") || return 1
            ldap_server_config=$(jq -n --argjson config "$ldap_server_config" --arg username "$LDAP_USERNAME" --rawfile password "$password_file" \
                '$config + {"ldap-default-user":$username,"ldap-password":$password}') || {
                ldap_cleanup_password_file "$password_file"
                return 1
            }
            ldap_cleanup_password_file "$password_file"
        else
            ldap_server_config=$(jq -n --argjson config "$ldap_server_config" --arg username "$LDAP_USERNAME" \
                '$config + {"ldap-default-user":$username}') || return 1
        fi
    fi

    external_security_json=$(jq -n \
        --arg name "$EXTERNAL_SECURITY_NAME" \
        --argjson server "$ldap_server_config" \
        '{"external-security-name":$name,"description":"LDAP external security configuration created by script","authentication":"ldap","cache-timeout":"300","authorization":"internal","ldap-server":$server}') || return 1

    # authorization "internal" maps the LDAP user to a MarkLogic user through external-name;
    # "ldap" derives roles from the user's groups using the lookup attributes below.
    external_security_json=$(printf '%s' "$external_security_json" | jq --arg authz "$AUTHORIZATION" '.authorization = $authz') || return 1
    if [ -n "$MEMBEROF_ATTRIBUTE" ]; then
        external_security_json=$(printf '%s' "$external_security_json" | jq --arg v "$MEMBEROF_ATTRIBUTE" '.["ldap-server"]["ldap-memberof-attribute"] = $v') || return 1
    fi
    if [ -n "$MEMBER_ATTRIBUTE" ]; then
        external_security_json=$(printf '%s' "$external_security_json" | jq --arg v "$MEMBER_ATTRIBUTE" '.["ldap-server"]["ldap-member-attribute"] = $v') || return 1
    fi
    if [ "$NESTED_LOOKUP" = "true" ]; then
        external_security_json=$(printf '%s' "$external_security_json" | jq '.["ldap-server"]["ldap-nested-lookup"] = true') || return 1
    fi
    if [ "$START_TLS" = "true" ]; then
        external_security_json=$(printf '%s' "$external_security_json" | jq '.["ldap-server"]["ldap-start-tls"] = true') || return 1
    fi
    if [ -n "$CLIENT_CERT_FILE" ]; then
        local client_cert_pem client_key_pem
        client_cert_pem=$(openssl x509 -in "$CLIENT_CERT_FILE" 2>/dev/null) || { ml_log_error "--client-cert is not a valid PEM certificate"; return 1; }
        client_key_pem=$(openssl pkey -in "$CLIENT_KEY_FILE" -passin pass: 2>/dev/null) || { ml_log_error "--client-key is not a valid unencrypted PEM private key"; return 1; }
        [ "$(printf '%s\n' "$client_cert_pem" | openssl x509 -noout -pubkey | openssl sha256)" = "$(printf '%s\n' "$client_key_pem" | openssl pkey -pubout | openssl sha256)" ] || { ml_log_error "--client-cert and --client-key do not match"; return 1; }
        external_security_json=$(printf '%s' "$external_security_json" | jq --arg cert "$client_cert_pem" --arg key "$client_key_pem" \
            '.["ldap-server"] += {"ldap-certificate":$cert,"ldap-private-key":$key}') || return 1
    fi
    if [ -n "$CERTIFICATE_FILE" ]; then
        [ -f "$CERTIFICATE_FILE" ] || { ml_log_error "Certificate file not found"; return 1; }
        external_security_json=$(printf '%s' "$external_security_json" | jq --rawfile certificate "$CERTIFICATE_FILE" '.["ldap-server"]["ldap-certificate"] = $certificate') || return 1
    fi

    # Do not log the JSON: it may contain the LDAP bind password.
    printf '%s\n' "$external_security_json"
}

# Create LDAP external security
ldap_create_external_security() {
    ml_log_step "Creating LDAP external security: $EXTERNAL_SECURITY_NAME"

    # Validate required fields
    if [ -z "$EXTERNAL_SECURITY_NAME" ]; then
        ml_log_error "External security name is required"
        return 1
    fi

    if [ -z "$LDAP_SERVER" ]; then
        ml_log_error "LDAP server URI is required"
        return 1
    fi

    if [ -z "$LDAP_BASE" ]; then
        ml_log_error "LDAP base DN is required"
        return 1
    fi

    # Validate bind credentials (required by MarkLogic)
    if [ -z "$LDAP_USERNAME" ]; then
        ml_log_error "LDAP bind username is required (--bind-username)"
        ml_log_error "This is the DN used by MarkLogic to bind to the LDAP server"
        return 1
    fi

    if [ -z "$LDAP_PASSWORD" ] && [ "$DRY_RUN" != "true" ]; then
        ml_log_error "LDAP bind password is required; set LDAP_BIND_PASSWORD or run interactively"
        return 1
    fi

    # Check if external security already exists
    local existence_status
    if ldap_check_external_security_exists "$EXTERNAL_SECURITY_NAME" "$MARKLOGIC_USER" "$MARKLOGIC_PASS"; then
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

    # Test LDAP connectivity first
    ml_log_info "Testing LDAP connectivity before creating configuration..."
    if ! ldap_test_connectivity; then
        ml_log_error "LDAP connectivity test failed. Please check LDAP server settings."
        return 1
    fi

    # Create external security JSON
    local external_security_json
    external_security_json=$(ldap_create_external_security_json)

    # MarkLogic answers a duplicate POST with HTTP 400 (not 409), so route --force to the
    # properties PUT whenever the existence check said the object is already there.
    if [ "$existence_status" -eq 0 ] && [ "$FORCE" = "true" ]; then
        ml_log_info "Updating existing external security..."
        ldap_update_external_security "$external_security_json"
        return $?
    fi

    # Apply external security to MarkLogic
    local response status_code
    if ml_api_call_with_dryrun response "POST" "/manage/v2/external-security" \
        "$MARKLOGIC_USER" "$MARKLOGIC_PASS" "$external_security_json"; then
        status_code=$(ml_extract_status_code "$response")
    else
        case $? in
            3) ml_log_info "[DRY-RUN] Would create LDAP external security '$EXTERNAL_SECURITY_NAME'"; return 0 ;;
            *) ml_log_error "Failed to create LDAP external security"; return 1 ;;
        esac
    fi

    case "$status_code" in
        201)
            ml_log_success "LDAP external security '$EXTERNAL_SECURITY_NAME' created successfully"
            ldap_show_next_steps
            return 0
            ;;
        409)
            if [ "$FORCE" = "true" ]; then
                ml_log_info "Updating existing external security..."
                ldap_update_external_security "$external_security_json"
                return $?
            else
                ml_log_error "External security already exists (HTTP $status_code)"
                return 1
            fi
            ;;
        400)
            ml_log_error "Bad request - check external security parameters (HTTP $status_code)"
            ml_log_info "Response body suppressed because the request contains LDAP credentials"
            return 1
            ;;
        *)
            ml_log_error "Failed to create external security (HTTP $status_code)"
            return 1
            ;;
    esac
}

# Update existing external security
ldap_update_external_security() {
    local external_security_json="$1" security_path
    security_path=$(ldap_encode_path_segment "$EXTERNAL_SECURITY_NAME") || return 1

    local response status_code
    local update_json
    update_json=$(printf '%s' "$external_security_json" | jq 'del(.["external-security-name"])') || return 1
    if ml_api_call_with_dryrun response "PUT" "/manage/v2/external-security/$security_path/properties" \
        "$MARKLOGIC_USER" "$MARKLOGIC_PASS" "$update_json"; then
        status_code=$(ml_extract_status_code "$response")
    else
        case $? in
            3) ml_log_info "[DRY-RUN] Would update LDAP external security '$EXTERNAL_SECURITY_NAME'"; return 0 ;;
            *) ml_log_error "Failed to update LDAP external security"; return 1 ;;
        esac
    fi

    case "$status_code" in
        204|200)
            ml_log_success "LDAP external security '$EXTERNAL_SECURITY_NAME' updated successfully"
            ldap_show_next_steps
            return 0
            ;;
        *)
            ml_log_error "Failed to update external security (HTTP $status_code)"
            return 1
            ;;
    esac
}

# Configure app server for LDAP authentication
ldap_configure_appserver() {
    ml_log_step "Configuring app server '$APPSERVER_NAME' for LDAP authentication"

    local appserver_path
    appserver_path=$(ldap_encode_path_segment "$APPSERVER_NAME") || return 1

    local existence_status
    if ldap_check_external_security_exists "$EXTERNAL_SECURITY_NAME" "$MARKLOGIC_USER" "$MARKLOGIC_PASS"; then
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
    if ml_api_call_with_dryrun response "GET" "/manage/v2/servers/$appserver_path/properties?group-id=$APPSERVER_GROUP&format=json" \
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

    # Build LDAP configuration
    local ldap_config
    ldap_config=$(jq -n --arg authentication "$AUTH_MODE" --arg external_security "$EXTERNAL_SECURITY_NAME" \
        '{"authentication":$authentication,"external-security":$external_security}') || return 1

    if ! ml_confirm "Apply LDAP authentication settings to app server '$APPSERVER_NAME'?" "n"; then
        ml_log_info "App-server update cancelled"
        return 0
    fi

    # Update app server configuration
    if ml_api_call_with_dryrun response "PUT" "/manage/v2/servers/$appserver_path/properties?group-id=$APPSERVER_GROUP" \
        "$MARKLOGIC_USER" "$MARKLOGIC_PASS" "$ldap_config"; then
        status_code=$(ml_extract_status_code "$response")
    else
        case $? in
            3) ml_log_info "[DRY-RUN] Would configure LDAP on app server '$APPSERVER_NAME'"; return 0 ;;
            *) ml_log_error "Failed to configure LDAP on app server"; return 1 ;;
        esac
    fi

    case "$status_code" in
        204)
            ml_log_success "LDAP authentication configured for app server '$APPSERVER_NAME'"
            ml_log_info "External Security: $EXTERNAL_SECURITY_NAME"
            ml_log_info "Authentication Mode: $AUTH_MODE"

            ml_log_warning "MarkLogic Server restart may be required for authentication changes to take effect"
            return 0
            ;;
        *)
            ml_log_error "Failed to configure LDAP authentication (HTTP $status_code)"
            local response_body
            response_body=$(ml_extract_response_body "$response")
            ml_pretty_print_json "$response_body"
            return 1
            ;;
    esac
}

# Delete external security configuration
ldap_delete_external_security() {
    ml_log_step "Deleting LDAP external security: $EXTERNAL_SECURITY_NAME"
    local security_path
    security_path=$(ldap_encode_path_segment "$EXTERNAL_SECURITY_NAME") || return 1

    # Validate required fields
    if [ -z "$EXTERNAL_SECURITY_NAME" ]; then
        ml_log_error "External security name is required (use --name NAME)"
        return 1
    fi

    # Handle dry-run mode - emit preview and return without any API calls
    if [ "$DRY_RUN" = "true" ]; then
        ml_log_info "[DRY-RUN] Would check whether external security '$EXTERNAL_SECURITY_NAME' exists, then delete it if present"
        ml_log_info "[DRY-RUN] GET /manage/v2/external-security/$security_path"
        ml_log_info "[DRY-RUN] DELETE /manage/v2/external-security/$security_path"
        return 0
    fi

    # Check if external security exists
    local existence_status
    if ldap_check_external_security_exists "$EXTERNAL_SECURITY_NAME" "$MARKLOGIC_USER" "$MARKLOGIC_PASS"; then
        existence_status=0
    else
        existence_status=$?
    fi
    case $existence_status in
        0)  # Exists - proceed
            ;;
        1)  # Does not exist
            ml_log_error "External security '$EXTERNAL_SECURITY_NAME' does not exist"
            return 1
            ;;
        *)  # Error
            ml_log_error "Error checking external security existence"
            return 1
            ;;
    esac

    if ! ml_confirm "Delete LDAP external security '$EXTERNAL_SECURITY_NAME'? Reliable rollback is unavailable; preserve recovery information separately." "n"; then
        ml_log_info "Deletion cancelled"
        return 0
    fi

    ml_log_verbose "Sending DELETE request to /manage/v2/external-security/$security_path"

    # Make DELETE request
    local response status_code
    if ml_api_call_with_dryrun response "DELETE" "/manage/v2/external-security/$security_path" \
        "$MARKLOGIC_USER" "$MARKLOGIC_PASS"; then
        status_code=$(ml_extract_status_code "$response")
    else
        case $? in
            3) ml_log_info "[DRY-RUN] Would delete LDAP external security '$EXTERNAL_SECURITY_NAME'"; return 0 ;;
            *) ml_log_error "Failed to delete LDAP external security"; return 1 ;;
        esac
    fi

    status_code=$(ml_extract_status_code "$response")

    case "$status_code" in
        204|200)
            ml_log_success "External security '$EXTERNAL_SECURITY_NAME' deleted successfully"
            return 0
            ;;
        404)
            ml_log_error "External security '$EXTERNAL_SECURITY_NAME' not found (HTTP $status_code)"
            return 1
            ;;
        400)
            ml_log_error "Bad request - external security may be in use (HTTP $status_code)"
            local response_body
            response_body=$(ml_extract_response_body "$response")
            ml_pretty_print_json "$response_body"
            return 1
            ;;
        401|403)
            ml_log_error "Authentication/authorization failed (HTTP $status_code)"
            return 1
            ;;
        *)
            ml_log_error "Failed to delete external security (HTTP $status_code)"
            local response_body
            response_body=$(ml_extract_response_body "$response")
            if [ -n "$response_body" ]; then
                ml_pretty_print_json "$response_body"
            fi
            return 1
            ;;
    esac
}

# Show next steps after configuration
ldap_show_next_steps() {
    echo
    ml_log_info "Next steps:"
    ml_log_info "1. Test LDAP authentication: $0 test-ldap --external-security $EXTERNAL_SECURITY_NAME --test-user <username>"
    ml_log_info "2. Configure app servers: $0 configure-appserver --appserver <NAME> --external-security $EXTERNAL_SECURITY_NAME"
    ml_log_info "3. Search for users: $0 search-users --external-security $EXTERNAL_SECURITY_NAME"
    ml_log_info "4. Verify user/group mappings"
    ml_log_info "5. Test end-to-end authentication with client applications"
}

# ================================================================
# LDAP TESTING FUNCTIONS
# ================================================================

# Test LDAP connectivity
ldap_test_connectivity() {
    local host port
    if [ "$DRY_RUN" = "true" ]; then
        if [ -z "$LDAP_SERVER" ]; then
            ml_log_info "[DRY-RUN] LDAP target is unknown because external-security settings were not fetched"
        else
            ldap_validate_server_uri "$LDAP_SERVER" || { ml_log_error "Invalid LDAP server URI"; return 1; }
            ldap_parse_server_uri "$LDAP_SERVER" || return 1
            ml_log_info "[DRY-RUN] Would test TCP connectivity to $LDAP_HOSTNAME:$LDAP_PORT"
            if [ -n "$LDAP_USERNAME" ]; then ml_log_info "[DRY-RUN] Would test an LDAP bind without exposing credentials"; fi
        fi
        return 0
    fi

    ldap_validate_server_uri "$LDAP_SERVER" || { ml_log_error "Invalid LDAP server URI"; return 1; }
    ldap_parse_server_uri "$LDAP_SERVER" || return 1
    host="$LDAP_HOSTNAME"
    port="$LDAP_PORT"
    ml_log_step "Testing LDAP connectivity to $LDAP_SERVER"
    if command -v nc >/dev/null 2>&1; then
        if nc -z "$host" "$port" 2>/dev/null; then
            ml_log_success "TCP connection to LDAP server successful"
        else
            ml_log_error "Cannot connect to LDAP server on port $port"
            return 1
        fi
    else
        ml_log_warning "nc (netcat) not found. Cannot test TCP connectivity."
    fi

    if [ -n "$LDAP_USERNAME" ] && [ -n "$LDAP_PASSWORD" ]; then
        if ! command -v ldapsearch >/dev/null 2>&1; then
            ml_log_error "ldapsearch command not found"
            return 1
        fi
        if ldap_run_search "$LDAP_USERNAME" "$LDAP_PASSWORD" ldapsearch -x -H "$LDAP_SERVER" -b "$LDAP_BASE" -s base "objectClass=*" >/dev/null 2>&1; then
            ml_log_success "LDAP bind authentication successful"
        else
            ml_log_warning "LDAP bind authentication failed (credentials may be wrong)"
            return 1
        fi
    fi
    return 0
}

# Report which LDAP identity the server maps a client certificate to (ldapwhoami -Y EXTERNAL).
# Needs no MarkLogic access. The key is passed via LDAPTLS_* environment variables, never on a command line.
ldap_whoami() {
    ml_log_step "Asking the LDAP server who this client certificate maps to (SASL EXTERNAL)"
    [ -n "$LDAP_SERVER" ] || { ml_log_error "--ldap-server is required"; return 1; }
    [ -n "$CLIENT_CERT_FILE" ] && [ -n "$CLIENT_KEY_FILE" ] || { ml_log_error "--client-cert and --client-key are required"; return 1; }
    ldap_validate_server_uri "$LDAP_SERVER" || { ml_log_error "Invalid LDAP server URI"; return 1; }
    case "$LDAP_SERVER" in
        ldaps://*) ;;
        *) [ "$START_TLS" = "true" ] || { ml_log_error "A client certificate needs TLS: use an ldaps:// URI or add --start-tls"; return 1; } ;;
    esac
    if [ "$DRY_RUN" = "true" ]; then
        ml_log_info "[DRY-RUN] Would run: ldapwhoami -H $LDAP_SERVER -Y EXTERNAL with the supplied client certificate"
        return 0
    fi
    command -v ldapwhoami >/dev/null 2>&1 || { ml_log_error "ldapwhoami command not found (install openldap-clients / ldap-utils)"; return 1; }
    local -a args=(ldapwhoami -H "$LDAP_SERVER" -Y EXTERNAL)
    [ "$START_TLS" = "true" ] && args+=(-ZZ)
    local out status
    local -a tls_env=(LDAPTLS_CERT="$CLIENT_CERT_FILE" LDAPTLS_KEY="$CLIENT_KEY_FILE")
    [ -z "$CA_FILE" ] || tls_env+=(LDAPTLS_CACERT="$CA_FILE")
    if out=$(env "${tls_env[@]}" "${args[@]}" 2>&1); then status=0; else status=$?; fi
    if [ "$status" -eq 0 ]; then
        printf '%s\n' "$out" | grep -E '^(dn|u):' | sed 's/^/  /'
        ml_log_success "The server accepted the certificate and mapped it to the identity above"
        return 0
    fi
    ml_log_error "Certificate bind failed"
    case "$out" in
        *"Invalid credentials"*) ml_log_error "TLS worked but 389-ds could not map the certificate to an entry (check certmap.conf FilterComps and that the entry has a matching attribute)" ;;
        *"certificate verify failed"*|*"unable to get local issuer"*) ml_log_error "The server certificate is not trusted: pass --ca-file with the CA that signed it" ;;
        *"Can't contact"*) ml_log_error "Could not connect to $LDAP_SERVER. Either the host/port is unreachable, or the server rejected the TLS handshake because the client certificate was issued by a CA it does not trust (389-ds logs \"Peer's certificate issuer has been marked as not trusted\")" ;;
        *"no mechanism available"*|*"Unknown authentication method"*) ml_log_error "This ldapwhoami has no SASL EXTERNAL support (the macOS built-in one does not). Use OpenLDAP from Homebrew (brew install openldap) or a Linux host" ;;
        *) printf '%s\n' "$out" | tail -2 | sed 's/^/  /' >&2 ;;
    esac
    return 1
}

# Test LDAP user authentication
ldap_test_user_authentication() {
    if [ "$DRY_RUN" = "true" ]; then
        ml_log_info "[DRY-RUN] Would resolve and test LDAP user authentication for '$TEST_USER'"
        return 0
    fi
    ml_log_step "Testing LDAP user authentication for: $TEST_USER"

    if [ -z "$TEST_USER" ] || [ -z "$TEST_PASSWORD" ]; then
        ml_log_error "Test username and password are required"
        return 1
    fi

    local existence_status
    if ldap_check_external_security_exists "$EXTERNAL_SECURITY_NAME" "$MARKLOGIC_USER" "$MARKLOGIC_PASS"; then
        existence_status=0
    else
        existence_status=$?
    fi
    case $existence_status in
        0) ml_log_info "External security exists; checking configured app-server authentication." ;;
        1) ml_log_info "External security does not exist; skipping the MarkLogic app-server test." ;;
        2) ml_log_error "Could not verify external-security state"; return 1 ;;
        3) ml_log_error "Unexpected unknown external-security state outside dry-run"; return 1 ;;
        *) ml_log_error "Unexpected external-security status: $existence_status"; return 1 ;;
    esac

    if [ "$existence_status" -eq 0 ]; then
        local app_servers
        app_servers=$(ml_find_appservers_with_external_security "$EXTERNAL_SECURITY_NAME") || return 1
        if [ -z "$app_servers" ]; then
            ml_log_info "App-server discovery is not implemented; no MarkLogic authentication result is available."
        else
            local app_server
            app_server=$(printf '%s\n' "$app_servers" | head -1)
            ldap_test_marklogic_authentication "$app_server" || return 1
        fi
    fi

    if ! command -v ldapsearch >/dev/null 2>&1; then
        ml_log_error "ldapsearch command not found"
        return 1
    fi
    local search_filter user_result user_dn
    search_filter="(&(objectClass=*)(${LDAP_ATTRIBUTE}=$(ldap_escape_filter_value "$TEST_USER")))"
    ldap_validate_filter_input "$search_filter" || { ml_log_error "Could not construct a valid LDAP filter"; return 1; }
    user_result=$(ldap_run_search "$LDAP_USERNAME" "$LDAP_PASSWORD" ldapsearch -x -H "$LDAP_SERVER" -b "$LDAP_BASE" -s "$SEARCH_SCOPE" "$search_filter" dn) || return 1
    user_dn=$(printf '%s\n' "$user_result" | awk 'tolower(substr($0,1,4)) == "dn: " {print substr($0,5); exit}')
    if [ -z "$user_dn" ] || ! ldap_validate_dn_input "$user_dn"; then
        ml_log_error "No valid user DN was returned for the requested test user"
        return 1
    fi
    if ldap_test_user_auth "$LDAP_SERVER" "$user_dn" "$TEST_PASSWORD" "$LDAP_BASE" "$START_TLS"; then
        ml_log_success "Direct LDAP authentication successful"
        return 0
    fi
    ml_log_error "Direct LDAP authentication failed"
    return 1
}

# Test MarkLogic LDAP authentication
ldap_test_marklogic_authentication() {
    local app_server="$1" appserver_path
    appserver_path=$(ldap_encode_path_segment "$app_server") || return 1
    [ "$DRY_RUN" = "true" ] && { ml_log_info "[DRY-RUN] Would test LDAP authentication through app server '$app_server'"; return 0; }

    # Get app server port
    local response status_code app_server_port response_body
    if ml_api_call_with_dryrun response "GET" "/manage/v2/servers/$appserver_path/properties?group-id=$APPSERVER_GROUP&format=json" \
        "$MARKLOGIC_USER" "$MARKLOGIC_PASS"; then
        status_code=$(ml_extract_status_code "$response")
    else
        case $? in
            3)
                # Dry-run mode - provide example details for display
                ml_log_info "[DRY-RUN] Would show LDAP test instructions for app server '$app_server'"
                return 0
                ;;
            *)
                ml_log_error "Failed to get app server details"
                return 1
                ;;
        esac
    fi

    if [ "$status_code" != "200" ]; then
        ml_log_error "Failed to get app server details (HTTP $status_code)"
        return 1
    fi

    # Extract port from the response body, excluding the appended HTTP status.
    response_body=$(ml_extract_response_body "$response")
    if command -v jq >/dev/null 2>&1; then
        app_server_port=$(echo "$response_body" | jq -r '.port // empty')
    else
        app_server_port=$(echo "$response_body" | grep -o '"port":[0-9]*' | cut -d':' -f2)
    fi

    if ! [[ "$app_server_port" =~ ^[0-9]{1,5}$ ]] || [ "$app_server_port" -lt 1 ] || [ "$app_server_port" -gt 65535 ]; then
        ml_log_error "Could not determine a valid app-server port"
        return 1
    fi

    local app_response app_status saved_port
    saved_port="$ML_PORT"
    ML_PORT="$app_server_port"
    if app_response=$(ml_api_request GET "/" "$TEST_USER" "$TEST_PASSWORD"); then
        ML_PORT="$saved_port"
        app_status=$(ml_extract_status_code "$app_response")
        if [ "$app_status" = "200" ]; then
            ml_log_success "MarkLogic LDAP authentication successful via app server $app_server"
            return 0
        fi
    else
        ML_PORT="$saved_port"
    fi
    ml_log_error "MarkLogic LDAP authentication failed"
    return 1
}

# Find app servers using external security
ml_find_appservers_with_external_security() {
    local security_name="$1"

    # This is a simplified version - in reality, you'd query all app servers
    # and check their external-security property
    ml_log_verbose "Searching for app servers using external security: $security_name"

    # For now, return empty - this would need to be implemented with proper API calls
    echo ""
}

# ================================================================
# LDAP SEARCH FUNCTIONS
# ================================================================

# Search for LDAP users
ldap_search_users() {
    local search_base="${SEARCH_BASE:-$LDAP_BASE}"
    local search_filter="${SEARCH_FILTER:-(&(objectClass=person)(|(uid=*)(sAMAccountName=*)))}"
    if [ "$DRY_RUN" = "true" ]; then
        ml_log_info "[DRY-RUN] Would search LDAP users in the selected base and scope"
        return 0
    fi
    ldap_validate_filter_input "$search_filter" || { ml_log_error "Malformed LDAP search filter"; return 1; }
    command -v ldapsearch >/dev/null 2>&1 || { ml_log_error "ldapsearch command not found"; return 1; }

    ml_log_info "Search base: $search_base"
    ml_log_info "Search filter: $search_filter"
    ml_log_info "Search scope: $SEARCH_SCOPE"
    ml_log_info "Max results: $MAX_RESULTS"
    local -a search_args=(ldapsearch -x -H "$LDAP_SERVER" -b "$search_base" -s "$SEARCH_SCOPE" -z "$MAX_RESULTS" "$search_filter" uid sAMAccountName cn mail)
    if ldap_run_search "$LDAP_USERNAME" "$LDAP_PASSWORD" "${search_args[@]}"; then
        ml_log_success "User search completed"
    else
        ml_log_error "User search failed"
        return 1
    fi
}

# Search for LDAP groups
ldap_search_groups() {
    local search_base="${SEARCH_BASE:-$LDAP_BASE}"
    local search_filter="${SEARCH_FILTER:-(&(|(objectClass=group)(objectClass=groupOfNames)(objectClass=posixGroup)))}"
    if [ "$DRY_RUN" = "true" ]; then
        ml_log_info "[DRY-RUN] Would search LDAP groups in the selected base and scope"
        return 0
    fi
    ldap_validate_filter_input "$search_filter" || { ml_log_error "Malformed LDAP search filter"; return 1; }
    command -v ldapsearch >/dev/null 2>&1 || { ml_log_error "ldapsearch command not found"; return 1; }

    ml_log_info "Search base: $search_base"
    ml_log_info "Search filter: $search_filter"
    ml_log_info "Search scope: $SEARCH_SCOPE"
    ml_log_info "Max results: $MAX_RESULTS"
    local -a search_args=(ldapsearch -x -H "$LDAP_SERVER" -b "$search_base" -s "$SEARCH_SCOPE" -z "$MAX_RESULTS" "$search_filter" cn description member uniqueMember memberUid)
    if ldap_run_search "$LDAP_USERNAME" "$LDAP_PASSWORD" "${search_args[@]}"; then
        ml_log_success "Group search completed"
    else
        ml_log_error "Group search failed"
        return 1
    fi
}

# Show LDAP schema information
ldap_show_schema() {
    if [ "$DRY_RUN" = "true" ]; then
        ml_log_info "[DRY-RUN] Would query the LDAP root DSE and retrieve schema details"
        return 0
    fi
    command -v ldapsearch >/dev/null 2>&1 || { ml_log_error "ldapsearch command not found"; return 1; }

    ml_log_step "Retrieving LDAP schema information"
    local schema_result schema_dn
    schema_result=$(ldap_run_search "$LDAP_USERNAME" "$LDAP_PASSWORD" ldapsearch -x -H "$LDAP_SERVER" -b "" -s base "objectClass=*" subschemaSubentry) || return 1
    schema_dn=$(printf '%s\n' "$schema_result" | awk '/^subschemaSubentry:[[:space:]]*/ {sub(/^[^:]*:[[:space:]]*/, ""); print; exit}')
    if [ -z "$schema_dn" ] || ! ldap_validate_dn_input "$schema_dn"; then
        ml_log_error "Could not find a valid subschema DN"
        return 1
    fi

    ml_log_info "Retrieving LDAP schema details..."
    if ldap_run_search "$LDAP_USERNAME" "$LDAP_PASSWORD" ldapsearch -x -H "$LDAP_SERVER" -b "$schema_dn" -s base "objectClass=*" objectClasses attributeTypes; then
        ml_log_success "Schema information retrieved"
    else
        ml_log_error "Failed to retrieve schema details"
        return 1
    fi
}

# ================================================================
# COMMAND LINE INTERFACE
# ================================================================

show_usage() {
    cat << EOF
Usage: $0 [COMMAND] [OPTIONS]

MarkLogic LDAP Authentication Configuration Script

COMMANDS:
    create-external-security    Create LDAP external security
    delete-external-security    Delete LDAP external security
    configure-appserver        Configure app server for LDAP
    test-ldap                  Test LDAP connectivity and authentication (read-only)
    search-users               Search for LDAP users (read-only)
    search-groups              Search for LDAP groups (read-only)
    validate-config            Validate LDAP configuration (read-only)
    show-schema                Show LDAP schema information (read-only)
    whoami                     Show the LDAP identity a client certificate maps to (read-only, no MarkLogic needed)

CREATE-EXTERNAL-SECURITY OPTIONS:
    --name NAME                   External security name (required)
    --ldap-server URI             LDAP server URI (required)
    --ldap-base DN                LDAP base DN (required)
    --bind-method METHOD          Bind method: simple (default) or external. MarkLogic 12 has no SASL bind.
    --bind-username USER          Bind username/DN (required)
    --bind-password PASS          Rejected; use LDAP_BIND_PASSWORD or a hidden prompt
    --ldap-attribute ATTR         User attribute (default: uid)
    --authorization MODE          internal (default: map to MarkLogic users via external-name) or ldap (roles from groups)
    --memberof-attribute ATTR     User attribute listing groups (MarkLogic default: memberOf)
    --member-attribute ATTR       Group attribute listing members (MarkLogic default: member)
    --nested-lookup               Also resolve groups of groups
    --start-tls                   Enable StartTLS
    --certificate-file FILE       SSL certificate file
    --client-cert FILE            PEM client certificate MarkLogic presents to the LDAP server (mutual TLS)
    --client-key FILE             PEM private key for --client-cert (unencrypted)
    --force                       Overwrite existing external security

CONFIGURE-APPSERVER OPTIONS:
    --appserver NAME              App server name (required)
    --external-security NAME      External security name (required)
    --auth-mode MODE              Authentication mode: digest, basic, application-level (default: digest)
    --group NAME                  MarkLogic group containing the app server (default: Default)

TEST-LDAP OPTIONS:
    --external-security NAME      External security name (required)
    --test-user USERNAME          Test username (required)
    --test-password PASSWORD      Rejected; use LDAP_TEST_PASSWORD or a hidden prompt

SEARCH-USERS OPTIONS (read-only):
    --external-security NAME      External security name (for LDAP settings)
    --search-base DN              Search base DN (optional, defaults to LDAP base)
    --search-filter FILTER        LDAP search filter (optional)
    --search-scope SCOPE          Search scope: base, one, sub (default: sub)
    --max-results NUM             Maximum results (default: 100)

SEARCH-GROUPS OPTIONS (read-only):
    --external-security NAME      External security name (for LDAP settings)
    --search-base DN              Search base DN (optional, defaults to LDAP base)
    --search-filter FILTER        LDAP search filter (optional)
    --search-scope SCOPE          Search scope: base, one, sub (default: sub)
    --max-results NUM             Maximum results (default: 100)

VALIDATE-CONFIG OPTIONS:
    --external-security NAME      External security name (required)

DELETE-EXTERNAL-SECURITY OPTIONS:
    --name NAME                   External security name to delete (required)
    --dry-run                     Show what would be deleted without making changes
    --verbose                     Show detailed output

WHOAMI OPTIONS (ldapwhoami -Y EXTERNAL equivalent):
    --ldap-server URI             ldaps:// URI, or ldap:// with --start-tls (required)
    --client-cert FILE            PEM client certificate to present (required)
    --client-key FILE             PEM private key for the certificate (required)
    --ca-file FILE                CA that signed the LDAP server certificate (optional)
    --start-tls                   Use StartTLS on an ldap:// URI

SHOW-SCHEMA OPTIONS:
    --external-security NAME      External security name (for LDAP settings)

LDAP PASSWORD INPUT:
    Set LDAP_BIND_PASSWORD or LDAP_TEST_PASSWORD for unattended use.
    Interactive runs prompt without echo. Password value options are rejected.

RECOVERY:
    LDAP deletes/overwrites and app-server updates have no automatic rollback.
    Export the exact prior configuration and document manual recovery first.

$(ml_show_common_usage)

EXAMPLES:
    # Create LDAP external security for Active Directory
    $0 create-external-security --name ad-auth \\
        --ldap-server "ldaps://ad.example.com:636" \\
        --ldap-base "DC=example,DC=com" \\
        --bind-method simple \\
        --bind-username "CN=svc-marklogic,CN=Users,DC=example,DC=com" \\
        --ldap-attribute "sAMAccountName"

    # Create for OpenLDAP
    $0 create-external-security --name openldap-auth \\
        --ldap-server "ldap://ldap.example.com:389" \\
        --ldap-base "ou=people,dc=example,dc=com" \\
        --bind-method simple \\
        --bind-username "cn=marklogic,ou=services,dc=example,dc=com" \\
        --ldap-attribute "uid" \\
        --start-tls --certificate-file /path/to/ca.crt

    # Configure app server for LDAP
    $0 configure-appserver --appserver App-Services \\
        --external-security ad-auth --auth-mode digest

    # Test LDAP authentication; set LDAP_TEST_PASSWORD in your secret manager or shell environment
    $0 test-ldap --external-security ad-auth --test-user jdoe
    unset LDAP_TEST_PASSWORD

    # Search for users
    $0 search-users --external-security ad-auth \\
        --search-filter "(|(sAMAccountName=j*)(cn=John*))" --max-results 50

    # Search for groups
    $0 search-groups --external-security ad-auth \\
        --search-filter "(cn=MarkLogic*)" --max-results 20

    # Show LDAP schema
    $0 show-schema --external-security ad-auth

    # Which LDAP identity does my client certificate map to? (like: ldapwhoami -Y EXTERNAL)
    $0 whoami --ldap-server ldaps://ldap.example.com:636 \\
        --client-cert client.pem --client-key client.key --ca-file ca.pem

    # Create external security whose MarkLogic->LDAP connection uses mutual TLS
    $0 create-external-security --name ldap-mtls --ldap-server ldaps://ldap.example.com:636 \\
        --ldap-base "dc=example,dc=com" --bind-username "cn=svc,dc=example,dc=com" \\
        --client-cert client.pem --client-key client.key

    # Delete external security
    $0 delete-external-security --name ad-auth

    # Delete with dry-run (preview only)
    $0 delete-external-security --name ad-auth --dry-run --verbose

EOF
}

# Parse command line arguments
parse_arguments() {
    if [ $# -eq 0 ]; then
        show_usage
        exit 1
    fi

    # Handle --help as first argument
    if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
        show_usage
        exit 0
    fi

    COMMAND="$1"
    shift

    # Parse remaining arguments including common ones
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --name|--external-security|--ldap-server|--ldap-base|--bind-method|--bind-username|--ldap-attribute|--authorization|--memberof-attribute|--member-attribute|--certificate-file|--client-cert|--client-key|--ca-file|--appserver|--auth-mode|--test-user|--search-base|--search-filter|--search-scope|--max-results|--marklogic-host|--marklogic-port|--marklogic-user)
                if [ "$#" -lt 2 ] || [ -z "${2:-}" ]; then ml_log_error "$1 requires a non-empty value"; return 1; fi
                ;;
        esac
        case $1 in
            --name)
                EXTERNAL_SECURITY_NAME="$2"
                shift 2
                ;;
            --external-security)
                EXTERNAL_SECURITY_NAME="$2"
                shift 2
                ;;
            --ldap-server)
                LDAP_SERVER="$2"
                shift 2
                ;;
            --ldap-base)
                LDAP_BASE="$2"
                shift 2
                ;;
            --bind-method)
                LDAP_BIND_METHOD="$2"
                shift 2
                ;;
            --bind-username)
                LDAP_USERNAME="$2"
                shift 2
                ;;
            --bind-password)
                ml_log_error "--bind-password VALUE is rejected"
                ml_log_error "Set LDAP_BIND_PASSWORD or use the hidden interactive prompt"
                return 1
                ;;
            --ldap-attribute)
                LDAP_ATTRIBUTE="$2"
                shift 2
                ;;
            --authorization)
                AUTHORIZATION="$2"
                shift 2
                ;;
            --memberof-attribute)
                MEMBEROF_ATTRIBUTE="$2"
                shift 2
                ;;
            --member-attribute)
                MEMBER_ATTRIBUTE="$2"
                shift 2
                ;;
            --nested-lookup)
                NESTED_LOOKUP="true"
                shift
                ;;
            --start-tls)
                START_TLS="true"
                shift
                ;;
            --certificate-file)
                CERTIFICATE_FILE="$2"
                shift 2
                ;;
            --client-cert)
                CLIENT_CERT_FILE="$2"
                shift 2
                ;;
            --client-key)
                CLIENT_KEY_FILE="$2"
                shift 2
                ;;
            --ca-file)
                CA_FILE="$2"
                shift 2
                ;;
            --appserver)
                APPSERVER_NAME="$2"
                shift 2
                ;;
            --auth-mode)
                AUTH_MODE="$2"
                shift 2
                ;;
            --group)
                APPSERVER_GROUP="$2"
                shift 2
                ;;
            --test-user)
                TEST_USER="$2"
                shift 2
                ;;
            --test-password)
                ml_log_error "--test-password VALUE is rejected"
                ml_log_error "Set LDAP_TEST_PASSWORD or use the hidden interactive prompt"
                return 1
                ;;
            --search-base)
                SEARCH_BASE="$2"
                shift 2
                ;;
            --search-filter)
                SEARCH_FILTER="$2"
                shift 2
                ;;
            --search-scope)
                SEARCH_SCOPE="$2"
                shift 2
                ;;
            --max-results)
                MAX_RESULTS="$2"
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
            # Common arguments (must be handled explicitly to not break parsing)
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
                ml_log_error "Unknown argument"
                show_usage
                exit 1
                ;;
        esac
    done
}

# Load LDAP settings from external security (for commands that need them)
load_ldap_settings() {
    if [ -z "$EXTERNAL_SECURITY_NAME" ]; then
        return 0
    fi
    local security_path
    security_path=$(ldap_encode_path_segment "$EXTERNAL_SECURITY_NAME") || return 1

    # Check if external security exists
    local existence_status
    if ldap_check_external_security_exists "$EXTERNAL_SECURITY_NAME" "$MARKLOGIC_USER" "$MARKLOGIC_PASS"; then
        existence_status=0
    else
        existence_status=$?
    fi

    case $existence_status in
        0)  # Exists - proceed with loading settings
            local response status_code
        if ml_api_call_with_dryrun response "GET" "/manage/v2/external-security/$security_path?format=json" \
            "$MARKLOGIC_USER" "$MARKLOGIC_PASS"; then
            status_code=$(ml_extract_status_code "$response")
        else
            case $? in
                3) return 0 ;;
                *) ml_log_error "Failed to load LDAP settings from MarkLogic"; return 1 ;;
            esac
        fi

        if [ "$status_code" != "200" ]; then
            ml_log_error "Unexpected HTTP status while loading LDAP settings: $status_code"
            return 1
        fi
        if [ "$status_code" = "200" ]; then
            if command -v jq >/dev/null 2>&1; then
                local response_body
                response_body=$(ml_extract_response_body "$response")

                LDAP_SERVER=$(echo "$response_body" | jq -r '(.["external-security-default"] // .["external-security-properties"] // .)["ldap-server"]["ldap-server-uri"] // .["ldap-server"]["ldap-server-uri"] // .["ldap-server-uri"] // empty')
                LDAP_BASE=$(echo "$response_body" | jq -r '(.["external-security-default"] // .["external-security-properties"] // .)["ldap-server"]["ldap-base"] // .["ldap-server"]["ldap-base"] // .["ldap-base"] // empty')
                LDAP_USERNAME=$(echo "$response_body" | jq -r '(.["external-security-default"] // .["external-security-properties"] // .)["ldap-server"]["ldap-default-user"] // .["ldap-server"]["ldap-default-user"] // .["ldap-username"] // empty')
                LDAP_BIND_METHOD=$(echo "$response_body" | jq -r '(.["external-security-default"] // .["external-security-properties"] // .)["ldap-server"]["ldap-bind-method"] // .["ldap-server"]["ldap-bind-method"] // .["ldap-bind-method"] // "simple"')
                LDAP_ATTRIBUTE=$(echo "$response_body" | jq -r '(.["external-security-default"] // .["external-security-properties"] // .)["ldap-server"]["ldap-attribute"] // .["ldap-server"]["ldap-attribute"] // .["ldap-attribute"] // "uid"')

                local start_tls_val
                start_tls_val=$(echo "$response_body" | jq -r '(.["external-security-default"] // .["external-security-properties"] // .)["ldap-start-tls"] // .["ldap-start-tls"] // false')
                if [ "$start_tls_val" = "true" ]; then
                    START_TLS="true"
                fi

                ml_log_verbose "Loaded LDAP settings from external security: $EXTERNAL_SECURITY_NAME"
            fi
        fi
            ;;
        1)  # Does not exist - skip loading
            ml_log_verbose "External security '$EXTERNAL_SECURITY_NAME' does not exist - skipping settings load"
            ;;
        3)  # Unknown in dry-run - skip loading
            ml_log_verbose "[DRY-RUN] Cannot verify external security existence - skipping settings load"
            ;;
        *)  # Error - fail closed
            ml_log_error "Error checking external security existence; refusing to continue with unknown settings"
            return 1
            ;;
    esac
}

# Main execution function
main() {
    ml_show_header "MarkLogic LDAP Authentication" "1.0.0" \
        "Configure LDAP authentication for MarkLogic Server"

    ml_check_dependencies || exit 1
    ldap_validate_command_inputs || exit 1

    local needs_marklogic=false
    case "$COMMAND" in
        create-external-security|configure-appserver|delete-external-security|test-ldap) needs_marklogic=true ;;
        search-users|search-groups|validate-config|show-schema)
            [ -z "$EXTERNAL_SECURITY_NAME" ] || needs_marklogic=true
            ;;
    esac
    if [ "$DRY_RUN" != "true" ] && [ "$needs_marklogic" = true ]; then
        if [ -z "$MARKLOGIC_USER" ]; then
            ml_log_error "MarkLogic user is required (--marklogic-user or MARKLOGIC_USER)"
            exit 1
        fi
        MARKLOGIC_PASS=$(ml_resolve_password) || exit 1
    fi

    ml_parse_host_url "$MARKLOGIC_HOST"

    if [[ "$COMMAND" =~ ^(test-ldap|search-users|search-groups|validate-config|show-schema)$ ]]; then
        load_ldap_settings || exit 1
    fi
    ldap_validate_command_inputs || exit 1

    if [ "$DRY_RUN" != "true" ]; then
        case "$COMMAND" in
            create-external-security|test-ldap|search-users|search-groups|validate-config|show-schema)
                if [ -n "$LDAP_USERNAME" ] && [ -z "$LDAP_PASSWORD" ]; then
                    LDAP_PASSWORD=$(ldap_resolve_secret LDAP_BIND_PASSWORD "LDAP bind password: ") || exit 1
                fi
                ;;
        esac
        if [ "$COMMAND" = "create-external-security" ] && [ -z "$LDAP_PASSWORD" ]; then
            LDAP_PASSWORD=$(ldap_resolve_secret LDAP_BIND_PASSWORD "LDAP bind password: ") || exit 1
        fi
        if [ "$COMMAND" = "test-ldap" ] && [ -z "$TEST_PASSWORD" ]; then
            TEST_PASSWORD=$(ldap_resolve_secret LDAP_TEST_PASSWORD "LDAP test-user password: ") || exit 1
        fi

        case "$COMMAND" in
            test-ldap|search-users|search-groups|validate-config|show-schema)
                [ -n "$LDAP_SERVER" ] || { ml_log_error "LDAP server URI is required (provide --ldap-server or --external-security)"; exit 1; }
                ;;
        esac
        case "$COMMAND" in
            test-ldap|search-users|search-groups)
                [ -n "$LDAP_BASE" ] || { ml_log_error "LDAP base DN is required"; exit 1; }
                ;;
        esac
        if [[ "$COMMAND" =~ ^(create-external-security|test-ldap|search-users|search-groups|validate-config)$ ]] && [ -n "$LDAP_USERNAME" ]; then
            [ -n "$LDAP_BASE" ] || { ml_log_error "LDAP base DN is required"; exit 1; }
        fi
    fi

    # Read-only LDAP diagnostics do not need a MarkLogic preflight request.
    if [ "$DRY_RUN" != "true" ] && [[ ! "$COMMAND" =~ ^(search-users|search-groups|show-schema|validate-config)$ ]] && [ "$needs_marklogic" = true ]; then
        ml_test_connectivity || exit 1
        echo
    fi

    # Execute command while retaining its status for the footer and final exit.
    set +e
    case "$COMMAND" in
        create-external-security)
            ldap_create_external_security
            ;;
        configure-appserver)
            ldap_configure_appserver
            ;;
        test-ldap)
            ldap_test_user_authentication
            ;;
        search-users)
            ldap_search_users
            ;;
        search-groups)
            ldap_search_groups
            ;;
        validate-config)
            ldap_test_connectivity
            ;;
        show-schema)
            ldap_show_schema
            ;;
        whoami)
            ldap_whoami
            ;;
        delete-external-security)
            ldap_delete_external_security
            ;;
        *)
            ml_log_error "Unknown command: $COMMAND"
            show_usage
            exit 1
            ;;
    esac

    local exit_code=$?
    set -e

    if [ "$exit_code" -eq 0 ]; then
        echo
        case "$COMMAND" in
            create-external-security)
                ml_show_footer "1. Test LDAP connectivity: $0 test-ldap --external-security $EXTERNAL_SECURITY_NAME --test-user <username>
2. Configure app server: $0 configure-appserver --appserver <NAME> --external-security $EXTERNAL_SECURITY_NAME
3. Search users/groups: $0 search-users --external-security $EXTERNAL_SECURITY_NAME"
                ;;
            configure-appserver)
                ml_show_footer "1. Restart MarkLogic Server if needed
2. Test authentication with client application
3. Verify user/group mappings work correctly"
                ;;
            *)
                ml_show_footer ""
                ;;
        esac
    fi

    exit $exit_code
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    parse_arguments "$@"
    main
fi