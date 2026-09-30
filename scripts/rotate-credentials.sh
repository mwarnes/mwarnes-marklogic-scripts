#!/bin/bash

# ================================================================
# Credential Rotation Script
# ================================================================
#
# Automates LDAP bind-password, OAuth2 client-secret, and SAML key updates.
# Prior secrets may be redacted by MarkLogic; recovery is manual.
#
# Author: Martin Warnes
# Version: 1.0.0
# Date: February 2026
#
# ================================================================

# Source utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/marklogic-utils.sh"

# ================================================================
# CONFIGURATION
# ================================================================

CREDENTIAL_TYPE=""
EXTERNAL_SECURITY=""
NEW_CREDENTIAL="${ROTATE_NEW_CREDENTIAL:-}"
NEW_KEY_FILE=""
VERIFY_BEFORE_COMMIT=true
DRY_RUN=false
MARKLOGIC_HOST="${MARKLOGIC_HOST:-localhost}"
MARKLOGIC_PORT="${MARKLOGIC_PORT:-8002}"
MARKLOGIC_USER="${MARKLOGIC_USER:-admin}"
MARKLOGIC_PASS="${MARKLOGIC_PASS:-}"

# ================================================================
# FUNCTIONS
# ================================================================

show_help() {
    cat << EOF
Credential Rotation Script (mutates MarkLogic configuration)

Automates LDAP bind-password, OAuth2 client-secret, and SAML key updates.

USAGE:
    $0 [OPTIONS]

OPTIONS:
    --type <type>                   Credential type: ldap, oauth, saml (required)
    --external-security <name>      External Security configuration name (required)
    --new-key-file <path>           New SAML signing key file
    --verify-before-commit          Rejected; no provider verifier is implemented
    --no-verify                     Required acknowledgement for manual verification
    --marklogic-host <host>         MarkLogic host (default: localhost)
    --marklogic-port <port>         MarkLogic Management API port (default: 8002)
    --marklogic-user <user>         MarkLogic admin user (default: admin)
    --marklogic-pass <pass>         Rejected; use MARKLOGIC_PASS or a hidden prompt
    --dry-run                       Preview only; no API request or file writes
    --yes                           Confirm the update without prompting
    --verbose                       Enable detailed logging
    --help                          Display this help message

No automatic rollback is offered: the Management API may redact prior secrets.
Preserve old credentials separately and verify updates with the provider before relying on them.

EXAMPLES:
    # Rotate LDAP bind password; set ROTATE_NEW_CREDENTIAL or use the hidden prompt
    $0 --type ldap --external-security LDAP-AD --no-verify

    # Rotate OAuth2 client secret from ROTATE_NEW_CREDENTIAL or a hidden prompt
    $0 --type oauth --external-security OAuth2-Config --no-verify

    # Rotate SAML signing key
    $0 --type saml --external-security SAML-IdP \\
       --new-key-file /path/to/new-key.pem --no-verify

    # Dry-run mode
    $0 --type ldap --external-security LDAP-AD --dry-run

EXIT CODES:
    0 - Success
    1 - Error or cancelled

EOF
}

rotate_resolve_secret() {
    [ "$DRY_RUN" != true ] || return 0
    local value="${ROTATE_NEW_CREDENTIAL:-}"
    if [ -n "$value" ]; then printf '%s' "$value"; return 0; fi
    if [ ! -t 0 ]; then
        ml_log_error "Set ROTATE_NEW_CREDENTIAL for unattended use or run interactively for a hidden prompt"
        return 1
    fi
    read -r -s -p "New credential: " value
    printf '\n' >&2
    [ -n "$value" ] || { ml_log_error "New credential cannot be empty"; return 1; }
    printf '%s' "$value"
}

rotate_api_path_segment() {
    local value="$1"
    [[ -n "$value" && "$value" != "." && "$value" != ".." && "$value" != *"/"* && "$value" != *"?"* && "$value" != *"#"* && "$value" != *$'\n'* && "$value" != *$'\r'* ]] || return 1
    jq -nr --arg value "$value" '$value|@uri'
}

rotate_create_secret_file() {
    if [ "$DRY_RUN" = true ]; then
        ml_log_error "Refusing to create a credential file in DRY-RUN"
        return 1
    fi
    local secret="$1" file
    file=$(mktemp) || return 1
    chmod 600 "$file" || { rm -f "$file"; return 1; }
    printf '%s' "$secret" > "$file" || { rm -f "$file"; return 1; }
    printf '%s' "$file"
}

rotate_cleanup_secret_file() {
    [ -n "$1" ] && [ -f "$1" ] && rm -f "$1"
}

rotate_apply_update() {
    if [ "$DRY_RUN" = true ]; then
        ml_log_info "[DRY-RUN] Would send a protected credential update request"
        return 0
    fi
    local external_security="$1" payload="$2" path response status_code
    path=$(rotate_api_path_segment "$external_security") || return 1
    if ! response=$(ml_api_request PUT "/manage/v2/external-security/$path/properties" "$MARKLOGIC_USER" "$MARKLOGIC_PASS" "$payload"); then
        ml_log_error "Credential update request failed"
        return 1
    fi
    status_code=$(ml_extract_status_code "$response")
    case "$status_code" in
        200|204) ml_log_success "Credential update accepted by MarkLogic (HTTP $status_code)"; return 0 ;;
        *) ml_log_error "Credential update failed (HTTP $status_code)"; return 1 ;;
    esac
}

rotate_ldap_password() {
    local external_security="$1" new_password="$2" secret_file payload
    if [ "$DRY_RUN" = true ]; then
        ml_log_info "[DRY-RUN] Would update the LDAP bind password for '$external_security'"
        return 0
    fi
    secret_file=$(rotate_create_secret_file "$new_password") || return 1
    if payload=$(jq -n --rawfile credential "$secret_file" '{"ldap-bind-password":$credential}'); then
        rotate_cleanup_secret_file "$secret_file"
    else
        rotate_cleanup_secret_file "$secret_file"
        return 1
    fi
    rotate_apply_update "$external_security" "$payload"
}

rotate_oauth_secret() {
    local external_security="$1" new_secret="$2" secret_file payload
    if [ "$DRY_RUN" = true ]; then
        ml_log_info "[DRY-RUN] Would update the OAuth2 client secret for '$external_security'"
        return 0
    fi
    secret_file=$(rotate_create_secret_file "$new_secret") || return 1
    if payload=$(jq -n --rawfile credential "$secret_file" '{"oauth-client-secret":$credential}'); then
        rotate_cleanup_secret_file "$secret_file"
    else
        rotate_cleanup_secret_file "$secret_file"
        return 1
    fi
    rotate_apply_update "$external_security" "$payload"
}

rotate_saml_key() {
    local external_security="$1" new_key_file="$2" payload
    if [ "$DRY_RUN" = true ]; then
        ml_log_info "[DRY-RUN] Would update the SAML signing key for '$external_security'"
        return 0
    fi
    [ -f "$new_key_file" ] || { ml_log_error "Key file not found"; return 1; }
    payload=$(jq -n --rawfile key "$new_key_file" '{"saml-sp-private-key":$key}') || return 1
    rotate_apply_update "$external_security" "$payload"
}

# ================================================================
# MAIN
# ================================================================

main() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --type|--external-security|--new-key-file|--marklogic-host|--marklogic-port|--marklogic-user)
                if [ "$#" -lt 2 ] || [ -z "${2:-}" ]; then ml_log_error "$1 requires a non-empty value"; exit 1; fi
                ;;
        esac
        case "$1" in
            --type) CREDENTIAL_TYPE="$2"; shift 2 ;;
            --external-security) EXTERNAL_SECURITY="$2"; shift 2 ;;
            --new-credential)
                ml_log_error "--new-credential VALUE is rejected"
                ml_log_error "Use ROTATE_NEW_CREDENTIAL or a hidden prompt; use --new-key-file for SAML"
                exit 1
                ;;
            --new-key-file) NEW_KEY_FILE="$2"; shift 2 ;;
            --verify-before-commit)
                ml_log_error "No real provider verifier is implemented; verification must be performed out of band"
                exit 1
                ;;
            --no-verify) VERIFY_BEFORE_COMMIT=false; shift ;;
            --marklogic-host) MARKLOGIC_HOST="$2"; shift 2 ;;
            --marklogic-port) MARKLOGIC_PORT="$2"; shift 2 ;;
            --marklogic-user) MARKLOGIC_USER="$2"; shift 2 ;;
            --marklogic-pass)
                ml_log_error "--marklogic-pass VALUE is rejected"
                ml_log_error "Use MARKLOGIC_PASS or the hidden interactive prompt"
                exit 1
                ;;
            --dry-run) DRY_RUN=true; shift ;;
            --verbose) ML_VERBOSE=1; shift ;;
            --yes) YES=true; shift ;;
            --help) show_help; exit 0 ;;
            *) ml_log_error "Unknown option"; show_help; exit 1 ;;
        esac
    done

    [ -n "$CREDENTIAL_TYPE" ] || { ml_log_error "Credential type is required (--type)"; show_help; exit 1; }
    [ -n "$EXTERNAL_SECURITY" ] || { ml_log_error "External security name is required (--external-security)"; show_help; exit 1; }
    [[ "$CREDENTIAL_TYPE" =~ ^(ldap|oauth|saml)$ ]] || { ml_log_error "Credential type must be ldap, oauth, or saml"; exit 1; }
    [[ "$EXTERNAL_SECURITY" != "." && "$EXTERNAL_SECURITY" != ".." && "$EXTERNAL_SECURITY" != *"/"* && "$EXTERNAL_SECURITY" != *"?"* && "$EXTERNAL_SECURITY" != *"#"* && "$EXTERNAL_SECURITY" != *$'\n'* && "$EXTERNAL_SECURITY" != *$'\r'* ]] || { ml_log_error "Invalid external-security name"; exit 1; }

    if [ "$DRY_RUN" = true ]; then
        ml_log_info "[DRY-RUN] Would update the $CREDENTIAL_TYPE credential for '$EXTERNAL_SECURITY' on $MARKLOGIC_HOST:$MARKLOGIC_PORT"
        ml_log_info "[DRY-RUN] No server request, password prompt, key read, or file write was performed"
        exit 0
    fi
    if [ "$VERIFY_BEFORE_COMMIT" = true ]; then
        ml_log_error "This script has no real provider verifier; pass --no-verify only when you will verify the new credential out of band"
        exit 1
    fi
    ml_check_dependencies || exit 1
    if ! ml_confirm "Rotate $CREDENTIAL_TYPE credential for '$EXTERNAL_SECURITY'? No automatic rollback is available." "n"; then
        ml_log_info "Credential rotation cancelled"
        exit 0
    fi
    if [ "$CREDENTIAL_TYPE" = "saml" ]; then
        [ -n "$NEW_KEY_FILE" ] || { ml_log_error "SAML rotation requires --new-key-file"; exit 1; }
        [ -f "$NEW_KEY_FILE" ] || { ml_log_error "Key file not found"; exit 1; }
    else
        [ -z "$NEW_KEY_FILE" ] || { ml_log_error "--new-key-file is only valid for SAML rotation"; exit 1; }
        NEW_CREDENTIAL=$(rotate_resolve_secret) || exit 1
    fi

    [ -n "$MARKLOGIC_USER" ] || { ml_log_error "MarkLogic user is required"; exit 1; }
    MARKLOGIC_PASS=$(ml_resolve_password) || exit 1
    ml_parse_host_url "$MARKLOGIC_HOST"

    case "$CREDENTIAL_TYPE" in
        ldap) rotate_ldap_password "$EXTERNAL_SECURITY" "$NEW_CREDENTIAL" || exit 1 ;;
        oauth) rotate_oauth_secret "$EXTERNAL_SECURITY" "$NEW_CREDENTIAL" || exit 1 ;;
        saml) rotate_saml_key "$EXTERNAL_SECURITY" "$NEW_KEY_FILE" || exit 1 ;;
    esac
    unset NEW_CREDENTIAL
    ml_log_warning "The Management API accepted the update; verify the credential with the provider. Recovery is manual."
    exit 0
}

# Run main if executed directly
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
