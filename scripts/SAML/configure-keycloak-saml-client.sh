#!/bin/bash

# Configure one Keycloak SAML client for a MarkLogic AppServer.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../OAUTH/oauth2-utils.sh"

KEYCLOAK_URL="${KEYCLOAK_URL:-https://localhost:8443}"
KEYCLOAK_REALM="${KEYCLOAK_REALM:-master}"
KEYCLOAK_ADMIN_USER="${KEYCLOAK_ADMIN_USER:-admin}"
KEYCLOAK_ADMIN_PASSWORD="${KEYCLOAK_ADMIN_PASSWORD:-}"
CLIENT_ID="${KEYCLOAK_SAML_CLIENT_ID:-marklogic-saml}"
MARKLOGIC_BASE_URL="${MARKLOGIC_BASE_URL:-https://localhost:8000}"
BACKUP_DIR="${KEYCLOAK_SAML_BACKUP_DIR:-./keycloak-saml-backups}"
INSECURE=false
DRY_RUN=false
FORCE=false

show_help() {
    cat <<'EOF'
Usage: configure-keycloak-saml-client.sh [OPTIONS]

Create a Keycloak SAML client for MarkLogic. TLS verification is enabled by
default. Updating an existing client requires --force, interactive confirmation,
and a protected local snapshot; Keycloak may omit secret fields, so restoration
is manual if the snapshot is incomplete.

Options:
  --keycloak-url URL       Keycloak base URL (env: KEYCLOAK_URL)
  --realm NAME             Keycloak realm (env: KEYCLOAK_REALM)
  --admin-user USER        Keycloak admin user (env: KEYCLOAK_ADMIN_USER)
  --client-id ID           SAML client ID (env: KEYCLOAK_SAML_CLIENT_ID)
  --marklogic-base-url URL Public MarkLogic AppServer base URL (env: MARKLOGIC_BASE_URL)
  --backup-dir DIR         Protected update snapshots (env: KEYCLOAK_SAML_BACKUP_DIR)
  --force                  Allow updating an existing client after confirmation
  --insecure               Disable TLS verification (discouraged opt-in)
  --dry-run                Preview only; no login, request, backup, or temp file
  --help                   Show this help

Set KEYCLOAK_ADMIN_PASSWORD for unattended use; otherwise enter it at the hidden
prompt. Password-valued command-line arguments are not supported.
EOF
}

require_value() {
    [ "$#" -ge 2 ] && [ -n "$2" ] && [[ "$2" != --* ]] || { oauth2_log_error "$1 requires a value"; exit 1; }
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --keycloak-url) require_value "$1" "${2:-}"; KEYCLOAK_URL="$2"; shift 2 ;;
        --realm) require_value "$1" "${2:-}"; KEYCLOAK_REALM="$2"; shift 2 ;;
        --admin-user) require_value "$1" "${2:-}"; KEYCLOAK_ADMIN_USER="$2"; shift 2 ;;
        --client-id) require_value "$1" "${2:-}"; CLIENT_ID="$2"; shift 2 ;;
        --marklogic-base-url) require_value "$1" "${2:-}"; MARKLOGIC_BASE_URL="$2"; shift 2 ;;
        --backup-dir) require_value "$1" "${2:-}"; BACKUP_DIR="$2"; shift 2 ;;
        --admin-pass|--password|--client-secret) oauth2_log_error "Password-valued arguments are rejected; use environment variables or a hidden prompt"; exit 1 ;;
        --force) FORCE=true; shift ;;
        --insecure) INSECURE=true; shift ;;
        --dry-run) DRY_RUN=true; shift ;;
        --help|-h) show_help; exit 0 ;;
        *) oauth2_log_error "Unknown option"; show_help; exit 1 ;;
    esac
done

case "$KEYCLOAK_URL" in */) KEYCLOAK_URL="${KEYCLOAK_URL%/}" ;; esac
oauth2_validate_url "$KEYCLOAK_URL" || exit 1
oauth2_validate_url "$MARKLOGIC_BASE_URL" || exit 1
[[ "$KEYCLOAK_REALM" =~ ^[A-Za-z0-9._-]+$ ]] || { oauth2_log_error "Invalid Keycloak realm"; exit 1; }
[[ "$CLIENT_ID" =~ ^[A-Za-z0-9._-]+$ ]] || { oauth2_log_error "Invalid Keycloak client ID"; exit 1; }

if [ "$DRY_RUN" = true ]; then
    oauth2_log_info "[DRY-RUN] Would inspect and create/update the named Keycloak SAML client"
    oauth2_log_info "[DRY-RUN] Remote client state is unknown; no login, network request, snapshot, or temp file was created"
    exit 0
fi

command -v curl >/dev/null 2>&1 || { oauth2_log_error "curl is required"; exit 1; }
command -v jq >/dev/null 2>&1 || { oauth2_log_error "jq is required"; exit 1; }
if [ -z "$KEYCLOAK_ADMIN_PASSWORD" ]; then
    [ -t 0 ] || { oauth2_log_error "Set KEYCLOAK_ADMIN_PASSWORD for non-interactive use"; exit 1; }
    printf 'Keycloak admin password: ' >&2
    IFS= read -r -s KEYCLOAK_ADMIN_PASSWORD || exit 1
    printf '\n' >&2
fi

curl_flags=""
if [ "$INSECURE" = true ]; then
    oauth2_log_warning "TLS verification disabled by explicit request"
    curl_flags="--insecure"
fi
token_url="$KEYCLOAK_URL/realms/master/protocol/openid-connect/token"
access_token=$(oauth2_get_token_password "$token_url" "$KEYCLOAK_ADMIN_USER" "$KEYCLOAK_ADMIN_PASSWORD" "admin-cli" "" "" "$curl_flags") || exit 1
auth_header="Authorization: Bearer $access_token"
realm_path=$(oauth2_api_path_segment "$KEYCLOAK_REALM") || exit 1
clients_url="$KEYCLOAK_URL/admin/realms/$realm_path/clients"
clients_json=$(oauth2_http_get "$clients_url" 30 "$auth_header" "$curl_flags") || { oauth2_log_error "Could not read Keycloak clients"; exit 1; }
printf '%s' "$clients_json" | jq -e 'type == "array"' >/dev/null 2>&1 || { oauth2_log_error "Keycloak client response was invalid"; exit 1; }
existing_id=$(printf '%s' "$clients_json" | jq -r --arg client_id "$CLIENT_ID" '[.[] | select(.clientId == $client_id) | .id] | first // empty')

if [ -n "$existing_id" ]; then
    [ "$FORCE" = true ] || { oauth2_log_error "SAML client exists; use --force to request a guarded update"; exit 1; }
    if ! ml_confirm "Update existing Keycloak client '$CLIENT_ID'?" n; then
        oauth2_log_warning "Keycloak update cancelled"
        exit 1
    fi
    client_path=$(oauth2_api_path_segment "$existing_id") || exit 1
    client_url="$clients_url/$client_path"
    previous=$(oauth2_http_get "$client_url" 30 "$auth_header" "$curl_flags") || { oauth2_log_error "Could not export the current Keycloak client; refusing update"; exit 1; }
    [ -d "$BACKUP_DIR" ] || { umask 077; mkdir -p "$BACKUP_DIR"; }
    [ ! -L "$BACKUP_DIR" ] || { oauth2_log_error "Backup directory must not be a symlink"; exit 1; }
    chmod 700 "$BACKUP_DIR" || exit 1
    [[ -O "$BACKUP_DIR" ]] || { oauth2_log_error "Backup directory must be owned by the current user"; exit 1; }
    backup_file=$(mktemp "$BACKUP_DIR/keycloak-saml-client.XXXXXX") || exit 1
    chmod 600 "$backup_file" || { rm -f "$backup_file"; exit 1; }
    printf '%s\n' "$previous" > "$backup_file" || { rm -f "$backup_file"; exit 1; }
    oauth2_log_warning "Protected Keycloak client export saved to $backup_file; secrets may be omitted, so restoration is manual"
    operation=PUT
else
    client_url="$clients_url"
    operation=POST
fi

client_json=$(jq -n --arg client_id "$CLIENT_ID" --arg redirect "$MARKLOGIC_BASE_URL/*" --arg base_url "$MARKLOGIC_BASE_URL/" \
    '{clientId:$client_id,protocol:"saml",enabled:true,frontchannelLogout:false,attributes:{"saml.assertion.signature":"true","saml.client.signature":"false","saml.signature.algorithm":"RSA_SHA256","saml.force.post.binding":"true","saml.authnstatement":"true","saml.server.signature":"true","saml.server.signature.keyinfo.ext":"false","saml_force_name_id_format":"false","saml.encrypt":"false","saml_name_id_format":"username","saml_signature_canonicalization_method":"http://www.w3.org/2001/10/xml-exc-c14n#"},redirectUris:[$redirect],baseUrl:$base_url,adminUrl:"",surrogateAuthRequired:false,alwaysDisplayInConsole:false,clientAuthenticatorType:"client-secret",defaultRoles:[],implicitFlowEnabled:false,standardFlowEnabled:true,directAccessGrantsEnabled:false,serviceAccountsEnabled:false,publicClient:true,bearerOnly:false,consentRequired:false,fullScopeAllowed:true}') || exit 1

case "$operation" in
    POST) response=$(oauth2_http_post_json "$client_url" "$client_json" 30 "$auth_header") ;;
    PUT) response=$(oauth2_http_put_json "$client_url" "$client_json" 30 "$auth_header") ;;
esac || { oauth2_log_error "Keycloak SAML client request failed"; exit 1; }
status="${response: -3}"
case "$operation:$status" in
    POST:201|PUT:204) oauth2_log_success "Keycloak SAML client '$CLIENT_ID' $([ "$operation" = POST ] && echo created || echo updated)" ;;
    *) oauth2_log_error "Keycloak client mutation failed (HTTP $status; body suppressed)"; exit 1 ;;
esac
