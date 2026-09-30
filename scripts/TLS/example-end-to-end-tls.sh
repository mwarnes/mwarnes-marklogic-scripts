#!/bin/bash
#
# example-end-to-end-tls.sh - Worked example: private CA -> MarkLogic-generated CSR ->
# sign -> import -> HTTPS app server -> verified TLS handshake.
#
# Everything is done by the other scripts in this directory; read this file as a recipe.
# It is meant for test systems: the CA is a throw-away private CA created in --work-dir.
#
# Usage:
#   export MARKLOGIC_PASS='<admin password>'
#   ./example-end-to-end-tls.sh --marklogic-host https://ml.example.com \
#       --hostname ml.example.com --create-appserver 8443
#
# Version: 1.0.0
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../marklogic-utils.sh"

MARKLOGIC_HOST="${MARKLOGIC_HOST:-}"
MARKLOGIC_USER="${MARKLOGIC_USER:-admin}"
HOSTNAME_CN=""
TEMPLATE="example-tls-$(date +%Y%m%d%H%M)"
APPSERVER=""
CREATE_PORT=""
TLS_PORT=""
WORK_DIR=""
DRY_RUN=false

usage() {
    cat << EOF
Usage: $(basename "$0") --marklogic-host URL --hostname NAME (--appserver NAME | --create-appserver PORT) [OPTIONS]

Runs the complete flow on a TEST system and verifies the result with a CA- and
hostname-checked TLS handshake.

REQUIRED:
    --marklogic-host URL       Management API host, e.g. https://ml.example.com (port 8002)
    --hostname NAME            Name clients use; becomes the certificate CN and DNS SAN
    --appserver NAME           Existing app server to switch to HTTPS ...
    --create-appserver PORT    ... or create a new HTTP app server on this port and use it

OPTIONS:
    --marklogic-user USER      Management API user (default: admin)
    --template NAME            Certificate template to create (default: example-tls-<timestamp>)
    --work-dir DIR             Where the CA and CSR are kept (default: a new private temp dir)
    --dry-run                  Print the steps without changing anything
    --verbose                  Show the underlying script output
    --help                     Show this help

Passwords: set MARKLOGIC_PASS (admin) and optionally TLS_CA_PASSWORD (CA key). A CA password
is generated into <work-dir>/ca-password.txt if TLS_CA_PASSWORD is unset.
Remote plain HTTP additionally needs MARKLOGIC_ALLOW_HTTP=true (isolated tests only).
The app server must allow /v1/eval on port 8000 (see configure-marklogic-tls.sh --eval-port).
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --marklogic-host) MARKLOGIC_HOST="${2:?--marklogic-host needs a value}"; shift 2 ;;
        --marklogic-user) MARKLOGIC_USER="${2:?--marklogic-user needs a value}"; shift 2 ;;
        --hostname) HOSTNAME_CN="${2:?--hostname needs a value}"; shift 2 ;;
        --template) TEMPLATE="${2:?--template needs a value}"; shift 2 ;;
        --appserver) APPSERVER="${2:?--appserver needs a value}"; shift 2 ;;
        --create-appserver) CREATE_PORT="${2:?--create-appserver needs a port}"; shift 2 ;;
        --work-dir) WORK_DIR="${2:?--work-dir needs a value}"; shift 2 ;;
        --dry-run) DRY_RUN=true; shift ;;
        --verbose) ML_VERBOSE=1; shift ;;
        --help|-h) usage; exit 0 ;;
        --marklogic-pass|--password) ml_log_error "Password flags are rejected; set MARKLOGIC_PASS / TLS_CA_PASSWORD"; exit 1 ;;
        *) ml_log_error "Unknown option: $1"; usage >&2; exit 1 ;;
    esac
done

[ -n "$MARKLOGIC_HOST" ] && [ -n "$HOSTNAME_CN" ] || { ml_log_error "--marklogic-host and --hostname are required"; usage >&2; exit 1; }
[[ "$HOSTNAME_CN" =~ ^[A-Za-z0-9.-]+$ ]] || { ml_log_error "--hostname may contain only letters, digits, '.' and '-'"; exit 1; }
[ -n "$APPSERVER$CREATE_PORT" ] || { ml_log_error "Give --appserver NAME or --create-appserver PORT"; exit 1; }
[ -z "$APPSERVER" ] || [ -z "$CREATE_PORT" ] || { ml_log_error "Use only one of --appserver / --create-appserver"; exit 1; }
if [ -n "$CREATE_PORT" ]; then
    [[ "$CREATE_PORT" =~ ^[0-9]{2,5}$ ]] && [ "$CREATE_PORT" -le 65535 ] || { ml_log_error "Invalid port"; exit 1; }
    APPSERVER="example-tls-$CREATE_PORT"; TLS_PORT="$CREATE_PORT"
fi
for c in curl jq openssl; do command -v "$c" >/dev/null 2>&1 || { ml_log_error "$c is required"; exit 1; }; done

MARKLOGIC_PASS=$(DRY_RUN=false ml_resolve_password) || exit 1
export MARKLOGIC_PASS

if [ "$DRY_RUN" = false ]; then
    [ -n "$WORK_DIR" ] || WORK_DIR=$(mktemp -d)
    mkdir -p "$WORK_DIR" && chmod 700 "$WORK_DIR"
    if [ -z "${TLS_CA_PASSWORD:-}" ]; then
        TLS_CA_PASSWORD=$(ml_generate_random_string 24)
        ( umask 077; printf '%s\n' "$TLS_CA_PASSWORD" > "$WORK_DIR/ca-password.txt" )
    fi
    export TLS_CA_PASSWORD
else
    WORK_DIR="${WORK_DIR:-<work-dir>}"
fi
CA_KEY="$WORK_DIR/ca.key"; CA_CERT="$WORK_DIR/ca.pem"; CSR="$WORK_DIR/$TEMPLATE.csr"; CERT="$WORK_DIR/$TEMPLATE.pem"
ML_ARGS=(--marklogic-host "$MARKLOGIC_HOST" --marklogic-user "$MARKLOGIC_USER" --yes)

step() { ml_log_step "$1"; }
# Run a sibling script; in --dry-run just show it. Output is hidden unless --verbose.
run() {
    if [ "$DRY_RUN" = true ]; then ml_log_info "[DRY-RUN] $*"; return 0; fi
    if [ "${ML_VERBOSE:-0}" = 1 ]; then "$@"; else "$@" >/dev/null 2>"$WORK_DIR/last.err" || { cat "$WORK_DIR/last.err" >&2; return 1; }; fi
}

step "1/7 Create a private CA (throw-away, for testing)"
run bash "$SCRIPT_DIR/generate-ca-certificate.sh" create-ca --cn "Example-Test-CA" --ca-key "$CA_KEY" --ca-cert "$CA_CERT" --ca-bundle "$WORK_DIR/ca-bundle.pem"

step "2/7 Create the certificate template in MarkLogic"
run bash "$SCRIPT_DIR/configure-marklogic-tls.sh" create-template --name "$TEMPLATE" --common-name "$HOSTNAME_CN" --organization "Example" "${ML_ARGS[@]}"

step "3/7 Have MarkLogic generate the CSR (the private key stays inside MarkLogic)"
if [ "$DRY_RUN" = true ]; then ml_log_info "[DRY-RUN] configure-marklogic-tls.sh generate-csr --template $TEMPLATE --dns-name $HOSTNAME_CN > $CSR"
else
    bash "$SCRIPT_DIR/configure-marklogic-tls.sh" generate-csr --template "$TEMPLATE" --dns-name "$HOSTNAME_CN" "${ML_ARGS[@]}" 2>/dev/null \
        | awk '/BEGIN CERTIFICATE REQUEST/,/END CERTIFICATE REQUEST/' > "$CSR"
    [ -s "$CSR" ] || { ml_log_error "No CSR was returned"; exit 1; }
fi

step "4/7 Sign the CSR with the private CA"
run bash "$SCRIPT_DIR/generate-ca-certificate.sh" sign-csr --ca-cert "$CA_CERT" --ca-key "$CA_KEY" --csr "$CSR" --output "$CERT" --validity 365

step "5/7 Import the signed certificate (no key: MarkLogic already holds it)"
run bash "$SCRIPT_DIR/configure-marklogic-tls.sh" import-cert --template "$TEMPLATE" --cert-file "$CERT" "${ML_ARGS[@]}"

if [ -n "$CREATE_PORT" ]; then
    step "6/7 Create a new app server on port $CREATE_PORT"
    if [ "$DRY_RUN" = true ]; then ml_log_info "[DRY-RUN] POST /manage/v2/servers ($APPSERVER, port $CREATE_PORT)"
    else
        ml_parse_host_url "$MARKLOGIC_HOST"
        body=$(jq -n --arg n "$APPSERVER" --argjson p "$CREATE_PORT" '{"server-name":$n,"root":"/","port":$p,"content-database":"Documents","authentication":"digest"}')
        resp=$(ml_api_request POST "/manage/v2/servers?group-id=Default&server-type=http" "$MARKLOGIC_USER" "$MARKLOGIC_PASS" "$body") || { ml_log_error "Could not create the app server"; exit 1; }
        [ "$(ml_extract_status_code "$resp")" = 201 ] || { ml_log_error "App server creation failed (HTTP $(ml_extract_status_code "$resp"))"; exit 1; }
    fi
else
    step "6/7 Using existing app server '$APPSERVER'"
fi

step "7/7 Bind the template to the app server and verify TLS"
run bash "$SCRIPT_DIR/configure-marklogic-tls.sh" configure-ssl --template "$TEMPLATE" --appserver "$APPSERVER" "${ML_ARGS[@]}"
if [ "$DRY_RUN" = true ]; then
    ml_log_info "[DRY-RUN] configure-marklogic-tls.sh test-ssl --host $HOSTNAME_CN --port <port> --ca-file $CA_CERT"
    exit 0
fi
if [ -z "$TLS_PORT" ]; then
    ml_parse_host_url "$MARKLOGIC_HOST"
    resp=$(ml_api_request GET "/manage/v2/servers/$APPSERVER/properties?group-id=Default&format=json" "$MARKLOGIC_USER" "$MARKLOGIC_PASS")
    TLS_PORT=$(ml_extract_response_body "$resp" | jq -r '.port')
fi
sleep 8   # MarkLogic applies the SSL change asynchronously
bash "$SCRIPT_DIR/configure-marklogic-tls.sh" test-ssl --host "$HOSTNAME_CN" --port "$TLS_PORT" --ca-file "$CA_CERT" 2>&1 \
    | grep -E 'Protocol:|subject=|issuer=|ERROR' || true

echo
ml_log_success "Done. Template: $TEMPLATE  App server: $APPSERVER  HTTPS port: $TLS_PORT"
ml_log_info "CA certificate for clients: $CA_CERT   (CA key + password stay in $WORK_DIR)"
ml_log_info "Try: curl --cacert $CA_CERT -u $MARKLOGIC_USER https://$HOSTNAME_CN:$TLS_PORT/"
