#!/usr/bin/env bash
#
# marklogic-cert-deploy.sh
#
# Certbot deploy-hook: pushes the renewed certificate + private key into a
# MarkLogic certificate template via the Management API's
# insert-host-certificates operation.
#
# Usage as a certbot deploy hook:
#   certbot renew --deploy-hook /usr/local/bin/marklogic-cert-deploy-wrapper.sh
#
# Certbot sets RENEWED_LINEAGE when it calls this script; standalone mode
# accepts --cert-dir for testing.
#
# Configuration via environment variables (validated and exported by the wrapper):
#
#   ML_HOST            MarkLogic Management API host   (default: localhost)
#   ML_PORT            MarkLogic Management API port   (default: 8002)
#   ML_SCHEME          http | https                    (default: https)
#   ML_CA_FILE         Path to CA bundle (PEM) for verifying the Management API
#   ML_USER            MarkLogic user                  (default: admin)
#   ML_PASSWORD        MarkLogic password              (required)
#   ML_CERT_TEMPLATE   Certificate template id or name (required)
#
# Flags (override env vars):
#   --cert-dir DIR     Directory containing cert.pem/privkey.pem
#   --host HOST        Management API host
#   --port PORT        Management API port
#   --scheme SCHEME    http | https
#   --cert-template ID Template name or id
#   --ca-file PATH     CA bundle for verifying Management API
#   --insecure         Disable TLS verification (test only)
#   -v, --verbose      Enable verbose output
#   -n, --dry-run      Validate and preview without calling MarkLogic
#   -h, --help         Show this message
#
# Recovery: no automatic rollback is claimed because MarkLogic may redact prior key state.
# Use a reviewed prior Certbot archive with --cert-dir for manual re-deployment; CA issuance
# and external DNS actions are outside this hook's rollback scope.
#
# Exit codes: 0 success, 1 configuration error, 2 API call failed, 7 network error.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/tls-utils.sh"

# ---- defaults -------------------------------------------------------------
ML_HOST="${ML_HOST:-localhost}"
ML_PORT="${ML_PORT:-8002}"
ML_SCHEME="${ML_SCHEME:-https}"
ML_USER="${ML_USER:-admin}"
ML_PASSWORD="${ML_PASSWORD:-}"
ML_CERT_TEMPLATE="${ML_CERT_TEMPLATE:-}"
ML_CA_FILE="${ML_CA_FILE:-}"
ML_BACKUP_DIR="${ML_BACKUP_DIR:-/var/lib/marklogic-cert-deploy/backups}"
ML_INSECURE="${ML_INSECURE:-0}"
CERT_DIR="${RENEWED_LINEAGE:-}"
VERBOSE=false
DRY_RUN=false

# Temporary files for secure credential handling
TMPDIR="${TMPDIR:-/tmp}"
CURL_CONFIG=""
RESPONSE_FILE=""
PAYLOAD_FILE=""
cleanup() {
  [[ -n "$CURL_CONFIG" && -f "$CURL_CONFIG" ]] && rm -f "$CURL_CONFIG"
  [[ -n "$RESPONSE_FILE" && -f "$RESPONSE_FILE" ]] && rm -f "$RESPONSE_FILE"
  [[ -n "$PAYLOAD_FILE" && -f "$PAYLOAD_FILE" ]] && rm -f "$PAYLOAD_FILE"
  return 0
}
trap cleanup EXIT INT TERM

# ---- flag parsing (overrides env) -----------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --cert-dir)       CERT_DIR="$2"; shift 2 ;;
    --host)           ML_HOST="$2"; shift 2 ;;
    --port)           ML_PORT="$2"; shift 2 ;;
    --scheme)         ML_SCHEME="$2"; shift 2 ;;
    --cert-template)  ML_CERT_TEMPLATE="$2"; shift 2 ;;
    --ca-file)        ML_CA_FILE="$2"; shift 2 ;;
    --insecure)       ML_INSECURE=1; shift ;;
    -v|--verbose)     VERBOSE=true; shift ;;
    -n|--dry-run)     DRY_RUN=true; shift ;;
    -h|--help)
      grep '^#' "$0" | sed 's/^# \?//'; exit 0 ;;
    --password|--user|--password=*|--user=*)
      echo "[marklogic-cert-deploy] ERROR: Credentials must be in environment, not CLI arguments" >&2
      exit 1 ;;
    *)
      echo "[marklogic-cert-deploy] ERROR: Unknown argument (use --help)" >&2
      exit 1 ;;
  esac
done

log()     { echo "[marklogic-cert-deploy] $*"; }
log_verbose() { [[ "$VERBOSE" == "true" ]] && echo "[marklogic-cert-deploy] [VERBOSE] $*" || true; }
fail()    { echo "[marklogic-cert-deploy] ERROR: $*" >&2; exit 1; }

# ---- static validation ------------------------------------------------------
[[ -n "$ML_CERT_TEMPLATE" ]] || fail "ML_CERT_TEMPLATE is required."
[[ "$ML_CERT_TEMPLATE" =~ ^[A-Za-z0-9._-]+$ ]] || fail "Invalid certificate-template name."
[[ -n "$CERT_DIR" ]] || fail "No certificate directory. Set RENEWED_LINEAGE (certbot sets this) or pass --cert-dir."
case "$ML_SCHEME" in http|https) ;; *) fail "ML_SCHEME must be 'http' or 'https'." ;; esac
[[ "$ML_HOST" =~ ^[A-Za-z0-9.-]+$ ]] || fail "ML_HOST must be a DNS name or IPv4 address without a scheme or path."
[[ "$ML_PORT" =~ ^[0-9]{1,5}$ ]] && [ "$ML_PORT" -ge 1 ] && [ "$ML_PORT" -le 65535 ] || fail "ML_PORT must be between 1 and 65535."
[[ "$ML_CERT_TEMPLATE" != *"/"* && "$ML_CERT_TEMPLATE" != *"?"* && "$ML_CERT_TEMPLATE" != *"#"* && "$ML_CERT_TEMPLATE" != *$'\\n'* && "$ML_CERT_TEMPLATE" != *$'\\r'* ]] || fail "Invalid certificate-template name."
if [[ "$ML_INSECURE" == "1" && -n "$ML_CA_FILE" ]]; then fail "--insecure and --ca-file are mutually exclusive."; fi
if [[ -n "$ML_CA_FILE" ]]; then [[ -r "$ML_CA_FILE" ]] || fail "CA file is not readable."; fi
CERT_FILE="$CERT_DIR/cert.pem"
KEY_FILE="$CERT_DIR/privkey.pem"
[[ -r "$CERT_FILE" ]] || fail "Certificate is not readable."
[[ -r "$KEY_FILE" ]] || fail "Private key is not readable."

if [[ "$DRY_RUN" == "true" ]]; then
  log "Would POST renewed certificate material to the configured template; remote state is unknown."
  log "Dry run created no temporary files, read no key payload, and made no network request."
  exit 0
fi

[[ -n "$ML_PASSWORD" ]] || fail "ML_PASSWORD is required for live deployment."
[[ "$ML_USER" != *:* && "$ML_USER" != *[[:cntrl:]]* ]] || fail "ML_USER contains unsupported characters."
case "$ML_USER$ML_PASSWORD" in *$'\n'*|*$'\r'*) fail "Credentials must not contain line breaks." ;; esac
command -v jq >/dev/null 2>&1 || fail "jq is required."
command -v curl >/dev/null 2>&1 || fail "curl is required."
command -v openssl >/dev/null 2>&1 || fail "openssl is required."
tls_verify_cert_key_match "$CERT_FILE" "$KEY_FILE" || fail "Certificate and private key do not match."

template_path=$(jq -nr --arg name "$ML_CERT_TEMPLATE" '$name|@uri') || fail "Could not encode certificate-template name."
log_verbose "Deploying to configured certificate template (name omitted)"
log_verbose "TLS verification is enabled unless --insecure is explicitly set."

# ---- build request ----------------------------------------------------------
URL="${ML_SCHEME}://${ML_HOST}:${ML_PORT}/manage/v2/certificate-templates/${template_path}"

PAYLOAD_FILE="$(mktemp "$TMPDIR/ml-cert-deploy-payload.XXXXXX")"
chmod 600 "$PAYLOAD_FILE"

jq -n \
  --rawfile cert "$CERT_FILE" \
  --rawfile pkey "$KEY_FILE" \
  '{
     "operation": "insert-host-certificates",
     "certificates": [
       { "certificate": { "cert": $cert, "pkey": $pkey } }
     ]
   }' >"$PAYLOAD_FILE"

RESPONSE_FILE="$(mktemp "$TMPDIR/ml-cert-deploy-response.XXXXXX")"
chmod 600 "$RESPONSE_FILE"
CURL_CONFIG="$(mktemp "$TMPDIR/ml-cert-deploy-curl.XXXXXX")"
chmod 600 "$CURL_CONFIG"

safe_user=${ML_USER//\\/\\\\}
safe_user=${safe_user//\"/\\\"}
safe_password=${ML_PASSWORD//\\/\\\\}
safe_password=${safe_password//\"/\\\"}
printf 'user = "%s:%s"\ndigest\n' "$safe_user" "$safe_password" > "$CURL_CONFIG"

CURL_TLS_OPTS=()
if [[ "$ML_INSECURE" == "1" ]]; then
  CURL_TLS_OPTS+=(-k)
elif [[ -n "$ML_CA_FILE" ]]; then
  CURL_TLS_OPTS+=(--cacert "$ML_CA_FILE")
fi

# Preserve an exact protected pre-change export for manual recovery.
if [[ -L "$ML_BACKUP_DIR" ]]; then fail "Backup directory must not be a symlink."; fi
if [[ ! -d "$ML_BACKUP_DIR" ]]; then mkdir -p -m 700 "$ML_BACKUP_DIR" || fail "Could not create backup directory."; fi
chmod 700 "$ML_BACKUP_DIR" || fail "Could not secure backup directory."
[[ -O "$ML_BACKUP_DIR" ]] || fail "Backup directory must be owned by the deploy-hook user."
BACKUP_FILE=$(mktemp "$ML_BACKUP_DIR/template-${ML_CERT_TEMPLATE}.XXXXXX") || fail "Could not create a protected backup file."
chmod 600 "$BACKUP_FILE" || { rm -f "$BACKUP_FILE"; fail "Could not secure the backup file."; }
GET_URL="${ML_SCHEME}://${ML_HOST}:${ML_PORT}/manage/v2/certificate-templates/${template_path}/properties?format=json"
GET_CODE=$(curl -sS --connect-timeout 10 --max-time 30 -K "$CURL_CONFIG" -o "$BACKUP_FILE" -w "%{http_code}" -X GET "$GET_URL" \
  -H "Accept: application/json" "${CURL_TLS_OPTS[@]}") || { rm -f "$BACKUP_FILE"; fail "Could not read previous certificate-template state."; }
if [[ "$GET_CODE" != "200" ]] || ! jq -e . "$BACKUP_FILE" >/dev/null 2>&1; then
  rm -f "$BACKUP_FILE"
  fail "Previous certificate-template state is unavailable or invalid; refusing deployment."
fi
log "Protected previous-state export saved at $BACKUP_FILE; MarkLogic may redact secrets, so restoration is manual."

CURL_OPTS=(-sS --connect-timeout 10 --max-time 60 -K "$CURL_CONFIG" -o "$RESPONSE_FILE" -w "%{http_code}" \
  -X POST "$URL" \
  -H "Content-Type: application/json" \
  --data-binary "@$PAYLOAD_FILE" "${CURL_TLS_OPTS[@]}")

log "Pushing renewed certificate into template '${ML_CERT_TEMPLATE}' at ${URL} ..."
log_verbose "Calling curl with digest authentication"

if HTTP_CODE=$(curl "${CURL_OPTS[@]}"); then CURL_EXIT=0; else CURL_EXIT=$?; fi

if [[ $CURL_EXIT -ne 0 ]]; then
  log "curl failed with exit code $CURL_EXIT"
  exit 7
fi

if [[ "$HTTP_CODE" -ge 200 && "$HTTP_CODE" -lt 300 ]]; then
  log "Success (HTTP $HTTP_CODE). Protected previous-state snapshot: $BACKUP_FILE"
  log "Automatic rollback is unavailable if MarkLogic redacts prior key material; restore manually after review."
  exit 0
else
  log "Management API call failed (HTTP $HTTP_CODE; response suppressed)."
  log "Protected previous-state snapshot retained at $BACKUP_FILE for manual recovery."
  exit 2
fi
