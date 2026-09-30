#!/usr/bin/env bash
#
# marklogic-cert-deploy-wrapper.sh
#
# Parses an owner-controlled configuration allow-list without sourcing shell
# code, then executes the MarkLogic certificate deploy hook.
#
# Usage:
#   certbot renew --deploy-hook /usr/local/bin/marklogic-cert-deploy-wrapper.sh
#
# Configuration file (default: /etc/default/marklogic-cert-deploy):
#   Must be readable by the user running certbot (typically root).
#   Must be owned by the effective user and have no group/other permissions
#   since it contains the MarkLogic password.
#
# Flags:
#   --config FILE      Path to config file (default: /etc/default/marklogic-cert-deploy)
#   -v, --verbose      Enable verbose output
#   -n, --dry-run      Pass dry-run to the hook
#   -h, --help         Show this message

set -euo pipefail

CONFIG_FILE="${ML_CERT_DEPLOY_CONFIG:-/etc/default/marklogic-cert-deploy}"
VERBOSE=false
DRY_RUN=false

usage() {
  cat <<'EOF'
marklogic-cert-deploy-wrapper.sh - Load protected config and execute deploy hook

Usage:
  marklogic-cert-deploy-wrapper.sh [OPTIONS]

Options:
  --config FILE      Path to config file (default: /etc/default/marklogic-cert-deploy)
  -v, --verbose      Enable verbose output
  -n, --dry-run      Pass dry-run to the hook (validation only)
  -h, --help         Show this message

Configuration file format (strict allow-list; shell expansion is not performed):
  ML_HOST=localhost
  ML_PORT=8002
  ML_SCHEME=https
  ML_USER=admin
  ML_PASSWORD=<secret-from-vault>
  ML_CERT_TEMPLATE=MarkLogic
  # Optional:
  # ML_CA_FILE=/path/to/ca-bundle.pem
  # ML_BACKUP_DIR=/var/lib/marklogic-cert-deploy/backups

Security:
  The configuration file MUST be readable only by root (0600 root:root).
  Use 'sudo chmod 600 /etc/default/marklogic-cert-deploy' to secure it.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config) CONFIG_FILE="$2"; shift 2 ;;
    -v|--verbose) VERBOSE=true; shift ;;
    -n|--dry-run) DRY_RUN=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument (use --help)" >&2; exit 1 ;;
  esac
done

[[ -f "$CONFIG_FILE" ]] || { echo "ERROR: Config file not found" >&2; exit 1; }
[[ ! -L "$CONFIG_FILE" ]] || { echo "ERROR: Config file must not be a symlink" >&2; exit 1; }
[[ -r "$CONFIG_FILE" && -O "$CONFIG_FILE" ]] || { echo "ERROR: Config file must be readable and owned by the effective user" >&2; exit 1; }
if [[ -n "$(find "$CONFIG_FILE" \( -perm -004 -o -perm -040 -o -perm -001 -o -perm -010 -o -perm -002 -o -perm -020 \) -print -quit 2>/dev/null)" ]]; then
  echo "ERROR: Config file must not grant group/other access; use chmod 600" >&2
  exit 1
fi

# Parse a strict allow-list; never source a privileged configuration file.
ML_HOST="${ML_HOST:-localhost}"
ML_PORT="${ML_PORT:-8002}"
ML_SCHEME="${ML_SCHEME:-https}"
ML_USER="${ML_USER:-admin}"
ML_PASSWORD="${ML_PASSWORD:-}"
ML_CERT_TEMPLATE="${ML_CERT_TEMPLATE:-}"
ML_CA_FILE="${ML_CA_FILE:-}"
ML_BACKUP_DIR="${ML_BACKUP_DIR:-/var/lib/marklogic-cert-deploy/backups}"
ML_INSECURE="${ML_INSECURE:-0}"
seen_keys=""
while IFS= read -r line || [[ -n "$line" ]]; do
  line="${line%$'\r'}"
  [[ -z "${line//[[:space:]]/}" || "$line" =~ ^[[:space:]]*# ]] && continue
  [[ "$line" == *=* ]] || { echo "ERROR: Invalid config line" >&2; exit 1; }
  key="${line%%=*}"
  value="${line#*=}"
  case "$key" in
    ML_HOST|ML_PORT|ML_SCHEME|ML_USER|ML_PASSWORD|ML_CERT_TEMPLATE|ML_CA_FILE|ML_BACKUP_DIR|ML_INSECURE) ;;
    *) echo "ERROR: Unsupported config key: $key" >&2; exit 1 ;;
  esac
  case " $seen_keys " in *" $key "*) echo "ERROR: Duplicate config key: $key" >&2; exit 1 ;; esac
  seen_keys="$seen_keys $key"
  if [[ "$value" == \"*\" && "$value" == *\" ]]; then value="${value:1:${#value}-2}"; fi
  if [[ "$value" == \'*\' && "$value" == *\' ]]; then value="${value:1:${#value}-2}"; fi
  case "$key" in
    ML_HOST) ML_HOST="$value" ;;
    ML_PORT) ML_PORT="$value" ;;
    ML_SCHEME) ML_SCHEME="$value" ;;
    ML_USER) ML_USER="$value" ;;
    ML_PASSWORD) ML_PASSWORD="$value" ;;
    ML_CERT_TEMPLATE) ML_CERT_TEMPLATE="$value" ;;
    ML_CA_FILE) ML_CA_FILE="$value" ;;
    ML_BACKUP_DIR) ML_BACKUP_DIR="$value" ;;
    ML_INSECURE) ML_INSECURE="$value" ;;
  esac
done < "$CONFIG_FILE"
export ML_HOST ML_PORT ML_SCHEME ML_USER ML_PASSWORD ML_CERT_TEMPLATE ML_CA_FILE ML_BACKUP_DIR ML_INSECURE

HOOK_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
HOOK="$HOOK_DIR/marklogic-cert-deploy.sh"

[[ -x "$HOOK" ]] || { echo "ERROR: Hook not executable: $HOOK" >&2; exit 1; }

HOOK_ARGS=()
[[ "$VERBOSE" == "true" ]] && HOOK_ARGS+=("--verbose")
[[ "$DRY_RUN" == "true" ]] && HOOK_ARGS+=("--dry-run")

[[ "$VERBOSE" == "true" ]] && echo "[wrapper] Executing: $HOOK ${HOOK_ARGS[*]}"

if [[ ${#HOOK_ARGS[@]} -gt 0 ]]; then
  exec "$HOOK" ${HOOK_ARGS[@]+"${HOOK_ARGS[@]}"}
else
  exec "$HOOK"
fi
