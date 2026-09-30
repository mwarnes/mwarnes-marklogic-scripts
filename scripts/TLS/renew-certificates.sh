#!/bin/bash
#
# renew-certificates.sh - Find MarkLogic certificate templates that are expiring
# and request a fresh CSR for each one from MarkLogic (key stays inside MarkLogic).
#
# It reuses monitor-certificate-expiry.sh (read-only report) and
# configure-marklogic-tls.sh generate-csr. The installed certificate keeps serving
# until you sign the new CSR and import it:
#   configure-marklogic-tls.sh import-cert --template T --cert-file signed.pem
#
# Exit codes: 0 nothing to renew, 1 error, 2 CSR(s) needed/requested
# Version: 2.0.0
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../marklogic-utils.sh"

THRESHOLD=30
CERT_TEMPLATE=""
DRY_RUN=false
CRON_MODE=false
NOTIFY_EMAIL=""
NOTIFY_WEBHOOK=""
CSR_DIR="."
MARKLOGIC_HOST="${MARKLOGIC_HOST:-localhost}"
MARKLOGIC_PORT="${MARKLOGIC_PORT:-8002}"
MARKLOGIC_USER="${MARKLOGIC_USER:-admin}"

usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Report certificate templates expiring within a threshold and request a new CSR
from MarkLogic for each. Nothing is imported; sign the CSR and use
configure-marklogic-tls.sh import-cert.

OPTIONS:
    --threshold DAYS         Renew when <= DAYS remain (default: 30)
    --cert-template NAME     Only check this template
    --csr-dir DIR            Where to write <template>-renewal-<date>.csr (default: .)
    --marklogic-host HOST    MarkLogic host or URL (default: localhost)
    --marklogic-port PORT    Management API port (default: 8002)
    --marklogic-user USER    Management API user (default: admin)
    --marklogic-pass VALUE   Rejected; set MARKLOGIC_PASS or use the hidden prompt
    --notify-email ADDRESS   Mail a summary when CSRs are needed (live runs only)
    --notify-webhook URL     POST a JSON summary when CSRs are needed (live runs only)
    --cron                   No colours
    --dry-run                Check expiry (read-only) but do not generate CSRs or notify
    --verbose                Detailed logging
    --help                   Show this help

Remote plain HTTP additionally needs MARKLOGIC_ALLOW_HTTP=true (isolated tests only).
EOF
}

require_value() { [ -n "${2:-}" ] || { ml_log_error "$1 requires a value"; exit 1; }; }

while [ $# -gt 0 ]; do
    case "$1" in
        --threshold) require_value "$1" "${2:-}"; THRESHOLD="$2"; shift 2 ;;
        --cert-template) require_value "$1" "${2:-}"; CERT_TEMPLATE="$2"; shift 2 ;;
        --csr-dir) require_value "$1" "${2:-}"; CSR_DIR="$2"; shift 2 ;;
        --marklogic-host) require_value "$1" "${2:-}"; MARKLOGIC_HOST="$2"; shift 2 ;;
        --marklogic-port) require_value "$1" "${2:-}"; MARKLOGIC_PORT="$2"; shift 2 ;;
        --marklogic-user) require_value "$1" "${2:-}"; MARKLOGIC_USER="$2"; shift 2 ;;
        --marklogic-pass) ml_log_error "--marklogic-pass VALUE is rejected; use MARKLOGIC_PASS or a hidden prompt"; exit 1 ;;
        --notify-email) require_value "$1" "${2:-}"; NOTIFY_EMAIL="$2"; shift 2 ;;
        --notify-webhook) require_value "$1" "${2:-}"; NOTIFY_WEBHOOK="$2"; shift 2 ;;
        --cron) CRON_MODE=true; ML_NO_COLOR=1; shift ;;
        --dry-run) DRY_RUN=true; shift ;;
        --verbose) ML_VERBOSE=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) ml_log_error "Unknown option: $1"; usage >&2; exit 1 ;;
    esac
done

[[ "$THRESHOLD" =~ ^[0-9]{1,4}$ ]] || { ml_log_error "--threshold must be a non-negative integer"; exit 1; }
[ -d "$CSR_DIR" ] && [ -w "$CSR_DIR" ] || { ml_log_error "--csr-dir must be a writable directory"; exit 1; }
for c in jq curl openssl; do command -v "$c" >/dev/null 2>&1 || { ml_log_error "$c is required"; exit 1; }; done

# Resolve the password once (env or hidden prompt) and hand it on via the environment.
MARKLOGIC_PASS=$(DRY_RUN=false ml_resolve_password) || exit 1
export MARKLOGIC_PASS

COMMON=(--marklogic-host "$MARKLOGIC_HOST" --marklogic-port "$MARKLOGIC_PORT" --marklogic-user "$MARKLOGIC_USER")
[ "$CRON_MODE" = true ] && COMMON+=(--cron)

ml_log_info "Checking certificate expiry (threshold: $THRESHOLD days)"
[ "$DRY_RUN" != true ] || ml_log_info "[DRY-RUN] no CSRs will be generated or notifications sent"

# monitor exits 2/3 for warnings and missing certificates; the JSON is still valid.
report=$(bash "$SCRIPT_DIR/monitor-certificate-expiry.sh" "${COMMON[@]}" --output-format json </dev/null 2>/dev/null) || true
if ! printf '%s' "$report" | jq -e '.certificates' >/dev/null 2>&1; then
    ml_log_error "Could not read certificate templates (check host, credentials and MARKLOGIC_ALLOW_HTTP)"
    exit 1
fi

due=$(printf '%s' "$report" | jq -r --argjson t "$THRESHOLD" --arg only "$CERT_TEMPLATE" '
    .certificates[]
    | select($only == "" or .template_name == $only)
    | select(.status == "EXPIRED" or (.days_remaining != null and .days_remaining <= $t))
    | "\(.template_name)\t\(.days_remaining // "expired")"')
checked=$(printf '%s' "$report" | jq -r --arg only "$CERT_TEMPLATE" '[.certificates[]|select($only=="" or .template_name==$only)]|length')
[ "$checked" -gt 0 ] || { ml_log_error "No matching certificate templates"; exit 1; }
ml_log_info "Checked $checked certificate template(s)"

if [ -z "$due" ]; then
    ml_log_success "All certificates valid (no renewals needed)"
    exit 0
fi

failed=0; created=""
while IFS=$'\t' read -r template days; do
    ml_log_warning "Template '$template' needs renewal (days remaining: $days)"
    if [ "$DRY_RUN" = true ]; then
        ml_log_info "[DRY-RUN] Would generate a CSR for '$template'"
        continue
    fi
    csr="$CSR_DIR/${template}-renewal-$(date +%Y%m%d).csr"
    if ( umask 077; bash "$SCRIPT_DIR/configure-marklogic-tls.sh" generate-csr --template "$template" --yes "${COMMON[@]}" </dev/null 2>/dev/null \
            | awk '/BEGIN CERTIFICATE REQUEST/,/END CERTIFICATE REQUEST/' > "$csr" ) && [ -s "$csr" ]; then
        ml_log_success "CSR for '$template' written to $csr"
        created="${created}${template} "
    else
        rm -f "$csr"; ml_log_error "Could not generate a CSR for '$template'"; failed=1
    fi
done <<< "$due"

msg="Certificate renewal needed on $MARKLOGIC_HOST: $(printf '%s' "$due" | cut -f1 | tr '\n' ' ')"
if [ "$DRY_RUN" != true ] && [ -n "$created" ]; then
    ml_log_info "Sign each CSR, then: configure-marklogic-tls.sh import-cert --template <name> --cert-file <signed.pem>"
    [ -z "$NOTIFY_EMAIL" ] || { printf '%s\n' "$msg" | mail -s "Certificate renewal needed" "$NOTIFY_EMAIL" || ml_log_warning "Email failed"; }
    [ -z "$NOTIFY_WEBHOOK" ] || jq -n --arg m "$msg" '{level:"warning",message:$m}' \
        | curl -sf -X POST -H 'Content-Type: application/json' -d @- "$NOTIFY_WEBHOOK" >/dev/null || ml_log_warning "Webhook failed"
fi
[ "$failed" -eq 0 ] || exit 1
exit 2
