#!/bin/bash

# Read-only MarkLogic certificate-template expiry monitor.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../marklogic-utils.sh"
source "$SCRIPT_DIR/../OAUTH/oauth2-utils.sh"
source "$SCRIPT_DIR/tls-utils.sh"

THRESHOLD_CRITICAL=7
THRESHOLD_WARNING=30
THRESHOLD_INFO=60
OUTPUT_FORMAT=text
ALERT_EMAIL=""
ALERT_WEBHOOK=""
CRON_MODE=false
DRY_RUN=false
INSECURE=false
MARKLOGIC_HOST="${MARKLOGIC_HOST:-localhost}"
MARKLOGIC_PORT="${MARKLOGIC_PORT:-8002}"
MARKLOGIC_USER="${MARKLOGIC_USER:-admin}"
MARKLOGIC_PASS="${MARKLOGIC_PASS:-}"

show_help() {
    cat << EOF
Usage: $0 [OPTIONS]

Read-only expiry report for MarkLogic certificate templates.

Options:
  --threshold-critical DAYS  Critical threshold (default: 7)
  --threshold-warning DAYS   Warning threshold (default: 30)
  --threshold-info DAYS      Info threshold (default: 60)
  --output-format FORMAT     text or json (default: text)
  --alert-email ADDRESS      Send alerts using mail (live runs only)
  --alert-webhook URL        Send JSON alerts (live runs only)
  --marklogic-host URL       MarkLogic host (default: localhost)
  --marklogic-port PORT      Management API port (default: 8002)
  --marklogic-user USER      Management API user (default: admin)
  --marklogic-pass VALUE     Rejected; use MARKLOGIC_PASS or a hidden prompt
  --insecure                 Explicitly disable TLS verification (discouraged)
  --dry-run                  Preview only; no requests, temp files, or alerts
  --output-file PATH         Rejected; redirect stdout after review
  --cron                     Disable colored logs
  --verbose                  Enable verbose logs
  --help                     Show this help

Set MARKLOGIC_PASS for unattended use. Interactive runs prompt without echo.
EOF
}

require_value() {
    [ "$#" -ge 2 ] && [ -n "$2" ] && [[ "$2" != --* ]] || {
        ml_log_error "$1 requires a value"
        show_help
        exit 1
    }
}

monitor_add_row() {
    local existing="$1" row="$2"
    if [ -n "$existing" ]; then printf '%s\n%s' "$existing" "$row"; else printf '%s' "$row"; fi
}

monitor_check_template() {
    local name="$1" response status body payload certificates cert_count index cert_pem host display_name
    local cert_file expiry_date subject_cn days expiry_status template_path
    template_path=$(oauth2_api_path_segment "$name") || return 1
    payload=$(jq -cn '{"operation":"get-certificates-for-template"}') || return 1
    if ! response=$(ml_api_request POST "/manage/v2/certificate-templates/$template_path?format=json" "$MARKLOGIC_USER" "$MARKLOGIC_PASS" "$payload"); then
        printf 'ERROR|%s|unknown|0|unavailable\n' "${name//|/ }"
        return 0
    fi
    status=$(ml_extract_status_code "$response")
    if [ "$status" != "200" ]; then
        printf 'ERROR|%s|unknown|0|HTTP %s\n' "${name//|/ }" "$status"
        return 0
    fi
    body=$(ml_extract_response_body "$response")
    if ! certificates=$(printf '%s' "$body" | jq -ce '[."certificate-list".certificate[]? | select((.authority | tostring) != "true") | {host:(."host-name" // "unknown"),pem:(.pem // "")}]'); then
        printf 'ERROR|%s|unknown|0|invalid certificate-list response\n' "${name//|/ }"
        return 0
    fi
    cert_count=$(printf '%s' "$certificates" | jq -r 'length') || return 1
    if [ "$cert_count" -eq 0 ]; then
        printf 'NO_CERT|%s|unknown|0|not configured\n' "${name//|/ }"
        return 0
    fi

    for ((index=0; index<cert_count; index++)); do
        host=$(printf '%s' "$certificates" | jq -r --argjson i "$index" '.[$i].host') || return 1
        cert_pem=$(printf '%s' "$certificates" | jq -r --argjson i "$index" '.[$i].pem') || return 1
        display_name="${name//|/ }"
        host=${host//$'\n'/ }
        host=${host//$'\r'/ }
        host=${host//|/ }
        if [ "$cert_count" -gt 1 ] && [ -n "$host" ] && [ "$host" != "unknown" ]; then
            display_name="$display_name ($host)"
        fi
        if [ -z "$cert_pem" ]; then
            printf 'ERROR|%s|unknown|0|certificate PEM missing\n' "$display_name"
            continue
        fi
        cert_file=$(mktemp) || return 1
        chmod 600 "$cert_file" || { rm -f "$cert_file"; return 1; }
        if ! printf '%s\n' "$cert_pem" > "$cert_file"; then
            rm -f "$cert_file"
            return 1
        fi
        if ! expiry_date=$(openssl x509 -in "$cert_file" -noout -enddate 2>/dev/null | cut -d'=' -f2); then
            rm -f "$cert_file"
            printf 'ERROR|%s|unknown|0|expiry check failed\n' "$display_name"
            continue
        fi
        subject_cn=$(openssl x509 -in "$cert_file" -noout -subject -nameopt RFC2253 2>/dev/null | sed 's/subject=//' | grep -o 'CN=[^,]*' | cut -d'=' -f2 || true)
        if days=$(tls_check_certificate_expiry "$cert_file" 0); then expiry_status=0; else expiry_status=$?; fi
        rm -f "$cert_file"
        case "$expiry_status" in
            0|2) status=OK ;;
            3) status=EXPIRED ;;
            *) printf 'ERROR|%s|unknown|0|expiry check failed\n' "$display_name"; continue ;;
        esac
        if [ "$expiry_status" -ne 3 ]; then
            if [ "$days" -le "$THRESHOLD_CRITICAL" ]; then status=CRITICAL
            elif [ "$days" -le "$THRESHOLD_WARNING" ]; then status=WARNING
            elif [ "$days" -le "$THRESHOLD_INFO" ]; then status=INFO
            else status=OK; fi
        fi
        subject_cn=${subject_cn//$'\n'/ }
        subject_cn=${subject_cn//$'\r'/ }
        subject_cn=${subject_cn//|/ }
        printf '%s|%s|%s|%s|%s\n' "$status" "$display_name" "${subject_cn:-unknown}" "$days" "$expiry_date"
    done
}

monitor_report_text() {
    local rows="$1" status template cn days expiry
    printf 'Certificate Expiry Report\nGenerated: %s\nThresholds (days): critical <= %s, warning <= %s, info <= %s\n\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$THRESHOLD_CRITICAL" "$THRESHOLD_WARNING" "$THRESHOLD_INFO"
    printf '%-12s %-25s %-30s %-12s %s\n' STATUS TEMPLATE SUBJECT_CN DAYS_LEFT EXPIRY_DATE
    while IFS='|' read -r status template cn days expiry; do
        [ -n "$status" ] || continue
        printf '%-12s %-25s %-30s %-12s %s\n' "$status" "$template" "${cn:0:30}" "$days" "$expiry"
    done <<< "$rows"
}

monitor_report_json() {
    local rows="$1" certificates='[]' status template cn days expiry item
    while IFS='|' read -r status template cn days expiry; do
        [ -n "$status" ] || continue
        case "$status" in
            NO_CERT|ERROR)
                item=$(jq -cn --arg template "$template" --arg subject_cn "$cn" --arg status "$status" --arg detail "$expiry" \
                    '{template_name:$template,subject_cn:$subject_cn,status:$status,days_remaining:null,detail:$detail}') || return 1
                ;;
            *)
                item=$(jq -cn --arg template "$template" --arg subject_cn "$cn" --arg status "$status" \
                    --argjson days_remaining "$days" --arg expiry_date "$expiry" \
                    '{template_name:$template,subject_cn:$subject_cn,status:$status,days_remaining:$days_remaining,expiry_date:$expiry_date}') || return 1
                ;;
        esac
        certificates=$(jq -cn --argjson current "$certificates" --argjson item "$item" '$current + [$item]') || return 1
    done <<< "$rows"
    jq -n --arg report_date "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --argjson critical "$THRESHOLD_CRITICAL" \
        --argjson warning "$THRESHOLD_WARNING" --argjson info "$THRESHOLD_INFO" --argjson certificates "$certificates" \
        '{report_date:$report_date,thresholds:{critical:$critical,warning:$warning,info:$info},summary:{expired:([$certificates[]|select(.status=="EXPIRED")]|length),critical:([$certificates[]|select(.status=="CRITICAL")]|length),warning:([$certificates[]|select(.status=="WARNING")]|length),info:([$certificates[]|select(.status=="INFO")]|length),ok:([$certificates[]|select(.status=="OK")]|length),errors:([$certificates[]|select(.status=="ERROR")]|length),without_certificate:([$certificates[]|select(.status=="NO_CERT")]|length)},certificates:$certificates}'
}

monitor_send_alerts() {
    local rows="$1" status critical=false warning=false level message payload response code
    while IFS='|' read -r status _; do
        case "$status" in EXPIRED|CRITICAL) critical=true ;; WARNING|NO_CERT) warning=true ;; esac
    done <<< "$rows"
    [ "$critical" = true ] || [ "$warning" = true ] || return 0
    level=warning
    message="Certificate expiry or missing-certificate warning detected"
    [ "$critical" != true ] || { level=critical; message="Critical or expired certificate detected"; }
    if [ -n "$ALERT_EMAIL" ]; then
        if command -v mail >/dev/null 2>&1; then
            printf '%s\n' "$rows" | mail -s "[$level] $message" "$ALERT_EMAIL" 2>/dev/null || ml_log_warning "Email alert could not be sent"
        else
            ml_log_warning "mail is unavailable; email alert was not sent"
        fi
    fi
    if [ -n "$ALERT_WEBHOOK" ]; then
        payload=$(jq -cn --arg level "$level" --arg message "$message" --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
            '{level:$level,message:$message,timestamp:$timestamp}') || return 1
        if response=$(oauth2_http_post_json "$ALERT_WEBHOOK" "$payload"); then
            code="${response: -3}"
            case "$code" in 2??) ;; *) ml_log_warning "Alert webhook returned HTTP $code" ;; esac
        else
            ml_log_warning "Alert webhook could not be reached"
        fi
    fi
}

main() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --threshold-critical) require_value "$1" "${2:-}"; THRESHOLD_CRITICAL="$2"; shift 2 ;;
            --threshold-warning) require_value "$1" "${2:-}"; THRESHOLD_WARNING="$2"; shift 2 ;;
            --threshold-info) require_value "$1" "${2:-}"; THRESHOLD_INFO="$2"; shift 2 ;;
            --output-format) require_value "$1" "${2:-}"; OUTPUT_FORMAT="$2"; shift 2 ;;
            --alert-email) require_value "$1" "${2:-}"; ALERT_EMAIL="$2"; shift 2 ;;
            --alert-webhook) require_value "$1" "${2:-}"; ALERT_WEBHOOK="$2"; shift 2 ;;
            --marklogic-host) require_value "$1" "${2:-}"; MARKLOGIC_HOST="$2"; shift 2 ;;
            --marklogic-port) require_value "$1" "${2:-}"; MARKLOGIC_PORT="$2"; shift 2 ;;
            --marklogic-user) require_value "$1" "${2:-}"; MARKLOGIC_USER="$2"; shift 2 ;;
            --marklogic-pass) ml_log_error "--marklogic-pass VALUE is rejected; use MARKLOGIC_PASS or a hidden prompt"; exit 1 ;;
            --dry-run) DRY_RUN=true; shift ;;
            --output-file) ml_log_error "--output-file is rejected; redirect stdout after review"; exit 1 ;;
            --cron) CRON_MODE=true; ML_NO_COLOR=1; shift ;;
            --verbose) ML_VERBOSE=1; shift ;;
            --help|-h) show_help; exit 0 ;;
            *) ml_log_error "Unknown option"; show_help; exit 1 ;;
        esac
    done
    [ -n "$MARKLOGIC_USER" ] || { ml_log_error "MarkLogic user is required"; exit 1; }
    [[ "$THRESHOLD_CRITICAL" =~ ^[0-9]{1,4}$ && "$THRESHOLD_WARNING" =~ ^[0-9]{1,4}$ && "$THRESHOLD_INFO" =~ ^[0-9]{1,4}$ ]] || { ml_log_error "Thresholds must be non-negative integers"; exit 1; }
    [ "$THRESHOLD_CRITICAL" -le "$THRESHOLD_WARNING" ] && [ "$THRESHOLD_WARNING" -le "$THRESHOLD_INFO" ] || { ml_log_error "Thresholds must be ordered critical <= warning <= info"; exit 1; }
    case "$OUTPUT_FORMAT" in text|json) ;; *) ml_log_error "Output format must be text or json"; exit 1 ;; esac
    case "$MARKLOGIC_HOST" in http://*|https://*) ;; *) MARKLOGIC_HOST="http://$MARKLOGIC_HOST" ;; esac
    oauth2_validate_url "$MARKLOGIC_HOST" || exit 1
    authority="${MARKLOGIC_HOST#*://}"
    case "$authority" in */) MARKLOGIC_HOST="${MARKLOGIC_HOST%/}" ;; */*) ml_log_error "MarkLogic host must not include a path"; exit 1 ;; esac
    MARKLOGIC_PORT="$MARKLOGIC_PORT"
    ml_parse_host_url "$MARKLOGIC_HOST"
    [[ -n "$ML_HOST" && "$ML_HOST" =~ ^[A-Za-z0-9.-]+$ ]] || { ml_log_error "Invalid MarkLogic host"; exit 1; }
    [[ "$ML_PORT" =~ ^[0-9]{1,5}$ ]] && [ "$ML_PORT" -ge 1 ] && [ "$ML_PORT" -le 65535 ] || { ml_log_error "Invalid MarkLogic port"; exit 1; }

    if [ "$DRY_RUN" = true ]; then
        ml_log_info "[DRY-RUN] Would query certificate templates and inspect expiry; no password prompt, request, temp file, or alert"
        exit 0
    fi
    command -v curl >/dev/null 2>&1 || { ml_log_error "curl is required"; exit 1; }
    command -v jq >/dev/null 2>&1 || { ml_log_error "jq is required"; exit 1; }
    command -v openssl >/dev/null 2>&1 || { ml_log_error "openssl is required"; exit 1; }
    MARKLOGIC_PASS=$(ml_resolve_password) || exit 1
    if [ "$CRON_MODE" = true ]; then export ML_NO_COLOR=1; fi

    local response status body templates rows="" template row report
    if ! response=$(ml_api_request GET "/manage/v2/certificate-templates?format=json" "$MARKLOGIC_USER" "$MARKLOGIC_PASS"); then
        ml_log_error "Could not list certificate templates"
        exit 1
    fi
    status=$(ml_extract_status_code "$response")
    [ "$status" = "200" ] || { ml_log_error "Certificate-template list failed (HTTP $status)"; exit 1; }
    body=$(ml_extract_response_body "$response")
    templates=$(printf '%s' "$body" | jq -r '.["certificate-templates-default-list"]["list-items"]["list-item"][]?.nameref // empty') || exit 1
    [ -n "$templates" ] || { ml_log_error "No certificate templates were returned"; exit 1; }
    while IFS= read -r template; do
        [ -n "$template" ] || continue
        if row=$(monitor_check_template "$template"); then
            if [ -n "$rows" ]; then rows="${rows}"$'\n'"${row}"; else rows="$row"; fi
        else
            ml_log_error "Certificate check failed for a template"
            exit 1
        fi
    done <<< "$templates"
    [ -n "$rows" ] || { ml_log_error "No certificate rows were produced"; exit 1; }
    if [ "$OUTPUT_FORMAT" = json ]; then report=$(monitor_report_json "$rows") || exit 1; else report=$(monitor_report_text "$rows") || exit 1; fi
    printf '%s\n' "$report"
    [ -z "$ALERT_EMAIL$ALERT_WEBHOOK" ] || monitor_send_alerts "$rows"

    local critical=false warning=false no_certificate=false has_error=false cert_status
    while IFS='|' read -r cert_status _; do
        case "$cert_status" in
            EXPIRED|CRITICAL) critical=true ;;
            WARNING) warning=true ;;
            NO_CERT) no_certificate=true ;;
            ERROR) has_error=true ;;
        esac
    done <<< "$rows"
    if [ "$has_error" = true ]; then ml_log_error "One or more certificate-template checks failed"; exit 1; fi
    if [ "$critical" = true ]; then ml_log_warning "Critical or expired certificates found"; exit 2; fi
    if [ "$warning" = true ] || [ "$no_certificate" = true ]; then
        [ "$no_certificate" != true ] || ml_log_warning "One or more certificate templates have no certificate"
        ml_log_warning "Certificate warnings found"
        exit 3
    fi
    ml_log_success "All certificates are healthy"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then main "$@"; fi
