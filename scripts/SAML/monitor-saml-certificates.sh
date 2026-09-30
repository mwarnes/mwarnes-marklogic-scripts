#!/bin/bash

# ================================================================
# SAML Certificate Monitoring Script
# ================================================================
#
# Monitors SAML IdP certificates for expiry by fetching metadata
# and extracting signing certificates. Provides alerts for
# approaching expiry to enable proactive certificate renewal.
#
# Author: Martin Warnes
# Version: 1.0.1
# Date: February 2026
#
# ================================================================

# Source utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../marklogic-utils.sh"
source "$SCRIPT_DIR/../OAUTH/oauth2-utils.sh"
source "$SCRIPT_DIR/../TLS/tls-utils.sh"

# ================================================================
# CONFIGURATION
# ================================================================

EXTERNAL_SECURITY=""
METADATA_URL=""
THRESHOLD=30
OUTPUT_FORMAT="text"
NOTIFY_EMAIL=""
NOTIFY_WEBHOOK=""
CRON_MODE=false
DRY_RUN=false

# ================================================================
# FUNCTIONS
# ================================================================

show_help() {
    cat << EOF
SAML Certificate Monitoring Script

Monitors SAML IdP certificates for expiry and provides proactive alerts.

USAGE:
    $0 [OPTIONS]

OPTIONS:
    --external-security <name>      SAML External Security name (required)
    --metadata-url <url>            IdP metadata URL (required; no auto-detection)
    --threshold <days>              Alert threshold in days (default: 30)
    --output-format <format>        Output format: text, json (default: text)
    --notify-email <address>        Email address for alerts
    --notify-webhook <url>          Webhook URL for alerts
    --dry-run                       Preview only; no network requests or temp files
    --cron                          Cron-friendly output (no colors)
    --verbose                       Enable detailed logging
    --help                          Display this help message

EXAMPLES:
    # Monitor SAML certificates from an explicit IdP metadata endpoint
    $0 --external-security SAML-IdP --metadata-url https://idp.example.com/metadata

    # Explicit metadata URL with custom threshold
    $0 --external-security SAML-IdP \\
       --metadata-url https://idp.example.com/metadata \\
       --threshold 14

    # JSON output for monitoring systems
    $0 --external-security SAML-IdP --output-format json

    # With email alerts
    $0 --external-security SAML-IdP \\
       --notify-email admin@company.com

    # Cron job (daily monitoring at 8 AM)
    # 0 8 * * * $0 --external-security SAML-IdP --cron

EXIT CODES:
    0 - All certificates healthy
    1 - Error occurred
    2 - Certificates expiring within threshold

EOF
}

saml_fetch_idp_metadata() {
    local metadata_url="$1" body
    if [ "$DRY_RUN" = true ]; then
        ml_log_info "[DRY-RUN] Would fetch and validate IdP metadata; no request was sent"
        return 3
    fi
    oauth2_validate_url "$metadata_url" || return 1
    ml_log_info "Fetching SAML IdP metadata from the configured endpoint"
    body=$(oauth2_http_get "$metadata_url" "$DEFAULT_TIMEOUT" "" "") || {
        ml_log_error "Failed to fetch IdP metadata"
        return 1
    }
    if ! printf '%s' "$body" | xmllint --nonet --noout - 2>/dev/null; then
        ml_log_error "Invalid XML response from metadata endpoint"
        return 1
    fi
    printf '%s\n' "$body"
}

saml_extract_certificates() {
    local metadata="$1" file cert_count index cert_base64
    file=$(mktemp) || return 1
    chmod 600 "$file" || { rm -f "$file"; return 1; }
    printf '%s' "$metadata" > "$file" || { rm -f "$file"; return 1; }
    cert_count=$(xmllint --nonet --xpath 'count(//*[local-name()="X509Certificate"])' "$file" 2>/dev/null) || { rm -f "$file"; return 1; }
    [[ "$cert_count" =~ ^[0-9]+$ ]] && [ "$cert_count" -gt 0 ] || { rm -f "$file"; return 1; }
    for ((index=1; index<=cert_count; index++)); do
        if ! cert_base64=$(xmllint --nonet --xpath "normalize-space(string((//*[local-name()='X509Certificate'])[$index]))" "$file" 2>/dev/null); then
            rm -f "$file"
            return 1
        fi
        [ -n "$cert_base64" ] || { rm -f "$file"; return 1; }
        printf '%s\n%s\n%s\n' '-----BEGIN CERTIFICATE-----' "$cert_base64" '-----END CERTIFICATE-----'
        printf '%s\n' '---CERT_SEPARATOR---'
    done
    rm -f "$file"
}

saml_check_expiry() {
    local cert_pem="$1"
    local cert_index="$2"

    # Save to temp file
    local temp_cert
    temp_cert=$(mktemp) || return 1
    chmod 600 "$temp_cert" || { rm -f "$temp_cert"; return 1; }
    printf '%s\n' "$cert_pem" > "$temp_cert" || { rm -f "$temp_cert"; return 1; }

    # Get certificate subject
    local subject_cn
    subject_cn=$(openssl x509 -in "$temp_cert" -noout -subject -nameopt RFC2253 2>/dev/null | sed 's/subject=//' | grep -o 'CN=[^,]*' | cut -d'=' -f2)

    # Get expiry date
    local expiry_date
    expiry_date=$(openssl x509 -in "$temp_cert" -noout -enddate 2>/dev/null | cut -d'=' -f2)

    # Capture numeric days separately from the helper's explicit status code.
    local days_remaining check_status status
    if days_remaining=$(tls_check_certificate_expiry "$temp_cert" "$THRESHOLD"); then
        check_status=0
    else
        check_status=$?
    fi
    rm -f "$temp_cert"
    case "$check_status" in
        0) status="OK" ;;
        2) status="WARNING" ;;
        3) status="EXPIRED" ;;
        *) ml_log_error "Could not determine certificate expiry"; return 1 ;;
    esac
    echo "$status|Cert $cert_index|$subject_cn|$days_remaining|$expiry_date"
}

saml_generate_report() {
    local format="$1"
    local cert_data="$2"

    case "$format" in
        json)
            saml_generate_json_report "$cert_data"
            ;;
        text)
            saml_generate_text_report "$cert_data"
            ;;
        *)
            ml_log_error "Unknown output format: $format"
            return 1
            ;;
    esac
}

saml_generate_text_report() {
    local cert_data="$1"

    echo "========================================"
    echo "SAML Certificate Expiry Report"
    echo "========================================"
    echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "External Security: $EXTERNAL_SECURITY"
    echo "Metadata source: configured (URL omitted)"
    echo ""
    echo "Threshold: <= $THRESHOLD days"
    echo ""
    echo "----------------------------------------"
    printf "%-12s %-15s %-30s %s\n" "STATUS" "CERTIFICATE" "SUBJECT CN" "DAYS LEFT"
    echo "----------------------------------------"

    local count_expired=0
    local count_warning=0
    local count_ok=0
    local count_error=0

    while IFS='|' read -r status cert_name cn days_left expiry_date; do
        [ -z "$status" ] && continue

        case "$status" in
            EXPIRED)
                count_expired=$((count_expired + 1))
                printf "%-12s %-15s %-30s %s\n" "EXPIRED" "$cert_name" "${cn:0:30}" "EXPIRED"
                ;;
            WARNING)
                count_warning=$((count_warning + 1))
                printf "%-12s %-15s %-30s %s\n" "WARNING" "$cert_name" "${cn:0:30}" "$days_left days"
                ;;
            OK)
                count_ok=$((count_ok + 1))
                printf "%-12s %-15s %-30s %s\n" "OK" "$cert_name" "${cn:0:30}" "$days_left days"
                ;;
            ERROR)
                count_error=$((count_error + 1))
                printf "%-12s %-15s %-30s %s\n" "ERROR" "$cert_name" "$cn" "N/A"
                ;;
        esac
    done <<< "$cert_data"

    echo "----------------------------------------"
    echo ""
    echo "Summary:"
    echo "  Expired:   $count_expired"
    echo "  Warning:   $count_warning"
    echo "  OK:        $count_ok"
    echo "  Errors:    $count_error"
    echo "========================================"
}

saml_generate_json_report() {
    local cert_data="$1" certificates='[]' count_expired=0 count_warning=0 count_ok=0
    while IFS='|' read -r status cert_name cn days_left expiry_date; do
        [ -n "$status" ] || continue
        [ "$status" = "ERROR" ] && continue
        case "$status" in
            EXPIRED) count_expired=$((count_expired + 1)) ;;
            WARNING) count_warning=$((count_warning + 1)) ;;
            OK) count_ok=$((count_ok + 1)) ;;
            *) continue ;;
        esac
        local item
        item=$(jq -cn --arg certificate "$cert_name" --arg subject_cn "$cn" --arg status "$status" \
            --argjson days_remaining "$days_left" --arg expiry_date "$expiry_date" \
            '{certificate:$certificate,subject_cn:$subject_cn,status:$status,days_remaining:$days_remaining,expiry_date:$expiry_date}') || return 1
        certificates=$(jq -cn --argjson current "$certificates" --argjson item "$item" '$current + [$item]') || return 1
    done <<< "$cert_data"

    jq -n --arg report_date "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg external_security "$EXTERNAL_SECURITY" \
        --argjson threshold "$THRESHOLD" --argjson expired "$count_expired" --argjson warning "$count_warning" \
        --argjson ok "$count_ok" --argjson certificates "$certificates" \
        '{report_date:$report_date,external_security:$external_security,metadata_source:"configured",threshold:$threshold,summary:{expired:$expired,warning:$warning,ok:$ok},certificates:$certificates}'
}

saml_send_alerts() {
    local cert_data="$1"
    local has_warning=false
    local has_expired=false

    # Check for expired or warning certificates
    while IFS='|' read -r status cert_name cn days_left expiry_date; do
        [ -z "$status" ] && continue

        if [ "$status" = "EXPIRED" ]; then
            has_expired=true
            break
        elif [ "$status" = "WARNING" ]; then
            has_warning=true
        fi
    done <<< "$cert_data"

    if [ "$has_expired" = false ] && [ "$has_warning" = false ]; then
        ml_log_info "No alerts needed (all certificates OK)"
        return 0
    fi

    local alert_level="warning"
    local alert_message="SAML certificates expiring within $THRESHOLD days"

    if [ "$has_expired" = true ]; then
        alert_level="critical"
        alert_message="CRITICAL: SAML certificates have expired"
    fi

    # Email notification
    if [ -n "$NOTIFY_EMAIL" ]; then
        ml_log_info "Sending email alert to: $NOTIFY_EMAIL"
        echo "$cert_data" | mail -s "[$alert_level] $alert_message - $EXTERNAL_SECURITY" "$NOTIFY_EMAIL" 2>/dev/null || true
    fi

    # Webhook notification; body is JSON-escaped and sent through a protected file.
    if [ -n "$NOTIFY_WEBHOOK" ]; then
        oauth2_validate_url "$NOTIFY_WEBHOOK" || return 1
        local payload response status_code
        payload=$(jq -n --arg level "$alert_level" --arg message "$alert_message" \
            --arg external_security "$EXTERNAL_SECURITY" --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
            '{level:$level,message:$message,external_security:$external_security,timestamp:$timestamp}') || return 1
        ml_log_info "Sending webhook notification"
        if response=$(oauth2_http_post_json "$NOTIFY_WEBHOOK" "$payload"); then
            status_code="${response: -3}"
            case "$status_code" in 2??) ;; *) ml_log_warning "Webhook returned HTTP $status_code" ;; esac
        else
            ml_log_warning "Webhook notification failed"
        fi
    fi
}

# ================================================================
# MAIN
# ================================================================

main() {
    require_value() {
        [ "$#" -ge 2 ] && [ -n "$2" ] && [[ "$2" != --* ]] || {
            ml_log_error "$1 requires a value"
            show_help
            exit 1
        }
    }

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --external-security) require_value "$1" "${2:-}"; EXTERNAL_SECURITY="$2"; shift 2 ;;
            --metadata-url) require_value "$1" "${2:-}"; METADATA_URL="$2"; shift 2 ;;
            --threshold) require_value "$1" "${2:-}"; THRESHOLD="$2"; shift 2 ;;
            --output-format) require_value "$1" "${2:-}"; OUTPUT_FORMAT="$2"; shift 2 ;;
            --notify-email) require_value "$1" "${2:-}"; NOTIFY_EMAIL="$2"; shift 2 ;;
            --notify-webhook) require_value "$1" "${2:-}"; NOTIFY_WEBHOOK="$2"; shift 2 ;;
            --marklogic-pass) ml_log_error "--marklogic-pass VALUE is not used or accepted"; exit 1 ;;
            --dry-run) DRY_RUN=true; shift ;;
            --cron) CRON_MODE=true; ML_NO_COLOR=1; shift ;;
            --verbose) ML_VERBOSE=1; shift ;;
            --help|-h) show_help; exit 0 ;;
            *) ml_log_error "Unknown option"; show_help; exit 1 ;;
        esac
    done

    [ -n "$EXTERNAL_SECURITY" ] || { ml_log_error "External-security name is required"; show_help; exit 1; }
    [ -n "$METADATA_URL" ] || { ml_log_error "--metadata-url is required; MarkLogic does not retain the source metadata URL"; show_help; exit 1; }
    [[ "$THRESHOLD" =~ ^[0-9]{1,4}$ ]] && [ "$THRESHOLD" -le 3650 ] || { ml_log_error "Threshold must be an integer from 0 to 3650"; exit 1; }
    case "$OUTPUT_FORMAT" in text|json) ;; *) ml_log_error "Output format must be text or json"; exit 1 ;; esac
    oauth2_validate_url "$METADATA_URL" || exit 1
    [ -z "$NOTIFY_WEBHOOK" ] || oauth2_validate_url "$NOTIFY_WEBHOOK" || exit 1

    if [ "$DRY_RUN" = true ]; then
        ml_log_info "[DRY-RUN] Would fetch the configured IdP metadata and check certificate expiry"
        [ -z "$NOTIFY_EMAIL" ] && [ -z "$NOTIFY_WEBHOOK" ] || ml_log_info "[DRY-RUN] Notifications were configured but will not be sent"
        ml_log_info "[DRY-RUN] No request, temporary file, or alert was created"
        exit 0
    fi

    command -v curl >/dev/null 2>&1 || { ml_log_error "curl is required"; exit 1; }
    command -v jq >/dev/null 2>&1 || { ml_log_error "jq is required"; exit 1; }
    command -v xmllint >/dev/null 2>&1 || { ml_log_error "xmllint is required"; exit 1; }
    command -v openssl >/dev/null 2>&1 || { ml_log_error "openssl is required"; exit 1; }
    if [ "$CRON_MODE" = true ]; then export ML_NO_COLOR=1; fi

    ml_log_info "Starting SAML certificate monitoring for '$EXTERNAL_SECURITY'"
    local metadata certs_pem
    if metadata=$(saml_fetch_idp_metadata "$METADATA_URL"); then :; else ml_log_error "Metadata fetch/validation failed"; exit 1; fi
    if certs_pem=$(saml_extract_certificates "$metadata"); then :; else ml_log_error "No valid certificates were extracted"; exit 1; fi

    local all_cert_data="" cert_index=1 current_cert="" line cert_info
    while IFS= read -r line; do
        if [ "$line" = "---CERT_SEPARATOR---" ]; then
            if [ -n "$current_cert" ]; then
                if cert_info=$(saml_check_expiry "$current_cert" "$cert_index"); then
                    if [ -n "$all_cert_data" ]; then all_cert_data="${all_cert_data}"$'\n'"${cert_info}"; else all_cert_data="$cert_info"; fi
                else
                    ml_log_error "Certificate expiry check failed for certificate $cert_index"
                    exit 1
                fi
                cert_index=$((cert_index + 1))
                current_cert=""
            fi
        elif [ -n "$current_cert" ]; then
            current_cert="${current_cert}"$'\n'"${line}"
        else
            current_cert="$line"
        fi
    done <<< "$certs_pem"

    [ -n "$all_cert_data" ] || { ml_log_error "Metadata contains no certificates"; exit 1; }
    local report
    report=$(saml_generate_report "$OUTPUT_FORMAT" "$all_cert_data") || { ml_log_error "Could not generate certificate report"; exit 1; }
    printf '%s\n' "$report"

    if [ -n "$NOTIFY_EMAIL" ] || [ -n "$NOTIFY_WEBHOOK" ]; then
        saml_send_alerts "$all_cert_data"
    fi

    local has_warning=false has_expired=false status cert_name cn days_left expiry_date
    while IFS='|' read -r status cert_name cn days_left expiry_date; do
        [ -n "$status" ] || continue
        if [ "$status" = "EXPIRED" ]; then has_expired=true; break; fi
        [ "$status" != "WARNING" ] || has_warning=true
    done <<< "$all_cert_data"
    if [ "$has_expired" = true ] || [ "$has_warning" = true ]; then
        ml_log_warning "Certificates expiring soon or expired"
        exit 2
    fi
    ml_log_success "All SAML certificates healthy"
    exit 0
}

# Run main if executed directly
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
