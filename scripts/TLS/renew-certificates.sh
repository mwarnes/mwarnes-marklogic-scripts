#!/bin/bash

# ================================================================
# Certificate Renewal Automation Script
# ================================================================
#
# Automatically checks certificate expiry and generates renewal
# requests before certificates expire. Supports email and webhook
# notifications, dry-run mode, and cron scheduling.
#
# Author: Martin Warnes
# Version: 1.0.1
# Date: February 2026
#
# ================================================================

# Source utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/tls-utils.sh"
source "$SCRIPT_DIR/../marklogic-utils.sh"

# ================================================================
# CONFIGURATION
# ================================================================

RENEWAL_THRESHOLD=30
CERT_TEMPLATE=""
DRY_RUN=false
NOTIFY_EMAIL=""
NOTIFY_WEBHOOK=""
CRON_MODE=false
LOG_FILE="/var/log/marklogic-renewal.log"
MARKLOGIC_HOST="localhost"
MARKLOGIC_PORT=8002
MARKLOGIC_USER="admin"
MARKLOGIC_PASS="admin"

# ================================================================
# FUNCTIONS
# ================================================================

show_help() {
    cat << EOF
Certificate Renewal Automation Script

Automatically checks certificate expiry and generates renewal requests.

USAGE:
    $0 [OPTIONS]

OPTIONS:
    --threshold <days>          Renewal threshold in days (default: 30)
    --cert-template <name>      Specific certificate template to check
    --marklogic-host <host>     MarkLogic host (default: localhost)
    --marklogic-port <port>     MarkLogic Management API port (default: 8002)
    --marklogic-user <user>     MarkLogic admin user (default: admin)
    --marklogic-pass <pass>     MarkLogic admin password (default: admin)
    --notify-email <address>    Email address for notifications
    --notify-webhook <url>      Webhook URL for notifications
    --log-file <path>           Log file location (default: /var/log/marklogic-renewal.log)
    --dry-run                   Preview actions without making changes
    --cron                      Cron-friendly output (no colors)
    --verbose                   Enable detailed logging
    --help                      Display this help message

EXAMPLES:
    # Check all certificates expiring in 30 days
    $0 --threshold 30 --marklogic-host localhost

    # Dry-run for specific template
    $0 --cert-template WebServer --dry-run

    # With email notifications
    $0 --threshold 30 --notify-email admin@company.com

    # Cron job (daily at 8 AM)
    # 0 8 * * * $0 --threshold 30 --cron --log-file /var/log/certs.log

EXIT CODES:
    0 - Success
    1 - Error
    2 - Certificates expiring soon (warning)

EOF
}

renew_check_certificates() {
    ml_log_info "Checking certificate expiry (threshold: $RENEWAL_THRESHOLD days)"

    # Fetch all certificate templates from MarkLogic
    local response status_code
    response=$(curl -s -w "%{http_code}" --anyauth -u "$MARKLOGIC_USER:$MARKLOGIC_PASS" \
        "http://$MARKLOGIC_HOST:$MARKLOGIC_PORT/manage/v2/certificate-templates?format=json")

    status_code="${response: -3}"
    local body="${response%???}"

    if [ "$status_code" != "200" ]; then
        ml_log_error "Failed to fetch certificate templates from MarkLogic (HTTP $status_code)"
        return 1
    fi

    # Parse template names using jq
    local templates
    if ! templates=$(echo "$body" | jq -r '.["certificate-template-default-list"]["list-items"]["list-item"][]?.nameref // empty' 2>/dev/null); then
        ml_log_error "Failed to parse certificate templates"
        return 1
    fi

    if [ -z "$templates" ]; then
        ml_log_info "No certificate templates found"
        return 0
    fi

    local expiring_certs=0
    local total_checked=0

    while IFS= read -r template; do
        [ -z "$template" ] && continue

        # Filter by specific template if specified
        if [ -n "$CERT_TEMPLATE" ] && [ "$template" != "$CERT_TEMPLATE" ]; then
            continue
        fi

        ((total_checked++))
        renew_check_template "$template"
        local result=$?
        if [ $result -eq 2 ]; then
            ((expiring_certs++))
        fi
    done <<< "$templates"

    ml_log_info "Checked $total_checked certificate template(s)"

    if [ $expiring_certs -gt 0 ]; then
        ml_log_warning "$expiring_certs certificate(s) expiring within $RENEWAL_THRESHOLD days"
        renew_notify "warning" "$expiring_certs certificates expiring soon on $MARKLOGIC_HOST"
        return 2
    else
        ml_log_success "All certificates valid (no renewals needed)"
        return 0
    fi
}

renew_check_template() {
    local template_name="$1"

    ml_log_verbose "Checking template: $template_name"

    # Get certificate details from template
    local response status_code
    response=$(curl -s -w "%{http_code}" --anyauth -u "$MARKLOGIC_USER:$MARKLOGIC_PASS" \
        "http://$MARKLOGIC_HOST:$MARKLOGIC_PORT/manage/v2/certificate-templates/$template_name/properties?format=json")

    status_code="${response: -3}"
    local body="${response%???}"

    if [ "$status_code" != "200" ]; then
        ml_log_warning "Failed to fetch template $template_name (HTTP $status_code)"
        return 1
    fi

    # Extract certificate PEM from template
    local cert_pem
    cert_pem=$(echo "$body" | jq -r '.["certificate-template-properties"]["template-certificate"]? // empty' 2>/dev/null)

    if [ -z "$cert_pem" ]; then
        ml_log_verbose "Template $template_name has no certificate"
        return 0
    fi

    # Save certificate to temp file for expiry check
    local temp_cert
    temp_cert=$(mktemp)
    echo "$cert_pem" > "$temp_cert"

    # Check certificate expiry using tls_check_certificate_expiry from tls-utils.sh
    local days_remaining
    if ! days_remaining=$(tls_check_certificate_expiry "$temp_cert" 2>/dev/null); then
        ml_log_warning "Failed to check expiry for template $template_name"
        rm -f "$temp_cert"
        return 1
    fi

    rm -f "$temp_cert"

    # Parse days remaining
    days_remaining=$(echo "$days_remaining" | head -1 | tr -d ' ')

    if [ -z "$days_remaining" ] || [ "$days_remaining" -lt 0 ]; then
        ml_log_error "Certificate in template $template_name has EXPIRED"
        renew_generate_csr "$template_name"
        return 2
    elif [ "$days_remaining" -le "$RENEWAL_THRESHOLD" ]; then
        ml_log_warning "Certificate in template $template_name expires in $days_remaining days (threshold: $RENEWAL_THRESHOLD)"
        renew_generate_csr "$template_name"
        return 2
    else
        ml_log_verbose "Template $template_name: certificate valid for $days_remaining days"
        return 0
    fi
}

renew_generate_csr() {
    local template_name="$1"

    if [ "$DRY_RUN" = true ]; then
        ml_log_info "[DRY-RUN] Would generate CSR for: $template_name"
        return 0
    fi

    ml_log_info "Generating CSR for: $template_name"

    # Get template properties to extract subject information
    local response status_code
    response=$(curl -s -w "%{http_code}" --anyauth -u "$MARKLOGIC_USER:$MARKLOGIC_PASS" \
        "http://$MARKLOGIC_HOST:$MARKLOGIC_PORT/manage/v2/certificate-templates/$template_name/properties?format=json")

    status_code="${response: -3}"
    local body="${response%???}"

    if [ "$status_code" != "200" ]; then
        ml_log_error "Failed to fetch template properties (HTTP $status_code)"
        return 1
    fi

    # Extract certificate to get subject details
    local cert_pem
    cert_pem=$(echo "$body" | jq -r '.["certificate-template-properties"]["template-certificate"]? // empty' 2>/dev/null)

    if [ -z "$cert_pem" ]; then
        ml_log_error "No certificate found in template $template_name"
        return 1
    fi

    # Save to temp file and extract subject
    local temp_cert
    temp_cert=$(mktemp)
    echo "$cert_pem" > "$temp_cert"

    local subject
    subject=$(openssl x509 -in "$temp_cert" -noout -subject -nameopt RFC2253 2>/dev/null | sed 's/subject=//')

    local cn
    cn=$(echo "$subject" | grep -o 'CN=[^,]*' | cut -d'=' -f2)

    rm -f "$temp_cert"

    if [ -z "$cn" ]; then
        ml_log_error "Failed to extract Common Name from certificate"
        return 1
    fi

    # Generate CSR filename
    local csr_file="${template_name}-renewal-$(date +%Y%m%d).csr"
    local key_file="${template_name}-renewal-$(date +%Y%m%d)-key.pem"

    ml_log_info "Generating CSR for CN: $cn"
    ml_log_info "CSR will be saved to: $csr_file"

    # Create OpenSSL config for CSR generation
    local config_file
    config_file=$(mktemp)

    cat > "$config_file" << EOF
[ req ]
default_bits = 2048
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[ req_distinguished_name ]
CN = $cn

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
EOF

    # Generate private key and CSR
    if ! openssl genrsa -out "$key_file" 2048 2>/dev/null; then
        ml_log_error "Failed to generate private key"
        rm -f "$config_file"
        return 1
    fi

    if ! openssl req -new -key "$key_file" -out "$csr_file" -config "$config_file" 2>/dev/null; then
        ml_log_error "Failed to generate CSR"
        rm -f "$config_file" "$key_file"
        return 1
    fi

    rm -f "$config_file"
    chmod 600 "$key_file"

    ml_log_success "CSR generated: $csr_file"
    ml_log_success "Private key: $key_file"
    ml_log_info "Submit CSR to your Certificate Authority for signing"

    return 0
}

renew_notify() {
    local level="$1"
    local message="$2"

    # Email notification
    if [ -n "$NOTIFY_EMAIL" ]; then
        if [ "$DRY_RUN" = true ]; then
            ml_log_info "[DRY-RUN] Would send email to: $NOTIFY_EMAIL"
        else
            echo "$message" | mail -s "Certificate Renewal Alert [$level]" "$NOTIFY_EMAIL" 2>/dev/null
            if [ $? -eq 0 ]; then
                ml_log_info "Email notification sent to: $NOTIFY_EMAIL"
            fi
        fi
    fi

    # Webhook notification
    if [ -n "$NOTIFY_WEBHOOK" ]; then
        if [ "$DRY_RUN" = true ]; then
            ml_log_info "[DRY-RUN] Would POST to webhook: $NOTIFY_WEBHOOK"
        else
            curl -s -X POST "$NOTIFY_WEBHOOK" \
                -H "Content-Type: application/json" \
                -d "{\"level\":\"$level\",\"message\":\"$message\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" \
                >/dev/null 2>&1
            if [ $? -eq 0 ]; then
                ml_log_info "Webhook notification sent"
            fi
        fi
    fi
}

# ================================================================
# MAIN
# ================================================================

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --threshold)
                RENEWAL_THRESHOLD="$2"
                shift 2
                ;;
            --cert-template)
                CERT_TEMPLATE="$2"
                shift 2
                ;;
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
                MARKLOGIC_PASS="$2"
                shift 2
                ;;
            --notify-email)
                NOTIFY_EMAIL="$2"
                shift 2
                ;;
            --notify-webhook)
                NOTIFY_WEBHOOK="$2"
                shift 2
                ;;
            --log-file)
                LOG_FILE="$2"
                shift 2
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --cron)
                CRON_MODE=true
                ML_NO_COLOR=1
                shift
                ;;
            --verbose)
                ML_VERBOSE=1
                shift
                ;;
            --help)
                show_help
                exit 0
                ;;
            *)
                ml_log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done

    # Disable colors in cron mode
    if [ "$CRON_MODE" = true ]; then
        export ML_NO_COLOR=1
    fi

    # Log start
    if [ "$DRY_RUN" = true ]; then
        ml_log_info "Starting certificate renewal check (DRY-RUN mode)"
    else
        ml_log_info "Starting certificate renewal check"
    fi

    # Check certificates
    renew_check_certificates
    local result=$?

    # Log completion
    if [ $result -eq 0 ]; then
        ml_log_success "Certificate renewal check completed successfully"
        exit 0
    elif [ $result -eq 2 ]; then
        ml_log_warning "Certificate renewal check completed with warnings"
        exit 2
    else
        ml_log_error "Certificate renewal check failed"
        exit 1
    fi
}

# Run main if executed directly
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
