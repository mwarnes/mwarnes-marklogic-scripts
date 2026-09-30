#!/bin/bash

# ================================================================
# OAuth JWKS Key Rotation Automation Script
# ================================================================
#
# Automates the rotation of OAuth2 JWKS keys by fetching from
# provider endpoints, comparing with MarkLogic configuration, and
# managing key lifecycle with automated cleanup.
#
# Author: Martin Warnes
# Version: 1.0.1
# Date: February 2026
#
# ================================================================

# Source utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../marklogic-utils.sh"

# ================================================================
# CONFIGURATION
# ================================================================

EXTERNAL_SECURITY=""
JWKS_URL=""
RETENTION_DAYS=30
DRY_RUN=false
AUDIT_LOG="/var/log/marklogic-jwks-rotation.log"
NOTIFY_WEBHOOK=""
CRON_MODE=false
MARKLOGIC_HOST="localhost"
MARKLOGIC_PORT=8002
MARKLOGIC_USER="admin"
MARKLOGIC_PASS="admin"

# ================================================================
# FUNCTIONS
# ================================================================

show_help() {
    cat << EOF
OAuth JWKS Key Rotation Automation Script

Automates fetching and rotating OAuth2 JWKS keys from identity providers.

USAGE:
    $0 [OPTIONS]

OPTIONS:
    --external-security <name>      External Security configuration name (required)
    --jwks-url <url>                JWKS endpoint URL (auto-detected if not provided)
    --retention-days <days>         Keep old keys for N days (default: 30)
    --audit-log <path>              Audit log file (default: /var/log/marklogic-jwks-rotation.log)
    --notify-webhook <url>          Webhook URL for notifications
    --marklogic-host <host>         MarkLogic host (default: localhost)
    --marklogic-port <port>         MarkLogic Management API port (default: 8002)
    --marklogic-user <user>         MarkLogic admin user (default: admin)
    --marklogic-pass <pass>         MarkLogic admin password (default: admin)
    --dry-run                       Preview changes without applying
    --cron                          Cron-friendly output (no colors)
    --verbose                       Enable detailed logging
    --help                          Display this help message

EXAMPLES:
    # Auto-detect JWKS URL from configuration
    $0 --external-security OAuth2-Config

    # Explicit JWKS URL
    $0 --external-security OAuth2-Config \\
       --jwks-url https://auth.example.com/.well-known/jwks.json

    # Dry-run mode
    $0 --external-security OAuth2-Config --dry-run

    # With webhook notifications
    $0 --external-security OAuth2-Config \\
       --notify-webhook https://monitoring.example.com/webhook

    # Cron job (weekly rotation, Sunday 2 AM)
    # 0 2 * * 0 $0 --external-security OAuth2-Config --cron

EXIT CODES:
    0 - Success
    1 - Error
    2 - Keys rotated (new keys added or old keys removed)

EOF
}

rotate_fetch_jwks() {
    local jwks_url="$1"

    ml_log_info "Fetching JWKS from: $jwks_url"

    local response status_code
    response=$(curl -s -w "%{http_code}" "$jwks_url")

    status_code="${response: -3}"
    local body="${response%???}"

    if [ "$status_code" != "200" ]; then
        ml_log_error "Failed to fetch JWKS (HTTP $status_code)"
        return 1
    fi

    # Validate JSON
    if ! echo "$body" | jq . >/dev/null 2>&1; then
        ml_log_error "Invalid JSON response from JWKS endpoint"
        return 1
    fi

    echo "$body"
}

rotate_get_existing_keys() {
    local external_security="$1"

    ml_log_info "Fetching existing keys from MarkLogic"

    local response status_code
    response=$(curl -s -w "%{http_code}" --anyauth -u "$MARKLOGIC_USER:$MARKLOGIC_PASS" \
        -H "Accept: application/json" \
        "http://$MARKLOGIC_HOST:$MARKLOGIC_PORT/manage/v2/external-security/$external_security/properties?format=json")

    status_code="${response: -3}"
    local body="${response%???}"

    if [ "$status_code" != "200" ]; then
        ml_log_error "Failed to fetch external security configuration (HTTP $status_code)"
        return 1
    fi

    # Extract key IDs
    local key_ids
    key_ids=$(echo "$body" | jq -r '.["external-security-properties"]["oauth-server"]["oauth-jwk-id"][]? // empty' 2>/dev/null)

    if [ -z "$key_ids" ]; then
        ml_log_info "No existing keys found in configuration"
        return 0
    fi

    echo "$key_ids"
}

rotate_compare_keys() {
    local jwks_data="$1"
    local existing_keys="$2"

    # Extract key IDs from JWKS
    local remote_keys
    remote_keys=$(echo "$jwks_data" | jq -r '.keys[]?.kid // empty' 2>/dev/null)

    if [ -z "$remote_keys" ]; then
        ml_log_warning "No keys found in JWKS endpoint"
        return 1
    fi

    # Find new keys (in remote but not in MarkLogic)
    local new_keys=""
    while IFS= read -r remote_kid; do
        [ -z "$remote_kid" ] && continue

        local found=false
        while IFS= read -r existing_kid; do
            [ -z "$existing_kid" ] && continue
            if [ "$remote_kid" = "$existing_kid" ]; then
                found=true
                break
            fi
        done <<< "$existing_keys"

        if [ "$found" = false ]; then
            if [ -n "$new_keys" ]; then
                new_keys="${new_keys}
${remote_kid}"
            else
                new_keys="$remote_kid"
            fi
        fi
    done <<< "$remote_keys"

    # Find obsolete keys (in MarkLogic but not in remote)
    local obsolete_keys=""
    while IFS= read -r existing_kid; do
        [ -z "$existing_kid" ] && continue

        local found=false
        while IFS= read -r remote_kid; do
            [ -z "$remote_kid" ] && continue
            if [ "$existing_kid" = "$remote_kid" ]; then
                found=true
                break
            fi
        done <<< "$remote_keys"

        if [ "$found" = false ]; then
            if [ -n "$obsolete_keys" ]; then
                obsolete_keys="${obsolete_keys}
${existing_kid}"
            else
                obsolete_keys="$existing_kid"
            fi
        fi
    done <<< "$existing_keys"

    # Export results
    export ROTATE_NEW_KEYS="$new_keys"
    export ROTATE_OBSOLETE_KEYS="$obsolete_keys"

    local new_count=0
    local obsolete_count=0
    [ -n "$new_keys" ] && new_count=$(echo "$new_keys" | wc -l | tr -d ' ')
    [ -n "$obsolete_keys" ] && obsolete_count=$(echo "$obsolete_keys" | wc -l | tr -d ' ')

    ml_log_info "Key comparison: $new_count new, $obsolete_count obsolete"

    return 0
}

rotate_add_new_keys() {
    local external_security="$1"
    local jwks_data="$2"
    local new_keys="$3"

    [ -z "$new_keys" ] && return 0

    ml_log_info "Adding new keys to MarkLogic"

    local added_count=0

    while IFS= read -r kid; do
        [ -z "$kid" ] && continue

        # Extract key data for this kid
        local key_data
        key_data=$(echo "$jwks_data" | jq -r --arg kid "$kid" '.keys[] | select(.kid == $kid)' 2>/dev/null)

        if [ -z "$key_data" ]; then
            ml_log_warning "Failed to extract key data for kid: $kid"
            continue
        fi

        # Convert to PEM format if RSA key
        local kty
        kty=$(echo "$key_data" | jq -r '.kty // empty')

        if [ "$kty" = "RSA" ]; then
            local n e
            n=$(echo "$key_data" | jq -r '.n // empty')
            e=$(echo "$key_data" | jq -r '.e // empty')

            if [ -z "$n" ] || [ -z "$e" ]; then
                ml_log_warning "Invalid RSA key data for kid: $kid"
                continue
            fi

            # Create temporary Python script to convert to PEM
            local temp_script
            temp_script=$(mktemp)

            cat > "$temp_script" << 'EOFPYTHON'
import sys
import base64
import json
from binascii import a2b_base64

def base64url_to_int(val):
    val = val.replace('-', '+').replace('_', '/')
    padding = 4 - (len(val) % 4)
    if padding != 4:
        val += '=' * padding
    return int.from_bytes(a2b_base64(val), byteorder='big')

data = json.load(sys.stdin)
n = base64url_to_int(data['n'])
e = base64url_to_int(data['e'])

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

public_numbers = rsa.RSAPublicNumbers(e, n)
public_key = public_numbers.public_key()

pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

print(pem.decode('utf-8'))
EOFPYTHON

            local pem_key
            if command -v python3 >/dev/null 2>&1; then
                pem_key=$(echo "$key_data" | python3 "$temp_script" 2>/dev/null)
            else
                ml_log_warning "Python3 not available, skipping key conversion for kid: $kid"
                rm -f "$temp_script"
                continue
            fi

            rm -f "$temp_script"

            if [ -z "$pem_key" ]; then
                ml_log_warning "Failed to convert key to PEM for kid: $kid"
                continue
            fi
        fi

        if [ "$DRY_RUN" = true ]; then
            ml_log_info "[DRY-RUN] Would add key: $kid"
            ((added_count++))
            continue
        fi

        # Add key to MarkLogic using Management API
        local add_payload
        add_payload=$(cat << EOF
{
  "operation": "add-jwk-id",
  "jwk-id": "$kid"
}
EOF
)

        local response status_code
        response=$(curl -s -w "%{http_code}" --anyauth -u "$MARKLOGIC_USER:$MARKLOGIC_PASS" \
            -X POST \
            -H "Content-Type: application/json" \
            -d "$add_payload" \
            "http://$MARKLOGIC_HOST:$MARKLOGIC_PORT/manage/v2/external-security/$external_security/properties")

        status_code="${response: -3}"

        if [ "$status_code" = "204" ] || [ "$status_code" = "200" ]; then
            ml_log_success "Added key: $kid"
            ((added_count++))
            rotate_audit_log "ADD" "$kid" "$external_security"
        else
            ml_log_error "Failed to add key: $kid (HTTP $status_code)"
        fi

    done <<< "$new_keys"

    ml_log_info "Added $added_count new key(s)"
    return 0
}

rotate_cleanup_old_keys() {
    local external_security="$1"
    local obsolete_keys="$2"

    [ -z "$obsolete_keys" ] && return 0

    ml_log_info "Cleaning up obsolete keys (retention: $RETENTION_DAYS days)"

    local removed_count=0

    while IFS= read -r kid; do
        [ -z "$kid" ] && continue

        # Check if key is old enough to remove (based on audit log)
        local key_age
        key_age=$(rotate_get_key_age "$kid")

        if [ -n "$key_age" ] && [ "$key_age" -lt "$RETENTION_DAYS" ]; then
            ml_log_info "Keeping key $kid (age: $key_age days, retention: $RETENTION_DAYS days)"
            continue
        fi

        if [ "$DRY_RUN" = true ]; then
            ml_log_info "[DRY-RUN] Would remove key: $kid"
            ((removed_count++))
            continue
        fi

        # Remove key from MarkLogic
        local remove_payload
        remove_payload=$(cat << EOF
{
  "operation": "remove-jwk-id",
  "jwk-id": "$kid"
}
EOF
)

        local response status_code
        response=$(curl -s -w "%{http_code}" --anyauth -u "$MARKLOGIC_USER:$MARKLOGIC_PASS" \
            -X POST \
            -H "Content-Type: application/json" \
            -d "$remove_payload" \
            "http://$MARKLOGIC_HOST:$MARKLOGIC_PORT/manage/v2/external-security/$external_security/properties")

        status_code="${response: -3}"

        if [ "$status_code" = "204" ] || [ "$status_code" = "200" ]; then
            ml_log_success "Removed obsolete key: $kid"
            ((removed_count++))
            rotate_audit_log "REMOVE" "$kid" "$external_security"
        else
            ml_log_error "Failed to remove key: $kid (HTTP $status_code)"
        fi

    done <<< "$obsolete_keys"

    ml_log_info "Removed $removed_count obsolete key(s)"
    return 0
}

rotate_audit_log() {
    local action="$1"
    local kid="$2"
    local external_security="$3"

    local timestamp
    timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)

    local log_entry="$timestamp|$action|$external_security|$kid"

    if [ "$DRY_RUN" = false ]; then
        echo "$log_entry" >> "$AUDIT_LOG"
    fi

    ml_log_verbose "Audit: $log_entry"
}

rotate_get_key_age() {
    local kid="$1"

    # Search audit log for when key was first added
    if [ ! -f "$AUDIT_LOG" ]; then
        return 0
    fi

    local first_add
    first_add=$(grep "|ADD|.*|$kid" "$AUDIT_LOG" | head -1 | cut -d'|' -f1)

    if [ -z "$first_add" ]; then
        # Key not in audit log, assume it's old enough to remove
        echo "$RETENTION_DAYS"
        return 0
    fi

    # Calculate age in days
    local add_epoch now_epoch age_seconds age_days
    add_epoch=$(date -j -f "%Y-%m-%dT%H:%M:%SZ" "$first_add" "+%s" 2>/dev/null || date -d "$first_add" "+%s" 2>/dev/null)
    now_epoch=$(date "+%s")

    if [ -z "$add_epoch" ]; then
        # Failed to parse date, assume old enough
        echo "$RETENTION_DAYS"
        return 0
    fi

    age_seconds=$((now_epoch - add_epoch))
    age_days=$((age_seconds / 86400))

    echo "$age_days"
}

rotate_notify() {
    local message="$1"

    if [ -z "$NOTIFY_WEBHOOK" ]; then
        return 0
    fi

    if [ "$DRY_RUN" = true ]; then
        ml_log_info "[DRY-RUN] Would send webhook notification"
        return 0
    fi

    ml_log_info "Sending webhook notification"

    curl -s -X POST "$NOTIFY_WEBHOOK" \
        -H "Content-Type: application/json" \
        -d "{\"event\":\"jwks-rotation\",\"message\":\"$message\",\"external_security\":\"$EXTERNAL_SECURITY\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" \
        >/dev/null 2>&1 || true
}

rotate_auto_detect_jwks_url() {
    local external_security="$1"

    ml_log_info "Auto-detecting JWKS URL from configuration"

    local response status_code
    response=$(curl -s -w "%{http_code}" --anyauth -u "$MARKLOGIC_USER:$MARKLOGIC_PASS" \
        -H "Accept: application/json" \
        "http://$MARKLOGIC_HOST:$MARKLOGIC_PORT/manage/v2/external-security/$external_security/properties?format=json")

    status_code="${response: -3}"
    local body="${response%???}"

    if [ "$status_code" != "200" ]; then
        ml_log_error "Failed to fetch external security configuration (HTTP $status_code)"
        return 1
    fi

    # Extract JWKS URI
    local jwks_uri
    jwks_uri=$(echo "$body" | jq -r '.["external-security-properties"]["oauth-server"]["oauth-jwks-uri"]? // empty' 2>/dev/null)

    if [ -z "$jwks_uri" ]; then
        ml_log_error "Could not auto-detect JWKS URL from configuration"
        return 1
    fi

    echo "$jwks_uri"
}

# ================================================================
# MAIN
# ================================================================

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --external-security)
                EXTERNAL_SECURITY="$2"
                shift 2
                ;;
            --jwks-url)
                JWKS_URL="$2"
                shift 2
                ;;
            --retention-days)
                RETENTION_DAYS="$2"
                shift 2
                ;;
            --audit-log)
                AUDIT_LOG="$2"
                shift 2
                ;;
            --notify-webhook)
                NOTIFY_WEBHOOK="$2"
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

    # Validate required parameters
    if [ -z "$EXTERNAL_SECURITY" ]; then
        ml_log_error "External security name is required (--external-security)"
        show_help
        exit 1
    fi

    # Disable colors in cron mode
    if [ "$CRON_MODE" = true ]; then
        export ML_NO_COLOR=1
    fi

    if [ "$DRY_RUN" = true ]; then
        ml_log_info "Starting JWKS key rotation (DRY-RUN mode)"
    else
        ml_log_info "Starting JWKS key rotation"
    fi

    # Auto-detect JWKS URL if not provided
    if [ -z "$JWKS_URL" ]; then
        JWKS_URL=$(rotate_auto_detect_jwks_url "$EXTERNAL_SECURITY")
        if [ $? -ne 0 ]; then
            exit 1
        fi
        ml_log_info "Detected JWKS URL: $JWKS_URL"
    fi

    # Fetch JWKS from remote
    local jwks_data
    jwks_data=$(rotate_fetch_jwks "$JWKS_URL")
    if [ $? -ne 0 ]; then
        exit 1
    fi

    # Get existing keys from MarkLogic
    local existing_keys
    existing_keys=$(rotate_get_existing_keys "$EXTERNAL_SECURITY")

    # Compare keys
    if ! rotate_compare_keys "$jwks_data" "$existing_keys"; then
        exit 1
    fi

    # Check if any changes needed
    if [ -z "$ROTATE_NEW_KEYS" ] && [ -z "$ROTATE_OBSOLETE_KEYS" ]; then
        ml_log_success "No key rotation needed (all keys up to date)"
        exit 0
    fi

    # Add new keys
    if [ -n "$ROTATE_NEW_KEYS" ]; then
        rotate_add_new_keys "$EXTERNAL_SECURITY" "$jwks_data" "$ROTATE_NEW_KEYS"
    fi

    # Remove obsolete keys
    if [ -n "$ROTATE_OBSOLETE_KEYS" ]; then
        rotate_cleanup_old_keys "$EXTERNAL_SECURITY" "$ROTATE_OBSOLETE_KEYS"
    fi

    # Send notification
    local new_count=0
    local obsolete_count=0
    [ -n "$ROTATE_NEW_KEYS" ] && new_count=$(echo "$ROTATE_NEW_KEYS" | wc -l | tr -d ' ')
    [ -n "$ROTATE_OBSOLETE_KEYS" ] && obsolete_count=$(echo "$ROTATE_OBSOLETE_KEYS" | wc -l | tr -d ' ')

    rotate_notify "JWKS rotation completed: $new_count new keys, $obsolete_count removed"

    ml_log_success "JWKS key rotation completed successfully"
    exit 2
}

# Run main if executed directly
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
