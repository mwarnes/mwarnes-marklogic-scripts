#!/bin/bash

# JWKS Key Cleanup Analysis Script
# Usage: ./cleanup-obsolete-jwks-keys.sh <JWKS_ENDPOINT_URL> [--delete-keys] [OPTIONS]
# 
# This script compares keys in MarkLogic External Security profile with
# keys currently available in the JWKS endpoint and identifies obsolete
# keys that can be safely removed from MarkLogic.
# 
# Requirements: curl, jq
#
# ⚠️  DISCLAIMER: This software is NOT an official Progress MarkLogic product.
# This integration toolset is provided "AS IS" without any warranties or guarantees.
# Usage is solely at your own risk. No support will be provided by Progress MarkLogic
# for these scripts. Users are responsible for testing and validating functionality
# in their environment. Always test in a development environment before using in production.
# By using this script, you acknowledge and accept full responsibility for any consequences.

set -e  # Exit on any error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../marklogic-utils.sh"
source "$SCRIPT_DIR/oauth2-utils.sh"

# Default configuration values
DEFAULT_MARKLOGIC_HOST="${MARKLOGIC_HOST:-localhost}"
DEFAULT_MARKLOGIC_PORT="${MARKLOGIC_PORT:-8002}"
DEFAULT_MARKLOGIC_USER="${MARKLOGIC_USER:-admin}"
DEFAULT_MARKLOGIC_PASS="${MARKLOGIC_PASS:-}"
DEFAULT_EXTERNAL_SECURITY_NAME="Your-External-Security-Profile"
DRY_RUN=false
BACKUP_FILE=""
CURRENT_JWKS_KEYS=""
MARKLOGIC_KEYS=""
EXISTING_CONFIG=""

# Function to show usage
show_usage() {
    echo "Usage: $0 <JWKS_ENDPOINT_URL> [--delete-keys] [OPTIONS]"
    echo ""
    echo "Required:"
    echo "  <JWKS_ENDPOINT_URL>        The HTTPS/HTTP URL of the JWKS endpoint"
    echo ""
    echo "Modes:"
    echo "  (default)                  Analysis mode - identifies obsolete keys but doesn't delete them"
    echo "  --delete-keys              Delete mode - actually removes obsolete keys from MarkLogic"
    echo "  --confirm-delete           Confirm irreversible deletion for unattended use"
    echo "  --dry-run                  Preview only; does not fetch JWKS or contact MarkLogic"
    echo ""
    echo "MarkLogic Configuration Options:"
    echo "  --marklogic-host HOST      MarkLogic server hostname (default: $DEFAULT_MARKLOGIC_HOST)"
    echo "  --marklogic-port PORT      MarkLogic Management API port (default: $DEFAULT_MARKLOGIC_PORT)"
    echo "  --marklogic-user USER      MarkLogic admin username (default: $DEFAULT_MARKLOGIC_USER)"
    echo "  --marklogic-pass PASS      Rejected; use MARKLOGIC_PASS or a hidden prompt"
    echo "  --external-security NAME   External Security profile name (default: $DEFAULT_EXTERNAL_SECURITY_NAME)"
    echo ""
    echo "Examples:"
    echo "  # Analyze obsolete keys (safe mode)"
    echo "  $0 https://your-idp.example.com/realms/your-realm/protocol/openid-connect/certs"
    echo ""
    echo "  # Delete obsolete keys with default settings"
    echo "  $0 https://your-idp.example.com/jwks --delete-keys"
    echo ""
    echo "  # Analyze with custom MarkLogic configuration"
    echo "  $0 https://your-idp.example.com/jwks \\"
    echo "     --marklogic-host ml.company.com --external-security OAuth2-Production"
    echo ""
    echo "  # Delete only after review, backup, and explicit confirmation"
    echo "  $0 https://your-idp.example.com/jwks --delete-keys --confirm-delete"
    echo ""
    echo "Set MARKLOGIC_PASS for unattended use; interactive runs prompt without echo."
    echo "JWKS URLs containing userinfo, query values, or fragments are rejected."
    echo ""
    echo "This script analyzes key differences between MarkLogic and JWKS endpoint"
    echo "and identifies obsolete keys that are no longer in the JWKS."
    exit "${1:-1}"
}

# Initialize variables with defaults
JWKS_URL=""
DELETE_KEYS=false
MARKLOGIC_HOST="$DEFAULT_MARKLOGIC_HOST"
MARKLOGIC_PORT="$DEFAULT_MARKLOGIC_PORT"
MARKLOGIC_USER="$DEFAULT_MARKLOGIC_USER"
MARKLOGIC_PASS="$DEFAULT_MARKLOGIC_PASS"
EXTERNAL_SECURITY_NAME="$DEFAULT_EXTERNAL_SECURITY_NAME"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --delete-keys)
            DELETE_KEYS=true
            shift
            ;;
        --confirm-delete|--yes)
            YES=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --marklogic-host)
            if [[ -z "$2" || "$2" == --* ]]; then
                echo "Error: --marklogic-host requires a value"
                show_usage
            fi
            MARKLOGIC_HOST="$2"
            shift 2
            ;;
        --marklogic-port)
            if [[ -z "$2" || "$2" == --* ]]; then
                echo "Error: --marklogic-port requires a value"
                show_usage
            fi
            if ! [[ "$2" =~ ^[0-9]+$ ]] || [ "$2" -lt 1 ] || [ "$2" -gt 65535 ]; then
                echo "Error: --marklogic-port must be a valid port number (1-65535)"
                show_usage
            fi
            MARKLOGIC_PORT="$2"
            shift 2
            ;;
        --marklogic-user)
            if [[ -z "$2" || "$2" == --* ]]; then
                echo "Error: --marklogic-user requires a value"
                show_usage
            fi
            MARKLOGIC_USER="$2"
            shift 2
            ;;
        --marklogic-pass)
            echo "Error: --marklogic-pass VALUE is rejected. Use MARKLOGIC_PASS or a hidden prompt."
            exit 1
            ;;
        --external-security)
            if [[ -z "$2" || "$2" == --* ]]; then
                echo "Error: --external-security requires a value"
                show_usage
            fi
            EXTERNAL_SECURITY_NAME="$2"
            shift 2
            ;;
        --verbose)
            ML_VERBOSE=1
            shift
            ;;
        --help|-h)
            show_usage 0
            ;;
        --*)
            echo "Error: Unknown option"
            show_usage
            ;;
        *)
            if [[ -z "$JWKS_URL" ]]; then
                JWKS_URL="$1"
            else
                echo "Error: Unexpected argument $1"
                show_usage
            fi
            shift
            ;;
    esac
done

# Check if JWKS URL is provided
if [[ -z "$JWKS_URL" ]]; then
    echo "Error: JWKS endpoint URL is required"
    show_usage
fi

oauth2_validate_url "$JWKS_URL" || exit 1
oauth2_api_path_segment "$EXTERNAL_SECURITY_NAME" >/dev/null || { echo "Error: Invalid external-security name" >&2; exit 1; }
case "$MARKLOGIC_HOST" in http://*|https://*) ;; *) MARKLOGIC_HOST="http://$MARKLOGIC_HOST" ;; esac
oauth2_validate_url "$MARKLOGIC_HOST" || exit 1
MARKLOGIC_AUTHORITY="${MARKLOGIC_HOST#*://}"
case "$MARKLOGIC_AUTHORITY" in */) MARKLOGIC_HOST="${MARKLOGIC_HOST%/}" ;; */*) echo "Error: MarkLogic host must not include a path" >&2; exit 1 ;; esac
ml_parse_host_url "$MARKLOGIC_HOST"
[[ -n "$ML_HOST" && "$ML_HOST" =~ ^[A-Za-z0-9.-]+$ ]] || { echo "Error: Invalid MarkLogic host" >&2; exit 1; }
[[ "$ML_PORT" =~ ^[0-9]{1,5}$ ]] && [ "$ML_PORT" -ge 1 ] && [ "$ML_PORT" -le 65535 ] || { echo "Error: Invalid MarkLogic port" >&2; exit 1; }

if [ "$DRY_RUN" = true ]; then
    echo "[DRY-RUN] Would fetch JWKS and MarkLogic inventories, compare key IDs, and report any deletion plan. Remote state is unknown; no requests or backups were created."
    [ "$DELETE_KEYS" = true ] && echo "[DRY-RUN] Delete mode was requested, but no key can be classified or deleted without live inventories."
    exit 0
fi

# Show delete mode warning if enabled
if [ "$DELETE_KEYS" = true ]; then
    echo "⚠️  DELETE MODE ENABLED - Obsolete keys will be removed from MarkLogic!"
    echo ""
fi

# Check if required tools are available
command -v curl >/dev/null 2>&1 || { echo "Error: curl is required but not installed." >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "Error: jq is required but not installed." >&2; exit 1; }
[ -n "$MARKLOGIC_USER" ] || { echo "Error: MarkLogic user is required" >&2; exit 1; }
MARKLOGIC_PASS=$(ml_resolve_password) || exit 1

if [ "$DELETE_KEYS" = true ]; then
    echo "JWKS Key Cleanup and Deletion"
else
    echo "JWKS Key Cleanup Analysis"
fi
echo "================================="
echo "JWKS Endpoint: configured and syntactically validated"
echo "MarkLogic External Security Profile: $EXTERNAL_SECURITY_NAME"
if [ "$DELETE_KEYS" = true ]; then
    echo "Mode: DELETE MODE - Will remove obsolete keys"
else
    echo "Mode: ANALYSIS MODE - Will identify obsolete keys only"
fi
echo ""

# Fetch and validate a non-empty JWKS inventory before comparing or deleting keys.
get_current_jwks_keys() {
    echo "Fetching the current JWKS inventory..."
    if ! JWKS_DATA=$(curl -sS --fail --connect-timeout 10 --max-time 30 "$JWKS_URL"); then
        echo "Error: Failed to fetch JWKS data" >&2
        return 1
    fi
    if ! echo "$JWKS_DATA" | jq -e '(.keys | type == "array") and (.keys | length > 0)' >/dev/null 2>&1; then
        echo "Error: JWKS is invalid or contains no keys; refusing to infer that stored keys are obsolete" >&2
        return 1
    fi

    local total_keys key_count
    total_keys=$(echo "$JWKS_DATA" | jq '.keys | length') || return 1
    CURRENT_JWKS_KEYS=$(echo "$JWKS_DATA" | jq -r '.keys[].kid // empty' | sort -u) || return 1
    key_count=$(printf '%s\n' "$CURRENT_JWKS_KEYS" | awk 'NF {n++} END {print n+0}')
    if [ "$key_count" -eq 0 ] || [ "$key_count" -ne "$total_keys" ]; then
        echo "Error: JWKS inventory has missing or duplicate key IDs; refusing key cleanup" >&2
        return 1
    fi
    echo "Found $key_count current JWKS key(s)."
}

# Fetch a complete MarkLogic key inventory; failures/empty inventories are never treated as absence.
get_marklogic_keys() {
    echo "Fetching the MarkLogic external-security key inventory..."
    local profile_path response status_code keys_json total_keys key_count
    profile_path=$(oauth2_api_path_segment "$EXTERNAL_SECURITY_NAME") || return 1
    response=$(ml_api_request GET "/manage/v2/external-security/$profile_path/properties?format=json" "$MARKLOGIC_USER" "$MARKLOGIC_PASS") || {
        echo "Error: Could not retrieve the MarkLogic configuration" >&2
        return 1
    }
    status_code=$(ml_extract_status_code "$response")
    [ "$status_code" = "200" ] || { echo "Error: MarkLogic inventory request returned HTTP $status_code" >&2; return 1; }
    EXISTING_CONFIG=$(ml_extract_response_body "$response")
    echo "$EXISTING_CONFIG" | jq -e . >/dev/null 2>&1 || { echo "Error: MarkLogic returned invalid JSON" >&2; return 1; }

    keys_json=$(echo "$EXISTING_CONFIG" | jq -c '.["external-security-properties"]["oauth-server"]["oauth-jwt-secrets"]["oauth-jwt-secret"] // .["oauth-server"]["oauth-jwt-secrets"]["oauth-jwt-secret"] // empty') || return 1
    echo "$keys_json" | jq -e 'type == "array" and length > 0' >/dev/null 2>&1 || {
        echo "Error: MarkLogic key inventory is empty or unavailable; refusing cleanup" >&2
        return 1
    }
    total_keys=$(echo "$keys_json" | jq 'length') || return 1
    MARKLOGIC_KEYS=$(echo "$keys_json" | jq -r '.[] | .["oauth-jwt-key-id"] // empty' | sort -u) || return 1
    key_count=$(printf '%s\n' "$MARKLOGIC_KEYS" | awk 'NF {n++} END {print n+0}')
    if [ "$key_count" -eq 0 ] || [ "$key_count" -ne "$total_keys" ]; then
        echo "Error: MarkLogic key inventory has missing or duplicate key IDs; refusing cleanup" >&2
        return 1
    fi
    echo "Found $key_count MarkLogic key(s)."
}

save_marklogic_backup() {
    BACKUP_FILE=$(mktemp "${TMPDIR:-/tmp}/oauth-jwks-backup.XXXXXX") || return 1
    chmod 600 "$BACKUP_FILE" || { rm -f "$BACKUP_FILE"; BACKUP_FILE=""; return 1; }
    printf '%s\n' "$EXISTING_CONFIG" > "$BACKUP_FILE" || { rm -f "$BACKUP_FILE"; BACKUP_FILE=""; return 1; }
    echo "Protected MarkLogic configuration snapshot saved to: $BACKUP_FILE"
}

# Function to analyze key differences
analyze_key_differences() {
    echo "📊 Analyzing key differences..."
    echo ""
    
    # Find keys that exist in MarkLogic but not in current JWKS (obsolete keys)
    OBSOLETE_KEYS=""
    if [ -n "$MARKLOGIC_KEYS" ]; then
        while IFS= read -r ml_key; do
            if [ -n "$ml_key" ]; then
                # Check if this MarkLogic key exists in current JWKS
                if ! echo "$CURRENT_JWKS_KEYS" | grep -Fxq -- "$ml_key"; then
                    if [ -z "$OBSOLETE_KEYS" ]; then
                        OBSOLETE_KEYS="$ml_key"
                    else
                        OBSOLETE_KEYS="$OBSOLETE_KEYS"$'\n'"$ml_key"
                    fi
                fi
            fi
        done <<< "$MARKLOGIC_KEYS"
    fi
    
    # Find keys that exist in current JWKS but not in MarkLogic (missing keys)
    MISSING_KEYS=""
    if [ -n "$CURRENT_JWKS_KEYS" ]; then
        while IFS= read -r jwks_key; do
            if [ -n "$jwks_key" ]; then
                # Check if this JWKS key exists in MarkLogic
                if ! echo "$MARKLOGIC_KEYS" | grep -Fxq -- "$jwks_key"; then
                    if [ -z "$MISSING_KEYS" ]; then
                        MISSING_KEYS="$jwks_key"
                    else
                        MISSING_KEYS="$MISSING_KEYS"$'\n'"$jwks_key"
                    fi
                fi
            fi
        done <<< "$CURRENT_JWKS_KEYS"
    fi
    
    # Find keys that exist in both (synchronized keys)
    SYNCHRONIZED_KEYS=""
    if [ -n "$MARKLOGIC_KEYS" ] && [ -n "$CURRENT_JWKS_KEYS" ]; then
        while IFS= read -r ml_key; do
            if [ -n "$ml_key" ]; then
                if echo "$CURRENT_JWKS_KEYS" | grep -Fxq -- "$ml_key"; then
                    if [ -z "$SYNCHRONIZED_KEYS" ]; then
                        SYNCHRONIZED_KEYS="$ml_key"
                    else
                        SYNCHRONIZED_KEYS="$SYNCHRONIZED_KEYS"$'\n'"$ml_key"
                    fi
                fi
            fi
        done <<< "$MARKLOGIC_KEYS"
    fi
    
    # Display results
    echo "🔄 SYNCHRONIZED KEYS (Present in both MarkLogic and JWKS):"
    if [ -n "$SYNCHRONIZED_KEYS" ]; then
        SYNC_COUNT=$(echo "$SYNCHRONIZED_KEYS" | wc -l | tr -d ' ')
        echo "   Count: $SYNC_COUNT"
        while IFS= read -r key_id; do
            [ -n "$key_id" ] && echo "   ✅ $key_id"
        done <<< "$SYNCHRONIZED_KEYS"
    else
        echo "   Count: 0"
        echo "   ⚠️  No keys are synchronized between MarkLogic and JWKS"
    fi
    echo ""
    
    echo "🆕 MISSING KEYS (Present in JWKS but not in MarkLogic):"
    if [ -n "$MISSING_KEYS" ]; then
        MISSING_COUNT=$(echo "$MISSING_KEYS" | wc -l | tr -d ' ')
        echo "   Count: $MISSING_COUNT"
        while IFS= read -r key_id; do
            [ -n "$key_id" ] && echo "   ➕ $key_id"
        done <<< "$MISSING_KEYS"
        echo "   💡 Use scripts/extract-jwks-keys.sh to review safe public key fields; additions require a separate reviewed procedure"
    else
        echo "   Count: 0"
        echo "   ✅ All JWKS keys are already in MarkLogic"
    fi
    echo ""
    
    echo "🗑️  OBSOLETE KEYS (Present in MarkLogic but not in current JWKS):"
    if [ -n "$OBSOLETE_KEYS" ]; then
        OBSOLETE_COUNT=$(echo "$OBSOLETE_KEYS" | wc -l | tr -d ' ')
        echo "   Count: $OBSOLETE_COUNT"
        echo "   ⚠️  These keys can potentially be removed from MarkLogic:"
        while IFS= read -r key_id; do
            [ -n "$key_id" ] && echo "   🔴 $key_id"
        done <<< "$OBSOLETE_KEYS"
        echo ""
        echo "   📋 Key IDs that can be deleted (copy/paste ready):"
        while IFS= read -r key_id; do
            [ -n "$key_id" ] && echo "      $key_id"
        done <<< "$OBSOLETE_KEYS"
    else
        echo "   Count: 0"
        echo "   ✅ No obsolete keys found - MarkLogic is clean"
    fi
    echo ""
}

# Delete obsolete keys only after a valid non-empty inventory and explicit confirmation.
delete_obsolete_keys() {
    if [ "$DRY_RUN" = true ]; then
        echo "[DRY-RUN] Remote key state is unknown; no backup or deletion was performed."
        return 0
    fi
    if [ -z "$OBSOLETE_KEYS" ]; then
        echo "No obsolete keys to delete"
        return 0
    fi

    local obsolete_count deleted_count=0 failed_count=0 key_id key_path profile_path response status_code request_status
    obsolete_count=$(printf '%s\n' "$OBSOLETE_KEYS" | awk 'NF {n++} END {print n+0}')
    profile_path=$(oauth2_api_path_segment "$EXTERNAL_SECURITY_NAME") || return 1
    echo "Delete mode: $obsolete_count key(s) were classified as obsolete from two valid, non-empty inventories."
    echo "A protected configuration snapshot will be saved; provider-side restoration may still be manual."
    if ! ml_confirm "Delete these keys from '$EXTERNAL_SECURITY_NAME'?" "n"; then
        echo "Deletion cancelled"
        return 1
    fi
    save_marklogic_backup || { echo "Could not save the protected configuration snapshot; refusing deletion" >&2; return 1; }

    while IFS= read -r key_id; do
        [ -n "$key_id" ] || continue
        key_path=$(oauth2_api_path_segment "$key_id") || { failed_count=$((failed_count + 1)); continue; }
        if ml_api_call_with_dryrun response DELETE "/manage/v2/external-security/$profile_path/jwt-secrets/$key_path" "$MARKLOGIC_USER" "$MARKLOGIC_PASS"; then
            status_code=$(ml_extract_status_code "$response")
            case "$status_code" in
                200|204) echo "Deleted key '$key_id'"; deleted_count=$((deleted_count + 1)) ;;
                *) echo "Failed to delete key '$key_id' (HTTP $status_code)"; failed_count=$((failed_count + 1)) ;;
            esac
        else
            request_status=$?
            if [ "$request_status" -eq 3 ]; then
                echo "[DRY-RUN] Key deletion request was not sent; remote key state is unknown."
                return 0
            fi
            echo "Failed to delete key '$key_id' (request error)"
            failed_count=$((failed_count + 1))
        fi
    done <<< "$OBSOLETE_KEYS"

    echo "Deleted: $deleted_count; failed: $failed_count. Snapshot: $BACKUP_FILE"
    [ "$failed_count" -eq 0 ]
}

# Function to display summary and recommendations
display_summary() {
    echo "📈 SUMMARY & RECOMMENDATIONS"
    echo "============================="
    
    SYNC_COUNT=0
    MISSING_COUNT=0
    OBSOLETE_COUNT=0
    
    [ -n "$SYNCHRONIZED_KEYS" ] && SYNC_COUNT=$(echo "$SYNCHRONIZED_KEYS" | wc -l | tr -d ' ')
    [ -n "$MISSING_KEYS" ] && MISSING_COUNT=$(echo "$MISSING_KEYS" | wc -l | tr -d ' ')
    [ -n "$OBSOLETE_KEYS" ] && OBSOLETE_COUNT=$(echo "$OBSOLETE_KEYS" | wc -l | tr -d ' ')
    
    echo "🔄 Synchronized keys: $SYNC_COUNT"
    echo "🆕 Missing keys: $MISSING_COUNT"
    echo "🗑️  Obsolete keys: $OBSOLETE_COUNT"
    echo ""
    
    if [ "$MISSING_COUNT" -gt 0 ]; then
        echo "📝 Next Actions:"
        echo "   1. Review new keys with scripts/extract-jwks-keys.sh; no automatic upload is provided"
        echo ""
    fi
    
    if [ "$OBSOLETE_COUNT" -gt 0 ] && [ "$DELETE_KEYS" = false ]; then
        echo "🧹 Cleanup Options:"
        echo "   1. Review obsolete keys before deletion"
        echo "   2. Ensure no applications are using old tokens signed with these keys"
        echo "   3. Consider grace period for key rotation"
        echo "   4. To delete obsolete keys, run:"
        echo "      $0 $JWKS_URL --delete-keys"
        echo ""
        echo "⚠️  IMPORTANT: Only delete keys if you're certain they're no longer needed!"
    elif [ "$OBSOLETE_COUNT" -eq 0 ]; then
        echo "✅ No cleanup needed - all keys are current"
    fi
}

# Main execution
get_current_jwks_keys
get_marklogic_keys
analyze_key_differences

# Delete obsolete keys if requested
if [ "$DELETE_KEYS" = true ]; then
    delete_obsolete_keys
fi

display_summary

if [ "$DELETE_KEYS" = true ]; then
    echo "🏁 Cleanup and deletion complete!"
else
    echo "🏁 Analysis complete!"
fi