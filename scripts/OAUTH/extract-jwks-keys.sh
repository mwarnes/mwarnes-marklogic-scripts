#!/bin/bash

# JWKS Key Extractor with MarkLogic Integration
# Usage: ./extract-jwks-keys.sh <JWKS_ENDPOINT_URL> [--upload-to-marklogic] [OPTIONS]
#
# This script fetches a JWKS endpoint, extracts the key ID (kid), converts
# RSA key data to PEM format, and optionally uploads to MarkLogic External Security.
#
# Requirements: curl, jq, openssl, python3
#
# ⚠️  DISCLAIMER: This software is NOT an official Progress MarkLogic product.
# This integration toolset is provided "AS IS" without any warranties or guarantees.
# Usage is solely at your own risk. No support will be provided by Progress MarkLogic
# for these scripts. Users are responsible for testing and validating functionality
# in their environment. Always test in a development environment before using in production.
# By using this script, you acknowledge and accept full responsibility for any consequences.

set -e  # Exit on any error

# Default configuration values
DEFAULT_MARKLOGIC_HOST="your-marklogic-server.com"
DEFAULT_MARKLOGIC_PORT="8002"
DEFAULT_MARKLOGIC_USER="admin"
DEFAULT_MARKLOGIC_PASS="your-admin-password"
DEFAULT_EXTERNAL_SECURITY_NAME="Your-External-Security-Profile"

# Function to show usage
show_usage() {
    echo "Usage: $0 <JWKS_ENDPOINT_URL> [--upload-to-marklogic] [OPTIONS]"
    echo ""
    echo "Required:"
    echo "  <JWKS_ENDPOINT_URL>        The HTTPS/HTTP URL of the JWKS endpoint"
    echo ""
    echo "Flags:"
    echo "  --upload-to-marklogic      Upload new keys to MarkLogic (default: analysis only)
  --insecure                 Skip TLS verification of the JWKS endpoint (self-signed IdP; not recommended)"
    echo ""
    echo "MarkLogic Configuration Options:"
    echo "  --marklogic-host HOST      MarkLogic server hostname (default: $DEFAULT_MARKLOGIC_HOST)"
    echo "  --marklogic-port PORT      MarkLogic Management API port (default: $DEFAULT_MARKLOGIC_PORT)"
    echo "  --marklogic-user USER      MarkLogic admin username (default: $DEFAULT_MARKLOGIC_USER)"
    echo "  --marklogic-pass PASS      MarkLogic admin password (default: $MARKLOGIC_PASS environment variable, else placeholder)"
    echo "  --external-security NAME   External Security profile name (default: $DEFAULT_EXTERNAL_SECURITY_NAME)"
    echo ""
    echo "Examples:"
    echo "  # Basic key extraction (analysis only)"
    echo "  $0 https://your-idp.example.com/realms/your-realm/protocol/openid-connect/certs"
    echo ""
    echo "  # Upload to MarkLogic with default settings"
    echo "  $0 https://your-idp.example.com/jwks --upload-to-marklogic"
    echo ""
    echo "  # Upload with custom MarkLogic configuration"
    echo "  $0 https://your-idp.example.com/jwks --upload-to-marklogic \\"
    echo "     --marklogic-host ml.company.com --marklogic-port 8002 \\"
    echo "     --external-security OAuth2-Production"
    echo ""
    echo "  # Use environment variables for sensitive data"
    echo "  $0 https://your-idp.example.com/jwks --upload-to-marklogic \\"
    echo "     --marklogic-user \"\$ML_USER\" --marklogic-pass \"\$ML_PASS\""
    exit 1
}

# Initialize variables with defaults
JWKS_URL=""
UPLOAD_TO_MARKLOGIC=false
MARKLOGIC_HOST="$DEFAULT_MARKLOGIC_HOST"
MARKLOGIC_PORT="$DEFAULT_MARKLOGIC_PORT"
MARKLOGIC_USER="$DEFAULT_MARKLOGIC_USER"
MARKLOGIC_PASS="${MARKLOGIC_PASS:-$DEFAULT_MARKLOGIC_PASS}"  # environment variable preferred over --marklogic-pass (argv is visible in ps)
EXTERNAL_SECURITY_NAME="$DEFAULT_EXTERNAL_SECURITY_NAME"
INSECURE_CURL=()

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --upload-to-marklogic)
            UPLOAD_TO_MARKLOGIC=true
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
            if [[ -z "$2" || "$2" == --* ]]; then
                echo "Error: --marklogic-pass requires a value"
                show_usage
            fi
            MARKLOGIC_PASS="$2"
            shift 2
            ;;
        --external-security)
            if [[ -z "$2" || "$2" == --* ]]; then
                echo "Error: --external-security requires a value"
                show_usage
            fi
            EXTERNAL_SECURITY_NAME="$2"
            shift 2
            ;;
        --insecure)
            INSECURE_CURL=(-k)
            echo "Warning: TLS verification disabled for the JWKS fetch" >&2
            shift
            ;;
        --help|-h)
            show_usage
            ;;
        --*)
            echo "Error: Unknown option $1"
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

# Validate JWKS URL format
if ! [[ "$JWKS_URL" =~ ^https?:// ]]; then
    echo "Error: JWKS URL must start with http:// or https://"
    show_usage
fi

# Array to store key data for MarkLogic upload
KEY_DATA=()

# Check if required tools are available
command -v curl >/dev/null 2>&1 || { echo "Error: curl is required but not installed." >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "Error: jq is required but not installed. Install with: brew install jq" >&2; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo "Warning: openssl not found. RSA keys will be output in base64url format instead of PEM." >&2; }
command -v python3 >/dev/null 2>&1 || { echo "Warning: python3 not found. RSA keys will be output in base64url format instead of PEM." >&2; }

# Function to get existing key IDs from MarkLogic
get_existing_key_ids() {
    echo "🔍 Checking existing keys in MarkLogic External Security profile '$EXTERNAL_SECURITY_NAME'..."

    # Build the URL for debugging
    MARKLOGIC_URL="http://$MARKLOGIC_HOST:$MARKLOGIC_PORT/manage/v2/external-security/$EXTERNAL_SECURITY_NAME/properties"
    echo "🔗 API URL: $MARKLOGIC_URL"

    # Query MarkLogic for existing external security configuration (properties endpoint for detailed config)
    EXISTING_CONFIG=$(curl -X GET --anyauth -u "$MARKLOGIC_USER:$MARKLOGIC_PASS" \
        -H "Accept: application/json" \
        -s \
        --connect-timeout 10 \
        --max-time 30 \
        "$MARKLOGIC_URL" 2>&1)

    # Check if query was successful
    if [ $? -ne 0 ]; then
        echo "⚠️  Warning: Could not retrieve existing MarkLogic configuration"
        echo "   Proceeding with all keys (they may be duplicates)"
        return 1
    fi

    # Check if response contains valid JSON
    echo "$EXISTING_CONFIG" | jq . >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo "⚠️  Warning: Invalid JSON response from MarkLogic"
        echo "   Response: $EXISTING_CONFIG"
        echo "   Proceeding with all keys (they may be duplicates)"
        return 1
    fi

    # Debug: Show the structure of the response to help with JSON path debugging
    echo "🔍 MarkLogic configuration structure (first level keys):"
    echo "$EXISTING_CONFIG" | jq -r 'keys[]' 2>/dev/null | head -10 | sed 's/^/   - /'

    # Debug: Show oauth-server structure if it exists
    if echo "$EXISTING_CONFIG" | jq -e '.["oauth-server"]' >/dev/null 2>&1; then
        echo "🔍 Found oauth-server structure"
        if echo "$EXISTING_CONFIG" | jq -e '.["oauth-server"]["oauth-jwt-secrets"]' >/dev/null 2>&1; then
            echo "🔍 Found oauth-jwt-secrets structure"
            SECRET_COUNT=$(echo "$EXISTING_CONFIG" | jq '.["oauth-server"]["oauth-jwt-secrets"]["oauth-jwt-secret"] | length' 2>/dev/null || echo "0")
            echo "🔍 Found $SECRET_COUNT existing secrets"
        fi
    fi

    # Extract existing key IDs from the oauth-jwt-secrets.oauth-jwt-secret array
    # Based on the MarkLogic API properties response structure
    EXISTING_KEY_IDS=$(echo "$EXISTING_CONFIG" | jq -r '.["oauth-server"]["oauth-jwt-secrets"]["oauth-jwt-secret"][]? | .["oauth-jwt-key-id"] // empty' 2>/dev/null)

    if [ -z "$EXISTING_KEY_IDS" ]; then
        echo "📭 No existing JWT secrets found in MarkLogic"
        return 0
    fi

    # Count existing keys
    EXISTING_COUNT=$(echo "$EXISTING_KEY_IDS" | wc -l | tr -d ' ')
    echo "📊 Found $EXISTING_COUNT existing key(s) in MarkLogic:"

    # Display existing key IDs
    while IFS= read -r key_id; do
        [ -n "$key_id" ] && echo "   - $key_id"
    done <<< "$EXISTING_KEY_IDS"

    return 0
}

# Function to check if a key ID already exists in MarkLogic
key_exists_in_marklogic() {
    local kid="$1"

    # If we couldn't get existing keys, assume it doesn't exist
    if [ -z "$EXISTING_KEY_IDS" ]; then
        return 1
    fi

    # Check if the key ID is in the list of existing keys
    echo "$EXISTING_KEY_IDS" | grep -Fxq "$kid"
    return $?
}

# Function to upload keys to MarkLogic
upload_keys_to_marklogic() {
    if [ ${#KEY_DATA[@]} -eq 0 ]; then
        echo ""
        echo "ℹ️  No new RSA keys to upload; MarkLogic already has every key the IdP publishes."
        return 0
    fi

    echo ""
    echo "🔄 Preparing to upload ${#KEY_DATA[@]} new key(s) to MarkLogic..."

    # Create JSON payload
    PAYLOAD_FILE=$(mktemp "${TMPDIR:-/tmp}/JWTSecretsPayload.XXXXXX") || { echo "Error: cannot create temporary payload file" >&2; return 1; }
    trap 'rm -f "$PAYLOAD_FILE"' EXIT

    # Start building JSON
    echo "{" > "$PAYLOAD_FILE"
    echo "  \"oauth-server\": {" >> "$PAYLOAD_FILE"
    echo "    \"oauth-jwt-secret\": [" >> "$PAYLOAD_FILE"

    # Add each key to the JSON
    for i in "${!KEY_DATA[@]}"; do
        echo "      ${KEY_DATA[$i]}" >> "$PAYLOAD_FILE"
        # Add comma if not the last element
        if [ $i -lt $((${#KEY_DATA[@]} - 1)) ]; then
            echo "," >> "$PAYLOAD_FILE"
        else
            echo "" >> "$PAYLOAD_FILE"
        fi
    done

    # Close JSON structure
    echo "    ]" >> "$PAYLOAD_FILE"
    echo "  }" >> "$PAYLOAD_FILE"
    echo "}" >> "$PAYLOAD_FILE"

    echo "📝 Created payload file: $PAYLOAD_FILE"
    echo "📄 Payload content:"
    cat "$PAYLOAD_FILE" | jq . 2>/dev/null || cat "$PAYLOAD_FILE"
    echo ""

    # Upload to MarkLogic using the hardcoded curl command
    echo "🚀 Uploading new keys to MarkLogic External Security profile..."
    echo "   External Security Profile: $EXTERNAL_SECURITY_NAME"
    echo "   MarkLogic Server: http://$MARKLOGIC_HOST:$MARKLOGIC_PORT"
    echo "   New keys to add: ${#KEY_DATA[@]}"
    echo ""

    CURL_RESPONSE=$(curl -X POST --anyauth -u "$MARKLOGIC_USER:$MARKLOGIC_PASS" \
        -H "Content-Type:application/json" \
        -d @"$PAYLOAD_FILE" \
        -w "\nHTTP_CODE:%{http_code}" \
        -s \
        "http://$MARKLOGIC_HOST:$MARKLOGIC_PORT/manage/v2/external-security/$EXTERNAL_SECURITY_NAME/jwt-secrets" 2>&1)

    # Parse response
    HTTP_CODE=$(echo "$CURL_RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)
    RESPONSE_BODY=$(echo "$CURL_RESPONSE" | sed '/HTTP_CODE:/d')

    if [ "$HTTP_CODE" = "204" ] || [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ]; then
        echo "✅ Successfully uploaded JWT secrets to MarkLogic!"
        echo "   HTTP Status: $HTTP_CODE"
        echo "   Keys added: ${#KEY_DATA[@]}"
    else
        echo "❌ Failed to upload JWT secrets to MarkLogic"
        echo "   HTTP Status: $HTTP_CODE"
        echo "   Response: $RESPONSE_BODY"
        echo ""
        echo "💡 Troubleshooting tips:"
        echo "   - Verify MarkLogic is running on $MARKLOGIC_HOST:$MARKLOGIC_PORT"
        echo "   - Check external security profile '$EXTERNAL_SECURITY_NAME' exists"
        echo "   - Verify admin credentials are correct"
        echo "   - Ensure the external security profile is configured for JWT tokens"
    fi
}

# Fetch JWKS data. TLS is verified unless --insecure is given (keys fetched here are uploaded as trusted signing keys).
JWKS_DATA=$(curl -s "${INSECURE_CURL[@]}" -L --max-redirs 3 --connect-timeout 10 --max-time 30 "$JWKS_URL")

# Check if curl was successful
if [ $? -ne 0 ]; then
    echo "Error: Failed to fetch JWKS data from $JWKS_URL"
    exit 1
fi

# Check if response is valid JSON
echo "$JWKS_DATA" | jq . >/dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "Error: Invalid JSON response from JWKS endpoint"
    exit 1
fi

# Check if response has keys array
KEY_COUNT=$(echo "$JWKS_DATA" | jq '.keys | length' 2>/dev/null || echo "0")

if [ "$KEY_COUNT" -eq 0 ]; then
    echo "No keys found in JWKS response"
    exit 0
fi

# Initialize existing key IDs variable and get existing keys if upload is requested
EXISTING_KEY_IDS=""
if [ "$UPLOAD_TO_MARKLOGIC" = true ]; then
    get_existing_key_ids
fi

# Extract and display each key's information (simple format)
for i in $(seq 0 $((KEY_COUNT - 1))); do
    # Extract key ID (kid)
    KID=$(echo "$JWKS_DATA" | jq -r ".keys[$i].kid // \"(no kid)\"")
    echo "$KID"

    # Extract key data based on key type
    KTY=$(echo "$JWKS_DATA" | jq -r ".keys[$i].kty // \"(no kty)\"")

    if [ "$KTY" = "RSA" ]; then
        # RSA keys - convert to PEM format
        MODULUS=$(echo "$JWKS_DATA" | jq -r ".keys[$i].n // \"(no modulus)\"")
        EXPONENT=$(echo "$JWKS_DATA" | jq -r ".keys[$i].e // \"(no exponent)\"")

        # Create RSA public key in PEM format using python3 and openssl
        PEM_KEY_CONTENT=""
        if command -v openssl >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1 && [ "$MODULUS" != "(no modulus)" ] && [ "$EXPONENT" != "(no exponent)" ]; then
            # Create temporary file for RSA key generation
            TEMP_FILE=$(mktemp)

            # Use Python to create proper RSA public key in PEM format
            python3 -c "
import base64
import sys

def base64url_decode(data):
    # Add padding if needed
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    return base64.urlsafe_b64decode(data)

def der_encode_length(length):
    if length < 0x80:
        return bytes([length])
    else:
        length_bytes = []
        while length > 0:
            length_bytes.insert(0, length & 0xff)
            length >>= 8
        return bytes([0x80 | len(length_bytes)]) + bytes(length_bytes)

def der_encode_integer(value):
    # Remove leading zeros except when needed to prevent negative interpretation
    while len(value) > 1 and value[0] == 0 and (value[1] & 0x80) == 0:
        value = value[1:]
    # Add leading zero if first bit is set (to prevent negative interpretation)
    if value[0] & 0x80:
        value = b'\x00' + value
    return b'\x02' + der_encode_length(len(value)) + value

try:
    # Decode modulus and exponent from base64url
    n = base64url_decode('$MODULUS')
    e = base64url_decode('$EXPONENT')

    # Create DER encoded integers
    n_der = der_encode_integer(n)
    e_der = der_encode_integer(e)

    # Create SEQUENCE containing n and e
    seq_content = n_der + e_der
    rsa_seq = b'\x30' + der_encode_length(len(seq_content)) + seq_content

    # Create SubjectPublicKeyInfo structure
    # RSA OID: 1.2.840.113549.1.1.1 with NULL parameters
    rsa_oid = bytes.fromhex('300d06092a864886f70d0101010500')

    # BIT STRING containing the RSA sequence
    bit_string = b'\x03' + der_encode_length(len(rsa_seq) + 1) + b'\x00' + rsa_seq

    # Final SubjectPublicKeyInfo SEQUENCE
    spki_content = rsa_oid + bit_string
    spki = b'\x30' + der_encode_length(len(spki_content)) + spki_content

    # Write DER to temporary file
    with open('$TEMP_FILE', 'wb') as f:
        f.write(spki)

except Exception as e:
    print(f'Error creating RSA key: {e}', file=sys.stderr)
    sys.exit(1)
" 2>/dev/null

            # Convert DER to PEM using openssl
            if [ -f "$TEMP_FILE" ] && [ -s "$TEMP_FILE" ]; then
                PEM_OUTPUT=$(openssl rsa -pubin -inform DER -in "$TEMP_FILE" -outform PEM 2>/dev/null)
                if [ $? -eq 0 ] && [ -n "$PEM_OUTPUT" ]; then
                    echo "$PEM_OUTPUT"
                    # Store PEM content for MarkLogic upload (escape newlines for JSON)
                    PEM_KEY_CONTENT=$(echo "$PEM_OUTPUT" | awk '{printf "%s\\n", $0}' | sed 's/\\n$//')
                else
                    echo "Error: Could not convert to PEM format. Raw modulus:"
                    echo "$MODULUS"
                fi
            else
                echo "Error: Could not generate RSA key structure. Raw modulus:"
                echo "$MODULUS"
            fi

            # Clean up
            rm -f "$TEMP_FILE" 2>/dev/null
        else
            # Fallback to base64url modulus if dependencies not available
            echo "$MODULUS"
        fi

    elif [ "$KTY" = "EC" ]; then
        # Elliptic Curve keys - output x coordinate (main key data)
        X_COORD=$(echo "$JWKS_DATA" | jq -r ".keys[$i].x // \"(no x)\"")
        echo "$X_COORD"

    elif [ "$KTY" = "oct" ]; then
        # Symmetric keys - output key value
        KEY_VALUE=$(echo "$JWKS_DATA" | jq -r ".keys[$i].k // \"(no key value)\"")
        echo "$KEY_VALUE"

    else
        # Unknown key type - output raw JSON
        echo "$JWKS_DATA" | jq -c ".keys[$i]"
    fi

    # Store key data for MarkLogic upload if requested
    if [ "$UPLOAD_TO_MARKLOGIC" = true ]; then
        if [ "$KTY" = "RSA" ] && [ "$PEM_KEY_CONTENT" != "" ]; then
            # Check if this key already exists in MarkLogic
            if key_exists_in_marklogic "$KID"; then
                echo "⏭️  Key '$KID' already exists in MarkLogic - skipping"
            else
                echo "✅ Key '$KID' is new - will be added to MarkLogic"
                # Store kid and PEM key for later processing
                KEY_DATA+=("{\"oauth-jwt-key-id\": \"$KID\", \"oauth-jwt-secret-value\": \"$PEM_KEY_CONTENT\"}")
            fi
        fi
    fi

    # Add blank line between keys (except for last key)
    if [ $i -lt $((KEY_COUNT - 1)) ]; then
        echo ""
    fi
done

# Upload to MarkLogic if requested
if [ "$UPLOAD_TO_MARKLOGIC" = true ]; then
    upload_keys_to_marklogic
fi