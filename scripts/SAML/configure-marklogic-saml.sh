#!/bin/bash

# ================================================================
# MarkLogic SAML Authentication Configuration Script
# ================================================================
#
# This script helps configure SAML authentication for MarkLogic Server
# including external security setup, identity provider integration,
# app server configuration, and SAML assertion processing.
#
# Features:
# - Configure external SAML security in MarkLogic
# - Set up app servers for SAML authentication
# - Identity Provider (IdP) metadata processing
# - Service Provider (SP) metadata generation
# - Certificate management for SAML signing/encryption
# - SAML assertion validation and testing
# - Support for popular IdPs (Azure AD, Okta, ADFS, etc.)
# - Attribute mapping configuration
#
# Author: Martin Warnes
# Version: 1.0.2
# Date: November 2025
#
# Usage:
#   ./configure-marklogic-saml.sh [COMMAND] [OPTIONS]
#
# Commands:
#   create-external-security    Create SAML external security
#   delete-external-security    Delete SAML external security
#   configure-appserver        Configure app server for SAML
#   import-idp-metadata        Download and validate IdP metadata without retaining a copy
#   generate-sp-metadata       Generate Service Provider metadata to stdout
#   test-saml                  Test SAML authentication flow
#   validate-assertion         Validate SAML assertion
#   show-idp-info             Show IdP configuration details
#
# Examples:
#   # Create SAML external security with Keycloak (Warnesnet)
#   ./configure-marklogic-saml.sh create-external-security --name keycloak-saml \\
#       --idp-metadata-url "https://oauth.warnesnet.com:8443/realms/master/protocol/saml/descriptor"
#
#   # Create SAML external security with Azure AD
#   ./configure-marklogic-saml.sh create-external-security --name azure-saml \\
#       --idp-metadata-url "https://login.microsoftonline.com/tenant-id/federationmetadata/2007-06/federationmetadata.xml"
#
#   # Create with Okta
#   ./configure-marklogic-saml.sh create-external-security --name okta-saml \\
#       --idp-metadata-file okta-metadata.xml --sp-entity-id "oauth.warnesnet.com"
#
#   # Configure app server for SAML
#   ./configure-marklogic-saml.sh configure-appserver --appserver App-Services \\
#       --external-security keycloak-saml --saml-acs-url "https://oauth.warnesnet.com/saml/acs"
#
#   # Generate SP metadata for IdP configuration
#   ./configure-marklogic-saml.sh generate-sp-metadata --external-security keycloak-saml
#
# ================================================================

set -euo pipefail

# Source common utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../marklogic-utils.sh"

# ================================================================
# CONFIGURATION VARIABLES
# ================================================================

# Default values
COMMAND=""
EXTERNAL_SECURITY_NAME=""
IDP_METADATA_URL=""
IDP_METADATA_FILE=""
SP_ENTITY_ID=""
SP_ACS_URL=""
SP_CERTIFICATE_FILE=""
SP_PRIVATE_KEY_FILE=""
ATTRIBUTE_MAPPING=""
NAME_ID_FORMAT="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
SIGNING_CERTIFICATE_FILE=""
ENCRYPTION_CERTIFICATE_FILE=""
APPSERVER_NAME=""
ASSERTION_FILE=""
FORCE="false"
SAML_BINDING="HTTP-POST"
CLOCK_SKEW="300"
DRY_RUN="false"
VERBOSE="false"

# ================================================================
# SAML CONFIGURATION FUNCTIONS
# ================================================================

saml_api_path_segment() {
    local value="$1"
    [[ -n "$value" && "$value" != "." && "$value" != ".." && "$value" != *"/"* && "$value" != *"?"* && "$value" != *"#"* && "$value" != *$'\n'* && "$value" != *$'\r'* ]] || return 1
    jq -nr --arg value "$value" '$value|@uri'
}

saml_xml_escape() {
    jq -nr --arg value "$1" '$value|@html'
}

saml_validate_http_url() {
    local url="$1" authority
    case "$url" in http://*|https://*) ;; *) ml_log_error "URL must use HTTP or HTTPS"; return 1 ;; esac
    authority="${url#*://}"
    authority="${authority%%/*}"
    if [ -z "$authority" ] || [[ "$authority" == *"@"* || "$url" == *"?"* || "$url" == *"#"* || "$url" == *[[:space:]]* || "$url" == *$'\n'* || "$url" == *$'\r'* ]]; then
        ml_log_error "URL contains unsupported credentials, query, fragment, or whitespace"
        return 1
    fi
}

saml_check_external_security_exists() {
    local path
    path=$(saml_api_path_segment "$1") || return 2
    ml_check_external_security_exists "$path" "$2" "$3"
}

# Extract IdP entity ID, SSO destination, and signing certificate from an
# IdP metadata file and merge them into the given external-security JSON.
# Honors $SAML_BINDING (HTTP-POST or HTTP-Redirect) when selecting the SSO
# endpoint, falling back to whichever binding the metadata actually offers.
saml_apply_idp_metadata_to_json() {
    local json="$1"
    local metadata_file="$2"

    if ! command -v xmllint >/dev/null 2>&1; then
        ml_log_error "xmllint is required to process IdP metadata safely"
        return 1
    fi

    local idp_entity_id
    idp_entity_id=$(xmllint --nonet --xpath "string(//*[local-name()='EntityDescriptor']/@entityID)" "$metadata_file" 2>/dev/null)
    [ -n "$idp_entity_id" ] || { ml_log_error "IdP metadata has no entity ID"; return 1; }
    if [ -n "$idp_entity_id" ]; then
        json=$(echo "$json" | jq --arg v "$idp_entity_id" '."saml-server"."saml-entity-id" = $v')
    fi

    local binding_urn="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    if [ "${SAML_BINDING:-HTTP-POST}" = "HTTP-Redirect" ]; then
        binding_urn="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
    fi

    local sso_destination
    sso_destination=$(xmllint --nonet --xpath "string(//*[local-name()='SingleSignOnService'][@Binding='$binding_urn']/@Location)" "$metadata_file" 2>/dev/null)
    if [ -z "$sso_destination" ]; then
        # Fall back to whichever binding the metadata actually provides
        sso_destination=$(xmllint --nonet --xpath "string(//*[local-name()='SingleSignOnService']/@Location)" "$metadata_file" 2>/dev/null)
    fi
    [ -n "$sso_destination" ] || { ml_log_error "IdP metadata has no SingleSignOnService destination"; return 1; }
    case "$sso_destination" in http://*|https://*) ;; *) ml_log_error "IdP SSO destination is not an HTTP(S) URL"; return 1 ;; esac
    if [ -n "$sso_destination" ]; then
        json=$(echo "$json" | jq --arg v "$sso_destination" '."saml-server"."saml-destination" = $v')
    fi

    local idp_cert
    idp_cert=$(xmllint --nonet --xpath "string(//*[local-name()='X509Certificate'])" "$metadata_file" 2>/dev/null)
    [ -n "$idp_cert" ] || { ml_log_error "IdP metadata has no signing certificate"; return 1; }
    if [ -n "$idp_cert" ]; then
        local formatted_cert
        formatted_cert=$(printf '%s\n%s\n%s\n' "-----BEGIN CERTIFICATE-----" "$(echo "$idp_cert" | fold -w 64)" "-----END CERTIFICATE-----")
        json=$(echo "$json" | jq --arg v "$formatted_cert" '."saml-server"."saml-idp-certificate-authority" = $v')
    fi

    echo "$json"
}

# Build safely encoded SAML configuration without placing private-key contents in jq argv.
saml_create_external_security_json() {
    if [ "$DRY_RUN" = "true" ]; then
        ml_log_info "[DRY-RUN] Would build SAML configuration; metadata and key material remain unread"
        return 3
    fi
    local external_security_json metadata_file="" metadata_created=false
    local -a cert_args key_args mapping_args
    if [ -n "$SP_CERTIFICATE_FILE" ]; then
        [ -r "$SP_CERTIFICATE_FILE" ] || { ml_log_error "SP certificate file is not readable"; return 1; }
        cert_args=(--rawfile sp_cert "$SP_CERTIFICATE_FILE")
    else
        cert_args=(--arg sp_cert "")
    fi
    if [ -n "$SP_PRIVATE_KEY_FILE" ]; then
        [ -r "$SP_PRIVATE_KEY_FILE" ] || { ml_log_error "SP private-key file is not readable"; return 1; }
        key_args=(--rawfile sp_key "$SP_PRIVATE_KEY_FILE")
    else
        key_args=(--arg sp_key "")
    fi
    if [ -n "$ATTRIBUTE_MAPPING" ]; then
        printf '%s' "$ATTRIBUTE_MAPPING" | jq -e 'type == "object" and (.["saml-attribute-name"] | type == "array")' >/dev/null 2>&1 || { ml_log_error "Attribute mapping must be a JSON object with a saml-attribute-name array"; return 1; }
        mapping_args=(--argjson attribute_mapping "$ATTRIBUTE_MAPPING")
    else
        mapping_args=(--argjson attribute_mapping null)
    fi

    if ! external_security_json=$(jq -n --arg name "$EXTERNAL_SECURITY_NAME" --arg issuer "$SP_ENTITY_ID" \
        "${cert_args[@]}" "${key_args[@]}" "${mapping_args[@]}" \
        '{"external-security-name":$name,"description":"SAML external security configuration created by script","authentication":"saml","cache-timeout":"300","authorization":"saml","saml-server":({"saml-issuer":$issuer,"saml-authn-signature":"sha256"} + (if $sp_cert == "" then {} else {"saml-sp-certificate":$sp_cert} end) + (if $sp_key == "" then {} else {"saml-sp-private-key":$sp_key} end) + (if $attribute_mapping == null then {} else {"saml-attribute-names":$attribute_mapping} end))}'); then
        ml_log_error "Could not build SAML configuration JSON"
        return 1
    fi

    if [ -n "$IDP_METADATA_URL" ]; then
        saml_validate_http_url "$IDP_METADATA_URL" || return 1
        metadata_file=$(mktemp) || return 1
        metadata_created=true
        chmod 600 "$metadata_file" || { rm -f "$metadata_file"; return 1; }
        if ! curl -sS -f -L --max-redirs 3 --connect-timeout 10 --max-time 30 -o "$metadata_file" "$IDP_METADATA_URL" 2>/dev/null; then
            rm -f "$metadata_file"
            ml_log_error "Failed to download IdP metadata"
            return 1
        fi
        if ! saml_validate_idp_metadata "$metadata_file"; then
            rm -f "$metadata_file"
            return 1
        fi
        if ! external_security_json=$(saml_apply_idp_metadata_to_json "$external_security_json" "$metadata_file"); then
            rm -f "$metadata_file"
            return 1
        fi
    elif [ -n "$IDP_METADATA_FILE" ]; then
        saml_validate_idp_metadata "$IDP_METADATA_FILE" || return 1
        external_security_json=$(saml_apply_idp_metadata_to_json "$external_security_json" "$IDP_METADATA_FILE") || return 1
    fi

    [ "$metadata_created" != true ] || rm -f "$metadata_file"
    ml_log_verbose "SAML external-security JSON prepared; payload omitted"
    printf '%s\n' "$external_security_json"
}

saml_save_protected_snapshot() {
    local label="$1" json="$2" file
    printf '%s' "$json" | jq empty >/dev/null 2>&1 || { ml_log_error "Could not validate $label snapshot"; return 1; }
    file=$(mktemp) || return 1
    chmod 600 "$file" || { rm -f "$file"; return 1; }
    printf '%s\n' "$json" > "$file" || { rm -f "$file"; return 1; }
    ml_log_warning "Protected $label snapshot saved to $file; API redaction may require manual restoration"
}

saml_backup_resource() {
    local endpoint="$1" label="$2" response status body
    if ! response=$(ml_api_request GET "$endpoint" "$MARKLOGIC_USER" "$MARKLOGIC_PASS"); then
        ml_log_error "Could not read $label; refusing mutation"
        return 1
    fi
    status=$(ml_extract_status_code "$response")
    [ "$status" = "200" ] || { ml_log_error "Could not snapshot $label (HTTP $status); refusing mutation"; return 1; }
    body=$(ml_extract_response_body "$response")
    saml_save_protected_snapshot "$label" "$body"
}

# Create SAML external security
saml_create_external_security() {
    ml_log_step "Creating SAML external security: $EXTERNAL_SECURITY_NAME"

    # Validate required fields
    if [ -z "$EXTERNAL_SECURITY_NAME" ]; then
        ml_log_error "External security name is required"
        return 1
    fi

    # Set default values if not provided
    if [ -z "$SP_ENTITY_ID" ]; then
        SP_ENTITY_ID="MarkLogic-SP"
        ml_log_info "Using default SP Entity ID: $SP_ENTITY_ID"
    fi

    if [ -z "$IDP_METADATA_URL" ] && [ -z "$IDP_METADATA_FILE" ]; then
        ml_log_error "Identity Provider metadata URL or file is required"
        return 1
    fi

    # Check if external security already exists
    local existence_status
    if saml_check_external_security_exists "$EXTERNAL_SECURITY_NAME" "$MARKLOGIC_USER" "$MARKLOGIC_PASS"; then
        existence_status=0
    else
        existence_status=$?
    fi
    case $existence_status in
        0)  # Exists
            if [ "$FORCE" != "true" ]; then
                ml_log_error "External security '$EXTERNAL_SECURITY_NAME' already exists. Use --force to overwrite."
                return 1
            else
                ml_log_warning "Overwriting existing external security '$EXTERNAL_SECURITY_NAME'"
                SAML_EXISTS_FORCE=true
            fi
            ;;
        1)  # Does not exist - proceed with create
            ;;
        3)  # Unknown in dry-run
            ml_log_info "[DRY-RUN] Cannot check existence; would create/update external security '$EXTERNAL_SECURITY_NAME'"
            return 0
            ;;
        *)  # Error
            ml_log_error "Error checking external security existence"
            return 1
            ;;
    esac

    # Create external security JSON
    local external_security_json
    external_security_json=$(saml_create_external_security_json)

    # Existing profile + --force: PUT /properties. (A POST with changed values returns 400 MANAGE-CONFLICTINGCONFIG,
    # and an unchanged one is silently accepted, so POST cannot be used to update.)
    if [ "${SAML_EXISTS_FORCE:-false}" = "true" ]; then
        saml_update_external_security "$external_security_json"
        return $?
    fi

    # Apply external security to MarkLogic
    local response status_code
    if ml_api_call_with_dryrun response "POST" "/manage/v2/external-security" "$MARKLOGIC_USER" "$MARKLOGIC_PASS" "$external_security_json"; then
        status_code=$(ml_extract_status_code "$response")
    else
        case $? in
            3) ml_log_info "[DRY-RUN] Would create SAML external security '$EXTERNAL_SECURITY_NAME'"; return 0 ;;
            *) ml_log_error "Failed to create SAML external security"; return 1 ;;
        esac
    fi

    case "$status_code" in
        201)
            ml_log_success "SAML external security '$EXTERNAL_SECURITY_NAME' created successfully"
            saml_show_next_steps
            return 0
            ;;
        409)
            if [ "$FORCE" = "true" ]; then
                ml_log_info "Updating existing external security..."
                saml_update_external_security "$external_security_json"
                return $?
            else
                ml_log_error "External security already exists (HTTP $status_code)"
                return 1
            fi
            ;;
        400)
            ml_log_error "Bad request - check external-security parameters (HTTP $status_code; response suppressed)"
            return 1
            ;;
        *)
            ml_log_error "Failed to create external security (HTTP $status_code)"
            return 1
            ;;
    esac
}

# Delete external security configuration
saml_delete_external_security() {
    ml_log_step "Deleting SAML external security: $EXTERNAL_SECURITY_NAME"

    # Validate required fields
    if [ -z "$EXTERNAL_SECURITY_NAME" ]; then
        ml_log_error "External security name is required"
        return 1
    fi
    local name_path
    name_path=$(saml_api_path_segment "$EXTERNAL_SECURITY_NAME") || { ml_log_error "Invalid external-security name"; return 1; }

    # Dry run mode - skip existence check since API calls are disabled
    if [ "$DRY_RUN" = "true" ]; then
        ml_log_info "[DRY-RUN] Would delete the named SAML external-security resource; remote state is unknown"
        return 0
    fi

    # Check if external security exists
    local existence_status
    if saml_check_external_security_exists "$EXTERNAL_SECURITY_NAME" "$MARKLOGIC_USER" "$MARKLOGIC_PASS"; then
        existence_status=0
    else
        existence_status=$?
    fi
    case $existence_status in
        0)  # Exists - proceed with delete
            ;;
        1)  # Does not exist
            ml_log_error "External security '$EXTERNAL_SECURITY_NAME' does not exist"
            return 1
            ;;
        3)  # Unknown in dry-run
            ml_log_info "[DRY-RUN] Cannot verify existence; would attempt to delete '$EXTERNAL_SECURITY_NAME'"
            ;;
        *)  # Error
            ml_log_error "Error checking external security existence"
            return 1
            ;;
    esac

    if ! ml_confirm "Permanently delete SAML external security '$EXTERNAL_SECURITY_NAME'?" n; then
        ml_log_warning "SAML deletion cancelled"
        return 1
    fi
    saml_backup_resource "/manage/v2/external-security/$name_path/properties?format=json" "SAML external-security '$EXTERNAL_SECURITY_NAME'" || return 1

    # Delete only the confirmed, backed-up exact target.
    local response status_code
    if ml_api_call_with_dryrun response "DELETE" "/manage/v2/external-security/$name_path" "$MARKLOGIC_USER" "$MARKLOGIC_PASS"; then
        status_code=$(ml_extract_status_code "$response")
    else
        case $? in
            3) ml_log_info "[DRY-RUN] Would delete SAML external security '$EXTERNAL_SECURITY_NAME'"; return 0 ;;
            *) ml_log_error "Failed to delete SAML external security"; return 1 ;;
        esac
    fi

    case "$status_code" in
        204|200)
            ml_log_success "SAML external security '$EXTERNAL_SECURITY_NAME' deleted successfully"
            return 0
            ;;
        404)
            ml_log_error "External security '$EXTERNAL_SECURITY_NAME' not found (HTTP $status_code)"
            return 1
            ;;
        400|500)
            ml_log_error "MarkLogic refused (HTTP $status_code). The usual cause is SEC-EXTERNALSECURITYINUSE: an app server still uses it. Run: configure-appserver-security.sh --appserver <name> --remove-security, then retry"
            return 1
            ;;
        *)
            ml_log_error "Failed to delete external security (HTTP $status_code; response suppressed)"
            return 1
            ;;
    esac
}

# Update existing external security
saml_update_external_security() {
    local external_security_json="$1" name_path response status_code
    name_path=$(saml_api_path_segment "$EXTERNAL_SECURITY_NAME") || { ml_log_error "Invalid external-security name"; return 1; }
    if [ "$DRY_RUN" = "true" ]; then
        ml_log_info "[DRY-RUN] Would update the exact SAML external-security resource; remote state is unknown"
        return 0
    fi
    if ! ml_confirm "Replace SAML external security '$EXTERNAL_SECURITY_NAME'? A protected export will be saved first." n; then
        ml_log_warning "SAML update cancelled"
        return 1
    fi
    saml_backup_resource "/manage/v2/external-security/$name_path/properties?format=json" "SAML external-security '$EXTERNAL_SECURITY_NAME'" || return 1
    if ml_api_call_with_dryrun response "PUT" "/manage/v2/external-security/$name_path/properties" "$MARKLOGIC_USER" "$MARKLOGIC_PASS" "$external_security_json"; then
        status_code=$(ml_extract_status_code "$response")
    else
        case $? in
            3) ml_log_info "[DRY-RUN] Would update SAML external security '$EXTERNAL_SECURITY_NAME'"; return 0 ;;
            *) ml_log_error "Failed to update SAML external security"; return 1 ;;
        esac
    fi

    case "$status_code" in
        204|200)
            ml_log_success "SAML external security '$EXTERNAL_SECURITY_NAME' updated successfully"
            saml_show_next_steps
            return 0
            ;;
        *)
            ml_log_error "Failed to update external security (HTTP $status_code)"
            return 1
            ;;
    esac
}

# Configure app server for SAML authentication
saml_configure_appserver() {
    ml_log_step "Configuring app server '$APPSERVER_NAME' for SAML authentication"
    if [ "$DRY_RUN" = "true" ]; then
        ml_log_info "[DRY-RUN] Would bind external security '$EXTERNAL_SECURITY_NAME' to app server '$APPSERVER_NAME'; current remote state is unknown"
        return 0
    fi

    local existence_status
    if saml_check_external_security_exists "$EXTERNAL_SECURITY_NAME" "$MARKLOGIC_USER" "$MARKLOGIC_PASS"; then
        existence_status=0
    else
        existence_status=$?
    fi
    case $existence_status in
        0)  # Exists - proceed
            ;;
        1)  # Does not exist
            ml_log_error "External security '$EXTERNAL_SECURITY_NAME' does not exist"
            return 1
            ;;
        3)  # Unknown in dry-run
            ml_log_info "[DRY-RUN] Cannot verify external security; would configure app server assuming it exists"
            ;;
        *)  # Error
            ml_log_error "Error checking external security existence"
            return 1
            ;;
    esac

    # Get current app server configuration. group-id is a required query
    # parameter for this endpoint (REST-REQUIREDPARAM if omitted).
    local response status_code
    local group_id="${APPSERVER_GROUP:-Default}" appserver_path group_path
    appserver_path=$(saml_api_path_segment "$APPSERVER_NAME") || { ml_log_error "Invalid app-server name"; return 1; }
    group_path=$(saml_api_path_segment "$group_id") || { ml_log_error "Invalid app-server group"; return 1; }
    if ml_api_call_with_dryrun response "GET" "/manage/v2/servers/$appserver_path/properties?group-id=$group_path&format=json" "$MARKLOGIC_USER" "$MARKLOGIC_PASS"; then
        status_code=$(ml_extract_status_code "$response")
    else
        case $? in
            3) ml_log_info "[DRY-RUN] Would read app server '$APPSERVER_NAME' configuration"; return 0 ;;
            *) ml_log_error "Failed to read app server configuration"; return 1 ;;
        esac
    fi

    if [ "$status_code" != "200" ]; then
        ml_log_error "App server '$APPSERVER_NAME' not found in group '$group_id' (HTTP $status_code)"
        return 1
    fi
    local prior_properties
    prior_properties=$(ml_extract_response_body "$response")
    if ! ml_confirm "Apply SAML authentication to app server '$APPSERVER_NAME'?" n; then
        ml_log_warning "App-server update cancelled"
        return 1
    fi
    saml_save_protected_snapshot "app-server '$APPSERVER_NAME' properties" "$prior_properties" || return 1

    # Build configuration with jq to avoid interpolating names into JSON.
    local saml_config
    saml_api_path_segment "$EXTERNAL_SECURITY_NAME" >/dev/null || { ml_log_error "Invalid external-security name"; return 1; }
    saml_config=$(jq -n --arg name "$EXTERNAL_SECURITY_NAME" '{"authentication":"saml","external-security":[$name]}') || return 1

    # Update only the selected app-server resource.
    if ml_api_call_with_dryrun response "PUT" "/manage/v2/servers/$appserver_path/properties?group-id=$group_path" "$MARKLOGIC_USER" "$MARKLOGIC_PASS" "$saml_config"; then
        status_code=$(ml_extract_status_code "$response")
    else
        case $? in
            3) ml_log_info "[DRY-RUN] Would configure SAML on app server '$APPSERVER_NAME'"; return 0 ;;
            *) ml_log_error "Failed to configure SAML on app server"; return 1 ;;
        esac
    fi

    case "$status_code" in
        204)
            ml_log_success "SAML authentication configured for app server '$APPSERVER_NAME'"
            ml_log_info "External Security: $EXTERNAL_SECURITY_NAME"

            ml_log_warning "MarkLogic Server restart may be required for authentication changes to take effect"
            return 0
            ;;
        *)
            ml_log_error "Failed to configure SAML authentication (HTTP $status_code; response suppressed)"
            return 1
            ;;
    esac
}

# Show next steps after configuration
saml_show_next_steps() {
    echo
    ml_log_info "Next steps:"
    ml_log_info "1. Generate SP metadata: $0 generate-sp-metadata --external-security $EXTERNAL_SECURITY_NAME --sp-acs-url https://<public-app-server>/saml/acs"
    ml_log_info "2. Configure IdP with SP metadata"
    ml_log_info "3. Configure app server: $0 configure-appserver --appserver <NAME> --external-security $EXTERNAL_SECURITY_NAME"
    ml_log_info "4. Test SAML flow: $0 test-saml --external-security $EXTERNAL_SECURITY_NAME"
    ml_log_info "5. Verify attribute mappings work correctly"
}

# ================================================================
# METADATA MANAGEMENT FUNCTIONS
# ================================================================

# Validate IdP metadata XML
saml_validate_idp_metadata() {
    local metadata_file="$1"

    if [ ! -f "$metadata_file" ]; then
        ml_log_error "Metadata file not found: $metadata_file"
        return 1
    fi

    # XML parsing is required; disable network resolution for external entities.
    command -v xmllint >/dev/null 2>&1 || { ml_log_error "xmllint is required to validate IdP metadata"; return 1; }
    if xmllint --nonet --noout "$metadata_file" 2>/dev/null; then
        ml_log_success "IdP metadata XML is well-formed"
    else
        ml_log_error "IdP metadata XML is malformed"
        return 1
    fi

    # Check for required SAML metadata elements
    if grep -q "EntityDescriptor" "$metadata_file" && \
       grep -q "IDPSSODescriptor" "$metadata_file"; then
        ml_log_success "IdP metadata contains required SAML elements"
    else
        ml_log_error "IdP metadata missing required SAML elements"
        return 1
    fi

    return 0
}

# Validate IdP metadata from a URL without retaining a local copy.
saml_import_idp_metadata() {
    if [ "$DRY_RUN" = "true" ]; then
        ml_log_info "[DRY-RUN] Would download and validate IdP metadata; no request or temp file created"
        return 0
    fi
    [ -n "$IDP_METADATA_URL" ] || { ml_log_error "IdP metadata URL is required"; return 1; }
    saml_validate_http_url "$IDP_METADATA_URL" || return 1
    local temp_metadata
    temp_metadata=$(mktemp) || return 1
    chmod 600 "$temp_metadata" || { rm -f "$temp_metadata"; return 1; }
    if ! curl -sS -f -L --max-redirs 3 --connect-timeout 10 --max-time 30 -o "$temp_metadata" "$IDP_METADATA_URL" 2>/dev/null; then
        rm -f "$temp_metadata"
        ml_log_error "Failed to download IdP metadata"
        return 1
    fi
    if saml_validate_idp_metadata "$temp_metadata"; then
        rm -f "$temp_metadata"
        ml_log_success "IdP metadata is valid; no local copy was retained"
    else
        rm -f "$temp_metadata"
        return 1
    fi
}

# Generate SP metadata XML
saml_generate_sp_metadata() {
    ml_log_step "Generating Service Provider metadata"

    if [ -z "$EXTERNAL_SECURITY_NAME" ]; then
        ml_log_error "External security name is required"
        return 1
    fi
    local name_path
    name_path=$(saml_api_path_segment "$EXTERNAL_SECURITY_NAME") || { ml_log_error "Invalid external-security name"; return 1; }

    # Get external security configuration
    local existence_status
    if saml_check_external_security_exists "$EXTERNAL_SECURITY_NAME" "$MARKLOGIC_USER" "$MARKLOGIC_PASS"; then
        existence_status=0
    else
        existence_status=$?
    fi
    case $existence_status in
        0)  # Exists - proceed
            ;;
        1)  # Does not exist
            ml_log_error "External security '$EXTERNAL_SECURITY_NAME' does not exist"
            return 1
            ;;
        3)  # Unknown in dry-run
            ml_log_info "[DRY-RUN] Cannot verify external security for metadata generation"
            return 0
            ;;
        *)  # Error
            ml_log_error "Error checking external security existence"
            return 1
            ;;
    esac

    # Load the exact configuration through a path-encoded, read-only request.
    local response status_code
    if ml_api_call_with_dryrun response "GET" "/manage/v2/external-security/$name_path/properties?format=json" "$MARKLOGIC_USER" "$MARKLOGIC_PASS"; then
        status_code=$(ml_extract_status_code "$response")
    else
        case $? in
            3) ml_log_info "[DRY-RUN] Would read external security '$EXTERNAL_SECURITY_NAME' for metadata"; return 0 ;;
            *) ml_log_error "Failed to read external security configuration"; return 1 ;;
        esac
    fi

    if [ "$status_code" != "200" ]; then
        ml_log_error "Failed to retrieve external security configuration"
        return 1
    fi

    # Extract configuration values
    local response_body
    response_body=$(ml_extract_response_body "$response")

    if command -v jq >/dev/null 2>&1; then
        local entity_id acs_url name_id_format entity_id_xml acs_url_xml name_id_format_xml
        entity_id="$SP_ENTITY_ID"
        if [ -z "$entity_id" ]; then
            entity_id=$(echo "$response_body" | jq -r '."saml-server"."saml-issuer" // .["external-security-config"]."saml-server"."saml-issuer" // .["external-security-properties"]."saml-server"."saml-issuer" // .["saml-issuer"] // .["saml-sp-entity-id"] // empty')
        fi
        acs_url="$SP_ACS_URL"
        name_id_format="$NAME_ID_FORMAT"
        if [ -z "$entity_id" ] || [ -z "$acs_url" ]; then
            ml_log_error "SP entity ID and --sp-acs-url are required to generate metadata"
            return 1
        fi
        saml_validate_http_url "$acs_url" || return 1
        entity_id_xml=$(saml_xml_escape "$entity_id")
        acs_url_xml=$(saml_xml_escape "$acs_url")
        name_id_format_xml=$(saml_xml_escape "$name_id_format")
        local sp_cert sp_key authn_requests_signed="false"
        sp_cert=$(echo "$response_body" | jq -r '."saml-server"."saml-sp-certificate" // .["external-security-config"]."saml-server"."saml-sp-certificate" // .["external-security-properties"]."saml-server"."saml-sp-certificate" // empty')
        sp_key=$(echo "$response_body" | jq -r '."saml-server"."saml-sp-private-key" // .["external-security-config"]."saml-server"."saml-sp-private-key" // .["external-security-properties"]."saml-server"."saml-sp-private-key" // empty')
        if [ -n "$sp_cert" ] && [ -n "$sp_key" ]; then authn_requests_signed="true"; fi

        # Generate SP metadata XML
        local sp_metadata
        sp_metadata=$(cat << EOF
<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     entityID="$entity_id_xml">
    <md:SPSSODescriptor AuthnRequestsSigned="$authn_requests_signed"
                        WantAssertionsSigned="true"
                        protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">

        <md:NameIDFormat>$name_id_format_xml</md:NameIDFormat>

        <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                     Location="$acs_url_xml"
                                     index="1" />
    </md:SPSSODescriptor>
</md:EntityDescriptor>
EOF
        )

        # Add the public SP certificate when present; never emit private-key content.
        if [ -n "$sp_cert" ]; then
            # Extract certificate content (remove headers/footers)
            local cert_content
            cert_content=$(echo "$sp_cert" | sed '/-----BEGIN CERTIFICATE-----/d' | sed '/-----END CERTIFICATE-----/d' | tr -d '\n')

            # Insert certificate into metadata (before closing SPSSODescriptor tag)
            sp_metadata=$(echo "$sp_metadata" | sed "/<md:NameIDFormat>/i\\
        <md:KeyDescriptor use=\"signing\">\\
            <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\\
                <ds:X509Data>\\
                    <ds:X509Certificate>$cert_content</ds:X509Certificate>\\
                </ds:X509Data>\\
            </ds:KeyInfo>\\
        </md:KeyDescriptor>")
        fi

        # File writes are disabled; stdout can be redirected after review.
        printf '%s\n' "$sp_metadata"

        echo
        ml_log_info "Configure your Identity Provider with this SP metadata"
        ml_log_info "Entity ID: $entity_id"
        ml_log_info "ACS URL: $acs_url"
        ml_log_info "NameID Format: $name_id_format"

        return 0
    else
        ml_log_error "jq is required for metadata generation"
        return 1
    fi
}

# Show IdP configuration information
saml_show_idp_info() {
    ml_log_step "Showing IdP configuration information"

    if [ -z "$EXTERNAL_SECURITY_NAME" ]; then
        ml_log_error "External security name is required"
        return 1
    fi
    local name_path
    name_path=$(saml_api_path_segment "$EXTERNAL_SECURITY_NAME") || { ml_log_error "Invalid external-security name"; return 1; }

    # Get external security configuration
    local existence_status
    if saml_check_external_security_exists "$EXTERNAL_SECURITY_NAME" "$MARKLOGIC_USER" "$MARKLOGIC_PASS"; then
        existence_status=0
    else
        existence_status=$?
    fi
    case $existence_status in
        0)  # Exists - proceed
            ;;
        1)  # Does not exist
            ml_log_error "External security '$EXTERNAL_SECURITY_NAME' does not exist"
            return 1
            ;;
        3)  # Unknown in dry-run
            ml_log_info "[DRY-RUN] Cannot verify external security for IdP info display"
            return 0
            ;;
        *)  # Error
            ml_log_error "Error checking external security existence"
            return 1
            ;;
    esac

    local response status_code
    if ml_api_call_with_dryrun response "GET" "/manage/v2/external-security/$name_path/properties?format=json" "$MARKLOGIC_USER" "$MARKLOGIC_PASS"; then
        status_code=$(ml_extract_status_code "$response")
    else
        case $? in
            3) ml_log_info "[DRY-RUN] Would validate SAML configuration"; return 0 ;;
            *) ml_log_error "Failed to read SAML configuration for validation"; return 1 ;;
        esac
    fi

    if [ "$status_code" != "200" ]; then
        ml_log_error "Failed to retrieve external security configuration"
        return 1
    fi

    local response_body
    response_body=$(ml_extract_response_body "$response")

    echo "SAML Configuration Information:"
    echo "=============================="

    if command -v jq >/dev/null 2>&1; then
        local saml_server idp_entity idp_destination sp_issuer idp_cert sp_cert
        saml_server=$(echo "$response_body" | jq -c '."saml-server" // .["external-security-config"]."saml-server" // .["external-security-properties"]."saml-server" // {}')
        idp_entity=$(echo "$saml_server" | jq -r '."saml-entity-id" // empty')
        idp_destination=$(echo "$saml_server" | jq -r '."saml-destination" // empty')
        sp_issuer=$(echo "$saml_server" | jq -r '."saml-issuer" // empty')
        idp_cert=$(echo "$saml_server" | jq -r '."saml-idp-certificate-authority" // empty')
        sp_cert=$(echo "$saml_server" | jq -r '."saml-sp-certificate" // empty')
        [ -z "$idp_entity" ] || echo "IdP Entity ID: configured (value omitted)"
        [ -z "$idp_destination" ] || echo "IdP SSO destination: configured (value omitted)"
        [ -z "$sp_issuer" ] || echo "SP issuer: configured (value omitted)"
        echo "SP ACS URL: app-server-specific; provide --sp-acs-url when generating metadata"
        echo "NameID format: controlled by the IdP"
        [ -z "$idp_cert" ] || echo "IdP signing certificate: configured"
        [ -z "$sp_cert" ] || echo "SP signing certificate: configured"
    else
        ml_log_error "jq is required to display the supported SAML configuration summary"
        return 1
    fi
}

# ================================================================
# SAML TESTING FUNCTIONS
# ================================================================

# Test SAML authentication flow
saml_test_authentication() {
    ml_log_step "Testing SAML authentication flow"
    if [ "$DRY_RUN" = "true" ]; then
        ml_log_info "[DRY-RUN] Would inspect app-server bindings and test the SAML redirect; no request was sent"
        return 0
    fi

    if [ -z "$EXTERNAL_SECURITY_NAME" ]; then
        ml_log_error "External security name is required"
        return 1
    fi

    # Find app servers using this external security
    local app_servers
    app_servers=$(saml_find_appservers_with_external_security "$EXTERNAL_SECURITY_NAME")

    if [ -z "$app_servers" ]; then
        ml_log_warning "No app servers configured with external security '$EXTERNAL_SECURITY_NAME'"
        ml_log_info "Configure an app server first with: $0 configure-appserver"
        return 1
    fi

    local app_server
    app_server=$(echo "$app_servers" | head -1)

    # Get app server port. group-id is a required query parameter for this
    # endpoint; the app server's own body (not the raw curl response, which
    # has the HTTP status code appended and is not valid JSON) is what gets
    # parsed for the port.
    local response status_code app_server_port response_body
    local group_id="${APPSERVER_GROUP:-Default}" group_path appserver_path
    group_path=$(saml_api_path_segment "$group_id") || { ml_log_error "Invalid app-server group"; return 1; }
    appserver_path=$(saml_api_path_segment "$app_server") || { ml_log_error "Invalid app-server name"; return 1; }
    if ml_api_call_with_dryrun response "GET" "/manage/v2/servers/$appserver_path/properties?group-id=$group_path&format=json" "$MARKLOGIC_USER" "$MARKLOGIC_PASS"; then
        status_code=$(ml_extract_status_code "$response")
    else
        case $? in
            3) ml_log_info "[DRY-RUN] Would read app server port for metadata generation"; return 0 ;;
            *) ml_log_error "Failed to read app server details"; return 1 ;;
        esac
    fi

    if [ "$status_code" != "200" ]; then
        ml_log_error "Failed to get app server details"
        return 1
    fi

    response_body=$(ml_extract_response_body "$response")
    if command -v jq >/dev/null 2>&1; then
        app_server_port=$(echo "$response_body" | jq -r '.port // empty')
    else
        app_server_port=$(echo "$response_body" | grep -o '"port":[0-9]*' | cut -d':' -f2)
    fi

    if [ -z "$app_server_port" ]; then
        ml_log_error "Could not determine app server port"
        return 1
    fi

    # Use the same protocol as the Management API connection - SAML app
    # servers are commonly HTTPS-only, and a hardcoded http:// test URL
    # would be actively wrong in that case.
    local test_url="${ML_PROTOCOL:-http}://${ML_HOST}:${app_server_port}/"

    ml_log_info "Testing SAML flow with app server: $app_server"
    ml_log_info "App-server URL is configured (value omitted)"
    ml_log_info ""
    ml_log_info "Manual test steps:"
    ml_log_info "1. Open a browser and navigate to the configured app-server URL"
    ml_log_info "2. You should be redirected to your Identity Provider"
    ml_log_info "3. Log in with valid credentials"
    ml_log_info "4. You should be redirected back to MarkLogic"
    ml_log_info "5. Verify successful authentication"

    # Try automated test with curl (limited effectiveness for SAML)
    if command -v curl >/dev/null 2>&1; then
        echo
        ml_log_info "Testing initial redirect..."
        local response_code
        if response_code=$(curl -sS -I -o /dev/null -w "%{http_code}" --connect-timeout 10 --max-time 30 "$test_url" 2>/dev/null); then
            case "$response_code" in
                3??) ml_log_success "SAML redirect detected (HTTP $response_code)" ;;
                401|403) ml_log_success "Authentication required; SAML may be configured (HTTP $response_code)" ;;
                *) ml_log_warning "Unexpected app-server response (HTTP $response_code)" ;;
            esac
        else
            ml_log_error "Failed to connect to app server"
            return 1
        fi
    fi
}

# Find app servers using external security (simplified)
saml_find_appservers_with_external_security() {
    local security_name="$1"
    local group_id="${APPSERVER_GROUP:-Default}" group_path
    group_path=$(saml_api_path_segment "$group_id") || return 1

    ml_log_verbose "Looking for app servers in group '$group_id' using external security: $security_name"

    if ! command -v jq >/dev/null 2>&1; then
        ml_log_warning "jq is required to search app servers for external security bindings"
        return 0
    fi

    local servers_response
    if ml_api_call_with_dryrun servers_response "GET" "/manage/v2/servers?group-id=$group_path&format=json&view=default" "$MARKLOGIC_USER" "$MARKLOGIC_PASS"; then
        if [ "$(ml_extract_status_code "$servers_response")" != "200" ]; then
            ml_log_warning "Could not list app servers in group '$group_id'"
            return 0
        fi
    else
        case $? in
            3) ml_log_info "[DRY-RUN] Would search app servers using external security '$security_name'"; return 0 ;;
            *) ml_log_warning "Could not list app servers in group '$group_id'"; return 0 ;;
        esac
    fi

    local servers_json server_names
    servers_json=$(ml_extract_response_body "$servers_response")
    server_names=$(echo "$servers_json" | jq -r '."server-default-list"."list-items"."list-item"[]?.nameref // empty')

    local name
    while IFS= read -r name; do
        [ -n "$name" ] || continue
        local name_path props_response props_json
        name_path=$(saml_api_path_segment "$name") || continue
        if ml_api_call_with_dryrun props_response "GET" "/manage/v2/servers/$name_path/properties?group-id=$group_path&format=json" "$MARKLOGIC_USER" "$MARKLOGIC_PASS"; then
            if [ "$(ml_extract_status_code "$props_response")" != "200" ]; then
                continue
            fi
        else
            case $? in
                3) ml_log_info "[DRY-RUN] Would check app server '$name' for external security binding" ;;
                *) continue ;;
            esac
            continue
        fi
        props_json=$(ml_extract_response_body "$props_response")
        # external-security may be a bare string or an array depending on
        # how it was last written; jq's flatten-and-match handles both.
        if echo "$props_json" | jq -e --arg name "$security_name" \
            '([."external-security"] | flatten) | index($name) != null' >/dev/null 2>&1; then
            echo "$name"
        fi
    done <<< "$server_names"
}

# Validate SAML assertion
saml_validate_assertion() {
    ml_log_step "Validating SAML assertion"

    if [ -z "$ASSERTION_FILE" ] || [ ! -f "$ASSERTION_FILE" ]; then
        ml_log_error "SAML assertion file is required and must exist"
        return 1
    fi

    # Basic XML validation
    if command -v xmllint >/dev/null 2>&1; then
        if xmllint --nonet --noout "$ASSERTION_FILE" 2>/dev/null; then
            ml_log_success "SAML assertion XML is well-formed"
        else
            ml_log_error "SAML assertion XML is malformed"
            return 1
        fi
    else
        ml_log_warning "xmllint not found. Cannot validate XML format."
    fi

    # Check for required SAML assertion elements
    if grep -q "saml:Assertion" "$ASSERTION_FILE" || grep -q "Assertion" "$ASSERTION_FILE"; then
        ml_log_success "SAML assertion elements found"
    else
        ml_log_error "File does not appear to contain a SAML assertion"
        return 1
    fi

    # Show assertion details
    echo
    ml_log_info "SAML Assertion Analysis:"
    echo "========================"

    # Extract key information
    local subject issuer
    if command -v xmllint >/dev/null 2>&1; then
        subject=$(xmllint --nonet --xpath "//*[local-name()='Subject']/*[local-name()='NameID']/text()" "$ASSERTION_FILE" 2>/dev/null || true)
        issuer=$(xmllint --nonet --xpath "string(//*[local-name()='Issuer'][1])" "$ASSERTION_FILE" 2>/dev/null || true)

        [ -z "$subject" ] || echo "Subject (NameID): present (value omitted)"
        [ -z "$issuer" ] || echo "Issuer: present (value omitted)"

        # Check for attributes
        local attr_count
        attr_count=$(xmllint --nonet --xpath "count(//*[local-name()='AttributeStatement']/*[local-name()='Attribute'])" "$ASSERTION_FILE" 2>/dev/null || echo "0")
        echo "Attribute Count: $attr_count"

        if [ "$attr_count" -gt 0 ]; then
            ml_log_info "Assertion contains $attr_count attribute(s); names and values omitted"
        fi
    else
        # Fallback to grep-based analysis
        if grep -q "NameID" "$ASSERTION_FILE"; then
            echo "NameID found in assertion"
        fi
        if grep -q "Issuer" "$ASSERTION_FILE"; then
            echo "Issuer found in assertion"
        fi
        if grep -q "AttributeStatement" "$ASSERTION_FILE"; then
            echo "Attributes found in assertion"
        fi
    fi

    return 0
}

# ================================================================
# COMMAND LINE INTERFACE
# ================================================================

show_usage() {
    cat << EOF
Usage: $0 [COMMAND] [OPTIONS]

MarkLogic SAML Authentication Configuration Script

COMMANDS:
    create-external-security    Create SAML external security
    delete-external-security    Delete SAML external security (alias: --remove)
    configure-appserver        Configure app server for SAML
    import-idp-metadata        Download and validate IdP metadata (no copy retained)
    generate-sp-metadata       Generate Service Provider metadata to stdout
    test-saml                  Test SAML authentication flow
    validate-assertion         Validate SAML assertion
    show-idp-info             Show IdP configuration details

CREATE-EXTERNAL-SECURITY OPTIONS:
    --name NAME                   External security name (required)
    --sp-entity-id ID             SP Entity ID (default: MarkLogic-SP; used in SAML issuer)
    --sp-acs-url URL              Public ACS URL; required only for SP metadata generation
    --idp-metadata-url URL        Identity Provider metadata URL
    --idp-metadata-file FILE      Identity Provider metadata file
    --sp-certificate-file FILE    SP certificate file
    --sp-private-key-file FILE    SP private key file
    --name-id-format FORMAT       NameID format written into generated SP metadata only (default: email).
                                  MarkLogic itself always sends NameIDPolicy "unspecified" in AuthnRequests
    --saml-binding BINDING        Which IdP SSO endpoint to read from the IdP metadata: HTTP-POST or
                                  HTTP-Redirect (default: HTTP-POST). MarkLogic 12.1 sends AuthnRequests
                                  by redirect and receives the response by POST regardless
    --clock-skew SECONDS          Accepted but NOT applied: MarkLogic 12.1 has no clock-skew property
                                  for external security (keep IdP and MarkLogic clocks in sync)
    --attribute-mapping JSON      Attribute mapping configuration
    --force                       Request overwrite after protected snapshot and confirmation

CONFIGURE-APPSERVER OPTIONS:
    --appserver NAME              App server name (required)
    --external-security NAME      External security name (required)

GENERATE-SP-METADATA OPTIONS:
    --external-security NAME      External security name (required)
    --sp-entity-id ID             Override the SP entity ID from the configuration
    --sp-acs-url URL              Public app-server ACS URL (required)
    --output-file FILE            Rejected; script-managed file output is disabled

SHOW-IDP-INFO OPTIONS:
    --external-security NAME      External security name (required)

TEST-SAML OPTIONS:
    --external-security NAME      External security name (required)

VALIDATE-ASSERTION OPTIONS:
    --assertion-file FILE         SAML assertion file (required)

DELETE-EXTERNAL-SECURITY OPTIONS:
    --name NAME                   External security name to delete (required)
    --remove NAME                 Alias for delete-external-security command

$(ml_show_common_usage)

Rollback and recovery:
    Mutations save a protected snapshot before update/delete. MarkLogic may redact private-key fields,
    so no automatic rollback is claimed; restore manually only after reviewing the exact target.
    IdP-side changes and metadata publication must be reversed at the provider.

EXAMPLES:
    # Create SAML external security with Keycloak (Warnesnet)
    $0 create-external-security --name keycloak-saml \\
        --sp-entity-id "https://oauth.warnesnet.com" \\
        --idp-metadata-url "https://oauth.warnesnet.com:8443/realms/master/protocol/saml/descriptor"

    # Create SAML external security for Azure AD
    $0 create-external-security --name azure-saml \\
        --sp-entity-id "https://oauth.warnesnet.com" \\
        --idp-metadata-url "https://login.microsoftonline.com/tenant-id/federationmetadata/2007-06/federationmetadata.xml"

    # Create for Okta with local metadata file
    $0 create-external-security --name okta-saml \\
        --sp-entity-id "oauth.warnesnet.com" \\
        --idp-metadata-file "okta-metadata.xml" \\
        --sp-certificate-file "sp-cert.pem" \\
        --sp-private-key-file "sp-key.pem"

    # Configure app server for SAML
    $0 configure-appserver --appserver App-Services \\
        --external-security azure-saml

    # Generate SP metadata; ACS URL is specific to the public app-server deployment
    $0 generate-sp-metadata --external-security azure-saml \\
        --sp-acs-url "https://oauth.warnesnet.com:8000/saml/acs"

    # Test SAML authentication flow
    $0 test-saml --external-security azure-saml

    # Validate SAML assertion from file
    $0 validate-assertion --assertion-file assertion.xml

    # Show IdP configuration details
    $0 show-idp-info --external-security azure-saml

    # Delete external security configuration
    $0 delete-external-security --name azure-saml

    # Or use --remove shorthand
    $0 --remove azure-saml

EOF
}

# Parse command line arguments
parse_arguments() {
    if [ $# -eq 0 ]; then
        show_usage
        exit 1
    fi

    # Handle --help and --remove at the start
    case "$1" in
        --help|-h)
            show_usage
            exit 0
            ;;
        --remove)
            COMMAND="delete-external-security"
            if [ $# -lt 2 ]; then
                ml_log_error "--remove requires an external security name"
                exit 1
            fi
            EXTERNAL_SECURITY_NAME="$2"
            shift 2
            ;;
        -*)
            ml_log_error "Unknown option"
            show_usage
            exit 1
            ;;
        *)
            COMMAND="$1"
            shift
            ;;
    esac

    # Parse remaining arguments including common ones
    while [[ $# -gt 0 ]]; do
        case $1 in
            --name)
                EXTERNAL_SECURITY_NAME="$2"
                shift 2
                ;;
            --external-security)
                EXTERNAL_SECURITY_NAME="$2"
                shift 2
                ;;
            --sp-entity-id)
                SP_ENTITY_ID="$2"
                shift 2
                ;;
            --sp-acs-url)
                SP_ACS_URL="$2"
                shift 2
                ;;
            --idp-metadata-url)
                IDP_METADATA_URL="$2"
                shift 2
                ;;
            --idp-metadata-file)
                IDP_METADATA_FILE="$2"
                shift 2
                ;;
            --sp-certificate-file)
                SP_CERTIFICATE_FILE="$2"
                shift 2
                ;;
            --sp-private-key-file)
                SP_PRIVATE_KEY_FILE="$2"
                shift 2
                ;;
            --name-id-format)
                NAME_ID_FORMAT="$2"
                shift 2
                ;;
            --saml-binding)
                SAML_BINDING="$2"
                shift 2
                ;;
            --clock-skew)
                CLOCK_SKEW="$2"
                shift 2
                ;;
            --attribute-mapping)
                ATTRIBUTE_MAPPING="$2"
                shift 2
                ;;
            --appserver)
                APPSERVER_NAME="$2"
                shift 2
                ;;
            --output-file)
                ml_log_error "--output-file is rejected; generate metadata to stdout and redirect it after review"
                exit 1
                ;;
            --assertion-file)
                ASSERTION_FILE="$2"
                shift 2
                ;;
            --marklogic-pass)
                ml_log_error "--marklogic-pass VALUE is rejected; use MARKLOGIC_PASS or a hidden prompt"
                exit 1
                ;;
            --force)
                FORCE="true"
                shift
                ;;
            --remove)
                COMMAND="delete-external-security"
                EXTERNAL_SECURITY_NAME="$2"
                shift 2
                ;;
            --help)
                show_usage
                exit 0
                ;;
            *)
                # Try to parse common arguments
                ml_parse_common_args "$@"
                break
                ;;
        esac
    done

    # Set defaults if not already set (no default credentials)
    MARKLOGIC_HOST="${MARKLOGIC_HOST:-localhost}"
    MARKLOGIC_USER="${MARKLOGIC_USER:-}"
    MARKLOGIC_PORT="${MARKLOGIC_PORT:-8002}"
}

# Main execution function
main() {
    ml_show_header "MarkLogic SAML Authentication" "1.0.0" \
        "Configure SAML authentication for MarkLogic Server"

    # Validate static inputs before any live request or credential prompt.
    ml_check_dependencies || exit 1
    case "$MARKLOGIC_HOST" in http://*|https://*) ;; *) MARKLOGIC_HOST="http://$MARKLOGIC_HOST" ;; esac
    saml_validate_http_url "$MARKLOGIC_HOST" || exit 1
    local ml_authority="${MARKLOGIC_HOST#*://}"
    case "$ml_authority" in */) MARKLOGIC_HOST="${MARKLOGIC_HOST%/}" ;; */*) ml_log_error "MarkLogic host must not include a path"; exit 1 ;; esac
    ml_parse_host_url "$MARKLOGIC_HOST"
    [[ -n "$ML_HOST" && "$ML_HOST" =~ ^[A-Za-z0-9.-]+$ ]] || { ml_log_error "Invalid MarkLogic host"; exit 1; }
    [[ "$ML_PORT" =~ ^[0-9]{1,5}$ ]] && [ "$ML_PORT" -ge 1 ] && [ "$ML_PORT" -le 65535 ] || { ml_log_error "Invalid MarkLogic port"; exit 1; }
    if [ -n "$EXTERNAL_SECURITY_NAME" ]; then
        saml_api_path_segment "$EXTERNAL_SECURITY_NAME" >/dev/null || { ml_log_error "Invalid external-security name"; exit 1; }
    fi
    if [ -n "$APPSERVER_NAME" ]; then
        saml_api_path_segment "$APPSERVER_NAME" >/dev/null || { ml_log_error "Invalid app-server name"; exit 1; }
    fi
    if [ -n "$IDP_METADATA_URL" ]; then
        saml_validate_http_url "$IDP_METADATA_URL" || exit 1
    fi
    if [ -n "$SP_CERTIFICATE_FILE" ] && [ ! -r "$SP_CERTIFICATE_FILE" ]; then
        ml_log_error "SP certificate file is not readable"
        exit 1
    fi
    if [ -n "$SP_PRIVATE_KEY_FILE" ] && [ ! -r "$SP_PRIVATE_KEY_FILE" ]; then
        ml_log_error "SP private-key file is not readable"
        exit 1
    fi
    if [ -n "$SP_ACS_URL" ]; then saml_validate_http_url "$SP_ACS_URL" || exit 1; fi
    case "$SAML_BINDING" in HTTP-POST|HTTP-Redirect) ;; *) ml_log_error "SAML binding must be HTTP-POST or HTTP-Redirect"; exit 1 ;; esac
    if [ "$DRY_RUN" != "true" ] && [ -n "$IDP_METADATA_FILE" ]; then
        saml_validate_idp_metadata "$IDP_METADATA_FILE" || exit 1
    fi
    case "$COMMAND" in
        create-external-security) [ -n "$EXTERNAL_SECURITY_NAME" ] && { [ -n "$IDP_METADATA_URL" ] || [ -n "$IDP_METADATA_FILE" ]; } || { ml_log_error "Creation requires --name and IdP metadata URL/file"; exit 1; } ;;
        delete-external-security|show-idp-info|test-saml) [ -n "$EXTERNAL_SECURITY_NAME" ] || { ml_log_error "--external-security or --name is required"; exit 1; } ;;
        generate-sp-metadata) [ -n "$EXTERNAL_SECURITY_NAME" ] && [ -n "$SP_ACS_URL" ] || { ml_log_error "--external-security and --sp-acs-url are required"; exit 1; } ;;
        configure-appserver) [ -n "$EXTERNAL_SECURITY_NAME" ] && [ -n "$APPSERVER_NAME" ] || { ml_log_error "--external-security and --appserver are required"; exit 1; } ;;
        import-idp-metadata) [ -n "$IDP_METADATA_URL" ] || { ml_log_error "--idp-metadata-url is required"; exit 1; } ;;
        validate-assertion) [ -n "$ASSERTION_FILE" ] && [ -f "$ASSERTION_FILE" ] || { ml_log_error "--assertion-file must name an existing file"; exit 1; } ;;
        *) ml_log_error "Unknown command: $COMMAND"; show_usage; exit 1 ;;
    esac

    # Read-only local commands do not need MarkLogic credentials or connectivity.
    case "$COMMAND" in
        validate-assertion|import-idp-metadata) ;;
        *)
            if [ "$DRY_RUN" != "true" ]; then
                if [ -z "$MARKLOGIC_USER" ]; then
                    ml_log_error "MarkLogic user is required (--marklogic-user or MARKLOGIC_USER)"
                    exit 1
                fi
                MARKLOGIC_PASS=$(ml_resolve_password) || exit 1
                ml_test_connectivity || exit 1
                echo
            fi
            ;;
    esac

    # Execute command while retaining its status for the final report under set -e.
    local exit_code=0
    case "$COMMAND" in
        create-external-security) saml_create_external_security || exit_code=$? ;;
        delete-external-security) saml_delete_external_security || exit_code=$? ;;
        configure-appserver) saml_configure_appserver || exit_code=$? ;;
        import-idp-metadata) saml_import_idp_metadata || exit_code=$? ;;
        generate-sp-metadata) saml_generate_sp_metadata || exit_code=$? ;;
        test-saml) saml_test_authentication || exit_code=$? ;;
        validate-assertion) saml_validate_assertion || exit_code=$? ;;
        show-idp-info) saml_show_idp_info || exit_code=$? ;;
        *) ml_log_error "Unknown command: $COMMAND"; show_usage; exit 1 ;;
    esac

    if [ $exit_code -eq 0 ]; then
        if [ "$DRY_RUN" = "true" ]; then
            ml_log_warning "Dry run complete; no requests, mutations, metadata downloads, or output files were created"
        else
            echo
            case "$COMMAND" in
            create-external-security)
                ml_show_footer "1. Generate SP metadata: $0 generate-sp-metadata --external-security $EXTERNAL_SECURITY_NAME
2. Configure your IdP with the SP metadata
3. Configure app server: $0 configure-appserver --appserver <NAME> --external-security $EXTERNAL_SECURITY_NAME
4. Test SAML flow: $0 test-saml --external-security $EXTERNAL_SECURITY_NAME"
                ;;
            configure-appserver)
                ml_show_footer "1. Restart MarkLogic Server if needed
2. Test SAML flow: $0 test-saml --external-security $EXTERNAL_SECURITY_NAME
3. Verify with browser-based authentication"
                ;;
            generate-sp-metadata)
                ml_show_footer "Configure your Identity Provider with the generated SP metadata
Ensure Entity ID and ACS URL match your MarkLogic configuration"
                ;;
            delete-external-security)
                ml_show_footer "External security configuration has been removed.
Note: App servers that were using this configuration may need to be reconfigured."
                ;;
            *)
                ml_show_footer ""
                ;;
            esac
        fi
    fi

    exit $exit_code
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    parse_arguments "$@"
    main
fi