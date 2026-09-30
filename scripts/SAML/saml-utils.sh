#!/bin/bash

# ================================================================
# SAML Utilities for MarkLogic Authentication
# ================================================================
#
# Common utility functions for SAML authentication management
# in MarkLogic environments. These functions provide SAML
# metadata processing, assertion validation, and configuration
# testing utilities.
#
# Author: Martin Warnes
# Version: 1.0.1
# Date: November 2025
#
# ================================================================

# Source common utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../marklogic-utils.sh"

saml_validate_url_for_curl() {
    local url="$1" authority
    case "$url" in http://*|https://*) ;; *) ml_log_error "URL must use HTTP or HTTPS"; return 1 ;; esac
    authority="${url#*://}"
    authority="${authority%%/*}"
    if [ -z "$authority" ] || [[ "$authority" == *"@"* || "$url" == *"?"* || "$url" == *"#"* || "$url" == *$'\n'* || "$url" == *$'\r'* || "$url" == *[[:space:]]* ]]; then
        ml_log_error "URL must not contain userinfo, query values, fragments, or whitespace"
        return 1
    fi
    return 0
}

# ================================================================
# SAML METADATA PROCESSING FUNCTIONS
# ================================================================

# Extract entity ID from SAML metadata
saml_extract_entity_id() {
    local metadata_file="$1"
    
    if [ ! -f "$metadata_file" ]; then
        ml_log_error "Metadata file not found: $metadata_file"
        return 1
    fi
    
    if command -v xmllint >/dev/null 2>&1; then
        local entity_id
        entity_id=$(xmllint --xpath "string(//*[local-name()='EntityDescriptor']/@entityID)" "$metadata_file" 2>/dev/null)
        if [ -n "$entity_id" ]; then
            echo "$entity_id"
            return 0
        fi
    fi
    
    # Fallback to grep-based extraction
    local entity_id
    entity_id=$(grep -o 'entityID="[^"]*"' "$metadata_file" | head -1 | cut -d'"' -f2)
    if [ -n "$entity_id" ]; then
        echo "$entity_id"
        return 0
    fi
    
    ml_log_error "Could not extract entity ID from metadata"
    return 1
}

# Extract SSO URLs from IdP metadata
saml_extract_sso_urls() {
    local metadata_file="$1"
    
    if [ ! -f "$metadata_file" ]; then
        ml_log_error "Metadata file not found: $metadata_file"
        return 1
    fi
    
    ml_log_info "SSO URLs from IdP metadata:"
    
    if command -v xmllint >/dev/null 2>&1; then
        # Extract HTTP-POST binding
        local post_url
        post_url=$(xmllint --xpath "string(//*[local-name()='SingleSignOnService'][@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST']/@Location)" "$metadata_file" 2>/dev/null)
        if [ -n "$post_url" ]; then
            post_url="${post_url%%\?*}"
            echo "  HTTP-POST: $post_url"
        fi
        
        # Extract HTTP-Redirect binding
        local redirect_url
        redirect_url=$(xmllint --xpath "string(//*[local-name()='SingleSignOnService'][@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect']/@Location)" "$metadata_file" 2>/dev/null)
        if [ -n "$redirect_url" ]; then
            redirect_url="${redirect_url%%\?*}"
            echo "  HTTP-Redirect: $redirect_url"
        fi
    else
        # Fallback to grep-based extraction
        ml_log_warning "xmllint not available. Using grep-based extraction."
        grep -o 'Location="[^"]*"' "$metadata_file" | grep -v "metadata" | sed 's/[?#].*$//' | head -5
    fi
}

# Extract certificates from SAML metadata
saml_extract_certificates() {
    local metadata_file="$1"
    local output_dir="${2:-.}"
    
    if [ ! -f "$metadata_file" ]; then
        ml_log_error "Metadata file not found: $metadata_file"
        return 1
    fi
    
    if [ "${DRY_RUN:-false}" = "true" ]; then
        ml_log_info "[DRY-RUN] Certificate extraction skipped; no files were written"
        return 0
    fi
    ml_log_step "Extracting certificates from SAML metadata"
    
    if command -v xmllint >/dev/null 2>&1; then
        # Extract signing certificates
        local cert_count
        cert_count=$(xmllint --xpath "count(//*[local-name()='KeyDescriptor'][@use='signing']//*[local-name()='X509Certificate'])" "$metadata_file" 2>/dev/null)
        
        if [ "$cert_count" -gt 0 ]; then
            ml_log_info "Found $cert_count signing certificate(s)"
            
            for i in $(seq 1 "$cert_count"); do
                local cert_content
                cert_content=$(xmllint --xpath "string(//*[local-name()='KeyDescriptor'][@use='signing'][position()=$i]//*[local-name()='X509Certificate'])" "$metadata_file" 2>/dev/null)
                
                if [ -n "$cert_content" ]; then
                    local cert_file="$output_dir/signing-cert-$i.pem"
                    [ ! -e "$cert_file" ] || { ml_log_error "Refusing to overwrite an existing certificate file"; return 1; }
                    (
                        set -eC
                        umask 077
                        printf '%s\n' '-----BEGIN CERTIFICATE-----' > "$cert_file"
                        printf '%s\n' "$cert_content" | fold -w 64 >> "$cert_file"
                        printf '%s\n' '-----END CERTIFICATE-----' >> "$cert_file"
                    ) || { ml_log_error "Could not create protected certificate file"; return 1; }
                    ml_log_success "Signing certificate $i saved to: $cert_file"
                fi
            done
        fi
        
        # Extract encryption certificates
        cert_count=$(xmllint --xpath "count(//*[local-name()='KeyDescriptor'][@use='encryption']//*[local-name()='X509Certificate'])" "$metadata_file" 2>/dev/null)
        
        if [ "$cert_count" -gt 0 ]; then
            ml_log_info "Found $cert_count encryption certificate(s)"
            
            for i in $(seq 1 "$cert_count"); do
                local cert_content
                cert_content=$(xmllint --xpath "string(//*[local-name()='KeyDescriptor'][@use='encryption'][position()=$i]//*[local-name()='X509Certificate'])" "$metadata_file" 2>/dev/null)
                
                if [ -n "$cert_content" ]; then
                    local cert_file="$output_dir/encryption-cert-$i.pem"
                    [ ! -e "$cert_file" ] || { ml_log_error "Refusing to overwrite an existing certificate file"; return 1; }
                    (
                        set -eC
                        umask 077
                        printf '%s\n' '-----BEGIN CERTIFICATE-----' > "$cert_file"
                        printf '%s\n' "$cert_content" | fold -w 64 >> "$cert_file"
                        printf '%s\n' '-----END CERTIFICATE-----' >> "$cert_file"
                    ) || { ml_log_error "Could not create protected certificate file"; return 1; }
                    ml_log_success "Encryption certificate $i saved to: $cert_file"
                fi
            done
        fi
        
        # Extract general certificates (no specific use)
        cert_count=$(xmllint --xpath "count(//*[local-name()='KeyDescriptor'][not(@use)]//*[local-name()='X509Certificate'])" "$metadata_file" 2>/dev/null)
        
        if [ "$cert_count" -gt 0 ]; then
            ml_log_info "Found $cert_count general certificate(s)"
            
            for i in $(seq 1 "$cert_count"); do
                local cert_content
                cert_content=$(xmllint --xpath "string(//*[local-name()='KeyDescriptor'][not(@use)][position()=$i]//*[local-name()='X509Certificate'])" "$metadata_file" 2>/dev/null)
                
                if [ -n "$cert_content" ]; then
                    local cert_file="$output_dir/general-cert-$i.pem"
                    [ ! -e "$cert_file" ] || { ml_log_error "Refusing to overwrite an existing certificate file"; return 1; }
                    (
                        set -eC
                        umask 077
                        printf '%s\n' '-----BEGIN CERTIFICATE-----' > "$cert_file"
                        printf '%s\n' "$cert_content" | fold -w 64 >> "$cert_file"
                        printf '%s\n' '-----END CERTIFICATE-----' >> "$cert_file"
                    ) || { ml_log_error "Could not create protected certificate file"; return 1; }
                    ml_log_success "General certificate $i saved to: $cert_file"
                fi
            done
        fi
    else
        ml_log_error "xmllint is required for certificate extraction"
        return 1
    fi
}

# Validate SAML metadata structure
saml_validate_metadata() {
    local metadata_file="$1"
    local metadata_type="${2:-idp}" # idp or sp
    
    if [ ! -f "$metadata_file" ]; then
        ml_log_error "Metadata file not found: $metadata_file"
        return 1
    fi
    
    ml_log_step "Validating SAML metadata structure"
    
    local validation_passed=true
    
    # Check XML well-formedness
    if command -v xmllint >/dev/null 2>&1; then
        if xmllint --noout "$metadata_file" 2>/dev/null; then
            ml_log_success "XML is well-formed"
        else
            ml_log_error "XML is malformed"
            validation_passed=false
        fi
    else
        ml_log_warning "xmllint not available. Cannot validate XML structure."
    fi
    
    # Check for required elements
    if grep -q "EntityDescriptor" "$metadata_file"; then
        ml_log_success "EntityDescriptor found"
    else
        ml_log_error "EntityDescriptor not found"
        validation_passed=false
    fi
    
    # Check for IdP or SP specific elements
    if [ "$metadata_type" = "idp" ]; then
        if grep -q "IDPSSODescriptor" "$metadata_file"; then
            ml_log_success "IDPSSODescriptor found"
        else
            ml_log_error "IDPSSODescriptor not found"
            validation_passed=false
        fi
        
        if grep -q "SingleSignOnService" "$metadata_file"; then
            ml_log_success "SingleSignOnService found"
        else
            ml_log_warning "SingleSignOnService not found"
        fi
    elif [ "$metadata_type" = "sp" ]; then
        if grep -q "SPSSODescriptor" "$metadata_file"; then
            ml_log_success "SPSSODescriptor found"
        else
            ml_log_error "SPSSODescriptor not found"
            validation_passed=false
        fi
        
        if grep -q "AssertionConsumerService" "$metadata_file"; then
            ml_log_success "AssertionConsumerService found"
        else
            ml_log_warning "AssertionConsumerService not found"
        fi
    fi
    
    # Check for certificates
    if grep -q "X509Certificate" "$metadata_file"; then
        ml_log_success "Certificates found in metadata"
    else
        ml_log_info "No certificates found in metadata"
    fi
    
    if [ "$validation_passed" = "true" ]; then
        ml_log_success "SAML metadata validation passed"
        return 0
    else
        ml_log_error "SAML metadata validation failed"
        return 1
    fi
}

# ================================================================
# SAML ASSERTION PROCESSING FUNCTIONS
# ================================================================

# Extract NameID from SAML assertion
saml_extract_nameid() {
    local assertion_file="$1"
    
    if [ ! -f "$assertion_file" ]; then
        ml_log_error "Assertion file not found: $assertion_file"
        return 1
    fi
    
    if command -v xmllint >/dev/null 2>&1; then
        local nameid
        nameid=$(xmllint --xpath "string(//*[local-name()='NameID'])" "$assertion_file" 2>/dev/null)
        if [ -n "$nameid" ]; then
            echo "$nameid"
            return 0
        fi
    fi
    
    # Fallback to grep-based extraction
    local nameid
    nameid=$(grep -o '<saml.*:NameID[^>]*>[^<]*' "$assertion_file" | sed 's/.*>//')
    if [ -n "$nameid" ]; then
        echo "$nameid"
        return 0
    fi
    
    ml_log_error "Could not extract NameID from assertion"
    return 1
}

# Extract attributes from SAML assertion
saml_extract_attributes() {
    local assertion_file="$1"
    
    if [ ! -f "$assertion_file" ]; then
        ml_log_error "Assertion file not found: $assertion_file"
        return 1
    fi
    
    ml_log_step "Extracting attributes from SAML assertion"
    
    if command -v xmllint >/dev/null 2>&1; then
        # Get attribute count
        local attr_count
        attr_count=$(xmllint --xpath "count(//*[local-name()='Attribute'])" "$assertion_file" 2>/dev/null)
        
        if [ "$attr_count" -gt 0 ]; then
            ml_log_info "Found $attr_count attribute(s):"
            
            for i in $(seq 1 "$attr_count"); do
                local attr_name attr_value
                attr_name=$(xmllint --xpath "string(//*[local-name()='Attribute'][position()=$i]/@Name)" "$assertion_file" 2>/dev/null)
                attr_value=$(xmllint --xpath "string(//*[local-name()='Attribute'][position()=$i]/*[local-name()='AttributeValue'])" "$assertion_file" 2>/dev/null)
                
                echo "  $attr_name: $attr_value"
            done
        else
            ml_log_info "No attributes found in assertion"
        fi
    else
        ml_log_warning "xmllint not available. Using grep-based extraction."
        
        # Fallback method
        if grep -q "AttributeStatement" "$assertion_file"; then
            ml_log_info "Attributes found (use xmllint for detailed extraction):"
            grep -o 'Name="[^"]*"' "$assertion_file" | cut -d'"' -f2 | while read -r attr; do
                echo "  $attr"
            done
        else
            ml_log_info "No attributes found in assertion"
        fi
    fi
}

# Validate SAML assertion signature
saml_validate_assertion_signature() {
    local assertion_file="$1"
    local idp_cert_file="$2"
    
    if [ ! -f "$assertion_file" ]; then
        ml_log_error "Assertion file not found: $assertion_file"
        return 1
    fi
    
    if [ ! -f "$idp_cert_file" ]; then
        ml_log_error "IdP certificate file not found: $idp_cert_file"
        return 1
    fi
    
    ml_log_step "Validating SAML assertion signature"
    
    # Check if assertion is signed
    if ! grep -q "Signature" "$assertion_file"; then
        ml_log_warning "No signature found in assertion"
        return 1
    fi
    
    # Note: Proper SAML signature validation requires specialized tools
    # like xmlsec1. This is a basic check.
    if command -v xmlsec1 >/dev/null 2>&1; then
        if xmlsec1 --verify --pubkey-cert-pem "$idp_cert_file" "$assertion_file" >/dev/null 2>&1; then
            ml_log_success "SAML assertion signature is valid"
            return 0
        else
            ml_log_error "SAML assertion signature validation failed"
            return 1
        fi
    else
        ml_log_warning "xmlsec1 not found. Cannot validate signature."
        ml_log_info "Install xmlsec1 for signature validation:"
        ml_log_info "  Ubuntu/Debian: sudo apt-get install xmlsec1"
        ml_log_info "  CentOS/RHEL: sudo yum install xmlsec1"
        ml_log_info "  macOS: brew install libxmlsec1"
        return 1
    fi
}

# Check assertion validity period
saml_check_assertion_validity() {
    local assertion_file="$1"
    local clock_skew="${2:-300}"
    
    if [ ! -f "$assertion_file" ]; then
        ml_log_error "Assertion file not found: $assertion_file"
        return 1
    fi
    
    ml_log_step "Checking SAML assertion validity period"
    
    if command -v xmllint >/dev/null 2>&1; then
        # Extract validity conditions
        local not_before not_on_or_after
        not_before=$(xmllint --xpath "string(//*[local-name()='Conditions']/@NotBefore)" "$assertion_file" 2>/dev/null)
        not_on_or_after=$(xmllint --xpath "string(//*[local-name()='Conditions']/@NotOnOrAfter)" "$assertion_file" 2>/dev/null)
        
        if [ -n "$not_before" ] && [ -n "$not_on_or_after" ]; then
            ml_log_info "NotBefore: $not_before"
            ml_log_info "NotOnOrAfter: $not_on_or_after"
            
            # Convert to epoch time for comparison
            local not_before_epoch not_on_or_after_epoch current_epoch
            
            if command -v gdate >/dev/null 2>&1; then
                # macOS with GNU date
                not_before_epoch=$(gdate -d "$not_before" +%s 2>/dev/null)
                not_on_or_after_epoch=$(gdate -d "$not_on_or_after" +%s 2>/dev/null)
            else
                # Linux date
                not_before_epoch=$(date -d "$not_before" +%s 2>/dev/null)
                not_on_or_after_epoch=$(date -d "$not_on_or_after" +%s 2>/dev/null)
            fi
            
            current_epoch=$(date +%s)
            
            if [ -n "$not_before_epoch" ] && [ -n "$not_on_or_after_epoch" ]; then
                local adjusted_not_before adjusted_not_on_or_after
                adjusted_not_before=$((not_before_epoch - clock_skew))
                adjusted_not_on_or_after=$((not_on_or_after_epoch + clock_skew))
                
                if [ "$current_epoch" -ge "$adjusted_not_before" ] && [ "$current_epoch" -le "$adjusted_not_on_or_after" ]; then
                    ml_log_success "Assertion is within validity period (with $clock_skew second clock skew)"
                    return 0
                else
                    ml_log_error "Assertion is outside validity period"
                    
                    if [ "$current_epoch" -lt "$adjusted_not_before" ]; then
                        local diff=$((adjusted_not_before - current_epoch))
                        ml_log_error "Assertion not yet valid (starts in $diff seconds)"
                    else
                        local diff=$((current_epoch - adjusted_not_on_or_after))
                        ml_log_error "Assertion has expired ($diff seconds ago)"
                    fi
                    return 1
                fi
            else
                ml_log_warning "Could not parse date formats for validity checking"
                return 1
            fi
        else
            ml_log_warning "No validity conditions found in assertion"
            return 1
        fi
    else
        ml_log_warning "xmllint not available. Cannot check validity period."
        return 1
    fi
}

# ================================================================
# SAML CONFIGURATION TESTING FUNCTIONS
# ================================================================

# Test SAML metadata URL accessibility
saml_test_metadata_url() {
    local metadata_url="$1"
    
    if [ -z "$metadata_url" ]; then
        ml_log_error "Metadata URL is required"
        return 1
    fi
    saml_validate_url_for_curl "$metadata_url" || return 1
    if [ "${DRY_RUN:-false}" = "true" ]; then
        ml_log_info "[DRY-RUN] Metadata URL request skipped; no network request was made"
        return 0
    fi
    ml_log_step "Testing SAML metadata URL accessibility"
    
    if command -v curl >/dev/null 2>&1; then
        local curl_result
        if curl_result=$(curl -s -f --connect-timeout 5 --max-time 20 -w "%{http_code}" "$metadata_url" 2>/dev/null); then
            local http_code
            http_code=$(echo "$curl_result" | tail -1)
            local response_body
            response_body=$(echo "$curl_result" | head -n -1)
            
            case "$http_code" in
                200)
                    ml_log_success "Metadata URL is accessible (HTTP $http_code)"
                    
                    # Check if response contains SAML metadata
                    if echo "$response_body" | grep -q "EntityDescriptor"; then
                        ml_log_success "Response contains SAML metadata"
                    else
                        ml_log_warning "Response does not appear to contain SAML metadata"
                    fi
                    return 0
                    ;;
                *)
                    ml_log_error "Metadata URL returned HTTP $http_code"
                    return 1
                    ;;
            esac
        else
            ml_log_error "Failed to access metadata URL"
            return 1
        fi
    else
        ml_log_error "curl not found. Cannot test metadata URL."
        return 1
    fi
}

# Comprehensive SAML configuration validation
saml_validate_configuration() {
    local idp_metadata="$1"
    local sp_entity_id="$2"
    local sp_acs_url="$3"
    
    ml_log_step "Comprehensive SAML configuration validation"
    if [ "${DRY_RUN:-false}" = "true" ]; then
        ml_log_info "[DRY-RUN] Metadata and ACS reachability checks skipped; configuration is not certified"
        return 0
    fi
    
    local validation_passed=true
    
    # Test 1: Validate IdP metadata
    echo "1. Validating IdP metadata..."
    if [ -n "$idp_metadata" ]; then
        if [[ "$idp_metadata" == http* ]]; then
            if ! saml_test_metadata_url "$idp_metadata"; then
                validation_passed=false
            fi
        else
            if ! saml_validate_metadata "$idp_metadata" "idp"; then
                validation_passed=false
            fi
        fi
    else
        ml_log_error "IdP metadata not provided"
        validation_passed=false
    fi
    
    # Test 2: Validate SP configuration
    echo
    echo "2. Validating SP configuration..."
    if [ -n "$sp_entity_id" ]; then
        ml_log_success "SP Entity ID configured"
    else
        ml_log_error "SP Entity ID not configured"
        validation_passed=false
    fi
    
    if [ -n "$sp_acs_url" ]; then
        ml_log_success "SP ACS URL configured"
        
        # Test if ACS URL is accessible
        if ! saml_validate_url_for_curl "$sp_acs_url"; then
            validation_passed=false
        elif command -v curl >/dev/null 2>&1; then
            if curl -s -I --connect-timeout 5 --max-time 20 "$sp_acs_url" >/dev/null 2>&1; then
                ml_log_success "SP ACS URL is accessible"
            else
                ml_log_warning "SP ACS URL may not be accessible"
            fi
        fi
    else
        ml_log_error "SP ACS URL not configured"
        validation_passed=false
    fi
    
    # Test 3: Certificate validation (if available)
    echo
    echo "3. Certificate validation..."
    ml_log_info "Certificate validation requires specific certificate files"
    
    if [ "$validation_passed" = "true" ]; then
        echo
        ml_log_success "SAML configuration validation passed"
        return 0
    else
        echo
        ml_log_error "SAML configuration validation failed"
        return 1
    fi
}

# ================================================================
# TROUBLESHOOTING FUNCTIONS
# ================================================================

# Show common SAML troubleshooting tips
saml_show_troubleshooting_tips() {
    cat << EOF

Common SAML Troubleshooting Tips:
=================================

1. Metadata Issues:
   - Verify IdP metadata URL is accessible
   - Check metadata XML is well-formed
   - Ensure EntityDescriptor and IDPSSODescriptor are present
   - Validate metadata certificates

2. Configuration Mismatches:
   - SP Entity ID must match what's configured in IdP
   - ACS URL must match exactly (including protocol and port)
   - NameID format must be supported by both SP and IdP
   - Binding types must match (HTTP-POST vs HTTP-Redirect)

3. Certificate Issues:
   - Verify SAML assertions are properly signed
   - Check IdP signing certificate is trusted
   - Ensure certificate hasn't expired
   - Validate certificate chain

4. Clock Synchronization:
   - SAML assertions have validity windows
   - Clock skew between IdP and SP can cause failures
   - Default clock skew is usually 5 minutes
   - Synchronize clocks using NTP

5. Attribute Mapping:
   - Verify required attributes are sent by IdP
   - Check attribute names match expected values
   - Ensure attribute values are in correct format
   - Test with minimal required attributes first

6. MarkLogic Integration:
   - Check MarkLogic logs for SAML errors
   - Verify external security configuration
   - Ensure app server is configured for SAML
   - Restart MarkLogic after configuration changes

7. Network Issues:
   - Verify SAML endpoints are accessible
   - Check firewall rules for HTTP/HTTPS traffic
   - Test SSL/TLS certificates on HTTPS endpoints
   - Ensure DNS resolution works correctly

Debug Tools:
============
   xmllint --format metadata.xml          # Format XML for reading
   xmlsec1 --verify --pubkey-cert-pem ...  # Verify signatures
   curl -I <metadata-url>                  # Test URL accessibility
   openssl x509 -in cert.pem -text        # Examine certificates

Common SAML Flows:
==================
   1. User accesses MarkLogic app server
   2. MarkLogic redirects to IdP SSO URL
   3. User authenticates with IdP
   4. IdP posts SAML assertion to ACS URL
   5. MarkLogic validates assertion and creates session

EOF
}

# Comprehensive SAML troubleshooting
saml_comprehensive_troubleshooting() {
    local idp_metadata="$1"
    local sp_entity_id="$2"
    local sp_acs_url="$3"
    
    ml_log_step "Comprehensive SAML troubleshooting"
    
    echo "1. SAML configuration validation..."
    saml_validate_configuration "$idp_metadata" "$sp_entity_id" "$sp_acs_url" || true
    
    echo
    echo "2. Network connectivity tests..."
    if [ "${DRY_RUN:-false}" = "true" ]; then
        ml_log_info "[DRY-RUN] Metadata and ACS reachability checks skipped"
    else
        if [ -n "$idp_metadata" ] && [[ "$idp_metadata" == http* ]]; then
            saml_test_metadata_url "$idp_metadata" || true
        fi

        if [ -n "$sp_acs_url" ] && [[ "$sp_acs_url" == http* ]] && saml_validate_url_for_curl "$sp_acs_url"; then
            ml_log_info "Testing SP ACS URL accessibility..."
            if command -v curl >/dev/null 2>&1; then
                curl -s -I --connect-timeout 5 --max-time 20 "$sp_acs_url" >/dev/null 2>&1 || true
            fi
        fi
    fi
    
    echo
    echo "3. Metadata analysis..."
    if [ -n "$idp_metadata" ] && [ -f "$idp_metadata" ]; then
        saml_extract_entity_id "$idp_metadata" || true
        saml_extract_sso_urls "$idp_metadata" || true
    fi
    
    echo
    saml_show_troubleshooting_tips
}

# ================================================================
# UTILITY EXPORT FUNCTIONS
# ================================================================

# Make functions available to other scripts
export -f saml_validate_url_for_curl
export -f saml_extract_entity_id
export -f saml_extract_sso_urls
export -f saml_extract_certificates
export -f saml_validate_metadata
export -f saml_extract_nameid
export -f saml_extract_attributes
export -f saml_validate_assertion_signature
export -f saml_check_assertion_validity
export -f saml_test_metadata_url
export -f saml_validate_configuration
export -f saml_show_troubleshooting_tips
export -f saml_comprehensive_troubleshooting