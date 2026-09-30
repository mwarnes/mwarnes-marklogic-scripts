#!/bin/bash

# ================================================================
# LDAP Utilities for MarkLogic Authentication
# ================================================================
#
# Common utility functions for LDAP authentication management
# in MarkLogic environments. These functions provide LDAP
# connectivity testing, user/group search, and configuration
# validation utilities.
#
# Author: Martin Warnes
# Version: 1.0.2
# Date: November 2025
#
# ================================================================

# Source common utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../marklogic-utils.sh"

# ================================================================
# LDAP SECURITY HELPERS
# ================================================================

# Create secure temporary password file
ldap_create_password_file() {
    if [ "${DRY_RUN:-false}" = "true" ]; then
        ml_log_error "Refusing to create an LDAP password file in DRY_RUN"
        return 1
    fi
    local password="$1"
    local temp_file
    temp_file=$(mktemp) || return 1
    chmod 600 "$temp_file" || { rm -f "$temp_file"; return 1; }
    printf '%s' "$password" > "$temp_file" || { rm -f "$temp_file"; return 1; }
    echo "$temp_file"
}

# Clean up password file
ldap_cleanup_password_file() {
    local password_file="$1"
    [ -n "$password_file" ] && [ -f "$password_file" ] && rm -f "$password_file"
}

# Validate LDAP attribute descriptor (RFC4512)
ldap_validate_attribute_descriptor() {
    local attr="$1"
    # RFC4512: attributedescription = attributetype [ ";" options ]
    # attributetype = oid / ( ALPHA *( ALPHA / DIGIT / "-" ) )
    # oid = descr / numericoid
    if [[ "$attr" =~ ^[a-zA-Z][a-zA-Z0-9-]*([;][a-zA-Z0-9-]+)*$|^[0-9]+([.][0-9]+)*([;][a-zA-Z0-9-]+)*$ ]]; then
        return 0
    else
        return 1
    fi
}

# Escape LDAP filter values (RFC4515)
ldap_escape_filter_value() {
    local value="$1"
    # Escape special characters: \ first, then * ( )
    printf '%s' "$value" | sed 's/\\/\\5c/g; s/\*/\\2a/g; s/(/\\28/g; s/)/\\29/g'
}

# ================================================================
# LDAP CLIENT TOOLS VALIDATION
# ================================================================

# Check if LDAP client tools are available
ldap_check_tools() {
    ml_log_step "Checking LDAP client tools availability"

    local tools_available=true

    # Check for ldapsearch (most important)
    if command -v ldapsearch >/dev/null 2>&1; then
        ml_log_success "ldapsearch: Available"
    else
        ml_log_error "ldapsearch: Not found"
        tools_available=false
    fi

    # Check for other useful LDAP tools
    if command -v ldapwhoami >/dev/null 2>&1; then
        ml_log_success "ldapwhoami: Available"
    else
        ml_log_info "ldapwhoami: Not found (optional, useful for testing authentication)"
    fi

    if command -v ldapcompare >/dev/null 2>&1; then
        ml_log_success "ldapcompare: Available"
    else
        ml_log_info "ldapcompare: Not found (optional)"
    fi

    if command -v ldapmodify >/dev/null 2>&1; then
        ml_log_success "ldapmodify: Available"
    else
        ml_log_info "ldapmodify: Not found (not needed for authentication testing)"
    fi

    if [ "$tools_available" = "true" ]; then
        ml_log_success "Essential LDAP tools are available"
        return 0
    else
        ml_log_error "Missing essential LDAP tools"
        ml_log_error "Install LDAP client package:"
        ml_log_error "  Ubuntu/Debian: sudo apt-get install ldap-utils"
        ml_log_error "  CentOS/RHEL: sudo yum install openldap-clients"
        ml_log_error "  macOS: brew install openldap"
        return 1
    fi
}

# ================================================================
# LDAP SERVER CONNECTIVITY FUNCTIONS
# ================================================================

# Parse LDAP server URI
ldap_parse_server_uri() {
    local ldap_uri="$1"

    if [[ "$ldap_uri" =~ ^(ldaps?)://([^:/]+):?([0-9]+)?/?.*$ ]]; then
        LDAP_PROTOCOL="${BASH_REMATCH[1]}"
        LDAP_HOSTNAME="${BASH_REMATCH[2]}"
        LDAP_PORT="${BASH_REMATCH[3]}"

        # Set default ports if not specified
        if [ -z "$LDAP_PORT" ]; then
            if [ "$LDAP_PROTOCOL" = "ldaps" ]; then
                LDAP_PORT="636"
            else
                LDAP_PORT="389"
            fi
        fi

        ml_log_verbose "Parsed LDAP URI: protocol=$LDAP_PROTOCOL, host=$LDAP_HOSTNAME, port=$LDAP_PORT"
        return 0
    else
        ml_log_error "Invalid LDAP server URI format: $ldap_uri"
        ml_log_error "Expected format: ldap://host[:port] or ldaps://host[:port]"
        return 1
    fi
}

# Test basic TCP connectivity to LDAP server
ldap_test_tcp_connectivity() {
    local ldap_uri="$1"

    # Parse the LDAP URI
    if ! ldap_parse_server_uri "$ldap_uri"; then
        return 1
    fi

    if [ "${DRY_RUN:-false}" = "true" ]; then
        ml_log_info "DRY_RUN: Would test TCP connectivity to $LDAP_HOSTNAME:$LDAP_PORT"
        return 0
    fi

    ml_log_step "Testing TCP connectivity to $LDAP_HOSTNAME:$LDAP_PORT"

    # Test TCP connection
    if command -v nc >/dev/null 2>&1; then
        if nc -z "$LDAP_HOSTNAME" "$LDAP_PORT" 2>/dev/null; then
            ml_log_success "TCP connection successful"
            return 0
        else
            ml_log_error "TCP connection failed"
            ml_log_error "Check:"
            ml_log_error "  1. LDAP server is running"
            ml_log_error "  2. Network connectivity to $LDAP_HOSTNAME"
            ml_log_error "  3. Firewall allows port $LDAP_PORT"
            ml_log_error "  4. Correct hostname/port in URI"
            return 1
        fi
    elif command -v telnet >/dev/null 2>&1; then
        # Fallback to telnet test
        if echo "" | telnet "$LDAP_HOSTNAME" "$LDAP_PORT" 2>/dev/null | grep -q "Connected"; then
            ml_log_success "TCP connection successful (via telnet)"
            return 0
        else
            ml_log_error "TCP connection failed (via telnet)"
            return 1
        fi
    else
        ml_log_warning "Neither nc nor telnet available for connectivity testing"
        return 1
    fi
}

# Test anonymous LDAP bind
ldap_test_anonymous_bind() {
    local ldap_uri="$1"
    local ldap_base="$2"

    if ! command -v ldapsearch >/dev/null 2>&1; then
        ml_log_error "ldapsearch command not found"
        return 1
    fi

    ml_log_step "Testing anonymous LDAP bind"

    # Try anonymous bind with base search
    if [ "${DRY_RUN:-false}" = "true" ]; then
        ml_log_info "DRY_RUN: Would test anonymous bind to $ldap_uri with base '$ldap_base'"
        return 0
    fi

    local ldapsearch_cmd=(ldapsearch -x -H "$ldap_uri" -b "$ldap_base" -s base "objectClass=*")

    if "${ldapsearch_cmd[@]}" >/dev/null 2>&1; then
        ml_log_success "Anonymous LDAP bind successful"
        return 0
    else
        ml_log_info "Anonymous LDAP bind failed (may be disabled)"
        return 1
    fi
}

# Test authenticated LDAP bind
ldap_test_authenticated_bind() {
    local ldap_uri="$1"
    local bind_dn="$2"
    local bind_password="$3"
    local ldap_base="$4"
    local start_tls="${5:-false}"

    if ! command -v ldapsearch >/dev/null 2>&1; then
        ml_log_error "ldapsearch command not found"
        return 1
    fi

    ml_log_step "Testing authenticated LDAP bind for: $bind_dn"

    if [ "${DRY_RUN:-false}" = "true" ]; then
        ml_log_info "DRY_RUN: Would test authenticated bind as '$bind_dn' to $ldap_uri with base '$ldap_base'"
        return 0
    fi

    # Create secure password file
    local password_file
    password_file=$(ldap_create_password_file "$bind_password") || {
        ml_log_error "Failed to create secure password file"
        return 1
    }

    # Build ldapsearch command
    local ldapsearch_cmd=(ldapsearch -x -H "$ldap_uri" -D "$bind_dn" -y "$password_file" -b "$ldap_base" -s base "objectClass=*")

    # Add StartTLS if requested
    if [ "$start_tls" = "true" ]; then
        ldapsearch_cmd+=(-Z)
    fi

    if "${ldapsearch_cmd[@]}" >/dev/null 2>&1; then
        ldap_cleanup_password_file "$password_file"
        ml_log_success "Authenticated LDAP bind successful"
        return 0
    else
        ldap_cleanup_password_file "$password_file"
        ml_log_error "Authenticated LDAP bind failed"
        ml_log_error "Check:"
        ml_log_error "  1. Bind DN format is correct"
        ml_log_error "  2. Password is correct"
        ml_log_error "  3. Account is not locked/disabled"
        ml_log_error "  4. Account has appropriate permissions"
        return 1
    fi
}

# Test LDAP StartTLS functionality
ldap_test_starttls() {
    local ldap_uri="$1"
    local bind_dn="$2"
    local bind_password="$3"
    local ldap_base="$4"

    if ! command -v ldapsearch >/dev/null 2>&1; then
        ml_log_error "ldapsearch command not found"
        return 1
    fi

    ml_log_step "Testing LDAP StartTLS functionality"

    if [ "${DRY_RUN:-false}" = "true" ]; then
        ml_log_info "DRY_RUN: Would test StartTLS to $ldap_uri as '$bind_dn'"
        return 0
    fi

    # Create secure password file
    local password_file
    password_file=$(ldap_create_password_file "$bind_password") || {
        ml_log_error "Failed to create secure password file"
        return 1
    }

    # Test StartTLS with authentication
    local ldapsearch_cmd=(ldapsearch -x -H "$ldap_uri" -Z -D "$bind_dn" -y "$password_file" -b "$ldap_base" -s base "objectClass=*")

    if "${ldapsearch_cmd[@]}" >/dev/null 2>&1; then
        ldap_cleanup_password_file "$password_file"
        ml_log_success "LDAP StartTLS test successful"
        return 0
    else
        ldap_cleanup_password_file "$password_file"
        ml_log_error "LDAP StartTLS test failed"
        ml_log_error "Check:"
        ml_log_error "  1. LDAP server supports StartTLS"
        ml_log_error "  2. SSL/TLS certificate is valid"
        ml_log_error "  3. Certificate authority is trusted"
        return 1
    fi
}

# ================================================================
# USER AND GROUP SEARCH FUNCTIONS
# ================================================================

# Search for a specific user
ldap_search_user() {
    local ldap_uri="$1"
    local bind_dn="$2"
    local bind_password="$3"
    local search_base="$4"
    local username="$5"
    local user_attr="${6:-uid}"
    local start_tls="${7:-false}"

    if ! command -v ldapsearch >/dev/null 2>&1; then
        ml_log_error "ldapsearch command not found"
        return 1
    fi

    ml_log_step "Searching for user: $username (attribute: $user_attr)"

    # Validate attribute descriptor
    if ! ldap_validate_attribute_descriptor "$user_attr"; then
        ml_log_error "Invalid LDAP attribute descriptor: $user_attr"
        return 1
    fi

    # Escape the username for LDAP filter
    local escaped_username
    escaped_username=$(ldap_escape_filter_value "$username")

    # Build search filter
    local search_filter="(&(objectClass=*)(${user_attr}=${escaped_username}))"

    if [ "${DRY_RUN:-false}" = "true" ]; then
        ml_log_info "DRY_RUN: Would search for user '$username' with filter '$search_filter' in base '$search_base'"
        return 0
    fi

    # Build ldapsearch command
    local ldapsearch_cmd=(ldapsearch -x -H "$ldap_uri" -b "$search_base" "$search_filter" "$user_attr" cn mail dn)
    local password_file=""

    # Add authentication if provided
    if [ -n "$bind_dn" ] && [ -n "$bind_password" ]; then
        password_file=$(ldap_create_password_file "$bind_password") || {
            ml_log_error "Failed to create secure password file"
            return 1
        }
        ldapsearch_cmd+=(-D "$bind_dn" -y "$password_file")
    fi

    # Add StartTLS if requested
    if [ "$start_tls" = "true" ]; then
        ldapsearch_cmd+=(-Z)
    fi

    ml_log_info "Search filter: $search_filter"
    ml_log_info "Search base: $search_base"

    if "${ldapsearch_cmd[@]}"; then
        [ -n "$password_file" ] && ldap_cleanup_password_file "$password_file"
        ml_log_success "User search completed"
        return 0
    else
        [ -n "$password_file" ] && ldap_cleanup_password_file "$password_file"
        ml_log_error "User search failed"
        return 1
    fi
}

# Search for users matching a pattern
ldap_search_users_pattern() {
    local ldap_uri="$1"
    local bind_dn="$2"
    local bind_password="$3"
    local search_base="$4"
    local pattern="$5"
    local user_attr="${6:-uid}"
    local max_results="${7:-50}"
    local start_tls="${8:-false}"

    if ! command -v ldapsearch >/dev/null 2>&1; then
        ml_log_error "ldapsearch command not found"
        return 1
    fi

    ml_log_step "Searching for users matching pattern: $pattern"

    # Validate attribute descriptor
    if ! ldap_validate_attribute_descriptor "$user_attr"; then
        ml_log_error "Invalid LDAP attribute descriptor: $user_attr"
        return 1
    fi

    # For pattern search, preserve * wildcard but escape other special chars
    local escaped_pattern="$pattern"
    if [[ "$pattern" != *"*"* ]]; then
        # No wildcards, escape completely
        escaped_pattern=$(ldap_escape_filter_value "$pattern")
    else
        # Has wildcards, escape only non-wildcard special chars (preserve *)
        escaped_pattern=$(printf '%s' "$pattern" | sed 's/\\/\\5c/g; s/(/\\28/g; s/)/\\29/g')
    fi

    # Build search filter for common user object classes
    local search_filter="(&(|(objectClass=person)(objectClass=inetOrgPerson)(objectClass=user))(${user_attr}=${escaped_pattern}))"

    if [ "${DRY_RUN:-false}" = "true" ]; then
        ml_log_info "DRY_RUN: Would search for users with pattern '$pattern' (escaped: '$escaped_pattern') in base '$search_base'"
        return 0
    fi

    # Build ldapsearch command
    local ldapsearch_cmd=(ldapsearch -x -H "$ldap_uri" -b "$search_base" "$search_filter" "$user_attr" cn mail sAMAccountName -z "$max_results")
    local password_file=""

    # Add authentication if provided
    if [ -n "$bind_dn" ] && [ -n "$bind_password" ]; then
        password_file=$(ldap_create_password_file "$bind_password") || {
            ml_log_error "Failed to create secure password file"
            return 1
        }
        ldapsearch_cmd+=(-D "$bind_dn" -y "$password_file")
    fi

    # Add StartTLS if requested
    if [ "$start_tls" = "true" ]; then
        ldapsearch_cmd+=(-Z)
    fi

    ml_log_info "Search filter: $search_filter"
    ml_log_info "Search base: $search_base"
    ml_log_info "Max results: $max_results"

    if "${ldapsearch_cmd[@]}"; then
        [ -n "$password_file" ] && ldap_cleanup_password_file "$password_file"
        ml_log_success "User pattern search completed"
        return 0
    else
        [ -n "$password_file" ] && ldap_cleanup_password_file "$password_file"
        ml_log_error "User pattern search failed"
        return 1
    fi
}

# Get user's group memberships
ldap_get_user_groups() {
    local ldap_uri="$1"
    local bind_dn="$2"
    local bind_password="$3"
    local user_dn="$4"
    local start_tls="${5:-false}"

    if ! command -v ldapsearch >/dev/null 2>&1; then
        ml_log_error "ldapsearch command not found"
        return 1
    fi

    ml_log_step "Getting group memberships for user: $user_dn"

    # Escape DN and extract/escape UID for filter safety
    local escaped_dn
    escaped_dn=$(ldap_escape_filter_value "$user_dn")
    local user_uid="${user_dn##*=}"
    local escaped_uid
    escaped_uid=$(ldap_escape_filter_value "$user_uid")

    # Search for groups that contain this user
    local search_filter="(&(|(objectClass=group)(objectClass=groupOfNames)(objectClass=posixGroup))(|(member=${escaped_dn})(uniqueMember=${escaped_dn})(memberUid=${escaped_uid})))"

    # Extract search base from user DN (assume groups are in same domain)
    local search_base
    if [[ "$user_dn" =~ DC= ]]; then
        # Active Directory style
        search_base=$(echo "$user_dn" | sed 's/.*\(DC=.*\)/\1/')
    else
        # OpenLDAP style
        search_base=$(echo "$user_dn" | sed 's/.*\(dc=.*\)/\1/')
    fi

    if [ "${DRY_RUN:-false}" = "true" ]; then
        ml_log_info "DRY_RUN: Would search for groups containing user '$user_dn' in base '$search_base'"
        return 0
    fi

    # Build ldapsearch command
    local ldapsearch_cmd=(ldapsearch -x -H "$ldap_uri" -b "$search_base" "$search_filter" cn dn)
    local password_file=""

    # Add authentication if provided
    if [ -n "$bind_dn" ] && [ -n "$bind_password" ]; then
        password_file=$(ldap_create_password_file "$bind_password") || {
            ml_log_error "Failed to create secure password file"
            return 1
        }
        ldapsearch_cmd+=(-D "$bind_dn" -y "$password_file")
    fi

    # Add StartTLS if requested
    if [ "$start_tls" = "true" ]; then
        ldapsearch_cmd+=(-Z)
    fi

    ml_log_info "Search filter: $search_filter"
    ml_log_info "Search base: $search_base"

    if "${ldapsearch_cmd[@]}"; then
        [ -n "$password_file" ] && ldap_cleanup_password_file "$password_file"
        ml_log_success "Group membership search completed"
        return 0
    else
        [ -n "$password_file" ] && ldap_cleanup_password_file "$password_file"
        ml_log_error "Group membership search failed"
        return 1
    fi
}

# ================================================================
# USER AUTHENTICATION FUNCTIONS
# ================================================================

# Test user authentication with LDAP
ldap_test_user_auth() {
    local ldap_uri="$1"
    local user_dn="$2"
    local user_password="$3"
    local ldap_base="$4"
    local start_tls="${5:-false}"

    if ! command -v ldapsearch >/dev/null 2>&1; then
        ml_log_error "ldapsearch command not found"
        return 1
    fi

    ml_log_step "Testing user authentication for: $user_dn"

    if [ "${DRY_RUN:-false}" = "true" ]; then
        ml_log_info "DRY_RUN: Would test authentication for user '$user_dn' against base '$ldap_base'"
        return 0
    fi

    # Create secure password file
    local password_file
    password_file=$(ldap_create_password_file "$user_password") || {
        ml_log_error "Failed to create secure password file"
        return 1
    }

    # Try to bind as the user
    local ldapsearch_cmd=(ldapsearch -x -H "$ldap_uri" -D "$user_dn" -y "$password_file" -b "$ldap_base" -s base "objectClass=*")

    # Add StartTLS if requested
    if [ "$start_tls" = "true" ]; then
        ldapsearch_cmd+=(-Z)
    fi

    if "${ldapsearch_cmd[@]}" >/dev/null 2>&1; then
        ldap_cleanup_password_file "$password_file"
        ml_log_success "User authentication successful"
        return 0
    else
        ldap_cleanup_password_file "$password_file"
        ml_log_error "User authentication failed"
        return 1
    fi
}

# Test user authentication with ldapwhoami
ldap_test_user_whoami() {
    local ldap_uri="$1"
    local user_dn="$2"
    local user_password="$3"
    local start_tls="${4:-false}"

    if ! command -v ldapwhoami >/dev/null 2>&1; then
        ml_log_info "ldapwhoami not available, skipping whoami test"
        return 0
    fi

    ml_log_step "Testing user authentication with ldapwhoami"

    if [ "${DRY_RUN:-false}" = "true" ]; then
        ml_log_info "DRY_RUN: Would test ldapwhoami for user '$user_dn'"
        return 0
    fi

    # Create secure password file
    local password_file
    password_file=$(ldap_create_password_file "$user_password") || {
        ml_log_error "Failed to create secure password file"
        return 1
    }

    # Build ldapwhoami command
    local ldapwhoami_cmd=(ldapwhoami -x -H "$ldap_uri" -D "$user_dn" -y "$password_file")

    # Add StartTLS if requested
    if [ "$start_tls" = "true" ]; then
        ldapwhoami_cmd+=(-Z)
    fi

    local whoami_result
    if whoami_result=$("${ldapwhoami_cmd[@]}" 2>&1); then
        ldap_cleanup_password_file "$password_file"
        ml_log_success "ldapwhoami test successful: $whoami_result"
        return 0
    else
        ldap_cleanup_password_file "$password_file"
        ml_log_error "ldapwhoami test failed: $whoami_result"
        return 1
    fi
}

# ================================================================
# LDAP CONFIGURATION VALIDATION
# ================================================================

# Validate LDAP configuration for MarkLogic
ldap_validate_marklogic_config() {
    local ldap_uri="$1"
    local bind_dn="$2"
    local bind_password="$3"
    local ldap_base="$4"
    local user_attr="$5"
    local start_tls="${6:-false}"

    ml_log_step "Validating LDAP configuration for MarkLogic"

    local validation_passed=true

    # Test 1: TCP connectivity
    echo "1. Testing TCP connectivity..."
    if ! ldap_test_tcp_connectivity "$ldap_uri"; then
        validation_passed=false
    fi

    echo
    echo "2. Testing anonymous bind..."
    ldap_test_anonymous_bind "$ldap_uri" "$ldap_base" || true

    # Test 3: Authenticated bind (if credentials provided)
    if [ -n "$bind_dn" ] && [ -n "$bind_password" ]; then
        echo
        echo "3. Testing authenticated bind..."
        if ! ldap_test_authenticated_bind "$ldap_uri" "$bind_dn" "$bind_password" "$ldap_base" "$start_tls"; then
            validation_passed=false
        fi
    fi

    # Test 4: StartTLS (if enabled)
    if [ "$start_tls" = "true" ] && [ -n "$bind_dn" ] && [ -n "$bind_password" ]; then
        echo
        echo "4. Testing StartTLS..."
        if ! ldap_test_starttls "$ldap_uri" "$bind_dn" "$bind_password" "$ldap_base"; then
            ml_log_warning "StartTLS test failed, but continuing validation"
        fi
    fi

    # Test 5: User attribute search
    if [ -n "$user_attr" ] && [ -n "$bind_dn" ] && [ -n "$bind_password" ]; then
        echo
        echo "5. Testing user attribute search..."
        ldap_test_user_attribute_search "$ldap_uri" "$bind_dn" "$bind_password" "$ldap_base" "$user_attr" "$start_tls"
    fi

    echo
    if [ "$validation_passed" = "true" ]; then
        ml_log_success "LDAP configuration validation passed"
        return 0
    else
        ml_log_error "LDAP configuration validation failed"
        return 1
    fi
}

# Test if user attribute is searchable
ldap_test_user_attribute_search() {
    local ldap_uri="$1"
    local bind_dn="$2"
    local bind_password="$3"
    local ldap_base="$4"
    local user_attr="$5"
    local start_tls="${6:-false}"

    if ! command -v ldapsearch >/dev/null 2>&1; then
        ml_log_error "ldapsearch command not found"
        return 1
    fi

    ml_log_info "Testing if users can be found by attribute: $user_attr"

    # Validate attribute descriptor
    if ! ldap_validate_attribute_descriptor "$user_attr"; then
        ml_log_error "Invalid LDAP attribute descriptor: $user_attr"
        return 1
    fi

    # Search for any user with the specified attribute
    local search_filter="(&(objectClass=*)(${user_attr}=*))"

    if [ "${DRY_RUN:-false}" = "true" ]; then
        ml_log_info "DRY_RUN: Would test searchability of user attribute '$user_attr' in base '$ldap_base'"
        return 0
    fi

    # Create secure password file
    local password_file
    password_file=$(ldap_create_password_file "$bind_password") || {
        ml_log_error "Failed to create secure password file"
        return 1
    }

    # Build ldapsearch command
    local ldapsearch_cmd=(ldapsearch -x -H "$ldap_uri" -D "$bind_dn" -y "$password_file" -b "$ldap_base" "$search_filter" "$user_attr" -z 5)

    # Add StartTLS if requested
    if [ "$start_tls" = "true" ]; then
        ldapsearch_cmd+=(-Z)
    fi

    if "${ldapsearch_cmd[@]}" >/dev/null 2>&1; then
        ldap_cleanup_password_file "$password_file"
        ml_log_success "User attribute '$user_attr' is searchable"
        return 0
    else
        ldap_cleanup_password_file "$password_file"
        ml_log_warning "User attribute '$user_attr' search failed or no results"
        ml_log_warning "Check if '$user_attr' is the correct attribute name for your LDAP directory"
        return 1
    fi
}

# ================================================================
# LDAP DIRECTORY TYPE DETECTION
# ================================================================

# Detect LDAP directory type (Active Directory vs OpenLDAP)
ldap_detect_directory_type() {
    local ldap_uri="$1"
    local bind_dn="$2"
    local bind_password="$3"
    local ldap_base="$4"
    local start_tls="${5:-false}"

    if ! command -v ldapsearch >/dev/null 2>&1; then
        ml_log_error "ldapsearch command not found"
        return 1
    fi

    ml_log_step "Detecting LDAP directory type"

    if [ "${DRY_RUN:-false}" = "true" ]; then
        ml_log_info "DRY_RUN: Would detect directory type by querying root DSE of $ldap_uri"
        return 0
    fi

    # Build ldapsearch command to get root DSE
    local ldapsearch_cmd=(ldapsearch -x -H "$ldap_uri" -b "" -s base "objectClass=*")
    local password_file=""

    # Add authentication if provided
    if [ -n "$bind_dn" ] && [ -n "$bind_password" ]; then
        password_file=$(ldap_create_password_file "$bind_password") || {
            ml_log_error "Failed to create secure password file"
            return 1
        }
        ldapsearch_cmd+=(-D "$bind_dn" -y "$password_file")
    fi

    # Add StartTLS if requested
    if [ "$start_tls" = "true" ]; then
        ldapsearch_cmd+=(-Z)
    fi

    local root_dse
    root_dse=$("${ldapsearch_cmd[@]}" 2>/dev/null)
    [ -n "$password_file" ] && ldap_cleanup_password_file "$password_file"

    if echo "$root_dse" | grep -qi "microsoft"; then
        ml_log_info "Directory type: Microsoft Active Directory"
        ml_log_info "Recommended user attribute: sAMAccountName"
        ml_log_info "User DN template example: CN={user},CN=Users,DC=example,DC=com"
    elif echo "$root_dse" | grep -qi "openldap"; then
        ml_log_info "Directory type: OpenLDAP"
        ml_log_info "Recommended user attribute: uid"
        ml_log_info "User DN template example: uid={user},ou=people,dc=example,dc=com"
    elif echo "$root_dse" | grep -qi "389"; then
        ml_log_info "Directory type: 389 Directory Server"
        ml_log_info "Recommended user attribute: uid"
        ml_log_info "User DN template example: uid={user},ou=people,dc=example,dc=com"
    elif echo "$root_dse" | grep -qi "novell"; then
        ml_log_info "Directory type: Novell eDirectory"
        ml_log_info "Recommended user attribute: cn"
        ml_log_info "User DN template example: cn={user},ou=users,o=example"
    else
        ml_log_info "Directory type: Unknown or Generic LDAP"
        ml_log_info "Common user attributes: uid, cn, sAMAccountName"
        ml_log_info "Check your directory documentation for proper user DN format"
    fi

    # Show common object classes found
    echo
    ml_log_info "Common object classes found:"
    echo "$root_dse" | grep "objectClass:" | head -10 || true
}

# ================================================================
# TROUBLESHOOTING FUNCTIONS
# ================================================================

# Comprehensive LDAP troubleshooting
ldap_comprehensive_troubleshooting() {
    local ldap_uri="$1"
    local bind_dn="$2"
    local bind_password="$3"
    local ldap_base="$4"
    local start_tls="${5:-false}"

    ml_log_step "Comprehensive LDAP troubleshooting"

    echo "1. Checking LDAP client tools..."
    ldap_check_tools || true

    echo
    echo "2. Testing TCP connectivity..."
    ldap_test_tcp_connectivity "$ldap_uri" || true

    echo
    echo "3. Detecting directory type..."
    ldap_detect_directory_type "$ldap_uri" "$bind_dn" "$bind_password" "$ldap_base" "$start_tls" || true

    echo
    echo "4. Testing anonymous bind..."
    ldap_test_anonymous_bind "$ldap_uri" "$ldap_base" || true

    if [ -n "$bind_dn" ] && [ -n "$bind_password" ]; then
        echo
        echo "5. Testing authenticated bind..."
        ldap_test_authenticated_bind "$ldap_uri" "$bind_dn" "$bind_password" "$ldap_base" "$start_tls" || true

        if [ "$start_tls" = "true" ]; then
            echo
            echo "6. Testing StartTLS..."
            ldap_test_starttls "$ldap_uri" "$bind_dn" "$bind_password" "$ldap_base" || true
        fi
    fi

    echo
    ldap_show_troubleshooting_tips
}

# Show common LDAP troubleshooting tips
ldap_show_troubleshooting_tips() {
    cat << EOF

Common LDAP Troubleshooting Tips:
=================================

1. Connection Issues:
   - Check network connectivity to LDAP server
   - Verify correct hostname and port
   - Check firewall rules (ports 389/TCP, 636/TCP)
   - Test with telnet or nc: nc -z hostname port

2. Authentication Failures:
   - Verify bind DN format (case sensitive)
   - Check password correctness
   - Ensure account is not locked/disabled
   - Verify account has search permissions

3. StartTLS/SSL Issues:
   - Check LDAP server SSL certificate
   - Verify certificate authority is trusted
   - Use ldaps:// for SSL or ldap:// with StartTLS
   - Check certificate hostname matches

4. User Search Issues:
   - Verify user attribute name (uid vs sAMAccountName)
   - Check user DN template format
   - Ensure users exist in specified base DN
   - Test with broader search filters

5. MarkLogic Integration:
   - Verify external security configuration
   - Check app server authentication mode
   - Restart MarkLogic after configuration changes
   - Monitor MarkLogic error logs

Common LDAP Ports:
==================
   389/TCP  - LDAP (unencrypted)
   636/TCP  - LDAPS (SSL/TLS)
   3268/TCP - AD Global Catalog
   3269/TCP - AD Global Catalog SSL

Debug Commands:
===============
   ldapsearch -x -H ldap://server -b "base" "(objectClass=*)"
   ldapwhoami -x -H ldap://server -D "dn" -W
   openssl s_client -connect server:636 -showcerts

EOF
}

# ================================================================
# UTILITY EXPORT FUNCTIONS
# ================================================================

# Make functions available to other scripts
export -f ldap_check_tools
export -f ldap_parse_server_uri
export -f ldap_test_tcp_connectivity
export -f ldap_test_anonymous_bind
export -f ldap_test_authenticated_bind
export -f ldap_test_starttls
export -f ldap_search_user
export -f ldap_search_users_pattern
export -f ldap_get_user_groups
export -f ldap_test_user_auth
export -f ldap_test_user_whoami
export -f ldap_validate_marklogic_config
export -f ldap_test_user_attribute_search
export -f ldap_detect_directory_type
export -f ldap_comprehensive_troubleshooting
export -f ldap_show_troubleshooting_tips