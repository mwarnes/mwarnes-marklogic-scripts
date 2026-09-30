#!/bin/bash

# ================================================================
# Kerberos Utilities for MarkLogic Authentication
# ================================================================
#
# Common utility functions for Kerberos authentication management
# in MarkLogic environments. These functions provide Kerberos
# configuration validation, ticket management, and troubleshooting
# utilities.
#
# Author: Martin Warnes
# Version: 1.0.1
# Date: November 2025
#
# ================================================================

# Source common utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../marklogic-utils.sh"

# ================================================================
# KERBEROS ENVIRONMENT VALIDATION
# ================================================================

# Check if Kerberos client tools are available
kerberos_check_tools() {
    ml_log_step "Checking Kerberos client tools availability"
    
    local tools_available=true
    
    # Check for essential tools
    if command -v kinit >/dev/null 2>&1; then
        ml_log_success "kinit: Available"
    else
        ml_log_error "kinit: Not found"
        tools_available=false
    fi
    
    if command -v klist >/dev/null 2>&1; then
        ml_log_success "klist: Available"
    else
        ml_log_error "klist: Not found"
        tools_available=false
    fi
    
    if command -v kdestroy >/dev/null 2>&1; then
        ml_log_success "kdestroy: Available"
    else
        ml_log_warning "kdestroy: Not found (optional)"
    fi
    
    # Check for optional tools
    if command -v kvno >/dev/null 2>&1; then
        ml_log_success "kvno: Available"
    else
        ml_log_info "kvno: Not found (optional, used for service ticket testing)"
    fi
    
    if command -v kadmin >/dev/null 2>&1; then
        ml_log_success "kadmin: Available"
    else
        ml_log_info "kadmin: Not found (required for principal management)"
    fi
    
    # Check for Windows-specific tools
    if command -v setspn >/dev/null 2>&1; then
        ml_log_success "setspn: Available (Windows AD tools)"
    elif command -v ktpass >/dev/null 2>&1; then
        ml_log_success "ktpass: Available (Windows AD tools)"
    fi
    
    if [ "$tools_available" = "true" ]; then
        ml_log_success "Essential Kerberos tools are available"
        return 0
    else
        ml_log_error "Missing essential Kerberos tools"
        ml_log_error "Install Kerberos client package:"
        ml_log_error "  Ubuntu/Debian: sudo apt-get install krb5-user"
        ml_log_error "  CentOS/RHEL: sudo yum install krb5-workstation"
        ml_log_error "  macOS: brew install krb5"
        return 1
    fi
}

# Validate Kerberos configuration file
kerberos_validate_config() {
    local krb5_conf="${1:-/etc/krb5.conf}"
    
    ml_log_step "Validating Kerberos configuration: $krb5_conf"
    
    if [ ! -f "$krb5_conf" ]; then
        ml_log_error "Kerberos configuration file not found: $krb5_conf"
        ml_log_error "Create a basic krb5.conf file with realm and KDC information"
        return 1
    fi
    
    # Check for basic sections
    if grep -q "^\[libdefaults\]" "$krb5_conf"; then
        ml_log_success "libdefaults section found"
    else
        ml_log_warning "libdefaults section not found"
    fi
    
    if grep -q "^\[realms\]" "$krb5_conf"; then
        ml_log_success "realms section found"
    else
        ml_log_error "realms section not found"
        return 1
    fi
    
    if grep -q "^\[domain_realm\]" "$krb5_conf"; then
        ml_log_success "domain_realm section found"
    else
        ml_log_info "domain_realm section not found (optional)"
    fi
    
    # Extract default realm
    local default_realm
    default_realm=$(grep -A 10 "^\[libdefaults\]" "$krb5_conf" | grep "default_realm" | cut -d'=' -f2 | xargs)
    
    if [ -n "$default_realm" ]; then
        ml_log_success "Default realm: $default_realm"
        
        # Check if realm is defined
        if grep -q "^[[:space:]]*${default_realm}[[:space:]]*=" "$krb5_conf"; then
            ml_log_success "Realm $default_realm is configured"
        else
            ml_log_error "Realm $default_realm is not defined in [realms] section"
            return 1
        fi
    else
        ml_log_warning "No default realm specified"
    fi
    
    return 0
}

# Test KDC connectivity
kerberos_test_kdc_connectivity() {
    local kdc_host="$1"
    local kdc_port="${2:-88}"
    
    if [ "${DRY_RUN:-false}" = "true" ]; then
        ml_log_info "DRY_RUN: Would test KDC connectivity to $kdc_host:$kdc_port"
        return 0
    fi

    ml_log_step "Testing KDC connectivity: $kdc_host:$kdc_port"
    
    # Test TCP connectivity
    if command -v nc >/dev/null 2>&1; then
        if nc -z "$kdc_host" "$kdc_port" 2>/dev/null; then
            ml_log_success "TCP connection to KDC successful"
        else
            ml_log_error "Cannot connect to KDC on TCP port $kdc_port"
            return 1
        fi
    else
        ml_log_warning "nc (netcat) not found. Cannot test KDC connectivity."
    fi
    
    # Test UDP connectivity (Kerberos uses UDP by default)
    if command -v nc >/dev/null 2>&1; then
        # Note: nc UDP test is unreliable, but we'll try anyway
        ml_log_info "KDC typically uses UDP port $kdc_port for authentication"
    fi
    
    return 0
}

# ================================================================
# TICKET MANAGEMENT FUNCTIONS
# ================================================================

# ponytail: use a private FILE cache; adapt only if a supported Kerberos library requires another cache type.
# Run ticket tests in a subshell so the caller's KRB5CCNAME is unchanged.
kerberos_run_with_private_cache() (
    if [ "${DRY_RUN:-false}" = "true" ]; then
        ml_log_info "DRY_RUN: Would run a Kerberos test in a private cache"
        return 0
    fi
    local cache_dir
    cache_dir=$(mktemp -d) || return 1
    chmod 700 "$cache_dir" || { rm -rf "$cache_dir"; return 1; }
    local _kerberos_private_cache_dir="$cache_dir"
    export -n _kerberos_private_cache_dir 2>/dev/null || true
    export KRB5CCNAME="FILE:$cache_dir/ccache"
    _kerberos_private_cache_cleanup() {
        local status=$?
        trap - EXIT
        if command -v kdestroy >/dev/null 2>&1; then
            kdestroy >/dev/null 2>&1 || true
        fi
        rm -rf "$cache_dir"
        exit "$status"
    }
    trap _kerberos_private_cache_cleanup EXIT
    "$@"
)

kerberos_private_cache_active() {
    [ -n "${_kerberos_private_cache_dir:-}" ] &&
        [ "${KRB5CCNAME:-}" = "FILE:${_kerberos_private_cache_dir}/ccache" ] &&
        [ -d "$_kerberos_private_cache_dir" ]
}

# Get current Kerberos tickets
kerberos_get_current_tickets() {
    if [ "${DRY_RUN:-false}" = "true" ]; then
        ml_log_info "DRY_RUN: Would check current Kerberos tickets"
        return 0
    fi

    ml_log_step "Checking current Kerberos tickets"
    
    if ! command -v klist >/dev/null 2>&1; then
        ml_log_error "klist command not found"
        return 1
    fi
    
    if klist 2>/dev/null; then
        ml_log_success "Current Kerberos tickets listed above"
        return 0
    else
        ml_log_info "No current Kerberos tickets found"
        return 1
    fi
}

# Check if valid tickets exist for principal
kerberos_check_valid_ticket() {
    local principal="$1"

    if [ "${DRY_RUN:-false}" = "true" ]; then
        ml_log_info "DRY_RUN: Would check for a ticket for '$principal'"
        return 0
    fi

    if ! command -v klist >/dev/null 2>&1; then
        ml_log_error "klist command not found"
        return 1
    fi
    
    local tickets
    tickets=$(klist 2>/dev/null)
    
    if echo "$tickets" | grep -q "krbtgt.*$principal"; then
        ml_log_success "Valid ticket found for principal: $principal"
        return 0
    else
        ml_log_info "No valid ticket found for principal: $principal"
        return 1
    fi
}

# Acquire Kerberos ticket
kerberos_acquire_ticket() {
    local principal="$1"
    local password="$2"
    local keytab="$3"

    if [ "${DRY_RUN:-false}" = "true" ]; then
        ml_log_info "DRY_RUN: Would acquire a test ticket for '$principal'"
        return 0
    fi
    if ! kerberos_private_cache_active; then
        kerberos_run_with_private_cache kerberos_acquire_ticket "$principal" "$password" "$keytab"
        return $?
    fi

    if ! command -v kinit >/dev/null 2>&1; then
        ml_log_error "kinit command not found"
        return 1
    fi
    
    ml_log_step "Acquiring Kerberos ticket for: $principal"
    
    if [ -n "$keytab" ]; then
        # Use keytab file
        if [ ! -f "$keytab" ]; then
            ml_log_error "Keytab file not found: $keytab"
            return 1
        fi
        
        if kinit -kt "$keytab" "$principal"; then
            ml_log_success "Ticket acquired using keytab"
        else
            ml_log_error "Failed to acquire ticket using keytab"
            return 1
        fi
    elif [ -n "$password" ]; then
        # Use password
        if printf '%s\n' "$password" | kinit "$principal"; then
            ml_log_success "Ticket acquired using password"
        else
            ml_log_error "Failed to acquire ticket using password"
            return 1
        fi
    else
        # Prompt for password
        if kinit "$principal"; then
            ml_log_success "Ticket acquired successfully"
        else
            ml_log_error "Failed to acquire ticket"
            return 1
        fi
    fi
    
    # Verify ticket acquisition
    if command -v klist >/dev/null 2>&1; then
        echo
        ml_log_info "Acquired tickets:"
        klist
    fi
    
    return 0
}

# Destroy Kerberos tickets
kerberos_destroy_tickets() {
    if [ "${DRY_RUN:-false}" = "true" ]; then
        ml_log_info "DRY_RUN: Would destroy tickets in the private test cache"
        return 0
    fi
    if ! kerberos_private_cache_active; then
        ml_log_error "Refusing to destroy tickets outside a private test cache"
        return 1
    fi

    ml_log_step "Destroying Kerberos tickets"
    
    if ! command -v kdestroy >/dev/null 2>&1; then
        ml_log_error "kdestroy command not found"
        return 1
    fi
    
    if kdestroy; then
        ml_log_success "All Kerberos tickets destroyed"
        return 0
    else
        ml_log_error "Failed to destroy Kerberos tickets"
        return 1
    fi
}

# ================================================================
# KEYTAB MANAGEMENT FUNCTIONS
# ================================================================

# List principals in keytab
kerberos_list_keytab_principals() {
    local keytab="$1"

    if [ "${DRY_RUN:-false}" = "true" ]; then
        ml_log_info "DRY_RUN: Would list principals in the selected keytab"
        return 0
    fi
    if [ ! -f "$keytab" ]; then
        ml_log_error "Keytab file not found: $keytab"
        return 1
    fi
    
    if ! command -v klist >/dev/null 2>&1; then
        ml_log_error "klist command not found"
        return 1
    fi
    
    ml_log_step "Listing principals in keytab: $keytab"
    
    if klist -kt "$keytab"; then
        ml_log_success "Keytab principals listed above"
        return 0
    else
        ml_log_error "Failed to list keytab principals"
        return 1
    fi
}

# Test keytab authentication
kerberos_test_keytab_auth() {
    local keytab="$1"
    local principal="$2"

    if [ "${DRY_RUN:-false}" = "true" ]; then
        ml_log_info "DRY_RUN: Would test keytab authentication for '$principal'"
        return 0
    fi
    if ! kerberos_private_cache_active; then
        kerberos_run_with_private_cache kerberos_test_keytab_auth "$keytab" "$principal"
        return $?
    fi

    if [ ! -f "$keytab" ]; then
        ml_log_error "Keytab file not found: $keytab"
        return 1
    fi
    
    # If no principal specified, use the first one from keytab
    if [ -z "$principal" ]; then
        if command -v klist >/dev/null 2>&1; then
            principal=$(klist -kt "$keytab" 2>/dev/null | grep -v "^Keytab name\|^KVNO\|^----" | head -1 | awk '{print $2}')
            if [ -z "$principal" ]; then
                ml_log_error "No principals found in keytab"
                return 1
            fi
            ml_log_info "Using first principal from keytab: $principal"
        else
            ml_log_error "klist command not found and no principal specified"
            return 1
        fi
    fi
    
    ml_log_step "Testing keytab authentication for: $principal"

    # The enclosing private-cache subshell owns and cleans this test cache.
    # Try to acquire ticket using keytab
    if kerberos_acquire_ticket "$principal" "" "$keytab"; then
        ml_log_success "Keytab authentication test successful"
        return 0
    else
        ml_log_error "Keytab authentication test failed"
        return 1
    fi
}

# Validate keytab file permissions
kerberos_validate_keytab_permissions() {
    local keytab="$1"
    
    if [ ! -f "$keytab" ]; then
        ml_log_error "Keytab file not found: $keytab"
        return 1
    fi
    
    ml_log_step "Validating keytab permissions: $keytab"
    
    # Check file ownership and permissions
    local file_owner file_group file_perms
    
    if command -v stat >/dev/null 2>&1; then
        if stat -c "%U %G %a" "$keytab" >/dev/null 2>&1; then
            # Linux stat
            file_owner=$(stat -c "%U" "$keytab")
            file_group=$(stat -c "%G" "$keytab")
            file_perms=$(stat -c "%a" "$keytab")
        else
            # macOS stat
            file_owner=$(stat -f "%Su" "$keytab")
            file_group=$(stat -f "%Sg" "$keytab")
            file_perms=$(stat -f "%A" "$keytab")
        fi
        
        ml_log_info "Owner: $file_owner"
        ml_log_info "Group: $file_group"
        ml_log_info "Permissions: $file_perms"
        
        # Check if readable by others
        if [ "${file_perms: -1}" != "0" ] && [ "${file_perms: -1}" != "4" ]; then
            ml_log_warning "Keytab is readable by others. Consider changing to 640 or 600."
            ml_log_warning "Command: chmod 640 $keytab"
        else
            ml_log_success "Keytab permissions are secure"
        fi
        
        # Check if writable by group or others
        local group_perms="${file_perms: -2:1}"
        if [ "$group_perms" -ge 2 ]; then
            ml_log_warning "Keytab is writable by group"
        fi
        
        return 0
    else
        ml_log_warning "stat command not found. Cannot check file permissions."
        return 1
    fi
}

# ================================================================
# SERVICE TESTING FUNCTIONS
# ================================================================

# Test service ticket acquisition
kerberos_test_service_ticket() {
    local service_principal="$1"
    
    if [ -z "$service_principal" ]; then
        ml_log_error "Service principal is required"
        return 1
    fi
    
    if ! command -v kvno >/dev/null 2>&1; then
        ml_log_error "kvno command not found"
        return 1
    fi
    
    if [ "${DRY_RUN:-false}" = "true" ]; then
        ml_log_info "DRY_RUN: Would acquire service ticket '$service_principal' in a private cache"
        return 0
    fi
    if ! kerberos_private_cache_active; then
        ml_log_error "Service-ticket tests require a private cache with a test TGT; caller caches are never used"
        return 1
    fi

    ml_log_step "Testing service ticket acquisition for: $service_principal"
    
    if kvno "$service_principal"; then
        ml_log_success "Service ticket acquired successfully"
        
        # Show the service ticket
        if command -v klist >/dev/null 2>&1; then
            echo
            ml_log_info "Current tickets (including service ticket):"
            klist
        fi
        
        return 0
    else
        ml_log_error "Failed to acquire service ticket"
        ml_log_error "Possible issues:"
        ml_log_error "  1. Service principal does not exist"
        ml_log_error "  2. No valid user ticket (TGT) available"
        ml_log_error "  3. Clock skew between client and KDC"
        ml_log_error "  4. Network connectivity issues"
        return 1
    fi
}

# Test HTTP negotiate authentication
kerberos_test_http_negotiate() {
    local url="$1"
    local service_principal="$2"
    
    if [ -z "$url" ]; then
        ml_log_error "URL is required"
        return 1
    fi
    
    if [ "${DRY_RUN:-false}" = "true" ]; then
        ml_log_info "DRY_RUN: Would test HTTP negotiate authentication at the supplied URL"
        return 0
    fi
    if ! kerberos_private_cache_active; then
        ml_log_error "HTTP negotiate tests require a private cache with a test TGT; caller caches are never used"
        return 1
    fi

    ml_log_step "Testing HTTP negotiate authentication: $url"
    
    # First acquire service ticket if specified
    if [ -n "$service_principal" ]; then
        if ! kerberos_test_service_ticket "$service_principal"; then
            ml_log_warning "Service ticket acquisition failed, but continuing with HTTP test"
        fi
    fi
    
    # Test with curl if available
    if command -v curl >/dev/null 2>&1; then
        ml_log_info "Testing with curl (negotiate authentication)..."
        
        local curl_output
        if curl_output=$(curl -s -f --negotiate -u : "$url" 2>&1); then
            ml_log_success "HTTP negotiate authentication successful"
            echo "Response preview (first 200 characters):"
            echo "$curl_output" | head -c 200
            [ ${#curl_output} -gt 200 ] && echo "..."
        else
            ml_log_error "HTTP negotiate authentication failed"
            ml_log_error "curl output: $curl_output"
            return 1
        fi
    else
        ml_log_warning "curl not found. Manual test required."
        ml_log_info "Test manually by accessing: $url"
        ml_log_info "Ensure browser supports Kerberos authentication"
    fi
    
    return 0
}

# ================================================================
# TROUBLESHOOTING FUNCTIONS
# ================================================================

# Comprehensive Kerberos environment check
kerberos_environment_check() {
    local realm="$1"
    local kdc_host="$2"
    
    ml_log_step "Comprehensive Kerberos environment check"
    
    local check_passed=true
    
    echo "1. Checking Kerberos client tools..."
    if ! kerberos_check_tools; then
        check_passed=false
    fi
    
    echo
    echo "2. Validating Kerberos configuration..."
    if ! kerberos_validate_config; then
        check_passed=false
    fi
    
    if [ -n "$kdc_host" ]; then
        echo
        echo "3. Testing KDC connectivity..."
        if ! kerberos_test_kdc_connectivity "$kdc_host"; then
            check_passed=false
        fi
    fi
    
    echo
    echo "4. Checking current tickets..."
    kerberos_get_current_tickets || true
    
    echo
    echo "5. Checking system clock..."
    kerberos_check_clock_skew "$kdc_host"
    
    if [ "$check_passed" = "true" ]; then
        echo
        ml_log_success "Kerberos environment check passed"
        return 0
    else
        echo
        ml_log_error "Kerberos environment check failed"
        return 1
    fi
}

# Check for clock skew issues
kerberos_check_clock_skew() {
    local kdc_host="$1"
    
    ml_log_info "Checking system clock synchronization..."
    
    # Show current system time
    ml_log_info "Current system time: $(date)"
    
    if [ -n "$kdc_host" ]; then
        if command -v ntpdate >/dev/null 2>&1; then
            ml_log_info "Use 'ntpdate -q $kdc_host' to check time difference with KDC"
        elif command -v chrony >/dev/null 2>&1; then
            ml_log_info "Use 'chronyc sources' to check time synchronization"
        else
            ml_log_warning "No time synchronization tools found"
            ml_log_warning "Ensure system clock is synchronized with KDC"
            ml_log_warning "Clock skew > 5 minutes will cause authentication failures"
        fi
    fi
}

# Common Kerberos troubleshooting tips
kerberos_show_troubleshooting_tips() {
    cat << EOF

Common Kerberos Troubleshooting Tips:
====================================

1. Authentication Failures:
   - Check clock synchronization (max 5 minute skew)
   - Verify realm and principal names (case sensitive)
   - Ensure keytab has correct principals and encryption types
   - Check network connectivity to KDC

2. Service Ticket Issues:
   - Verify service principal exists in KDC
   - Check SPN registration (setspn for Windows)
   - Ensure keytab contains service principal
   - Validate DNS resolution for service hostname

3. MarkLogic Integration:
   - Verify external security configuration
   - Check app server authentication mode
   - Ensure MarkLogic can read keytab file
   - Restart MarkLogic after configuration changes

4. Network Issues:
   - KDC ports: 88 (Kerberos), 464 (kadmin), 749 (kadmin)
   - Check firewall rules
   - Verify DNS resolution for realm and hostnames

5. Configuration Files:
   - /etc/krb5.conf (client configuration)
   - Check default realm and KDC settings
   - Verify domain_realm mappings

Debug Commands:
===============
   klist -v                    # Show ticket details
   kinit -V principal          # Verbose ticket acquisition
   kvno -S service host        # Test service tickets
   kadmin -p admin@REALM       # Principal management

EOF
}

# ================================================================
# UTILITY EXPORT FUNCTIONS
# ================================================================

# Make functions available to other scripts
export -f kerberos_check_tools
export -f kerberos_validate_config
export -f kerberos_test_kdc_connectivity
export -f kerberos_get_current_tickets
export -f kerberos_check_valid_ticket
export -f kerberos_acquire_ticket
export -f kerberos_destroy_tickets
export -f kerberos_list_keytab_principals
export -f kerberos_test_keytab_auth
export -f kerberos_validate_keytab_permissions
export -f kerberos_test_service_ticket
export -f kerberos_test_http_negotiate
export -f kerberos_environment_check
export -f kerberos_check_clock_skew
export -f kerberos_show_troubleshooting_tips