#!/bin/bash

# ================================================================
# Example: Complete MarkLogic Environment Setup Demo
# ================================================================
#
# This example demonstrates the complete workflow for setting up
# a MarkLogic test environment with TLS certificates and security
#
# ================================================================

set -e

# Navigate to the TLS scripts directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "==================================================================="
echo "MarkLogic Complete Environment Setup Demo"
echo "==================================================================="
echo

# Example 1: Basic setup with defaults
echo "Example 1: Basic Setup with Defaults"
echo "====================================="
echo

echo "Command:"
echo "./setup-complete-marklogic-environment.sh --dry-run"
echo

./setup-complete-marklogic-environment.sh --dry-run

echo
echo "-------------------------------------------------------------------"
echo

# Example 2: Custom configuration
echo "Example 2: Custom Host and Port Configuration"
echo "============================================="
echo

echo "Command:"
echo "./setup-complete-marklogic-environment.sh \\"
echo "  --host marklogic.example.com \\"
echo "  --port 10050 \\"
echo "  --name 'Test-AppServer-CustomDemo' \\"
echo "  --dry-run"
echo

./setup-complete-marklogic-environment.sh \
  --host marklogic.example.com \
  --port 10050 \
  --name "Test-AppServer-CustomDemo" \
  --dry-run

echo
echo "-------------------------------------------------------------------"
echo

# Example 3: Show help
echo "Example 3: Help Documentation"
echo "============================="
echo

./setup-complete-marklogic-environment.sh --help

echo
echo "==================================================================="
echo "Demo Complete!"
echo "==================================================================="
echo
echo "To run the actual setup (not dry-run), use one of these commands:"
echo
echo "# Basic setup:"
echo "./setup-complete-marklogic-environment.sh"
echo
echo "# Custom setup:"
echo "./setup-complete-marklogic-environment.sh \\"
echo "  --host your-marklogic-host \\"
echo "  --admin-user your-admin-user \\"
echo "  --admin-pass your-admin-password"
echo
echo "# Specific port and name:"
echo "./setup-complete-marklogic-environment.sh \\"
echo "  --port 10075 \\"
echo "  --name 'MyTest-AppServer-2025'"
echo