#!/usr/bin/env bash
#
# setup-certbot-route53.sh
#
# Idempotent installer for Certbot + Route 53 DNS plugin + MarkLogic deploy hook
# on RHEL-family hosts (RHEL/Rocky/AlmaLinux 8+, Amazon Linux 2023+).
#
# After this setup:
#   1. Edit /etc/default/marklogic-cert-deploy with your MarkLogic connection and template name
#   2. Attach the reviewed Route 53 policy or instance role
#   3. Test with staging: certbot certonly --dns-route53 --test-cert --dry-run -d example.com \
#        --deploy-hook /usr/local/bin/marklogic-cert-deploy-wrapper.sh
#   4. Issue production certificate: same command without --test-cert --dry-run
#
# OPTIONS:
#   --package-manager auto|dnf|yum   Select package manager (default: auto = prefer dnf)
#   -v, --verbose                    Enable verbose output
#   -n, --dry-run                    Show plan without making changes
#   -h, --help                       Show this help message
#
# Exit codes: 0 = success, 1 = unsupported host or missing dependency

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PACKAGE_MANAGER="${PACKAGE_MANAGER:-auto}"
VERBOSE=false
DRY_RUN=false

log_info() { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
log_verbose() { [[ "$VERBOSE" == "true" ]] && echo -e "[DEBUG] $*" || true; }

usage() {
  cat << 'EOF'
Usage: setup-certbot-route53.sh [OPTIONS]

Installs Certbot with Route 53 DNS plugin and the MarkLogic certificate deploy hook
on RHEL-family systems (RHEL/Rocky/AlmaLinux 8+, Amazon Linux 2023+).

OPTIONS:
  --package-manager auto|dnf|yum   Package manager (default: auto)
                                   auto = prefer dnf, fall back to yum
  -v, --verbose                    Verbose output
  -n, --dry-run                    Show plan without changes
  -h, --help                       Show this help

Recovery:
  Package installation, Certbot issuance/revocation, AWS DNS changes, and service
  scheduling are not automatically reversible. Preserve host backups and perform
  provider-side recovery manually.

EXAMPLES:
  # Preview what would be installed (dnf preferred):
  sudo ./setup-certbot-route53.sh --dry-run

  # Install with explicit yum on a host that also has dnf:
  sudo ./setup-certbot-route53.sh --package-manager yum

  # Install with verbose logging:
  sudo ./setup-certbot-route53.sh --verbose

NEXT STEPS after installation:
  1. Edit /etc/default/marklogic-cert-deploy with MarkLogic connection details
  2. Attach the reviewed Route 53 IAM policy or instance role
  3. Test with Let's Encrypt staging: 
     certbot certonly --dns-route53 --test-cert --dry-run -d example.com \
       --deploy-hook /usr/local/bin/marklogic-cert-deploy-wrapper.sh
  4. Issue production certificate (same command without --test-cert --dry-run)

EOF
}

# ---- flag parsing (before requiring root or executables) ------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --package-manager) PACKAGE_MANAGER="$2"; shift 2 ;;
    -v|--verbose)      VERBOSE=true; shift ;;
    -n|--dry-run)      DRY_RUN=true; shift ;;
    -h|--help)         usage; exit 0 ;;
    *)
      log_error "Unknown argument (use --help)"
      exit 1 ;;
  esac
done

[[ "$DRY_RUN" == "true" ]] && log_warn "DRY RUN MODE - no changes will be made"

# ---- package manager detection (shell built-ins only) ----------------------
#
# This must complete without requiring root, Python, dirname, grep, or other
# executables, so the test suite can verify detection with temporary PATH shims.
#
DETECTED_PM=""
if [[ "$PACKAGE_MANAGER" == "auto" ]]; then
  if type -P dnf >/dev/null 2>&1; then
    DETECTED_PM="dnf"
  elif type -P yum >/dev/null 2>&1; then
    DETECTED_PM="yum"
  fi
elif [[ "$PACKAGE_MANAGER" == "dnf" ]] || [[ "$PACKAGE_MANAGER" == "yum" ]]; then
  if type -P "$PACKAGE_MANAGER" >/dev/null 2>&1; then
    DETECTED_PM="$PACKAGE_MANAGER"
  fi
else
  log_error "Invalid --package-manager: $PACKAGE_MANAGER (use auto|dnf|yum)"
  exit 1
fi

if [[ -z "$DETECTED_PM" ]]; then
  log_error "No supported package manager found (dnf or yum required for RHEL-family hosts)"
  exit 1
fi

log_info "Selected package manager: $DETECTED_PM"

if [[ "$DRY_RUN" == "true" ]]; then
  printf '\n'
  printf 'DRY RUN PLAN:\n'
  printf '  Package manager:     %s\n' "$DETECTED_PM"
  printf '  System packages:     python3 python3-pip python3-virtualenv jq curl cronie\n'
  printf '  Certbot install:     /opt/certbot (Python virtual environment)\n'
  printf '  Certbot symlink:     /usr/local/bin/certbot (if path is available)\n'
  printf '  Deploy hook:         /usr/local/bin/marklogic-cert-deploy.sh\n'
  printf '  Deploy wrapper:      /usr/local/bin/marklogic-cert-deploy-wrapper.sh\n'
  printf '  Protected config:    /etc/default/marklogic-cert-deploy (if absent)\n'
  printf '  Renewal schedule:    /etc/cron.d/certbot (if no timer/cron already active)\n'
  printf '  \n'
  printf 'This setup is idempotent: it preserves existing configurations and does not\n'
  printf 'create duplicate schedules. Run without --dry-run to proceed.\n'
  printf '\n'
  exit 0
fi

# ---- from here on, we need root and external commands ----------------------
if [[ $EUID -ne 0 ]]; then
  log_error "This script must be run as root (use sudo)"
  exit 1
fi

# ---- determine script directory --------------------------------------------
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# ---- install system packages -----------------------------------------------
log_info "Installing system dependencies via $DETECTED_PM..."

# Package names for python3 + venv/pip
case "$DETECTED_PM" in
  dnf)
    PYTHON_PACKAGES="python3 python3-pip python3-virtualenv"
    ;;
  yum)
    PYTHON_PACKAGES="python3 python3-pip python3-virtualenv"
    ;;
esac

REQUIRED_PACKAGES="$PYTHON_PACKAGES jq curl cronie"

# shellcheck disable=SC2086
if ! $DETECTED_PM install -y $REQUIRED_PACKAGES; then
  log_error "Failed to install required packages: $REQUIRED_PACKAGES"
  log_error "Manual recovery: verify $DETECTED_PM is configured correctly and the system is up to date."
  log_error "Supported platforms: RHEL/Rocky/AlmaLinux 8+, Amazon Linux 2023+"
  log_error "Check $DETECTED_PM output above for specific package errors."
  exit 1
fi

# ---- create certbot virtual environment ------------------------------------
log_info "Installing Certbot and certbot-dns-route53 into /opt/certbot..."

if [[ ! -d /opt/certbot ]]; then
  python3 -m venv /opt/certbot
fi

/opt/certbot/bin/pip install --upgrade pip setuptools wheel
/opt/certbot/bin/pip install certbot certbot-dns-route53

# ---- symlink certbot binary if safe ----------------------------------------
CERTBOT_BIN="/opt/certbot/bin/certbot"
CERTBOT_SYMLINK="/usr/local/bin/certbot"

if [[ -L "$CERTBOT_SYMLINK" ]]; then
  EXISTING_TARGET="$(readlink -f "$CERTBOT_SYMLINK")"
  if [[ "$EXISTING_TARGET" != "$CERTBOT_BIN" ]]; then
    log_warn "Symlink $CERTBOT_SYMLINK points to $EXISTING_TARGET, not our Certbot"
    log_warn "Skipping symlink creation to avoid overwriting unrelated binary"
    CERTBOT_CMD="$CERTBOT_BIN"
  else
    log_verbose "Symlink $CERTBOT_SYMLINK already points to $CERTBOT_BIN"
    CERTBOT_CMD="$CERTBOT_SYMLINK"
  fi
elif [[ -e "$CERTBOT_SYMLINK" ]]; then
  log_warn "File $CERTBOT_SYMLINK exists and is not a symlink, leaving it alone"
  CERTBOT_CMD="$CERTBOT_BIN"
else
  ln -s "$CERTBOT_BIN" "$CERTBOT_SYMLINK"
  log_verbose "Created symlink $CERTBOT_SYMLINK -> $CERTBOT_BIN"
  CERTBOT_CMD="$CERTBOT_SYMLINK"
fi

# ---- install deploy hook and wrapper ---------------------------------------
HOOK_SRC="$SCRIPT_DIR/marklogic-cert-deploy.sh"
WRAPPER_SRC="$SCRIPT_DIR/marklogic-cert-deploy-wrapper.sh"
CONFIG_EXAMPLE="$SCRIPT_DIR/marklogic-cert-deploy.env.example"

HOOK_DEST="/usr/local/bin/marklogic-cert-deploy.sh"
WRAPPER_DEST="/usr/local/bin/marklogic-cert-deploy-wrapper.sh"
CONFIG_DEST="/etc/default/marklogic-cert-deploy"

if [[ ! -f "$HOOK_SRC" ]]; then
  log_error "Deploy hook not found at $HOOK_SRC (are you in the scripts/TLS directory?)"
  exit 1
fi
if [[ ! -f "$WRAPPER_SRC" ]]; then
  log_error "Deploy wrapper not found at $WRAPPER_SRC"
  exit 1
fi

install_managed_file() {
  local source_file="$1" destination="$2"
  if [[ -e "$destination" || -L "$destination" ]]; then
    if [[ -f "$destination" && ! -L "$destination" ]] && cmp -s "$source_file" "$destination"; then
      log_info "Managed file already matches: $destination"
      return 0
    fi
    log_error "Refusing to overwrite existing file with different content: $destination"
    return 1
  fi
  install -m 0755 "$source_file" "$destination"
}

# Detect conflicts for both paths before installing either file.
for pair in "$HOOK_SRC:$HOOK_DEST" "$WRAPPER_SRC:$WRAPPER_DEST"; do
  source_file="${pair%%:*}"
  destination="${pair#*:}"
  if [[ -e "$destination" || -L "$destination" ]]; then
    [[ -f "$destination" && ! -L "$destination" ]] && cmp -s "$source_file" "$destination" || {
      log_error "Refusing partial install because a managed path conflicts: $destination"
      exit 1
    }
  fi
done

log_info "Installing deploy hook and wrapper..."
install_managed_file "$HOOK_SRC" "$HOOK_DEST" || exit 1
install_managed_file "$WRAPPER_SRC" "$WRAPPER_DEST" || exit 1

# ---- create protected config template if absent ----------------------------
if [[ -f "$CONFIG_DEST" ]]; then
  log_info "Protected config $CONFIG_DEST already exists, preserving it"
else
  log_info "Creating protected config template at $CONFIG_DEST"
  if [[ -f "$CONFIG_EXAMPLE" ]]; then
    install -m 0600 "$CONFIG_EXAMPLE" "$CONFIG_DEST"
  else
    # Fallback minimal template
    cat > "$CONFIG_DEST" <<'EOF_CONFIG'
# MarkLogic certificate deployment configuration
# This file is parsed by an allow-list; shell expressions are not evaluated

ML_HOST=localhost
ML_PORT=8002
ML_SCHEME=https
ML_USER=admin
ML_PASSWORD=

# Certificate template name or ID in MarkLogic
ML_CERT_TEMPLATE=

# Optional: path to CA bundle for verifying Management API TLS
# ML_CA_FILE=/path/to/ca-bundle.pem
EOF_CONFIG
  fi
  chmod 0600 "$CONFIG_DEST"
  chown root:root "$CONFIG_DEST"
  log_verbose "Created $CONFIG_DEST with mode 0600, owner root:root"
fi

# ---- renewal schedule: reuse existing or create cron entry -----------------
log_info "Configuring renewal schedule..."

TIMER_ACTIVE=false
CRON_ACTIVE=false

# Check for systemd timer
if command -v systemctl >/dev/null 2>&1; then
  if systemctl is-enabled certbot-renew.timer >/dev/null 2>&1 || \
     systemctl is-active certbot-renew.timer >/dev/null 2>&1 || \
     systemctl is-enabled certbot.timer >/dev/null 2>&1 || \
     systemctl is-active certbot.timer >/dev/null 2>&1; then
    TIMER_ACTIVE=true
    log_info "Found active Certbot systemd timer, no cron entry needed"
  fi
fi

# Check for existing cron entry
if [[ "$TIMER_ACTIVE" == "false" && ( -e /etc/cron.d/certbot || -L /etc/cron.d/certbot ) ]]; then
  if [[ -f /etc/cron.d/certbot && ! -L /etc/cron.d/certbot ]] && grep -q certbot /etc/cron.d/certbot 2>/dev/null; then
    CRON_ACTIVE=true
    log_info "Found existing Certbot cron entry, no changes needed"
  else
    log_error "Refusing to overwrite an existing /etc/cron.d/certbot file"
    exit 1
  fi
fi

# Create cron entry if neither timer nor cron is present
if [[ "$TIMER_ACTIVE" == "false" && "$CRON_ACTIVE" == "false" ]]; then
  log_info "No active renewal schedule found, creating /etc/cron.d/certbot"
  cat > /etc/cron.d/certbot <<EOF_CRON
# Certbot renewal - runs daily
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

0 3 * * * root $CERTBOT_CMD renew --quiet
EOF_CRON
  chmod 0644 /etc/cron.d/certbot
  log_verbose "Created /etc/cron.d/certbot (daily at 3am)"
  
  # Enable and start crond if not running
  if command -v systemctl >/dev/null 2>&1; then
    systemctl enable crond 2>/dev/null || true
    systemctl start crond 2>/dev/null || systemctl restart crond 2>/dev/null || true
  fi
fi

# ---- installation complete -------------------------------------------------
log_info "Setup complete"
cat <<EOF_NEXT_STEPS

${GREEN}Next steps:${NC}

1. Edit the protected configuration file with your MarkLogic details:
   ${YELLOW}sudo vim $CONFIG_DEST${NC}
   
   Set ML_HOST, ML_PORT, ML_USER, ML_PASSWORD, and ML_CERT_TEMPLATE.
   This file is mode 0600, owned by root, and never logged.

2. Attach the reviewed Route 53 IAM policy to this instance role, or configure
   AWS credentials with route53:ChangeResourceRecordSets permission.
   
   Example policy: $SCRIPT_DIR/route53-certbot-policy.json.example

3. Test with Let's Encrypt staging on a disposable MarkLogic template:
   ${YELLOW}WARNING: This issues a real staging certificate and invokes the deploy hook,${NC}
   ${YELLOW}which will replace the certificate in ML_CERT_TEMPLATE. Use a test template.${NC}
   
   ${YELLOW}sudo $CERTBOT_CMD certonly --dns-route53 --test-cert \\
     -d your-domain.com \\
     --deploy-hook $WRAPPER_DEST${NC}

4. When staging test succeeds, update ML_CERT_TEMPLATE to your production template
   and issue a production certificate:
   ${YELLOW}sudo $CERTBOT_CMD certonly --dns-route53 \\
     -d your-domain.com \\
     --deploy-hook $WRAPPER_DEST${NC}

5. Renewal runs automatically via $(if [[ "$TIMER_ACTIVE" == "true" ]]; then echo "systemd timer"; elif [[ "$CRON_ACTIVE" == "true" ]]; then echo "existing cron"; else echo "cron (daily at 3am)"; fi).
   The deploy hook updates MarkLogic on each renewal.

EOF_NEXT_STEPS
