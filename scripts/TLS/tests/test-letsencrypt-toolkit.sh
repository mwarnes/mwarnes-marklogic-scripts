#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
HOOK="$SCRIPT_DIR/marklogic-cert-deploy.sh"
TMP_DIR="$(mktemp -d)"
# Isolate from the caller's environment and from /var/lib (tests must run unprivileged).
unset ML_HOST ML_PORT ML_SCHEME ML_USER ML_PASSWORD ML_CERT_TEMPLATE ML_CA_FILE ML_INSECURE RENEWED_LINEAGE
export ML_BACKUP_DIR="$TMP_DIR/backups"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "==> Testing basic validation and help"
HELP_OUTPUT="$("$HOOK" --help)"
if ! grep -q 'ML_CERT_TEMPLATE' <<<"$HELP_OUTPUT"; then
  echo "Help text missing ML_CERT_TEMPLATE" >&2
  exit 1
fi

if "$HOOK" --cert-dir "$TMP_DIR" >"$TMP_DIR/missing-config.out" 2>&1; then
  echo "Expected missing template configuration to fail" >&2
  exit 1
fi
grep -q 'ML_CERT_TEMPLATE' "$TMP_DIR/missing-config.out"

if env -u RENEWED_LINEAGE ML_CERT_TEMPLATE=Smoke "$HOOK" >"$TMP_DIR/missing-lineage.out" 2>&1; then
  echo "Expected missing RENEWED_LINEAGE to fail" >&2
  exit 1
fi
grep -q 'certificate directory' "$TMP_DIR/missing-lineage.out"

if "$HOOK" --password=canary-secret >"$TMP_DIR/secret-flag.out" 2>&1; then
  echo "Expected a secret-bearing command-line option to be rejected" >&2
  exit 1
fi
if grep -q 'canary-secret' "$TMP_DIR/secret-flag.out"; then
  echo "A rejected secret-bearing argument was echoed" >&2
  exit 1
fi

echo "==> Generating test certificate and key"
mkdir -p "$TMP_DIR/certs"
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$TMP_DIR/certs/privkey.pem" \
  -out "$TMP_DIR/certs/cert.pem" \
  -days 1 -subj "/CN=test.local" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth" 2>/dev/null

echo "==> Testing missing certificate/key detection"
mv "$TMP_DIR/certs/cert.pem" "$TMP_DIR/certs/cert.pem.bak"
if ML_CERT_TEMPLATE=Smoke ML_PASSWORD=test "$HOOK" --cert-dir "$TMP_DIR/certs" >"$TMP_DIR/missing-cert.out" 2>&1; then
  echo "Expected missing certificate to fail" >&2
  exit 1
fi
grep -qi 'certificate.*not readable' "$TMP_DIR/missing-cert.out"
mv "$TMP_DIR/certs/cert.pem.bak" "$TMP_DIR/certs/cert.pem"

mv "$TMP_DIR/certs/privkey.pem" "$TMP_DIR/certs/privkey.pem.bak"
if ML_CERT_TEMPLATE=Smoke ML_PASSWORD=test "$HOOK" --cert-dir "$TMP_DIR/certs" >"$TMP_DIR/missing-key.out" 2>&1; then
  echo "Expected missing key to fail" >&2
  exit 1
fi
grep -qi 'private key.*not readable' "$TMP_DIR/missing-key.out"
mv "$TMP_DIR/certs/privkey.pem.bak" "$TMP_DIR/certs/privkey.pem"

echo "==> Testing with mock curl"
mkdir -p "$TMP_DIR/mock-bin" "$TMP_DIR/test-tmpdir"
cat >"$TMP_DIR/mock-bin/curl" <<'CURL_MOCK'
#!/usr/bin/env bash
set -euo pipefail
output_file=""
data_binary_file=""
for arg in "$@"; do
  [[ "$arg" == *canary-secret* ]] && printf 'leaked\n' >"$MOCK_ARG_LEAK"
  if [[ "$arg" =~ PRIVATE\ KEY|BEGIN\ RSA|BEGIN\ EC|BEGIN\ PRIVATE ]]; then
    printf 'private-key-in-argv\n' >"$MOCK_PKEY_LEAK"
  fi
done
method="POST"
while (($#)); do
  case "$1" in
    -X) method="$2"; shift 2 ;;
    -o) output_file="$2"; shift 2 ;;
    --data-binary) data_binary_file="$2"; shift 2 ;;
    *) shift ;;
  esac
done
if [[ -n "$data_binary_file" && "$data_binary_file" == @* ]]; then
  file_path="${data_binary_file#@}"
  if [[ -f "$file_path" ]]; then
    if command -v jq >/dev/null 2>&1; then
      if ! jq -e '.operation == "insert-host-certificates" and .certificates[0].certificate.cert and .certificates[0].certificate.pkey' "$file_path" >/dev/null 2>&1; then
        printf 'invalid-payload-structure\n' >"$MOCK_PAYLOAD_INVALID"
      fi
    fi
    printf '%s' "$file_path" >"$MOCK_PAYLOAD_FILE_PATH"
  fi
fi
printf '{"mock":"response"}\n' >"$output_file"
# The hook first GETs the template for its protected backup (expects 200), then POSTs.
if [[ "$method" == "GET" ]]; then printf '200'; exit 0; fi
printf '%s' "${MOCK_HTTP_CODE:-204}"
exit "${MOCK_CURL_EXIT:-0}"
CURL_MOCK
chmod +x "$TMP_DIR/mock-bin/curl"

export PATH="$TMP_DIR/mock-bin:$PATH"
export TMPDIR="$TMP_DIR/test-tmpdir"
export MOCK_ARG_LEAK="$TMP_DIR/arg-leak"
export MOCK_PKEY_LEAK="$TMP_DIR/pkey-leak"
export MOCK_PAYLOAD_INVALID="$TMP_DIR/payload-invalid"
export MOCK_PAYLOAD_FILE_PATH="$TMP_DIR/payload-file-path"

echo "==> Testing successful API call (HTTP 204)"
export MOCK_HTTP_CODE=204
if ! ML_CERT_TEMPLATE=Smoke ML_PASSWORD=canary-secret "$HOOK" --cert-dir "$TMP_DIR/certs" >"$TMP_DIR/success.out" 2>&1; then
  echo "Expected HTTP 204 to succeed" >&2
  cat "$TMP_DIR/success.out" >&2
  exit 1
fi
grep -q 'Success' "$TMP_DIR/success.out"
if [[ -f "$MOCK_ARG_LEAK" ]]; then
  echo "Password leaked to curl argv" >&2
  exit 1
fi
if grep -q 'canary-secret' "$TMP_DIR/success.out"; then
  echo "Password appeared in output" >&2
  exit 1
fi
if [[ -f "$MOCK_PKEY_LEAK" ]]; then
  echo "Private key leaked to curl argv" >&2
  exit 1
fi
if ! [[ -f "$MOCK_PAYLOAD_FILE_PATH" ]]; then
  echo "Payload file path not captured by mock curl" >&2
  exit 1
fi
PAYLOAD_PATH="$(cat "$MOCK_PAYLOAD_FILE_PATH")"
if ! [[ "$PAYLOAD_PATH" =~ ^/ ]]; then
  echo "Payload file path should be absolute, got: $PAYLOAD_PATH" >&2
  exit 1
fi
if [[ -f "$MOCK_PAYLOAD_INVALID" ]]; then
  echo "Payload JSON structure validation failed" >&2
  exit 1
fi
if [[ -n "$(ls "$TMP_DIR/test-tmpdir" 2>/dev/null || true)" ]]; then
  echo "Temporary files not cleaned up" >&2
  ls -la "$TMP_DIR/test-tmpdir" >&2
  exit 1
fi

echo "==> Testing failed API call (HTTP 401)"
export MOCK_HTTP_CODE=401
if ML_CERT_TEMPLATE=Smoke ML_PASSWORD=test "$HOOK" --cert-dir "$TMP_DIR/certs" >"$TMP_DIR/auth-fail.out" 2>&1; then
  echo "Expected HTTP 401 to fail" >&2
  exit 1
fi
grep -q 'failed.*401' "$TMP_DIR/auth-fail.out"

echo "==> Testing network error (curl exit 7)"
export MOCK_HTTP_CODE=000
export MOCK_CURL_EXIT=7
STATUS=0
ML_CERT_TEMPLATE=Smoke ML_PASSWORD=test "$HOOK" --cert-dir "$TMP_DIR/certs" >"$TMP_DIR/network-fail.out" 2>&1 || STATUS=$?
if [[ $STATUS -eq 0 ]]; then
  echo "Expected curl exit 7 to fail" >&2
  exit 1
fi
if [[ $STATUS -ne 7 ]]; then
  echo "Expected exit code 7, got $STATUS" >&2
  exit 1
fi

echo "==> Testing dry-run mode"
unset MOCK_CURL_EXIT
export MOCK_HTTP_CODE=204
if ! ML_CERT_TEMPLATE=Smoke ML_PASSWORD=test "$HOOK" --cert-dir "$TMP_DIR/certs" --dry-run >"$TMP_DIR/dryrun.out" 2>&1; then
  echo "Dry-run should succeed" >&2
  cat "$TMP_DIR/dryrun.out" >&2
  exit 1
fi
grep -q 'Would POST renewed certificate' "$TMP_DIR/dryrun.out"
grep -q 'made no network request' "$TMP_DIR/dryrun.out"
if grep -q 'Pushing renewed certificate' "$TMP_DIR/dryrun.out"; then
  echo "Dry-run should not make API calls" >&2
  exit 1
fi

echo "==> Testing package manager selection and detection"
SETUP="$SCRIPT_DIR/setup-certbot-route53.sh"
BASH_BIN="$(command -v bash)"

make_manager_dir() {
  local dir="$1"
  shift
  mkdir -p "$dir"
  for manager in "$@"; do
    printf '#!/bin/sh\nexit 0\n' >"$dir/$manager"
    chmod +x "$dir/$manager"
  done
}

make_manager_dir "$TMP_DIR/both" dnf yum
make_manager_dir "$TMP_DIR/yum-only" yum
make_manager_dir "$TMP_DIR/dnf-only" dnf

output="$(PATH="$TMP_DIR/both:$PATH" "$BASH_BIN" "$SETUP" --dry-run)"
[[ "$output" == *"dnf"* ]] || { echo "Expected auto mode to prefer dnf" >&2; exit 1; }
output="$(PATH="$TMP_DIR/yum-only" "$BASH_BIN" "$SETUP" --dry-run)"
[[ "$output" == *"yum"* ]] || { echo "Expected auto mode to fall back to yum" >&2; exit 1; }
output="$(PATH="$TMP_DIR/both:$PATH" "$BASH_BIN" "$SETUP" --package-manager yum --dry-run)"
[[ "$output" == *"yum"* ]] || { echo "Expected explicit yum selection" >&2; exit 1; }

mkdir -p "$TMP_DIR/no-manager"
if PATH="$TMP_DIR/no-manager" "$BASH_BIN" "$SETUP" --dry-run >"$TMP_DIR/no-manager.out" 2>&1; then
  echo "Expected unsupported-host detection to fail" >&2
  exit 1
fi
grep -qE 'dnf.*yum|yum.*dnf' "$TMP_DIR/no-manager.out"

echo "==> Testing log_verbose with VERBOSE=false under set -e"
cat >"$TMP_DIR/test-log-verbose.sh" <<'EOF_TEST'
#!/usr/bin/env bash
set -euo pipefail
VERBOSE=false
log_verbose() { [[ "$VERBOSE" == "true" ]] && echo -e "[DEBUG] $*" || true; }
log_verbose "This should not abort the script"
echo "success"
EOF_TEST
chmod +x "$TMP_DIR/test-log-verbose.sh"
if ! "$TMP_DIR/test-log-verbose.sh" >"$TMP_DIR/log-verbose-test.out" 2>&1; then
  echo "log_verbose with VERBOSE=false failed under set -e" >&2
  cat "$TMP_DIR/log-verbose-test.out" >&2
  exit 1
fi
grep -q 'success' "$TMP_DIR/log-verbose-test.out"

echo "==> Testing wrapper with no forwarded flags (empty HOOK_ARGS)"
WRAPPER="$SCRIPT_DIR/marklogic-cert-deploy-wrapper.sh"
if [[ ! -x "$WRAPPER" ]]; then
  echo "ERROR: Wrapper not found or not executable: $WRAPPER" >&2
  exit 1
fi

# Create temp config with restrictive permissions
CONFIG_FILE="$TMP_DIR/test-config"
(
  umask 077
  cat >"$CONFIG_FILE" <<'EOF_CONFIG'
ML_HOST=localhost
ML_PORT=8002
ML_SCHEME=http
ML_USER=test
ML_PASSWORD=test
ML_CERT_TEMPLATE=Smoke
EOF_CONFIG
)

# Verify config has restrictive permissions (0600); GNU stat first (BSD "stat -f" means something else on Linux)
PERMS=$(stat -c %a "$CONFIG_FILE" 2>/dev/null || stat -f %Lp "$CONFIG_FILE" 2>/dev/null || echo "unknown")
if [[ "$PERMS" != "600" ]]; then
  echo "Config file permissions are not 0600: $PERMS" >&2
  exit 1
fi

# Create empty certificate directory (RENEWED_LINEAGE)
EMPTY_CERT_DIR="$TMP_DIR/empty-certs"
mkdir -p "$EMPTY_CERT_DIR"

# Invoke wrapper with ONLY --config and RENEWED_LINEAGE (no --verbose, no --dry-run = empty HOOK_ARGS)
# This should fail with "Certificate not readable" (preflight check), NOT "unbound variable"
if RENEWED_LINEAGE="$EMPTY_CERT_DIR" "$WRAPPER" --config "$CONFIG_FILE" >"$TMP_DIR/wrapper-error.out" 2>&1; then
  echo "Expected wrapper to fail when certificate not found" >&2
  exit 1
fi

WRAPPER_OUTPUT="$(cat "$TMP_DIR/wrapper-error.out")"

# Verify the wrapper reached the deploy hook and failed on certificate validation,
# NOT on unbound variable or shell syntax error
if grep -qE 'unbound variable|HOOK_ARGS|Syntax error' "$TMP_DIR/wrapper-error.out"; then
  echo "Wrapper failed with shell error (unbound variable or syntax):" >&2
  cat "$TMP_DIR/wrapper-error.out" >&2
  exit 1
fi

# The deploy hook should report missing certificate (preflight validation)
if ! grep -qE 'certificate|not readable|no such file' "$TMP_DIR/wrapper-error.out"; then
  echo "Expected certificate validation error, got:" >&2
  cat "$TMP_DIR/wrapper-error.out" >&2
  exit 1
fi

echo "All smoke checks passed"
