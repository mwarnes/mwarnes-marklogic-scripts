#!/bin/bash
# ================================================================
# OAuth2 Configuration Examples (prints; runs nothing)
# ================================================================
#
# Prints the command sequence that was tested end to end against MarkLogic 12.1
# with an OIDC provider (authentik). Copy, adjust the variables, run.
#
# Secrets are never passed as arguments: the scripts reject --marklogic-pass,
# --client-secret and --test-password. Export MARKLOGIC_PASS, OAUTH_CLIENT_SECRET
# and OAUTH_TEST_PASSWORD instead (or answer the hidden prompt).
#
# MarkLogic 12.1 validates JWT signatures with RS256 only. Configure your
# provider's signing key as RSA; an ES256 (EC) key is rejected by MarkLogic.
# ================================================================

cat << 'EOF'
# ---------------------------------------------------------------
# 0. Variables (edit)
# ---------------------------------------------------------------
export MARKLOGIC_PASS='...'             # admin password (not on the command line)
export OAUTH_CLIENT_SECRET='...'        # only for validate (client_credentials test)
ML=https://ml.example.com               # use http:// + MARKLOGIC_ALLOW_HTTP=true for labs only
IDP=https://idp.example.com/application/o/my-app   # OIDC issuer (authentik style)
WELL_KNOWN=$IDP/.well-known/openid-configuration

# ---------------------------------------------------------------
# 1. Preview, then create the external security (Resource Server, JWT)
#    --role-attribute is the token claim holding group names; the script
#    default is "marklogic-roles". authentik and Keycloak emit "groups".
# ---------------------------------------------------------------
./configure-marklogic-oauth2.sh --well-known-url "$WELL_KNOWN" \
    --config-name My-OAuth --client-id my-app \
    --username-attribute preferred_username --role-attribute groups \
    --marklogic-host "$ML" --marklogic-user admin --dry-run

./configure-marklogic-oauth2.sh --well-known-url "$WELL_KNOWN" \
    --config-name My-OAuth --client-id my-app \
    --username-attribute preferred_username --role-attribute groups \
    --marklogic-host "$ML" --marklogic-user admin --yes

# ---------------------------------------------------------------
# 2. Bind it to an app server
# ---------------------------------------------------------------
./../configure-appserver-security.sh --appserver MyAppServer \
    --external-security My-OAuth --authentication-method oauth \
    --marklogic-host "$ML" --yes

# ---------------------------------------------------------------
# 3. MarkLogic roles: a role's external name must equal the group name in
#    the token. A user whose groups match no role authenticates with NO roles.
#    After changing a user's groups at the IdP, clear MarkLogic's login cache
#    (sec:external-security-clear-cache) or wait for cache-timeout (default 300s).
# ---------------------------------------------------------------

# ---------------------------------------------------------------
# 4. Validate (read-only checks plus a live token request)
# ---------------------------------------------------------------
./validate-oauth2-config.sh --well-known-url "$WELL_KNOWN" \
    --app-server MyAppServer --client-id my-app --no-decode-tokens \
    --marklogic-host "$ML" --marklogic-user admin

# ---------------------------------------------------------------
# 5. JWKS key maintenance (when the provider rotates its signing key)
#    The script above stores a jwks-uri; MarkLogic can also hold static keys.
# ---------------------------------------------------------------
./extract-jwks-keys.sh "$IDP/jwks/"                              # analyse only
./extract-jwks-keys.sh "$IDP/jwks/" --upload-to-marklogic \
    --marklogic-host ml.example.com --external-security My-OAuth # add missing keys
./cleanup-obsolete-jwks-keys.sh "$IDP/jwks/" \
    --marklogic-host ml.example.com --external-security My-OAuth # analyse
./cleanup-obsolete-jwks-keys.sh "$IDP/jwks/" --delete-keys --confirm-delete \
    --marklogic-host ml.example.com --external-security My-OAuth # delete obsolete
./rotate-oauth-keys.sh --external-security My-OAuth \
    --marklogic-host ml.example.com --dry-run                    # add new + remove obsolete

# ---------------------------------------------------------------
# 6. Rotate the client secret
# ---------------------------------------------------------------
ROTATE_NEW_CREDENTIAL='new-secret' ./../rotate-credentials.sh \
    --type oauth --external-security My-OAuth --no-verify --yes

# ---------------------------------------------------------------
# 7. Remove
# ---------------------------------------------------------------
./configure-marklogic-oauth2.sh --config-name My-OAuth --remove --marklogic-host "$ML" --yes

# Expected MarkLogic behaviour (not a bug): a request to a Resource Server app
# server with no, or a malformed, bearer token returns HTTP 500 (XDMP-OAUTH
# "Access token provided is empty"), not 401. A token with a bad signature
# returns 401.
EOF
