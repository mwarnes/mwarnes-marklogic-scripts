# MarkLogic security and TLS scripts

Bash automation for MarkLogic security configuration, certificate management and auditing.
Documentation and walkthroughs: <https://mwarnes.github.io/scripts-browser/>

This is the **single source of truth** for these scripts. Personal collection, not official
Progress/MarkLogic documentation; test in a non-production environment before use.

## Download

Pick one. All three give you the same files from the `main` branch.

```bash
# 1. Clone (easiest to update later with `git pull`)
git clone https://github.com/mwarnes/mwarnes-marklogic-scripts.git
cd mwarnes-marklogic-scripts/scripts

# 2. Tarball, no git needed
curl -L https://github.com/mwarnes/mwarnes-marklogic-scripts/archive/refs/heads/main.tar.gz | tar xz
cd mwarnes-marklogic-scripts-main/scripts

# 3. Zip: https://github.com/mwarnes/mwarnes-marklogic-scripts/archive/refs/heads/main.zip
```

Download the whole `scripts/` directory, not a single file. Scripts load shared helpers
(`marklogic-utils.sh`, and `OAUTH/oauth2-utils.sh`, `SAML/saml-utils.sh`, `LDAP/ldap-utils.sh`,
`Kerberos/kerberos-utils.sh`, `TLS/tls-utils.sh` next to the scripts that use them) by relative path.
Files fetched one by one from the raw URLs will fail with "No such file" on the first `source`.

If you unpack a zip, the executable bit may be lost: run `chmod +x $(find . -name '*.sh')`.
To pin a release, check out a tag or commit instead of `main`
(`git checkout <commit>`), so a later update cannot change a tested script under you.

### Requirements

| Needed for | Tools |
|---|---|
| Every script | `bash` (3.2 or newer), `curl`, `jq`, `openssl` |
| SAML, TLS metadata checks | `xmllint` (libxml2) |
| LDAP | `ldapsearch`, `ldapwhoami` (OpenLDAP client tools) |
| OAuth JWKS-to-PEM, a few helpers | `python3` |
| Kerberos (untested) | `kinit`, `klist`, `kdestroy` (MIT Kerberos client) |
| Let's Encrypt toolkit | `certbot`, AWS CLI access to Route 53 (see `scripts/TLS/README.md`) |

macOS: `brew install jq libxml2 openldap` (curl, openssl and python3 are included or already present).
Amazon Linux / RHEL: `sudo dnf install -y jq libxml2 openldap-clients`.
Debian / Ubuntu: `sudo apt install -y jq libxml2-utils ldap-utils`.

## Quick start

```bash
cd mwarnes-marklogic-scripts/scripts
export MARKLOGIC_PASS='<admin password>'          # never pass passwords as CLI flags
./verify-marklogic-config.sh --config-type list --marklogic-host my-host
./TLS/configure-marklogic-tls.sh list-templates --marklogic-host https://my-host --marklogic-user admin
```

Start with `--dry-run` wherever it exists. It prints what would change and does not contact the server.
Secrets are read from environment variables (`MARKLOGIC_PASS`, `OAUTH_CLIENT_SECRET`, `LDAP_BIND_PASSWORD`,
`TLS_CA_PASSWORD`, `ROTATE_NEW_CREDENTIAL`) or a hidden prompt; the scripts reject `--password VALUE` style flags.

Every script supports `--help`; most support `--dry-run` and `--verbose`.
Remote plain-HTTP is refused unless `MARKLOGIC_ALLOW_HTTP=true` (isolated test systems only).
Keep `marklogic-utils.sh` (and `TLS/tls-utils.sh`) alongside the scripts that source them.

## QA status

> **⚠️ Kerberos scripts (`scripts/Kerberos/`): use at your own risk.** They have not been tested on current MarkLogic 11 or 12 releases and are provided as-is. See the table below.

| Area | Status |
|------|--------|
| `TLS/configure-marklogic-tls.sh`, `generate-ca-certificate.sh`, `generate-csr.sh`, `validate-tls.sh`, `validate-certificate-type.sh` | Tested against MarkLogic 12.1, including both certificate-import routes (MarkLogic-generated CSR and external key pair) and CA-verified TLS handshakes |
| `TLS/monitor-certificate-expiry.sh`, `TLS/renew-certificates.sh` | Tested against MarkLogic 12.1 |
| `TLS/setup-certbot-route53.sh`, `TLS/marklogic-cert-deploy*.sh` | Tested on Amazon Linux 2023 with a real Let's Encrypt lineage deployed into a MarkLogic template (the Route 53 issuance itself is not exercised) |
| `TLS/example-end-to-end-tls.sh`, `TLS/example-marklogic-client-auth.sh` | Tested |
| `security-audit.sh`, `verify-marklogic-config.sh` | Tested against MarkLogic 12.1 (TLS/app-server checks) |
| `LDAP/configure-marklogic-ldap.sh` | Tested against MarkLogic 12.1 and a 389 Directory Server: create (simple bind over ldap/ldaps/StartTLS, authorization internal or ldap, mutual TLS with a client certificate), update with `--force`, configure app server, validate, test, search, schema, delete, and `whoami` (client-certificate mapping check). Active Directory behaviour is documented from Microsoft's documentation and not run |
| `Kerberos/` | **Use at your own risk: not tested on MarkLogic 11 or 12** (no Kerberos environment available; only syntax and option checks were run). Known problem: `configure-marklogic-kerberos.sh configure-appserver` sends `negotiate` / `basic+negotiate`, which MarkLogic 12 rejects (`XDMP-VALIDATEBADTYPE`); the 12.1 value is `kerberos-ticket`, which also requires internal security to be disabled on the app server |
| `OAUTH/` (`configure-marklogic-oauth2.sh`, `validate-oauth2-config.sh`, `extract-jwks-keys.sh`, `cleanup-obsolete-jwks-keys.sh`, `rotate-oauth-keys.sh`), `SAML/` (`configure-marklogic-saml.sh`, `monitor-saml-certificates.sh`), `rotate-credentials.sh` (OAuth and SAML), and the OAuth/SAML paths of `configure-appserver-security.sh` and `verify-marklogic-config.sh` | Tested against MarkLogic 12.1.0 and authentik 2026.8: OAuth Resource Server and Authorization Code (RS256 only), SAML SP-initiated login with signed assertions, create/update/remove, JWKS key maintenance, secret rotation, and negative cases. Keycloak, Entra ID, Okta, ADFS and Auth0 are **not** tested. |
| `SAML/configure-keycloak-saml-client.sh`, `SAML/test-saml-flow.sh` | **Keycloak only; not tested against Keycloak** (`--dry-run` / first redirect step only). Review before use. |

The scripts run on macOS (bash 3.2) and Linux; see Requirements above.

## Reporting problems

Open an issue with the script version (`--help` header), MarkLogic version and the exact error.
