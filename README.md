# MarkLogic security and TLS scripts

Bash automation for MarkLogic security configuration, certificate management and auditing.
Documentation and walkthroughs: <https://mwarnes.github.io/scripts-browser/>

This is the **single source of truth** for these scripts. Personal collection, not official
Progress/MarkLogic documentation; test in a non-production environment before use.

## Quick start

```bash
git clone https://github.com/mwarnes/mwarnes-marklogic-scripts.git && cd mwarnes-marklogic-scripts/scripts
export MARKLOGIC_PASS='<admin password>'          # never pass passwords as CLI flags
./verify-marklogic-config.sh --config-type list --marklogic-host my-host
./TLS/configure-marklogic-tls.sh list-templates --marklogic-host https://my-host --marklogic-user admin
```

Every script supports `--help`; most support `--dry-run` and `--verbose`.
Remote plain-HTTP is refused unless `MARKLOGIC_ALLOW_HTTP=true` (isolated test systems only).
Keep `marklogic-utils.sh` (and `TLS/tls-utils.sh`) alongside the scripts that source them.

## QA status

| Area | Status |
|------|--------|
| `TLS/configure-marklogic-tls.sh`, `generate-ca-certificate.sh`, `generate-csr.sh`, `validate-tls.sh`, `validate-certificate-type.sh` | Tested against MarkLogic 12.1, including both certificate-import routes (MarkLogic-generated CSR and external key pair) and CA-verified TLS handshakes |
| `TLS/monitor-certificate-expiry.sh`, `TLS/renew-certificates.sh` | Tested against MarkLogic 12.1 |
| `TLS/setup-certbot-route53.sh`, `TLS/marklogic-cert-deploy*.sh` | Tested on Amazon Linux 2023 with a real Let's Encrypt lineage deployed into a MarkLogic template (the Route 53 issuance itself is not exercised) |
| `TLS/example-end-to-end-tls.sh`, `TLS/example-marklogic-client-auth.sh` | Tested |
| `security-audit.sh`, `verify-marklogic-config.sh` | Tested against MarkLogic 12.1 (TLS/app-server checks) |
| `LDAP/configure-marklogic-ldap.sh` | Tested against MarkLogic 12.1 and a 389 Directory Server: create (simple bind over ldap/ldaps/StartTLS, authorization internal or ldap, mutual TLS with a client certificate), update with `--force`, configure app server, validate, test, search, schema, delete, and `whoami` (client-certificate mapping check). Active Directory behaviour is documented from Microsoft's documentation and not run |
| `Kerberos/` | Syntax and option checks only; no KDC available. Known issue: `configure-marklogic-kerberos.sh configure-appserver` sends `negotiate`/`basic+negotiate`, which MarkLogic 12 rejects (valid value is `kerberos-ticket`, which also requires internal security to be disabled) |
| `OAUTH/`, `SAML/`, `rotate-credentials.sh`, and the OAuth/SAML paths of `configure-appserver-security.sh` | **Not yet QA-tested** (no identity-provider test servers available). Review before use. |

Requires `bash`, `curl`, `jq` and `openssl`. The scripts run on macOS (bash 3.2) and Linux.

## Reporting problems

Open an issue with the script version (`--help` header), MarkLogic version and the exact error.
