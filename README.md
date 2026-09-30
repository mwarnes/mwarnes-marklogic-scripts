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
| `TLS/`: `configure-marklogic-tls.sh`, `generate-ca-certificate.sh`, `generate-csr.sh`, `validate-tls.sh`, `validate-certificate-type.sh`, `monitor-certificate-expiry.sh` | Tested against MarkLogic 12.1 (CSR-matched certificate import via the Management API is **not yet verified**) |
| `security-audit.sh`, `verify-marklogic-config.sh`, `configure-appserver-security.sh`, `rotate-credentials.sh` (dry-run) | Tested read-only / dry-run |
| Other `TLS/` scripts (`renew-certificates.sh`, `marklogic-cert-deploy*.sh`, `setup-*`, `example-*`) | **QA in progress** |
| `OAUTH/`, `SAML/`, `LDAP/`, `Kerberos/` | **Not yet QA-tested**: review before use |

## Reporting problems

Open an issue with the script version (`--help` header), MarkLogic version and the exact error.
