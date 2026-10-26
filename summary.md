# summary.md: handover for an agent continuing the work in this repository

Written 2026-10-26. Owner: Martin Warnes (MarkLogic Support). Read this first, then `scripts/Security/README.md`.
The related repositories are `~/Projects/marklogic-labs` (private test labs for these scripts), `~/Projects/marklogic-support-skill`
(the Claude skills `marklogic-support`, `ticket`, `kcs`, `kcs-review`; the support skill carries a copy of the gather script) and
`~/Projects/mwarnes.github.io` (public articles; `articles/OAUTH2-TROUBLESHOOTING.md`, `articles/SAML-TROUBLESHOOTING.md`, `articles/TLS_CERTIFICATE_MANAGEMENT.md`).
The scripts and labs were built during support ticket 01967797 (SAML 401 after an upgrade to 12.1.0) and have since been moved out of the ticket folder.

## What is here

| Path | What |
|---|---|
| `scripts/Security/ml-security-gather.py` | The security must-gather (about 2,400 lines). `ml-security-gather.py AREA ...` with AREA = `saml`, `oauth`, `ldap`, `https`. Read-only, Management API (port 8002) plus `curl` and `openssl`; Python 3.9 compatible, standard library only. |
| `scripts/Security/ml-trace-events.py` | `enable`/`disable`/`status` for trace events of a group, presets `saml`, `oauth`, `ldap`, or `--event NAME` (repeatable). |
| `scripts/Security/tests/test_ml_security_gather.py` | 30 unit tests against a mock Management API and mock IdP (no MarkLogic needed). Run: `python3 -m unittest discover -s scripts/Security/tests`. |
| `scripts/Security/README.md` | User documentation of the two scripts. |
| `scripts/TLS/` | Certificate tooling: `marklogic-cert-deploy.sh` (Certbot deploy hook for a MarkLogic certificate template), `setup-certbot-route53.sh`, `renew-certificates.sh`, tests in `tests/test-letsencrypt-toolkit.sh`, README. |
| `kcs/` | **Gitignored, local only.** Draft KCS how-to articles for the gather scripts (`kcs-01967797-howto-gather-{saml,oauth,ldap,https}-diagnostics` as `.md`, `.docx`, `.html`). Render with the skill's `scripts/kcs_render.py`. Ticket resolution articles do NOT go here; they stay in the ticket folder. |
| other `scripts/*` | Older scripts (Kerberos, LDAP, OAUTH, SAML, security audit); not part of this work. |

A byte-identical copy of `ml-security-gather.py` (and `ml-trace-events.py`) lives in
`~/Projects/marklogic-support-skill/skills/marklogic-support/assets/support-scripts/`. After every change here, run `scripts/Security/sync-support-scripts.sh` (copies both scripts and checks them with `cmp`; a symlink was rejected because the skill repository is published and a symlink would dangle in other clones).

## How the gather script works (decisions worth keeping)

- Only `--host` and `--user` are required. The user should be a MarkLogic `admin`-role account (`MARKLOGIC_USER` environment variable also works); the password comes from `MARKLOGIC_PASS` or a terminal prompt, never from the command line. `--scheme http` when the Management API is plain HTTP (the lab servers are), `--cacert`/`--insecure` otherwise.
- Anything not given is skipped and listed in a **Not collected** table of `SUMMARY.md`. Errors in option parsing print the area help and then the error.
- Output: `./<area>-gather-<timestamp>/` with `SUMMARY.md`, raw JSON (secrets, private keys and client secrets are removed), filtered logs, and a `.zip`. Start reading `SUMMARY.md` at "Check results" (FAIL, WARN, PASS, INFO).
- Logs: `--logs` with `--start` (ISO 8601; `Z` or no zone = UTC; offsets are converted) or `--minutes N`. The ErrorLog is searched by time through `GET /manage/v2/logs?filename=ErrorLog.txt&start=&end=`; the AccessLog cannot be time-searched (`MANAGE-CANNOTSEARCH`), so it is read whole and filtered. The ErrorLog does not say which app server a line belongs to: one lab or login per window, otherwise other logins' errors appear in the report.
- `scrub()` removes long values, SAML request/response values and whole JWTs/token-endpoint responses from saved log lines. Keep it that way: a test covers it.
- `--token FILE` (OAuth) checks header/claims, issuer, audience, username claim, role-claim-to-role mapping and the RS256 signature (via `openssl`) against the JWKS. Only RS256 is supported (ML12 rejects ES256).
- Version differences are handled: MarkLogic 11 has no Authorization code flow; TLS settings are `ssl-disable-*` on 11 and `ssl-min-allow-tls`/`ssl-ciphersuites` on 12; `GET .../certificate-templates/<name>/properties` returns 400 on 11 (use the plain URL).
- Role mapping (SAML and OAuth): roles come from the assertion `Group` values or the OAuth role claim matched against role **external names**. A MarkLogic user's own roles and external names are not used. The script FAILs when no value matches a role, and WARNs (guidance, not a fault) when SAML authorization is `internal`.
- The trace-events script writes the shape the server accepts: a flat `"event": [...]` list plus `"events-activated"`. `disable --preset oauth` also removes `External Authenticate` (part of every preset); pass explicit `--event` names to avoid that if another test relies on it.

## Facts established by live testing (MarkLogic 11.3.7 and 12.1.0 lab servers, Authentik 2026.8 as IdP; the lab hosts are described in the private `~/Projects/marklogic-labs/summary.md`)

- SAML: roles come only from Group value to role external name, with authorization `saml` or `internal`; `internal` was not found unsupported on 11.3.7 or 12.1.0 (engineering's contrary statement was not reproduced). A user's own external name is ignored. On ML12 the built-in roles `qconsole-user` and `admin` already carry external names, which can hide a missing mapping in a lab: use per-lab prefixed Group values.
- SAML Issuer check: the assertion Issuer must equal `saml-entity-id`; a wrong value gives HTTP 401 and `Saml Response Error: Issuer ... does not match configured IdP ...` even when signature, audience and validity pass. Enforced on 11.3.7. Whether earlier releases enforced it is unknown (ticket 01967797 worked before the upgrade; a SAML signature-verification CVE, CVE-2026-7557, was fixed in 11.3.6 and 12.0.3).
- OAuth Resource server: issuer mismatch returns HTTP 500 (`JWT issuer URI validation fails`); a role claim matching no role gives 403; the trace line `Roles: [...]` lists claim values, not granted roles. **MarkLogic 11.3.7's HTTPS client cannot connect to an IdP that requires TLS 1.3 or the TLS extended master secret** (Authentik's own HTTPS port): `SVC-SOCCONN`, `sslv3 alert handshake failure`. ML12 connects. The gather script FAILs on ML11 when `openssl s_client -tls1_2 -no_ems` is refused.
- OAuth Authorization code (12.1.0): 303 to the IdP (`response_mode=form_post`, PKCE S256, redirect URI = app server URL without path), IdP posts `code` and `state` back, cookie `oauth-token`. The first request logs `getRedirectURI() ... (empty)` and `External authentication failed: user=`: normal. Authentik without the `authorization_code` grant posts `invalid_request` back (MarkLogic 500); a redirect URI mismatch is visible only at the IdP page and the script WARNs "browser was sent to the IdP but never came back".
- TLS/Let's Encrypt: a certificate template made through the API has no certificate until one is imported; `insert-host-certificates` takes one certificate; the intermediate must be imported as a trusted CA (`pki:insert-trusted-certificates` through `/v1/eval` on the Security database) or the port sends the leaf only. Let's Encrypt signs with different intermediates (YE1, YE2): import each. Importing the cross-signed `Root YE` and `ISRG Root X2` makes the port send a chain curl verifies. CA list names are the **issuer** name, not the subject.
- Management API quirks: Authentik/MarkLogic POST of a duplicate gives 400 or 500 rather than 409; `PUT .../properties` replaces lists; `GET /manage/v2/external-security/<name>` omits `oauth-server`, use `.../properties?format=json`; a template needs `organizationName` (`PKI-NOORGNAME`); REST API instances are created with `POST /v1/rest-apis` on port 8002; deleting an app server restarts the listener briefly.

## Status

Done and merged on `main` (all pushed): the four areas, tests, trace-events script, TLS hook fix for MarkLogic 11, OAuth checks verified with real tokens, SAML hint for issuer mismatch.
Not verified or missing:
- **LDAP** is only tested against crafted log lines and mock data. A lab needs the directory details (a lab directory server exists, see the private labs repository; bind DN, password, base DN and a test user must come from Martin).
- Entra ID, Okta and Keycloak were never tested live; Entra behaviour is known only from a customer ErrorLog.
- Comparison of a captured SAML response with the profile (issuer, audience, signing certificate) was tested on generated data and on lab logins only.
- Trigger of the "Duplicate certificate subject" ErrorLog warning in MarkLogic is unknown.
- The gather script has no unit test for the TLS legacy-client probe (it needs a live server).

Ideas: an OAuth Authorization code example that secures an Admin Interface clone; a `--summary-json` output; more IdPs.

## Working rules (from the owner)

- Branch before committing when on `main`; commit, push and merge only when asked; commit messages end with `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`; delete merged branches only when asked.
- Never write credentials (MarkLogic passwords, Authentik API tokens, client secrets, app passwords, private keys) into any file, commit or message that is saved. Tokens given in chat are for that session; remind the owner to revoke them.
- This repository is PUBLIC (as is the skill repository): never put real lab host names, ports, object names, key paths or customer data in it, in commits or in examples; use `example.com`. Lab details belong in the private `marklogic-labs` repository.
- Do not delete or change lab or server objects beyond what the task needs; every temporary object is recorded and cleaned up. How to reach the lab servers (ssh options, ports) is in the private labs summary.
- Keep ticket folders (`~/Projects/MarkLogic-Support/<ticket>/`) for ticket data only. Scripts, labs and script KCS drafts belong in their own repositories, as here.
- The `rm -rf` safety check blocks variable expansions: use `"${VAR:?}"/*` or literal paths. Never run commands that kill the shell (`pkill -f` with a pattern that matches it).
