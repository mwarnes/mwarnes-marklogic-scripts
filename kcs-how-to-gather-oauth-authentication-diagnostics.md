<!--
KCS ARTICLE — How-To (framed as Problem/Solution per template constraints)
Paste each section below into the matching Salesforce field.
-->

## Title
How to gather OAuth authentication diagnostics

## URL Name
how-to-gather-oauth-authentication-diagnostics

## Summary
Collect the OAuth profile, IdP discovery and JWKS, IdP TLS chain, access token checks and logs for a MarkLogic 11 or 12 OAuth token or login that fails.

## Validation Status
Unverified

## Article Number
*(assigned by Salesforce on save)*

## Environment
Product: MarkLogic\
Version: 11.3.7 and 12.1.0\
OS: All supported platforms\
Component: Security

## Question/Problem Description
Which information does MarkLogic Support need to diagnose an OAuth authentication problem, and how is it collected easily and safely?

Typical situations are a bearer token that MarkLogic refuses (the HTTP status depends on the validation error and version; Resource server flow, MarkLogic 11 and 12), a browser that loops back to the IdP after a successful login (Authorization code flow, MarkLogic 12), a user who authenticates but receives no roles, or an OAuth configuration that stopped working after an upgrade, a key rotation at the IdP or a certificate change.

## Steps to Reproduce
N/A — this article is a configuration procedure, not a defect.

## Clarifying Information
**Environment details:** The script was verified on MarkLogic 11.3.7 (Resource server profiles) and MarkLogic 12.1.0 (Resource server and Authorization code profiles) with an OpenID Connect IdP (authentik 2026.8) that issued real RS256 tokens, and HTTPS app servers using a Let's Encrypt certificate. Reading the profile, the app servers, the IdP discovery document and JWKS and the IdP's TLS chain, the token check (including the RS256 signature), and the log analysis were each run against working and failing configurations on both releases. Only RS256 tokens are checked. Other IdPs (Microsoft Entra ID, Okta, Keycloak) were not tested.

- MarkLogic 11 supports the OAuth **Resource server** flow only; MarkLogic 12 also supports the **Authorization code** flow. A profile with the Authorization code flow cannot be created on MarkLogic 11 (HTTP 400, `MANAGE-INVALIDPAYLOAD`), and the script reports one as a failure if it finds it.
- In a tested MarkLogic 11.3.7 Resource server case, an expired token returned HTTP `500`; the ErrorLog combined signature, format and expiration in one validation message. Do not infer the specific cause or status from that message alone. An issuer mismatch returned HTTP `500` with `XDMP-OAUTH: JWT issuer URI validation fails` in the tested configuration. Check the `OAuth` trace and app server AccessLog for the actual failure and status in the affected version and flow; an invalid-signature status was not independently verified here.
- The `Roles: [...]` in the trace line `OAuth Authentication with Username: [user] Roles: [...]` lists the values of the role claim, not the roles that were granted: a user can show roles there and still receive HTTP `403` when none of the values equals the external name of a role.
- MarkLogic 11.3.7's HTTPS client offers neither TLS 1.3 nor the TLS extended master secret extension. An IdP endpoint that requires either (authentik's own HTTPS port does) cannot be reached: fetching the JWKS fails with `XDMP-OAUTH: SVC-SOCCONN` and `sslv3 alert handshake failure`, although a browser or `curl` connects. MarkLogic 12.1.0 connects. Use a TLS proxy in front of the IdP that accepts such clients, or MarkLogic 12.
- A `401` means the token or login was refused: the reason is in the `ErrorLog.txt` OAuth trace lines. A `403` after a successful OAuth login means the user was authenticated but lacks a role or privilege for the URL; this is in the app server access log, not in `ErrorLog.txt`.
- The Management API does not return the client secret of an Authorization code profile, so whether it is set, and whether it matches the IdP, cannot be checked; the redirect URI must also match the client registered at the IdP.
- With authorization `oauth`, the values of the role claim (`oauth-role-attribute`) are matched to the external names of roles.
- Successful and failed external logins are cached for `cache-timeout` seconds, so a retry within that window can produce no trace lines at all; test with a user that has not logged in recently, or wait out the timeout.

## Error Message
N/A

## Defect Number
N/A

## Enhancement Number
N/A

## Cause
N/A

## Resolution
Two scripts are attached to this article: `ml-security-gather.py` (read-only collection; the first argument selects the area, here `oauth`) and `ml-trace-events.py` (switches trace events on and off; it works for any trace event). Both need `python3`, `curl` and `openssl` on the machine that runs them and network access to the Management API (default port 8002). Run the script as a MarkLogic user with the `admin` role: the user `admin` or another administrator account (`--user <name>`, or the `MARKLOGIC_USER` environment variable). Reading the security configuration, users, roles and logs needs administrator access; the script was verified only with the user `admin`. The password is read from the `MARKLOGIC_PASS` environment variable (or asked for on a terminal) and never from the command line. Add `--scheme http` if the Management API port does not use TLS, and `--cacert <ca.pem>` (or `--insecure` for a one-off test) if its certificate is not trusted from the machine running the script.

1. Switch on the trace events for the group that holds the affected app server.

   ```
   export MARKLOGIC_PASS='<password>'
   python3 ml-trace-events.py enable --host ml1.example.com --user admin --group Default --preset oauth
   ```

   The `oauth` preset enables `OAuth`, `OAuth Status`, `OAuth Communications`, `OAuth JSON Processing` and `External Authenticate`. Use `status` instead of `enable` to list what is on, and `--dry-run` to preview the change. Trace output goes to `ErrorLog.txt` at `Info` level; no change to the file log level is needed.

   Admin Interface: **Groups** → the group → **Diagnostics** → **Trace Events**, then add the events and activate trace events.

   Management API alternative (a `PUT` replaces the whole event list, so include any events that are already enabled; event names are not validated):

   ```
   curl --anyauth -u admin -X PUT -H "Content-Type: application/json" \
     -d '{"events-activated": true, "event": ["OAuth", "OAuth Status", "OAuth Communications", "OAuth JSON Processing", "External Authenticate"]}' \
     "https://ml1.example.com:8002/manage/v2/groups/Default/properties"
   ```

2. Reproduce one failed request (or one failed browser login) and note the time in UTC just before the attempt (`date -u +%Y-%m-%dT%H:%M:%SZ`).

3. Optional but valuable: save the access token of one failed request to a text file, for example `token.txt`. It can be the bearer token itself or the whole `Authorization: Bearer <token>` header line from the application's request log. A JWT may contain personal data; its expiry is set by the issuer and is not necessarily within minutes. The raw token is not written to the report, but selected claim values such as issuer, audience, username and role values may appear. Only RS256 JWTs are signature-checked.

4. Collect the configuration, the IdP data and the logs. Substitute the host, the name of the OAuth external security profile and a start time a few minutes before the test.

   ```
   python3 ml-security-gather.py oauth --host ml1.example.com --user admin \
     --external-security example-oauth-profile \
     --token token.txt \
     --logs --start 2026-01-15T09:00:00Z
   ```

   - Only `--host` and `--user` are required. Anything left out is skipped and listed under **Not collected** in `SUMMARY.md`, so a partial run is still useful. `python3 ml-security-gather.py oauth --help` prints the full documentation, and it is printed again when an option is wrong or missing.
   - `--external-security <name>` reads that one profile (shown in the Admin Interface under **Security** → **External Security**, or with `curl --anyauth -u admin "https://ml1.example.com:8002/manage/v2/external-security?format=json"`). Without it every OAuth profile is read.
   - `--logs` adds the ErrorLog and the app server access log for a time window in UTC. Give the window with `--start <UTC time>` (the time noted before the test, from `date -u +%Y-%m-%dT%H:%M:%SZ`; accepted forms are `2026-01-15T09:00:00Z`, `2026-01-15T09:00Z`, `2026-01-15 09:00:00` (no zone means UTC) and a date alone, or a time with an offset such as `2026-01-15T10:00:00+01:00`, which is converted to UTC), or with `--minutes <n>` for the last n minutes counted back from now (default 60; run the gather within n minutes of the test). `--end` is optional (default: now). Without `--logs` only the configuration is collected.
   - `--token <file>` compares the token with the profile (see the table below). Without it the token check is listed under **Not collected**.
   - The IdP discovery document and JWKS are read from the machine that runs the script, which may see a different network and trust store than the MarkLogic hosts. The script uses normal TLS verification and marks HTTP or otherwise unauthenticated sources. Comparisons based on unauthenticated discovery or JWKS documents are diagnostic only. The Management API provides parsed CA metadata, not trusted CA certificate bytes, so possible name or key-identifier matches cannot establish MarkLogic's actual trust path or prove that MarkLogic can call the IdP. `--no-probe` skips these connections when the machine cannot reach the IdP.
   - `--user-name <user>` (repeatable) adds the user's external names, roles and privileges.

   The script writes a folder `oauth-gather-<timestamp>` with `SUMMARY.md`, redacted JSON of each call and filtered logs, plus a `.zip` beside the folder. The gather itself is read-only. This procedure temporarily changes group trace settings; disable them after the test.

5. Switch the trace events off again, and confirm.

   ```
   python3 ml-trace-events.py disable --host ml1.example.com --user admin --group Default --preset oauth
   python3 ml-trace-events.py status  --host ml1.example.com --user admin --group Default
   ```

   `disable` removes only the named events and switches the trace mechanism off only if the script switched it on.

6. Open `SUMMARY.md`, then inspect every file in the output directory and `.zip` before sharing it. The report can contain host names, URLs, certificate details and user names. Known credential fields and token forms are redacted on a best-effort basis, not guaranteed removed; inspect for residual sensitive data and remove it before attaching the archive. Query strings are removed from the access log.

What `SUMMARY.md` contains and why:

| Section | What it shows |
| --- | --- |
| Version, hosts | MarkLogic version and host names |
| OAuth profile | Flow type, client ID, issuer URI, JWKS URI, authorization and token endpoints, algorithm, username and role claim names (the client secret is never read out) |
| App servers | Which app servers use the profile and their authentication mode |
| IdP endpoints | The discovery document compared with the profile (issuer, endpoints, JWKS URI, algorithm), the JWKS keys (key ID, algorithm, certificate expiry) |
| IdP TLS | The certificate chain and host name match as seen from the gather machine, plus possible CA-list metadata matches; these do not verify MarkLogic's trust path |
| Token check | Header and claim names, issuer, algorithm, audience, username claim, role claim against the roles' external names, and an RS256 comparison with a JWKS key with the same key ID (a diagnostic WARN when the JWKS source is unauthenticated) |
| Trace events, ErrorLog | Whether the OAuth trace is on, each OAuth message and error, grouped |
| AccessLog | HTTP status codes of the app server in the window |
| Not collected | Any part that was skipped, why, and which option adds it |
| Check results | PASS, WARN, FAIL and INFO lines, most serious first |

How to read the result. Start from the first `FAIL` line in **Check results**. Common findings:

| Finding | Usual meaning |
| --- | --- |
| `token iss = oauth-jwt-issuer-uri` fails | The issuer in the token must equal `oauth-jwt-issuer-uri` exactly, including any trailing slash. |
| `token kid is in the JWKS` fails | The IdP rotated its signing key; the key MarkLogic holds or can fetch does not contain the key ID of the token. |
| `token signature verifies with the JWKS key` fails | With an authenticated JWKS source, the token was altered or was signed with a different key than the JWKS publishes. An unauthenticated JWKS comparison is diagnostic only and is reported as a WARN. |
| `role claim values map to a MarkLogic role` fails | None of the values in the role claim equals the external name of any role, so the user gets no roles. |
| `discovery issuer = oauth-jwt-issuer-uri` or an endpoint comparison fails | The profile differs from what the IdP publishes. |
| MarkLogic trust status is not verified | The Management API does not provide the trusted CA certificate bytes needed to validate the chain. A reported name or key-identifier correspondence is only a lead; confirm the connection from a MarkLogic host and review its ErrorLog before changing trusted CAs. |
| Flow `supported on MarkLogic 11` fails | The Authorization code flow needs MarkLogic 12. |
| `role claim values map to a MarkLogic role` fails and names another claim that does match | `oauth-role-attribute` points at the wrong claim (for example `groups` where the roles are in `marklogic_roles`); set it to the claim named in the finding. |
| `IdP endpoint ... accepts MarkLogic 11's HTTPS client` fails | The IdP endpoint refuses a TLS 1.2 client without the extended master secret extension; MarkLogic 11 cannot fetch the JWKS (see above). |
| `browser was sent to the IdP but never came back` warns | The Authorization code login left for the IdP and no authorization code returned. The browser page and the IdP's log say why (for example a redirect URI error, or the `authorization_code` grant not enabled). |

| Message in `ErrorLog.txt` | Usual meaning |
| --- | --- |
| `OAuth JWT Issuer URI must be configured` | `oauth-jwt-issuer-uri` is not set. |
| `JWT validation failed, re-initiating authorization flow: XDMP-OAUTH` | Token validation failed and MarkLogic restarted the authorization flow (the browser loops back to the IdP). The line before it gives the reason. |
| `Access token provided is empty` | The request carries no bearer token, or an empty one. |
| `JWT issuer URI validation fails. Expected issuer URI: ... Received issuer URI: ...` | The `iss` of the token differs from `oauth-jwt-issuer-uri`; compare both, including a trailing slash. |
| `OAuth Error: 'invalid_request', Description: The request is otherwise malformed` | Authorization code flow: the IdP refused the request, in authentik because the provider does not allow the `authorization_code` grant. |
| `XDMP-OAUTH: SVC-SOCCONN` / `sslv3 alert handshake failure` | MarkLogic could not open a TLS connection to the IdP (JWKS or token endpoint): network, CA trust, or a TLS requirement of the IdP that the MarkLogic version cannot meet. |
| `getRedirectURI() called with stateVal: (empty)` and `External authentication failed: user=` | Normal at the first request of every Authorization code login, before a session exists; the script does not count them as errors. |
| lines mentioning `jwks` | The JWKS could not be fetched or holds no matching key. |

## Workaround
N/A — this article describes a diagnostic procedure.

## Notes
The `ErrorLog` can be searched by time window through the Management API; the app server access log cannot (`MANAGE-CANNOTSEARCH`), so the script reads the access log of the bound app server whole and filters it by time. Log times are in each host's local time zone and the script's window is UTC; widen the window with `--start` and `--end` if a host is not on UTC. Rotated log files (for example `8012_AccessLog_1.txt`) are not read.

The ErrorLog does not say which app server a line belongs to: if several app servers use external security within the window, reproduce one login at a time and keep the window small. The access log part is per app server. It covers only the app servers that use the profile, only the current log file (rotated files are not read), and the lines are saved without query strings; request the rotated files, the access log of any other port, or the full ErrorLog separately when they are needed.

The same script has the areas `saml`, `oauth`, `ldap`, `https` and `certificate`, with the same connection and log options; run `python3 ml-security-gather.py --help` to list them.

References to Other Documentation:

PUT /manage/v2/groups/[id-or-name]/properties (MarkLogic 12 REST reference)
<https://docs.marklogic.com/12.0/REST/PUT/manage/v2/groups/[id-or-name]/properties>

MarkLogic article(s):
- How to gather SAML authentication diagnostics
- How to gather LDAP authentication diagnostics
- How to gather HTTPS app server diagnostics
- How to gather client certificate login diagnostics

## Internal Comments
*(manual entry)*

## Article Category
Product Group: MarkLogic\
Area of Interest: Security

## Keyword Phrase
MarkLogic OAuth authentication troubleshooting must gather trace events OAuth Status JWT JWKS Resource server Authorization code external security Management API 401 403 token issuer ml-security-gather.py ml-trace-events.py

## Admin Ticket ID
*(fill in if applicable)*
