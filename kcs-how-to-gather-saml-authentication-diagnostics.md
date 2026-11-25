<!--
KCS ARTICLE — How-To (framed as Problem/Solution per template constraints)
Paste each section below into the matching Salesforce field.
-->

## Title
How to gather SAML authentication diagnostics

## URL Name
how-to-gather-saml-authentication-diagnostics

## Summary
Collect the SAML configuration, IdP certificate, trace events and logs needed to diagnose a MarkLogic SAML login that returns 401 or 403.

## Validation Status
Verified

## Article Number
*(assigned by Salesforce on save)*

## Environment
Product: MarkLogic\
Version: 11.3.7 and 12.1.0\
OS: All supported platforms\
Component: Security

## Question/Problem Description
Which information does MarkLogic Support need to diagnose a SAML authentication problem, and how is it collected easily and safely?

Typical situations are a login that is refused with HTTP `401 Unauthorized`, a login that succeeds at the identity provider (IdP) but ends with HTTP `403 Forbidden` in MarkLogic, or a SAML configuration that stopped working after an upgrade, a certificate rotation or a redeployment of the external security configuration. The application can be a browser user or a middle tier that sends the assertion to a REST app server in an `authorization: SAML token=<base64 SAMLResponse>` header.

## Steps to Reproduce
N/A — this article is a configuration procedure, not a defect.

## Clarifying Information
**Environment details:** The procedure and the log messages quoted below were verified on MarkLogic 12.1.0 and 11.3.7, with an HTTPS app server using signed assertions and a SAML 2.0 IdP (authentik); the SAML login and the trace messages were checked on both releases, and the role-mapping variants on 11.3.7. They were not verified with other IdPs (for example Okta or Microsoft Entra ID) or on other releases; message wording can differ between releases. The two scripts need `python3`, `curl` and `openssl` on the machine that runs them and network access to the Management API (default port 8002).

- A `401` means authentication was refused: the reason is in the `ErrorLog.txt` SAML trace lines. A `403` after a successful SAML login means the user was authenticated but lacks a role or privilege for the URL: the reason is in the app server access log, not in `ErrorLog.txt`.
- The Issuer check is enforced: on MarkLogic 11.3.7 a wrong `saml-entity-id` was reproduced with the SAML trace events on, giving HTTP `401` and the line `Saml Response Error: Issuer ... does not match configured IdP ...` while every other check (signature, audience, validity) passed. It was not tested on other releases, so do not assume that a configuration that worked before an upgrade still passes: compare `saml-entity-id` with the Issuer of the assertion first.
- The roles of a SAML login come from the assertion's `Group` values, which are matched to role external names; MarkLogic user roles and external names are not used (tested on 11.3.7). Use `authorization` set to `saml` for the documented SAML authorization configuration; the gather warns when another value is configured. A test on 11.3.7 still granted a role when `authorization` was `internal` and the role external name matched a `Group` value; this behavior was not retested on 12.1. For a `403` with an empty `Mapped to Temp User ... Role(s):` line, check the `Group` values against role external names; changing `authorization` alone does not establish that the mapping is fixed.
- `External authentication failed: user=` lines with no user name are logged for the first request, before a session exists, and are normal.
- Authentication through the browser flow and through the `authorization: SAML token=` header both write the same validation lines to the trace. The header flow has no `recipient` line because there is no assertion consumer step.
- The IdP signing certificate stored in MarkLogic does not need its issuing certificate. A login worked on 12.1.0 with only the IdP signing certificate stored, so compare the stored certificate with the IdP metadata rather than checking for a complete chain. A self-signed signing certificate is its own trust anchor.

## Error Message
```
[Event:id=SAML] Saml Response Error: Issuer https://sts.windows.net/<tenant-id>/ does not match configured IdP http://marklogic/<profile-name>
[Event:id=External Authenticate] External authentication failed: user=
```
The lines appear in `ErrorLog.txt` with the SAML and SAML Response trace events on; the browser receives HTTP `401 Unauthorized`.

## Defect Number
N/A

## Enhancement Number
N/A

## Cause
N/A

## Resolution
Two scripts are attached to this article: `ml-security-gather.py` (read-only collection; the first argument selects the area, here `saml`) and `ml-trace-events.py` (switches trace events on and off; it works for any trace event, not only SAML). The password is read from the `MARKLOGIC_PASS` environment variable and never from the command line. Run the script as a MarkLogic user with the `admin` role: the user `admin` or another administrator account (`--user <name>`, or the `MARKLOGIC_USER` environment variable). Reading the security configuration, users, roles and logs needs administrator access; both scripts were verified only with the user `admin`. Add `--scheme http` if the Management API port does not use TLS, and `--cacert <ca.pem>` (or `--insecure` for a one-off test) if its certificate is not trusted from the machine running the script.

1. Switch on the SAML trace events for the group that holds the affected app server.

   ```
   export MARKLOGIC_PASS='<password>'
   python3 ml-trace-events.py enable --host ml1.example.com --user admin --group Default --preset saml
   ```

   The `saml` preset enables `SAML`, `SAML Response` and `External Authenticate`. Use `status` instead of `enable` to list what is on, and `--dry-run` to preview the change. Trace output goes to `ErrorLog.txt` at `Info` level; no change to the file log level is needed.

   Admin Interface: **Groups** → the group → **Diagnostics** → **Trace Events**, then add the three events and activate trace events.

   Management API alternative (a `PUT` replaces the whole event list, so include any events that are already enabled; event names are not validated):

   ```
   curl --anyauth -u admin -X PUT -H "Content-Type: application/json" \
     -d '{"events-activated": true, "event": ["SAML", "SAML Response", "External Authenticate"]}' \
     "https://ml1.example.com:8002/manage/v2/groups/Default/properties"
   ```

2. Reproduce one failed login for each affected app server and note the time in UTC just before the attempt (`date -u +%Y-%m-%dT%H:%M:%SZ`).

3. Optional but valuable: save the SAML response of one failed login to a text file, for example `saml-response.txt`. It can be the `SAMLResponse` captured with a browser SAML tracer extension, or the value after `SAML token=` in the application's request log. The file can be raw XML, base64, or a whole `authorization:` header line. It contains personal data; its validity period is set by the IdP and is not necessarily a few minutes. The raw response is not written to the report, but parsed values such as NameID and group/attribute values may appear.

4. Collect the configuration and logs. Substitute the host, the name of the SAML external security profile used by the affected app server, the failing user's MarkLogic user name, the IdP metadata and a start time a few minutes before the test.

   ```
   python3 ml-security-gather.py saml --host ml1.example.com --user admin \
     --external-security example-saml-profile \
     --user-name alice \
     --idp-metadata https://idp.example.com/metadata \
     --saml-response saml-response.txt \
     --logs --start 2026-01-15T09:00:00Z
   ```

   The profile name is shown in the Admin Interface under **Security** → **External Security**, and in the app server's settings (**Groups** → the group → **App Servers** → the app server, under authentication). With the Management API: `curl --anyauth -u admin "https://ml1.example.com:8002/manage/v2/external-security?format=json"`.

   - `--external-security <name>` reads that one profile. Use it when the app server has a single SAML profile, which is the usual case. The `--saml-response` comparison also needs it when more than one SAML profile exists. Without the option the script reads every SAML profile and finds the app servers that use any of them.
   - Only `--host` and `--user` are required. Anything left out is skipped and listed under **Not collected** in `SUMMARY.md`, so a partial run is still useful. `python3 ml-security-gather.py saml --help` prints the full documentation, and it is printed again when an option is wrong or missing.
   - `--user-name` adds a MarkLogic user's external names, roles and privileges to the report; it can be repeated and is informational only, because the roles of a SAML login come from the assertion's `Group` values matched to role external names, not from a MarkLogic user. All roles that have an external name are always listed.
   - `--idp-metadata` and `--saml-response` are optional but give the most useful comparison. Without `--logs` only the configuration is collected.
   - `--logs` adds the ErrorLog and the app server access log for a time window in UTC. Give the window with `--start <UTC time>` (the time noted before the test, from `date -u +%Y-%m-%dT%H:%M:%SZ`; accepted forms are `2026-01-15T09:00:00Z`, `2026-01-15T09:00Z`, `2026-01-15 09:00:00` (no zone means UTC) and a date alone, or a time with an offset such as `2026-01-15T10:00:00+01:00`, which is converted to UTC), or with `--minutes <n>` for the last n minutes counted back from now (default 60; run the gather within n minutes of the test). `--end` is optional (default: now). Without `--logs` only the configuration is collected.
   - If several app servers use different SAML profiles, run the command once per profile with that profile's metadata and response file.

   The script writes a folder `saml-gather-<timestamp>` with `SUMMARY.md`, redacted JSON of each call and filtered logs, plus a `.zip` beside the folder. The gather itself is read-only. This procedure temporarily changes group trace settings; disable them after the test.

5. Switch the trace events off again, and confirm.

   ```
   python3 ml-trace-events.py disable --host ml1.example.com --user admin --group Default --preset saml
   python3 ml-trace-events.py status  --host ml1.example.com --user admin --group Default
   ```

   `disable` removes only the named events and switches the trace mechanism off only if the script switched it on.

6. Open `SUMMARY.md`, then inspect every file in the output directory and `.zip` before sharing it. The report can contain host names, entity IDs, certificate details, user names and group values. Known credential fields and token forms are redacted on a best-effort basis, not guaranteed removed; inspect for residual sensitive data and remove it before attaching the archive. Query strings are removed from the access log.

What `SUMMARY.md` contains and why:

| Section | What it shows |
| --- | --- |
| Version, hosts | MarkLogic version and host names |
| External security | `saml-entity-id`, `saml-destination`, `saml-issuer`, signature algorithm, authorization mode (the private key is never read out) |
| IdP and SP certificates | Subject, issuer, expiry, SHA-1 and SHA-256 fingerprints, signature check |
| App servers | Which app servers use the object, their authentication mode and TLS template |
| Users, roles | The roles that have external names (what the `Group` values are matched to), and for each `--user-name` the user's external names, roles and privileges |
| IdP metadata | `entityID`, SSO URLs and signing certificates compared with the stored configuration |
| SAML response | Issuer, audience, signed element, signing certificate, NameID and attribute values compared with the configuration |
| Trace events, ErrorLog | Whether the SAML trace is on, each validation step and error, the NameID and groups MarkLogic saw |
| AccessLog | HTTP status codes and the roles the SAML identity received |
| Not collected | Any part that was skipped, why, and which option adds it |
| Check results | PASS, WARN, FAIL and INFO lines, most serious first |

How to read the result. Start from the first `FAIL` line in **Check results**; it quotes the log message. Common messages and their usual meaning:

| Message in `ErrorLog.txt` | Usual meaning |
| --- | --- |
| `signature is invalid` | The IdP signed with a certificate other than the one stored in `saml-idp-certificate-authority` (rotated, not migrated, or a different certificate per application), or the assertion was altered. Compare the stored SHA-1 with the metadata and the response. |
| `Signature node not found in SAML XML` | The assertion arrived unsigned. MarkLogic requires a signed assertion. |
| `Issuer ... does not match configured IdP ...` | The Issuer of the assertion differs from `saml-entity-id` of the external security profile. The signature, audience and time checks can all pass and the login is still refused (HTTP `401`). Set `saml-entity-id` to the Issuer exactly as it appears in the message, including a trailing slash (Microsoft Entra: `https://sts.windows.net/<tenant-id>/`, the Microsoft Entra Identifier; the value is also the `entityID` of the IdP metadata). A value such as `http://marklogic/<name>` is a placeholder that never matches. |
| `Audience ... does not match SP entity ID` | The audience set by the IdP must equal `saml-issuer`. |
| `recipient ... does not match` | The IdP's assertion consumer URL differs from the app server URL. |
| `status ... is not Success` | The IdP returned an error status. |
| `cannot parse response` | The value after `SAML token=` is not a base64 SAML Response. |
| `NotBefore` or `notOnOrAfter` errors | Clock difference between the IdP and the MarkLogic hosts. |
| `Saml Response Expired: notOnOrAfter ...` with the same `samlId` repeated | The browser is resubmitting an old response; it is only noise. Read the first attempt of that `samlId` for the real reason. |
| `Mapped to Temp User ... with Role(s):` empty (access log) | The identity received no roles: no role external name matched the `Group` values, or the user's own roles were expected to apply (they are not used; see Clarifying Information). |

## Workaround
N/A — this article describes a diagnostic procedure.

## Notes
The `ErrorLog` can be searched by time window through the Management API; the app server access log cannot (`MANAGE-CANNOTSEARCH`), so the script reads the access log of the bound app server whole and filters it by time. Log times are in each host's local time zone and the script's window is UTC; widen the window with `--start` and `--end` if a host is not on UTC. Rotated log files (for example `8012_AccessLog_1.txt`) are not read.

The ErrorLog does not say which app server a line belongs to: if several app servers use external security within the window, reproduce one login at a time and keep the window small. The access log part is per app server. It covers only the app servers that use the profile, only the current log file (rotated files are not read), and the lines are saved without query strings; request the rotated files, the access log of any other port, or the full ErrorLog separately when they are needed.

The same script also has the areas `oauth`, `ldap`, `https` and `certificate`, with the same connection and log options; run `python3 ml-security-gather.py --help` to list them.

The script only reads from the Management API (`GET` requests). It does not verify the XML signature itself; it compares the certificate embedded in the response with the stored one.

References to Other Documentation:

SAML-Based Authentication and Authorization (MarkLogic 12 Security Guide)
<https://docs.progress.com/bundle/marklogic-server-secure-12/page/topics/external-security/saml-based-authentication-and-authorization.html>

PUT /manage/v2/groups/[id-or-name]/properties (MarkLogic 12 REST reference)
<https://docs.marklogic.com/12.0/REST/PUT/manage/v2/groups/[id-or-name]/properties>

MarkLogic article(s):
- How to gather OAuth authentication diagnostics
- How to gather LDAP authentication diagnostics
- How to gather HTTPS app server diagnostics
- How to gather client certificate login diagnostics

## Internal Comments
*(manual entry)*

## Article Category
Product Group: MarkLogic\
Area of Interest: Security

## Keyword Phrase
MarkLogic SAML authentication troubleshooting must gather trace events SAML Response External Authenticate external security Management API 401 403 IdP certificate role external name ml-security-gather.py ml-trace-events.py

## Admin Ticket ID
*(fill in if applicable)*
