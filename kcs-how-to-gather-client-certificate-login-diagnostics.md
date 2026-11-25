<!--
KCS ARTICLE — How-To (framed as Problem/Solution per template constraints)
Paste each section below into the matching Salesforce field.
-->

## Title
How to gather client certificate login diagnostics

## URL Name
how-to-gather-client-certificate-login-diagnostics

## Summary
Collect app server TLS settings, selected client CAs, DN mapping, LDAP lookup and logs for a MarkLogic client certificate login that fails.

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
Which information does MarkLogic Support need to diagnose a client certificate authentication problem, with authorization `internal` or `ldap`, and how is it collected easily and safely?

Typical situations are a client that is refused in the TLS handshake (`unknown ca`, `certificate expired`, `unsupported certificate`), a certificate that passes TLS but ends with HTTP `401 Unauthorized`, a login that succeeds but ends with HTTP `403 Forbidden` because no role is granted, or a configuration that stopped working after a certificate renewal, a change of the issuing CA or a change in the directory. With authorization `ldap` the roles come from the user's LDAP groups, so the directory side is part of the diagnosis.

## Steps to Reproduce
N/A — this article is a configuration procedure, not a defect.

## Clarifying Information
**Environment details:** The procedure and the report were verified on MarkLogic 11.3.7 and 12.1.0 with HTTPS app servers using authentication `certificate`, with authorization `internal` and with authorization `ldap` (389 Directory Server), against working and failing configurations: unselected or expired CA, expired certificate, serverAuth-only key usage, certificate DN without a matching external name, reversed DN, missing entry, wrong LDAP attribute, wrong search account password, wrong LDAP port, LDAP host that does not resolve. Active Directory was not tested.

- MarkLogic matches the **full subject DN** of the client certificate, in the order stored in the certificate, to the external name of a MarkLogic user. A user whose external name is only the CN does not match. `openssl` prints the DN in reverse (RFC 2253) order; the report shows both.
- This needs an external security profile with authentication `certificate` selected on the app server. Without a profile MarkLogic looks for a user whose **name** equals the CN of the certificate subject, and external names are not used (tested on 11.3.7 and 12.1.0).
- A certificate rejected in the TLS handshake (no certificate, expired, not yet valid, serverAuth-only usage, issuing CA not selected) leaves **nothing** in the ErrorLog or AccessLog. The cause comes from the app server settings and the certificate itself. Only a certificate that passes TLS and maps to no user (`certificateAuthenticate() fail because no user`) and a successful login are logged.
- The issuing CA must be among the **selected** client CAs of the app server (`ssl-client-certificate-authority`); being trusted by MarkLogic is not enough. With `ssl-client-issuer-authority-verification` false every CA up to the root must be selected; with true the issuing CA alone is enough.
- With authorization `ldap` MarkLogic does not match an external name. It binds as the search account and runs a **base-scope search whose base is the certificate's subject DN exactly as stored**, reads the attribute named in `ldap-attribute`, and maps the user's `memberOf` group DNs to the external names of roles. `ldap-base` is not used for this lookup. A certificate whose DN is stored general-first (`DC=com,DC=example,...`, typical of enterprise CAs) is searched as is and fails.
- `certificateAuthenticate() fail because unknown user, dn <DN>` is written for four different causes: the DN is reversed or wrong, the entry does not exist, the entry lacks the attribute named in `ldap-attribute` (for example `sAMAccountName` on a non-Active-Directory entry), or the search account cannot read the entry. Only the directory's access log tells them apart. A bad search-account password adds `XDMP-LDAP-INVALID-CRED ... (49)`.
- A user who authenticates but is in no group that maps to a role is logged as `certificateAuthenticate() pass ... temp true` and then receives HTTP `403`.
- Results are cached for `cache-timeout` seconds per profile (a failure for the negative cache timeout), so a directory change shows only after that time. Set `cache-timeout` to 1 while testing and back afterwards.
- MarkLogic 11.3.7 does not serve TLS 1.3. With every TLS 1.2 and older version disabled (`ssl-disable-*`), no client can connect and the report says so. On MarkLogic 12, `ssl-min-allow-tls` TLSv1.3 excludes clients that offer only TLS 1.2.
- The script never queries the directory and never prints the search account's password. It prints the `ldapsearch` and `ldapwhoami` commands to run.

## Error Message
```
certificateAuthenticate() fail because no user, dn <subject DN>
certificateAuthenticate() fail because unknown user, dn <subject DN>
externalAuthenticate failed because no external security is configured
```
The lines appear in `ErrorLog.txt` with the `External Authenticate` trace event on (the second needs authorization `ldap`; the third appears when the app server has no external security profile and the CN of the certificate matches no user). The client receives HTTP `401 Unauthorized`.

## Defect Number
N/A

## Enhancement Number
N/A

## Cause
N/A

## Resolution
Two scripts are attached to this article: `ml-security-gather.py` (read-only collection; the first argument selects the area, here `certificate` and, for authorization `ldap`, also `ldap`) and `ml-trace-events.py` (switches trace events on and off). Both need `python3`, `curl` and `openssl` on the machine that runs them and network access to the Management API (default port 8002) and to the app server port. Run the script as a MarkLogic user with the `admin` role: the user `admin` or another administrator account (`--user <name>`, or the `MARKLOGIC_USER` environment variable). The password is read from the `MARKLOGIC_PASS` environment variable (or asked for on a terminal) and never from the command line. Add `--scheme http` if the Management API port does not use TLS, and `--cacert <ca.pem>` (or `--insecure` for a one-off test) if its certificate is not trusted from the machine running the script.

1. Switch on the trace events for the group that holds the affected app server. With authorization `internal` the `certificate` preset is enough; with authorization `ldap` also enable the `ldap` preset (`LDAP`, `LDAP Search`).

   ```
   export MARKLOGIC_PASS='<password>'
   python3 ml-trace-events.py enable --host ml1.example.com --user admin --group Default --preset certificate
   python3 ml-trace-events.py enable --host ml1.example.com --user admin --group Default --preset ldap
   ```

   The `certificate` preset enables `External Authenticate`; the `ldap` preset enables `External Authenticate`, `LDAP` and `LDAP Search`. Use `status` instead of `enable` to list what is on, and `--dry-run` to preview the change. Trace output goes to `ErrorLog.txt` at `Info` level; no change to the file log level is needed.

   Admin Interface: **Groups** → the group → **Diagnostics** → **Trace Events**, then add the events and activate trace events.

   Management API alternative (a `PUT` replaces the whole event list, so include any events that are already enabled; event names are not validated):

   ```
   curl --anyauth -u admin -X PUT -H "Content-Type: application/json" \
     -d '{"events-activated": true, "event": ["External Authenticate", "LDAP", "LDAP Search"]}' \
     "https://ml1.example.com:8002/manage/v2/groups/Default/properties"
   ```

2. Reproduce one failed login with the client certificate and note the time in UTC just before the attempt (`date -u +%Y-%m-%dT%H:%M:%SZ`). Use a client that has not logged in recently, because a result is cached for `cache-timeout` seconds. For a handshake failure, note the client-side error (for example `curl -v --cert client.pem --key client.key https://ml1.example.com:8012/`): the TLS alert is the only evidence.

3. Optional but valuable: save the **public** client certificate, and the certificate chain of its issuers, to PEM files, for example `client.pem` and `ca-chain.pem`. A file that contains a private key is refused by the script. To extract the certificate from a combined file: `openssl x509 -in combined.pem -out client.pem`.

4. Collect the app server settings, the certificate checks and the logs. Substitute the host, the app server name and a start time a few minutes before the test.

   ```
   python3 ml-security-gather.py certificate --host ml1.example.com --user admin \
     --appserver example-app \
     --client-cert client.pem --client-chain ca-chain.pem \
     --logs --start 2026-01-15T09:00:00Z
   ```

   - Only `--host` and `--user` are required. Anything left out is skipped and listed under **Not collected** in `SUMMARY.md`, so a partial run is still useful. `python3 ml-security-gather.py certificate --help` prints the full documentation.
   - `--appserver <name>` checks that app server (without it every app server with authentication `certificate` is checked); `--group <name>` gives its group.
   - `--client-cert` and `--client-chain` add the checks of the certificate itself: validity, key usage, whether its issuer is selected on the app server, and the DN to user mapping.
   - `--server-ca <ca.pem>` verifies the certificate the app server presents against a private CA; `--probe-host <name>` connects to another host name (for example a load balancer); `--no-probe` skips every connection from this machine.
   - `--logs` adds the ErrorLog lines and the status codes of the app server access log for a time window in UTC. Give the window with `--start <UTC time>` (accepted forms are `2026-01-15T09:00:00Z`, `2026-01-15 09:00:00` (no zone means UTC), a date alone, or a time with an offset such as `+01:00`, which is converted to UTC), or with `--minutes <n>` for the last n minutes (default 60). `--end` is optional (default: now).

   The script writes a folder `certificate-gather-<timestamp>` with `SUMMARY.md`, redacted JSON of each call and filtered logs, plus a `.zip` beside the folder. The gather itself is read-only. This procedure temporarily changes group trace settings and may change `cache-timeout`; restore both after the test.

5. With authorization `ldap`, also collect the directory side from the external security profile named in the app server settings.

   ```
   python3 ml-security-gather.py ldap --host ml1.example.com --user admin \
     --external-security certificate-ldap-profile \
     --appserver example-app \
     --logs --start 2026-01-15T09:00:00Z
   ```

   The `ldap` area reads a profile with authentication `certificate` when it is named with `--external-security` (it notes that this is a certificate profile). It adds the directory server's TLS chain (LDAPS or StartTLS), verification from the gather machine against a CA stored in the profile, possible matches against MarkLogic's CA-list metadata (not verified trust), and the group DN to role external name mapping. The `certificate` area already checks that the directory host resolves and that its port answers, and prints the DN as MarkLogic searches it. Neither area binds to or searches the directory. Run the printed `ldapsearch` command against the directory, once as the search account and once as an administrator, to tell the four `unknown user` causes apart, and attach the directory's access log lines for the test (a 389 Directory Server buffers its access log by up to a minute).

6. Switch the trace events off again, and confirm.

   ```
   python3 ml-trace-events.py disable --host ml1.example.com --user admin --group Default --preset certificate
   python3 ml-trace-events.py disable --host ml1.example.com --user admin --group Default --preset ldap
   python3 ml-trace-events.py status  --host ml1.example.com --user admin --group Default
   ```

   `disable` removes only the named events and switches the trace mechanism off only if the script switched it on. Set `cache-timeout` of the profile back to its previous value.

7. Open `SUMMARY.md`, then inspect every file in the output directory and `.zip` before sharing it. The report can contain host names, certificate details, distinguished names and user names. Known credential fields and token forms are redacted on a best-effort basis, not guaranteed removed; inspect for residual sensitive data and remove it before attaching the archive. Query strings are removed from the access log.

What `SUMMARY.md` contains and why:

| Section | What it shows |
| --- | --- |
| Version, hosts | MarkLogic version and host names |
| App server settings | Authentication, external security profile, certificate template, TLS protocols, whether a client certificate is required, issuer verification |
| Selected client CAs | Subject, issuer and expiry of each CA selected on the app server |
| Client certificate | Validity, key usage, issuer selected, subject DN in stored and RFC 2253 order, mapping to a user |
| External security profile | Authorization mode and, for `ldap`, the LDAP settings, how the DN is searched and the `ldapsearch` command to run |
| Server certificate | The chain the port presents, host name match, expiry, negotiated protocol |
| Users, roles | External names of users and the roles' external names (group DNs) |
| Trace events, ErrorLog | Whether the trace is on, each message and error, grouped, with a hint |
| AccessLog | HTTP status codes of the app server in the window |
| Not collected | Any part that was skipped, why, and which option adds it |
| Check results | PASS, WARN, FAIL and INFO lines, most serious first |

How to read the result. Start from the conclusion in the first lines of `SUMMARY.md`, then the first `FAIL` line in **Check results**. Common findings:

| Finding | Usual meaning and fix |
| --- | --- |
| Issuer not selected (TLS alert `unknown ca`) | The CA that signed the client certificate is not among the selected client CAs. Select it; with issuer verification false select every CA up to the root. |
| Certificate expired or not yet valid (alert `certificate expired`) | The client certificate or a selected CA is outside its validity. |
| Key usage lacks `clientAuth` (alert `unsupported certificate`) | The certificate is issued for server authentication only. Reissue it with `clientAuth`. |
| Subject DN has no matching external name | No user has the DN as external name. The external name must equal the full DN in the stored order; a CN alone, a different case of the type names, an extra or missing RDN or a blank do not match. |
| No external security profile on the app server | Only a user named like the CN can log in. Create a profile with authentication `certificate` and select it. |
| A client certificate is not required (INFO) | `ssl-require-client-certificate` is false: a client without a certificate gets HTTP `401` instead of a TLS failure. |
| No TLS version is usable (FAIL) / only TLS 1.3 allowed (WARN) | Protocol settings exclude the client. Enable TLS 1.2 (MarkLogic 11 has no TLS 1.3). |
| Certificate DN stored general-first (FAIL, authorization `ldap`) | MarkLogic searches the string as stored, which cannot exist in the directory. Have the CA issue the certificate with the DN in directory order (most specific first). |
| `ldap-attribute` while the DN starts with `uid=` (WARN) | The entry may lack that attribute; use an attribute the entry has. |
| LDAP host does not resolve, or the port does not answer (FAIL) | MarkLogic cannot reach the directory: correct `ldap-server-uri` (389 for LDAP and StartTLS, 636 for LDAPS) and the network. |
| LDAP connection is not encrypted (WARN) | A plain `ldap://` URI without StartTLS sends the search account's password in clear text. |
| No role external name is a group DN (WARN) | The user gets no roles. Give a role the full DN of a group the user belongs to as external name. |

| Message in `ErrorLog.txt` | Usual meaning |
| --- | --- |
| `certificateAuthenticate() fail because no user, dn <DN>` | Authorization `internal`: no user has that DN as external name. |
| `certificateAuthenticate() fail because external name` | The user was identified but the external name does not match exactly. |
| `certificateAuthenticate() fail because unknown user, dn <DN>` | Authorization `ldap`: the base search of that DN found no usable entry (four causes above). |
| `XDMP-LDAP-INVALID-CRED ... (49)` | The search account's DN or password was refused. |
| `LDAP user <DN> not found in ldapUserCache` | The DN string MarkLogic searches for (trace events `LDAP` and `LDAP Search`). |
| `certificateAuthenticate() pass ... temp true` followed by HTTP `403` | The certificate was accepted but the user has no role or privilege for the URL. |
| `externalAuthenticate failed because no external security is configured` | The app server has no external security profile. |

## Workaround
N/A — this article describes a diagnostic procedure.

## Notes
The `ErrorLog` can be searched by time window through the Management API; the app server access log cannot (`MANAGE-CANNOTSEARCH`), so the script reads the access log of the app server whole and filters it by time. Log times are in each host's local time zone and the script's window is UTC; widen the window with `--start` and `--end` if a host is not on UTC. Rotated log files (for example `8012_AccessLog_1.txt`) are not read.

The ErrorLog does not say which app server a line belongs to: if several app servers use external security within the window, reproduce one login at a time and keep the window small. Request the rotated files, the access log of any other port, or the full ErrorLog separately when they are needed.

The same script has the areas `saml`, `oauth`, `ldap`, `https` and `certificate`, with the same connection and log options; run `python3 ml-security-gather.py --help` to list them.

References to Other Documentation:

PUT /manage/v2/groups/[id-or-name]/properties (MarkLogic 12 REST reference)
<https://docs.marklogic.com/12.0/REST/PUT/manage/v2/groups/[id-or-name]/properties>

MarkLogic article(s):
- How to gather SAML authentication diagnostics
- How to gather OAuth authentication diagnostics
- How to gather LDAP authentication diagnostics
- How to gather HTTPS app server diagnostics

## Internal Comments
*(manual entry)*

## Article Category
Product Group: MarkLogic\
Area of Interest: Security

## Keyword Phrase
MarkLogic client certificate authentication troubleshooting must gather mutual TLS two-way SSL external security certificate LDAP authorization subject DN external name client CA unknown ca trace events External Authenticate Management API 401 403 ml-security-gather.py ml-trace-events.py

## Admin Ticket ID
*(fill in if applicable)*
