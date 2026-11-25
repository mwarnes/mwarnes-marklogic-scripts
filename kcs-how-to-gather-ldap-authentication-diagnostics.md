<!--
KCS ARTICLE — How-To (framed as Problem/Solution per template constraints)
Paste each section below into the matching Salesforce field.
-->

## Title
How to gather LDAP authentication diagnostics

## URL Name
how-to-gather-ldap-authentication-diagnostics

## Summary
Collect the LDAP profile, certificates, directory server TLS, user and role external names and logs for a MarkLogic LDAP login that fails.

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
Which information does MarkLogic Support need to diagnose an LDAP authentication problem, and how is it collected easily and safely?

Typical situations are a login that is refused, a user who authenticates but receives no roles, a directory connection that fails over LDAPS or StartTLS, or an LDAP configuration that stopped working after an upgrade or a certificate change at the directory.

## Steps to Reproduce
N/A — this article is a configuration procedure, not a defect.

## Clarifying Information
**Environment details:** The script was verified on MarkLogic 12.1.0 and 11.3.7: reading an LDAP profile (the bind password is removed from the output) and checking a 389 Directory Server's LDAPS chain, host name and expiry. When a CA certificate is stored in the profile, the script can verify the chain from the machine running the gather against it. It can report possible matches between the chain and MarkLogic's CA-list metadata, but cannot verify MarkLogic's actual trust path from the Management API. The LDAP trace messages in the table below and the login outcomes were checked with the script on both releases against a 389 Directory Server (working and failing configurations: wrong port, host that does not resolve, wrong search account, StartTLS off, LDAPS on the wrong port). Active Directory was not tested.

- A `401` means the login was refused: the reason is in the `ErrorLog.txt` LDAP trace lines. A `403` after a successful login means the user was authenticated but lacks a role or privilege for the URL; this is in the app server access log, not in `ErrorLog.txt`.
- `External authentication failed: user=` lines with no user name are logged for the first request, before a session exists, and are normal.
- A CA certificate stored in the profile can be used to verify the directory's TLS chain from the gather machine. If no CA is stored, a possible match in MarkLogic's CA-list metadata is diagnostic only; the script cannot determine from that match whether MarkLogic trusts the directory's chain.
- A plain `ldap://` connection without StartTLS sends the bind password and user names in clear text; the script warns about it.
- The trace goes to `ErrorLog.txt` at `Info` level, so no change to the file log level is needed. A 389 Directory Server buffers its access log by default, so recent entries can be missing from it.

## Error Message
N/A

## Defect Number
N/A

## Enhancement Number
N/A

## Cause
N/A

## Resolution
Two scripts are attached to this article: `ml-security-gather.py` (read-only collection; the first argument selects the area, here `ldap`) and `ml-trace-events.py` (switches trace events on and off; it works for any trace event). Both need `python3`, `curl` and `openssl` on the machine that runs them and network access to the Management API (default port 8002). Run the script as a MarkLogic user with the `admin` role: the user `admin` or another administrator account (`--user <name>`, or the `MARKLOGIC_USER` environment variable). Reading the security configuration, users, roles and logs needs administrator access; the script was verified only with the user `admin`. The password is read from the `MARKLOGIC_PASS` environment variable (or asked for on a terminal) and never from the command line. Add `--scheme http` if the Management API port does not use TLS, and `--cacert <ca.pem>` (or `--insecure` for a one-off test) if its certificate is not trusted from the machine running the script.

1. Switch on the trace events for the group that holds the affected app server.

   ```
   export MARKLOGIC_PASS='<password>'
   python3 ml-trace-events.py enable --host ml1.example.com --user admin --group Default --preset ldap
   ```

   The `ldap` preset enables `External Authenticate`, `LDAP` and `LDAP Search`. Use `status` instead of `enable` to list what is on, and `--dry-run` to preview the change. Trace output goes to `ErrorLog.txt` at `Info` level; no change to the file log level is needed.

   Admin Interface: **Groups** → the group → **Diagnostics** → **Trace Events**, then add the events and activate trace events.

   Management API alternative (a `PUT` replaces the whole event list, so include any events that are already enabled; event names are not validated):

   ```
   curl --anyauth -u admin -X PUT -H "Content-Type: application/json" \
     -d '{"events-activated": true, "event": ["External Authenticate", "LDAP", "LDAP Search"]}' \
     "https://ml1.example.com:8002/manage/v2/groups/Default/properties"
   ```

2. Reproduce one failed login and note the time in UTC just before the attempt (`date -u +%Y-%m-%dT%H:%M:%SZ`). Use a user that has not logged in recently: a result is cached for `cache-timeout` seconds (and a failure for `ldap-negative-cache-timeout`), and a retry within that window can produce no trace lines.

3. Collect the configuration, the directory server's TLS and the logs. Substitute the host, the name of the LDAP external security profile, the MarkLogic user the login maps to and a start time a few minutes before the test.

   ```
   python3 ml-security-gather.py ldap --host ml1.example.com --user admin \
     --external-security example-ldap-profile \
     --user-name alice \
     --logs --start 2026-01-15T09:00:00Z
   ```

   - Only `--host` and `--user` are required. Anything left out is skipped and listed under **Not collected** in `SUMMARY.md`, so a partial run is still useful. `python3 ml-security-gather.py ldap --help` prints the full documentation, and it is printed again when an option is wrong or missing.
   - `--external-security <name>` reads that one profile (shown in the Admin Interface under **Security** → **External Security**, or with `curl --anyauth -u admin "https://ml1.example.com:8002/manage/v2/external-security?format=json"`). Without it every LDAP profile is read.
   - `--logs` adds the ErrorLog and the app server access log for a time window in UTC. Give the window with `--start <UTC time>` (the time noted before the test, from `date -u +%Y-%m-%dT%H:%M:%SZ`; accepted forms are `2026-01-15T09:00:00Z`, `2026-01-15T09:00Z`, `2026-01-15 09:00:00` (no zone means UTC) and a date alone, or a time with an offset such as `2026-01-15T10:00:00+01:00`, which is converted to UTC), or with `--minutes <n>` for the last n minutes counted back from now (default 60; run the gather within n minutes of the test). `--end` is optional (default: now). Without `--logs` only the configuration is collected.
   - `--appserver <name>` also checks that this app server uses the profile (and names one that has no external security profile attached); `--group <name>` gives the group of that app server when its name is not unique.
   - `--user-name <user>` (repeatable) adds the user's external names, roles and privileges, and the external names of roles.
   - The directory server's TLS (LDAPS, or StartTLS when the profile asks for it) is checked from the machine that runs the script, which may see a different network and trust store than the MarkLogic hosts. `--no-probe` skips this connection.
   - The script does not bind or search the directory, so it needs no directory credentials.

   The script writes a folder `ldap-gather-<timestamp>` with `SUMMARY.md`, redacted JSON of each call and filtered logs, plus a `.zip` beside the folder. The gather itself is read-only. This procedure temporarily changes group trace settings; disable them after the test.

4. Switch the trace events off again, and confirm.

   ```
   python3 ml-trace-events.py disable --host ml1.example.com --user admin --group Default --preset ldap
   python3 ml-trace-events.py status  --host ml1.example.com --user admin --group Default
   ```

   `disable` removes only the named events and switches the trace mechanism off only if the script switched it on.

5. Open `SUMMARY.md`, then inspect every file in the output directory and `.zip` before sharing it. The report can contain host names, URLs, certificate details and user names. Known credential fields and token forms are redacted on a best-effort basis, not guaranteed removed; inspect for residual sensitive data and remove it before attaching the archive. Query strings are removed from the access log.

What `SUMMARY.md` contains and why:

| Section | What it shows |
| --- | --- |
| Version, hosts | MarkLogic version and host names |
| LDAP profile | Server URI, base, attribute, bind method, default user, authorization mode (the bind password is never read out) |
| Certificates in the profile | Subject, issuer, expiry, fingerprints and chain of any certificate stored in the profile |
| Directory server | The certificate chain the directory presents, host name match, expiry, verification from the gather machine against a CA stored in the profile, possible matches against MarkLogic's CA-list metadata (not verified trust), or a note that the connection is not encrypted |
| App servers | Which app servers use the profile |
| Users, roles | The user's external names, roles, role external names and privileges |
| Trace events, ErrorLog | Whether the LDAP trace is on, each message and error, grouped |
| AccessLog | HTTP status codes of the app server in the window |
| Not collected | Any part that was skipped, why, and which option adds it |
| Check results | PASS, WARN, FAIL and INFO lines, most serious first |

How to read the result. Start from the first `FAIL` line in **Check results**; it quotes the log message. Common messages:

| Message in `ErrorLog.txt` | Usual meaning |
| --- | --- |
| `ldapAuthenticate() fail because authentication failure` | MarkLogic did not get a valid bind: wrong password or default user DN, or a bind method that does not support password login. |
| `ldapAuthenticate() fail because no LDAP user` | The bind worked but the search found no entry: check `ldap-base` and `ldap-attribute` with the exact user name. |
| `certificateAuthenticate() fail because no user` | Client certificate authentication found no MarkLogic user whose external name equals the DN shown. See "How to gather client certificate login diagnostics". |
| `externalAuthenticate failed because no external security is configured` | The app server needs an external security profile and none is selected. |
| `ldapAuthenticate() pass <user>` | LDAP authentication passed and identified the user; check the configured authorization mode and role mapping separately. |

With authorization `internal`, the LDAP user is matched to a MarkLogic user's external name; with `ldap`, the user's group DNs are matched to the external names of roles. The directory server's own access log shows whether MarkLogic arrived and how the bind was answered (`err=0` or `err=49` on a 389 Directory Server).

A profile with authentication `certificate` and authorization `ldap` (client certificate login with roles from LDAP groups) is also read by this area (use `--external-security <profile>`: it shows the directory's TLS chain, any verification against a CA stored in the profile, possible CA-list matches that do not establish MarkLogic trust, and the group DN to role mapping), but the DN lookup is checked by the `certificate` area. Follow "How to gather client certificate login diagnostics" for that case and switch on the `certificate` and `ldap` trace presets together.

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
- How to gather OAuth authentication diagnostics
- How to gather HTTPS app server diagnostics
- How to gather client certificate login diagnostics

## Internal Comments
*(manual entry)*

## Article Category
Product Group: MarkLogic\
Area of Interest: Security

## Keyword Phrase
MarkLogic LDAP authentication troubleshooting must gather trace events External Authenticate LDAP Search external security LDAPS StartTLS directory server certificate external name Management API ml-security-gather.py ml-trace-events.py

## Admin Ticket ID
*(fill in if applicable)*
