<!--
KCS ARTICLE — How-To (framed as Problem/Solution per template constraints)
Paste each section below into the matching Salesforce field.
-->

## Title
How to gather HTTPS app server diagnostics

## URL Name
how-to-gather-https-app-server-diagnostics

## Summary
Collect the TLS settings, certificate template status, served certificate chain and logs for a MarkLogic HTTPS app server with a certificate or TLS problem.

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
Which information does MarkLogic Support need to diagnose a certificate or TLS problem on an HTTPS app server, and how is it collected easily and safely?

Typical situations are clients that do not trust the certificate the app server presents, a handshake that fails before any certificate is sent, a temporary certificate that is still in use, a certificate that does not match the host name or has expired, a missing intermediate certificate, or warnings about duplicate certificate subjects in the ErrorLog.

## Steps to Reproduce
N/A — this article is a configuration procedure, not a defect.

## Clarifying Information
**Environment details:** The script and the findings in this article were verified on MarkLogic 12.1.0 and 11.3.7 with HTTPS app servers using templates with a MarkLogic-generated temporary certificate, certificates signed by a private CA chain, and a Let's Encrypt certificate (ECDSA, imported with a Certbot deploy hook). The Let's Encrypt chain fix was tested on 12.1.0 only.

- MarkLogic 12 names the TLS settings `ssl-min-allow-tls` and `ssl-ciphersuites` (TLS 1.3); MarkLogic 11.3.7 uses the `ssl-disable-*` flags and has no TLS 1.3 setting. The report shows the allowed range for both. In the test, the 11.3.7 app server refused TLS 1.3.
- The Management API reports whether a template's certificate is temporary: `GET /manage/v2/certificates/<id>` (host certificates) and `GET /manage/v2/certificate-authorities/<id>` (authorities, including the temporary one) return `temporary`, `template-id` and `template-version`. There is no template status resource.
- The client certificate authorities selected on an app server (`ssl-client-certificate-authority`, used for client certificate authentication) are part of the app server's properties and are read by the `certificate` area, not by this one: see "How to gather client certificate login diagnostics".
- MarkLogic logs `Duplicate certificate subject found in Security Database` as a Warning, always in pairs. On both test servers one pair was the old VeriSign certificates that are part of the default certificate authority list, and the other was a host certificate held by two templates (an RSA and an EC template for one host name). On one server the same key also appeared twice under `ISRG Root X2` (the self-signed root and its cross-signed copy). These cases are harmless; a warning is raised only when different keys share one subject. What triggers the log line was not found.
- The names in the certificate authority list are the **issuer's** name, not the certificate's own: an imported intermediate is listed under its root's name, so a name such as `DigiCert Global Root CA` can appear several times for different certificates. The report shows list name against real subject.
- A TLS handshake test from `openssl s_client` prints `Protocol: TLSv1` even when the handshake fails; a negotiated cipher is what shows that a version was accepted.

## Error Message
N/A

## Defect Number
N/A

## Enhancement Number
N/A

## Cause
N/A

## Resolution
The script `ml-security-gather.py` is attached to this article (read-only collection; the first argument selects the area, here `https`). It needs `python3`, `curl` and `openssl` on the machine that runs it and network access to the Management API (default port 8002) and to the app server port. Run the script as a MarkLogic user with the `admin` role: the user `admin` or another administrator account (`--user <name>`, or the `MARKLOGIC_USER` environment variable). Reading the security configuration, users, roles and logs needs administrator access; the script was verified only with the user `admin`. The password is read from the `MARKLOGIC_PASS` environment variable (or asked for on a terminal) and never from the command line. Add `--scheme http` if the Management API port does not use TLS, and `--cacert <ca.pem>` (or `--insecure` for a one-off test) if its certificate is not trusted from the machine running the script.

1. Collect the TLS settings, the certificate status and what the port really serves. Substitute the host and the app server name; without `--appserver` every app server that has a certificate template is checked.

   ```
   export MARKLOGIC_PASS='<password>'
   python3 ml-security-gather.py https --host ml1.example.com --user admin \
     --appserver example-app \
     --logs --start 2026-01-15T09:00:00Z
   ```

   - Only `--host` and `--user` are required. Anything left out is skipped and listed under **Not collected** in `SUMMARY.md`. `python3 ml-security-gather.py https --help` prints the full documentation, and it is printed again when an option is wrong or missing.
   - The certificate and protocols are read by connecting to the app server port from the machine that runs the script. To see what clients see, run the script from a client machine; `--probe-host <name>` connects to another host name (for example a load balancer), and `--no-probe` skips the connection.
   - `--server-ca <ca.pem>` verifies the served certificate against a private CA instead of this machine's trust store; without it the report says whether this machine trusts the certificate, which is not MarkLogic's trust decision. For client certificate authentication the same option is available in the `certificate` area.
   - `--logs` adds the ErrorLog lines about certificates and TLS and the status codes of the app server access log for a time window in UTC. Give the window with `--start <UTC time>` (the time noted before the test, from `date -u +%Y-%m-%dT%H:%M:%SZ`; accepted forms are `2026-01-15T09:00:00Z`, `2026-01-15T09:00Z`, `2026-01-15 09:00:00` (no zone means UTC) and a date alone, or a time with an offset such as `2026-01-15T10:00:00+01:00`, which is converted to UTC), or with `--minutes <n>` for the last n minutes counted back from now (default 60; run the gather within n minutes of the test). `--end` is optional (default: now). Without `--logs` only the configuration is collected.

   The script writes a folder `https-gather-<timestamp>` with `SUMMARY.md`, redacted JSON of each call and filtered logs, plus a `.zip` beside the folder. The gather is read-only and does not change server settings. No trace events are needed for this area.

2. Open `SUMMARY.md`, then inspect every file in the output directory and `.zip` before sharing it. The report can contain host names, URLs, certificate details and user names. Known credential fields and token forms are redacted on a best-effort basis, not guaranteed removed; inspect for residual sensitive data and remove it before attaching the archive. Query strings are removed from the access log.

What `SUMMARY.md` contains and why:

| Section | What it shows |
| --- | --- |
| Version, hosts | MarkLogic version and host names |
| App server settings | Authentication, certificate template, allowed TLS protocols, ciphers, client certificate requirement (MarkLogic 12 and 11 name these settings differently; the report shows both the same way) |
| Template certificate status | For each template, whether its certificate is **TEMPORARY** (generated by MarkLogic, self-signed) or **PERMANENT** (signed by a certificate authority), who signed it, expiry, serial and template version |
| Certificate served | The chain the port sends, host name match, expiry, negotiated protocol and cipher, whether the served certificate is the template's certificate, which protocol versions this machine can negotiate |
| Security database certificates | Certificates that share a subject (what each group is), and list names that differ from the certificate's subject |
| Trace and log lines | ErrorLog lines about certificates and TLS, with a meaning for each |
| Not collected | Any part that was skipped, why, and which option adds it |
| Check results | PASS, WARN, FAIL and INFO lines, most serious first |

How to read the result. Start from the first `FAIL` line in **Check results**. Common findings and the usual fix:

| Finding | Usual meaning and fix |
| --- | --- |
| `certificate is TEMPORARY` | Only the self-signed certificate that MarkLogic generated exists. Clients do not trust it and its name rarely matches the host. Generate a certificate request on the template, have it signed by a certificate authority and import the signed certificate. |
| `certificate present` fails or warns, handshake fails before a certificate is sent, ErrorLog `Failed to find server certificate in certificate template <id>` | The template holds no certificate. A template created through the Management API has none until a certificate is generated or imported. |
| `server sends only its own certificate` | The intermediate is not sent, so clients that do not have it fail with `unable to verify the first certificate`. MarkLogic sends the chain it can build from its trusted certificate authorities: import the issuing CA certificate there (see Resolution below). |
| `certificate matches host name` fails | The name used to connect is not in the certificate's subject alternative names or common name. |
| `the port does not serve a certificate of its template` | The served serial is not one of the template's: the app server may need a restart after the certificate was replaced, or the port is behind a proxy or load balancer. |
| `certificate expired` or `expires soon` | A certificate in the template or in the served chain is at or near its expiry. |
| `TLSv1 is accepted` or `TLSv1.1 is accepted` | Old protocol versions are accepted; the app server's minimum should be TLS 1.2. |
| `certificate was issued for template version N` (INFO) | The template changed after the certificate was issued; the certificate may not reflect its current subject or key settings. |

To serve the intermediate, import the issuing CA certificate once per issuing CA, for example in Query Console against the **Security** database (for a Let's Encrypt certificate the intermediate is the second certificate in `fullchain.pem`):

Importing a CA into the Security database also changes the certificate authorities MarkLogic trusts for outgoing TLS connections and client-certificate checks. Confirm that the issuing CA is approved for those trust purposes before adding it.

```
xquery version "1.0-ml";
import module namespace pki = "http://marklogic.com/xdmp/pki" at "/MarkLogic/pki.xqy";
let $pem := '-----BEGIN CERTIFICATE-----
...paste the intermediate certificate here...
-----END CERTIFICATE-----'
return pki:insert-trusted-certificates($pem)
```

The function returns the certificate ID (`pki:delete-certificate(<id>)` removes it again). The port then sends the leaf and the intermediate at once, without a restart. Putting the intermediate into the certificate import itself does not work: `insert-host-certificates` accepts one certificate, and a bundle is rejected with HTTP 400 (`PKI-BADCERTIFICATE`). The client still needs the root in its own trust store; newer Let's Encrypt roots (for example `Root YE`) are missing from older trust stores, which then report `unable to get local issuer certificate` although the server chain is complete. Let's Encrypt signs each issuance with one of several intermediates (observed: `YE1` on one host and `YE2` on another), so import each issuing intermediate the first time it appears. To let clients that only trust an older root verify the chain, also import the cross-signed certificates between the intermediate and that root (for the new hierarchy: `Root YE` signed by `ISRG Root X2`, and `ISRG Root X2` signed by `ISRG Root X1`, both in `fullchain.pem`); MarkLogic then sends them as well (verified: the port sent leaf, `YE1`, `Root YE` and `ISRG Root X2`, and `curl` verified it).

## Workaround
N/A — this article describes a diagnostic procedure.

## Notes
The `ErrorLog` can be searched by time window through the Management API; the app server access log cannot (`MANAGE-CANNOTSEARCH`), so the script reads the access log of the bound app server whole and filters it by time. Log times are in each host's local time zone and the script's window is UTC; widen the window with `--start` and `--end` if a host is not on UTC. Rotated log files (for example `8012_AccessLog_1.txt`) are not read.

This area needs no trace events. The access log part covers only the app server given with `--appserver` (or every HTTPS app server), only the current log file (rotated files are not read), and the lines are saved without query strings; request the rotated files, the access log of any other port, or the full ErrorLog separately when they are needed.

The same script has the areas `saml`, `oauth`, `ldap`, `https` and `certificate`, with the same connection and log options; run `python3 ml-security-gather.py --help` to list them.

MarkLogic article(s):
- How to gather SAML authentication diagnostics
- How to gather OAuth authentication diagnostics
- How to gather LDAP authentication diagnostics
- How to gather client certificate login diagnostics

## Internal Comments
*(manual entry)*

## Article Category
Product Group: MarkLogic\
Area of Interest: Security

## Keyword Phrase
MarkLogic HTTPS app server TLS certificate template temporary certificate self-signed intermediate chain Let's Encrypt trusted certificate authorities duplicate certificate subject handshake ml-security-gather.py

## Admin Ticket ID
*(fill in if applicable)*
