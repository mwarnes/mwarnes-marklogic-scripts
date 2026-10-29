# Security must-gather: usage reference

This folder holds two read-only support tools, written for MarkLogic 11 and 12:

- `ml-security-gather.py`: collects what MarkLogic Support needs for a security problem, checks it for the usual mistakes
  and opens its report with a one-sentence conclusion.
- `ml-trace-events.py`: switches the trace events that the diagnosis needs on before a test and off afterwards.

Requirements: `python3` (standard library only), `curl` and `openssl`. Run both scripts from this folder. Host names below
are examples (`ml1.example.com`). Tests: `python3 -m unittest discover -s scripts/Security/tests`.

## Quick start

```
export MARKLOGIC_PASS='...'                       # never on the command line
ml-trace-events.py enable --host ml1.example.com --user admin --preset saml      # 1. trace on
#   2. reproduce the failing login (note the time)
ml-security-gather.py saml --host ml1.example.com --user admin --external-security <profile> \
    --user-name <user> --logs --minutes 15                                       # 3. gather
ml-trace-events.py disable --host ml1.example.com --user admin --preset saml     # 4. trace off
```

Open `SUMMARY.md` in the output folder first (its first lines are the conclusion), review it, then send the `.zip`.

## Areas

```
ml-security-gather.py AREA [options]       AREA = saml | oauth | ldap | https | certificate
ml-security-gather.py AREA --help          the options and examples of one area
```

| Area | Reads | Optional extras |
|---|---|---|
| `saml` | SAML profile, stored IdP/SP certificates, bound app servers, user/role external names | `--idp-metadata`, `--saml-response`, `--user-name`, `--logs` |
| `oauth` | OAuth profile (Resource server; Authorization code on MarkLogic 12), IdP discovery document, JWKS, IdP TLS chain and whether MarkLogic trusts it | `--token` (signature, issuer, expiry, claims, role mapping), `--user-name`, `--logs`, `--no-probe` |
| `ldap` | LDAP profile, its certificates, the directory server's TLS (LDAPS or StartTLS) and whether MarkLogic trusts it, the bound app server | `--appserver`, `--user-name`, `--logs`, `--no-probe` |
| `https` | App server TLS settings (MarkLogic 11 and 12 spell them differently), certificate template, TEMPORARY versus PERMANENT certificate, the chain the port really serves, host name, protocols | `--appserver`, `--server-ca`, `--probe-host`, `--logs`, `--no-probe` |
| `certificate` | App servers with authentication `certificate`: selected client CAs, issuer verification, external security profile (authorization `internal` or `ldap`), what the port asks for, the server certificate chain | `--appserver`, `--client-cert`, `--client-chain`, `--logs`, `--no-probe` |

A profile with authentication `certificate` and authorization `ldap` is read by the `certificate` area, which adds the LDAP checks
(DN order, search account, group mapping): see "Client certificate authentication" below.

## Options

Only `--host` and `--user` are required (`--user` defaults to the `MARKLOGIC_USER` environment variable; use `admin` or any
user with the admin role). Anything left out is skipped and listed in the **Not collected** table of `SUMMARY.md` with the option that adds it.

**Common to every area**

| Option | Default | Meaning |
|---|---|---|
| `--host HOST` | required | any host of the cluster |
| `--port PORT` | `8002` | Management API port |
| `--scheme http\|https` | `https` | Management API scheme (a lab without TLS on 8002 needs `--scheme http`) |
| `--user USER` | `$MARKLOGIC_USER` | MarkLogic user with the admin role |
| `--cacert CA.PEM` / `--insecure` | verify with the system CAs | CA bundle for the Management API certificate / do not verify it |
| `--out DIR` | `./<area>-gather-<timestamp>` | output directory |

**Logs (all areas)**

| Option | Default | Meaning |
|---|---|---|
| `--logs` | off | also read the ErrorLog (trace events) and the app server AccessLog for a time window |
| `--minutes N` | `60` | with `--logs`: how far back to look |
| `--start T` / `--end T` | now | window in UTC, e.g. `2026-01-15T09:00:00Z`; a time without a zone means UTC; an offset such as `+01:00` is converted; `--start` overrides `--minutes` |

**Profile selection and checks**

| Option | Areas | Meaning |
|---|---|---|
| `--external-security NAME` | saml, oauth, ldap | profile to read (default: every profile of the area) |
| `--user-name NAME` | saml, oauth, ldap | MarkLogic user to look up (its external names and roles); repeat for several |
| `--appserver NAME` | ldap, https, certificate | check this app server (https and certificate: default every matching app server; ldap: also check that it uses the profile) |
| `--group NAME` | ldap, https, certificate | group of that app server (default any) |
| `--no-probe` | oauth, ldap, https, certificate | do not connect from this machine to other servers (IdP, directory, app server port) |
| `--idp-metadata FILE\|URL` | saml | IdP metadata: compared with the stored IdP certificate and entity id |
| `--metadata-insecure` | saml | do not verify the TLS certificate of a metadata URL |
| `--saml-response FILE` | saml | a captured SAMLResponse (XML, base64 or an authorization header line) |
| `--token FILE` | oauth | a captured access token (JWT) or an `Authorization: Bearer` line: signature against the JWKS, issuer, client id, expiry, claims, role mapping |
| `--server-ca CA.PEM` | https, certificate | CA bundle for verifying the certificate the app server presents |
| `--probe-host HOST` | https, certificate | host name to connect to for the live TLS check (default `--host`) |
| `--client-cert CERT.PEM` | certificate | a PUBLIC client certificate (a file containing a private key is refused): validity, key usage, issuer selected, DN to user mapping |
| `--client-chain CHAIN.PEM` | certificate | intermediate and root certificates of the client certificate (public) |

Examples (one per area):

```
ml-security-gather.py saml --host ml1.example.com --user admin --external-security <profile> \
    --user-name <user> --idp-metadata https://idp.example.com/metadata --saml-response response.txt --logs
ml-security-gather.py oauth --host ml1.example.com --user admin --external-security <profile> --token token.txt --logs
ml-security-gather.py ldap --host ml1.example.com --user admin --external-security <profile> \
    --appserver <app server> --user-name <user> --logs
ml-security-gather.py https --host ml1.example.com --user admin --appserver <app server> --server-ca my-ca.pem
ml-security-gather.py certificate --host ml1.example.com --user admin --appserver <app server> \
    --client-cert client.pem --client-chain ca-chain.pem --logs
```

## Passwords and secrets

The MarkLogic password is read from `MARKLOGIC_PASS` (or asked for when a terminal is attached) and is never accepted on the command line.
Passwords, private keys, client secrets, whole JWTs and token-endpoint responses are removed before anything is written. The script never
prints the LDAP search account's password and never queries the directory (it prints the `ldapsearch` and `ldapwhoami` commands to run).
Review `SUMMARY.md` before sending anything: it contains host names, entity IDs, certificate details and user names. Nothing is changed on the server.

## Output files

`./<area>-gather-<timestamp>/` holds `SUMMARY.md` (the report), the raw JSON of each Management API call (`cluster.json`, `hosts-status.json`,
`external-security-*.json`, `servers-list.json`, `server-*.json`, `certificate-template-*.json`, `users-external-names.json`,
`roles-external-names.json`, ...), with `--logs` the filtered `ErrorLog-*.txt` and `AccessLog-*.txt` for the window, and a `.zip` of the folder.

## Reading the report

1. **Conclusion** (first lines): "All good" when no check failed or warned, "No failure found. N warning(s); look at: ..." for warnings only, or
   "Root cause to look at first: ..." for the first failure, followed by a one-sentence explanation. Later failures are often consequences of the first.
   A "Probable cause" line is a lead from the logs (an ErrorLog or HTTP 403 pattern) that the configuration checks cannot confirm.
   The conclusion also says how many parts were **not collected**: a verdict covers only what was collected.
2. **Settings tables** of the profile, app servers, certificates and the live TLS probe.
3. **Check results** near the end: every check as `PASS`, `WARN`, `FAIL` or `INFO` (a fact or a next step, not a verdict), failures first, each with the reason and the fix.
4. **Not collected**: what was skipped and the option that would add it.
5. **Log findings** (with `--logs`): the errors found in the window, each with a hint; lines that are normal for the flow are not counted as errors.

## Trace events (`ml-trace-events.py`)

```
ml-trace-events.py enable|disable|status --host ml1.example.com --user admin [--preset NAME | --event "Trace event" ...]
```

| Option | Default | Meaning |
|---|---|---|
| `--host`, `--user` | required | as above (`--user` defaults to `$MARKLOGIC_USER`) |
| `--port`, `--scheme`, `--cacert`, `--insecure` | `8002`, `https` | Management API connection |
| `--group NAME` | `Default` | group to change; run once per group if the app servers are in different groups |
| `--preset NAME` | none | a named set of events (below) |
| `--event NAME` | none | one trace event; repeat for several |
| `--dry-run` | off | show what would be sent |

| Preset | Events enabled | Used for |
|---|---|---|
| `saml` | SAML, SAML Response, External Authenticate | SAML logins |
| `oauth` | OAuth, OAuth Status, OAuth Communications, OAuth JSON Processing, External Authenticate | OAuth logins (both flows) |
| `ldap` | External Authenticate, LDAP, LDAP Search | LDAP logins and group lookups |
| `certificate` | External Authenticate | client certificate logins (add `ldap` events for authorization `ldap`) |

`enable` adds the events to the group and turns the trace mechanism on; `disable` removes only the named events and turns the mechanism off
again only if this script turned it on (recorded in `.ml-trace-events-state.json` in the current directory). Events that were already configured are never touched.
Trace events add log volume: disable them when finished. They are written to ErrorLog.txt at Info level. Set the profile's `cache-timeout` to 1 while
testing: results are cached per profile, so a change at the IdP or the directory otherwise shows only after the timeout (300 seconds by default).

## Known limits

- A client certificate rejected in the TLS handshake (no certificate, expired, wrong CA, wrong key usage) leaves nothing in MarkLogic's logs; the report explains the TLS alerts and the client-side command that shows them.
- MarkLogic returns the SAML SP private key encrypted, so the report cannot prove it belongs to the certificate: it prints the certificate's public-key SHA-256 and the openssl command that gives the same value for the key file.
- A refused LDAP bind (error 49) is logged the same way whether the search account or the user was refused; only the directory's access log tells the causes of `unknown user` apart.
- With an OAuth token the checks are static: a token is not requested and nothing is exchanged with the IdP beyond reading discovery and the JWKS.
- MarkLogic 11.3 cannot reach an IdP endpoint that needs TLS 1.3 or the extended master secret (`SVC-SOCCONN`), and does not serve TLS 1.3 itself.
- The script reads configuration and logs; it does not log in and it does not read the directory, so group membership and the IdP's own configuration are outside what it can judge.

## Client certificate authentication (`certificate`)

MarkLogic maps the **full subject DN** of the client certificate to a MarkLogic user's external name; the DN is compared as MarkLogic logs it, in the order stored
in the certificate (a certificate stored CN, OU is `CN=...,OU=...`; openssl's RFC 2253 output shows it reversed, the report prints both; checked only for certificates
stored CN first). A user whose external name is only the CN does not match. `--client-cert` takes a **public** certificate; a file that contains a private key is refused.

What the report can and cannot explain: a certificate rejected in the TLS handshake (no certificate, expired, not yet valid, serverAuth-only usage, issuing CA not
selected) leaves **nothing** in the ErrorLog or AccessLog, so the cause comes from the app server settings and the certificate itself:
- the CA that signed the certificate must be among the **selected** client CAs (`ssl-client-certificate-authority`; being trusted by MarkLogic is not enough);
- with `ssl-client-issuer-authority-verification` false every CA up to the root must be selected, with true the issuing CA alone is enough;
- validity and clientAuth usage are checked either way (TLS alerts 45, 42 and 43).
Only a certificate that passes TLS but maps to no user (`certificateAuthenticate() fail because no user`) and a successful login are logged (trace event External Authenticate:
`ml-trace-events.py enable --preset certificate`). The report lists the TLS alerts and the client-side command that shows them.

**Authorization `ldap`.** When the external security profile has authorization `ldap`, MarkLogic does not look for a user whose external name equals the DN: it binds as the
search account and does a **base-scope search whose base is the certificate's subject DN as stored** (the directory's own DN order: most specific first), reads the attribute named in
`ldap-attribute`, and maps the user's `memberOf` groups to role external names. A certificate whose DN is stored general-first (`DC=com,DC=example,...`, typical of enterprise CAs)
is therefore searched as is and fails with `certificateAuthenticate() fail because unknown user, dn <DN>`. The report shows the DN as MarkLogic uses it and reversed, judges it
against `ldap-base`, gives the `ldapsearch` command to run against the directory (the script itself does not query it and never prints the search account's password), checks the group DNs
against the roles' external names, and explains that four causes write the same `unknown user` line (reversed or wrong DN, no such entry, an attribute the entry lacks, a search account that
cannot read the entry), which only the directory's access log tells apart. Switch on the trace events External Authenticate, LDAP and LDAP Search for the log part.

## Temporary versus permanent certificates (`https`)

MarkLogic generates a self-signed *temporary* certificate for a template that has `generate-temp-certificate` set. The
Management API says which certificates are temporary: `GET /manage/v2/certificates/<id>` (host certificates) and
`GET /manage/v2/certificate-authorities/<id>` (authorities, including the temporary ones) return `temporary`, `template-id`
and `template-version`. The report lists, per template, each certificate as **TEMPORARY** or **PERMANENT** (and who signed
it), warns when only a temporary certificate exists, compares the serial of the certificate the port serves with the
template's certificates, and notes a certificate issued for an older template version.

## Duplicate subjects

MarkLogic logs `Duplicate certificate subject found in Security Database` (a Warning, in pairs). The report groups every
certificate by its full subject and says what each group is: host certificates held by two templates (for example RSA and
EC), the same key in a self-signed root and its cross-signed copy, old certificates without a key identifier, or **different
keys under one subject** (a warning). It also shows that the names in the certificate-authority list are the **issuer's**
name, not the certificate's own, so an imported intermediate appears under its root's name and the list looks full of
duplicates. What triggers the log line was not found (not reproducible with API reads or TLS handshakes).

## Let's Encrypt import (checked 2026-10-25, MarkLogic 12.1.0)

Certbot (Route 53 DNS-01) plus `marklogic-cert-deploy-wrapper.sh` pushed a Let's Encrypt certificate into a new template; the
`https` area reported it as PERMANENT, issued by Let's Encrypt, served by the port, name matching. Two things to know: a template
created through the Management API holds **no** certificate until one is imported (the app server then fails the TLS handshake and
the ErrorLog says `Failed to find server certificate in certificate template <id>`), and the port sent only the leaf
certificate. **Tested fix:** import the issuing CA certificate (the intermediate, second block of `fullchain.pem`) into MarkLogic's trusted
certificate authorities (`pki:insert-trusted-certificates` in the Security database); the port then sends leaf + intermediate at once.
A bundle in the certificate import itself is rejected (`insert-host-certificates` takes one certificate, HTTP 400 `PKI-BADCERTIFICATE`).

## SAML roles and the user option

The roles of a SAML login come from the assertion's Group values matched to the **external names of roles**; a MarkLogic
user's roles and external names are not used. Tested on 11.3.7: with a matching role external name both authorization `saml`
and `internal` granted the role; with none, both left the identity without roles (HTTP 403). MarkLogic reports that `internal`
is no longer supported on 11.3.7 and 12.1 (not reproduced on 11.3.7, not retested on 12.1), so the `saml` area warns about it
and fails when no role has an external name. `--user` is required (it is not defaulted to `admin`); use any MarkLogic user with the admin role, or set
`MARKLOGIC_USER`.
