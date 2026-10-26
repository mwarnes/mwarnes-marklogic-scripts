# SAML configuration gather

Collected 2026-10-25 09:10 UTC from ml1.example.com:8002 as `admin`. Nothing was changed on the server.

MarkLogic version: 12.1.0 (cluster `ml1.example.com-cluster`)
Hosts: ml1.example.com

## External security objects

### `Manage-Clone-SAML`

| Setting | Value |
|---|---|
| authentication | `saml` |
| authorization | `saml` |
| cache-timeout | `60` |
| saml-entity-id | `https://idp.example.com:9443/application/saml/marklogic-manage-clone-saml/metadata/` |
| saml-destination | `https://idp.example.com:9443/application/saml/marklogic-manage-clone-saml/` |
| saml-issuer | `https://ml1.example.com:8012` |
| saml-assertion-host | `not set` |
| saml-authn-signature | `sha256` |
| saml-attribute-names | `none` |
| saml-sp-certificate | set |
| saml-sp-private-key | set (value never collected) |

#### `Manage-Clone-SAML` saml-idp-certificate-authority
| # | Subject | Issuer | Valid | Expires in | SHA-1 | Sig / key | CA |
|---|---|---|---|---|---|---|---|
| 1 | `OU=Self-signed,O=authentik,CN=authentik Self-signed Certificate` | `CN=authentik 2026.8.3` | 2026-09-20 to 2027-09-21 | 331 days | `23:5E:C2:D3:22:C7:DA:57:EB:4B:32:F8:6B:EE:D6:F1:02:39:98:8F` | sha256WithRSAEncryption / 4096 | n/a |
- #1 is issued by `CN=authentik 2026.8.3`, which is **not in the stored bundle**.

#### `Manage-Clone-SAML` saml-sp-certificate
| # | Subject | Issuer | Valid | Expires in | SHA-1 | Sig / key | CA |
|---|---|---|---|---|---|---|---|
| 1 | `CN=ml1.example.com-manage-clone-saml-sp` | `CN=ml1.example.com-manage-clone-saml-sp` | 2026-10-24 to 2027-10-24 | 364 days | `7C:67:3C:02:03:23:6D:04:6E:84:03:6E:1F:91:7E:B8:F7:94:84:5E` | sha256WithRSAEncryption / 2048 | yes |
- #1 is self-signed (it is its own trust anchor); signature check: ok

## App servers using these objects

- `manage-clone` (group `Default`, port 8012): authentication `saml`, internal-security `True`, external-security `Manage-Clone-SAML`, TLS template `MarkLogic-Test`

## Users, roles and external names

- `tuser1`: external names ['tuser1']; roles ['qconsole-user']
  - role `qconsole-user` external names: ['qconsole-user']; inherits none; privileges: environment-ui, qconsole

With authorization `saml`, MarkLogic matches the assertion's Group values to the external names of roles (12.1.0 lab).
In the same lab, with authorization `internal` a user's external name did NOT give that user any roles [unverified beyond one test].

## IdP metadata check

- entityID: `https://idp.example.com:9443/application/saml/marklogic-manage-clone-saml/metadata/`
- SingleSignOnService HTTP-Redirect: `https://idp.example.com:9443/application/saml/marklogic-manage-clone-saml/`
- SingleSignOnService HTTP-POST: `https://idp.example.com:9443/application/saml/marklogic-manage-clone-saml/`
- signing certificate: `OU=Self-signed,O=authentik,CN=authentik Self-signed Certificate`, expires 2027-09-21, SHA-1 `23:5E:C2:D3:22:C7:DA:57:EB:4B:32:F8:6B:EE:D6:F1:02:39:98:8F`

## SAML response check

- Issuer(s): `https://idp.example.com:9443/application/saml/marklogic-manage-clone-saml/metadata/`
- Audience: `https://ml1.example.com:8012`
- Response Destination: `https://ml1.example.com:8012/`, IssueInstant 2026-10-24T15:27:04Z
- Signed elements: Assertion
- Conditions: NotBefore 2026-10-24T15:22:04Z, NotOnOrAfter 2026-10-24T15:32:04Z (checked against the time this script ran: 2026-10-25T09:10Z)
  (a captured response is normally expired by now; compare with the time of the failed request, not with the time of this check)
- Signing certificate embedded in the response: SHA-1 `23:5E:C2:D3:22:C7:DA:57:EB:4B:32:F8:6B:EE:D6:F1:02:39:98:8F`
- NameID: `tuser1`
- Attribute names: `http://schemas.goauthentik.io/2021/02/saml/username` (1 value(s)), `http://schemas.xmlsoap.org/claims/Group` (1 value(s))
- Matched: NameID matches an external name (user tuser1)
- Matched: attribute `http://schemas.goauthentik.io/2021/02/saml/username` value `tuser1` matches (user tuser1)
- Matched: attribute `http://schemas.xmlsoap.org/claims/Group` value `qconsole-user` matches (role qconsole-user)

## Logs (2026-10-24T15:30:16Z to 2026-10-24T15:33:00Z UTC)

Log times are written in each host's local time zone; the window above is UTC. If a host is not on UTC, widen the window or pass --start/--end.

- Trace events, group `Default`: mechanism ON, events: SAML, SAML Response, External Authenticate

- ErrorLog on `ml1.example.com`: 95 SAML/authentication line(s) in the window (saved as ErrorLog-saml-*.txt)
- AccessLog `8012_AccessLog.txt` on `ml1.example.com`: 0 request(s) in the window

### SAML validation steps seen

| Count | Message |
|---|---|
| 8 | External authentication failed: user= |
| 5 | Saml Response: status is Success |
| 5 | Saml Response: assertion count is 1 |
| 5 | Saml Response: Issuer matches configured IdP |
| 5 | Saml Response: Audience matches SP entity ID |
| 5 | Saml Response: notOnOrAfter <time> is valid |
| 5 | Saml Response: NotBefore <time> is valid |
| 4 | Saml Response samlId:<id> Username:tuser1 Group: tuser1 qconsole-user  Valid from:<time> Valid until:<time> |
| 4 | Saml Response: signature is valid |
| 4 | Saml Response: signed element matches assertion |
| 4 | Saml Response is valid |
| 4 | ExternalSecurity[Manage-Clone-SAML] pass |
| 3 | Saml Authenticate url:/manage/v2 samlId(Cookie): |
| 3 | Saml Cached Response not found for samlId: |
| 3 | Saml Authn Request: <AuthnRequest xmlns= ... (XML/URL not shown) |
| 3 | Saml Authn Signature uses sha256 |
| 3 | Saml Redirect to IDP: https://idp.example.com ... (XML/URL not shown) |
| 3 | Saml Authenticate url:/ samlId(Cookie): |
| 3 | Saml Response: recipient https://ml1.example.com:8012/ matches |
| 3 | Saml Redirect to target url: /manage/v2 samlId(response):<id> |
| 3 | Saml Set Cookie samlId:<id> |
| 3 | Saml Authenticate url:/manage/v2 samlId(Cookie):<id> |
| 2 | Saml Cached Response is valid for samlId:<id> |
| 1 | Saml Response samlId:<id> Username:tuser1x Group: tuser1 qconsole-user  Valid from:<time> Valid until:<time> |
| 1 | SAML signature is invalid |
| 1 | Saml Response Error: signature is invalid |
| 1 | Saml Cached Response is invalid |
| 1 | Saml Response Error: cannot parse response |

**4 SAML error message(s)**; the first is the one to start from. Quoted in Check results.
Responses MarkLogic validated: 4; external authentication passes: 4.
(`External authentication failed: user=` lines with no user name appear for the first request, before a session exists; they are normal.)

### Identity in the assertion (from the trace) and role mapping

| Time | NameID (Username) | Group values | Valid from / until |
|---|---|---|---|
| 2026-10-24 15:30:17.794 | `tuser1x` | `tuser1 qconsole-user` | 2026-10-24T15:22:04Z / 2026-10-24T15:32:04Z |
| 2026-10-24 15:30:19.210 | `tuser1` | `tuser1 qconsole-user` | 2026-10-24T15:22:04Z / 2026-10-24T15:32:04Z |
| 2026-10-24 15:32:01.974 | `tuser1` | `tuser1 qconsole-user` | 2026-10-24T15:27:01Z / 2026-10-24T15:37:01Z |
| 2026-10-24 15:32:02.934 | `tuser1` | `tuser1 qconsole-user` | 2026-10-24T15:27:01Z / 2026-10-24T15:37:01Z |
| 2026-10-24 15:32:03.397 | `tuser1` | `tuser1 qconsole-user` | 2026-10-24T15:27:01Z / 2026-10-24T15:37:01Z |

With authorization `saml` the assertion's Group values are matched to roles' external names (roles-external-names.json lists them).

## Not collected

Nothing was skipped.

## Check results

| Result | Check | Detail |
|---|---|---|
| **FAIL** | SAML error, first at 2026-10-24 15:30:17.794 (1 time) | `SAML signature is invalid` - The signature does not verify with the certificate stored in `saml-idp-certificate-authority`: the IdP is signing with a different (rotated, or per-application) certificate, or the assertion was altered. Compare the stored certificate's SHA-1 with the IdP metadata and with the certificate embedded in the response. |
| **FAIL** | SAML error, first at 2026-10-24 15:30:17.794 (1 time) | `Saml Response Error: signature is invalid` - The signature does not verify with the certificate stored in `saml-idp-certificate-authority`: the IdP is signing with a different (rotated, or per-application) certificate, or the assertion was altered. Compare the stored certificate's SHA-1 with the IdP metadata and with the certificate embedded in the response. |
| **FAIL** | SAML error, first at 2026-10-24 15:30:18.264 (1 time) | `Saml Cached Response is invalid` |
| **FAIL** | SAML error, first at 2026-10-24 15:32:03.859 (1 time) | `Saml Response Error: cannot parse response` - The value sent after `SAML token=` (or posted as SAMLResponse) is not a base64-encoded SAML Response XML. Check what the application sends (truncated, double-encoded, or not a SAML response). |
| **INFO** | `Manage-Clone-SAML` saml-idp-certificate-authority issuer not stored | #1 issuer `CN=authentik 2026.8.3` missing. Informational: a SAML login worked on a 12.1.0 test server (authentik) with only the IdP signing certificate stored, so MarkLogic does not need the issuer. Match the stored certificate against the IdP metadata instead |
| **PASS** | `Manage-Clone-SAML` saml-sp-certificate chain complete | ends in a self-signed certificate (1 in bundle) |
| **PASS** | Manage-Clone-SAML: saml-entity-id = metadata entityID | config `https://idp.example.com:9443/application/saml/marklogic-manage-clone-saml/metadata/` / metadata `https://idp.example.com:9443/application/saml/marklogic-manage-clone-saml/metadata/` |
| **PASS** | Manage-Clone-SAML: saml-destination is a metadata SSO URL | config `https://idp.example.com:9443/application/saml/marklogic-manage-clone-saml/` / metadata https://idp.example.com:9443/application/saml/marklogic-manage-clone-saml/, https://idp.example.com:9443/application/saml/marklogic-manage-clone-saml/ |
| **PASS** | Manage-Clone-SAML: stored IdP certificate is in the metadata | stored 23:5E:C2:D3:22:C7:DA:57:EB:4B:32:F8:6B:EE:D6:F1:02:39:98:8F / metadata 23:5E:C2:D3:22:C7:DA:57:EB:4B:32:F8:6B:EE:D6:F1:02:39:98:8F |
| **PASS** | assertion Issuer = saml-entity-id | config `https://idp.example.com:9443/application/saml/marklogic-manage-clone-saml/metadata/` / assertion https://idp.example.com:9443/application/saml/marklogic-manage-clone-saml/metadata/ |
| **PASS** | assertion Audience = saml-issuer (SP entity ID) | config `https://ml1.example.com:8012` / assertion https://ml1.example.com:8012 |
| **PASS** | assertion is signed | MarkLogic requires a signed assertion (tested on 12.1.0); signed elements: Assertion |
| **PASS** | response signing cert = certificate stored in MarkLogic | response 23:5E:C2:D3:22:C7:DA:57:EB:4B:32:F8:6B:EE:D6:F1:02:39:98:8F / MarkLogic 23:5E:C2:D3:22:C7:DA:57:EB:4B:32:F8:6B:EE:D6:F1:02:39:98:8F |
| **PASS** | response signing cert is listed in the IdP metadata | metadata lists 1 signing certificate(s) |
| **PASS** | assertion matches a MarkLogic external name | NameID matches an external name (user tuser1); attribute `http://schemas.goauthentik.io/2021/02/saml/username` value `tuser1` matches (user tuser1); attribute `http://schemas.xmlsoap.org/claims/Group` value `qconsole-user` matches (role qconsole-user) |
| **PASS** | Group values of tuser1x map to MarkLogic roles | `qconsole-user` -> qconsole-user |
| **PASS** | Group values of tuser1 map to MarkLogic roles | `qconsole-user` -> qconsole-user |

Only the properties named above were read. The SP private key, passwords and secrets are removed before saving.
