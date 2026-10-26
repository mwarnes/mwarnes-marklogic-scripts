# SAML configuration gather

Collected 2026-10-25 09:11 UTC from ml1.example.com:8002 as `admin`. Nothing was changed on the server.

**4 part(s) were not collected**; see the section "Not collected" near the end.

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

## Not collected

These parts were skipped because the input was not given or the data was not available. Everything else in this report was collected.

| Not collected | Why | How to add it |
|---|---|---|
| User and role external names | no --user-name given | add --user-name <MarkLogic user the login maps to>; the external names of all roles were still collected |
| IdP metadata comparison | no --idp-metadata given | add --idp-metadata <file or https://... URL>; the entity ID, destination and certificate stored in the profile are listed above |
| SAML response comparison | no --saml-response given | add --saml-response <file> (a captured SAMLResponse or an authorization header line) |
| ErrorLog, AccessLog and trace-event status | --logs not given | add --logs --start <UTC time shortly before the test> (switch the trace events on first with ml-trace-events.py, preset saml or oauth) |

## Check results

| Result | Check | Detail |
|---|---|---|
| **INFO** | `Manage-Clone-SAML` saml-idp-certificate-authority issuer not stored | #1 issuer `CN=authentik 2026.8.3` missing. Informational: a SAML login worked on a 12.1.0 test server (authentik) with only the IdP signing certificate stored, so MarkLogic does not need the issuer. Match the stored certificate against the IdP metadata instead |
| **PASS** | `Manage-Clone-SAML` saml-sp-certificate chain complete | ends in a self-signed certificate (1 in bundle) |

Only the properties named above were read. The SP private key, passwords and secrets are removed before saving.
