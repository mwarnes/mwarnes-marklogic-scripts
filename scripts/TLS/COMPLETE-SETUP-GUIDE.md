# MarkLogic TLS setup and recovery

## End-to-end example

`example-end-to-end-tls.sh` runs the complete flow (private CA, MarkLogic-generated
CSR, signing, import, HTTPS app server, verified handshake) by calling the component
scripts below. It is meant for test systems; run it with `--dry-run` first.

## Reviewed component workflow

1. Create a test CA with `generate-ca-certificate.sh create-ca`.
2. Generate a CSR and private key with `generate-csr.sh server-csr` or
   `client-csr`.
3. Submit the CSR to the intended CA, then sign or import the certificate.
4. Configure a certificate template and AppServer with
   `configure-marklogic-tls.sh`.
5. Validate certificates with `validate-tls.sh` and inspect the AppServer with
   `test-ssl` only after reviewing the target and certificate trust.

Use each command's `--dry-run` first. The dry-run path does not generate keys,
create temporary payload files, call services, or perform TLS handshakes.

## Credentials and key handling

- MarkLogic scripts use `MARKLOGIC_PASS` for unattended execution or a hidden
  interactive prompt. Value-taking password flags are rejected.
- `generate-csr.sh` accepts `TLS_KEY_PASSWORD` and `TLS_CA_PASSWORD` for
  unattended use; otherwise it prompts without echo.
- `marklogic-cert-deploy-wrapper.sh` reads a strict allow-list from an
  owner-controlled configuration file with no group/other access. The wrapper
  parses values; it does not source shell code.
- Private-key output files and PKCS12 extractions are owner-only. Do not put
  private-key contents or passwords in command arguments or verbose logs.

## Generated-file recovery

CA, CSR, certificate-export, and PKCS12-output commands write a protected
`*.rollback.json` manifest after successful generation. To remove only files
that still match that manifest, use the generating script's `--rollback`
option and confirm the deletion. If any file changed, rollback refuses.

CA signing consumes a serial number; deleting a generated certificate does not
reverse CA issuance or restore serial state. Certbot/ACME issuance, Route 53
DNS changes, package installation, and service scheduling also require manual
provider/host recovery. MarkLogic snapshots may omit or redact private-key
material, so configuration restoration is manual when the export is incomplete.

## Examples

```bash
export TLS_CA_PASSWORD="<from a secret manager>"
./generate-ca-certificate.sh create-ca --cn "Example-CA" --org "Example Corp"
./generate-csr.sh server-csr --cn "server.example.com" --dns "server.example.com"
./generate-csr.sh --rollback server.example.com.csr.rollback.json
```

For a MarkLogic deployment, set `MARKLOGIC_PASS` or use the hidden prompt, then
run `configure-marklogic-tls.sh` with the reviewed template and AppServer names.
`example-end-to-end-tls.sh` changes the target MarkLogic (template, app server) and has no
automatic rollback; use it on a test system.
