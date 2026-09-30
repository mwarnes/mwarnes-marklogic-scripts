# TLS Certificate Utilities — Quick Reference

## Safe workflow

The example scripts print commands only. Generate keys/certificates only by
running the explicit component command after reviewing its preview and output
paths. Private-key files are created with owner-only permissions.

```bash
export TLS_CA_PASSWORD="<from a secret manager>"
./generate-ca-certificate.sh create-ca --cn "Example-CA" --org "Example Corp"

./generate-csr.sh server-csr \
  --cn "server.example.com" \
  --dns "server.example.com,*.server.example.com"
```

The CSR tool writes the private key, CSR, and a protected rollback manifest. To
remove only unchanged files created by that run:

```bash
./generate-csr.sh --rollback server.example.com.csr.rollback.json
```

`generate-ca-certificate.sh` similarly prints the manifest path after CA files
are created. CA signing consumes a serial number; rollback removes only the
unchanged signed certificate and does not rewind the CA serial.

## Sign a CSR

```bash
export TLS_CA_PASSWORD="<from a secret manager>"
./generate-ca-certificate.sh sign-csr \
  --ca-cert ca-certificate.pem \
  --ca-key ca-private-key.pem \
  --csr server.example.com.csr \
  --output server.example.com-certificate.pem
```

Password values are not accepted as command-line arguments. Set
`TLS_CA_PASSWORD`/`TLS_KEY_PASSWORD` for unattended use or enter them at hidden
prompts. `--no-encrypt` is discouraged and only suitable for throwaway testing.

## Validate certificates

```bash
./validate-tls.sh validate-cert --cert-file server.example.com-certificate.pem
./validate-tls.sh validate-pair --cert-file server.example.com-certificate.pem \
  --key-file server.example.com-private-key.pem
./validate-tls.sh validate-chain --cert-file server.example.com-certificate.pem \
  --ca-file ca-certificate.pem
./validate-tls.sh check-expiry --cert-file server.example.com-certificate.pem --warn-days 30
```

Use `--dry-run` to preview without reading certificate contents, creating temp
files, or making network probes. TLS verification is enabled by default;
`--insecure` is an explicit, discouraged opt-in.

## Configure MarkLogic

```bash
export MARKLOGIC_PASS="<from a secret manager>"
./configure-marklogic-tls.sh create-template --name web-ssl \
  --common-name server.example.com --organization "Example Corp"
./configure-marklogic-tls.sh configure-ssl --template web-ssl \
  --appserver App-Services --ssl-port 8443 --dry-run
```

Template/app-server updates save protected snapshots before mutation and prompt
for confirmation. MarkLogic may redact private-key fields, so restore is manual
when the export is incomplete. The all-in-one setup scripts remain available but
are not QA'd in this branch; review their multi-step changes before use. Package
installation, CA issuance, and external ACME/DNS actions require manual recovery.
