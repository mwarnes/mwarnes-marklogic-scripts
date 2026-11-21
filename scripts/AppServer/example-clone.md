# Example: cloning an app server with `appserver-clone.py`

This example clones the `App-Services` app server (port 8000) to a new app server called
`AppServices-Digest` on port 9000, then removes the clone again. The output shown is the
actual output of each command, captured on MarkLogic 12.1.0 on 2026-11-21.

`appserver-clone.py` needs Python 3.8 or newer and nothing outside the Python standard library.

## 1. Set the connection details

The script reads the connection details **only** from environment variables; it has no
command-line options for them. Enter the password at a hidden prompt rather than typing it
on the command line:

```bash
export MARKLOGIC_HOST=marklogic.warnesnet.com   # host running the Management API
export MARKLOGIC_USER=admin                     # a user with the manage-admin or admin role
read -rs MARKLOGIC_PASS && export MARKLOGIC_PASS
# Optional: MARKLOGIC_MANAGE_PORT (default 8002), MARKLOGIC_SCHEME (default http),
#           MARKLOGIC_CA_CERT (CA bundle for https)
```

## 2. Dry run

`--dry-run` reads the source app server and runs every check (the source exists, the new name
and port are free in its group, the record file doesn't already exist), then prints the exact
settings it would send. Nothing is created and no file is written.

```bash
./appserver-clone.py App-Services --port 9000 --name AppServices-Digest --dry-run
echo $?
```

Output:

```text
source:  App-Services (group 'Default', port 8000)
clone:   AppServices-Digest (group 'Default', port 9000)
record:  AppServices-Digest.json
DRY RUN: no changes made. Payload that would be sent to POST /manage/v2/servers:
{
  "server-name": "AppServices-Digest",
  "group-name": "Default",
  "server-type": "http",
  "enabled": true,
  "root": "/",
  "port": 9000,
  "public-port": false,
  "webDAV": false,
  "execute": true,
  "display-last-login": false,
  "address": "0.0.0.0",
  "backlog": 512,
  "threads": 32,
  "request-timeout": 30,
  "keep-alive-timeout": 5,
  "session-timeout": 3600,
  "max-time-limit": 3600,
  "default-time-limit": 600,
  "max-inference-size": 500,
  "default-inference-size": 100,
  "static-expires": 3600,
  "pre-commit-trigger-depth": 1000,
  "pre-commit-trigger-limit": 10000,
  "collation": "http://marklogic.com/collation/",
  "coordinate-system": "wgs84",
  "authentication": "digest",
  "internal-security": true,
  "API-token-authentication": false,
  "concurrent-request-limit": 0,
  "compute-content-length": true,
  "file-log-level": "info",
  "log-errors": false,
  "debug-allow": true,
  "profile-allow": true,
  "default-xquery-version": "1.0-ml",
  "multi-version-concurrency-control": "contemporaneous",
  "distribute-timestamps": "fast",
  "output-sgml-character-entities": "none",
  "output-encoding": "UTF-8",
  "output-method": "default",
  "output-byte-order-mark": "default",
  "output-cdata-section-namespace-uri": "",
  "output-cdata-section-localname": null,
  "output-doctype-public": "",
  "output-doctype-system": "",
  "output-escape-uri-attributes": "default",
  "output-include-content-type": "default",
  "output-indent": "default",
  "output-indent-untyped": "default",
  "output-indent-tabs": "default",
  "output-media-type": "",
  "output-normalization-form": "none",
  "output-omit-xml-declaration": "default",
  "output-standalone": "omit",
  "output-undeclare-prefixes": "default",
  "output-version": "",
  "output-include-default-attributes": "default",
  "default-error-format": "compatible",
  "error-handler": "/MarkLogic/rest-api/8000-error-handler.xqy",
  "url-rewriter": "/MarkLogic/rest-api/8000-rewriter.xml",
  "rewrite-resolves-globally": true,
  "ssl-min-allow-tls": "TLSv1.2",
  "ssl-hostname": "",
  "ssl-ciphers": "ALL:!LOW:@STRENGTH",
  "ssl-ciphersuites": "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256",
  "ssl-require-client-certificate": true,
  "ssl-client-issuer-authority-verification": false,
  "enable-hsts-header": false,
  "hsts-header-max-age": 31536000,
  "content-database": "Documents",
  "modules-database": "Modules",
  "default-user": "nobody"
}
```

Exit code: `0`

The payload is identical to the `App-Services` settings except `server-name` and `port`.

## 3. Live run

The same command without `--dry-run`:

```bash
./appserver-clone.py App-Services --port 9000 --name AppServices-Digest
echo $?
```

Output:

```text
source:  App-Services (group 'Default', port 8000)
clone:   AppServices-Digest (group 'Default', port 9000)
record:  AppServices-Digest.json
created app server 'AppServices-Digest' on port 9000 in group 'Default'; record saved to AppServices-Digest.json
```

Exit code: `0`

The new app server is now listening on port 9000, with the same settings as `App-Services`
(including `authentication: digest`).

## 4. The saved record

A successful run writes `AppServices-Digest.json` in the current directory (choose another
path with `--output FILE`). Keep it: it is the only input `--remove` accepts. Beginning of the
file:

```json
{
  "tool": "appserver-clone",
  "format-version": 1,
  "created": "2026-11-21T13:04:01Z",
  "marklogic-host": "marklogic.warnesnet.com",
  "group": "Default",
  "source": "App-Services",
  "clone": {
    "name": "AppServices-Digest",
    "port": 9000
  },
  "properties": { ... full properties of the new app server, as read back from MarkLogic ... }
}
```

The record contains no credentials.

## 5. Removing the clone

Removal uses only the record saved in step 4. Start with a dry run, which checks that the app
server still exists with the recorded name, group and port, and shows what would be deleted:

```bash
./appserver-clone.py --remove AppServices-Digest.json --dry-run
echo $?
```

Output:

```text
will delete app server 'AppServices-Digest' (group 'Default', port 9000); MarkLogic restarts on the group's hosts afterwards
DRY RUN: no changes made
```

Exit code: `0`

Then remove it. Without `--yes` the script asks `Delete app server AppServices-Digest (group
Default, port 9000)? [y/N]` before deleting. `--yes` skips the question (it is refused if
`MARKLOGIC_HOST` differs from the host recorded in the file):

```bash
./appserver-clone.py --remove AppServices-Digest.json --yes
echo $?
```

Output (about 10 seconds, most of it waiting for MarkLogic to restart):

```text
will delete app server 'AppServices-Digest' (group 'Default', port 9000); MarkLogic restarts on the group's hosts afterwards
waiting for MarkLogic to restart...
deleted app server 'AppServices-Digest' from group 'Default'; record renamed to AppServices-Digest.json.removed
```

Exit code: `0`

The app server has been deleted, and the record has been renamed to
`AppServices-Digest.json.removed` so it cannot be used a second time. Without a usable record
file the script refuses and tells you to delete the app server in the Admin UI instead.

## Notes

- If `--name` is omitted the clone is named `<source>-<port>`, here `App-Services-9000`.
- Run `./appserver-clone.py` with no arguments (or `-h`) for the full help.
- Exit codes: `0` success, `1` usage or environment error, `2` a pre-flight check failed
  (for example the port or name is already in use, or the record file already exists),
  `3` Management API or network error, `4` removal declined.
