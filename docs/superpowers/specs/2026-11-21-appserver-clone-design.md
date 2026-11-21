# appserver-clone.py: design

Date: 2026-11-21
Status: approved in brainstorming, awaiting written-spec review

## Purpose

A standalone Python script, written for a customer, that clones an existing MarkLogic app server
to a new port (optionally under a new name), saves a JSON record of what it created, and can later
remove that clone using only the record.

## Requirements (from the customer)

1. Self-documenting: running with no arguments prints the same output as `-h`/`--help`.
2. MarkLogic host, management port, admin user and password are passed only as environment variables.
3. Clone by app server name. Only the clone port is required; the clone name is optional and
   otherwise derived from the source.
4. Every other app server property is identical to the source.
5. Supports `--dry-run`.
6. A successful run saves a JSON file describing the app server created.
7. `--remove` takes only the JSON file from (6) as its source. If no usable JSON file is available,
   the user is told to remove the app server manually using the Admin UI.

## Decisions

| Topic | Decision |
|---|---|
| Dependencies | Python 3.8+ standard library only (`urllib`, `HTTPDigestAuthHandler`, `ssl`, `json`, `argparse`). Single file. |
| Approach | Read the source properties from the Management API, change `server-name` and `port`, and POST the result. No packaging API, no eval. |
| Group | Detected automatically from the server list. `--group` is needed only when the source name exists in more than one group. The clone is always created in the source's group. |
| Default clone name | `<source>-<port>`, e.g. `App-Services-8050`. |
| Remove safety | Check the server still exists with the recorded name, group and port; ask y/N for confirmation (`--yes` skips it); wait for the restart. |

## Location

- `scripts/AppServer/appserver-clone.py`
- `scripts/AppServer/test_appserver_clone.py`

## Command-line interface

```
appserver-clone.py SOURCE --port N [--name NAME] [--group G] [--output FILE] [--dry-run]
appserver-clone.py --remove FILE [--yes] [--dry-run]
```

- With no arguments the script prints the full help and exits 0. The help covers the environment
  variables, the clone and remove workflows, the JSON file format, the exit codes, the limits
  (it cannot detect non-MarkLogic processes holding a port) and examples.
- `--port` is required for a clone, must be in the range 1-65535, and cannot be combined with `--remove`.
  `SOURCE` is required for a clone and not allowed with `--remove`.
- `--output` defaults to `./<clone-name>.json`. The script refuses to overwrite an existing file.
- Flags that look like credentials (`--password`, `--user`, `--host` and similar)
  are not defined, and abbreviations are disabled (`allow_abbrev=False`). argparse rejects them, and the help explains the environment variables instead.

### Environment

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `MARKLOGIC_HOST` | yes | | Management host name |
| `MARKLOGIC_USER` | yes | | Admin user |
| `MARKLOGIC_PASS` | yes | | Admin password |
| `MARKLOGIC_MANAGE_PORT` | no | `8002` | Management API port |
| `MARKLOGIC_SCHEME` | no | `http` | `http` or `https` |
| `MARKLOGIC_CA_CERT` | no | system trust store | CA bundle used to verify HTTPS |
| `MARKLOGIC_INSECURE` | no | unset | `1` disables TLS certificate verification (a warning is printed on every run) |
| `MARKLOGIC_DEBUG` | no | unset | `1` shows Python tracebacks |

If a required variable is missing, the script names it and exits 1.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Success (including dry runs, and `--remove` when the server is already gone) |
| 1 | Usage or environment error |
| 2 | A pre-flight check failed: source not found, name or port already taken, ambiguous group, output file exists, JSON record missing, invalid or not matching the server |
| 3 | Management API or network error, or the wait for a restart timed out |
| 4 | Removal declined at the confirmation prompt, or refused because there was no terminal to prompt on and `--yes` was not given |

## Clone flow

1. Check the environment and arguments. Check that the output file does not exist and that its directory
   is writable. All of this happens before any change on the server.
2. Resolve the group with `GET /manage/v2/servers?format=json`, matching `nameref` and reading `groupnameref`.
   - 0 matches: exit 2.
   - 1 match: use that group.
   - More than 1 and no `--group`: exit 2 and list the groups.
   - `--group` given: that group must contain the source.
3. Read the source with `GET /manage/v2/servers/{source}/properties?group-id=G&format=json`.
4. Pre-flight checks:
   - the clone name does not already exist in group G;
   - no app server in group G uses the port (read each server's properties for its `port`).
5. Build the payload with `plan_clone`, a pure function: a deep copy of the source properties with
   `server-name` and `port` replaced. If a live test shows that MarkLogic 12 rejects a read-only
   property on POST, that property goes into a small, named, commented strip list. It is not
   silently dropped.
6. `--dry-run`: print a summary (source, clone name, group, port, changed fields) and the full JSON
   payload, then exit 0. No POST, no file.
7. `POST /manage/v2/servers?group-id=G`. If the response signals a restart (HTTP 202 with a
   restart body), wait for it.
8. Read the clone's properties back with GET.
9. Write the record: write to a temporary file in the same directory, then rename it with `os.replace`.
   If writing fails after the server was created, print the full record to stdout and a clear
   warning to stderr, then exit 3.

## JSON record

```json
{
  "tool": "appserver-clone",
  "format-version": 1,
  "created": "2026-11-21T14:03:11Z",
  "marklogic-host": "ml1.example.com",
  "group": "Default",
  "source": "App-Services",
  "clone": { "name": "App-Services-8050", "port": 8050 },
  "properties": { "...": "clone properties as read back from MarkLogic" }
}
```

No credentials are stored.

## Remove flow

1. Load the record. If the file is missing or unreadable, is not JSON, has `tool` other than `appserver-clone`,
   or has an unsupported `format-version`, print:

   > No usable clone record. This script only removes app servers it created.
   > Remove the app server manually in the Admin UI: Groups → *G* → App Servers → *NAME* → Delete.

   *G* and *NAME* come from the record when it can be parsed; otherwise the wording is generic.
   Exit 2.
2. If `MARKLOGIC_HOST` differs from `marklogic-host`, print a warning and continue (the same cluster
   is often reached by a different alias).
3. `GET /manage/v2/servers/{name}/properties?group-id=G&format=json`:
   - 404: report "already removed", leave the record in place, exit 0.
   - Port differs from the record: refuse, exit 2.
4. Print what will be deleted. `--dry-run` stops here with exit 0.
5. Confirm with `Delete app server NAME (group G, port P)? [y/N]`. `--yes` skips the prompt.
   If stdin is not a terminal and `--yes` was not given, refuse with exit 4. Answering no also exits 4.
6. `DELETE /manage/v2/servers/{name}?group-id=G`, then wait for the restart.
7. Rename the record to `<file>.removed`, which keeps the audit trail and stops it being run again.

## Waiting for a restart

A 202 response carries `{"restart": {"last-startup": [{"host-id": ..., "value": ...}]}}`.
For each host listed, poll `GET /manage/v2/hosts/{host-id}?view=status&format=json` every 2 seconds
and read `host-status.status-properties.status-detail.last-startup.value`. A host has restarted once
that value differs from the one in the 202 body. (`/admin/v1/timestamp` would also work, but it is
only served on the Admin port, 8001. Verified on MarkLogic 12.1: the host status view on 8002 reports
the same value.)

If the 202 body has no restart details, wait one interval, then poll `GET /manage/v2?format=json`
until it answers 200.

Connection errors and 5xx responses during the restart are expected and are retried. Timeout 180 s,
then exit 3 with a message that the change was submitted but completion could not be confirmed.
After a remove, the script also checks that the server's properties now return 404.

## Internal structure

| Unit | Responsibility |
|---|---|
| `load_config(environ)` | Check the environment variables and return a `Config` with an SSL context |
| `ManageClient` | `get` / `post` / `delete` with digest auth; parse JSON; raise `ApiError(method, path, status, message_code, message)` from MarkLogic's `errorResponse` |
| `list_servers(client)` | `[(name, group), ...]` from the server list |
| `resolve_group(servers, name, group)` | Pure: group lookup described above |
| `ports_in_group(client, servers, group)` | `{port: server_name}` |
| `plan_clone(source_props, name, port, existing_names, used_ports)` | Pure: checks plus payload |
| `build_record`, `check_output_path`, `write_record`, `load_record` | Create, check the target of, atomically write, and validate the JSON record |
| `wait_for_restart(client, body, timeout=180)` | Polling described above |
| `cmd_clone`, `cmd_remove` | Orchestrate the flows |
| `main(argv)` | argparse, help when run with no arguments, map exceptions to exit codes |

## Error messages

- One line, `error: ...`, on stderr, optionally followed by `hint: ...`.
- API errors show the method, path, status and MarkLogic `messageCode`,
  e.g. `POST /manage/v2/servers → 400 ADMIN-PORTINUSE`.
- No traceback unless `MARKLOGIC_DEBUG=1`. The password never appears in any output.

## Testing

### Unit tests (`python3 -m unittest`, fake `ManageClient`)

- No arguments prints the help and exits 0. `--password x` is rejected.
- Missing environment variables are named in the error.
- `resolve_group`: 0, 1 or several matches; `--group` that does not contain the source.
- `plan_clone`: name conflict; port conflict; the payload differs from the source only in `server-name` and `port`.
- Dry-run clone and dry-run remove make no POST or DELETE calls and write no files.
- Output file already exists: exit 2 before any API call.
- Record: written then loaded back unchanged; temp-file-then-rename write.
- Remove: missing file shows the Admin UI message; JSON from another tool is rejected; port mismatch;
  already removed; "no" at the prompt; no terminal without `--yes`; success renames the file to `.removed`.

### Live test (MarkLogic 12 test server)

Credentials are supplied only as environment variables for each command and are never written to files.

1. `--dry-run`: clone `App-Services` (port 8000) as `AppServices-Digest` on port 9000.
2. Real clone. Check the JSON record exists.
3. Compare the clone and source properties: they must be equal apart from `server-name` and `port`.
4. `--remove AppServices-Digest.json --dry-run`.
5. `--remove AppServices-Digest.json --yes`. Check the server is gone and the record was renamed to `.removed`.

## Out of scope

- Changing any property other than name and port, including authentication. The clone keeps the
  source's authentication method.
- Cloning across groups or clusters.
- Detecting non-MarkLogic processes listening on the port.
- Removing app servers that have no record from this script.
