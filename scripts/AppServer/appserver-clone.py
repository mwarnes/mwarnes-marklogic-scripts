#!/usr/bin/env python3
"""Clone a MarkLogic app server to a new port, or remove a clone made by this script.

Run with no arguments (or -h / --help) for full usage.
"""
from __future__ import annotations

import argparse
import copy
import datetime
import http.client
import json
import os
import ssl
import sys
import tempfile
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

TOOL = "appserver-clone"
FORMAT_VERSION = 1

EXIT_OK = 0
EXIT_USAGE = 1
EXIT_PREFLIGHT = 2
EXIT_API = 3
EXIT_DECLINED = 4

# Properties the Management API returns on GET but rejects on POST /manage/v2/servers.
# Keep this empty unless a live test proves otherwise, and give every entry a comment saying why.
STRIP_ON_POST: tuple = ()


class CloneError(Exception):
    """An expected failure: printed as 'error: ...' (plus an optional hint) and mapped to an exit code."""

    def __init__(self, message: str, exit_code: int, hint: str | None = None):
        super().__init__(message)
        self.exit_code = exit_code
        self.hint = hint


class ApiError(CloneError):
    """The Management API answered with an error status."""

    def __init__(self, method: str, path: str, status: int, message_code: str = "", message: str = ""):
        self.method = method
        self.path = path
        self.status = status
        self.message_code = message_code
        text = f"{method} {path} → {status}"
        if message_code:
            text += f" {message_code}"
        if message:
            text += f": {message}"
        super().__init__(text, EXIT_API)


class TransportError(CloneError):
    """The Management API could not be reached."""

    def __init__(self, message: str):
        super().__init__(message, EXIT_API, hint="check MARKLOGIC_HOST, MARKLOGIC_MANAGE_PORT and MARKLOGIC_SCHEME")


@dataclass(frozen=True)
class Config:
    host: str
    user: str
    password: str = field(repr=False)
    port: int = 8002
    scheme: str = "http"
    insecure: bool = False
    ssl_context: ssl.SSLContext | None = field(default=None, repr=False, compare=False)

    @property
    def base_url(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"


def load_config(environ) -> Config:
    """Build the connection settings from environment variables only."""
    missing = [v for v in ("MARKLOGIC_HOST", "MARKLOGIC_USER", "MARKLOGIC_PASS") if not environ.get(v)]
    if missing:
        raise CloneError("missing environment variable(s): " + ", ".join(missing), EXIT_USAGE,
                         hint="connection settings are read only from the environment; see --help")
    scheme = environ.get("MARKLOGIC_SCHEME", "http").strip().lower()
    if scheme not in ("http", "https"):
        raise CloneError(f"MARKLOGIC_SCHEME must be http or https, not '{scheme}'", EXIT_USAGE)
    raw_port = environ.get("MARKLOGIC_MANAGE_PORT", "8002").strip()
    if not raw_port.isdigit() or not 1 <= int(raw_port) <= 65535:
        raise CloneError(f"MARKLOGIC_MANAGE_PORT must be a port number (1-65535), not '{raw_port}'", EXIT_USAGE)
    insecure = environ.get("MARKLOGIC_INSECURE", "") == "1"
    context = None
    if scheme == "https":
        if insecure:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        else:
            cafile = environ.get("MARKLOGIC_CA_CERT") or None
            try:
                context = ssl.create_default_context(cafile=cafile)
            except (OSError, ssl.SSLError) as e:
                raise CloneError(f"cannot load MARKLOGIC_CA_CERT '{cafile}': {e}", EXIT_USAGE) from None
    return Config(host=environ["MARKLOGIC_HOST"].strip(), user=environ["MARKLOGIC_USER"],
                  password=environ["MARKLOGIC_PASS"], port=int(raw_port), scheme=scheme,
                  insecure=insecure, ssl_context=context)


def server_path(name: str, suffix: str = "") -> str:
    return "/manage/v2/servers/" + urllib.parse.quote(name, safe="") + suffix


def api_error(method: str, path: str, status: int, raw: bytes) -> ApiError:
    """Turn an error response (MarkLogic errorResponse JSON, or anything else) into an ApiError."""
    code = message = ""
    try:
        detail = json.loads(raw.decode("utf-8", "replace")).get("errorResponse", {})
        code = detail.get("messageCode", "") or ""
        message = detail.get("message", "") or ""
    except (ValueError, AttributeError):
        pass
    if code and message.startswith(code + ":"):
        message = message[len(code) + 1:].strip()
    err = ApiError(method, path, status, code, message)
    if status == 401:
        err.hint = "check MARKLOGIC_USER and MARKLOGIC_PASS"
    elif status == 403:
        err.hint = "MARKLOGIC_USER needs the manage-admin or admin role"
    return err


class ManageClient:
    """Minimal Management API client: digest auth, JSON in and out."""

    def __init__(self, config: Config, opener=None, timeout: float = 30):
        self.base_url = config.base_url
        self.timeout = timeout
        if opener is None:
            passwords = urllib.request.HTTPPasswordMgrWithDefaultRealm()
            passwords.add_password(None, self.base_url, config.user, config.password)
            handlers = [urllib.request.HTTPDigestAuthHandler(passwords)]
            if config.ssl_context is not None:
                handlers.append(urllib.request.HTTPSHandler(context=config.ssl_context))
            opener = urllib.request.build_opener(*handlers)
        self._opener = opener

    def _request(self, method: str, path: str, params=None, body=None):
        url = self.base_url + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        headers = {"Accept": "application/json"}
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as e:
            raise api_error(method, path, e.code, e.read()) from None
        except (urllib.error.URLError, OSError) as e:
            reason = getattr(e, "reason", e)
            raise TransportError(f"{method} {path}: cannot reach {self.base_url}: {reason}") from None
        except (http.client.HTTPException, ValueError) as e:
            raise TransportError(f"{method} {path}: bad response from {self.base_url}: {e!r}") from None

    @staticmethod
    def _json_or_none(raw: bytes):
        if not raw or not raw.strip():
            return None
        try:
            return json.loads(raw.decode("utf-8"))
        except ValueError:
            return None

    def get_json(self, path: str, params=None) -> dict:
        status, raw = self._request("GET", path, params)
        data = self._json_or_none(raw)
        if not isinstance(data, dict):
            raise ApiError("GET", path, status, message="response was not a JSON object")
        return data

    def post_json(self, path: str, params, body: dict):
        status, raw = self._request("POST", path, params, body)
        return status, self._json_or_none(raw)

    def delete(self, path: str, params):
        status, raw = self._request("DELETE", path, params)
        return status, self._json_or_none(raw)


def list_servers(client) -> list:
    """Every app server in the cluster as (name, group) pairs."""
    data = client.get_json("/manage/v2/servers", {"format": "json"})
    items = data.get("server-default-list", {}).get("list-items", {}).get("list-item", []) or []
    return [(item["nameref"], item["groupnameref"]) for item in items]


def resolve_group(servers, name: str, group: str | None = None) -> str:
    """Find the group holding app server `name`; `group` (from --group) narrows the search."""
    groups = sorted({g for n, g in servers if n == name})
    if group is not None:
        if group in groups:
            return group
        hint = f"'{name}' exists in: {', '.join(groups)}" if groups else None
        raise CloneError(f"app server '{name}' not found in group '{group}'", EXIT_PREFLIGHT, hint=hint)
    if not groups:
        raise CloneError(f"app server '{name}' not found in any group", EXIT_PREFLIGHT,
                         hint="names are case-sensitive; check the spelling in the Admin UI")
    if len(groups) > 1:
        raise CloneError(f"app server '{name}' exists in several groups: {', '.join(groups)}", EXIT_PREFLIGHT,
                         hint="choose one with --group")
    return groups[0]


def get_properties(client, name: str, group: str) -> dict:
    return client.get_json(server_path(name, "/properties"), {"group-id": group, "format": "json"})


def ports_in_group(client, servers, group: str) -> dict:
    """{port: app server name} for every app server in `group`."""
    used = {}
    for name, server_group in servers:
        if server_group == group:
            port = get_properties(client, name, group).get("port")
            if port is not None:
                used[int(port)] = name
    return used


def default_clone_name(source: str, port: int) -> str:
    return f"{source}-{port}"


def plan_clone(source_props: dict, name: str, port: int, existing_names, used_ports: dict) -> dict:
    """Check the clone's name and port are free and return the POST payload.

    The payload is the source's properties with only server-name and port changed
    (minus anything listed in STRIP_ON_POST).
    """
    group = source_props.get("group-name", "?")
    if name in existing_names:
        raise CloneError(f"an app server named '{name}' already exists in group '{group}'", EXIT_PREFLIGHT,
                         hint="choose another name with --name")
    if port in used_ports:
        raise CloneError(f"port {port} is already used by app server '{used_ports[port]}' in group '{group}'",
                         EXIT_PREFLIGHT, hint="choose another --port")
    payload = copy.deepcopy(source_props)
    for key in STRIP_ON_POST:
        payload.pop(key, None)
    payload["server-name"] = name
    payload["port"] = port
    return payload


def build_record(host: str, group: str, source: str, properties: dict, now=None) -> dict:
    """The JSON record saved after a successful clone. Contains no credentials."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    return {
        "tool": TOOL,
        "format-version": FORMAT_VERSION,
        "created": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "marklogic-host": host,
        "group": group,
        "source": source,
        "clone": {"name": properties["server-name"], "port": properties["port"]},
        "properties": properties,
    }


def check_output_path(path: str) -> None:
    """Fail before any change on the server if the record can't be written."""
    if os.path.exists(path):
        raise CloneError(f"output file '{path}' already exists", EXIT_PREFLIGHT,
                         hint="rename or move it, or choose another --output")
    directory = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(directory) or not os.access(directory, os.W_OK):
        raise CloneError(f"cannot write the record: directory '{directory}' is missing or not writable",
                         EXIT_PREFLIGHT, hint="choose another --output")


def write_record(path: str, record: dict) -> None:
    """Write to a temp file in the same directory, then rename it into place."""
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".appserver-clone-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(record, handle, indent=2)
            handle.write("\n")
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def load_record(path: str) -> dict:
    """Load and check a record written by this script, or explain how to remove the server by hand."""

    def fail(reason, record=None):
        group = name = None
        if isinstance(record, dict):
            group = record.get("group")
            clone = record.get("clone")
            name = clone.get("name") if isinstance(clone, dict) else None
        where = (f"Groups → {group} → App Servers → {name} → Delete" if isinstance(group, str) and isinstance(name, str)
                 else "Groups → <group> → App Servers → <app server> → Delete")
        raise CloneError(f"no usable clone record: {reason}", EXIT_PREFLIGHT,
                         hint="this script only removes app servers it created. "
                              f"Remove the app server manually in the Admin UI (port 8001): {where}")

    try:
        with open(path, encoding="utf-8") as handle:
            record = json.load(handle)
    except FileNotFoundError:
        fail(f"'{path}' does not exist")
    except OSError as e:
        fail(f"cannot read '{path}': {e.strerror}")
    except ValueError:
        fail(f"'{path}' is not valid JSON")
    if not isinstance(record, dict) or record.get("tool") != TOOL:
        fail(f"'{path}' was not created by {TOOL}")
    if record.get("format-version") != FORMAT_VERSION:
        fail(f"'{path}' has unsupported format-version {record.get('format-version')!r}", record)
    clone = record.get("clone")
    if (not isinstance(record.get("group"), str) or not isinstance(clone, dict)
            or not isinstance(clone.get("name"), str) or not isinstance(clone.get("port"), int)):
        fail(f"'{path}' is missing the group or clone name/port", record)
    return record


def restart_hosts(body) -> list:
    """(host-id, last-startup) pairs from a 202 restart response body; [] if absent."""
    try:
        return [(entry["host-id"], entry["value"]) for entry in body["restart"]["last-startup"]]
    except (KeyError, TypeError):
        return []


def _retryable(error: CloneError) -> bool:
    return isinstance(error, TransportError) or (isinstance(error, ApiError) and error.status >= 500)


def wait_for_restart(client, body, timeout: float = 180, interval: float = 2,
                     sleep=time.sleep, clock=time.monotonic) -> None:
    """Block until every host named in a 202 restart body has restarted."""
    pending = dict(restart_hosts(body))
    deadline = clock() + timeout
    if not pending:
        sleep(interval)  # no details: give the restart a chance to begin before polling
    while True:
        try:
            if pending:
                for host_id, old in list(pending.items()):
                    status = client.get_json("/manage/v2/hosts/" + urllib.parse.quote(host_id, safe=""),
                                             {"view": "status", "format": "json"})
                    try:
                        current = status["host-status"]["status-properties"]["status-detail"]["last-startup"]["value"]
                    except (KeyError, TypeError):
                        continue
                    if current != old:
                        del pending[host_id]
                if not pending:
                    return
            else:
                client.get_json("/manage/v2", {"format": "json"})
                return
        except (ApiError, TransportError) as e:
            if not _retryable(e):
                raise
        if clock() >= deadline:
            raise CloneError(f"MarkLogic did not finish restarting within {int(timeout)}s", EXIT_API,
                             hint="the change was submitted; check the Admin UI before trying again")
        sleep(interval)


def cmd_clone(client, config: Config, args, out=None, now=None, wait=wait_for_restart) -> int:
    out = out or sys.stdout
    name = args.name or default_clone_name(args.source, args.port)
    output = args.output or f"{name}.json"
    check_output_path(output)

    servers = list_servers(client)
    group = resolve_group(servers, args.source, args.group)
    source_props = get_properties(client, args.source, group)
    existing = {n for n, g in servers if g == group}
    payload = plan_clone(source_props, name, args.port, existing, ports_in_group(client, servers, group))

    print(f"source:  {args.source} (group '{group}', port {source_props.get('port')})", file=out)
    print(f"clone:   {name} (group '{group}', port {args.port})", file=out)
    print(f"record:  {output}", file=out)
    if args.dry_run:
        print("DRY RUN: no changes made. Payload that would be sent to POST /manage/v2/servers:", file=out)
        print(json.dumps(payload, indent=2), file=out)
        return EXIT_OK

    status, body = client.post_json("/manage/v2/servers", {"group-id": group}, payload)
    if status == 202:
        print("waiting for MarkLogic to restart...", file=out)
        wait(client, body)

    record = build_record(config.host, group, args.source, get_properties(client, name, group), now)
    try:
        write_record(output, record)
    except OSError as e:
        print(json.dumps(record, indent=2), file=out)
        raise CloneError(f"app server '{name}' WAS CREATED but the record could not be written to '{output}': {e}",
                         EXIT_API, hint="save the JSON printed above to a file; --remove needs it") from None
    print(f"created app server '{name}' on port {args.port} in group '{group}'; record saved to {output}", file=out)
    return EXIT_OK
