# appserver-clone.py Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A standalone, stdlib-only Python script that clones a MarkLogic app server to a new port via the Management API, saves a JSON record of the clone, and can later remove that clone using only the record.

**Architecture:** One file, `scripts/AppServer/appserver-clone.py`, built bottom-up. First the errors, configuration and Management API client; then pure lookup and planning functions; then the record file, the restart wait, the clone and remove commands, and finally the CLI. Pure functions take plain data. Network calls go through `ManageClient`, which the tests replace with an in-memory `FakeClient`.

**Tech Stack:** Python 3.8+ standard library only (`argparse`, `urllib.request` with `HTTPDigestAuthHandler`, `ssl`, `json`, `tempfile`), tested with `unittest`.

**Spec:** `docs/superpowers/specs/2026-11-21-appserver-clone-design.md`

## Global Constraints

- Python 3.8+ standard library only. No third-party imports. Single file. Keep `from __future__ import annotations` at the top so `str | None` annotations work on 3.8.
- Connection settings come **only** from environment variables: `MARKLOGIC_HOST`, `MARKLOGIC_USER`, `MARKLOGIC_PASS` (required); `MARKLOGIC_MANAGE_PORT` (default `8002`), `MARKLOGIC_SCHEME` (default `http`), `MARKLOGIC_CA_CERT`, `MARKLOGIC_INSECURE=1`, `MARKLOGIC_DEBUG=1` (optional). There are no flags for them, and `allow_abbrev=False`.
- Exit codes: `0` success, `1` usage or environment error, `2` pre-flight check failed, `3` Management API, network or restart-timeout error, `4` removal declined or not confirmed.
- Every property except `server-name` and `port` is copied unchanged from the source.
- Default clone name `<source>-<port>`. Default output `./<clone-name>.json`. Never overwrite an existing output file.
- The record has `"tool": "appserver-clone"` and `"format-version": 1`, and never contains credentials.
- The password never appears in any output or file. Tracebacks are shown only with `MARKLOGIC_DEBUG=1`.
- Run tests from the repo root: `python3 -m unittest discover -s scripts/AppServer -p 'test_*.py' -v`

## File Structure

| File | Responsibility |
|---|---|
| `scripts/AppServer/appserver-clone.py` | The script (created in Task 1, extended in each task) |
| `scripts/AppServer/test_appserver_clone.py` | Unit tests. Loads the hyphenated script with `importlib` |
| `README.md` | One new section pointing at the script (Task 8) |

---

### Task 1: Errors, configuration and the Management API client

**Files:**
- Create: `scripts/AppServer/appserver-clone.py`
- Create: `scripts/AppServer/test_appserver_clone.py`

**Interfaces:**
- Produces:
  - Constants `TOOL`, `FORMAT_VERSION`, `EXIT_OK`, `EXIT_USAGE`, `EXIT_PREFLIGHT`, `EXIT_API`, `EXIT_DECLINED`, `STRIP_ON_POST`
  - `CloneError(message, exit_code, hint=None)`, with `.exit_code` and `.hint`
  - `ApiError(method, path, status, message_code="", message="")`, a `CloneError` with `.status` and `.message_code`; exit code 3
  - `TransportError(message)`, a `CloneError`; exit code 3
  - `Config(host, user, password, port=8002, scheme="http", insecure=False, ssl_context=None)`, with `.base_url`
  - `load_config(environ) -> Config`
  - `server_path(name, suffix="") -> str`
  - `api_error(method, path, status, raw: bytes) -> ApiError`
  - `ManageClient(config, opener=None, timeout=30)` with:
    - `get_json(path, params=None) -> dict`
    - `post_json(path, params, body) -> (int, dict|None)`
    - `delete(path, params) -> (int, dict|None)`

- [ ] **Step 1: Write the failing tests**

Create `scripts/AppServer/test_appserver_clone.py`:

```python
"""Unit tests for appserver-clone.py. Run from the repo root:

    python3 -m unittest discover -s scripts/AppServer -p 'test_*.py' -v
"""
import argparse
import contextlib
import copy
import datetime
import importlib.util
import io
import json
import os
import pathlib
import ssl
import tempfile
import unittest
import urllib.error
import urllib.parse

_PATH = pathlib.Path(__file__).with_name("appserver-clone.py")
_SPEC = importlib.util.spec_from_file_location("appserver_clone", _PATH)
ac = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(ac)

ENV = {"MARKLOGIC_HOST": "ml1.example.com", "MARKLOGIC_USER": "admin", "MARKLOGIC_PASS": "s3cret-pw"}


class FakeResponse:
    def __init__(self, status, body=b""):
        self.status = status
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeOpener:
    def __init__(self, result):
        self.result = result
        self.requests = []

    def open(self, request, timeout=None):
        self.requests.append(request)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def http_error(code, body):
    return urllib.error.HTTPError("http://x", code, "err", {}, io.BytesIO(body))


class LoadConfigTests(unittest.TestCase):
    def test_missing_required_variables_are_all_named(self):
        with self.assertRaises(ac.CloneError) as cm:
            ac.load_config({})
        self.assertEqual(cm.exception.exit_code, ac.EXIT_USAGE)
        for name in ("MARKLOGIC_HOST", "MARKLOGIC_USER", "MARKLOGIC_PASS"):
            self.assertIn(name, str(cm.exception))

    def test_defaults(self):
        config = ac.load_config(ENV)
        self.assertEqual(config.port, 8002)
        self.assertEqual(config.scheme, "http")
        self.assertFalse(config.insecure)
        self.assertIsNone(config.ssl_context)
        self.assertEqual(config.base_url, "http://ml1.example.com:8002")

    def test_password_not_in_repr(self):
        self.assertNotIn("s3cret-pw", repr(ac.load_config(ENV)))

    def test_bad_scheme(self):
        with self.assertRaises(ac.CloneError) as cm:
            ac.load_config({**ENV, "MARKLOGIC_SCHEME": "ftp"})
        self.assertEqual(cm.exception.exit_code, ac.EXIT_USAGE)

    def test_bad_manage_port(self):
        for value in ("abc", "0", "70000"):
            with self.assertRaises(ac.CloneError):
                ac.load_config({**ENV, "MARKLOGIC_MANAGE_PORT": value})

    def test_https_insecure_disables_verification(self):
        config = ac.load_config({**ENV, "MARKLOGIC_SCHEME": "https", "MARKLOGIC_INSECURE": "1"})
        self.assertTrue(config.insecure)
        self.assertEqual(config.ssl_context.verify_mode, ssl.CERT_NONE)

    def test_https_verifies_by_default(self):
        config = ac.load_config({**ENV, "MARKLOGIC_SCHEME": "https"})
        self.assertEqual(config.ssl_context.verify_mode, ssl.CERT_REQUIRED)

    def test_missing_ca_file(self):
        with self.assertRaises(ac.CloneError) as cm:
            ac.load_config({**ENV, "MARKLOGIC_SCHEME": "https", "MARKLOGIC_CA_CERT": "/nonexistent/ca.pem"})
        self.assertEqual(cm.exception.exit_code, ac.EXIT_USAGE)


class ApiErrorTests(unittest.TestCase):
    def test_parses_marklogic_error_response(self):
        body = json.dumps({"errorResponse": {"statusCode": "404", "messageCode": "MANAGE-NOGROUPWITHSERVER",
                                             "message": "MANAGE-NOGROUPWITHSERVER: (err:FOER0000) No such group"}}).encode()
        err = ac.api_error("GET", "/manage/v2/servers/x/properties", 404, body)
        self.assertEqual(err.status, 404)
        self.assertEqual(err.message_code, "MANAGE-NOGROUPWITHSERVER")
        self.assertEqual(str(err), "GET /manage/v2/servers/x/properties → 404 MANAGE-NOGROUPWITHSERVER: (err:FOER0000) No such group")
        self.assertEqual(err.exit_code, ac.EXIT_API)

    def test_non_json_body(self):
        err = ac.api_error("GET", "/manage/v2", 401, b"<html>Unauthorized</html>")
        self.assertEqual(str(err), "GET /manage/v2 → 401")
        self.assertIn("MARKLOGIC_PASS", err.hint)

    def test_server_path_quotes_name(self):
        self.assertEqual(ac.server_path("My App/1", "/properties"), "/manage/v2/servers/My%20App%2F1/properties")


class ManageClientTests(unittest.TestCase):
    def client(self, result):
        opener = FakeOpener(result)
        return ac.ManageClient(ac.load_config(ENV), opener=opener), opener

    def test_get_json_builds_url_and_parses(self):
        client, opener = self.client(FakeResponse(200, b'{"a": 1}'))
        self.assertEqual(client.get_json("/manage/v2/servers", {"format": "json"}), {"a": 1})
        request = opener.requests[0]
        self.assertEqual(request.full_url, "http://ml1.example.com:8002/manage/v2/servers?format=json")
        self.assertEqual(request.get_method(), "GET")
        self.assertEqual(request.get_header("Accept"), "application/json")

    def test_get_json_rejects_non_object(self):
        client, _ = self.client(FakeResponse(200, b"<html/>"))
        with self.assertRaises(ac.ApiError):
            client.get_json("/manage/v2")

    def test_post_json_sends_body(self):
        client, opener = self.client(FakeResponse(201, b""))
        self.assertEqual(client.post_json("/manage/v2/servers", {"group-id": "Default"}, {"port": 9000}), (201, None))
        request = opener.requests[0]
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(json.loads(request.data), {"port": 9000})
        self.assertEqual(request.get_header("Content-type"), "application/json")

    def test_delete_returns_restart_body(self):
        body = b'{"restart": {"last-startup": [{"host-id": "1", "value": "t0"}]}}'
        client, opener = self.client(FakeResponse(202, body))
        status, data = client.delete("/manage/v2/servers/x", {"group-id": "Default"})
        self.assertEqual(status, 202)
        self.assertEqual(data["restart"]["last-startup"][0]["value"], "t0")
        self.assertEqual(opener.requests[0].get_method(), "DELETE")

    def test_http_error_becomes_api_error(self):
        body = b'{"errorResponse": {"messageCode": "ADMIN-PORTINUSE", "message": "port in use"}}'
        client, _ = self.client(http_error(400, body))
        with self.assertRaises(ac.ApiError) as cm:
            client.post_json("/manage/v2/servers", {}, {})
        self.assertEqual(cm.exception.status, 400)
        self.assertEqual(cm.exception.message_code, "ADMIN-PORTINUSE")

    def test_network_error_becomes_transport_error(self):
        client, _ = self.client(urllib.error.URLError("Connection refused"))
        with self.assertRaises(ac.TransportError) as cm:
            client.get_json("/manage/v2")
        self.assertEqual(cm.exception.exit_code, ac.EXIT_API)
        self.assertIn("Connection refused", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run the tests to check they fail**

Run: `python3 -m unittest discover -s scripts/AppServer -p 'test_*.py' -v`
Expected: an error loading the module (`FileNotFoundError` for `appserver-clone.py`).

- [ ] **Step 3: Write the implementation**

Create `scripts/AppServer/appserver-clone.py`:

```python
#!/usr/bin/env python3
"""Clone a MarkLogic app server to a new port, or remove a clone made by this script.

Run with no arguments (or -h / --help) for full usage.
"""
from __future__ import annotations

import argparse
import copy
import datetime
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
```

(`argparse`, `copy`, `datetime`, `os`, `sys`, `tempfile`, `time` and `traceback` are used by later tasks. Import them now so the header doesn't change again.)

- [ ] **Step 4: Run the tests to check they pass**

Run: `python3 -m unittest discover -s scripts/AppServer -p 'test_*.py' -v`
Expected: all tests in `LoadConfigTests`, `ApiErrorTests` and `ManageClientTests` pass.

- [ ] **Step 5: Commit**

```bash
chmod +x scripts/AppServer/appserver-clone.py
git add scripts/AppServer/appserver-clone.py scripts/AppServer/test_appserver_clone.py
git commit -m "appserver-clone: config from environment, Management API client"
```

---

### Task 2: Server lookups and clone planning

**Files:**
- Modify: `scripts/AppServer/appserver-clone.py` (append after `ManageClient`)
- Modify: `scripts/AppServer/test_appserver_clone.py` (add `FakeClient` and the test classes before `if __name__ == "__main__":`)

**Interfaces:**
- Consumes: `ApiError`, `CloneError`, `EXIT_PREFLIGHT`, `STRIP_ON_POST`, `server_path`, and a client offering `get_json(path, params)`.
- Produces:
  - `list_servers(client) -> list[tuple[str, str]]`, a list of `(name, group)`
  - `resolve_group(servers, name, group=None) -> str`
  - `get_properties(client, name, group) -> dict`
  - `ports_in_group(client, servers, group) -> dict[int, str]`
  - `default_clone_name(source, port) -> str`
  - `plan_clone(source_props, name, port, existing_names, used_ports) -> dict`
  - The test helper `FakeClient(servers, props)`, where `servers` is a list of `(name, group)` and `props` is `{(name, group): dict}`. It has `.calls`, `.post_status`, `.delete_status`, `.restart_body`, `.mutating_calls()` and `.fail_post`. Tasks 5–7 use it.

- [ ] **Step 1: Write the failing tests**

Add to `scripts/AppServer/test_appserver_clone.py`, before `if __name__ == "__main__":`:

```python
SOURCE_PROPS = {
    "server-name": "App-Services", "group-name": "Default", "server-type": "http", "port": 8000,
    "authentication": "digest", "content-database": "Documents", "modules-database": "Modules",
    "url-rewriter": "/MarkLogic/rest-api/8000-rewriter.xml", "output-cdata-section-localname": None,
}


class FakeClient:
    """In-memory stand-in for ManageClient. Records every call."""

    PREFIX = "/manage/v2/servers/"

    def __init__(self, servers, props):
        self.servers = list(servers)
        self.props = {k: copy.deepcopy(v) for k, v in props.items()}
        self.calls = []
        self.post_status = 201
        self.delete_status = 204
        self.restart_body = None
        self.fail_post = None

    def mutating_calls(self):
        return [c for c in self.calls if c[0] != "GET"]

    def _name(self, path, suffix=""):
        return urllib.parse.unquote(path[len(self.PREFIX):len(path) - len(suffix)])

    def get_json(self, path, params=None):
        self.calls.append(("GET", path, params))
        if path == "/manage/v2/servers":
            items = [{"nameref": n, "groupnameref": g} for n, g in self.servers]
            return {"server-default-list": {"list-items": {"list-item": items}}}
        if path.startswith(self.PREFIX) and path.endswith("/properties"):
            key = (self._name(path, "/properties"), params["group-id"])
            if key not in self.props:
                raise ac.ApiError("GET", path, 404, "MANAGE-NOGROUPWITHSERVER", "no such server")
            return copy.deepcopy(self.props[key])
        if path == "/manage/v2":
            return {}
        raise AssertionError(f"unexpected GET {path}")

    def post_json(self, path, params, body):
        self.calls.append(("POST", path, params, copy.deepcopy(body)))
        if self.fail_post:
            raise self.fail_post
        key = (body["server-name"], params["group-id"])
        self.props[key] = copy.deepcopy(body)
        self.servers.append(key)
        return self.post_status, self.restart_body

    def delete(self, path, params):
        self.calls.append(("DELETE", path, params))
        key = (self._name(path), params["group-id"])
        del self.props[key]
        self.servers.remove(key)
        return self.delete_status, self.restart_body


def default_fake():
    return FakeClient(
        [("App-Services", "Default"), ("Admin", "Default"), ("Manage", "Default")],
        {("App-Services", "Default"): SOURCE_PROPS,
         ("Admin", "Default"): {"server-name": "Admin", "port": 8001},
         ("Manage", "Default"): {"server-name": "Manage", "port": 8002}},
    )


class LookupTests(unittest.TestCase):
    def test_list_servers(self):
        self.assertEqual(ac.list_servers(default_fake())[0], ("App-Services", "Default"))

    def test_list_servers_empty(self):
        self.assertEqual(ac.list_servers(FakeClient([], {})), [])

    def test_resolve_single_group(self):
        self.assertEqual(ac.resolve_group([("A", "G1"), ("B", "G2")], "B"), "G2")

    def test_resolve_not_found(self):
        with self.assertRaises(ac.CloneError) as cm:
            ac.resolve_group([("A", "G1")], "Nope")
        self.assertEqual(cm.exception.exit_code, ac.EXIT_PREFLIGHT)

    def test_resolve_ambiguous_lists_groups(self):
        with self.assertRaises(ac.CloneError) as cm:
            ac.resolve_group([("A", "G2"), ("A", "G1")], "A")
        self.assertEqual(cm.exception.exit_code, ac.EXIT_PREFLIGHT)
        self.assertIn("G1, G2", str(cm.exception))
        self.assertIn("--group", cm.exception.hint)

    def test_resolve_explicit_group(self):
        self.assertEqual(ac.resolve_group([("A", "G1"), ("A", "G2")], "A", "G2"), "G2")

    def test_resolve_explicit_group_without_source(self):
        with self.assertRaises(ac.CloneError) as cm:
            ac.resolve_group([("A", "G1")], "A", "G2")
        self.assertIn("G1", cm.exception.hint)

    def test_ports_in_group(self):
        fake = default_fake()
        self.assertEqual(ac.ports_in_group(fake, ac.list_servers(fake), "Default"),
                         {8000: "App-Services", 8001: "Admin", 8002: "Manage"})


class PlanCloneTests(unittest.TestCase):
    def test_default_clone_name(self):
        self.assertEqual(ac.default_clone_name("App-Services", 8050), "App-Services-8050")

    def test_payload_differs_only_in_name_and_port(self):
        payload = ac.plan_clone(SOURCE_PROPS, "AppServices-Digest", 9000, {"App-Services"}, {8000: "App-Services"})
        self.assertEqual(payload["server-name"], "AppServices-Digest")
        self.assertEqual(payload["port"], 9000)
        changed = {k for k in set(payload) | set(SOURCE_PROPS) if payload.get(k, "<absent>") != SOURCE_PROPS.get(k, "<absent>")}
        self.assertEqual(changed, {"server-name", "port"})

    def test_source_not_mutated(self):
        before = copy.deepcopy(SOURCE_PROPS)
        ac.plan_clone(SOURCE_PROPS, "X", 9000, set(), {})
        self.assertEqual(SOURCE_PROPS, before)

    def test_name_conflict(self):
        with self.assertRaises(ac.CloneError) as cm:
            ac.plan_clone(SOURCE_PROPS, "App-Services", 9000, {"App-Services"}, {})
        self.assertEqual(cm.exception.exit_code, ac.EXIT_PREFLIGHT)
        self.assertIn("Default", str(cm.exception))

    def test_port_conflict_names_owner(self):
        with self.assertRaises(ac.CloneError) as cm:
            ac.plan_clone(SOURCE_PROPS, "X", 8001, set(), {8001: "Admin"})
        self.assertEqual(cm.exception.exit_code, ac.EXIT_PREFLIGHT)
        self.assertIn("Admin", str(cm.exception))
```

- [ ] **Step 2: Run the tests to check they fail**

Run: `python3 -m unittest discover -s scripts/AppServer -p 'test_*.py' -v`
Expected: the `LookupTests` and `PlanCloneTests` tests fail with `AttributeError: module 'appserver_clone' has no attribute 'list_servers'` (or a similar missing name).

- [ ] **Step 3: Write the implementation**

Append to `scripts/AppServer/appserver-clone.py`:

```python
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
```

- [ ] **Step 4: Run the tests to check they pass**

Run: `python3 -m unittest discover -s scripts/AppServer -p 'test_*.py' -v`
Expected: every test passes.

- [ ] **Step 5: Commit**

```bash
git add scripts/AppServer/appserver-clone.py scripts/AppServer/test_appserver_clone.py
git commit -m "appserver-clone: group lookup, port inventory, clone payload planning"
```

---

### Task 3: The JSON record

**Files:**
- Modify: `scripts/AppServer/appserver-clone.py` (append)
- Modify: `scripts/AppServer/test_appserver_clone.py` (add a test class before `if __name__ == "__main__":`)

**Interfaces:**
- Consumes: `CloneError`, `EXIT_PREFLIGHT`, `TOOL`, `FORMAT_VERSION`.
- Produces:
  - `build_record(host, group, source, properties, now=None) -> dict`
  - `check_output_path(path) -> None`, which raises `CloneError` (exit 2)
  - `write_record(path, record) -> None`, which writes atomically and raises `OSError` on failure
  - `load_record(path) -> dict`, which raises `CloneError` (exit 2) whose hint holds the Admin UI instructions

- [ ] **Step 1: Write the failing tests**

Add before `if __name__ == "__main__":`:

```python
CLONE_PROPS = dict(SOURCE_PROPS, **{"server-name": "AppServices-Digest", "port": 9000})
NOW = datetime.datetime(2026, 11, 21, 14, 3, 11, tzinfo=datetime.timezone.utc)


class RecordTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.path = os.path.join(self.dir.name, "AppServices-Digest.json")

    def record(self):
        return ac.build_record("ml1.example.com", "Default", "App-Services", CLONE_PROPS, now=NOW)

    def test_build_record_shape(self):
        record = self.record()
        self.assertEqual(record["tool"], "appserver-clone")
        self.assertEqual(record["format-version"], 1)
        self.assertEqual(record["created"], "2026-11-21T14:03:11Z")
        self.assertEqual(record["clone"], {"name": "AppServices-Digest", "port": 9000})
        self.assertEqual(record["properties"], CLONE_PROPS)
        self.assertNotIn("s3cret-pw", json.dumps(record))

    def test_write_then_load_round_trip(self):
        ac.write_record(self.path, self.record())
        self.assertEqual(ac.load_record(self.path), self.record())
        self.assertEqual(os.listdir(self.dir.name), ["AppServices-Digest.json"])  # no temp file left behind

    def test_check_output_path_refuses_existing(self):
        pathlib.Path(self.path).write_text("{}")
        with self.assertRaises(ac.CloneError) as cm:
            ac.check_output_path(self.path)
        self.assertEqual(cm.exception.exit_code, ac.EXIT_PREFLIGHT)

    def test_check_output_path_missing_directory(self):
        with self.assertRaises(ac.CloneError):
            ac.check_output_path(os.path.join(self.dir.name, "nope", "x.json"))

    def test_check_output_path_ok(self):
        ac.check_output_path(self.path)

    def test_load_missing_file_gives_admin_ui_instructions(self):
        with self.assertRaises(ac.CloneError) as cm:
            ac.load_record(self.path)
        self.assertEqual(cm.exception.exit_code, ac.EXIT_PREFLIGHT)
        self.assertIn("does not exist", str(cm.exception))
        self.assertIn("Admin UI", cm.exception.hint)
        self.assertIn("Groups", cm.exception.hint)

    def test_load_invalid_json(self):
        pathlib.Path(self.path).write_text("not json")
        with self.assertRaises(ac.CloneError) as cm:
            ac.load_record(self.path)
        self.assertIn("not valid JSON", str(cm.exception))

    def test_load_foreign_json(self):
        pathlib.Path(self.path).write_text('{"server-name": "X", "port": 1}')
        with self.assertRaises(ac.CloneError) as cm:
            ac.load_record(self.path)
        self.assertIn("not created by appserver-clone", str(cm.exception))
        self.assertIn("Admin UI", cm.exception.hint)

    def test_load_bad_version_names_server_in_hint(self):
        record = self.record()
        record["format-version"] = 99
        pathlib.Path(self.path).write_text(json.dumps(record))
        with self.assertRaises(ac.CloneError) as cm:
            ac.load_record(self.path)
        self.assertIn("Groups → Default → App Servers → AppServices-Digest → Delete", cm.exception.hint)
```

- [ ] **Step 2: Run the tests to check they fail**

Run: `python3 -m unittest discover -s scripts/AppServer -p 'test_*.py' -v`
Expected: the `RecordTests` tests fail with `AttributeError: ... 'build_record'` (or a similar missing name).

- [ ] **Step 3: Write the implementation**

Append to `scripts/AppServer/appserver-clone.py`:

```python
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
```

- [ ] **Step 4: Run the tests to check they pass**

Run: `python3 -m unittest discover -s scripts/AppServer -p 'test_*.py' -v`
Expected: every test passes.

- [ ] **Step 5: Commit**

```bash
git add scripts/AppServer/appserver-clone.py scripts/AppServer/test_appserver_clone.py
git commit -m "appserver-clone: JSON record build, atomic write, validated load"
```

---

### Task 4: Waiting for MarkLogic to restart

**Files:**
- Modify: `scripts/AppServer/appserver-clone.py` (append)
- Modify: `scripts/AppServer/test_appserver_clone.py` (add a test class before `if __name__ == "__main__":`)

**Interfaces:**
- Consumes: `ApiError`, `TransportError`, `CloneError`, `EXIT_API`, and `client.get_json`.
- Produces:
  - `restart_hosts(body) -> list[tuple[str, str]]`, a list of `(host_id, last_startup)`
  - `wait_for_restart(client, body, timeout=180, interval=2, sleep=time.sleep, clock=time.monotonic) -> None`, which raises `CloneError` (exit 3) on timeout

Background (checked against MarkLogic 12.1): a 202 response body looks like `{"restart": {"last-startup": [{"host-id": "...", "value": "2026-...Z"}]}}`. `GET /manage/v2/hosts/{host-id}?view=status&format=json` on port 8002 returns the current value at `host-status.status-properties.status-detail.last-startup.value`. A host has restarted once that value changes.

- [ ] **Step 1: Write the failing tests**

Add before `if __name__ == "__main__":`:

```python
def host_status(value):
    return {"host-status": {"status-properties": {"status-detail": {"last-startup": {"units": "datetime", "value": value}}}}}


class ScriptedClient:
    """Returns (or raises) the next scripted item on every get_json call."""

    def __init__(self, script):
        self.script = list(script)
        self.paths = []

    def get_json(self, path, params=None):
        self.paths.append(path)
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


RESTART_BODY = {"restart": {"last-startup": [{"host-id": "123", "value": "t0"}]}}


class WaitForRestartTests(unittest.TestCase):
    def wait(self, client, body, timeout=180):
        clock = FakeClock()
        ac.wait_for_restart(client, body, timeout=timeout, interval=2, sleep=clock.sleep, clock=clock)
        return clock

    def test_restart_hosts(self):
        self.assertEqual(ac.restart_hosts(RESTART_BODY), [("123", "t0")])
        self.assertEqual(ac.restart_hosts(None), [])
        self.assertEqual(ac.restart_hosts({"x": 1}), [])

    def test_waits_until_last_startup_changes(self):
        client = ScriptedClient([
            host_status("t0"),
            ac.TransportError("connection refused"),
            ac.ApiError("GET", "/manage/v2/hosts/123", 503),
            host_status("t1"),
        ])
        self.wait(client, RESTART_BODY)
        self.assertEqual(client.paths[0], "/manage/v2/hosts/123")
        self.assertEqual(client.script, [])

    def test_times_out(self):
        client = ScriptedClient([host_status("t0")] * 200)
        with self.assertRaises(ac.CloneError) as cm:
            self.wait(client, RESTART_BODY, timeout=10)
        self.assertEqual(cm.exception.exit_code, ac.EXIT_API)
        self.assertIn("submitted", cm.exception.hint)

    def test_client_errors_are_not_retried(self):
        client = ScriptedClient([ac.ApiError("GET", "/manage/v2/hosts/123", 401)])
        with self.assertRaises(ac.ApiError):
            self.wait(client, RESTART_BODY)

    def test_without_restart_details_polls_manage_root(self):
        client = ScriptedClient([ac.TransportError("refused"), {}])
        clock = self.wait(client, None)
        self.assertEqual(client.paths, ["/manage/v2", "/manage/v2"])
        self.assertGreaterEqual(clock.now, 2)  # waited at least one interval before the first poll
```

- [ ] **Step 2: Run the tests to check they fail**

Run: `python3 -m unittest discover -s scripts/AppServer -p 'test_*.py' -v`
Expected: the `WaitForRestartTests` tests fail with `AttributeError: ... 'restart_hosts'`.

- [ ] **Step 3: Write the implementation**

Append to `scripts/AppServer/appserver-clone.py`:

```python
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
```

- [ ] **Step 4: Run the tests to check they pass**

Run: `python3 -m unittest discover -s scripts/AppServer -p 'test_*.py' -v`
Expected: every test passes.

- [ ] **Step 5: Commit**

```bash
git add scripts/AppServer/appserver-clone.py scripts/AppServer/test_appserver_clone.py
git commit -m "appserver-clone: wait for restart via host last-startup on the Management API"
```

---

### Task 5: The clone command

**Files:**
- Modify: `scripts/AppServer/appserver-clone.py` (append)
- Modify: `scripts/AppServer/test_appserver_clone.py` (add a test class before `if __name__ == "__main__":`)

**Interfaces:**
- Consumes: everything from Tasks 1–4. In the tests, `FakeClient`, `default_fake`, `ENV`, `NOW` and `SOURCE_PROPS`.
- Produces: `cmd_clone(client, config, args, out=None, now=None, wait=wait_for_restart) -> int`. `args` has `source`, `port`, `name`, `group`, `output` and `dry_run`.

- [ ] **Step 1: Write the failing tests**

Add before `if __name__ == "__main__":`:

```python
def clone_args(**overrides):
    values = dict(source="App-Services", port=9000, name="AppServices-Digest", group=None, output=None, dry_run=False)
    values.update(overrides)
    return argparse.Namespace(**values)


class CloneCommandTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.config = ac.load_config(ENV)
        self.output = os.path.join(self.dir.name, "AppServices-Digest.json")

    def run_clone(self, fake, **overrides):
        overrides.setdefault("output", self.output)
        self.waits = getattr(self, "waits", [])
        out = io.StringIO()
        code = ac.cmd_clone(fake, self.config, clone_args(**overrides), out=out, now=NOW,
                            wait=lambda client, body: self.waits.append(body))
        return code, out.getvalue()

    def test_clone_posts_payload_and_writes_record(self):
        fake = default_fake()
        code, out = self.run_clone(fake)
        self.assertEqual(code, ac.EXIT_OK)
        (method, path, params, body), = fake.mutating_calls()
        self.assertEqual((method, path, params), ("POST", "/manage/v2/servers", {"group-id": "Default"}))
        self.assertEqual(body, dict(SOURCE_PROPS, **{"server-name": "AppServices-Digest", "port": 9000}))
        record = ac.load_record(self.output)
        self.assertEqual(record["clone"], {"name": "AppServices-Digest", "port": 9000})
        self.assertEqual(record["source"], "App-Services")
        self.assertEqual(record["marklogic-host"], "ml1.example.com")
        self.assertIn("created app server 'AppServices-Digest'", out)

    def test_default_name_and_output(self):
        fake = default_fake()
        cwd = os.getcwd()
        os.chdir(self.dir.name)
        self.addCleanup(os.chdir, cwd)
        code, _ = self.run_clone(fake, name=None, output=None, port=8050)
        self.assertEqual(code, ac.EXIT_OK)
        self.assertTrue(os.path.exists(os.path.join(self.dir.name, "App-Services-8050.json")))

    def test_dry_run_changes_nothing(self):
        fake = default_fake()
        code, out = self.run_clone(fake, dry_run=True)
        self.assertEqual(code, ac.EXIT_OK)
        self.assertEqual(fake.mutating_calls(), [])
        self.assertFalse(os.path.exists(self.output))
        self.assertIn("DRY RUN", out)
        self.assertIn('"server-name": "AppServices-Digest"', out)

    def test_existing_output_fails_before_any_api_call(self):
        pathlib.Path(self.output).write_text("{}")
        fake = default_fake()
        with self.assertRaises(ac.CloneError) as cm:
            self.run_clone(fake)
        self.assertEqual(cm.exception.exit_code, ac.EXIT_PREFLIGHT)
        self.assertEqual(fake.calls, [])

    def test_port_in_use_fails_without_post(self):
        fake = default_fake()
        with self.assertRaises(ac.CloneError) as cm:
            self.run_clone(fake, port=8001)
        self.assertIn("Admin", str(cm.exception))
        self.assertEqual(fake.mutating_calls(), [])

    def test_restart_is_waited_for(self):
        fake = default_fake()
        fake.post_status, fake.restart_body = 202, RESTART_BODY
        self.run_clone(fake)
        self.assertEqual(self.waits, [RESTART_BODY])

    def test_record_write_failure_prints_record(self):
        fake = default_fake()
        original = ac.write_record
        def broken(path, record):
            raise OSError(28, "No space left on device")
        ac.write_record = broken
        self.addCleanup(setattr, ac, "write_record", original)
        out = io.StringIO()
        with self.assertRaises(ac.CloneError) as cm:
            ac.cmd_clone(fake, self.config, clone_args(output=self.output), out=out, now=NOW, wait=lambda c, b: None)
        self.assertEqual(cm.exception.exit_code, ac.EXIT_API)
        self.assertIn("WAS CREATED", str(cm.exception))
        printed = out.getvalue()
        self.assertEqual(json.loads(printed[printed.index("{"):])["clone"]["name"], "AppServices-Digest")
```

- [ ] **Step 2: Run the tests to check they fail**

Run: `python3 -m unittest discover -s scripts/AppServer -p 'test_*.py' -v`
Expected: the `CloneCommandTests` tests fail with `AttributeError: ... 'cmd_clone'`.

- [ ] **Step 3: Write the implementation**

Append to `scripts/AppServer/appserver-clone.py`:

```python
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
```

- [ ] **Step 4: Run the tests to check they pass**

Run: `python3 -m unittest discover -s scripts/AppServer -p 'test_*.py' -v`
Expected: every test passes.

- [ ] **Step 5: Commit**

```bash
git add scripts/AppServer/appserver-clone.py scripts/AppServer/test_appserver_clone.py
git commit -m "appserver-clone: clone command with dry run and record"
```

---

### Task 6: The remove command

**Files:**
- Modify: `scripts/AppServer/appserver-clone.py` (append)
- Modify: `scripts/AppServer/test_appserver_clone.py` (add a test class before `if __name__ == "__main__":`)

**Interfaces:**
- Consumes: `load_record`'s output, `get_properties`, `server_path`, `wait_for_restart`, plus `FakeClient`, `CLONE_PROPS`, `NOW` and `RESTART_BODY` in the tests.
- Produces: `cmd_remove(client, config, args, record, stdin=None, input_fn=input, out=None, wait=wait_for_restart) -> int`. `args` has `remove` (the path), `yes` and `dry_run`.

- [ ] **Step 1: Write the failing tests**

Add before `if __name__ == "__main__":`:

```python
class FakeStdin:
    def __init__(self, tty):
        self.tty = tty

    def isatty(self):
        return self.tty


class RemoveCommandTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.config = ac.load_config(ENV)
        self.path = os.path.join(self.dir.name, "AppServices-Digest.json")
        ac.write_record(self.path, ac.build_record("ml1.example.com", "Default", "App-Services", CLONE_PROPS, now=NOW))
        self.record = ac.load_record(self.path)
        self.fake = FakeClient([("App-Services", "Default"), ("AppServices-Digest", "Default")],
                               {("App-Services", "Default"): SOURCE_PROPS,
                                ("AppServices-Digest", "Default"): CLONE_PROPS})

    def run_remove(self, yes=False, dry_run=False, tty=True, answer="y", config=None):
        out = io.StringIO()
        args = argparse.Namespace(remove=self.path, yes=yes, dry_run=dry_run)
        code = ac.cmd_remove(self.fake, config or self.config, args, self.record, stdin=FakeStdin(tty),
                             input_fn=lambda prompt: answer, out=out, wait=lambda c, b: None)
        return code, out.getvalue()

    def test_remove_with_yes_deletes_and_renames_record(self):
        code, out = self.run_remove(yes=True)
        self.assertEqual(code, ac.EXIT_OK)
        self.assertEqual(self.fake.mutating_calls(),
                         [("DELETE", "/manage/v2/servers/AppServices-Digest", {"group-id": "Default"})])
        self.assertFalse(os.path.exists(self.path))
        self.assertTrue(os.path.exists(self.path + ".removed"))
        self.assertIn("deleted app server 'AppServices-Digest'", out)

    def test_prompt_yes_deletes(self):
        code, _ = self.run_remove(answer="y")
        self.assertEqual(code, ac.EXIT_OK)
        self.assertEqual(len(self.fake.mutating_calls()), 1)

    def test_prompt_no_declines(self):
        code, _ = self.run_remove(answer="")
        self.assertEqual(code, ac.EXIT_DECLINED)
        self.assertEqual(self.fake.mutating_calls(), [])
        self.assertTrue(os.path.exists(self.path))

    def test_no_tty_without_yes_refuses(self):
        with self.assertRaises(ac.CloneError) as cm:
            self.run_remove(tty=False)
        self.assertEqual(cm.exception.exit_code, ac.EXIT_DECLINED)
        self.assertIn("--yes", cm.exception.hint)
        self.assertEqual(self.fake.mutating_calls(), [])

    def test_dry_run_changes_nothing(self):
        code, out = self.run_remove(dry_run=True, yes=True)
        self.assertEqual(code, ac.EXIT_OK)
        self.assertEqual(self.fake.mutating_calls(), [])
        self.assertTrue(os.path.exists(self.path))
        self.assertIn("DRY RUN", out)

    def test_already_removed(self):
        del self.fake.props[("AppServices-Digest", "Default")]
        code, out = self.run_remove(yes=True)
        self.assertEqual(code, ac.EXIT_OK)
        self.assertIn("nothing to remove", out)
        self.assertTrue(os.path.exists(self.path))

    def test_port_mismatch_refuses(self):
        self.fake.props[("AppServices-Digest", "Default")]["port"] = 9100
        with self.assertRaises(ac.CloneError) as cm:
            self.run_remove(yes=True)
        self.assertEqual(cm.exception.exit_code, ac.EXIT_PREFLIGHT)
        self.assertIn("9100", str(cm.exception))
        self.assertEqual(self.fake.mutating_calls(), [])

    def test_host_mismatch_warns_but_continues(self):
        other = ac.load_config({**ENV, "MARKLOGIC_HOST": "ml-alias.example.com"})
        code, out = self.run_remove(yes=True, config=other)
        self.assertEqual(code, ac.EXIT_OK)
        self.assertIn("warning", out)

    def test_restart_is_waited_for(self):
        self.fake.delete_status, self.fake.restart_body = 202, RESTART_BODY
        waits = []
        args = argparse.Namespace(remove=self.path, yes=True, dry_run=False)
        ac.cmd_remove(self.fake, self.config, args, self.record, stdin=FakeStdin(True), out=io.StringIO(),
                      wait=lambda c, b: waits.append(b))
        self.assertEqual(waits, [RESTART_BODY])
```

- [ ] **Step 2: Run the tests to check they fail**

Run: `python3 -m unittest discover -s scripts/AppServer -p 'test_*.py' -v`
Expected: the `RemoveCommandTests` tests fail with `AttributeError: ... 'cmd_remove'`.

- [ ] **Step 3: Write the implementation**

Append to `scripts/AppServer/appserver-clone.py`:

```python
def cmd_remove(client, config: Config, args, record: dict, stdin=None, input_fn=input, out=None,
               wait=wait_for_restart) -> int:
    out = out or sys.stdout
    stdin = stdin or sys.stdin
    group, name, port = record["group"], record["clone"]["name"], record["clone"]["port"]

    if record.get("marklogic-host") != config.host:
        print(f"warning: record was created via host '{record.get('marklogic-host')}', "
              f"MARKLOGIC_HOST is '{config.host}'; continuing because name, group and port are checked",
              file=out)
    try:
        current = get_properties(client, name, group)
    except ApiError as e:
        if e.status == 404:
            print(f"app server '{name}' no longer exists in group '{group}'; nothing to remove", file=out)
            return EXIT_OK
        raise
    if current.get("port") != port:
        raise CloneError(f"app server '{name}' now listens on port {current.get('port')}, but the record says {port}; "
                         "refusing to delete", EXIT_PREFLIGHT,
                         hint="it may have been changed or recreated; if you are sure, remove it in the Admin UI")

    print(f"will delete app server '{name}' (group '{group}', port {port}); "
          "MarkLogic restarts on the group's hosts afterwards", file=out)
    if args.dry_run:
        print("DRY RUN: no changes made", file=out)
        return EXIT_OK
    if not args.yes:
        if not stdin.isatty():
            raise CloneError("refusing to delete without confirmation: no terminal to prompt on", EXIT_DECLINED,
                             hint="re-run with --yes to confirm")
        answer = input_fn(f"Delete app server {name} (group {group}, port {port})? [y/N] ")
        if answer.strip().lower() not in ("y", "yes"):
            print("not deleted", file=out)
            return EXIT_DECLINED

    status, body = client.delete(server_path(name), {"group-id": group})
    if status == 202:
        print("waiting for MarkLogic to restart...", file=out)
        wait(client, body)
    try:
        get_properties(client, name, group)
    except ApiError as e:
        if e.status != 404:
            raise
    else:
        raise CloneError(f"DELETE returned {status} but app server '{name}' still exists", EXIT_API)

    removed = args.remove + ".removed"
    if os.path.exists(removed):
        removed += "." + datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    os.replace(args.remove, removed)
    print(f"deleted app server '{name}' from group '{group}'; record renamed to {removed}", file=out)
    return EXIT_OK
```

- [ ] **Step 4: Run the tests to check they pass**

Run: `python3 -m unittest discover -s scripts/AppServer -p 'test_*.py' -v`
Expected: every test passes.

- [ ] **Step 5: Commit**

```bash
git add scripts/AppServer/appserver-clone.py scripts/AppServer/test_appserver_clone.py
git commit -m "appserver-clone: remove command driven only by the saved record"
```

---

### Task 7: Command line, help text and `main`

**Files:**
- Modify: `scripts/AppServer/appserver-clone.py` (append)
- Modify: `scripts/AppServer/test_appserver_clone.py` (add a test class before `if __name__ == "__main__":`)

**Interfaces:**
- Consumes: `load_config`, `ManageClient`, `load_record`, `cmd_clone`, `cmd_remove`, `CloneError` and the exit codes.
- Produces:
  - `build_parser() -> argparse.ArgumentParser`
  - `validate_args(args) -> None`, which raises `CloneError` (exit 1)
  - `main(argv=None, environ=None, client_factory=ManageClient) -> int`
  - Script entry point `sys.exit(main())`

- [ ] **Step 1: Write the failing tests**

Add before `if __name__ == "__main__":`:

```python
class MainTests(unittest.TestCase):
    def run_main(self, argv, environ=ENV, fake=None):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = ac.main(argv, environ=environ, client_factory=lambda config: fake or default_fake())
        return code, out.getvalue(), err.getvalue()

    def test_no_arguments_prints_help_and_exits_0(self):
        code, out, _ = self.run_main([])
        self.assertEqual(code, ac.EXIT_OK)
        _, help_out, _ = self.run_main_help()
        self.assertEqual(out, help_out)
        for text in ("MARKLOGIC_PASS", "--remove", "--dry-run", "exit codes", "Admin UI"):
            self.assertIn(text, out)

    def run_main_help(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as cm:
            ac.main(["--help"], environ=ENV)
        self.assertEqual(cm.exception.code, 0)
        return 0, out.getvalue(), ""

    def test_password_flag_rejected(self):
        code, _, err = self.run_main(["App-Services", "--port", "9000", "--password", "x"])
        self.assertEqual(code, ac.EXIT_USAGE)
        self.assertIn("unrecognized arguments", err)
        self.assertIn("environment", err)

    def test_abbreviations_disabled(self):
        code, _, _ = self.run_main(["App-Services", "--po", "9000"])
        self.assertEqual(code, ac.EXIT_USAGE)

    def test_clone_requires_port(self):
        code, _, err = self.run_main(["App-Services"])
        self.assertEqual(code, ac.EXIT_USAGE)
        self.assertIn("--port", err)

    def test_invalid_port(self):
        code, _, _ = self.run_main(["App-Services", "--port", "70000"])
        self.assertEqual(code, ac.EXIT_USAGE)

    def test_remove_rejects_clone_options(self):
        code, _, err = self.run_main(["--remove", "x.json", "--port", "9000"])
        self.assertEqual(code, ac.EXIT_USAGE)
        self.assertIn("--port", err)

    def test_yes_only_with_remove(self):
        code, _, _ = self.run_main(["App-Services", "--port", "9000", "--yes"])
        self.assertEqual(code, ac.EXIT_USAGE)

    def test_missing_environment(self):
        code, _, err = self.run_main(["App-Services", "--port", "9000", "--dry-run"], environ={})
        self.assertEqual(code, ac.EXIT_USAGE)
        self.assertIn("MARKLOGIC_HOST", err)

    def test_remove_missing_record_explains_admin_ui_even_without_environment(self):
        code, _, err = self.run_main(["--remove", "/nonexistent/x.json"], environ={})
        self.assertEqual(code, ac.EXIT_PREFLIGHT)
        self.assertIn("Admin UI", err)

    def test_dry_run_end_to_end(self):
        fake = default_fake()
        with tempfile.TemporaryDirectory() as d:
            code, out, _ = self.run_main(["App-Services", "--port", "9000", "--output", os.path.join(d, "r.json"),
                                          "--dry-run"], fake=fake)
        self.assertEqual(code, ac.EXIT_OK)
        self.assertIn("DRY RUN", out)
        self.assertEqual(fake.mutating_calls(), [])

    def test_api_error_maps_to_exit_3_without_traceback(self):
        fake = default_fake()
        fake.fail_post = ac.ApiError("POST", "/manage/v2/servers", 400, "ADMIN-PORTINUSE", "port in use")
        with tempfile.TemporaryDirectory() as d:
            code, _, err = self.run_main(["App-Services", "--port", "9000", "--output", os.path.join(d, "r.json")],
                                         fake=fake)
        self.assertEqual(code, ac.EXIT_API)
        self.assertIn("error: POST /manage/v2/servers → 400 ADMIN-PORTINUSE", err)
        self.assertNotIn("Traceback", err)

    def test_password_never_printed(self):
        code, out, err = self.run_main(["App-Services", "--port", "9000", "--dry-run", "--output", "/nonexistent/d/r.json"])
        self.assertNotIn("s3cret-pw", out + err)

    def test_insecure_warning(self):
        env = {**ENV, "MARKLOGIC_SCHEME": "https", "MARKLOGIC_INSECURE": "1"}
        with tempfile.TemporaryDirectory() as d:
            _, _, err = self.run_main(["App-Services", "--port", "9000", "--dry-run",
                                       "--output", os.path.join(d, "r.json")], environ=env)
        self.assertIn("certificate verification is disabled", err)
```

- [ ] **Step 2: Run the tests to check they fail**

Run: `python3 -m unittest discover -s scripts/AppServer -p 'test_*.py' -v`
Expected: the `MainTests` tests fail with `AttributeError: ... 'main'`.

- [ ] **Step 3: Write the implementation**

Append to `scripts/AppServer/appserver-clone.py`:

```python
DESCRIPTION = """\
Clone a MarkLogic app server to a new port, or remove a clone that this script created.

The clone is created in the same group as the source and has exactly the same properties
as the source apart from its name and port."""

EPILOG = """\
environment (connection settings are read ONLY from these variables; there are no flags for them):
  MARKLOGIC_HOST         required  host running the MarkLogic Management API
  MARKLOGIC_USER         required  user with the manage-admin or admin role
  MARKLOGIC_PASS         required  that user's password
  MARKLOGIC_MANAGE_PORT  optional  Management API port (default 8002)
  MARKLOGIC_SCHEME       optional  http or https (default http)
  MARKLOGIC_CA_CERT      optional  CA bundle used to verify the HTTPS certificate
  MARKLOGIC_INSECURE     optional  1 = do not verify the HTTPS certificate (not recommended)
  MARKLOGIC_DEBUG        optional  1 = show Python tracebacks on errors

clone:
  Finds SOURCE in whichever group holds it (use --group if the name exists in more than
  one group), reads its properties, checks the new name and port are free in that group,
  and creates the clone. The name defaults to SOURCE-PORT. On success a JSON record of
  the new app server is saved to --output (default ./NAME.json); an existing file is
  never overwritten. The port check covers MarkLogic app servers only: it cannot see
  other programs listening on that port.

remove:
  --remove FILE deletes the app server described by a record this script saved. It
  checks the app server still exists with the recorded name, group and port, asks for
  confirmation (--yes skips the question), deletes it, waits for MarkLogic to restart,
  and renames FILE to FILE.removed. Without a usable record nothing is deleted: remove
  the app server in the Admin UI instead (Groups > GROUP > App Servers > NAME > Delete).

--dry-run:
  Reads from the Management API and runs every check, then prints what would happen.
  Nothing is created, deleted or written.

exit codes:
  0  success                                  1  usage or environment error
  2  a pre-flight check failed                3  Management API, network or restart error
  4  removal declined or not confirmed

examples:
  export MARKLOGIC_HOST=ml1.example.com MARKLOGIC_USER=admin
  read -rs MARKLOGIC_PASS && export MARKLOGIC_PASS
  %(prog)s App-Services --port 8050 --dry-run
  %(prog)s App-Services --port 9000 --name AppServices-Digest
  %(prog)s --remove AppServices-Digest.json --dry-run
  %(prog)s --remove AppServices-Digest.json
"""


class _Parser(argparse.ArgumentParser):
    """argparse that reports usage errors as CloneError (exit 1) instead of exiting with 2."""

    def error(self, message):
        raise CloneError(message, EXIT_USAGE,
                         hint="run with --help for usage; connection settings come only from "
                              "MARKLOGIC_* environment variables")


def port_number(text: str) -> int:
    if not text.isdigit() or not 1 <= int(text) <= 65535:
        raise argparse.ArgumentTypeError(f"invalid port '{text}': must be 1-65535")
    return int(text)


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="appserver-clone.py", description=DESCRIPTION, epilog=EPILOG,
                     formatter_class=argparse.RawDescriptionHelpFormatter, allow_abbrev=False)
    parser.add_argument("source", nargs="?", metavar="SOURCE", help="name of the app server to clone")
    parser.add_argument("--port", type=port_number, metavar="N", help="port for the clone (required to clone)")
    parser.add_argument("--name", help="name for the clone (default: SOURCE-PORT)")
    parser.add_argument("--group", help="group holding SOURCE (needed only if the name exists in several groups)")
    parser.add_argument("--output", metavar="FILE", help="where to save the clone record (default: ./NAME.json)")
    parser.add_argument("--remove", metavar="FILE", help="remove the app server described by this clone record")
    parser.add_argument("--yes", action="store_true", help="with --remove: do not ask for confirmation")
    parser.add_argument("--dry-run", action="store_true", help="run all checks and show what would happen; change nothing")
    return parser


def validate_args(args) -> None:
    if args.remove is not None:
        conflicts = [flag for flag, value in (("SOURCE", args.source), ("--port", args.port), ("--name", args.name),
                                              ("--group", args.group), ("--output", args.output)) if value is not None]
        if conflicts:
            raise CloneError("--remove cannot be combined with " + ", ".join(conflicts), EXIT_USAGE)
        return
    if args.source is None:
        raise CloneError("SOURCE (the app server to clone) is required", EXIT_USAGE, hint="run with --help for usage")
    if args.port is None:
        raise CloneError("--port is required when cloning", EXIT_USAGE, hint="run with --help for usage")
    if args.yes:
        raise CloneError("--yes only applies to --remove", EXIT_USAGE)


def main(argv=None, environ=None, client_factory=ManageClient) -> int:
    argv = sys.argv[1:] if argv is None else argv
    environ = os.environ if environ is None else environ
    parser = build_parser()
    if not argv:
        parser.print_help()
        return EXIT_OK
    try:
        args = parser.parse_args(argv)
        validate_args(args)
        record = load_record(args.remove) if args.remove is not None else None
        config = load_config(environ)
        if config.scheme == "https" and config.insecure:
            print("warning: MARKLOGIC_INSECURE=1: HTTPS certificate verification is disabled", file=sys.stderr)
        client = client_factory(config)
        if record is not None:
            return cmd_remove(client, config, args, record)
        return cmd_clone(client, config, args)
    except CloneError as e:
        if environ.get("MARKLOGIC_DEBUG") == "1":
            traceback.print_exc()
        print(f"error: {e}", file=sys.stderr)
        if e.hint:
            print(f"hint: {e.hint}", file=sys.stderr)
        return e.exit_code
    except KeyboardInterrupt:
        print("error: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run the tests to check they pass**

Run: `python3 -m unittest discover -s scripts/AppServer -p 'test_*.py' -v`
Expected: every test passes.

- [ ] **Step 5: Smoke-test the real entry point**

```bash
python3 scripts/AppServer/appserver-clone.py | head -5        # help, exit 0
python3 scripts/AppServer/appserver-clone.py; echo "exit=$?"  # exit=0
env -u MARKLOGIC_HOST python3 scripts/AppServer/appserver-clone.py App-Services --port 9000; echo "exit=$?"  # error naming MARKLOGIC_HOST, exit=1
python3 scripts/AppServer/appserver-clone.py --remove /nonexistent.json; echo "exit=$?"  # Admin UI hint, exit=2
python3 -m py_compile scripts/AppServer/appserver-clone.py
```

Also check Python 3.8 syntax compatibility, if a 3.8 interpreter is available:
`python3.8 -m py_compile scripts/AppServer/appserver-clone.py` (skip if it isn't installed, and say so in the report).

- [ ] **Step 6: Commit**

```bash
git add scripts/AppServer/appserver-clone.py scripts/AppServer/test_appserver_clone.py
git commit -m "appserver-clone: CLI, self-documenting help, exit-code mapping"
```

---

### Task 8: Live test on MarkLogic 12 and README

**Files:**
- Modify: `README.md` (add a section)
- Possibly modify: `scripts/AppServer/appserver-clone.py`, only `STRIP_ON_POST`, and only if step 3 fails as described there

**Interfaces:**
- Consumes: the finished script.

The test server is `marklogic.warnesnet.com`, Management API port 8002, user `admin`. The password is supplied by the user in the session. Export it in the shell for the commands **only**. Never write it to a file, the plan, the README or a commit.

- [ ] **Step 1: Set up the environment in a scratch directory**

```bash
mkdir -p /tmp/appserver-clone-live && cd /tmp/appserver-clone-live
export MARKLOGIC_HOST=marklogic.warnesnet.com MARKLOGIC_USER=admin MARKLOGIC_PASS='<password from session>'
SCRIPT=/Users/martin/Projects/mwarnes-marklogic-scripts/scripts/AppServer/appserver-clone.py
```

- [ ] **Step 2: Dry run**

Run: `python3 "$SCRIPT" App-Services --port 9000 --name AppServices-Digest --dry-run; echo "exit=$?"`
Expected: a summary showing group `Default` and port 9000, `DRY RUN`, the payload with `"server-name": "AppServices-Digest"` and `"port": 9000`, and `exit=0`. No file is created (`ls` shows nothing).

- [ ] **Step 3: Real clone**

Run: `python3 "$SCRIPT" App-Services --port 9000 --name AppServices-Digest; echo "exit=$?"`
Expected: `created app server 'AppServices-Digest' on port 9000 ...`, `exit=0`, and `AppServices-Digest.json` exists.

If POST fails with a 400 naming a property (for example a `null`-valued `output-cdata-section-localname` or the read-only `group-name`):
1. Add that key to `STRIP_ON_POST`, with a comment quoting the error.
2. Add a unit test in `PlanCloneTests` asserting that the key is absent from the payload.
3. Run the unit tests, commit with `git commit -m "appserver-clone: strip <key> from POST payload (rejected by ML12)"`, and repeat step 3.
4. Report the change. It is a documented exception to "identical properties".

- [ ] **Step 4: Check the clone matches the source**

```bash
curl -s --digest -u "$MARKLOGIC_USER:$MARKLOGIC_PASS" \
  "http://$MARKLOGIC_HOST:8002/manage/v2/servers/App-Services/properties?group-id=Default&format=json" > source.json
python3 - <<'EOF'
import json
src = json.load(open("source.json"))
clone = json.load(open("AppServices-Digest.json"))["properties"]
diff = sorted(k for k in set(src) | set(clone) if src.get(k, "<absent>") != clone.get(k, "<absent>"))
print("differing properties:", diff)
assert diff == ["port", "server-name"], diff
print("OK: clone identical to source apart from name and port")
EOF
```
Expected: `differing properties: ['port', 'server-name']` and `OK ...`. Any other difference must be reported, not hidden.

- [ ] **Step 5: Check the pre-flight checks against the live clone**

```bash
python3 "$SCRIPT" App-Services --port 9000 --output other.json --dry-run; echo "exit=$?"   # port 9000 used by AppServices-Digest, exit=2
python3 "$SCRIPT" App-Services --port 9000 --name AppServices-Digest; echo "exit=$?"        # output file exists, exit=2
```

- [ ] **Step 6: Remove, dry run**

Run: `python3 "$SCRIPT" --remove AppServices-Digest.json --dry-run; echo "exit=$?"`
Expected: `will delete app server 'AppServices-Digest' (group 'Default', port 9000)`, `DRY RUN`, `exit=0`.

- [ ] **Step 7: Remove for real (MarkLogic restarts; the user has approved this)**

Run: `python3 "$SCRIPT" --remove AppServices-Digest.json --yes; echo "exit=$?"`
Expected: `waiting for MarkLogic to restart...` if MarkLogic answers 202, then `deleted app server 'AppServices-Digest' ...` and `exit=0`. `AppServices-Digest.json.removed` exists, and `AppServices-Digest.json` does not.

Confirm: `curl -s -o /dev/null -w '%{http_code}\n' --digest -u "$MARKLOGIC_USER:$MARKLOGIC_PASS" "http://$MARKLOGIC_HOST:8002/manage/v2/servers/AppServices-Digest/properties?group-id=Default"` prints `404`.

- [ ] **Step 8: Missing-record message against the live server**

Run: `python3 "$SCRIPT" --remove AppServices-Digest.json; echo "exit=$?"`
Expected: `error: no usable clone record: 'AppServices-Digest.json' does not exist` plus the Admin UI hint, `exit=2`.

- [ ] **Step 9: Add a README section**

Append this section to the end of `README.md`:

````markdown
## App server clone (Python)

`scripts/AppServer/appserver-clone.py` is a standalone script (Python 3.8+, standard library only)
that clones an app server to a new port with identical settings, saves a JSON record of the clone,
and can remove the clone later using only that record. Run it with no arguments for full help.

```bash
export MARKLOGIC_HOST=ml1.example.com MARKLOGIC_USER=admin
read -rs MARKLOGIC_PASS && export MARKLOGIC_PASS
./scripts/AppServer/appserver-clone.py App-Services --port 9000 --name AppServices-Digest --dry-run
./scripts/AppServer/appserver-clone.py App-Services --port 9000 --name AppServices-Digest
./scripts/AppServer/appserver-clone.py --remove AppServices-Digest.json
```

Tested against MarkLogic 12.1. Unit tests: `python3 -m unittest discover -s scripts/AppServer -p 'test_*.py'`.
````

- [ ] **Step 10: Run everything one last time and commit**

```bash
cd /Users/martin/Projects/mwarnes-marklogic-scripts
python3 -m unittest discover -s scripts/AppServer -p 'test_*.py' -v
git status --short   # expect README.md (and the script only if STRIP_ON_POST changed); no files containing the password
git add README.md
git commit -m "README: appserver-clone.py (tested on MarkLogic 12.1)"
```
